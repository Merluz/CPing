/**
 * Windows backend for ICMP echo requests.
 *
 * Responsibilities:
 * - Raw ICMP send/receive using WinPcap + custom raw socket helpers
 * - Timestamp-based payload matching
 * - Interface selection (manual override or auto-pick)
 * - Handling local-host pings and engine delegation
 *
 * This module provides the platform-specific implementation used
 * internally by the high-level cping::ping_host() API.
 */

#include "cping/ping.hpp"
#include "cping/ip.hpp"
#include "win/win_route.hpp"
#include "win/win_pcap.hpp"
#include "win/win_icmp.hpp"

#include <cstring>
#include <pcap.h>
#include <chrono>
#include <string>
#include <iostream>
#include <atomic>

#include "cping/engine.hpp"

namespace cping {

// ---------------------------------------------------------------------------
// Thread-safe global sequence number
// ---------------------------------------------------------------------------
static std::atomic<uint16_t> g_seq{1};


/**
 * Performs a single ICMP probe on Windows.
 *
 * This function is the lowest-level building block for ping on Windows:
 *   - If the custom engine is active, delegates to the engine version.
 *   - Otherwise executes a raw ICMP Echo (send + capture) via WinPcap.
 *
 * Matching is performed by embedding a 64-bit tick timestamp in the payload.
 *
 * @param ip               Target IPv4 address as string (x.x.x.x)
 * @param timeout_ms       Probe timeout in milliseconds
 * @param if_name_override Manual interface substring (optional)
 * @param payload_size     Extra payload bytes to append after the timestamp
 * @param ttl_opt          Custom TTL, -1 = system default
 *
 * @return PingProbeResult containing RTT, TTL, error message, etc.
 */
static PingProbeResult ping_once_win(const std::string& ip,
                                     int timeout_ms,
                                     const std::string& if_name_override,
                                     int payload_size,
                                     int ttl_opt)
{
    // Engine override: when DLL engine is active, skip raw pcap path
    if (engine_available()) {
        return ping_once_engine(ip, timeout_ms, payload_size, ttl_opt);
    }

    PingProbeResult probe{};
    probe.if_name = if_name_override;

    // -----------------------------------------------------------------------
    // Validate target IP
    // -----------------------------------------------------------------------
    in_addr dst_addr{};
    if (InetPtonA(AF_INET, ip.c_str(), &dst_addr) != 1) {
        probe.error_msg = "Invalid IP address";
        return probe;
    }

    // -----------------------------------------------------------------------
    // Local-host fast path (pure local-loop ICMP)
    // -----------------------------------------------------------------------
    if (is_local_ipv4_addr(dst_addr)) {
        long rtt_ms = 0;
        int ttl = -1;

        if (icmp_ping_local(dst_addr, timeout_ms, rtt_ms, ttl)) {
            probe.success = true;
            probe.rtt_ms = rtt_ms;
            if(ttl != -1)
            {
                ttl++;
            }
            probe.ttl = ttl;
        } else {
            probe.error_msg = "Local ICMP failed";
        }
        return probe;
    }

    // -----------------------------------------------------------------------
    // Enumerate NICs
    // -----------------------------------------------------------------------
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        probe.error_msg = "pcap_findalldevs failed";
        return probe;
    }

    // Manual interface override takes priority
    pcap_if_t* dev = nullptr;

    if (!if_name_override.empty()) {
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            if (d->name && std::string(d->name).find(if_name_override) != std::string::npos) {
                dev = d;
                break;
            }
        }
    }

    // Otherwise auto-pick device for the target
    if (!dev) dev = pick_device_for_target(alldevs, dst_addr);

    if (!dev) {
        pcap_freealldevs(alldevs);
        probe.error_msg = "No suitable device";
        return probe;
    }

    // -----------------------------------------------------------------------
    // Configure pcap capture with ICMP reply filter
    // -----------------------------------------------------------------------
    Capture cap;
    if (!open_capture(cap, dev->name, timeout_ms, errbuf)) {
        pcap_freealldevs(alldevs);
        probe.error_msg = "open_capture failed";
        return probe;
    }

    if (!apply_icmp_filter(cap, ip)) {
        pcap_freealldevs(alldevs);
        probe.error_msg = "apply_icmp_filter failed";
        return probe;
    }

    // Only capture inbound packets on non-loopback devices
    if ((dev->flags & PCAP_IF_LOOPBACK) == 0) {
        (void)pcap_setdirection(cap.h, PCAP_D_IN);
    }

    // -----------------------------------------------------------------------
    // Craft payload: [uint64_t timestamp | extra bytes...]
    // -----------------------------------------------------------------------
    uint64_t ticks = GetTickCount64();
    std::vector<unsigned char> payload(sizeof(ticks) + payload_size, 0);
    std::memcpy(payload.data(), &ticks, sizeof(ticks));

    uint16_t id     = static_cast<uint16_t>(GetCurrentProcessId() & 0xFFFF);
    uint16_t seqNow = g_seq.fetch_add(1, std::memory_order_relaxed);

    auto t_send = std::chrono::high_resolution_clock::now();

    if (!send_icmp_echo_raw(dst_addr, id, seqNow, payload.data(), payload.size(), ttl_opt)) {
        pcap_freealldevs(alldevs);
        probe.error_msg = "send_icmp_echo_raw failed";
        return probe;
    }

    // -----------------------------------------------------------------------
    // Wait for reply until timeout
    // -----------------------------------------------------------------------
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);

    bool matched = recv_icmp_until(
        cap,
        [&](const IpHeader* iphdr, const IcmpHeader* icmph,
            const unsigned char* payload_rcv, size_t plen) -> bool {

            // Must be Echo Reply + payload must contain timestamp
            if (icmph->type != 0 || plen < sizeof(uint64_t)) return false;

            uint64_t echoed{};
            std::memcpy(&echoed, payload_rcv, sizeof(uint64_t));
            if (echoed != ticks) return false;  // validate correlation

            auto t_recv = std::chrono::high_resolution_clock::now();

            probe.rtt_ms = static_cast<long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(t_recv - t_send).count()
            );
            probe.ttl     = static_cast<int>(iphdr->ttl);
            probe.success = true;
            return true;
        },
        deadline
    );

    pcap_freealldevs(alldevs);

    if (!matched && !probe.success) {
        probe.error_msg = "No reply received";
    }

    return probe;
}


// ---------------------------------------------------------------------------
// Legacy signature
// ---------------------------------------------------------------------------
PingResult ping_host(const std::string& ip, int timeout_ms) {
    PingOptions opt;
    opt.timeout_ms = timeout_ms;
    opt.retries = 1;
    return ping_host(ip, opt);
}


// ---------------------------------------------------------------------------
// New signature: recommended API
// ---------------------------------------------------------------------------
PingResult ping_host(const std::string& ip, const PingOptions& opt) {
    PingResult result{};
    bool any_ok = false;

    for (int i = 0; i < std::max<int>(1, opt.retries); ++i) {
        auto probe = ping_once_win(ip, opt.timeout_ms, opt.if_name,
                                   opt.payload_size, opt.ttl);

        result.probes.push_back(probe);

        if (probe.success) {
            if (!any_ok || probe.rtt_ms < result.rtt_ms) {
                result.rtt_ms = probe.rtt_ms;
                result.ttl    = probe.ttl;
            }
            any_ok = true;

            if (opt.stop_on_first_success)
                break;
        }
    }

    result.reachable = any_ok;
    return result;
}

} // namespace cping
