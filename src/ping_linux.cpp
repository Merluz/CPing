#if !defined(__linux__)
#include "cping/ping.hpp"

namespace cping {

// Stub for non-Linux builds
PingResult ping_host(const std::string&, int) { return {}; }
PingResult ping_host(const std::string&, const PingOptions&) { return {}; }

} // namespace cping

#else

/**
 * Linux implementation of the basic ping logic (non-engine).
 *
 * This file provides a standalone ICMP Echo workflow using:
 *   - DATAGRAM ICMP sockets (SOCK_DGRAM + IPPROTO_ICMP)
 *   - recvmsg() with IP_RECVTTL to extract hop count
 *   - manual checksum + timestamp payload
 *
 * It mirrors the Windows version in structure and guarantees that
 * PingResult and PingProbeResult behave identically across platforms.
 */

#include "cping/ping.hpp"
#include "cping/ip.hpp"
#include "cping/util.hpp"

#include <chrono>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

namespace cping {

// ============================================================================
// Helper: ICMP checksum wrapper
// ============================================================================
static uint16_t icmp_checksum(const void* data, size_t len) {
    return checksum16(data, len);
}


// ============================================================================
// Perform a single ICMP Echo attempt on Linux (blocking)
// ============================================================================
static PingProbeResult ping_once_linux(const std::string& ip,
                                       int timeout_ms,
                                       const std::string& if_name_override,
                                       int payload_size,
                                       int ttl_opt)
{
    PingProbeResult probe{};
    probe.if_name = if_name_override;

    // ---------------------------------------------------------------------
    // Parse target IPv4
    // ---------------------------------------------------------------------
    sockaddr_in dst{};
    dst.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) != 1) {
        probe.error_msg = "Invalid IP address";
        return probe;
    }

    // ---------------------------------------------------------------------
    // ICMP datagram socket
    // ---------------------------------------------------------------------
    int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) {
        probe.error_msg = "socket() failed";
        return probe;
    }

    // Optional: bind to interface
    if (!if_name_override.empty()) {
        ::setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
                     if_name_override.c_str(),
                     (socklen_t)if_name_override.size());
    }

    // Must connect() for consistent recvmsg() semantics
    if (::connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        probe.error_msg = "connect() failed";
        ::close(s);
        return probe;
    }

    // Receive TTL via cmsg
    int one = 1;
    ::setsockopt(s, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));

    // Custom TTL (if supplied)
    if (ttl_opt > 0) {
        ::setsockopt(s, IPPROTO_IP, IP_TTL, &ttl_opt, sizeof(ttl_opt));
    }

    // Timeout
    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // ---------------------------------------------------------------------
    // Build ICMP Echo Request
    // ---------------------------------------------------------------------
    const size_t packet_size = sizeof(icmphdr) + sizeof(uint64_t) + payload_size;
    std::vector<unsigned char> packet(packet_size, 0);

    auto* hdr = reinterpret_cast<icmphdr*>(packet.data());
    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->un.echo.id = 0;
    hdr->un.echo.sequence = 0;

    // Timestamp payload
    uint64_t ticks = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();

    std::memcpy(packet.data() + sizeof(icmphdr), &ticks, sizeof(ticks));

    hdr->checksum = icmp_checksum(packet.data(), packet.size());

    // ---------------------------------------------------------------------
    // Send
    // ---------------------------------------------------------------------
    auto t_send = std::chrono::high_resolution_clock::now();

    if (::send(s, packet.data(), packet.size(), 0) < 0) {
        probe.error_msg = "send() failed";
        ::close(s);
        return probe;
    }

    // ---------------------------------------------------------------------
    // Prepare recvmsg()
    // ---------------------------------------------------------------------
    uint8_t recv_buf[1500];
    char cbuf[256];

    iovec iov{ recv_buf, sizeof(recv_buf) };

    msghdr msg{};
    sockaddr_in src{};

    msg.msg_name    = &src;
    msg.msg_namelen = sizeof(src);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(std::max(1, timeout_ms));

    // ---------------------------------------------------------------------
    // Receive loop
    // ---------------------------------------------------------------------
    while (std::chrono::steady_clock::now() < deadline) {

        ssize_t n = ::recvmsg(s, &msg, 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;

            probe.error_msg = "recvmsg() failed";
            ::close(s);
            return probe;
        }

        if (n < (ssize_t)sizeof(icmphdr))
            continue;

        const icmphdr* ricmp = reinterpret_cast<const icmphdr*>(recv_buf);
        if (ricmp->type != ICMP_ECHOREPLY)
            continue;

        // RTT
        auto t_recv = std::chrono::high_resolution_clock::now();
        probe.rtt_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                           t_recv - t_send)
                           .count();

        // Extract TTL
        int ttl = -1;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
             cmsg;
             cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP &&
                cmsg->cmsg_type == IP_TTL)
            {
                std::memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
                break;
            }
        }
        // NOTE: Linux ICMP datagram sockets subtract 1 from TTL before exposing it
        // through IP_RECVTTL. We compensate to match the real hop count.
        ttl++;

        probe.ttl = (ttl >= 0 ? ttl : -1);
        probe.success = true;

        ::close(s);
        return probe;
    }

    probe.error_msg = "No reply received";
    ::close(s);
    return probe;
}


// ============================================================================
// Public API: compatibility and full-options version
// ============================================================================
PingResult ping_host(const std::string& ip, int timeout_ms) {
    PingOptions opt{};
    opt.timeout_ms = timeout_ms;
    opt.retries    = 1;

    return ping_host(ip, opt);
}


PingResult ping_host(const std::string& ip, const PingOptions& opt) {
    PingResult result{};
    bool any_ok = false;

    const int attempts = std::max(1, opt.retries);

    for (int i = 0; i < attempts; ++i) {
        auto probe = ping_once_linux(ip,
                                     opt.timeout_ms,
                                     opt.if_name,
                                     opt.payload_size,
                                     opt.ttl);

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


#endif // __linux__

