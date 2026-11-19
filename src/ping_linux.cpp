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
 *   - recvmsg() with IP_RECVTTL to read the observed IPv4 TTL
 *   - manual checksum + timestamp payload
 *
 * It mirrors the Windows version in structure and guarantees that
 * PingResult and PingProbeResult behave identically across platforms.
 */

#include "linux_ping_socket.hpp"
#include "cping/util.hpp"

#include <chrono>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>

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
PingProbeResult detail::ping_once_linux(const sockaddr_in& target, const PingOptions& options)
{
    PingProbeResult probe{};

    if (!valid_outgoing_ping_ttl(options.ttl)) {
        probe.error_msg = "Invalid outgoing TTL";
        return probe;
    }

    std::string bound_if_name = options.if_name;

    // ---------------------------------------------------------------------
    // ICMP datagram socket
    // ---------------------------------------------------------------------
    int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) {
        probe.error_msg = "socket() failed";
        return probe;
    }

    if (!bind_ping_interface(s, bound_if_name)) {
        ::close(s);
        probe.error_msg = "Could not bind ICMP socket to interface: " + bound_if_name;
        return probe;
    }
    probe.if_name = std::move(bound_if_name);

    const uint16_t id = bind_ping_socket_id(s);
    if (id == 0) {
        probe.error_msg = "Could not assign an ICMP socket identifier";
        ::close(s);
        return probe;
    }

    // Must connect() for consistent recvmsg() semantics
    if (::connect(s, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) < 0) {
        probe.error_msg = "connect() failed";
        ::close(s);
        return probe;
    }

    // Receive TTL via cmsg
    int one = 1;
    ::setsockopt(s, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));

    // Timeout
    timeval tv{};
    tv.tv_sec  = options.timeout_ms / 1000;
    tv.tv_usec = (options.timeout_ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // ---------------------------------------------------------------------
    // Build ICMP Echo Request
    // ---------------------------------------------------------------------
    const size_t packet_size = sizeof(icmphdr) + sizeof(uint64_t) + options.payload_size;
    std::vector<unsigned char> packet(packet_size, 0);

    auto* hdr = reinterpret_cast<icmphdr*>(packet.data());
    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    constexpr uint16_t sequence = 0;
    hdr->un.echo.id = htons(id);
    hdr->un.echo.sequence = htons(sequence);

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

    if (send_ping_request(s, nullptr, packet.data(), packet.size(), options.ttl) < 0) {
        probe.error_msg = "sendmsg() failed";
        ::close(s);
        return probe;
    }

    // ---------------------------------------------------------------------
    // Prepare recvmsg()
    // ---------------------------------------------------------------------
    uint8_t recv_buf[1500];
    alignas(cmsghdr) char cbuf[256];

    iovec iov{ recv_buf, sizeof(recv_buf) };

    msghdr msg{};
    sockaddr_in src{};

    msg.msg_name    = &src;
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    msg.msg_control = cbuf;

    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(std::max(1, options.timeout_ms));

    // ---------------------------------------------------------------------
    // Receive loop
    // ---------------------------------------------------------------------
    while (std::chrono::steady_clock::now() < deadline) {
        msg.msg_namelen = sizeof(src);
        msg.msg_controllen = sizeof(cbuf);
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

        icmphdr reply{};
        std::memcpy(&reply, recv_buf, sizeof(reply));
        if (reply.type != ICMP_ECHOREPLY || reply.code != 0 ||
            ntohs(reply.un.echo.id) != id || ntohs(reply.un.echo.sequence) != sequence)
            continue;

        // RTT
        auto t_recv = std::chrono::high_resolution_clock::now();
        probe.rtt_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                           t_recv - t_send)
                           .count();

        probe.ttl = observed_ping_ttl(msg);
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
    const int attempts = std::max(1, opt.retries);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &target.sin_addr) != 1) {
        PingProbeResult probe{};
        probe.error_msg = "Invalid IP address";
        result.probes.assign(static_cast<std::size_t>(attempts), probe);
        return result;
    }

    bool any_ok = false;
    for (int i = 0; i < attempts; ++i) {
        auto probe = detail::ping_once_linux(target, opt);
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

