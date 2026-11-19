#if defined(__linux__)

/**
 * High-performance ICMP engine (Linux).
 *
 * Implementation notes:
 *  - Uses a datagram ICMP socket (SOCK_DGRAM + IPPROTO_ICMP)
 *  - Listener thread consumes replies via recvmsg(), extracting TTL
 *    from ancillary data (IP_RECVTTL)
 *  - Correlates replies to outstanding promises via (id, seq)
 *  - Mirrors the Windows engine design for full cross-platform consistency
 */

#include "cping/engine.hpp"
#include "cping/util.hpp"
#include "linux_ping_socket.hpp"

#include <cstring>
#include <atomic>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>

namespace cping {

// ============================================================================
// Global engine state (mirrors Windows implementation)
// ============================================================================
static int g_sock = -1;
static uint16_t g_socket_id = 0;
static std::thread g_listener;
static std::atomic<bool> g_running{false};

struct Key { uint16_t id; uint16_t seq; };
struct KeyHash {
    size_t operator()(const Key& k) const noexcept {
        return (size_t(k.id) << 16) ^ k.seq;
    }
};
struct KeyEq {
    bool operator()(const Key& a, const Key& b) const noexcept {
        return a.id == b.id && a.seq == b.seq;
    }
};

static std::unordered_map<
    Key,
    std::promise<PingProbeResult>,
    KeyHash,
    KeyEq
> g_waiters;

static std::mutex g_mtx;
static std::string g_if_name; // Protected by g_mtx.
static std::atomic<uint16_t> g_seq{1};


// ============================================================================
// Helper: detect if IP belongs to local machine
// ============================================================================
static bool is_local_ipv4_addr_linux(const in_addr& addr) {
    struct ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) != 0 || !ifa)
        return false;

    bool found = false;

    for (auto* p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET)
            continue;

        auto* sa = reinterpret_cast<sockaddr_in*>(p->ifa_addr);
        if (sa->sin_addr.s_addr == addr.s_addr) {
            found = true;
            break;
        }
    }

    freeifaddrs(ifa);
    return found;
}


// ============================================================================
// Listener thread
// Consumes ICMP Echo Replies and resolves the corresponding promises
// ============================================================================
static void listener_loop() {
    int s = g_sock;
    if (s < 0) return;

    uint8_t recv_buf[2048];
    alignas(cmsghdr) char cbuf[256];

    iovec iov{ recv_buf, sizeof(recv_buf) };
    sockaddr_in src{};

    msghdr msg{};
    msg.msg_name = &src;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;

    while (g_running.load()) {
        msg.msg_namelen = sizeof(src);
        msg.msg_controllen = sizeof(cbuf);
        ssize_t n = ::recvmsg(s, &msg, 0);

        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break; // fatal error or shutdown
        }
        if (n == 0)
            break; // socket shutdown

        if (n < (ssize_t)sizeof(icmphdr))
            continue;

        icmphdr reply{};
        std::memcpy(&reply, recv_buf, sizeof(reply));
        if (reply.type != ICMP_ECHOREPLY || reply.code != 0)
            continue;

        const Key k{ ntohs(reply.un.echo.id), ntohs(reply.un.echo.sequence) };

        PingProbeResult probe{};
        probe.success = true;
        probe.ttl     = detail::observed_ping_ttl(msg);
        probe.rtt_ms  = 0;  // caller computes RTT

        // Resolve waiter, if present
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            auto it = g_waiters.find(k);
            if (it != g_waiters.end()) {
                std::promise<PingProbeResult> tmp = std::move(it->second);
                g_waiters.erase(it);
                try { tmp.set_value(probe); } catch (...) {}
            }
        }

    }
}


// ============================================================================
// Engine lifecycle
// ============================================================================
bool init_engine(const std::string& if_name) {
    if (g_running.load()) {
        std::lock_guard<std::mutex> lk(g_mtx);
        return if_name.empty() || if_name == g_if_name;
    }

    std::string bound_if_name = if_name;

    // ICMP datagram socket (no IP header exposure)
    int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0)
        return false;

    if (!detail::bind_ping_interface(s, bound_if_name)) {
        ::close(s);
        return false;
    }

    const uint16_t id = detail::bind_ping_socket_id(s);
    if (id == 0) {
        ::close(s);
        return false;
    }

    // Enable TTL extraction via recvmsg()
    int one = 1;
    ::setsockopt(s, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_if_name = std::move(bound_if_name);
    }
    g_sock = s;
    g_socket_id = id;
    g_running = true;

    try {
        g_listener = std::thread(listener_loop);
    } catch (...) {
        g_running = false;
        ::close(g_sock);
        g_sock = -1;
        g_socket_id = 0;
        std::lock_guard<std::mutex> lk(g_mtx);
        g_if_name.clear();
        return false;
    }

    return true;
}


void shutdown_engine() {
    g_running = false;

    // Wake listener thread
    if (g_sock >= 0)
        ::shutdown(g_sock, SHUT_RD);

    if (g_listener.joinable()) {
        try { g_listener.join(); } catch (...) {}
    }

    if (g_sock >= 0) {
        ::close(g_sock);
        g_sock = -1;
        g_socket_id = 0;
    }

    // Resolve pending waiters
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto& kv : g_waiters) {
            try { kv.second.set_value(PingProbeResult{}); } catch (...) {}
        }
        g_waiters.clear();
        g_if_name.clear();
    }
}


// ============================================================================
// Single-probe API (Linux engine)
// ============================================================================
PingProbeResult ping_once_engine(const std::string& ip,
                                 int timeout_ms,
                                 int payload_size,
                                 int ttl)
{
    PingProbeResult probe{};

    // Parse IPv4
    sockaddr_in target{};
    target.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &target.sin_addr) != 1) {
        probe.error_msg = "Invalid IP";
        return probe;
    }

    if (!detail::valid_outgoing_ping_ttl(ttl)) {
        probe.error_msg = "Invalid outgoing TTL";
        return probe;
    }

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        probe.if_name = g_if_name;
    }

    // A local target can use a connected, temporary ping socket.
    if (is_local_ipv4_addr_linux(target.sin_addr)) {
        PingOptions options{};
        options.timeout_ms = timeout_ms;
        options.payload_size = payload_size;
        options.ttl = ttl;
        options.if_name = std::move(probe.if_name);
        return detail::ping_once_linux(target, options);
    }

    // Engine path
    if (g_sock < 0) {
        probe.error_msg = "Engine socket not available";
        return probe;
    }

    uint16_t id  = g_socket_id;
    uint16_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);
    Key k{ id, seq };

    std::promise<PingProbeResult> pr;
    auto fut = pr.get_future();

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_waiters.emplace(k, std::move(pr)).second) {
            probe.error_msg = "ICMP sequence already in use";
            return probe;
        }
    }

    // Build ICMP Echo Request
    std::vector<unsigned char> packet(sizeof(icmphdr) + sizeof(uint64_t) + payload_size, 0);

    auto* hdr = reinterpret_cast<icmphdr*>(packet.data());
    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->un.echo.id = htons(id);
    hdr->un.echo.sequence = htons(seq);

    uint64_t ticks =
        (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();

    std::memcpy(packet.data() + sizeof(icmphdr), &ticks, sizeof(ticks));

    hdr->checksum = 0;
    hdr->checksum = checksum16(packet.data(), packet.size());

    auto t_send = std::chrono::high_resolution_clock::now();
    if (detail::send_ping_request(g_sock, &target, packet.data(), packet.size(), ttl) < 0) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.erase(k);
        probe.error_msg = "sendmsg() failed";
        return probe;
    }

    // Await response
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) ==
        std::future_status::ready)
    {
        auto reply = fut.get();
        reply.if_name = std::move(probe.if_name);

        auto t_recv = std::chrono::high_resolution_clock::now();
        reply.rtt_ms =
            (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                t_recv - t_send)
                .count();

        return reply;
    }

    // Timeout: cleanup
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.erase(k);
    }

    probe.error_msg = "Timeout";
    return probe;
}


// ============================================================================
// Engine status
// ============================================================================
bool engine_available() {
    return g_running.load();
}

} // namespace cping

#endif // __linux__
