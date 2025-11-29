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
#include "cping/ip.hpp"

#include <cstring>
#include <atomic>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>

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
    char cbuf[256];

    iovec iov{ recv_buf, sizeof(recv_buf) };
    sockaddr_in src{};

    msghdr msg{};
    msg.msg_name = &src;
    msg.msg_namelen = sizeof(src);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    while (g_running.load()) {
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

        auto* ricmp = reinterpret_cast<const icmphdr*>(recv_buf);
        if (ricmp->type != ICMP_ECHOREPLY)
            continue;

        Key k{ ntohs(ricmp->un.echo.id),
               ntohs(ricmp->un.echo.sequence) };

        // Extract TTL from ancillary data
        int ttl_val = -1;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
             cmsg;
             cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP &&
                cmsg->cmsg_type == IP_TTL)
            {
                std::memcpy(&ttl_val, CMSG_DATA(cmsg), sizeof(ttl_val));
                break;
            }
        }

        PingProbeResult probe{};
        probe.success = true;
        probe.ttl     = (ttl_val >= 0) ? ttl_val : -1;
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

        // Reset control buffer
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);
    }
}


// ============================================================================
// Engine lifecycle
// ============================================================================
bool init_engine(const std::string& if_name) {
    if (g_running.load())
        return true;

    // ICMP datagram socket (no IP header exposure)
    int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0)
        return false;

    // Optional interface binding
    if (!if_name.empty()) {
        ::setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
                     if_name.c_str(), (socklen_t)if_name.size());
    }

    // Enable TTL extraction via recvmsg()
    int one = 1;
    ::setsockopt(s, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));

    // Default TTL (can be overridden per-probe)
    int ttl_def = 64;
    ::setsockopt(s, IPPROTO_IP, IP_TTL, &ttl_def, sizeof(ttl_def));

    g_sock = s;
    g_running = true;

    try {
        g_listener = std::thread(listener_loop);
    } catch (...) {
        g_running = false;
        ::close(g_sock);
        g_sock = -1;
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
    }

    // Resolve pending waiters
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto& kv : g_waiters) {
            try { kv.second.set_value(PingProbeResult{}); } catch (...) {}
        }
        g_waiters.clear();
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
    in_addr dst{};
    if (inet_pton(AF_INET, ip.c_str(), &dst) != 1) {
        probe.error_msg = "Invalid IP";
        return probe;
    }

    // Fast-path self-ping
    if (is_local_ipv4_addr_linux(dst)) {
        // (Kept exactly as your implementation — it's perfect)
        // Just wrapped commentary removed here for brevity.
        // -----------------------------------------------------
        // This block sends a one-shot ping via a temporary socket,
        // extracts TTL via cmsg, and computes RTT manually.
        // -----------------------------------------------------
        // [CODE UNCHANGED — identical to your version]
        // -----------------------------------------------------
        // (Te lo lascio invariato per coerenza e performance)
        // -----------------------------------------------------

        int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (s < 0) { probe.error_msg = "socket() failed"; return probe; }

        int one = 1;
        ::setsockopt(s, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (ttl > 0) ::setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        // Timeout
        timeval tv{};
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        sockaddr_in dstsa{};
        dstsa.sin_family = AF_INET;
        dstsa.sin_addr   = dst;

        if (::connect(s, reinterpret_cast<sockaddr*>(&dstsa), sizeof(dstsa)) < 0) {
            ::close(s);
            probe.error_msg = "connect() failed";
            return probe;
        }

        uint16_t id  = static_cast<uint16_t>(::getpid() & 0xFFFF);
        uint16_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);

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

        if (::send(s, packet.data(), packet.size(), 0) < 0) {
            ::close(s);
            probe.error_msg = "send() failed";
            return probe;
        }

        uint8_t recv_buf[1500];
        char cbuf[256];

        iovec iov{ recv_buf, sizeof(recv_buf) };
        msghdr msg{};
        sockaddr_in src{};

        msg.msg_name = &src;
        msg.msg_namelen = sizeof(src);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        while (true) {
            ssize_t n = ::recvmsg(s, &msg, 0);

            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    probe.error_msg = "Timeout";
                else
                    probe.error_msg = "recvmsg() failed";
                break;
            }

            if (n < (ssize_t)sizeof(icmphdr))
                continue;

            auto* ricmp = reinterpret_cast<const icmphdr*>(recv_buf);
            if (ricmp->type != ICMP_ECHOREPLY)
                continue;

            if (ntohs(ricmp->un.echo.id) != id ||
                ntohs(ricmp->un.echo.sequence) != seq)
                continue;

            auto t_recv = std::chrono::high_resolution_clock::now();
            probe.rtt_ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                               t_recv - t_send)
                               .count();

            // Extract TTL
            int ttl_val = -1;
            for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (cmsg->cmsg_level == IPPROTO_IP &&
                    cmsg->cmsg_type == IP_TTL)
                {
                    std::memcpy(&ttl_val, CMSG_DATA(cmsg), sizeof(ttl_val));
                    break;
                }
            }

            probe.ttl = (ttl_val >= 0) ? ttl_val : -1;
            probe.success = true;
            break;
        }

        ::close(s);
        return probe;
    }

    // Engine path
    if (g_sock < 0) {
        probe.error_msg = "Engine socket not available";
        return probe;
    }

    uint16_t id  = static_cast<uint16_t>(::getpid() & 0xFFFF);
    uint16_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);
    Key k{ id, seq };

    std::promise<PingProbeResult> pr;
    auto fut = pr.get_future();

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.emplace(k, std::move(pr));
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

    // Optional TTL override
    if (ttl > 0) {
        ::setsockopt(g_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }

    sockaddr_in dstsa{};
    dstsa.sin_family = AF_INET;
    dstsa.sin_addr   = dst;

    auto t_send = std::chrono::high_resolution_clock::now();

    ssize_t sent =
        ::sendto(g_sock,
                 packet.data(),
                 packet.size(),
                 0,
                 reinterpret_cast<sockaddr*>(&dstsa),
                 sizeof(dstsa));

    if (sent < 0) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.erase(k);
        probe.error_msg = "sendto() failed";
        return probe;
    }

    // Await response
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) ==
        std::future_status::ready)
    {
        probe = fut.get();

        auto t_recv = std::chrono::high_resolution_clock::now();
        probe.rtt_ms =
            (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                t_recv - t_send)
                .count();

        return probe;
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
