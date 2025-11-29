/**
 * High-performance ICMP engine (Windows).
 *
 * Responsibilities:
 * - Open a raw ICMP socket + WinPcap capture
 * - Spawn a listener thread that dispatches ICMP Echo Replies to waiting probes
 * - Correlate replies using (id, seq) pairs stored in a promise/future map
 * - Provide a fast async probe API (ping_once_engine)
 *
 * This engine is optional: the higher-level ping implementation will fall
 * back to raw-socket + pcap (ping_once_win) when the engine is disabled.
 */

#include "cping/engine.hpp"
#include "win/win_pcap.hpp"
#include "win/win_icmp.hpp"
#include "win/win_route.hpp"
#include "cping/util.hpp"

#include <cstring>
#include <atomic>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace cping {

// ============================================================================
// Global engine state
// ============================================================================
static Capture g_cap;
static SOCKET g_sock = INVALID_SOCKET;

static std::thread g_listener;
static std::atomic<bool> g_running{false};

// Key used to correlate echo replies with outstanding promises
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

// Map (id,seq) → promise<Probe>
static std::unordered_map<
    Key,
    std::promise<PingProbeResult>,
    KeyHash,
    KeyEq
> g_waiters;

static std::mutex g_mtx;

// Global sequence generator (per process)
static std::atomic<uint16_t> g_seq{1};


// ============================================================================
// Listener thread
// ============================================================================
/**
 * Captures inbound ICMP Echo Replies via WinPcap and dispatches them
 * to the corresponding waiting promise, if present.
 *
 * RTT is calculated by the caller (which knows the send timestamp).
 * Here we only capture TTL and confirm that the reply matches id/seq.
 */
static void listener_loop() {
    constexpr int ETHER_LEN = 14;

    pcap_t* cap = g_cap.h;
    if (!cap) return;

    while (g_running.load()) {
        pcap_pkthdr* h = nullptr;
        const u_char* data = nullptr;

        int r = pcap_next_ex(cap, &h, &data);
        if (r == 0)   continue; // timeout
        if (r == -2) break;     // breakloop()
        if (r == -1) break;     // error

        if (!h || h->caplen < ETHER_LEN + sizeof(IpHeader))
            continue;

        auto* iphdr = reinterpret_cast<const IpHeader*>(data + ETHER_LEN);
        if ((iphdr->ver_ihl >> 4) != 4) continue;  // must be IPv4
        if (iphdr->protocol != 1)        continue;  // ICMP only

        uint8_t ihl = (iphdr->ver_ihl & 0x0F) * 4;
        if (h->caplen < ETHER_LEN + ihl + sizeof(IcmpHeader))
            continue;

        auto* icmph = reinterpret_cast<const IcmpHeader*>(data + ETHER_LEN + ihl);
        if (icmph->type != 0) continue;  // 0 = Echo Reply

        Key k{ ntohs(icmph->id), ntohs(icmph->seq) };

        PingProbeResult probe{};
        probe.success = true;
        probe.ttl     = static_cast<int>(iphdr->ttl);
        probe.rtt_ms  = 0; // caller computes actual RTT

        // Try to resolve promise
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
/**
 * Initializes the global ICMP engine.
 *
 * 1) Select capture device (manual override or auto by ROUTE)
 * 2) Open WinPcap capture in immediate mode
 * 3) Open raw ICMP socket
 * 4) Start listener thread
 */
bool init_engine(const std::string& if_name) {
    if (g_running.load())
        return true; // already initialized

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs)
        return false;

    pcap_if_t* dev = nullptr;

    // Case 1: manual selection by substring
    if (!if_name.empty()) {
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            if (d->name && std::string(d->name).find(if_name) != std::string::npos) {
                dev = d;
                break;
            }
        }
    }

    // Case 2: auto-select based on best route to 8.8.8.8
    if (!dev) {
        in_addr gateway{};
        gateway.S_un.S_addr = inet_addr("8.8.8.8");
        dev = pick_device_for_target(alldevs, gateway);
    }

    if (!dev) {
        pcap_freealldevs(alldevs);
        return false;
    }

    // Configure capture
    if (!open_capture(g_cap, dev->name, 1, errbuf)) {
        pcap_freealldevs(alldevs);
        return false;
    }
    if (!apply_icmp_filter(g_cap, "")) {
        pcap_freealldevs(alldevs);
        return false;
    }

    pcap_freealldevs(alldevs);

    // Prepare raw ICMP socket
    if (!ensure_wsa())
        return false;

    g_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (g_sock == INVALID_SOCKET)
        return false;

    g_running = true;
    g_listener = std::thread(listener_loop);

    return true;
}


/**
 * Shuts down the global engine (listener, pcap, socket, pending waiters).
 */
void shutdown_engine() {
    g_running = false;

    // Signal capture loop to stop
    if (g_cap.h)
        pcap_breakloop(g_cap.h);

    // Join listener
    if (g_listener.joinable()) {
        try { g_listener.join(); } catch (...) {}
    }

    // Close capture
    if (g_cap.h) {
        pcap_close(g_cap.h);
        g_cap.h = nullptr;
    }

    // Close socket
    if (g_sock != INVALID_SOCKET) {
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }

    // Resolve all outstanding promises with empty result
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto& kv : g_waiters) {
            try {
                auto fut = kv.second.get_future();
                if (fut.valid())
                    kv.second.set_value(PingProbeResult{});
            } catch (...) {}
        }
        g_waiters.clear();
    }
}


// ============================================================================
// Engine probe
// ============================================================================
/**
 * Performs a single ICMP probe using the global engine.
 *
 * Workflow:
 * - Create (id,seq) pair
 * - Insert promise into waiter map
 * - Send raw ICMP Echo Request
 * - Wait for listener thread to resolve the future
 */
PingProbeResult ping_once_engine(const std::string& ip,
                                 int timeout_ms,
                                 int payload_size,
                                 int ttl)
{
    PingProbeResult probe{};

    // Validate IPv4
    in_addr dst{};
    if (InetPtonA(AF_INET, ip.c_str(), &dst) != 1) {
        probe.error_msg = "Invalid IP";
        return probe;
    }

    // Fast-path for local addresses
    if (is_local_ipv4_addr(dst)) {
        long rtt_ms = 0;
        int ttl_local = -1;

        if (icmp_ping_local(dst, timeout_ms, rtt_ms, ttl_local)) {
            probe.success = true;
            probe.rtt_ms  = rtt_ms;
            probe.ttl     = ttl_local;
        } else {
            probe.error_msg = "Local ICMP failed";
        }

        return probe;
    }

    if (g_sock == INVALID_SOCKET) {
        probe.error_msg = "Engine socket not available";
        return probe;
    }

    // Allocate id/seq and waiter entry
    uint16_t id  = static_cast<uint16_t>(GetCurrentProcessId() & 0xFFFF);
    uint16_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);

    Key k{ id, seq };

    std::promise<PingProbeResult> pr;
    auto fut = pr.get_future();

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.emplace(k, std::move(pr));
    }

    // Craft payload (timestamp + extra bytes)
    uint64_t ticks = GetTickCount64();
    std::vector<unsigned char> payload(sizeof(ticks) + payload_size, 0);
    std::memcpy(payload.data(), &ticks, sizeof(ticks));

    // Build ICMP Echo Request
    IcmpHeader req{};
    req.type = 8;
    req.code = 0;
    req.id   = htons(id);
    req.seq  = htons(seq);

    std::vector<unsigned char> packet(sizeof(IcmpHeader) + payload.size());
    std::memcpy(packet.data(), &req, sizeof(req));
    std::memcpy(packet.data() + sizeof(req), payload.data(), payload.size());

    reinterpret_cast<IcmpHeader*>(packet.data())->checksum =
        checksum16(packet.data(), packet.size());

    sockaddr_in dstsa{};
    dstsa.sin_family = AF_INET;
    dstsa.sin_addr   = dst;

    // Optional TTL override
    if (ttl > 0) {
        setsockopt(
            g_sock,
            IPPROTO_IP,
            IP_TTL,
            reinterpret_cast<const char*>(&ttl),
            sizeof(ttl)
        );
    }

    // Send
    auto t_send = std::chrono::high_resolution_clock::now();

    int sent = sendto(
        g_sock,
        reinterpret_cast<const char*>(packet.data()),
        static_cast<int>(packet.size()),
        0,
        reinterpret_cast<const sockaddr*>(&dstsa),
        sizeof(dstsa)
    );

    if (sent == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.erase(k);
        probe.error_msg = "sendto failed";
        return probe;
    }

    // Wait for reply
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready) {
        probe = fut.get();

        auto t_recv = std::chrono::high_resolution_clock::now();
        probe.rtt_ms = static_cast<long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t_recv - t_send).count()
        );

        return probe;
    }

    // Timeout: remove waiter
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_waiters.erase(k);
    }

    probe.error_msg = "Timeout";
    return probe;
}


// ============================================================================
// Status API
// ============================================================================
bool engine_available() {
    return g_running.load();
}

} // namespace cping
