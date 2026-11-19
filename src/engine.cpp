#include "cping/engine.hpp"
#include "cping/util.hpp"
#include "win/win_engine_session.hpp"
#include "win/win_icmp.hpp"
#include "win/win_pcap.hpp"
#include "win/win_route.hpp"

#include <cstring>
#include <future>
#include <unordered_map>
#include <utility>
#include <windows.h>

namespace cping {
namespace {

using win_engine::CaptureResult;
using win_engine::Clock;
using win_engine::Reply;
using win_engine::Transport;

PingProbeResult failed_probe(const char* reason) {
    PingProbeResult probe{};
    probe.error_msg = reason;
    return probe;
}

class WindowsTransport final : public Transport {
public:
    ~WindowsTransport() override {
        if (socket_ != INVALID_SOCKET) closesocket(socket_);
        if (stop_event_) CloseHandle(stop_event_);
    }

    bool open(const std::string& if_name) {
        char errbuf[PCAP_ERRBUF_SIZE]{};
        pcap_if_t* device_list = nullptr;
        const int listed = pcap_findalldevs(&device_list, errbuf);
        const std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)>
            devices(device_list, pcap_freealldevs);
        if (listed == -1 || !devices) return false;

        pcap_if_t* device = nullptr;
        if (!if_name.empty()) {
            for (auto* entry = devices.get(); entry; entry = entry->next) {
                if (entry->name && std::string(entry->name).find(if_name) != std::string::npos) {
                    device = entry;
                    break;
                }
            }
        }
        if (!device) {
            in_addr route_target{};
            route_target.S_un.S_addr = inet_addr("8.8.8.8");
            device = pick_device_for_target(devices.get(), route_target);
        }
        if (!device || !open_capture(capture_, device->name, 1, errbuf) ||
            !apply_icmp_filter(capture_, "")) {
            return false;
        }

        // Nonblocking reads drain packets already buffered by Npcap. The listener
        // then waits for either fresh capture data or our own shutdown event.
        if (pcap_setnonblock(capture_.h, 1, errbuf) != 0 ||
            pcap_setmintocopy(capture_.h, 0) != 0) {
            return false;
        }
        capture_event_ = pcap_getevent(capture_.h);
        if (!capture_event_ || capture_event_ == INVALID_HANDLE_VALUE) return false;

        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event_ || !ensure_wsa()) return false;

        socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (socket_ == INVALID_SOCKET) return false;

        DWORD default_ttl = 0;
        int size = sizeof(default_ttl);
        if (getsockopt(socket_, IPPROTO_IP, IP_TTL, reinterpret_cast<char*>(&default_ttl),
                       &size) == SOCKET_ERROR || default_ttl < 1 || default_ttl > 255) {
            return false;
        }
        default_ttl_ = static_cast<int>(default_ttl);
        return true;
    }

    CaptureResult receive(Reply& reply) noexcept override {
        if (WaitForSingleObject(stop_event_, 0) != WAIT_TIMEOUT) return CaptureResult::Failed;

        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        const int status = pcap_next_ex(capture_.h, &header, &data);
        if (status < 0) return CaptureResult::Failed;
        if (status == 0) {
            const HANDLE events[]{stop_event_, capture_event_};
            return WaitForMultipleObjects(2, events, FALSE, INFINITE) == WAIT_OBJECT_0 + 1
                ? CaptureResult::Idle : CaptureResult::Failed;
        }

        constexpr int ethernet_size = 14;
        if (!header || header->caplen < ethernet_size + sizeof(IpHeader)) {
            return CaptureResult::Idle;
        }

        const auto* ip = reinterpret_cast<const IpHeader*>(data + ethernet_size);
        if ((ip->ver_ihl >> 4) != 4 || ip->protocol != IPPROTO_ICMP) return CaptureResult::Idle;

        const int ip_size = (ip->ver_ihl & 0x0F) * 4;
        if (header->caplen < ethernet_size + ip_size + sizeof(IcmpHeader)) {
            return CaptureResult::Idle;
        }

        const auto* icmp = reinterpret_cast<const IcmpHeader*>(data + ethernet_size + ip_size);
        if (icmp->type != 0) return CaptureResult::Idle;

        reply = {ntohs(icmp->id), ntohs(icmp->seq), ip->ttl};
        return CaptureResult::Reply;
    }

    bool send(std::span<const unsigned char> packet, std::uint32_t destination,
              int ttl, Clock::time_point& sent_at) noexcept override {
        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_addr.S_un.S_addr = destination;

        if (!set_request_ttl(socket_, ttl, default_ttl_)) return false;

        sent_at = Clock::now();
        return sendto(socket_, reinterpret_cast<const char*>(packet.data()),
                      static_cast<int>(packet.size()), 0,
                      reinterpret_cast<const sockaddr*>(&target), sizeof(target)) != SOCKET_ERROR;
    }

    void wake() noexcept override {
        SetEvent(stop_event_);
    }

private:
    Capture capture_;
    SOCKET socket_ = INVALID_SOCKET;
    int default_ttl_ = -1;
    HANDLE capture_event_ = nullptr; // Owned by the pcap handle.
    HANDLE stop_event_ = nullptr;
};

win_engine::Engine& native_engine() {
    // DLL clients stop the engine before unloading. Joining a listener during
    // static destruction can run under the Windows DLL loader lock.
    static auto* const engine = new win_engine::Engine;
    return *engine;
}

} // namespace

namespace win_engine {

class Engine::Session {
public:
    explicit Session(std::unique_ptr<Transport> transport) : transport_(std::move(transport)) {}

    ~Session() {
        if (listener_.joinable()) stop();
    }

    bool start(const StartListener& launch) {
        auto listen = [this] { listen_loop(); };
        listener_ = launch ? launch(listen) : std::thread(listen);
        return listener_.joinable() && available();
    }

    void stop() {
        {
            std::lock_guard lock(mutex_);
            running_ = false;
            fail_pending("Engine stopped");
        }
        transport_->wake();
        listener_.join();
        transport_.reset();
    }

    bool available() const {
        std::lock_guard lock(mutex_);
        return running_;
    }

    PingProbeResult probe(std::uint16_t sequence, std::uint32_t destination,
                          int timeout_ms, int payload_size, int ttl) {
        if (payload_size < 0) return failed_probe("Invalid payload size");
        if (!valid_request_ttl(ttl)) return failed_probe("Invalid TTL");

        IcmpHeader request{};
        request.type = 8;
        request.id = htons(id_);
        request.seq = htons(sequence);

        const std::uint64_t ticks = GetTickCount64();
        std::vector<unsigned char> packet(sizeof(request) + sizeof(ticks) + payload_size, 0);
        std::memcpy(packet.data(), &request, sizeof(request));
        std::memcpy(packet.data() + sizeof(request), &ticks, sizeof(ticks));
        reinterpret_cast<IcmpHeader*>(packet.data())->checksum = checksum16(packet.data(), packet.size());

        auto completion = std::make_shared<std::promise<PingProbeResult>>();
        auto reply = completion->get_future();
        Clock::time_point sent_at;

        {
            std::lock_guard lock(mutex_);
            if (!running_) return failed_probe("Engine socket not available");
            if (!pending_.emplace(sequence, completion).second) {
                return failed_probe("ICMP sequence already in use");
            }

            // Stop waits for any in-progress send, but never for its reply.
            if (!transport_->send(packet, destination, ttl, sent_at)) {
                pending_.erase(sequence);
                return failed_probe("sendto failed");
            }
        }

        if (reply.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) {
            std::lock_guard lock(mutex_);
            const auto entry = pending_.find(sequence);
            if (entry != pending_.end() && entry->second == completion) {
                pending_.erase(entry);
                return failed_probe("Timeout");
            }
            // The listener or shutdown has already completed this waiter.
        }

        auto result = reply.get();
        if (result.success) {
            result.rtt_ms = static_cast<long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - sent_at).count());
        }
        return result;
    }

private:
    void fail_pending(const char* reason) {
        for (auto& [sequence, completion] : pending_) {
            completion->set_value(failed_probe(reason));
        }
        pending_.clear();
    }

    void listen_loop() {
        for (;;) {
            Reply reply{};
            const auto status = transport_->receive(reply);

            std::lock_guard lock(mutex_);
            if (!running_) return;
            if (status == CaptureResult::Failed) {
                running_ = false;
                fail_pending("Engine capture failed");
                return;
            }

            if (status != CaptureResult::Reply || reply.id != id_) continue;

            const auto entry = pending_.find(reply.sequence);
            if (entry == pending_.end()) continue;

            PingProbeResult result{};
            result.success = true;
            result.ttl = reply.ttl;
            entry->second->set_value(std::move(result));
            pending_.erase(entry);
        }
    }

    std::unique_ptr<Transport> transport_;
    std::thread listener_;
    mutable std::mutex mutex_;
    const std::uint16_t id_ = static_cast<std::uint16_t>(GetCurrentProcessId() & 0xFFFF);
    bool running_ = true;
    std::unordered_map<std::uint16_t, std::shared_ptr<std::promise<PingProbeResult>>> pending_;
};

Engine::~Engine() {
    stop();
}

bool Engine::start(const OpenTransport& open, const StartListener& launch) {
    std::lock_guard lock(lifecycle_mutex_);
    if (const auto previous = session_.load()) {
        if (previous->available()) return true;
        previous->stop();
        session_.store(nullptr);
    }

    try {
        auto transport = open();
        if (!transport) return false;

        auto session = std::make_shared<Session>(std::move(transport));
        if (!session->start(launch)) return false;

        session_.store(std::move(session));
        return true;
    } catch (...) {
        return false;
    }
}

void Engine::stop() {
    std::lock_guard lock(lifecycle_mutex_);
    if (const auto session = session_.load()) {
        session->stop();
        session_.store(nullptr);
    }
}

bool Engine::available() const {
    const auto session = session_.load();
    return session && session->available();
}

PingProbeResult Engine::probe(std::uint32_t destination, int timeout_ms, int payload_size, int ttl) {
    const auto session = session_.load();
    if (!session) return failed_probe("Engine socket not available");

    const auto sequence = sequence_.fetch_add(1, std::memory_order_relaxed);
    return session->probe(sequence, destination, timeout_ms, payload_size, ttl);
}

} // namespace win_engine

bool init_engine(const std::string& if_name) {
    return native_engine().start([&if_name]() -> std::unique_ptr<Transport> {
        auto transport = std::make_unique<WindowsTransport>();
        if (!transport->open(if_name)) return nullptr;
        return transport;
    });
}

void shutdown_engine() {
    native_engine().stop();
}

PingProbeResult ping_once_engine(const std::string& ip, int timeout_ms, int payload_size, int ttl) {
    if (!valid_request_ttl(ttl)) return failed_probe("Invalid TTL");

    in_addr destination{};
    if (InetPtonA(AF_INET, ip.c_str(), &destination) != 1) return failed_probe("Invalid IP");

    if (is_local_ipv4_addr(destination)) {
        PingProbeResult probe{};
        probe.success = icmp_ping_local(destination, timeout_ms, probe.rtt_ms, probe.ttl, ttl);
        if (!probe.success) probe.error_msg = "Local ICMP failed";
        return probe;
    }

    return native_engine().probe(destination.S_un.S_addr, timeout_ms, payload_size, ttl);
}

bool engine_available() {
    return native_engine().available();
}

} // namespace cping
