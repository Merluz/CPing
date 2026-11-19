#pragma once

#include "cping/ping.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <thread>

namespace cping::win_engine {

struct Reply {
    std::uint16_t id;
    std::uint16_t sequence;
    int ttl;
};

enum class CaptureResult { Reply, Idle, Failed };
using Clock = std::chrono::high_resolution_clock;

class Transport {
public:
    virtual ~Transport() = default;

    virtual CaptureResult receive(Reply& reply) noexcept = 0;
    virtual bool send(std::span<const unsigned char> packet, std::uint32_t destination,
                      int ttl, Clock::time_point& sent_at) noexcept = 0;
    virtual void wake() noexcept = 0;
};

using OpenTransport = std::function<std::unique_ptr<Transport>()>;
using StartListener = std::function<std::thread(std::function<void()>)>;

struct Interface {
    std::uint32_t index = 0;
    std::string name;
};

class Engine {
public:
    ~Engine();

    bool start(const OpenTransport& open, const StartListener& launch = {}, Interface selection = {});
    void stop();
    bool available() const;
    bool interface_pinned() const;
    PingProbeResult probe(std::uint32_t destination, int timeout_ms, int payload_size, int ttl);

private:
    class Session;

    std::mutex lifecycle_mutex_;
    std::atomic<std::shared_ptr<Session>> session_;
    std::atomic<std::uint16_t> sequence_{1};
};

} // namespace cping::win_engine
