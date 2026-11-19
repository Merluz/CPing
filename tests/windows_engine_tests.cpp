#include "win/win_engine_session.hpp"

#include "cping/icmp.hpp"

#include <winsock2.h>

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>

namespace {

using cping::PingProbeResult;
using namespace cping::win_engine;
using namespace std::chrono_literals;

constexpr auto prompt = 2s;
constexpr int probe_timeout_ms = 20000;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct FakeCapture {
    std::mutex mutex;
    std::condition_variable changed;
    std::optional<Reply> sent;
    std::optional<Reply> incoming;
    bool failed = false;
    bool woken = false;
    int close_count = 0;

    bool wait_for_send() {
        std::unique_lock lock(mutex);
        return changed.wait_for(lock, prompt, [&] { return sent.has_value(); });
    }

    void reply_to_probe() {
        std::lock_guard lock(mutex);
        incoming = sent;
        changed.notify_all();
    }

    void fail_capture() {
        std::lock_guard lock(mutex);
        failed = true;
        changed.notify_all();
    }

    int closes() {
        std::lock_guard lock(mutex);
        return close_count;
    }
};

class FakeTransport final : public Transport {
public:
    explicit FakeTransport(FakeCapture& capture) : capture_(capture) {}

    ~FakeTransport() override {
        std::lock_guard lock(capture_.mutex);
        ++capture_.close_count;
    }

    CaptureResult receive(Reply& reply) noexcept override {
        std::unique_lock lock(capture_.mutex);
        capture_.changed.wait(lock, [&] {
            return capture_.failed || capture_.woken || capture_.incoming.has_value();
        });
        if (capture_.failed) return CaptureResult::Failed;
        if (capture_.woken) return CaptureResult::Idle;

        reply = *capture_.incoming;
        capture_.incoming.reset();
        return CaptureResult::Reply;
    }

    bool send(std::span<const unsigned char> packet, std::uint32_t, int,
              Clock::time_point& sent_at) noexcept override {
        if (packet.size() < sizeof(IcmpHeader)) return false;

        IcmpHeader header{};
        std::memcpy(&header, packet.data(), sizeof(header));
        std::lock_guard lock(capture_.mutex);
        sent_at = Clock::now();
        capture_.sent = Reply{ntohs(header.id), ntohs(header.seq), 73};
        capture_.changed.notify_all();
        return true;
    }

    void wake() noexcept override {
        std::lock_guard lock(capture_.mutex);
        capture_.woken = true;
        capture_.changed.notify_all();
    }

private:
    FakeCapture& capture_;
};

auto open_fake(FakeCapture& capture) {
    return [&capture] { return std::make_unique<FakeTransport>(capture); };
}

std::future<PingProbeResult> launch_probe(Engine& engine, FakeCapture& capture) {
    auto result = std::async(std::launch::async, [&engine] {
        return engine.probe(htonl(0xc0000201), probe_timeout_ms, 0, -1);
    });
    if (!capture.wait_for_send()) {
        engine.stop();
        throw std::runtime_error("probe did not reach the fake transport");
    }
    return result;
}

PingProbeResult complete_probe(std::future<PingProbeResult>& result) {
    require(result.wait_for(prompt) == std::future_status::ready, "probe did not finish promptly");
    return result.get();
}

void expect_reply(Engine& engine, FakeCapture& capture) {
    auto result = launch_probe(engine, capture);
    capture.reply_to_probe();
    auto reply = complete_probe(result);
    require(reply.success && reply.ttl == 73 && reply.rtt_ms >= 0, "restarted engine did not deliver a reply");
}

void expect_failure(const PingProbeResult& result, std::string_view message) {
    require(!result.success && result.rtt_ms == -1 && result.ttl == -1, "failure retained reply metadata");
    require(result.error_msg == message, "unexpected engine failure reason");
}

void test_init() {
    FakeCapture failed_launch;
    FakeCapture running;
    Engine engine;

    require(!engine.start([] { return std::unique_ptr<Transport>{}; }), "open failure succeeded");
    require(!engine.available(), "engine remained available after open failure");

    const auto fail_to_launch = [](std::function<void()>) -> std::thread {
        throw std::runtime_error("fixture listener launch failure");
    };
    require(!engine.start(open_fake(failed_launch), fail_to_launch), "listener launch failure succeeded");
    require(!engine.available(), "engine remained available after launch failure");
    require(failed_launch.closes() == 1, "launch rollback retained its transport");

    require(engine.start(open_fake(running)), "initialization after failure failed");
    require(engine.available(), "engine unavailable after initialization");
    expect_reply(engine, running);
    engine.stop();
    require(running.closes() == 1, "shutdown retained its transport");
}

void test_stop() {
    FakeCapture before;
    FakeCapture after;
    Engine engine;

    require(engine.start(open_fake(before)), "initialization failed");
    auto result = launch_probe(engine, before);
    const auto started = std::chrono::steady_clock::now();
    engine.stop();
    require(std::chrono::steady_clock::now() - started < prompt, "shutdown took too long");
    expect_failure(complete_probe(result), "Engine stopped");
    require(!engine.available(), "engine remained available after shutdown");
    require(before.closes() == 1, "shutdown retained its transport");

    engine.stop();
    require(before.closes() == 1, "second shutdown closed the transport again");
    require(engine.start(open_fake(after)), "restart after shutdown failed");
    expect_reply(engine, after);
    engine.stop();
    require(after.closes() == 1, "shutdown after restart retained its transport");
}

void test_capture_failure() {
    FakeCapture before;
    FakeCapture after;
    Engine engine;

    require(engine.start(open_fake(before)), "initialization failed");
    auto result = launch_probe(engine, before);
    before.fail_capture();
    expect_failure(complete_probe(result), "Engine capture failed");
    require(!engine.available(), "engine remained available after capture failure");
    expect_failure(engine.probe(htonl(0xc0000201), probe_timeout_ms, 0, -1), "Engine socket not available");

    require(engine.start(open_fake(after)), "restart after capture failure failed");
    require(before.closes() == 1, "restart retained the failed transport");
    expect_reply(engine, after);
    engine.stop();
}

} // namespace

int main(int argc, char** argv) {
    const std::string_view test = argc == 2 ? argv[1] : "";
    try {
        if (test == "init") test_init();
        else if (test == "stop") test_stop();
        else if (test == "capture-failure") test_capture_failure();
        else throw std::runtime_error("expected init, stop, or capture-failure");
    } catch (const std::exception& error) {
        std::cerr << test << ": " << error.what() << '\n';
        return 1;
    }
    return 0;
}
