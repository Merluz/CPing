#include "runner.hpp"
#include "stats.hpp"
#include "terminal.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <csignal>
#include <iostream>
#include <thread>
#include <vector>

namespace {

std::atomic_flag interrupted{};

void handle_sigint(int) {
    interrupted.test_and_set(std::memory_order_relaxed);
}

void wait_between_attempts(std::chrono::milliseconds interval) {
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + interval;

    // Limit how long Ctrl+C can wait for a pause between probes to finish.
    while (!interrupted.test(std::memory_order_relaxed)) {
        const auto now = Clock::now();
        if (now >= deadline) break;
        std::this_thread::sleep_until(std::min(deadline, now + std::chrono::milliseconds(50)));
    }
}

void print_attempt(const CliOptions& opt, std::uint64_t attempt, const cping::PingResult& result) {
    if (!opt.continuous) std::cout << "Attempt " << attempt << ": ";

    if (result.reachable) {
        if (opt.continuous) {
            std::cout << term::green() << "Reply from " << opt.ip << term::reset()
                      << " RTT=" << result.rtt_ms << "ms TTL=" << result.ttl << '\n';
        } else {
            std::cout << "Reply, RTT=" << result.rtt_ms << "ms, TTL=" << result.ttl << '\n';
        }
    } else {
        const auto reason = result.probes.empty() || result.probes.front().error_msg.empty()
            ? "No reply received"
            : result.probes.front().error_msg;
        std::cout << term::red() << "Failed (" << reason << ")" << term::reset() << '\n';
    }
}

} // namespace

int run_ping(const CliOptions& opt) {
    term::g_enabled = !opt.no_color;
    term::enable_vt();

    const int attempt_limit = opt.count > 0 ? opt.count
        : opt.continuous ? 0 : std::max(1, opt.ping.retries);
    const bool show_attempts = !opt.quiet && !opt.summary;

    interrupted.clear(std::memory_order_relaxed);
    if (opt.continuous && std::signal(SIGINT, handle_sigint) == SIG_ERR) {
        std::cerr << "cping: could not install Ctrl+C handler\n";
        return 1;
    }

    if (show_attempts) {
        std::cout << "Pinging " << opt.ip;
        if (opt.continuous) {
            std::cout << " continuously, interval=" << opt.interval_ms << "ms (CTRL+C to stop)\n";
        } else {
            std::cout << " with " << attempt_limit
                      << " attempt(s), timeout=" << opt.ping.timeout_ms << "ms\n";
        }
    }

    // The CLI owns the attempt budget, including the pause between continuous probes.
    auto probe_options = opt.ping;
    probe_options.retries = 1;

    std::uint64_t attempts = 0;
    std::vector<long> rtts;
    long best_rtt = -1;
    int best_ttl = -1;

    const auto has_attempts_left = [&] {
        return attempt_limit == 0 || attempts < static_cast<std::uint64_t>(attempt_limit);
    };
    while (!interrupted.test(std::memory_order_relaxed) && has_attempts_left()) {
        const auto result = cping::ping_host(opt.ip, probe_options);
        ++attempts;
        if (result.reachable) {
            if (rtts.empty() || result.rtt_ms < best_rtt) {
                best_rtt = result.rtt_ms;
                best_ttl = result.ttl;
            }
            rtts.push_back(result.rtt_ms);
        }

        if (show_attempts) print_attempt(opt, attempts, result);
        if (opt.continuous && has_attempts_left()) {
            wait_between_attempts(std::chrono::milliseconds(opt.interval_ms));
        }
    }

    const auto summary = summarize_ping(attempts, rtts);
    if (opt.summary || opt.continuous) {
        print_summary(opt.ip, summary);
    } else if (summary.replies > 0) {
        std::cout << term::green() << "Reply from " << opt.ip << term::reset()
                  << " RTT=" << best_rtt << "ms TTL=" << best_ttl << '\n';
    } else {
        std::cout << term::red() << "Host " << opt.ip << " not reachable" << term::reset() << '\n';
    }

    if (!opt.export_path.empty()
        && !export_summary(opt.export_path, opt.export_format, opt.ip, summary, opt.export_append)) {
        std::cerr << "cping: could not write summary to " << opt.export_path << '\n';
        return 1;
    }

    return summary.replies > 0 ? 0 : 1;
}
