/**
 * Runner: orchestrates ping sessions.
 *
 * This module handles:
 * - Continuous ping loop (SIGINT-driven)
 * - Single-shot or multi-attempt pings
 * - RTT statistics (min/max/avg)
 * - Terminal color formatting
 * - Exporting results to file
 *
 * The low-level ICMP logic is provided by cping::ping_host().
 */

#include "runner.hpp"
#include "cping/ping.hpp"
#include "stats.hpp"
#include "terminal.hpp"
#include "export.hpp"

#include <iostream>
#include <csignal>
#include <chrono>
#include <thread>
#include <limits>
#include <vector>
#include <algorithm>

using namespace cping;

// Global flag toggled by CTRL+C
static bool keep_running = true;

/**
 * SIGINT handler for continuous mode.
 * Simply toggles a shared flag so the loop can exit gracefully.
 */
void handle_sigint(int) {
    keep_running = false;
}

/**
 * Main execution entry for CLI ping.
 *
 * Behavior:
 * - If continuous: loops until interrupted, printing live results + summary
 * - If normal mode: performs N attempts, gathers probe data and prints summary
 *
 * The function never throws; returns 0 on success, 1 on unreachable host.
 */
int run_ping(const CliOptions& opt) {
    // Terminal configuration
    term::g_enabled = !opt.no_color;
    term::enable_vt();

    // -------------------------------------------------------------
    // CONTINUOUS MODE
    // -------------------------------------------------------------
    if (opt.continuous) {
        std::signal(SIGINT, handle_sigint);

        std::cout << "Pinging " << opt.ip
                  << " continuously, interval=" << opt.interval_ms << "ms"
                  << " (CTRL+C to stop)\n";

        int sent = 0, received = 0;
        long min_rtt = std::numeric_limits<long>::max();
        long max_rtt = std::numeric_limits<long>::min();
        long sum_rtt = 0;
        std::vector<long> rtts;

        while (keep_running && (opt.count < 0 || sent < opt.count)) {
            sent++;

            auto res = ping_host(opt.ip, opt.ping);

            if (res.reachable) {
                received++;

                // Update RTT stats
                min_rtt = std::min(min_rtt, res.rtt_ms);
                max_rtt = std::max(max_rtt, res.rtt_ms);
                sum_rtt += res.rtt_ms;
                rtts.push_back(res.rtt_ms);

                std::cout << term::green() << "Reply from " << opt.ip
                          << term::reset() << " RTT=" << res.rtt_ms
                          << "ms TTL=" << res.ttl << "\n";
            } else {
                std::cout << term::red() << "Request timed out"
                          << term::reset() << "\n";
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(opt.interval_ms)
            );
        }

        // Post-loop summary
        print_summary_continuous(
            opt.ip, sent, received,
            min_rtt, max_rtt, sum_rtt, rtts
        );

        // Optional export
        if (!opt.export_path.empty()) {
            export_summary_continuous(
                opt.export_path, opt.export_format,
                opt.ip, sent, received,
                min_rtt, max_rtt, sum_rtt, rtts,
                opt.export_append
            );
        }

        return 0;
    }

    // -------------------------------------------------------------
    // NORMAL MODE (single or multi-attempt)
    // -------------------------------------------------------------
    PingResult res{};
    int total_attempts = (opt.count > 0)
        ? opt.count
        : std::max<int>(1, opt.ping.retries);

    // Run attempts and merge probe data
    for (int i = 0; i < total_attempts; ++i) {
        auto attempt = ping_host(opt.ip, opt.ping);

        // Append all probes from this attempt
        res.probes.insert(
            res.probes.end(),
            attempt.probes.begin(),
            attempt.probes.end()
        );

        // Track best RTT
        if (attempt.reachable) {
            if (!res.reachable || attempt.rtt_ms < res.rtt_ms) {
                res = attempt;
            }
        }
    }

    // Optional detailed per-attempt output
    if (!opt.quiet && !opt.summary) {
        std::cout << "Pinging " << opt.ip
                  << " with " << total_attempts
                  << " attempt(s), timeout=" << opt.ping.timeout_ms << "ms\n";

        int idx = 1;
        for (const auto& probe : res.probes) {
            std::cout << "Attempt " << idx++ << ": ";
            if (probe.success) {
                std::cout << "Reply, RTT=" << probe.rtt_ms
                          << "ms, TTL=" << probe.ttl << "\n";
            } else {
                std::cout << "Failed (" << probe.error_msg << ")\n";
            }
        }
    }

    // Final outcome
    if (res.reachable) {
        if (opt.summary) {
            print_summary(
                opt.ip,
                static_cast<int>(res.probes.size()),
                res.probes
            );

            if (!opt.export_path.empty()) {
                export_summary(
                    opt.export_path, opt.export_format,
                    opt.ip,
                    static_cast<int>(res.probes.size()),
                    res.probes,
                    opt.export_append
                );
            }
        } else {
            std::cout << term::green() << "Reply from " << opt.ip
                      << term::reset() << " RTT=" << res.rtt_ms
                      << "ms TTL=" << res.ttl << "\n";
        }
        return 0;
    }

    std::cout << term::red()
              << "Host " << opt.ip << " not reachable"
              << term::reset() << "\n";
    return 1;
}
