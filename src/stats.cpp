#include "stats.hpp"
#include <iostream>
#include <vector>
#include <limits>
#include <cmath>
#include <algorithm>

using namespace cping;

/**
 * Print a full summary block for classic (non-continuous) ping mode.
 *
 * Computes:
 *  - packet loss
 *  - min / avg / max RTT
 *  - median RTT
 *  - standard deviation (mdev)
 *  - jitter (temporal variation)
 *
 * The `probes` vector preserves probe order exactly as sent.
 */
void print_summary(const std::string& ip, int sent,
                   const std::vector<PingProbeResult>& probes)
{
    int received = 0;
    long min_rtt = std::numeric_limits<long>::max();
    long max_rtt = std::numeric_limits<long>::min();
    long sum_rtt = 0;

    // Store RTTs in temporal order
    std::vector<long> rtts;
    rtts.reserve(probes.size());

    for (const auto& p : probes) {
        if (p.success) {
            received++;
            min_rtt = std::min(min_rtt, p.rtt_ms);
            max_rtt = std::max(max_rtt, p.rtt_ms);
            sum_rtt += p.rtt_ms;
            rtts.push_back(p.rtt_ms);
        }
    }

    int loss = sent > 0 ? (100 - (received * 100 / sent)) : 100;

    std::cout << "--- " << ip << " ping statistics ---\n";
    std::cout << sent << " packets transmitted, "
              << received << " received, "
              << loss << "% packet loss\n";

    if (received == 0) return;

    const double avg = static_cast<double>(sum_rtt) / received;

    // --- Jitter (temporal variation; no sorting)
    double jitter = 0.0;
    if (rtts.size() > 1) {
        long sum_diff = 0;
        for (size_t i = 1; i < rtts.size(); ++i)
            sum_diff += std::abs(rtts[i] - rtts[i - 1]);
        jitter = static_cast<double>(sum_diff) / (rtts.size() - 1);
    }

    // --- Median (requires sorted copy)
    auto sorted = rtts;
    std::sort(sorted.begin(), sorted.end());
    double median = (sorted.size() % 2 == 0)
        ? (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0
        : sorted[sorted.size()/2];

    // --- Standard deviation (mdev)
    double var = 0.0;
    for (auto r : rtts) var += (r - avg) * (r - avg);
    var /= rtts.size();
    const double stddev = std::sqrt(var);

    std::cout << "rtt min/avg/max/median/mdev/jitter = "
              << min_rtt << "/"
              << avg << "/"
              << max_rtt << "/"
              << median << "/"
              << stddev << "/"
              << jitter << " ms\n";
}

/**
 * Variant used when running with the --continuous flag.
 *
 * The caller maintains:
 *  - sent / received counters
 *  - rolling min/max/sum RTT
 *  - full RTT vector (temporal order)
 *
 * This function performs the same statistical calculations as print_summary(),
 * but avoids re-scanning probe structures.
 */
void print_summary_continuous(const std::string& ip, int sent, int received,
                              long min_rtt, long max_rtt, long sum_rtt,
                              const std::vector<long>& rtts)
{
    int loss = sent > 0 ? (100 - (received * 100 / sent)) : 100;

    std::cout << "\n--- " << ip << " ping statistics ---\n";
    std::cout << sent << " packets transmitted, "
              << received << " received, "
              << loss << "% packet loss\n";

    if (received == 0) return;

    const double avg = static_cast<double>(sum_rtt) / received;

    // --- Jitter (temporal order)
    double jitter = 0.0;
    if (rtts.size() > 1) {
        long sum_diff = 0;
        for (size_t i = 1; i < rtts.size(); ++i)
            sum_diff += std::abs(rtts[i] - rtts[i - 1]);
        jitter = static_cast<double>(sum_diff) / (rtts.size() - 1);
    }

    // --- Median
    auto sorted = rtts;
    std::sort(sorted.begin(), sorted.end());
    double median = (sorted.size() % 2 == 0)
        ? (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0
        : sorted[sorted.size()/2];

    // --- Standard deviation
    double var = 0.0;
    for (auto r : rtts) var += (r - avg) * (r - avg);
    var /= rtts.size();
    const double stddev = std::sqrt(var);

    std::cout << "rtt min/avg/max/median/mdev/jitter = "
              << min_rtt << "/"
              << avg << "/"
              << max_rtt << "/"
              << median << "/"
              << stddev << "/"
              << jitter << " ms\n";
}
