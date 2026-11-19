#include "stats.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <iostream>
#include <numeric>

PingSummary summarize_ping(std::uint64_t attempts, const std::vector<long>& rtts) {
    PingSummary summary;
    summary.attempts = attempts;
    summary.replies = rtts.size();
    assert(summary.replies <= summary.attempts);

    if (attempts != 0) {
        const auto without_reply = summary.attempts - summary.replies;
        const auto percent = 100.0L * without_reply / summary.attempts;
        summary.without_reply_percent = static_cast<unsigned int>(std::lround(percent));
    }

    if (rtts.empty()) {
        return summary;
    }

    auto& rtt = summary.rtt.emplace();
    const auto samples = static_cast<double>(rtts.size());
    rtt.avg = std::accumulate(rtts.begin(), rtts.end(), 0.0) / samples;

    double squared_diffs = 0.0;
    for (const auto sample : rtts) {
        const auto difference = static_cast<double>(sample) - rtt.avg;
        squared_diffs += difference * difference;
    }
    rtt.stddev = std::sqrt(squared_diffs / samples);

    // Jitter depends on arrival order, so only the copy for the median is sorted.
    if (rtts.size() > 1) {
        double total_change = 0.0;
        for (std::size_t i = 1; i < rtts.size(); ++i) {
            total_change += std::abs(static_cast<double>(rtts[i]) - rtts[i - 1]);
        }
        rtt.jitter = total_change / (samples - 1);
    }

    auto sorted = rtts;
    std::sort(sorted.begin(), sorted.end());
    rtt.min = sorted.front();
    rtt.max = sorted.back();
    const auto mid = sorted.size() / 2;
    rtt.median = static_cast<double>(sorted[mid]);
    if (sorted.size() % 2 == 0) {
        rtt.median = (rtt.median + static_cast<double>(sorted[mid - 1])) / 2.0;
    }

    return summary;
}

void print_summary(const std::string& ip, const PingSummary& summary) {
    std::cout << "--- " << ip << " ping statistics ---\n"
              << summary.attempts << " attempts, "
              << summary.replies << " replies, ";
    if (summary.attempts == 0) {
        std::cout << "loss unavailable\n";
    } else {
        std::cout << summary.without_reply_percent << "% without reply\n";
    }

    if (summary.rtt) {
        const auto& rtt = *summary.rtt;
        std::cout << "rtt min/avg/max/median/mdev/jitter = "
                  << rtt.min << "/" << rtt.avg << "/" << rtt.max << "/"
                  << rtt.median << "/" << rtt.stddev << "/" << rtt.jitter << " ms\n";
    }
}
