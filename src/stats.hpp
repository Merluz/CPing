#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "export.hpp"

struct RttSummary {
    long min{0};
    double avg{0.0};
    long max{0};
    double median{0.0};
    double stddev{0.0};
    double jitter{0.0};
};

struct PingSummary {
    std::uint64_t attempts{0};
    std::uint64_t replies{0};
    unsigned int without_reply_percent{0};
    std::optional<RttSummary> rtt;
};

PingSummary summarize_ping(std::uint64_t attempts, const std::vector<long>& rtts);
void print_summary(const std::string& ip, const PingSummary& summary);
bool export_summary(const std::string& path, ExportFormat format,
                    const std::string& ip, const PingSummary& summary, bool append);
