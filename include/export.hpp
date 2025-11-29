#pragma once
#include <string>
#include <vector>
#include "cping/ping.hpp"

/**
 * Supported export formats.
 */
enum class ExportFormat {
    CSV,
    JSON
};

/**
 * Export summary from a standard ping run (non-continuous).
 * Statistics are computed from the full vector of probes.
 */
bool export_summary(const std::string& path,
                    ExportFormat fmt,
                    const std::string& ip,
                    int sent,
                    const std::vector<cping::PingProbeResult>& probes,
                    bool append = false);

/**
 * Export summary from continuous mode.
 * This version receives already-accumulated data.
 */
bool export_summary_continuous(const std::string& path,
                               ExportFormat fmt,
                               const std::string& ip,
                               int sent, int received,
                               long min_rtt, long max_rtt, long sum_rtt,
                               const std::vector<long>& rtts,
                               bool append = false);

/**
 * Optional: export raw probes line-by-line (CSV only).
 */
bool export_probes_csv(const std::string& path,
                       const std::string& ip,
                       const std::vector<cping::PingProbeResult>& probes,
                       bool append = false);
