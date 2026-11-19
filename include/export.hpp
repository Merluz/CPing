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
 * Optional: export raw probes line-by-line (CSV only).
 */
bool export_probes_csv(const std::string& path,
                       const std::string& ip,
                       const std::vector<cping::PingProbeResult>& probes,
                       bool append = false);
