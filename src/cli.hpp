#pragma once
#include <string>
#include "cping/ping.hpp"
#include "export.hpp"

/**
 * Parsed command-line options for the cping executable.
 *
 * This struct is intentionally flat and CLI-oriented, while the
 * internal engine uses cping::PingOptions. Fields are synchronized
 * after parsing.
 */
struct CliOptions {
    std::string ip;               // Target IP (mandatory)

    cping::PingOptions ping;      // Lower-level ping parameters

    bool quiet{false};            // Minimal output
    bool summary{false};          // Only show summary at the end
    bool continuous{false};       // Run until CTRL+C
    bool timestamp{false};        // Prefix per-line output with timestamp

    int interval_ms{1000};        // Continuous mode interval
    int count{-1};                // Number of probes (default infinite in continuous)
    int payload_size{0};          // Extra ICMP payload bytes
    int ttl{-1};                  // Custom TTL

    bool no_color{false};         // Disable ANSI colors

    std::string export_path;      // CSV/JSON export file path
    ExportFormat export_format{ExportFormat::CSV};
    bool export_append{false};    // Append instead of overwrite
};

/**
 * Parse all command-line arguments into a CliOptions struct.
 * Invalid flags produce warnings but parsing continues.
 */
CliOptions parse_args(int argc, char** argv);
