#pragma once
#include <string>
#include <vector>
#include "cping/visibility.hpp"

namespace cping {

/**
 * Represents the result of a single ICMP probe.
 */
struct PingProbeResult {
    bool success{false};           // Whether a valid reply was received
    long rtt_ms{-1};               // RTT in milliseconds (-1 = invalid)
    int  ttl{-1};                  // Observed TTL (-1 = invalid)
    std::string if_name;           // Interface used (optional)
    std::string error_msg;         // Error detail (empty if success=true)
};

/**
 * Aggregated result of multiple probes.
 *
 * Contains:
 * - Best RTT/TTL observed
 * - Full trace of all probe attempts
 */
struct PingResult {
    bool reachable{false};                // At least one successful reply
    long rtt_ms{-1};                      // Best RTT in ms
    int  ttl{-1};                         // TTL associated with best RTT
    std::vector<PingProbeResult> probes;  // Details for each attempt
};

/**
 * Options for ping execution.
 */
struct PingOptions {
    int timeout_ms{1000};                 // Timeout per probe (ms)
    int retries{1};                       // Number of sequential attempts
    std::string if_name;                  // Interface name/substring filter
    bool stop_on_first_success{true};     // Early exit on first valid reply
    int payload_size{0};                  // Extra payload bytes after timestamp
    int ttl{-1};                          // Custom TTL, -1 = system default
    bool timestamp{false};                // Print timestamp in CLI output
};

/**
 * Legacy signature for compatibility.
 */
CPING_API PingResult ping_host(const std::string& ip, int timeout_ms);

/**
 * Recommended API supporting full options.
 */
CPING_API PingResult ping_host(const std::string& ip, const PingOptions& opt);

} // namespace cping
