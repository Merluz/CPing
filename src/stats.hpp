#pragma once
#include <string>
#include <vector>
#include "cping/ping.hpp"

/**
 * Print summary statistics for classic ping mode.
 *
 * Accepts the complete probe list and computes:
 *  - min / avg / max RTT
 *  - median RTT
 *  - standard deviation (mdev)
 *  - jitter (temporal)
 *  - packet loss
 */
void print_summary(const std::string& ip,
                   int sent,
                   const std::vector<cping::PingProbeResult>& probes);

/**
 * Print summary statistics for continuous ping mode.
 *
 * The caller maintains rolling statistics and a vector of RTTs
 * in temporal order; this function performs the derived metrics.
 */
void print_summary_continuous(const std::string& ip,
                              int sent,
                              int received,
                              long min_rtt,
                              long max_rtt,
                              long sum_rtt,
                              const std::vector<long>& rtts);
