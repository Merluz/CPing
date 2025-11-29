/**
 * High-level ping execution logic.
 *
 * Exposes a single entry point used by the CLI frontend.
 * The actual ICMP work is delegated to the cping::ping_host() engine.
 */

#pragma once
#include "cli.hpp"

/**
 * Executes either:
 * - Continuous ping mode
 * - Single/limited-attempt ping mode
 *
 * Handles statistics, terminal formatting, and export logic.
 */
int run_ping(const CliOptions& opt);
