#pragma once
#include <string>
#include "ping.hpp"

namespace cping {

/**
 * Initializes the global ICMP engine.
 * Opens WinPcap capture + raw ICMP socket + listener thread.
 *
 * @param if_name Optional interface substring; empty = auto-select.
 */
bool init_engine(const std::string& if_name = "");

/**
 * Shuts down the engine and releases all resources.
 * Safely resolves outstanding futures.
 */
void shutdown_engine();

/**
 * Executes a single ICMP probe using the shared engine.
 * Returns the best matching PingProbeResult.
 */
PingProbeResult ping_once_engine(const std::string& ip,
                                 int timeout_ms,
                                 int payload_size = 0,
                                 int ttl = -1);

/**
 * @return true if init_engine() was successfully started.
 */
bool engine_available();

} // namespace cping
