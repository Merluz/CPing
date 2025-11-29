/**
 * C API wrapper for cping (C++ backend).
 *
 * Exposes a stable C ABI for:
 * - Basic ICMP ping (blocking)
 * - Extended ping options
 * - Optional high-performance engine (pcap + raw socket)
 *
 * This layer is meant for consumption by C projects or foreign
 * language bindings (e.g., Rust, Go, Python FFI).
 */

#include "cping_capi.h"
#include "cping/ping.hpp"
#include "cping/engine.hpp"

#include <string>

using namespace cping;

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------
static void to_out(const PingResult& in, CPingResultC* out) {
    if (!out) return;
    out->reachable = in.reachable ? 1 : 0;
    out->rtt_ms    = in.rtt_ms;
    out->ttl       = in.ttl;
}

static void to_out_probe(const PingProbeResult& in, CPingResultC* out) {
    if (!out) return;
    out->reachable = in.success ? 1 : 0;
    out->rtt_ms    = in.rtt_ms;
    out->ttl       = in.ttl;
}


// ---------------------------------------------------------------------------
// C API implementation
// ---------------------------------------------------------------------------
extern "C" {

// ---------------------------------------------------------------------------
// Basic ping
// ---------------------------------------------------------------------------
CPING_API int cping_ping_host(const char* ip,
                              int timeout_ms,
                              struct CPingResultC* out)
{
    if (!ip || !out) return 0;

    PingResult r = ping_host(std::string(ip), timeout_ms);
    to_out(r, out);
    return 1;
}


// ---------------------------------------------------------------------------
// Extended ping (C options → C++ options)
// ---------------------------------------------------------------------------
CPING_API int cping_ping_host_ex(const char* ip,
                                 const struct CPingOptionsC* optC,
                                 struct CPingResultC* out)
{
    if (!ip || !out) return 0;

    PingOptions opt{};

    if (optC) {
        opt.timeout_ms = (optC->timeout_ms > 0) ? optC->timeout_ms : 1000;
        opt.retries    = (optC->retries > 0)    ? optC->retries    : 1;
        opt.payload_size = (optC->payload_size >= 0) ? optC->payload_size : 0;
        opt.ttl = (optC->ttl >= 0) ? optC->ttl : -1;

        opt.stop_on_first_success = (optC->stop_on_first_success != 0);

        if (optC->if_name)
            opt.if_name = optC->if_name;
    }

    PingResult r = ping_host(std::string(ip), opt);
    to_out(r, out);
    return 1;
}



// ---------------------------------------------------------------------------
// Engine API (pcap + raw socket + listener thread)
// ---------------------------------------------------------------------------
CPING_API int cping_init_engine(const char* if_name) {
    std::string dev = if_name ? if_name : "";
    return init_engine(dev) ? 1 : 0;
}

CPING_API void cping_shutdown_engine() {
    shutdown_engine();
}

CPING_API int cping_ping_once_engine(const char* ip,
                                     int timeout_ms,
                                     int payload_size,
                                     int ttl,
                                     struct CPingResultC* out)
{
    if (!ip || !out) return 0;

    auto res = ping_once_engine(
        std::string(ip),
        timeout_ms,
        payload_size,
        ttl
    );

    to_out_probe(res, out);
    return 1;
}

CPING_API int cping_engine_available() {
    return engine_available() ? 1 : 0;
}

} // extern "C"
