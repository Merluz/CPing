#include "cping/ping.hpp"

#include <array>
#include <cstddef>
#include <csignal>
#include <fstream>
#include <stdexcept>

namespace cping {

PingResult ping_host(const std::string& ip, const PingOptions& opt) {
    if (opt.retries != 1) {
        throw std::logic_error("the CLI must request exactly one probe per backend call");
    }

    static std::size_t call = 0;
    std::ofstream calls("probes.txt", std::ios::app);
    calls << ++call << '\n';
    calls.close();
    if (!calls) {
        throw std::runtime_error("could not record the fixture probe");
    }

    long rtt = -1;
    if (ip == "192.0.2.1") {
        constexpr std::array<long, 3> mixed{-1, 30, 10};
        rtt = mixed.at(call - 1);
    } else if (ip == "192.0.2.3") {
        constexpr std::array<long, 3> all_replies{30, 10, 20};
        rtt = all_replies.at(call - 1);
    } else if (ip == "192.0.2.4") {
        rtt = 0;
    } else if (ip == "192.0.2.5") {
        constexpr std::array<long, 2> interrupted{-1, 14};
        rtt = interrupted.at(call - 1);
    } else if (ip != "192.0.2.2") {
        throw std::invalid_argument("unknown fixture target");
    }

    PingProbeResult probe;
    probe.success = rtt >= 0;
    probe.rtt_ms = rtt;
    if (probe.success) {
        probe.ttl = 64 - static_cast<int>(call);
    } else {
        probe.error_msg = "Fixture timeout";
    }
    if (ip == "192.0.2.5" && call == 2) {
        std::raise(SIGINT);
    }
    return {probe.success, probe.rtt_ms, probe.ttl, {probe}};
}

} // namespace cping
