#pragma once
#include <pcap.h>
#include <string>
#include <functional>
#include <chrono>

#include "cping/ip.hpp"
#include "cping/icmp.hpp"

/**
 * Small RAII wrapper for pcap handles.
 */
struct Capture {
    pcap_t* h{nullptr};
    ~Capture() { if (h) pcap_close(h); }
};

/**
 * Opens a live capture on a device in promiscuous mode.
 */
bool open_capture(Capture& cap,
                  const char* dev_name,
                  int timeout_ms,
                  char errbuf[PCAP_ERRBUF_SIZE]);

/**
 * Applies an ICMP filter for the given host.
 */
bool apply_icmp_filter(Capture& cap, const std::string& ip);

/**
 * Receives ICMP packets until:
 *   - on_pkt(...) returns true
 *   - deadline expires
 *
 * Callback receives parsed IP + ICMP headers.
 */
bool recv_icmp_until(
    Capture& cap,
    const std::function<bool(const IpHeader*,
                              const IcmpHeader*,
                              const unsigned char*,
                              size_t)>& on_pkt,
    std::chrono::steady_clock::time_point deadline);
