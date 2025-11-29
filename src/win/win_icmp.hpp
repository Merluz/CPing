#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

/**
 * Sends a raw ICMP Echo Request (type=8).
 *
 * @return true if sendto() succeeds.
 */
bool send_icmp_echo_raw(const in_addr& dst,
                        uint16_t id,
                        uint16_t seq,
                        const void* payload,
                        size_t len,
                        int ttl = -1);

/**
 * Performs a local ping using the OS ICMP API (IcmpSendEcho).
 * Works also for self-ping without WinPcap.
 */
bool icmp_ping_local(const in_addr& dst,
                     int timeout_ms,
                     long& out_rtt_ms,
                     int& out_ttl);

/**
 * Ensures Winsock initialization (WSAStartup).
 */
bool ensure_wsa();
