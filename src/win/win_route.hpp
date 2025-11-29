#pragma once
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/**
 * Determines the best WinPcap/Npcap device to reach `dst_addr`.
 *
 * Strategy:
 *  - Local address ➜ return loopback device
 *  - Use GetBestInterface() to determine outbound interface
 *  - Match adapter GUID against Npcap device names
 */
pcap_if_t* pick_device_for_target(pcap_if_t* alldevs, const in_addr& dst_addr);

/**
 * Checks whether the given IPv4 address belongs to one of the
 * system’s local interfaces.
 */
bool is_local_ipv4_addr(const in_addr& dst);
