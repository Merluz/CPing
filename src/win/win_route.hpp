#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <string>

struct WinPingInterface {
    pcap_if_t* device{nullptr};
    ULONG index{0};
};

// An explicit selection identifies both an Npcap capture and an IPv4 egress.
// Exact device names, GUIDs, and friendly names take precedence over substrings.
bool select_win_ping_interface(pcap_if_t* devices, const IP_ADAPTER_ADDRESSES* adapters,
                               const std::string& name, WinPingInterface& selection,
                               std::string& error);

bool resolve_win_ping_interface(pcap_if_t* devices, const std::string& name,
                                WinPingInterface& selection, std::string& error);

bool set_win_ipv4_egress_interface(SOCKET socket, ULONG index, std::string& error);

// Automatic capture selection follows the destination's IPv4 route.
pcap_if_t* pick_device_for_target(pcap_if_t* alldevs, const in_addr& dst_addr);

bool is_local_ipv4_addr(const in_addr& dst);
