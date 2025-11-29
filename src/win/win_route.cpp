/**
 * Windows routing & interface selection helpers.
 *
 * Responsibilities:
 * - Detect whether a target IPv4 belongs to a local interface
 * - Select the best WinPcap/Npcap device for a given destination IP
 *   using GetBestInterface + adapter GUID matching
 *
 * Used internally by the Windows ICMP backend (ping_win.cpp).
 */

#include "win_route.hpp"
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <iostream>

#pragma comment(lib, "Iphlpapi.lib")

// ---------------------------------------------------------------------------
// Utility: check if a pcap device is loopback
// ---------------------------------------------------------------------------
static inline bool is_loopback(const pcap_if_t* d) {
    return (d->flags & PCAP_IF_LOOPBACK) != 0;
}


// ---------------------------------------------------------------------------
// Determines whether `dst` matches one of the local IPv4 addresses.
// ---------------------------------------------------------------------------
/**
 * Checks whether the given IPv4 address belongs to one of the
 * local interfaces (unicast addresses).
 *
 * @return true if `dst` is a local IP.
 */
bool is_local_ipv4_addr(const in_addr& dst) {
    ULONG sz = 0;

    // First call: get required buffer size
    GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX,
        nullptr,
        nullptr,
        &sz
    );

    if (sz == 0)
        return false;

    std::vector<unsigned char> buf(sz);
    auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

    // Second call: retrieve adapter info
    if (GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            aa,
            &sz
        ) != NO_ERROR)
    {
        return false;
    }

    for (auto* a = aa; a; a = a->Next) {
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr &&
                u->Address.lpSockaddr->sa_family == AF_INET)
            {
                auto* sa = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
                if (sa->sin_addr.S_un.S_addr == dst.S_un.S_addr)
                    return true;
            }
        }
    }

    return false;
}


// ---------------------------------------------------------------------------
// Select best WinPcap device for the given target
// ---------------------------------------------------------------------------
/**
 * Picks the best Npcap/WinPcap device to reach `dst_addr`.
 *
 * Selection strategy:
 * 1. If destination is local ➜ return loopback interface
 * 2. Use GetBestInterface() to find best outbound interface index
 * 3. Match adapter GUID to corresponding pcap device name
 * 4. Fallback: first non-loopback device
 *
 * @return matching pcap_if_t*, or nullptr if none is suitable.
 */
pcap_if_t* pick_device_for_target(pcap_if_t* alldevs, const in_addr& dst_addr) {

    // Fast-path: local ping => loopback device
    if (is_local_ipv4_addr(dst_addr)) {
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK)
                return d; // ex: Npcap Loopback Adapter
        }
    }

    // Determine best outbound interface (interface index)
    DWORD ifIndex = 0;
    if (GetBestInterface(dst_addr.S_un.S_addr, &ifIndex) != NO_ERROR) {
        // Fallback: pick first non-loopback interface
        for (pcap_if_t* d = alldevs; d; d = d->next)
            if (!is_loopback(d))
                return d;
        return nullptr;
    }

    // Retrieve full adapter list to match GUID
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                         nullptr, nullptr, &sz);

    std::vector<unsigned char> buf(sz);
    auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, aa, &sz) != NO_ERROR)
    {
        return nullptr;
    }

    // Locate adapter matching the selected interface index
    const IP_ADAPTER_ADDRESSES* match = nullptr;
    for (auto* a = aa; a; a = a->Next) {
        if (a->IfIndex == ifIndex) {
            match = a;
            break;
        }
    }

    if (!match || !match->AdapterName)
        return nullptr;

    // AdapterName is typically "{GUID}"
    std::string guid = match->AdapterName;
    std::string guidCurly =
        (guid.size() && guid.front() == '{' && guid.back() == '}')
            ? guid
            : ("{" + guid + "}");  // Normalize for Npcap

#ifdef LIBPING_DEBUG
    std::wcout << L"[DBG] FriendlyName: "
               << (match->FriendlyName ? match->FriendlyName : L"(null)")
               << L"\n";
    std::cout << "[DBG] AdapterName: " << guid
              << "\n[DBG] Searching for matching Npcap device: "
              << guidCurly << "\n";
#endif

    // Match by GUID substring inside device name
    for (pcap_if_t* d = alldevs; d; d = d->next) {
#ifdef LIBPING_DEBUG
        if (d->name)
            std::cout << "    [CHK] " << d->name << "\n";
#endif
        if (d->name &&
            std::string(d->name).find(guidCurly) != std::string::npos)
        {
#ifdef LIBPING_DEBUG
            std::cout << "[DBG] Matched device: " << d->name << "\n";
#endif
            return d;
        }
    }

    // Final fallback: any non-loopback device
    for (pcap_if_t* d = alldevs; d; d = d->next)
        if (!is_loopback(d))
            return d;

    return nullptr;
}
