#include "win_route.hpp"
#include <ipifcons.h>
#include <string_view>
#include <vector>

#pragma comment(lib, "Iphlpapi.lib")

namespace {

constexpr ULONG adapter_flags =
    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

ULONG read_ipv4_adapters(ULONG flags, std::vector<unsigned char>& storage) {
    // Windows recommends 15 KiB initially. An interface change can require a retry.
    ULONG size = 15 * 1024;
    for (int attempt = 0; attempt < 3; ++attempt) {
        storage.resize(size);
        const ULONG status = GetAdaptersAddresses(
            AF_INET, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
        if (status != ERROR_BUFFER_OVERFLOW) return status;
    }
    return ERROR_BUFFER_OVERFLOW;
}

std::wstring widen(const char* text) {
    if (!text || !*text) return {};

    UINT code_page = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int count = MultiByteToWideChar(code_page, flags, text, -1, nullptr, 0);
    if (count == 0) {
        // Narrow Windows argv can use the active ANSI code page.
        code_page = CP_ACP;
        flags = 0;
        count = MultiByteToWideChar(code_page, flags, text, -1, nullptr, 0);
    }
    if (count == 0) return {};

    std::wstring result(count, L'\0');
    if (!MultiByteToWideChar(code_page, flags, text, -1, result.data(), count))
        return {};
    result.pop_back();
    return result;
}

bool names_equal(std::wstring_view a, std::wstring_view b) {
    return !a.empty() && a.size() == b.size() &&
        CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
                             b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

std::wstring_view unbraced(std::wstring_view guid) {
    if (guid.size() >= 2 && guid.front() == L'{' && guid.back() == L'}')
        return guid.substr(1, guid.size() - 2);
    return guid;
}

bool is_loopback(const pcap_if_t& device) {
    return (device.flags & PCAP_IF_LOOPBACK) != 0;
}

bool device_matches_adapter(std::wstring_view device_name,
                            const IP_ADAPTER_ADDRESSES& adapter) {
    // Modern Npcap exposes the OS software loopback as a synthetic device.
    if (names_equal(device_name, L"\\Device\\NPF_Loopback"))
        return adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK;

    constexpr std::wstring_view prefix = L"\\Device\\NPF_";
    if (!names_equal(device_name.substr(0, prefix.size()), prefix)) return false;
    return names_equal(unbraced(device_name.substr(prefix.size())),
                       unbraced(widen(adapter.AdapterName)));
}

const IP_ADAPTER_ADDRESSES* adapter_for_device(
    std::wstring_view name, const IP_ADAPTER_ADDRESSES* adapters)
{
    const IP_ADAPTER_ADDRESSES* match = nullptr;
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->IfIndex == 0 || !device_matches_adapter(name, *adapter)) continue;
        if (match) return nullptr;
        match = adapter;
    }
    return match;
}

enum class NameMatch { none, substring, exact };

NameMatch match_name(std::wstring_view request, std::wstring_view alias) {
    if (names_equal(request, alias)) return NameMatch::exact;
    if (request.size() < alias.size() &&
        FindStringOrdinal(FIND_FROMSTART, alias.data(), static_cast<int>(alias.size()),
                          request.data(), static_cast<int>(request.size()), TRUE) >= 0)
        return NameMatch::substring;
    return NameMatch::none;
}

NameMatch match_device_name(std::wstring_view request, std::wstring_view device_name,
                            const IP_ADAPTER_ADDRESSES* adapter)
{
    NameMatch match = match_name(request, device_name);
    if (!adapter || match == NameMatch::exact) return match;

    const auto guid = widen(adapter->AdapterName);
    if (names_equal(unbraced(request), unbraced(guid))) return NameMatch::exact;
    if (adapter->FriendlyName) {
        const NameMatch friendly_match = match_name(request, adapter->FriendlyName);
        if (friendly_match > match) match = friendly_match;
    }
    return match;
}

bool match_interface(pcap_if_t* devices, const IP_ADAPTER_ADDRESSES* adapters,
                     std::wstring_view request, WinPingInterface& selection)
{
    NameMatch rank = NameMatch::none;
    bool ambiguous = false;
    for (auto* device = devices; device; device = device->next) {
        const auto device_name = widen(device->name);
        const auto* adapter = adapter_for_device(device_name, adapters);
        const NameMatch match = match_device_name(request, device_name, adapter);
        if (match == NameMatch::none || match < rank) continue;
        if (match == rank) {
            ambiguous = true;
            continue;
        }
        selection = {device, adapter ? adapter->IfIndex : 0};
        rank = match;
        ambiguous = false;
    }
    return !ambiguous;
}

pcap_if_t* first_non_loopback(pcap_if_t* devices) {
    for (auto* device = devices; device; device = device->next)
        if (device->name && !is_loopback(*device)) return device;
    return nullptr;
}

} // namespace

bool select_win_ping_interface(pcap_if_t* devices, const IP_ADAPTER_ADDRESSES* adapters,
                               const std::string& name, WinPingInterface& selection,
                               std::string& error)
{
    selection = {};
    error.clear();
    const auto request = widen(name.c_str());
    if (request.empty() || name.find('\0') != std::string::npos) {
        error = "Invalid network interface name";
        return false;
    }

    WinPingInterface match;
    if (!match_interface(devices, adapters, request, match)) {
        error = "Ambiguous network interface: " + name;
        return false;
    }
    if (!match.device) {
        error = "Network interface not found: " + name;
        return false;
    }
    if (match.index == 0) {
        error = "Capture device has no matching IPv4 egress interface: " + name;
        return false;
    }

    selection = match;
    return true;
}

bool resolve_win_ping_interface(pcap_if_t* devices, const std::string& name,
                                WinPingInterface& selection, std::string& error)
{
    std::vector<unsigned char> storage;
    const ULONG status = read_ipv4_adapters(adapter_flags | GAA_FLAG_SKIP_UNICAST, storage);
    if (status != NO_ERROR) {
        selection = {};
        error = "Could not enumerate IPv4 network interfaces (Windows error " +
                std::to_string(status) + ")";
        return false;
    }

    const auto* adapters = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(storage.data());
    return select_win_ping_interface(devices, adapters, name, selection, error);
}

bool set_win_ipv4_egress_interface(SOCKET socket, ULONG index, std::string& error) {
    error.clear();
    if (index == 0 || index > 0x00ffffffUL) {
        error = "Invalid IPv4 egress interface index";
        return false;
    }

    // IP_UNICAST_IF expects the IPv4 interface index in network byte order.
    const DWORD value = htonl(index);
    if (setsockopt(socket, IPPROTO_IP, IP_UNICAST_IF,
                   reinterpret_cast<const char*>(&value), sizeof(value)) == SOCKET_ERROR) {
        error = "Could not select IPv4 egress interface (Winsock error " +
                std::to_string(WSAGetLastError()) + ")";
        return false;
    }
    return true;
}

bool is_local_ipv4_addr(const in_addr& dst) {
    std::vector<unsigned char> storage;
    if (read_ipv4_adapters(adapter_flags, storage) != NO_ERROR) return false;

    const auto* adapters = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(storage.data());
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        for (auto* address = adapter->FirstUnicastAddress; address; address = address->Next) {
            if (address->Address.lpSockaddr &&
                address->Address.lpSockaddr->sa_family == AF_INET) {
                const auto* ip = reinterpret_cast<const sockaddr_in*>(address->Address.lpSockaddr);
                if (ip->sin_addr.s_addr == dst.s_addr) return true;
            }
        }
    }
    return false;
}

pcap_if_t* pick_device_for_target(pcap_if_t* devices, const in_addr& dst) {
    if (is_local_ipv4_addr(dst)) {
        for (auto* device = devices; device; device = device->next)
            if (device->name && is_loopback(*device)) return device;
    }

    DWORD index = 0;
    if (GetBestInterface(dst.s_addr, &index) != NO_ERROR)
        return first_non_loopback(devices);

    std::vector<unsigned char> storage;
    if (read_ipv4_adapters(adapter_flags | GAA_FLAG_SKIP_UNICAST, storage) != NO_ERROR)
        return nullptr;

    auto* adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(storage.data());
    while (adapter && adapter->IfIndex != index) adapter = adapter->Next;
    if (!adapter) return nullptr;

    for (auto* device = devices; device; device = device->next)
        if (device_matches_adapter(widen(device->name), *adapter)) return device;

    return first_non_loopback(devices);
}
