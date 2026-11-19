#include "win/win_route.hpp"

#include <ipifcons.h>
#include <iostream>
#include <string_view>

namespace {

struct InterfaceFixture {
    std::string ethernet_guid = "{AABBCCDD-1234-5678-1111-111111111111}";
    std::string lab_guid = "{DDEEFFAA-1234-5678-2222-222222222222}";
    std::string wifi_guid = "{1234ABCD-1234-5678-3333-333333333333}";
    std::string ethernet_device = "\\Device\\NPF_{AABBCCDD-1234-5678-1111-111111111111}";
    std::string lab_device = "\\Device\\NPF_{DDEEFFAA-1234-5678-2222-222222222222}";
    std::string wifi_device = "\\Device\\NPF_{1234ABCD-1234-5678-3333-333333333333}";
    std::string loopback_device = "\\Device\\NPF_Loopback";
    std::string orphan_device = "\\Device\\NPF_Unmapped";
    std::wstring ethernet_name = L"Ethernet";
    std::wstring lab_name = L"Ethernet Lab";
    std::wstring wifi_name = L"R\u00e9seau local";
    std::wstring loopback_name = L"Loopback Pseudo-Interface";

    IP_ADAPTER_ADDRESSES ethernet_adapter{}, lab_adapter{}, wifi_adapter{}, loopback_adapter{};
    pcap_if_t ethernet{}, lab{}, wifi{}, loopback{}, orphan{};

    InterfaceFixture() {
        ethernet_adapter.IfIndex = 10;
        ethernet_adapter.AdapterName = ethernet_guid.data();
        ethernet_adapter.FriendlyName = ethernet_name.data();
        ethernet_adapter.Next = &lab_adapter;
        lab_adapter.IfIndex = 20;
        lab_adapter.AdapterName = lab_guid.data();
        lab_adapter.FriendlyName = lab_name.data();
        lab_adapter.Next = &wifi_adapter;
        wifi_adapter.IfIndex = 30;
        wifi_adapter.AdapterName = wifi_guid.data();
        wifi_adapter.FriendlyName = wifi_name.data();
        wifi_adapter.Next = &loopback_adapter;
        loopback_adapter.IfIndex = 1;
        loopback_adapter.IfType = IF_TYPE_SOFTWARE_LOOPBACK;
        loopback_adapter.FriendlyName = loopback_name.data();

        // Examine the partial match before the exact friendly name.
        lab.name = lab_device.data();
        lab.next = &ethernet;
        ethernet.name = ethernet_device.data();
        ethernet.next = &wifi;
        wifi.name = wifi_device.data();
        wifi.next = &loopback;
        loopback.name = loopback_device.data();
        loopback.flags = PCAP_IF_LOOPBACK;
        loopback.next = &orphan;
        orphan.name = orphan_device.data();
    }
};

struct Case {
    std::string name;
    const pcap_if_t* device;
    ULONG index;
    std::string_view error_prefix;
};

bool verify(InterfaceFixture& fixture, const Case& test) {
    WinPingInterface selection{&fixture.orphan, 99};
    std::string error = "stale error";
    const bool found = select_win_ping_interface(&fixture.lab, &fixture.ethernet_adapter,
                                                test.name, selection, error);
    const bool correct_error = test.error_prefix.empty() ? error.empty()
        : error.starts_with(test.error_prefix);
    if (found == (test.device != nullptr) && selection.device == test.device &&
        selection.index == test.index && correct_error) return true;

    std::cerr << "Unexpected result for selector '" << test.name << "'"
              << " (found=" << found << ", index=" << selection.index
              << ", error='" << error << "')\n";
    return false;
}

} // namespace

int main() {
    InterfaceFixture fixture;
    const Case cases[] = {
        {"ethernet", &fixture.ethernet, 10, ""},
        {"Ethernet Lab", &fixture.lab, 20, ""},
        {"aabbccdd-1234-5678-1111-111111111111", &fixture.ethernet, 10, ""},
        {"{AABBCCDD-1234-5678-1111-111111111111}", &fixture.ethernet, 10, ""},
        {"\\Device\\npf_{DDEEFFAA-1234-5678-2222-222222222222}", &fixture.lab, 20, ""},
        {"111111111111", &fixture.ethernet, 10, ""},
        {"R\xC3\xA9seau local", &fixture.wifi, 30, ""},
        {"\\Device\\NPF_Loopback", &fixture.loopback, 1, ""},
        {"thernet", nullptr, 0, "Ambiguous network interface"},
        {"Does not exist", nullptr, 0, "Network interface not found"},
        {"Unmapped", nullptr, 0, "Capture device has no matching IPv4 egress interface"},
        {"", nullptr, 0, "Invalid network interface name"},
        {std::string("Ethernet\0Extra", 14), nullptr, 0, "Invalid network interface name"}
    };
    for (const auto& test : cases)
        if (!verify(fixture, test)) return 1;

    fixture.lab_adapter.FriendlyName = fixture.ethernet_name.data();
    if (!verify(fixture, {"Ethernet", nullptr, 0, "Ambiguous network interface"}))
        return 1;
    return 0;
}
