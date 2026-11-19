#include "cping/engine.hpp"

#include <pcap.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

using namespace std::chrono_literals;

std::string loopback_capture_name() {
    char error[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* first = nullptr;
    if (pcap_findalldevs(&first, error) != 0) {
        throw std::runtime_error(std::string("Npcap enumeration failed: ") + error);
    }

    std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> devices(first, pcap_freealldevs);
    for (auto* device = devices.get(); device; device = device->next) {
        if (device->name && (device->flags & PCAP_IF_LOOPBACK)) return device->name;
    }
    throw std::runtime_error("Npcap did not expose a loopback capture device");
}

void exercise_engine(const std::string& adapter) {
    if (!cping::init_engine(adapter)) {
        throw std::runtime_error("could not start the engine on the Npcap loopback device");
    }

    // Leave the capture running without sending any test traffic.
    std::this_thread::sleep_for(100ms);
    const bool was_available = cping::engine_available();
    const auto started = std::chrono::steady_clock::now();
    cping::shutdown_engine();
    if (std::chrono::steady_clock::now() - started >= 2s) {
        throw std::runtime_error("idle capture did not shut down promptly");
    }
    if (!was_available || cping::engine_available()) {
        throw std::runtime_error("unexpected engine availability during the idle capture cycle");
    }
}

} // namespace

int main() {
    try {
        const auto device = loopback_capture_name();
        exercise_engine(device);
        exercise_engine(device);
        cping::shutdown_engine();
    } catch (const std::exception& error) {
        std::cerr << "Npcap idle smoke: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
