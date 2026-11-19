#include "win/win_icmp.hpp"

#include <initializer_list>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

struct ScopedSocket {
    SOCKET handle{INVALID_SOCKET};
    ~ScopedSocket() {
        if (handle != INVALID_SOCKET) closesocket(handle);
    }
};

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

int socket_ttl(SOCKET socket) {
    DWORD value = 0;
    int size = sizeof(value);
    if (getsockopt(socket, IPPROTO_IP, IP_TTL, reinterpret_cast<char*>(&value), &size) != 0) {
        throw std::runtime_error("getsockopt(IP_TTL) failed: " + std::to_string(WSAGetLastError()));
    }
    return static_cast<int>(value);
}

void expect_ttl(SOCKET socket, int expected, const char* scenario) {
    const auto actual = socket_ttl(socket);
    if (actual != expected) {
        throw std::runtime_error(std::string(scenario) + " expected TTL " +
                                 std::to_string(expected) + ", got " + std::to_string(actual));
    }
}

} // namespace

int main() {
    try {
        for (int ttl : {-1, 0, 1, 255}) {
            require(valid_request_ttl(ttl), "rejected a valid TTL");
        }
        require(ensure_wsa(), "could not initialize Winsock");
        const ScopedSocket udp{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
        require(udp.handle != INVALID_SOCKET, "could not open a UDP socket");

        // Use the same socket across overrides and restores without sending.
        const int default_ttl = socket_ttl(udp.handle);
        require(default_ttl >= 1 && default_ttl <= 255, "invalid default TTL from Winsock");
        const int override_ttl = default_ttl == 17 ? 18 : 17;

        require(set_request_ttl(udp.handle, override_ttl, default_ttl), "could not override the TTL");
        expect_ttl(udp.handle, override_ttl, "explicit override");
        for (int ttl : {-2, 256}) {
            require(!valid_request_ttl(ttl), "accepted an invalid TTL");
            require(!set_request_ttl(udp.handle, ttl, default_ttl), "applied an invalid TTL");
            expect_ttl(udp.handle, override_ttl, "invalid option");
        }

        require(set_request_ttl(udp.handle, -1, default_ttl), "could not restore the default TTL");
        expect_ttl(udp.handle, default_ttl, "default selection");
        require(set_request_ttl(udp.handle, override_ttl, default_ttl), "could not reapply the TTL override");
        require(set_request_ttl(udp.handle, 0, default_ttl), "legacy zero could not restore the default TTL");
        expect_ttl(udp.handle, default_ttl, "legacy default selection");

        require(set_request_ttl(udp.handle, override_ttl), "could not apply a per-socket override");
        require(set_request_ttl(udp.handle, -1), "default without a saved TTL failed");
        expect_ttl(udp.handle, override_ttl, "default without a saved TTL");
        require(!set_request_ttl(INVALID_SOCKET, override_ttl), "invalid socket accepted a TTL override");
    } catch (const std::exception& error) {
        std::cerr << "Windows request TTL: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
