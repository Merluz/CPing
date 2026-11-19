#include "cping/engine.hpp"
#include "cping/ping.hpp"
#include "linux_ping_socket.hpp"

#include <array>
#include <barrier>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
thread_local bool discard_ancillary_data = false;
}

extern "C" ssize_t __real_recvmsg(int socket, msghdr* message, int flags);

extern "C" ssize_t __wrap_recvmsg(int socket, msghdr* message, int flags) {
    const auto size = __real_recvmsg(socket, message, flags);
    if (size >= 0 && discard_ancillary_data) message->msg_controllen = 0;
    return size;
}

namespace {

bool expect_ttl(std::string_view scenario, int actual, int expected) {
    if (actual == expected) return true;
    std::cerr << scenario << " expected TTL " << expected << ", got " << actual << '\n';
    return false;
}

bool test_metadata() {
    using cping::detail::observed_ping_ttl;
    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    msghdr message{};

    bool ok = expect_ttl("No ancillary data", observed_ping_ttl(message), -1);
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IP;
    header->cmsg_type = IP_TTL;
    header->cmsg_len = CMSG_LEN(sizeof(int));

    for (const int ttl : {1, 64, 255}) {
        std::memcpy(CMSG_DATA(header), &ttl, sizeof(ttl));
        ok &= expect_ttl("Received IP_TTL", observed_ping_ttl(message), ttl);
    }

    header->cmsg_type = IP_TOS;
    ok &= expect_ttl("Unrelated ancillary data", observed_ping_ttl(message), -1);
    header->cmsg_type = IP_TTL;

    message.msg_flags = MSG_CTRUNC;
    ok &= expect_ttl("Truncated ancillary data flag", observed_ping_ttl(message), -1);
    message.msg_flags = 0;

    header->cmsg_len = CMSG_LEN(sizeof(int) - 1);
    ok &= expect_ttl("Short IP_TTL payload", observed_ping_ttl(message), -1);
    header->cmsg_len = CMSG_LEN(sizeof(int));

    message.msg_controllen = CMSG_LEN(sizeof(int)) - 1;
    ok &= expect_ttl("IP_TTL length beyond available bytes", observed_ping_ttl(message), -1);
    return ok;
}

struct ScopedSocket {
    int fd{-1};
    ~ScopedSocket() { if (fd >= 0) ::close(fd); }
};

struct EngineShutdown {
    ~EngineShutdown() { cping::shutdown_engine(); }
};

bool reserve_process_id(ScopedSocket& reservation) {
    const auto pid_id = static_cast<std::uint16_t>(::getpid());
    if (pid_id == 0) return true;

    // Keep the PID-derived identifier occupied so the tested sockets cannot receive it.
    reservation.fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (reservation.fd < 0) {
        std::cerr << "Unable to create reservation socket: " << std::strerror(errno) << '\n';
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(pid_id);
    if (::bind(reservation.fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0 &&
        errno != EADDRINUSE) {
        std::cerr << "Unable to reserve PID-derived ICMP identifier: " << std::strerror(errno) << '\n';
        return false;
    }
    return true;
}

bool expect_reply(std::string_view scenario, const cping::PingProbeResult& result, int ttl) {
    if (!result.success || result.rtt_ms < 0) {
        std::cerr << scenario << " expected a valid echo reply: " << result.error_msg << '\n';
        return false;
    }
    return expect_ttl(scenario, result.ttl, ttl);
}

bool expect_one_shot(std::string_view scenario, const cping::PingResult& result, int ttl) {
    if (result.probes.size() != 1) {
        std::cerr << scenario << " expected exactly one probe result\n";
        return false;
    }
    bool ok = expect_reply(scenario, result.probes.front(), ttl);
    if (result.probes.front().success && !result.reachable) {
        std::cerr << scenario << " missing reply in the aggregate result\n";
        ok = false;
    }
    if (result.reachable) ok &= expect_ttl(scenario, result.ttl, ttl);
    return ok;
}

bool test_smoke(const std::string& peer, int local_ttl, int peer_ttl) {
    ScopedSocket reservation;
    if (!reserve_process_id(reservation)) return false;

    cping::PingOptions options;
    options.ttl = 27;
    bool ok = expect_one_shot("One-shot probe to peer", cping::ping_host(peer, options), peer_ttl);

    // Keep the real kernel reply and remove only its ancillary metadata.
    discard_ancillary_data = true;
    const auto without_ttl = cping::ping_host(peer, options);
    discard_ancillary_data = false;
    ok &= expect_one_shot("One-shot probe without ancillary data", without_ttl, -1);

    if (!cping::init_engine()) {
        std::cerr << "Unable to initialize Linux ping engine\n";
        return false;
    }
    EngineShutdown shutdown;

    ok &= expect_reply("Engine local fast path",
                       cping::ping_once_engine("127.0.0.1", options.timeout_ms, 0, options.ttl),
                       local_ttl);
    ok &= expect_reply("Persistent engine to peer",
                       cping::ping_once_engine(peer, options.timeout_ms, 0, options.ttl), peer_ttl);
    return ok;
}

bool test_ttl_smoke(const std::string& peer, int peer_ttl) {
    if (!cping::init_engine()) {
        std::cerr << "Unable to initialize Linux ping engine\n";
        return false;
    }
    EngineShutdown shutdown;
    constexpr int timeout_ms = 1000;

    bool ok = true;
    for (const auto& [payload_size, ttl] : std::array<std::pair<int, int>, 2>{{{37, -2}, {38, 256}}}) {
        const auto result = cping::ping_once_engine(peer, timeout_ms, payload_size, ttl);
        if (result.success || result.error_msg != "Invalid outgoing TTL") {
            std::cerr << "Expected probe to reject outgoing TTL " << ttl << '\n';
            ok = false;
        }
    }

    // The peer identifies the outgoing requests by their extra payload sizes.
    constexpr std::array<std::pair<int, int>, 4> sequential{{{31, -1}, {32, 17}, {33, -1}, {36, 0}}};
    for (const auto& [payload_size, ttl] : sequential) {
        ok &= expect_reply("Sequential TTL probe", cping::ping_once_engine(peer, timeout_ms, payload_size, ttl),
                           peer_ttl);
    }

    std::barrier<> start(2);
    cping::PingProbeResult first;
    std::jthread worker([&] {
        start.arrive_and_wait();
        first = cping::ping_once_engine(peer, timeout_ms, 34, 23);
    });
    start.arrive_and_wait();
    const auto second = cping::ping_once_engine(peer, timeout_ms, 35, 47);
    worker.join();
    ok &= expect_reply("First concurrent TTL probe", first, peer_ttl);
    ok &= expect_reply("Second concurrent TTL probe", second, peer_ttl);
    return ok;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "metadata") {
        return test_metadata() ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc == 5 && std::string_view(argv[1]) == "smoke") {
        return test_smoke(argv[2], std::stoi(argv[3]), std::stoi(argv[4])) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc == 4 && std::string_view(argv[1]) == "ttl-smoke") {
        return test_ttl_smoke(argv[2], std::stoi(argv[3])) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    std::cerr << "Usage: " << argv[0] << " metadata | smoke PEER_IP LOCAL_TTL PEER_TTL"
              << " | ttl-smoke PEER_IP PEER_TTL\n";
    return EXIT_FAILURE;
}
