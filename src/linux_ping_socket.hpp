#pragma once

#include "cping/ping.hpp"

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <net/if.h>
#include <sys/socket.h>

namespace cping::detail {

CPING_LOCAL inline bool bind_ping_interface(int socket, const std::string& name) noexcept {
    if (name.empty())
        return true;
    if (name.size() >= IFNAMSIZ || name.find('\0') != std::string::npos)
        return false;

    return ::setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, name.c_str(),
                        static_cast<socklen_t>(name.size() + 1)) == 0;
}

// A Linux ping socket uses its local port as the echo identifier.
CPING_LOCAL inline std::uint16_t bind_ping_socket_id(int socket) noexcept {
    sockaddr_in local{};
    local.sin_family = AF_INET;
    if (::bind(socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0)
        return 0;

    socklen_t length = sizeof(local);
    if (::getsockname(socket, reinterpret_cast<sockaddr*>(&local), &length) != 0 ||
        length < sizeof(local) || local.sin_family != AF_INET)
        return 0;

    return ntohs(local.sin_port);
}

CPING_LOCAL inline int observed_ping_ttl(msghdr message) noexcept {
    if ((message.msg_flags & MSG_CTRUNC) != 0 || !message.msg_control)
        return -1;

    const auto* control = static_cast<const char*>(message.msg_control);
    for (auto* header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        const auto offset = static_cast<std::size_t>(reinterpret_cast<const char*>(header) - control);
        if (header->cmsg_len < CMSG_LEN(0) || header->cmsg_len > message.msg_controllen - offset)
            return -1;

        if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_TTL) {
            if (header->cmsg_len < CMSG_LEN(sizeof(int)))
                return -1;

            int ttl = -1;
            std::memcpy(&ttl, CMSG_DATA(header), sizeof(ttl));
            return (ttl >= 0 && ttl <= 255) ? ttl : -1;
        }
    }

    return -1;
}

CPING_LOCAL inline bool valid_outgoing_ping_ttl(int ttl) noexcept {
    // Zero has historically selected the default for zero-initialized C options.
    return ttl >= -1 && ttl <= 255;
}

CPING_LOCAL inline ssize_t send_ping_request(int socket, const sockaddr_in* target,
                                             unsigned char* packet, std::size_t size,
                                             int ttl) noexcept {
    iovec data{packet, size};
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    if (target) {
        message.msg_name = const_cast<sockaddr_in*>(target);
        message.msg_namelen = sizeof(*target);
    }

    // Overrides are attached to the datagram, even on the persistent socket.
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(ttl))]{};
    if (ttl > 0) {
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        auto* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = IPPROTO_IP;
        header->cmsg_type = IP_TTL;
        header->cmsg_len = CMSG_LEN(sizeof(ttl));
        std::memcpy(CMSG_DATA(header), &ttl, sizeof(ttl));
    }

    return ::sendmsg(socket, &message, 0);
}

CPING_LOCAL PingProbeResult ping_once_linux(const sockaddr_in& target, const PingOptions& options);

} // namespace cping::detail
