/**
 * Windows ICMP helpers (raw socket + OS ICMP API).
 *
 * Responsibilities:
 * - Ensure Winsock initialization
 * - Build and send ICMP Echo Request packets via raw sockets
 * - Compute checksums using the shared cping utilities
 * - Provide a fast-path self-ping using IcmpSendEcho
 *
 * This module is used internally by the Windows backend in ping_win.cpp.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <vector>
#include <cstring>
#include <mutex>
#include <windows.h>

#include "win_icmp.hpp"
#include "cping/icmp.hpp"
#include "cping/util.hpp"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

// ---------------------------------------------------------------------------
// Winsock bootstrap
// ---------------------------------------------------------------------------
/**
 * Ensures Winsock is initialized (WSAStartup). Safe to call repeatedly.
 *
 * @return true if Winsock is ready.
 */
bool ensure_wsa() {
    static std::mutex startup_mutex;
    static bool initialized = false;
    std::lock_guard lock(startup_mutex);
    if (initialized)
        return true;

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return false;

    initialized = true;
    return true;
}

bool valid_request_ttl(int ttl) noexcept {
    // Zero also selects the default for zero-initialized C options.
    return ttl >= -1 && ttl <= 255;
}

bool set_request_ttl(SOCKET socket, int ttl, int default_ttl) noexcept {
    if (!valid_request_ttl(ttl))
        return false;
    if (ttl <= 0)
        ttl = default_ttl;
    if (ttl <= 0)
        return true;

    const DWORD value = static_cast<DWORD>(ttl);
    return setsockopt(socket, IPPROTO_IP, IP_TTL,
                      reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
}

// ---------------------------------------------------------------------------
// Raw ICMP Echo Request
// ---------------------------------------------------------------------------
/**
 * Sends a raw ICMP Echo Request (type=8) using a raw socket.
 *
 * @param dst     Destination IPv4 address
 * @param id      Identifier field (host byte order)
 * @param seq     Sequence field (host byte order)
 * @param payload Optional payload pointer
 * @param len     Payload length in bytes
 * @param ttl     Outgoing TTL, -1 or 0 for the system default
 *
 * @return true if the request was sent with the requested options.
 */
bool send_icmp_echo_raw(const in_addr& dst,
                        uint16_t id,
                        uint16_t seq,
                        const void* payload,
                        size_t len,
                        int ttl)
{
    if (!ensure_wsa())
        return false;

    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET)
        return false;

    if (!set_request_ttl(s, ttl)) {
        closesocket(s);
        return false;
    }

    // Build ICMP header + payload
    IcmpHeader req{};
    req.type = 8;        // Echo Request
    req.code = 0;
    req.id   = htons(id);
    req.seq  = htons(seq);

    std::vector<unsigned char> packet(sizeof(IcmpHeader) + len);
    std::memcpy(packet.data(), &req, sizeof(req));

    if (payload && len > 0) {
        std::memcpy(packet.data() + sizeof(req), payload, len);
    }

    auto* icmph = reinterpret_cast<IcmpHeader*>(packet.data());
    icmph->checksum = 0;
    icmph->checksum = checksum16(packet.data(), packet.size());

    sockaddr_in dstsa{};
    dstsa.sin_family = AF_INET;
    dstsa.sin_addr   = dst;

    int sent = sendto(
        s,
        reinterpret_cast<const char*>(packet.data()),
        static_cast<int>(packet.size()),
        0,
        reinterpret_cast<const sockaddr*>(&dstsa),
        sizeof(dstsa)
    );

    closesocket(s);
    return sent != SOCKET_ERROR;
}


// ---------------------------------------------------------------------------
// Self-ping using Windows ICMP API
// ---------------------------------------------------------------------------
/**
 * Performs a local ICMP Echo using the OS-level API (IcmpSendEcho).
 *
 * This bypasses raw sockets and does not require WinPcap.
 *
 * @param dst          Local IPv4 address
 * @param timeout_ms   Timeout for the request
 * @param out_rtt_ms   RTT result
 * @param out_ttl      TTL from response
 * @param request_ttl  Outgoing TTL, -1 or 0 for the system default
 *
 * @return true if the ping succeeded.
 */
bool icmp_ping_local(const in_addr& dst,
                     int timeout_ms,
                     long& out_rtt_ms,
                     int& out_ttl,
                     int request_ttl)
{
    if (!valid_request_ttl(request_ttl))
        return false;

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
        return false;

    char sendData[8] = {0};  // Minimal payload
    constexpr DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
    std::vector<char> replyBuf(replySize);

    IP_OPTION_INFORMATION opt{};
    PIP_OPTION_INFORMATION requestOptions = nullptr;
    if (request_ttl > 0) {
        opt.Ttl = static_cast<UCHAR>(request_ttl);
        requestOptions = &opt;
    }

    DWORD dwRes = IcmpSendEcho(
        hIcmp,
        dst.S_un.S_addr,
        sendData,
        sizeof(sendData),
        requestOptions,
        replyBuf.data(),
        replySize,
        timeout_ms
    );

    bool ok = false;

    if (dwRes >= 1) {
        auto* rep = reinterpret_cast<ICMP_ECHO_REPLY*>(replyBuf.data());
        if (rep->Status == IP_SUCCESS) {
            out_rtt_ms = static_cast<long>(rep->RoundTripTime);
            out_ttl    = static_cast<int>(rep->Options.Ttl);
            ok = true;
        }
    }

    IcmpCloseHandle(hIcmp);
    return ok;
}
