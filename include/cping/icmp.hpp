#pragma once
#include <cstdint>

/**
 * Minimal ICMP header (Echo Request/Reply only).
 * Matches wire format exactly, so keep this struct packed.
 */
#pragma pack(push, 1)
struct IcmpHeader {
    uint8_t  type;      // 8 = Echo Request, 0 = Echo Reply
    uint8_t  code;      // unused for Echo
    uint16_t checksum;  // ICMP checksum
    uint16_t id;        // Identifier (host-chosen)
    uint16_t seq;       // Sequence number
    // The variable payload follows immediately
};
#pragma pack(pop)
