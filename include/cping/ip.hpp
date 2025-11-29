#pragma once
#include <cstdint>

/**
 * Minimal IPv4 header representation (network byte order).
 * Used only for parsing captured packets via pcap.
 *
 * Note: This struct must remain packed to match wire format.
 */
#pragma pack(push, 1)
struct IpHeader {
    uint8_t  ver_ihl;   // Version (4 bits) + IHL (4 bits)
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;  // 1 = ICMP
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
#pragma pack(pop)
