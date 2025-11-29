#include "cping/util.hpp"

/**
 * Compute the standard Internet checksum (RFC 1071).
 *
 * Used for:
 *   - ICMP Echo headers (IPv4)
 *   - arbitrary payload segments
 *
 * This is the classic 16-bit one's-complement sum:
 *   - sum words
 *   - fold carries
 *   - invert result
 */
uint16_t checksum16(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* p = static_cast<const uint16_t*>(data);

    // Sum 16-bit chunks
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }

    // Handle remaining odd byte
    if (len) {
        sum += *reinterpret_cast<const uint8_t*>(p);
    }

    // Fold carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}
