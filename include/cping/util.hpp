#pragma once
#include <cstddef>
#include <cstdint>

/**
 * Compute a classic 16-bit Internet checksum (RFC 1071).
 *
 * @param data  Pointer to raw buffer
 * @param len   Buffer length in bytes
 * @return      One's-complement 16-bit checksum
 */
uint16_t checksum16(const void* data, size_t len);
