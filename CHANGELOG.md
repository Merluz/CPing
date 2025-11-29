# Changelog
All notable changes to this project will be documented in this file.

---

## [Unreleased]

### Added
- Full Linux support (raw ICMP socket engine + TTL extraction via `IP_RECVTTL`)
- Full Windows support (Npcap-based capture + raw ICMP engine)
- Accurate RTT and real TTL extraction across platforms
- Dual API:
  - C++ modern interface (`cping::ping_host`)
  - C API (`cping_ping_host`, engine API)
- High-performance ICMP engine (persistent socket, async listener, future-based correlation)
- CLI tool (`cping`) with:
  - continuous mode
  - summaries
  - timestamp mode
  - payload size
  - interface override
  - TTL override
  - CSV / JSON export
  - colors and quiet modes
- Build system with CMake (static/shared libs + install rules)
- Cross-platform packaging (Linux tar.gz, Windows zip)
- Unit tests (basic external, TTL, payload, invalid IP checks)
- GitHub Actions CI (Linux build)

### Changed
- Unified structure for Windows & Linux engines  
- Improved error handling and result reporting  
- Improved internal code documentation and header layout  

### Fixed
- Corrected multiple TTL discrepancies across platforms  
- Fixed checksum inconsistencies  
- Corrected multiple Linux `memcpy` namespace issues  
- Stabilized engine listener behavior on both OS  

---

## [1.0.0] – First public release
This is the first official public release of **cping** <3
Stable, cross-platform, fully documented, and ready for integration.
