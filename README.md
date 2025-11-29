# cping

![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg)
![Latest Release](https://img.shields.io/github/v/release/Merluz/cping)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)
![Downloads](https://img.shields.io/github/downloads/Merluz/cping/total)



**cping** is a lightweight, cross-platform C++ library and CLI tool for performing ICMP Echo (ping) operations. It provides access to real Round-Trip Time (RTT) and Time-To-Live (TTL) values, offering a consistent API across Windows and Linux.

Designed for developers and network engineers, `cping` can be used as a standalone command-line utility or integrated into C/C++ applications as a static or shared library.

## Features

- **Cross-Platform**: Native support for Windows (via Npcap/Winsock) and Linux (via raw sockets).
- **Accurate Metrics**: Retrieves precise RTT (in milliseconds) and TTL values.
- **Flexible Configuration**:
  - Configurable timeout and retry attempts.
  - Custom ICMP payload size.
  - Force specific TTL values.
  - Interface selection (bind to specific network adapters).
- **Dual API**:
  - **C++ API**: Modern, type-safe interface.
  - **C API**: Compatible C interface for broader integration.
- **Optimized Engine**: "Engine" mode for high-performance, repetitive probing (reuses sockets/handles).

## Unique Windows Capability: Accurate TTL Extraction

On Windows, the official ICMP APIs (`IcmpSendEcho`, `IcmpSendEcho2`, etc.)
**do not expose the real IPv4 TTL** contained in the reply packet.  
The field `ICMP_ECHO_REPLY.Ttl` is always zero on modern Windows versions.

**cping solves this limitation.**

To provide real, accurate TTL values, cping uses a hybrid strategy:

- **Npcap raw capture** to sniff inbound ICMP replies.
- **Direct parsing of the IPv4 header** to extract the TTL field.
- **Packet correlation engine** (matching request → reply).
- **Safe fallback logic** for interface-bound sockets.

This makes `cping` one of the *very few lightweight C++ libraries* that can give you:

- **RTT (milliseconds)**  
- **Real TTL (as seen in the raw IP header)**  
- **Consistent behavior across Windows and Linux**

A reliable, developer-friendly alternative when the standard Microsoft APIs fall short.


## Build & Installation

### Requirements

- **CMake**: Version 3.21 or later.
- **Compiler**: C++20 compatible compiler (MSVC, GCC 11+, Clang 12+).
- **Windows**: [Npcap SDK](https://npcap.com/#download) (installed in `C:\Program Files\NpcapSDK`).

### Build Instructions

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/merluzz/cping.git
    cd cping
    ```

2.  **Configure**:
    ```bash
    cmake -S . -B build
    ```

3.  **Build**:
    - **Windows**:
      ```bash
      cmake --build build --config Release
      ```
    - **Linux**:
      ```bash
      cmake --build build -- -j$(nproc)
      ```

### Artifacts

After building, the artifacts can be found in `build/bin` (executables) and `build/lib` (libraries).

- `cping` (or `cping.exe`): The CLI tool.
- `cping.lib` / `libcping.a`: Static library.
- `cping.dll` / `libcping.so`: Shared library.

## CLI Usage

The `cping` CLI tool offers a robust set of options for network diagnostics.

**Syntax**:
```bash
cping <ip> [options]
```

### Options

| Flag | Argument | Default | Description |
| :--- | :--- | :--- | :--- |
| `-t`, `--timeout` | `<ms>` | 1000 | Timeout in milliseconds per attempt. |
| `-r`, `--retries` | `<num>` | 1 | Number of retries (normal mode). |
| `-i`, `--interval` | `<ms>` | 1000 | Interval between pings (continuous mode). |
| `-c`, `--count` | `<num>` | ∞ | Total number of packets to send. |
| `-s`, `--size` | `<bytes>` | 0 | Custom ICMP payload size (in addition to header). |
| `--ttl` | `<num>` | System | Force Time-To-Live for sent packets. |
| `--if` | `<name>` | — | Force specific network interface (substring match). |
| `--continuous` | — | Off | Run continuously until CTRL+C. |
| `--quiet` | — | Off | Suppress detailed output, show final result/summary only. |
| `--summary` | — | Off | Show final statistics (loss, min/avg/max RTT). |
| `--timestamp` | — | Off | Add timestamp to each output line. |
| `--no-color` | — | Off | Disable ANSI color output. |
| `--csv` | `<path>` | — | Export results to a CSV file. |
| `--json` | `<path>` | — | Export results to a JSON file. |
| `--export-append`| — | Off | Append to export file instead of overwriting. |

### Examples

**Basic ping (3 attempts)**:
```bash
cping 8.8.8.8 -r 3
```

**Continuous ping with custom interval**:
```bash
cping 1.1.1.1 --continuous --interval 200
```

**Ping specific interface with timeout**:
```bash
cping 10.0.0.1 --if "Ethernet" -t 500
```

**Export statistics to JSON**:
```bash
cping 8.8.8.8 -c 5 --summary --json results.json
```

## Library Integration

### CMake Integration

To use `cping` in your CMake project, you can include it as a subdirectory:

```cmake
add_subdirectory(path/to/cping)
target_link_libraries(your_app PRIVATE cping_static)
```

### C++ API Example

```cpp
#include <cping/ping.hpp>
#include <iostream>

int main() {
    // Simple one-shot ping
    auto result = cping::ping_host("8.8.8.8", 1000);

    if (result.reachable) {
        std::cout << "RTT: " << result.rtt_ms << "ms, TTL: " << result.ttl << std::endl;
    } else {
        std::cout << "Host unreachable." << std::endl;
    }

    // Advanced options
    cping::PingOptions opt;
    opt.timeout_ms = 500;
    opt.retries = 3;
    opt.ttl = 64;

    auto res2 = cping::ping_host("1.1.1.1", opt);
    return 0;
}
```

### C API Example

```c
#include <cping_capi.h>
#include <stdio.h>

int main() {
    CPingResultC res;
    
    // Simple ping
    if (cping_ping_host("8.8.8.8", 1000, &res)) {
        if (res.reachable) {
            printf("Success! RTT=%ldms TTL=%d\n", res.rtt_ms, res.ttl);
        } else {
            printf("Timeout.\n");
        }
    }
    
    // Engine API (for high-performance scenarios)
    if (cping_init_engine(NULL)) {
        if (cping_ping_once_engine("1.1.1.1", 1000, 0, -1, &res)) {
             // Handle result...
        }
        cping_shutdown_engine();
    }

    return 0;
}
```

## Project Structure

- `src/`: Source code for the library and CLI.
- `include/`: Public headers (`cping/ping.hpp`, `cping_capi.h`).
- `cmake/`: CMake configuration files.
- `tests/`: Unit tests.

## Roadmap

- IPv6 support
Add native ICMPv6 echo request/reply handling with full RTT & hop-limit extraction.
- 802.1Q VLAN support
Proper parsing and injection of IEEE 802.1Q tagged frames when using raw capture.
- Improved interface selection
Better heuristics for matching interfaces by name, GUID, or IP binding.
- RTT anomaly detection
Automatic detection of jitter spikes and anomalous round-trip variations in continuous mode.
- Continuous-mode streaming
Expose a low-latency buffer/stream interface for real-time consumers (e.g., dashboards, monitoring agents).
- Enhanced test suite
Introduce a mockable socket/pcap layer to fully test the engine without requiring live network access.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
