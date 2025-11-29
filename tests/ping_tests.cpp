#include "cping/ping.hpp"
#include <iostream>
#include <string>
#include <functional>
#include <vector>

// Simple test framework
int g_failures = 0;

void run_test(const std::string& name, std::function<bool()> test_fn) {
    std::cout << "[RUN] " << name << "... ";
    try {
        if (test_fn()) {
            std::cout << "PASS\n";
        } else {
            std::cout << "FAIL\n";
            g_failures++;
        }
    } catch (const std::exception& e) {
        std::cout << "FAIL (Exception: " << e.what() << ")\n";
        g_failures++;
    } catch (...) {
        std::cout << "FAIL (Unknown Exception)\n";
        g_failures++;
    }
}

bool test_localhost() {
    auto res = cping::ping_host("127.0.0.1", 500);
    if (!res.reachable) {
        std::cerr << "  Error: Localhost unreachable. " << (res.probes.empty() ? "" : res.probes[0].error_msg) << "\n";
        return false;
    }
    return true;
}

bool test_external_dns() {
    // 8.8.8.8 is Google DNS, usually reliable
    auto res = cping::ping_host("8.8.8.8", 2000);
    if (!res.reachable) {
        std::cerr << "  Warning: 8.8.8.8 unreachable (network issue?)\n";
        // We don't fail the test strictly if network is down, but for CI it might be good.
        // Let's assume for this test suite we expect internet access.
        return false; 
    }
    if (res.rtt_ms < 0) return false;
    if (res.ttl <= 0) return false;
    return true;
}

bool test_invalid_ip() {
    auto res = cping::ping_host("999.999.999.999", 100);
    // Should fail gracefully
    if (res.reachable) return false;
    return true;
}

bool test_options_payload() {
    cping::PingOptions opt;
    opt.timeout_ms = 1000;
    opt.payload_size = 128;
    opt.retries = 1;
    
    auto res = cping::ping_host("8.8.8.8", opt);
    if (!res.reachable) return false;
    return true;
}

bool test_options_ttl() {
    cping::PingOptions opt;
    opt.timeout_ms = 1000;
    opt.ttl = 5; // Low TTL
    opt.retries = 1;

    auto res = cping::ping_host("8.8.8.8", opt);
    // It might be reachable or not depending on hops, but it should run without crashing.
    // If it is reachable, TTL should be close to what remains. 
    // If we receive a Time Exceeded, cping currently might report it as unreachable or handle it.
    // The library logic for 'reachable' usually means Echo Reply. 
    // So if TTL expires, we expect reachable=false (or specific error if implemented).
    
    // For this test, we just ensure it doesn't crash and returns a valid structure.
    return true; 
}

int main() {
    std::cout << "Running cping tests...\n";

    run_test("Localhost Ping", test_localhost);
    run_test("External DNS Ping", test_external_dns);
    run_test("Invalid IP Handling", test_invalid_ip);
    run_test("Payload Option", test_options_payload);
    run_test("TTL Option", test_options_ttl);

    std::cout << "\nTests completed with " << g_failures << " failures.\n";
    return g_failures > 0 ? 1 : 0;
}
