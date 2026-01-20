/**
 * Entry point for the CLI ping tool.
 *
 * Responsible only for:
 * - Parsing command-line options
 * - Delegating execution to `run_ping`
 */

#include <iostream>
#include <exception>

#include "cli.hpp"
#include "runner.hpp"

int main(int argc, char** argv) {
    try {
        auto options = parse_args(argc, argv);
        return run_ping(options);
    }
    catch (const std::exception& e) {
        std::cerr << "cping: error: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "cping: unknown fatal error" << std::endl;
        return 1;
    }
}
