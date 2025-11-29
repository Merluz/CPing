/**
 * Entry point for the CLI ping tool.
 *
 * Responsible only for:
 * - Parsing command-line options
 * - Delegating execution to `run_ping`
 */

#include "cli.hpp"
#include "runner.hpp"

int main(int argc, char** argv) {
    auto options = parse_args(argc, argv);
    return run_ping(options);
}
