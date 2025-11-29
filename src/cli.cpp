#include "cli.hpp"
#include <iostream>
#include <string>

/**
 * Parse command-line arguments into a CliOptions struct.
 *
 * The CLI intentionally mimics classic ping/fping semantics while
 * adding features such as:
 *   - custom payload size
 *   - interface selection
 *   - continuous mode
 *   - export (CSV/JSON)
 *   - color toggle
 *   - timestamped output
 *
 * Invalid or unknown flags are reported but do not stop parsing.
 */
CliOptions parse_args(int argc, char** argv) {
    CliOptions opt{};

    // Minimal usage help
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  cping <ip> [options]\n";
        return opt; // opt.ip remains empty → main will print usage
    }

    opt.ip = argv[1];

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];

        // ------------------------------
        // Basic ping-style options
        // ------------------------------
        if ((a == "-t" || a == "--timeout" || a == "-W") && i + 1 < argc) {
            opt.ping.timeout_ms = std::stoi(argv[++i]);

        } else if ((a == "-r" || a == "--retries") && i + 1 < argc) {
            opt.ping.retries = std::stoi(argv[++i]);

        } else if (a == "--if" && i + 1 < argc) {
            opt.ping.if_name = argv[++i];

        } else if (a == "--quiet" || a == "-q") {
            opt.quiet = true;

        } else if (a == "--summary") {
            opt.summary = true;

        } else if (a == "--continuous") {
            opt.continuous = true;

        } else if ((a == "--interval" || a == "-i") && i + 1 < argc) {
            opt.interval_ms = std::stoi(argv[++i]);
            if (opt.interval_ms < 1) opt.interval_ms = 1;

        } else if ((a == "--count" || a == "-c") && i + 1 < argc) {
            opt.count = std::stoi(argv[++i]);
            if (opt.count < 1) opt.count = 1;

        } else if ((a == "--size" || a == "-s") && i + 1 < argc) {
            opt.payload_size = std::stoi(argv[++i]);
            if (opt.payload_size < 0) opt.payload_size = 0;
            opt.ping.payload_size = opt.payload_size;

        } else if (a == "--ttl" && i + 1 < argc) {
            opt.ttl = std::stoi(argv[++i]);
            if (opt.ttl < 1) opt.ttl = 1;
            opt.ping.ttl = opt.ttl;

        } else if (a == "--timestamp") {
            opt.timestamp = true;

        // ------------------------------
        // Output color handling
        // ------------------------------
        } else if (a == "--no-color") {
            opt.no_color = true;

        // ------------------------------
        // Export shortcuts
        // ------------------------------
        } else if (a == "--csv" && i + 1 < argc) {
            opt.export_path = argv[++i];
            opt.export_format = ExportFormat::CSV;

        } else if (a == "--json" && i + 1 < argc) {
            opt.export_path = argv[++i];
            opt.export_format = ExportFormat::JSON;

        } else if (a == "--export-append") {
            opt.export_append = true;

        // ------------------------------
        // Alternative syntax --export / --format
        // ------------------------------
        } else if (a == "--export" && i + 1 < argc) {
            opt.export_path = argv[++i];

        } else if (a == "--format" && i + 1 < argc) {
            std::string f = argv[++i];
            if (f == "csv") opt.export_format = ExportFormat::CSV;
            else if (f == "json") opt.export_format = ExportFormat::JSON;
            else std::cerr << "Unknown export format: " << f << "\n";

        // ------------------------------
        // Unknown argument
        // ------------------------------
        } else {
            std::cerr << "Unknown arg: " << a << "\n";
        }
    }

    // Final propagation into PingOptions
    opt.ping.payload_size = opt.payload_size;
    opt.ping.ttl = opt.ttl;
    opt.ping.timestamp = opt.timestamp;

    return opt;
}
