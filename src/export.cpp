#include "export.hpp"
#include <fstream>
#include <algorithm>
#include <cmath>

using namespace cping;

/**
 * Compute full statistics from a list of probe results.
 *
 * This is used by the non-continuous exporter and mirrors the logic
 * of the human-readable summary printer.
 */
static void compute_stats_from_probes(
    const std::vector<PingProbeResult>& probes,
    int& received, long& min_rtt, long& max_rtt,
    long& sum_rtt, double& avg,
    double& median, double& stddev, double& jitter)
{
    received = 0;
    min_rtt = std::numeric_limits<long>::max();
    max_rtt = std::numeric_limits<long>::min();
    sum_rtt = 0;

    std::vector<long> rtts;
    rtts.reserve(probes.size());

    for (const auto& p : probes) {
        if (p.success) {
            ++received;
            min_rtt = std::min(min_rtt, p.rtt_ms);
            max_rtt = std::max(max_rtt, p.rtt_ms);
            sum_rtt += p.rtt_ms;
            rtts.push_back(p.rtt_ms);
        }
    }

    avg = received ? (double)sum_rtt / received : 0.0;

    // Jitter = mean absolute diff between consecutive samples (temporal)
    jitter = 0.0;
    if (rtts.size() > 1) {
        long sum_diff = 0;
        for (size_t i = 1; i < rtts.size(); ++i)
            sum_diff += std::abs(rtts[i] - rtts[i - 1]);
        jitter = (double)sum_diff / (rtts.size() - 1);
    }

    // Median (sorted copy)
    median = 0.0;
    if (!rtts.empty()) {
        auto sorted = rtts;
        std::sort(sorted.begin(), sorted.end());
        median = (sorted.size() % 2 == 0)
            ? (sorted[sorted.size() / 2 - 1] + sorted[sorted.size() / 2]) / 2.0
            : sorted[sorted.size() / 2];
    }

    // Standard deviation
    stddev = 0.0;
    if (!rtts.empty()) {
        double var = 0.0;
        for (auto r : rtts)
            var += (r - avg) * (r - avg);
        var /= rtts.size();
        stddev = std::sqrt(var);
    }
}


/**
 * Same stats computation, but for the continuous mode (already accumulated values).
 */
static void compute_stats_from_series(
    int received, long min_rtt, long max_rtt,
    long sum_rtt, const std::vector<long>& rtts,
    double& avg, double& median,
    double& stddev, double& jitter)
{
    avg = received ? (double)sum_rtt / received : 0.0;

    jitter = 0.0;
    if (rtts.size() > 1) {
        long sum_diff = 0;
        for (size_t i = 1; i < rtts.size(); ++i)
            sum_diff += std::abs(rtts[i] - rtts[i - 1]);
        jitter = (double)sum_diff / (rtts.size() - 1);
    }

    median = 0.0;
    if (!rtts.empty()) {
        auto sorted = rtts;
        std::sort(sorted.begin(), sorted.end());
        median = (sorted.size() % 2 == 0)
            ? (sorted[sorted.size() / 2 - 1] + sorted[sorted.size() / 2]) / 2.0
            : sorted[sorted.size() / 2];
    }

    stddev = 0.0;
    if (!rtts.empty()) {
        double var = 0.0;
        for (auto r : rtts)
            var += (r - avg) * (r - avg);
        var /= rtts.size();
        stddev = std::sqrt(var);
    }
}


// ------------------------------------------------------------
// CSV Support
// ------------------------------------------------------------

static void write_csv_header(std::ofstream& f) {
    f << "host,sent,received,loss,min,avg,max,median,stddev,jitter\n";
}

static void write_csv_row(
    std::ofstream& f, const std::string& ip,
    int sent, int received, int loss,
    long minv, double avgv, long maxv,
    double median, double stddev, double jitter)
{
    f << ip << "," << sent << "," << received << "," << loss << ","
      << minv << "," << avgv << "," << maxv << ","
      << median << "," << stddev << "," << jitter << "\n";
}


// ------------------------------------------------------------
// Summary export — single run (non continuous)
// ------------------------------------------------------------

bool export_summary(const std::string& path, ExportFormat fmt,
                    const std::string& ip, int sent,
                    const std::vector<PingProbeResult>& probes,
                    bool append)
{
    int received = 0;
    long minv = 0, maxv = 0, sum = 0;
    double avg = 0, median = 0, stddev = 0, jitter = 0;

    compute_stats_from_probes(probes, received,
                              minv, maxv, sum,
                              avg, median, stddev, jitter);

    int loss = sent > 0 ? (100 - (received * 100 / sent)) : 100;

    std::ofstream f(path, std::ios::out |
                            (append ? std::ios::app : std::ios::trunc));
    if (!f) return false;

    if (fmt == ExportFormat::CSV) {
        if (!append) write_csv_header(f);
        write_csv_row(f, ip, sent, received, loss,
                      minv, avg, maxv, median, stddev, jitter);
        return true;
    }

    // JSON output
    f << "{"
      << "\"host\":\"" << ip << "\","
      << "\"sent\":" << sent << ","
      << "\"received\":" << received << ","
      << "\"loss\":" << loss << ","
      << "\"rtt\":{"
        << "\"min\":" << minv << ","
        << "\"avg\":" << avg << ","
        << "\"max\":" << maxv << ","
        << "\"median\":" << median << ","
        << "\"stddev\":" << stddev << ","
        << "\"jitter\":" << jitter
      << "}"
      << "}\n";
    return true;
}


// ------------------------------------------------------------
// Summary export — continuous mode
// ------------------------------------------------------------

bool export_summary_continuous(const std::string& path, ExportFormat fmt,
                               const std::string& ip, int sent, int received,
                               long minv, long maxv, long sum,
                               const std::vector<long>& rtts,
                               bool append)
{
    int loss = sent > 0 ? (100 - (received * 100 / sent)) : 100;

    double avg = 0, median = 0, stddev = 0, jitter = 0;
    compute_stats_from_series(received, minv, maxv, sum, rtts,
                              avg, median, stddev, jitter);

    std::ofstream f(path, std::ios::out |
                            (append ? std::ios::app : std::ios::trunc));
    if (!f) return false;

    if (fmt == ExportFormat::CSV) {
        if (!append) write_csv_header(f);
        write_csv_row(f, ip, sent, received, loss,
                      minv, avg, maxv, median, stddev, jitter);
        return true;
    }

    // JSON output
    f << "{"
      << "\"host\":\"" << ip << "\","
      << "\"sent\":" << sent << ","
      << "\"received\":" << received << ","
      << "\"loss\":" << loss << ","
      << "\"rtt\":{"
        << "\"min\":" << minv << ","
        << "\"avg\":" << avg << ","
        << "\"max\":" << maxv << ","
        << "\"median\":" << median << ","
        << "\"stddev\":" << stddev << ","
        << "\"jitter\":" << jitter
      << "}"
      << "}\n";
    return true;
}


// ------------------------------------------------------------
// Export raw probes (CSV)
// ------------------------------------------------------------

bool export_probes_csv(const std::string& path,
                       const std::string& ip,
                       const std::vector<PingProbeResult>& probes,
                       bool append)
{
    std::ofstream f(path, std::ios::out |
                            (append ? std::ios::app : std::ios::trunc));
    if (!f) return false;

    if (!append)
        f << "host,idx,success,rtt_ms,ttl,if,error\n";

    for (size_t i = 0; i < probes.size(); ++i) {
        const auto& p = probes[i];
        f << ip << "," << (i + 1) << ","
          << (p.success ? 1 : 0) << ","
          << (p.success ? p.rtt_ms : 0) << ","
          << (p.success ? p.ttl : -1) << ","
          << (p.if_name.empty() ? "-" : p.if_name) << ","
          << (p.error_msg.empty() ? "-" : p.error_msg)
          << "\n";
    }
    return true;
}
