#include "export.hpp"
#include "stats.hpp"

#include <cstddef>
#include <fstream>
#include <locale>

static std::ofstream open_export(const std::string& path, bool append) {
    const auto mode = append ? (std::ios::app | std::ios::ate) : std::ios::trunc;
    std::ofstream file(path, mode);
    file.imbue(std::locale::classic());
    return file;
}

static void write_csv_field(std::ostream& file, const std::string& value) {
    if (value.find_first_of(",\"\r\n") == std::string::npos) {
        file << value;
        return;
    }

    file.put('"');
    for (const auto ch : value) {
        if (ch == '"') {
            file.put('"');
        }
        file.put(ch);
    }
    file.put('"');
}

static void write_json_string(std::ostream& file, const std::string& value) {
    constexpr char hex[] = "0123456789abcdef";
    file.put('"');
    for (const auto byte : value) {
        const auto ch = static_cast<unsigned char>(byte);
        if (byte == '"' || byte == '\\') {
            file.put('\\');
            file.put(byte);
        } else if (ch < 0x20) {
            file << "\\u00" << hex[ch >> 4] << hex[ch & 0xf];
        } else {
            file.put(byte);
        }
    }
    file.put('"');
}

bool export_summary(const std::string& path, ExportFormat format,
                    const std::string& ip, const PingSummary& summary, bool append) {
    auto file = open_export(path, append);
    if (!file) {
        return false;
    }

    // Keep the numeric export schema when a session has no RTT samples.
    const auto rtt = summary.rtt.value_or(RttSummary{});
    if (format == ExportFormat::CSV) {
        if (file.tellp() == 0) {
            file << "host,sent,received,loss,min,avg,max,median,stddev,jitter\n";
        }
        write_csv_field(file, ip);
        file << "," << summary.attempts << "," << summary.replies << ","
             << summary.without_reply_percent << ","
             << rtt.min << "," << rtt.avg << "," << rtt.max << "," << rtt.median << ","
             << rtt.stddev << "," << rtt.jitter << "\n";
    } else {
        file << "{\"host\":";
        write_json_string(file, ip);
        file << ",\"sent\":" << summary.attempts
             << ",\"received\":" << summary.replies
             << ",\"loss\":" << summary.without_reply_percent
             << ",\"rtt\":{\"min\":" << rtt.min
             << ",\"avg\":" << rtt.avg
             << ",\"max\":" << rtt.max
             << ",\"median\":" << rtt.median
             << ",\"stddev\":" << rtt.stddev
             << ",\"jitter\":" << rtt.jitter << "}}\n";
    }

    file.close();
    return static_cast<bool>(file);
}

bool export_probes_csv(const std::string& path,
                       const std::string& ip,
                       const std::vector<cping::PingProbeResult>& probes,
                       bool append) {
    auto file = open_export(path, append);
    if (!file) {
        return false;
    }

    if (file.tellp() == 0) {
        file << "host,idx,success,rtt_ms,ttl,if,error\n";
    }

    for (std::size_t i = 0; i < probes.size(); ++i) {
        const auto& probe = probes[i];
        write_csv_field(file, ip);
        file << "," << (i + 1) << "," << (probe.success ? 1 : 0) << ","
             << (probe.success ? probe.rtt_ms : 0) << ","
             << (probe.success ? probe.ttl : -1) << ",";
        write_csv_field(file, probe.if_name.empty() ? "-" : probe.if_name);
        file.put(',');
        write_csv_field(file, probe.error_msg.empty() ? "-" : probe.error_msg);
        file.put('\n');
    }

    file.close();
    return static_cast<bool>(file);
}
