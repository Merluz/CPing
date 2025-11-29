/**
 * Windows WinPcap helpers for ICMP capture.
 *
 * Responsibilities:
 * - Open a live capture session with immediate mode (if supported)
 * - Apply a BPF filter for ICMP traffic
 * - Poll packets until a user-defined matcher returns true
 */

#include "win_pcap.hpp"
#include <iostream>

/**
 * Opens a live pcap capture on the given device.
 * Configured in:
 *   - promiscuous mode
 *   - immediate mode (when available)
 *   - direction: inbound packets only
 *
 * @return true on success.
 */
bool open_capture(Capture& cap,
                  const char* dev_name,
                  int timeout_ms,
                  char errbuf[PCAP_ERRBUF_SIZE])
{
    pcap_t* h = pcap_create(dev_name, errbuf);
    if (!h) {
#ifdef LIBPING_DEBUG
        std::cerr << "[ERR] pcap_create failed: " << errbuf << "\n";
#endif
        return false;
    }

    // Base config
    if (pcap_set_snaplen(h, 65536) != 0) { pcap_close(h); return false; }
    if (pcap_set_promisc(h, 1) != 0)      { pcap_close(h); return false; }
    if (pcap_set_timeout(h, 1) != 0)      { pcap_close(h); return false; } // small timeout

    // Immediate mode (no buffering)
#if defined(PCAP_API_VERSION)
    if (pcap_set_immediate_mode(h, 1) != 0) {
#ifdef LIBPING_DEBUG
        std::cerr << "[WRN] immediate mode not supported; continuing\n";
#endif
    }
#endif

    // Activate capture
    int rv = pcap_activate(h);
    if (rv < 0) {
#ifdef LIBPING_DEBUG
        std::cerr << "[ERR] pcap_activate failed: " << pcap_geterr(h) << "\n";
#endif
        pcap_close(h);
        return false;
    }

    cap.h = h;
    (void)pcap_setdirection(cap.h, PCAP_D_IN); // best-effort

#ifdef LIBPING_DEBUG
    std::cout << "[DBG] pcap_activate OK\n";
#endif

    return true;
}


/**
 * Applies a BPF filter to restrict capture to ICMP replies
 * matching the target host.
 *
 * @param ip   Empty => capture all ICMP traffic
 */
bool apply_icmp_filter(Capture& cap, const std::string& ip) {
    std::string filter;

    if (ip.empty())
        filter = "icmp";
    else
        filter = "icmp and (src host " + ip + " or dst host " + ip + ")";

#ifdef LIBPING_DEBUG
    std::cout << "[DBG] Applying BPF: " << filter << "\n";
#endif

    bpf_program fp{};
    if (pcap_compile(cap.h, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
#ifdef LIBPING_DEBUG
        std::cerr << "[ERR] pcap_compile: " << pcap_geterr(cap.h) << "\n";
#endif
        return false;
    }

    if (pcap_setfilter(cap.h, &fp) == -1) {
#ifdef LIBPING_DEBUG
        std::cerr << "[ERR] pcap_setfilter: " << pcap_geterr(cap.h) << "\n";
#endif
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    return true;
}


/**
 * Receives ICMP packets until either:
 *   - A successful on_pkt(...) returns true
 *   - The deadline expires
 *
 * The callback receives:
 *   - parsed IP header
 *   - parsed ICMP header
 *   - payload pointer
 *   - payload length
 */
bool recv_icmp_until(
    Capture& cap,
    const std::function<bool(const IpHeader*,
                              const IcmpHeader*,
                              const unsigned char*,
                              size_t)>& on_pkt,
    std::chrono::steady_clock::time_point deadline)
{
    constexpr int ETHER_LEN = 14;

    while (std::chrono::steady_clock::now() < deadline) {
        pcap_pkthdr* h = nullptr;
        const u_char* data = nullptr;

        int r = pcap_next_ex(cap.h, &h, &data);
        if (r == 0)   continue; // timeout => retry
        if (r == -1 || r == -2) break;

        if (!h || h->caplen < ETHER_LEN + sizeof(IpHeader))
            continue;

        auto* iphdr = reinterpret_cast<const IpHeader*>(data + ETHER_LEN);

        if ((iphdr->ver_ihl >> 4) != 4)   continue; // Not IPv4
        if (iphdr->protocol != 1)         continue; // Not ICMP

        uint8_t ihl = (iphdr->ver_ihl & 0x0F) * 4;
        if (h->caplen < ETHER_LEN + ihl + sizeof(IcmpHeader))
            continue;

        auto* icmph = reinterpret_cast<const IcmpHeader*>(data + ETHER_LEN + ihl);
        const unsigned char* payload =
            data + ETHER_LEN + ihl + sizeof(IcmpHeader);

        size_t payload_len =
            h->caplen - (ETHER_LEN + ihl + sizeof(IcmpHeader));

#ifdef LIBPING_DEBUG
        if (icmph->type == 0) {
            in_addr saddr{}, daddr{};
            saddr.s_addr = iphdr->saddr;
            daddr.s_addr = iphdr->daddr;
            char sbuf[64], dbuf[64];
            InetNtopA(AF_INET, &saddr, sbuf, sizeof(sbuf));
            InetNtopA(AF_INET, &daddr, dbuf, sizeof(dbuf));

            std::cout << "[DBG] REPLY: id=" << ntohs(icmph->id)
                      << " seq=" << ntohs(icmph->seq)
                      << " src=" << sbuf
                      << " dst=" << dbuf
                      << " ttl=" << (int)iphdr->ttl
                      << "\n";
        }
#endif

        if (on_pkt(iphdr, icmph, payload, payload_len))
            return true;
    }

    return false;
}
