import socket
import subprocess
import sys


ETH_P_IP = 0x0800
ICMP_HEADER_SIZE = 8
CPING_TIMESTAMP_SIZE = 8


def read_probe(packet, sender, peer):
    if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_ICMP:
        return None
    if packet[12:16] != sender or packet[16:20] != peer:
        return None

    header_size = (packet[0] & 0x0F) * 4
    total_size = int.from_bytes(packet[2:4], "big")
    payload_offset = header_size + ICMP_HEADER_SIZE + CPING_TIMESTAMP_SIZE
    if header_size < 20 or not payload_offset <= total_size <= len(packet):
        return None
    if packet[header_size:header_size + 2] != b"\x08\x00":
        return None
    return total_size - payload_offset, packet[8]


def capture_probe_ttls(interface, sender, peer, test_command):
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)) as capture:
        capture.bind((interface, ETH_P_IP))
        # The kernel buffers the few requests while the sender runs.
        subprocess.run(test_command, check=True, timeout=15)

        observed = {}
        capture.setblocking(False)
        while True:
            try:
                packet = capture.recv(2048)
            except BlockingIOError:
                break
            probe = read_probe(packet, sender, peer)
            if probe is None:
                continue
            payload_size, ttl = probe
            if payload_size in observed:
                raise RuntimeError(f"Duplicate outgoing probe with extra payload size {payload_size}")
            observed[payload_size] = ttl
        return observed


def main():
    interface, sender_ip, peer_ip, sender_netns, binary, sender_ttl, peer_ttl = sys.argv[1:]
    default = int(sender_ttl)
    expected = {31: default, 32: 17, 33: default, 34: 23, 35: 47, 36: default}
    command = ["ip", "netns", "exec", sender_netns, binary, "ttl-smoke", peer_ip, peer_ttl]
    observed = capture_probe_ttls(interface, socket.inet_aton(sender_ip), socket.inet_aton(peer_ip), command)
    if observed != expected:
        raise SystemExit(f"Expected outgoing TTLs by extra payload size {expected}, observed {observed}")
    print(f"Verified outgoing TTLs by extra payload size: {observed}")


if __name__ == "__main__":
    main()
