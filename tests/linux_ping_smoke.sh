#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]] || [[ ! -x $1 ]]; then
    echo "Usage: $0 PATH_TO_CPING_LINUX_TESTS" >&2
    exit 2
fi
test_binary=$(realpath -- "$1")
test_directory=$(dirname -- "$(realpath -- "$0")")

sender_ns="cping-sender-$BASHPID"
peer_ns="cping-peer-$BASHPID"
sender_ip=192.0.2.1
peer_ip=192.0.2.2
sender_created=0
peer_created=0
cleanup() {
    if (( peer_created )); then ip netns del "$peer_ns" || true; fi
    if (( sender_created )); then ip netns del "$sender_ns" || true; fi
}
trap cleanup EXIT

ip netns add "$sender_ns"
sender_created=1
ip netns add "$peer_ns"
peer_created=1
ip -n "$sender_ns" link add cping-tx type veth peer name cping-rx
ip -n "$sender_ns" link set cping-rx netns "$peer_ns"

ip -n "$sender_ns" link set lo up
ip -n "$sender_ns" addr add "$sender_ip/30" dev cping-tx
ip -n "$sender_ns" link set cping-tx up
ip -n "$peer_ns" link set lo up
ip -n "$peer_ns" addr add "$peer_ip/30" dev cping-rx
ip -n "$peer_ns" link set cping-rx up

group=$(id -g)
local_ttl=61
peer_ttl=43
ip netns exec "$sender_ns" sysctl -q -w "net.ipv4.ping_group_range=$group $group"
ip netns exec "$sender_ns" sysctl -q -w "net.ipv4.ip_default_ttl=$local_ttl"
ip netns exec "$peer_ns" sysctl -q -w "net.ipv4.ip_default_ttl=$peer_ttl"

ip netns exec "$sender_ns" timeout 15s "$test_binary" smoke "$peer_ip" "$local_ttl" "$peer_ttl"
ip netns exec "$peer_ns" python3 "$test_directory/linux_ping_ttl_capture.py" \
    ttl cping-rx "$sender_ip" "$peer_ip" "$sender_ns" "$test_binary" "$local_ttl" "$peer_ttl"

alternate_sender_ip=198.51.100.1
alternate_peer_ip=198.51.100.2
ip -n "$sender_ns" link add cping-tx-alt type veth peer name cping-rx-alt
ip -n "$sender_ns" link set cping-rx-alt netns "$peer_ns"
ip -n "$sender_ns" addr add "$alternate_sender_ip/30" dev cping-tx-alt
ip -n "$sender_ns" link set cping-tx-alt up
ip -n "$peer_ns" addr add "$alternate_peer_ip/30" dev cping-rx-alt
ip -n "$peer_ns" link set cping-rx-alt up
ip -n "$sender_ns" route add "$peer_ip/32" dev cping-tx src "$sender_ip" metric 10
ip -n "$sender_ns" route add "$peer_ip/32" via "$alternate_peer_ip" dev cping-tx-alt \
    src "$alternate_sender_ip" metric 20

# The test deliberately receives replies on a path different from the preferred route.
ip netns exec "$sender_ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.cping-tx-alt.rp_filter=0
ip netns exec "$peer_ns" python3 "$test_directory/linux_ping_ttl_capture.py" \
    interface cping-rx "$sender_ip" "$peer_ip" "$sender_ns" "$test_binary" "$local_ttl" "$peer_ttl" \
    cping-rx-alt "$alternate_sender_ip" cping-tx-alt
