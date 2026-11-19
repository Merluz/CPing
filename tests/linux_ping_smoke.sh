#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]] || [[ ! -x $1 ]]; then
    echo "Usage: $0 PATH_TO_CPING_LINUX_TESTS" >&2
    exit 2
fi
test_binary=$(realpath -- "$1")

sender_ns="cping-sender-$BASHPID"
peer_ns="cping-peer-$BASHPID"
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
ip -n "$sender_ns" addr add 192.0.2.1/30 dev cping-tx
ip -n "$sender_ns" link set cping-tx up
ip -n "$peer_ns" link set lo up
ip -n "$peer_ns" addr add 192.0.2.2/30 dev cping-rx
ip -n "$peer_ns" link set cping-rx up

group=$(id -g)
local_ttl=61
peer_ttl=43
ip netns exec "$sender_ns" sysctl -q -w "net.ipv4.ping_group_range=$group $group"
ip netns exec "$sender_ns" sysctl -q -w "net.ipv4.ip_default_ttl=$local_ttl"
ip netns exec "$peer_ns" sysctl -q -w "net.ipv4.ip_default_ttl=$peer_ttl"

ip netns exec "$sender_ns" timeout 15s "$test_binary" smoke 192.0.2.2 "$local_ttl" "$peer_ttl"
