# shellcheck shell=bash
# Bench network shared by scripts/trace-bench.sh and scripts/diagnose-bench.sh,
# sourced inside their user, network and mount namespaces (no root needed;
# nothing outside them changes):
#
#   client -> R1 -> R2 -> target   (10.0.{1,2,3}.0/24, fd00:{1,2,3}::/64)
#
# `bench_net` builds it, with the routers' ICMP rate limits off so every
# answer they owe is sent, and returns once every IPv6 address is usable.

at() { local ns=$1; shift; nsenter --net="/run/netns/$ns" -- "$@"; }

bench_net() {
    mount -t tmpfs none /run
    mkdir -p /run/netns
    ip netns add r1
    ip netns add r2
    ip netns add dst
    # No duplicate address detection: a link-local address stays tentative for a
    # second or more, and IPv6 neighbor discovery waits for it.
    for ns in "" r1 r2 dst; do
        run=(); [[ -n $ns ]] && run=(at "$ns")
        "${run[@]}" sh -c '
            printf 0 > /proc/sys/net/ipv6/conf/all/accept_dad
            printf 0 > /proc/sys/net/ipv6/conf/default/accept_dad'
    done

    ip link set lo up
    ip link add c0 type veth peer name r1a
    ip link set r1a netns r1
    ip -n r1 link add r1b type veth peer name r2a
    ip -n r1 link set r2a netns r2
    ip -n r2 link add r2b type veth peer name d0
    ip -n r2 link set d0 netns dst

    ip addr add 10.0.1.2/24 dev c0
    ip addr add fd00:1::2/64 dev c0 nodad
    ip link set c0 up
    ip route add default via 10.0.1.1
    ip -6 route add default via fd00:1::1

    ip -n r1 link set lo up
    ip -n r1 addr add 10.0.1.1/24 dev r1a
    ip -n r1 addr add fd00:1::1/64 dev r1a nodad
    ip -n r1 addr add 10.0.2.1/24 dev r1b
    ip -n r1 addr add fd00:2::1/64 dev r1b nodad
    ip -n r1 link set r1a up
    ip -n r1 link set r1b up
    ip -n r1 route add default via 10.0.2.2
    ip -n r1 -6 route add default via fd00:2::2

    ip -n r2 link set lo up
    ip -n r2 addr add 10.0.2.2/24 dev r2a
    ip -n r2 addr add fd00:2::2/64 dev r2a nodad
    ip -n r2 addr add 10.0.3.1/24 dev r2b
    ip -n r2 addr add fd00:3::1/64 dev r2b nodad
    ip -n r2 link set r2a up
    ip -n r2 link set r2b up
    ip -n r2 route add 10.0.1.0/24 via 10.0.2.1
    ip -n r2 -6 route add fd00:1::/64 via fd00:2::1

    ip -n dst link set lo up
    ip -n dst addr add 10.0.3.2/24 dev d0
    ip -n dst addr add fd00:3::2/64 dev d0 nodad
    ip -n dst link set d0 up
    ip -n dst route add default via 10.0.3.1
    ip -n dst -6 route add default via fd00:3::1

    # Routers answer every probe. IPv4: an empty rate mask exempts every ICMP
    # type, and leaves alone the per-peer tokens that route errors (`prohibit`,
    # sent by `ip_error`) spend, 5 at most and one more per second; a rate limit
    # of 0 would zero them with every time exceeded. IPv6 has no second limiter.
    for ns in r1 r2; do
        at "$ns" sh -c '
            printf 1 > /proc/sys/net/ipv4/ip_forward
            printf 1 > /proc/sys/net/ipv6/conf/all/forwarding
            printf 0 > /proc/sys/net/ipv4/icmp_ratemask
            printf 0 > /proc/sys/net/ipv6/icmp/ratelimit'
    done

    # Every IPv6 address usable before the first case.
    for _ in $(seq 50); do
        tentative=$(for ns in r1 r2 dst; do ip -n "$ns" -6 addr show tentative; done; ip -6 addr show tentative)
        [[ -z $tentative ]] && break
        sleep 0.1
    done
    [[ -z $tentative ]] || { echo "bench-net: IPv6 addresses still tentative" >&2; exit 2; }

}
