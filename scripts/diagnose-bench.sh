#!/usr/bin/env bash
# Linux bench for `--diagnose` (step 4 of 1.7): the real binary against a
# real path. Builds it and the E2E tests, then, in user, network and mount
# namespaces of its own (no root needed; nothing outside them changes), sets
# up the bench network of scripts/bench-net.sh
#
#   client -> R1 -> R2 -> target   (10.0.{1,2,3}.0/24, fd00:{1,2,3}::/64)
#
# with a hosts file of its own (`dual.test`: the target's IPv4 and IPv6
# addresses), and runs the ignored E2E test `diagnose_bench` for every case,
# with RAW sockets (ping sockets denied) and then DGRAM:
#
#   silent-tail     the target dropped at R2: silence after R2
#   prohibited      R2 refuses the target: R2 reports it
#   icmp-ignored    the target ignores echo requests: TCP answers (refused)
#   v4-broken       the name's IPv4 path dropped at R2, IPv6 fine
#   v6-only-host    the client has no IPv4 at all
#   explicit        -4, -S and --tcp keep out what they exclude
#   coexist         the main probe dies at R1 (-t 1) while the trace reaches
#                   the target: none of the trace's answers counts
#   stop            SIGTERM while diagnosing, with and without -c
#   context         the default route's source, then its gateway, change
#                   during a run: context_changed, never with -S or -I
#   renew           a long outage: R2 drops the target, then refuses it; the
#                   diagnosis, renewed 5 min after it concluded, says so
#                   (DGRAM only: it takes 6 min)
#
# Stops at the first failure; exits 2 when the host cannot run it (no user
# namespaces).
#
# Usage: scripts/diagnose-bench.sh
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
    for tool in unshare ip nsenter python3 cargo; do
        command -v "$tool" >/dev/null || { echo "diagnose-bench: $tool not found" >&2; exit 2; }
    done
    unshare -Urnm true 2>/dev/null || { echo "diagnose-bench: user namespaces are not available here" >&2; exit 2; }
    cd "$(dirname "$0")/.."
    bin=$(cargo test --test integration --no-run --message-format=json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
            and msg["target"]["name"] == "integration" and msg["profile"]["test"]):
        print(msg["executable"])
')
    [[ -n "$bin" && -x "$bin" ]] || { echo "diagnose-bench: E2E test binary not found" >&2; exit 2; }
    exec unshare -Urnm bash "$0" --inside "$bin"
fi

bin=$2
# shellcheck source=scripts/bench-net.sh
source "$(dirname "$0")/bench-net.sh"
bench_net

printf '10.0.3.2 dual.test\nfd00:3::2 dual.test\n' > /run/hosts
mount --bind /run/hosts /etc/hosts
# glibc asks only the hosts file; musl has no nsswitch.conf and reads it
# anyway (a DNS query would find no network here).
if [[ -e /etc/nsswitch.conf ]]; then
    printf 'hosts: files\n' > /run/nsswitch.conf
    mount --bind /run/nsswitch.conf /etc/nsswitch.conf
fi

# Cases that change the topology; `add` sets them up, `del` undoes them.
setup() {
    case $1 in
    silent-tail | stop)
        ip -n r2 route "$2" blackhole 10.0.3.2/32
        ip -n r2 -6 route "$2" blackhole fd00:3::2/128
        ;;
    renew)
        # The test replaces the blackhole with a prohibit route; `del`
        # removes either.
        if [[ $2 == add ]]; then
            ip -n r2 route add blackhole 10.0.3.2/32
            ip -n r2 -6 route add blackhole fd00:3::2/128
        else
            ip -n r2 route del 10.0.3.2/32
            ip -n r2 -6 route del fd00:3::2/128
        fi
        ;;
    prohibited)
        ip -n r2 route "$2" prohibit 10.0.3.2/32
        ip -n r2 -6 route "$2" prohibit fd00:3::2/128
        ;;
    icmp-ignored)
        local on=1; [[ $2 == del ]] && on=0
        at dst sh -c "
            printf $on > /proc/sys/net/ipv4/icmp_echo_ignore_all
            printf $on > /proc/sys/net/ipv6/icmp/echo_ignore_all"
        ;;
    v4-broken | explicit)
        ip -n r2 route "$2" blackhole 10.0.3.2/32
        ;;
    v6-only-host)
        if [[ $2 == add ]]; then
            ip addr del 10.0.1.2/24 dev c0
        else
            ip addr add 10.0.1.2/24 dev c0
            ip route add default via 10.0.1.1
        fi
        ;;
    context)
        # A second source on the client and a second address on R1: the
        # test points the default route at them while sping runs.
        if [[ $2 == del ]]; then
            ip route replace default via 10.0.1.1
        fi
        ip addr "$2" 10.0.1.3/24 dev c0
        ip -n r1 addr "$2" 10.0.1.254/24 dev r1a
        ;;
    coexist)
        # The target sends no TCP back: its connects time out, so the
        # trace runs; its ICMP goes back as usual.
        at dst ip rule "$2" ipproto tcp lookup 100 prio 100
        at dst ip -6 rule "$2" ipproto tcp lookup 100 prio 100
        ip -n dst route "$2" blackhole default table 100
        ip -n dst -6 route "$2" blackhole default table 100
        ;;
    esac
}

failed=0
# A new network namespace denies ping sockets: RAW first, then DGRAM (as
# scripts/trace-bench.sh).
read -r low high < /proc/sys/net/ipv4/ping_group_range
(( 0 < low || 0 > high )) || { echo "diagnose-bench: ping sockets are not denied ($low $high)" >&2; exit 2; }
for socket in raw dgram; do
    if [[ $socket == dgram ]]; then
        printf '0 0' > /proc/sys/net/ipv4/ping_group_range
    fi
    cases=(silent-tail prohibited icmp-ignored v4-broken v6-only-host explicit coexist stop context)
    # What `renew` shows does not depend on the socket, and it waits 5 min.
    if [[ $socket == dgram ]]; then
        cases+=(renew)
    fi
    for case in "${cases[@]}"; do
        setup "$case" add
        echo "== $socket $case"
        if out=$(SPING_DIAG_CASE=$case "$bin" --ignored --exact diagnose_bench --nocapture 2>&1) \
            && grep -q 'test result: ok. 1 passed' <<<"$out"; then
            grep -v -E '^(running 1 test|test result:|$)' <<<"$out" | sed 's/^/   /'
        else
            printf '%s\n' "$out" | sed 's/^/   /'
            failed=1
            break 2
        fi
        setup "$case" del
    done
done

if [[ $failed -ne 0 ]]; then
    echo "diagnose-bench: FAILED" >&2
    exit 1
fi
echo "diagnose-bench: all cases passed (RAW and DGRAM)"
