#!/usr/bin/env bash
# Linux bench for `sping --ip` (step 3 of 1.8): the real binary against a
# namespace's real addresses. Builds it and the E2E tests, then, in user,
# network and mount namespaces of its own (no root needed; nothing outside
# them changes), sets up the bench network of scripts/bench-net.sh
#
#   client -> R1 -> R2 -> target   (10.0.{1,2,3}.0/24, fd00:{1,2,3}::/64)
#
# and runs the ignored E2E test `ip_bench` for every case, on the client:
#
#   addresses   a secondary IPv4 address, one without a route, a deprecated
#               IPv6 one; the sources and the gateway; no packet sent
#   tentative   duplicate address detection still running (20 probes)
#   duplicate   an address R1 already holds: detection fails
#   temporary   the kernel's temporary address for a `mngtmpaddr` prefix
#   no-default  no default routes: no source, no gateway
#
# and, with --external, against a STUN server of its own in the target's
# namespace (scripts/stun-bench-server.py; `dual.test` names both of its
# addresses in a hosts file of the bench's own):
#
#   external          the server's answer, after a response of another
#                     transaction; one request per family
#   external-foreign  only responses of another transaction: unknown after
#                     3 s and 3 requests per family
#   external-silent   no answer: the same
#
# Stops at the first failure; exits 2 when the host cannot run it (no user
# namespaces).
#
# Usage: scripts/ip-bench.sh
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
    for tool in unshare ip nsenter python3 cargo; do
        command -v "$tool" >/dev/null || { echo "ip-bench: $tool not found" >&2; exit 2; }
    done
    unshare -Urnm true 2>/dev/null || { echo "ip-bench: user namespaces are not available here" >&2; exit 2; }
    cd "$(dirname "$0")/.."
    bin=$(cargo test --test integration --no-run --message-format=json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
            and msg["target"]["name"] == "integration" and msg["profile"]["test"]):
        print(msg["executable"])
')
    [[ -n "$bin" && -x "$bin" ]] || { echo "ip-bench: E2E test binary not found" >&2; exit 2; }
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

# The STUN server, in the target's namespace, in the mode given; it logs the
# requests it receives to /run/stun-log, which the test reads.
stun_start() {
    rm -f /run/stun-ready
    : > /run/stun-log
    # nsenter itself, not `at`: a function in the background is a subshell,
    # and `$!` would be its pid, not the server's (nsenter execs python3).
    nsenter --net=/run/netns/dst -- python3 -I "$(dirname "$0")/stun-bench-server.py" "$1" /run/stun-log /run/stun-ready &
    stun_pid=$!
    for _ in $(seq 50); do
        [[ -e /run/stun-ready ]] && return
        sleep 0.1
    done
    echo "ip-bench: the STUN server did not start" >&2
    exit 2
}
stun_stop() {
    [[ -n ${stun_pid:-} ]] || return 0
    kill "$stun_pid" 2>/dev/null || true
    wait "$stun_pid" 2>/dev/null || true
    stun_pid=
}
# A failed case stops the loop before its `del`: the server goes anyway.
trap stun_stop EXIT

dad() { printf %s "$1" > /proc/sys/net/ipv6/conf/c0/accept_dad; printf %s "$2" > /proc/sys/net/ipv6/conf/c0/dad_transmits; }

# Cases that change the client; `add` sets them up, `del` undoes them.
setup() {
    case $1 in
    addresses)
        if [[ $2 == add ]]; then
            ip addr add 10.0.1.9/24 dev c0
            ip addr add 10.9.9.9/24 dev c0 noprefixroute
            ip -6 addr add fd00:1::d/64 dev c0 preferred_lft 0 valid_lft forever nodad
            # IPv6's own messages about the new addresses (MLD reports) are
            # sent within the next seconds: let them pass before the test
            # counts the packets --ip sends, which must be none.
            sleep 3
        else
            ip addr del 10.0.1.9/24 dev c0
            ip addr del 10.9.9.9/24 dev c0
            ip -6 addr del fd00:1::d/64 dev c0
        fi
        ;;
    tentative)
        if [[ $2 == add ]]; then
            dad 1 20
            ip -6 addr add fd00:1::77/64 dev c0
        else
            ip -6 addr del fd00:1::77/64 dev c0
            dad 0 1
        fi
        ;;
    duplicate)
        if [[ $2 == add ]]; then
            dad 1 1
            ip -6 addr add fd00:1::1/64 dev c0
            for _ in $(seq 50); do
                ip -6 addr show dev c0 | grep -q 'fd00:1::1/64.*dadfailed' && break
                sleep 0.1
            done
            ip -6 addr show dev c0 | grep -q 'fd00:1::1/64.*dadfailed' || { echo "ip-bench: DAD did not fail" >&2; exit 2; }
        else
            ip -6 addr del fd00:1::1/64 dev c0
            dad 0 1
        fi
        ;;
    temporary)
        if [[ $2 == add ]]; then
            printf 2 > /proc/sys/net/ipv6/conf/c0/use_tempaddr
            ip -6 addr add fd00:5::5/64 dev c0 mngtmpaddr nodad
        else
            ip -6 addr flush dev c0 to fd00:5::/64
            printf 0 > /proc/sys/net/ipv6/conf/c0/use_tempaddr
        fi
        ;;
    no-default)
        if [[ $2 == add ]]; then
            ip route del default
            ip -6 route del default
        else
            ip route add default via 10.0.1.1
            ip -6 route add default via fd00:1::1
        fi
        ;;
    external | external-foreign | external-silent)
        local mode=${1#external-}
        [[ $mode == external ]] && mode=answer
        if [[ $2 == add ]]; then
            stun_start "$mode"
        else
            stun_stop
        fi
        ;;
    esac
}

failed=0
for case in addresses tentative duplicate temporary no-default external external-foreign external-silent; do
    setup "$case" add
    echo "== $case"
    if out=$(SPING_IP_CASE=$case "$bin" --ignored --exact ip_bench --nocapture 2>&1) \
        && grep -q 'test result: ok. 1 passed' <<<"$out"; then
        grep -v -E '^(running 1 test|test result:|$)' <<<"$out" | sed 's/^/   /'
    else
        printf '%s\n' "$out" | sed 's/^/   /'
        failed=1
        break
    fi
    setup "$case" del
done

if [[ $failed -ne 0 ]]; then
    echo "ip-bench: FAILED" >&2
    exit 1
fi
echo "ip-bench: all cases passed"
