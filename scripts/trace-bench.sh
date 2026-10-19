#!/usr/bin/env bash
# Linux bench for the bounded traceroute (`probe::trace`, step 1 of 1.7).
#
# Builds the unit tests, then, in user, network and mount namespaces of its
# own (no root needed; nothing outside them changes), sets up
#
#   client -> R1 -> R2 -> target   (10.0.{1,2,3}.0/24, fd00:{1,2,3}::/64)
#
# and runs the ignored test `trace_bench` for every case, both families and
# both socket types: RAW with ping sockets denied, then DGRAM. The routers'
# ICMP rate limits are off, so every answer they owe is sent. Stops at the
# first failure; exits 2 when the host cannot run it (no user namespaces).
#
# Usage: scripts/trace-bench.sh
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
    for tool in unshare ip nsenter python3 cargo; do
        command -v "$tool" >/dev/null || { echo "trace-bench: $tool not found" >&2; exit 2; }
    done
    unshare -Urnm true 2>/dev/null || { echo "trace-bench: user namespaces are not available here" >&2; exit 2; }
    cd "$(dirname "$0")/.."
    bin=$(cargo test --no-run --message-format=json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
            and msg["target"]["name"] == "sping" and "bin" in msg["target"]["kind"]
            and msg["profile"]["test"]):
        print(msg["executable"])
')
    [[ -n "$bin" && -x "$bin" ]] || { echo "trace-bench: unit test binary not found" >&2; exit 2; }
    exec unshare -Urnm bash "$0" --inside "$bin"
fi

bin=$2
# shellcheck source=scripts/bench-net.sh
source "$(dirname "$0")/bench-net.sh"
bench_net

# Cases that change the topology; the others run on the plain path.
setup() {
    case $1 in
    silent-router)
        # R1 cannot send its own packets back: its ICMP errors are lost,
        # while it keeps forwarding.
        ip -n r1 rule "$2" iif lo to 10.0.1.0/24 lookup 100 prio 100
        ip -n r1 route "$2" blackhole default table 100
        ip -n r1 -6 rule "$2" iif lo to fd00:1::/64 lookup 100 prio 100
        ip -n r1 -6 route "$2" blackhole default table 100
        ;;
    prohibited)
        ip -n r2 route "$2" prohibit 10.0.3.2/32
        ip -n r2 -6 route "$2" prohibit fd00:3::2/128
        ;;
    silent-tail | budget | cancel)
        ip -n r2 route "$2" blackhole 10.0.3.2/32
        ip -n r2 -6 route "$2" blackhole fd00:3::2/128
        ;;
    esac
}

failed=0
# A new network namespace denies ping sockets ("1 0", shown here with the
# unmapped ids as 65534): RAW first, while our group, 0, is outside the range.
# Then allow them to group 0 ("1 0" could not be written back: gid 1 is not
# mapped in this user namespace).
read -r low high < /proc/sys/net/ipv4/ping_group_range
(( 0 < low || 0 > high )) || { echo "trace-bench: ping sockets are not denied ($low $high)" >&2; exit 2; }
for socket in raw dgram; do
    if [[ $socket == dgram ]]; then
        printf '0 0' > /proc/sys/net/ipv4/ping_group_range
    fi
    for case in reach silent-router prohibited silent-tail budget cancel coexist; do
        setup "$case" add
        for target in 10.0.3.2 fd00:3::2; do
            echo "== $socket $case $target"
            if out=$(SPING_TRACE_CASE=$case SPING_TRACE_TARGET=$target SPING_TRACE_SOCKET=$socket \
                "$bin" --ignored --exact probe::trace::tests::trace_bench --nocapture 2>&1) \
                && grep -q 'test result: ok. 1 passed' <<<"$out"; then
                grep -v -E '^(running 1 test|test result:|$)' <<<"$out" | sed 's/^/   /'
            else
                printf '%s\n' "$out" | sed 's/^/   /'
                failed=1
                break 3
            fi
        done
        setup "$case" del
    done
done

if [[ $failed -ne 0 ]]; then
    echo "trace-bench: FAILED" >&2
    exit 1
fi
echo "trace-bench: all cases passed (DGRAM and RAW, IPv4 and IPv6)"
