#!/usr/bin/env bash
# Linux bench for the main probe's destination unreachables (step 1 of 1.8):
# the real binary against a real path. Builds it and the E2E tests, then, in
# user, network and mount namespaces of its own (no root needed; nothing
# outside them changes), sets up the bench network of scripts/bench-net.sh
#
#   client -> R1 -> R2 -> target   (10.0.{1,2,3}.0/24, fd00:{1,2,3}::/64)
#
# and runs the ignored E2E test `unreachable_bench` for every case, with RAW
# sockets (ping sockets denied) and then DGRAM:
#
#   unreachable   R2 has an `unreachable` route to the target: R2 says so
#   prohibited    R2 has a `prohibit` route: R2 says the target is filtered
#   blackhole     R2 drops the target silently: timeouts, as before
#   neighbor      no host answers for an address on the client's link: the
#                 client says so itself (address resolution shortened)
#   late          the same with resolution as long as usual (3 s) and a 1 s
#                 wait: every error comes after its probe's wait, in bursts;
#                 none may fail a later send or receive
#   redirect      R1 redirects every probe back to the client's link: a
#                 ping socket gets EREMOTEIO; timeouts, never an error
#   crosstalk     three processes at once: one to the unreachable target,
#                 one to R2 (which answers), one diagnosing the target
#   ttl1          a time exceeded from R1 (-t 1) stays a timeout
#
# Stops at the first failure; exits 2 when the host cannot run it (no user
# namespaces).
#
# Usage: scripts/unreachable-bench.sh
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
    for tool in unshare ip nsenter python3 cargo; do
        command -v "$tool" >/dev/null || { echo "unreachable-bench: $tool not found" >&2; exit 2; }
    done
    unshare -Urnm true 2>/dev/null || { echo "unreachable-bench: user namespaces are not available here" >&2; exit 2; }
    cd "$(dirname "$0")/.."
    bin=$(cargo test --test integration --no-run --message-format=json 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
            and msg["target"]["name"] == "integration" and msg["profile"]["test"]):
        print(msg["executable"])
')
    [[ -n "$bin" && -x "$bin" ]] || { echo "unreachable-bench: E2E test binary not found" >&2; exit 2; }
    exec unshare -Urnm bash "$0" --inside "$bin"
fi

bin=$2
# shellcheck source=scripts/bench-net.sh
source "$(dirname "$0")/bench-net.sh"
bench_net

# Cases that change the topology; `add` sets them up, `del` undoes them.
setup() {
    case $1 in
    unreachable | crosstalk)
        ip -n r2 route "$2" unreachable 10.0.3.2/32
        ip -n r2 -6 route "$2" unreachable fd00:3::2/128
        ;;
    prohibited)
        ip -n r2 route "$2" prohibit 10.0.3.2/32
        ip -n r2 -6 route "$2" prohibit fd00:3::2/128
        ;;
    blackhole)
        ip -n r2 route "$2" blackhole 10.0.3.2/32
        ip -n r2 -6 route "$2" blackhole fd00:3::2/128
        ;;
    neighbor)
        # Three solicitations 100 ms apart instead of a second apart.
        local ms=100; [[ $2 == del ]] && ms=1000
        printf %s "$ms" > /proc/sys/net/ipv4/neigh/c0/retrans_time_ms
        printf %s "$ms" > /proc/sys/net/ipv6/neigh/c0/retrans_time_ms
        ;;
    redirect)
        # R1 sends the target back out of the client's link, to the client
        # itself, and tells it so; the client takes no redirect (it would
        # route through its own address).
        local accept=0; [[ $2 == del ]] && accept=1
        printf %s "$accept" > /proc/sys/net/ipv4/conf/all/accept_redirects
        printf %s "$accept" > /proc/sys/net/ipv4/conf/c0/accept_redirects
        ip -n r1 route "$2" 10.0.3.2/32 via 10.0.1.2
        ;;
    esac
}

failed=0
# A new network namespace denies ping sockets: RAW first, then DGRAM (as
# scripts/diagnose-bench.sh).
read -r low high < /proc/sys/net/ipv4/ping_group_range
(( 0 < low || 0 > high )) || { echo "unreachable-bench: ping sockets are not denied ($low $high)" >&2; exit 2; }
for socket in raw dgram; do
    if [[ $socket == dgram ]]; then
        printf '0 0' > /proc/sys/net/ipv4/ping_group_range
    fi
    for case in unreachable prohibited blackhole neighbor late redirect crosstalk ttl1; do
        setup "$case" add
        echo "== $socket $case"
        if out=$(SPING_UNREACH_CASE=$case "$bin" --ignored --exact unreachable_bench --nocapture 2>&1) \
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
    echo "unreachable-bench: FAILED" >&2
    exit 1
fi
echo "unreachable-bench: all cases passed (RAW and DGRAM)"
