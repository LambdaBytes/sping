#!/usr/bin/env bash
# Linux bench for both address families of a name (`dns::resolve_both`) and
# the source of each (`iface::usable_source`), step 2 of 1.7.
#
# Builds the unit tests, then, in user, network and mount namespaces of its
# own (no root needed; nothing outside them changes), puts a hosts file of
# its own (`*.test` names) over /etc/hosts, with no DNS server to ask, and
# runs the ignored test `family_bench` once per case, each in a new network
# namespace:
#
#   bare             only lo
#   no-address       default routes through an interface with no address
#   link-local-only  link-local IPv6 only and a default route
#   on-link          link-local addresses only, other prefixes on the link
#   global           an address and a default route in each family
#   routes           unreachable, prohibit and blackhole routes
#   no-ipv6          IPv6 disabled
#   dns-timeout      a name server that never answers (`dns::re_resolve`)
#
# Stops at the first failure; exits 2 when the host cannot run it (no user
# namespaces).
#
# Usage: scripts/family-bench.sh
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
    for tool in unshare ip nsenter python3 cargo; do
        command -v "$tool" >/dev/null || { echo "family-bench: $tool not found" >&2; exit 2; }
    done
    unshare -Urnm true 2>/dev/null || { echo "family-bench: user namespaces are not available here" >&2; exit 2; }
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
    [[ -n "$bin" && -x "$bin" ]] || { echo "family-bench: unit test binary not found" >&2; exit 2; }
    exec unshare -Urnm bash "$0" --inside "$bin"
fi

bin=$2
at() { local ns=$1; shift; nsenter --net="/run/netns/$ns" -- "$@"; }

mount -t tmpfs none /run
mkdir -p /run/netns
cat > /run/hosts <<'EOF'
2001:db8::20 both.test
192.0.2.20 both.test
192.0.2.10 v4only.test
2001:db8::10 v6only.test
EOF
mount --bind /run/hosts /etc/hosts
# glibc asks only the hosts file; musl has no nsswitch.conf and reads it
# anyway (a DNS query would find no network here).
if [[ -e /etc/nsswitch.conf ]]; then
    printf 'hosts: files\n' > /run/nsswitch.conf
    mount --bind /run/nsswitch.conf /etc/nsswitch.conf
fi
# A resolv.conf of its own, for the dns-timeout case. Where /etc/resolv.conf
# is a link into /run (systemd-resolved), its target goes in this /run.
resolv=$(readlink -m /etc/resolv.conf)
mkdir -p "$(dirname "$resolv")"
[[ -e $resolv ]] || : > "$resolv"
: > /run/resolv.conf
mount --bind /run/resolv.conf "$resolv"

# A veth pair inside $ns, its link-local addresses usable (no duplicate
# address detection: they would stay tentative for a second or more, and
# meanwhile the kernel hands out `::1` as the source).
veth() {
    local ns=$1
    at "$ns" sh -c '
        printf 0 > /proc/sys/net/ipv6/conf/all/accept_dad
        printf 0 > /proc/sys/net/ipv6/conf/default/accept_dad'
    ip -n "$ns" link add v0 type veth peer name v1
    ip -n "$ns" link set v0 up
    ip -n "$ns" link set v1 up
    for _ in $(seq 50); do
        [[ -n $(ip -n "$ns" -6 addr show dev v0 scope link) ]] && return
        sleep 0.1
    done
    echo "family-bench: no link-local address on v0" >&2
    exit 2
}

setup() {
    local ns=$1
    ip -n "$ns" link set lo up
    case $ns in
    bare) ;;
    no-address)
        # No link-local address either.
        at "$ns" sh -c 'printf 1 > /proc/sys/net/ipv6/conf/default/addr_gen_mode'
        ip -n "$ns" link add v0 type veth peer name v1
        ip -n "$ns" link set v0 up
        ip -n "$ns" link set v1 up
        ip -n "$ns" route add default dev v0
        ip -n "$ns" -6 route add default dev v0
        ;;
    link-local-only)
        veth "$ns"
        ip -n "$ns" -6 route add default via fe80::1 dev v0
        ;;
    on-link)
        veth "$ns"
        ip -n "$ns" -6 route add fd00:9::/64 dev v0
        ip -n "$ns" addr add 169.254.1.2/16 dev v0
        ip -n "$ns" route add 10.9.0.0/16 dev v0
        ;;
    global)
        veth "$ns"
        ip -n "$ns" addr add 10.0.5.2/24 dev v0
        ip -n "$ns" route add default via 10.0.5.1
        ip -n "$ns" addr add 2001:db8:5::2/64 dev v0 nodad
        ip -n "$ns" -6 route add default via 2001:db8:5::1
        ;;
    routes)
        ip -n "$ns" route add unreachable 198.51.100.0/26
        ip -n "$ns" route add prohibit 198.51.100.64/26
        ip -n "$ns" route add blackhole 198.51.100.128/26
        ip -n "$ns" -6 route add unreachable 2001:db8:1::/48
        ip -n "$ns" -6 route add prohibit 2001:db8:2::/48
        ip -n "$ns" -6 route add blackhole 2001:db8:3::/48
        ;;
    no-ipv6)
        at "$ns" sh -c '
            printf 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
            printf 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
            printf 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6'
        ;;
    dns-timeout)
        # The name server is on the link, at a fixed MAC nobody answers for:
        # its queries leave and are dropped, with no ICMP back; the resolver
        # would wait 10 s for each. No IPv6 on the link: what its far end
        # receives is the queries alone (no neighbour discovery).
        at "$ns" sh -c 'printf 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6'
        ip -n "$ns" link add v0 type veth peer name v1
        ip -n "$ns" link set v0 up
        ip -n "$ns" link set v1 up
        ip -n "$ns" addr add 10.53.0.2/24 dev v0
        ip -n "$ns" neigh add 10.53.0.53 lladdr 02:00:00:00:00:53 dev v0 nud permanent
        printf 'nameserver 10.53.0.53\noptions timeout:10 attempts:1\n' > /run/resolv.conf
        if [[ -e /etc/nsswitch.conf ]]; then
            printf 'hosts: dns\n' > /run/nsswitch.conf
        fi
        ;;
    esac
}

# Packets the far end of the dns-timeout link received: its queries only.
received() {
    ip -n "$1" -s link show v1 | awk '/RX:/ { getline; print $2; exit }'
}

failed=0
for case in bare no-address link-local-only on-link global routes no-ipv6 dns-timeout; do
    ip netns add "$case"
    setup "$case"
    echo "== $case"
    if out=$(at "$case" env SPING_FAMILY_CASE="$case" \
        "$bin" --ignored --exact context::tests::family_bench --nocapture 2>&1) \
        && grep -q 'test result: ok. 1 passed' <<<"$out"; then
        :
    else
        printf '%s\n' "$out" | sed 's/^/   /'
        failed=1
        break
    fi
    if [[ $case == dns-timeout ]]; then
        # The queries did leave: the far end of the link saw them.
        if (( $(received "$case") == 0 )); then
            echo "family-bench: no query reached the link" >&2
            failed=1
            break
        fi
        printf 'hosts: files\n' > /run/nsswitch.conf
        : > /run/resolv.conf
    fi
    ip netns del "$case"
done

if [[ $failed -ne 0 ]]; then
    echo "family-bench: FAILED" >&2
    exit 1
fi
echo "family-bench: all cases passed"
