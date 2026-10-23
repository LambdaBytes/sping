# sping JSON Contract v1

This document defines the stable JSON output format for `sping --view json`.

## Format

NDJSON (Newline-Delimited JSON) — one JSON object per probe, one per line.
Batch mode writes one object per target instead: its state after its last
probe.

## Stable Fields (v1)

These fields are guaranteed present in every JSON line:

| Field | Type | Description |
|-------|------|-------------|
| `target_host` | string | Original target as provided by user |
| `target_ip` | string | Resolved IP address |
| `seq` | number | Probe sequence number (1-based) |
| `sent` | number | Total probes sent |
| `received` | number | Total replies received |
| `lost` | number | Total probes lost |
| `loss_pct` | number | Loss percentage (0.0–100.0) |
| `rtt_last` | number \| null | Last RTT in milliseconds |
| `rtt_avg` | number \| null | Average RTT in milliseconds |
| `rtt_min` | number \| null | Minimum RTT in milliseconds |
| `rtt_max` | number \| null | Maximum RTT in milliseconds |
| `jitter` | number \| null | Jitter in milliseconds |
| `mdev` | number \| null | RTT standard deviation in milliseconds (added in 1.4.0, additive) |
| `ttl` | number \| null | TTL from last reply (0 or null if unavailable) |
| `quality` | string | Grade: "A", "B", "C", "D", or "unknown" |
| `quality_score` | number \| string | Score 0–100, or "unknown" |
| `trend` | string | "stable", "improving", "degrading", or "unknown" |
| `pulse` | array | Recent probe results (Reply/Loss entries) |

## Optional Fields

| Field | Type | When present |
|-------|------|-------------|
| `dns_time` | number | Only when target was a hostname (ms) |
| `outage_duration` | number | Only during active outage (ms) |
| `last_spike_rtt` | number | Only when spike detected (ms) |
| `spike_guard` | boolean | Only when true (cooldown active) |
| `recovery_duration` | number | Only on recovery from outage (ms) |
| `net_ctx` | object | Network context (see below) |
| `probe` | string | Only with `--tcp`: `"tcp"` (added in 1.6.0) |
| `port` | number | Only with `--tcp`: the probed port (added in 1.6.0) |
| `refused` | number | Only with `--tcp`: refused connects so far, counted in `received` (added in 1.6.0) |
| `tcp_state` | string | Only with `--tcp`, after the first probe: how the last connect ended, `"open"`, `"refused"`, `"timeout"` or `"error"` (added in 1.6.0) |
| `gateway` | object | Single target only, once the gateway probe has a result: its state (see below; added in 1.6.0) |
| `wan` | object | Single target only, once the WAN reference probe (`--wan-probe`) has a result: its state (see below; added in 1.6.0) |
| `diagnosis` | array | Only when sping concludes something: the findings, in priority order (see below; added in 1.6.0) |
| `active_diagnosis` | object | Only with `--diagnose`, while or after the target is down: what the extra probes found (see below; added in 1.7.0, experimental) |
| `icmp_unreachable` | object | ICMP only, on the line whose probe got a destination unreachable instead of a reply: who sent it and what it said (see below; added in 1.8.0) |

## net_ctx Object

| Field | Type | Description |
|-------|------|-------------|
| `interface` | string | Network interface name |
| `local_ip` | string | Local IP address |
| `prefix_len` | number | Network prefix length |
| `gateway` | string \| null | Gateway IP or null |
| `target_class` | string | "SameLan", "RoutedInternal", "PublicNetwork", "DefaultGateway", "LinkLocal" (a loopback target, `127.0.0.0/8` or `::1`, is "RoutedInternal") |

## gateway and wan Objects (added in 1.6.0)

The auxiliary probes of the single-target mode: ICMP to the default gateway
and to the WAN reference, each one 3 s after the previous one ended (2 s
timeout), whatever the main probe.

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | Address probed |
| `state` | string | `"online"` or `"offline"` once 2 replies or 3 losses in a row decided it, else `"unknown"` |
| `rtt_last` | number \| null | Last probe's RTT in milliseconds; `null` when it got no reply |

An absent object means no evidence: no default gateway was found (`wan` can
be present without `gateway`), the probe has no result yet or could not start
(no ICMP permission), or the line comes from batch mode, which runs no
auxiliary probe. `"unknown"` means a result that has not decided a state yet.

## icmp_unreachable Object (added in 1.8.0)

The line's probe got an ICMP destination unreachable: a router on the way,
or this host, said the target cannot be reached. The probe is lost, as in
`ping` (`lost`, `pulse` `Loss`, no `rtt_last`), and is not a timeout. Only the
line of that probe carries it; a batch line, the target's last probe.

| Field | Type | Description |
|-------|------|-------------|
| `from` | string | Who sent it: a router, or this host's own address when it has no route or no neighbor for the target |
| `kind` | string | `"net"`, `"host"`, `"protocol"`, `"port"`, `"admin_prohibited"` or `"other"`, as in `reported_unreachable` |

What was observed, not its cause: a firewall on the way may send one too. On
Linux (IPv4 and IPv6), macOS (IPv4) and Windows. Elsewhere, and for any other
ICMP error (a time exceeded with `-t`, for one), the probe ends as before: a
timeout on Linux and macOS, an error naming the status on Windows.

## diagnosis Array (added in 1.6.0)

What sping concludes from the same line's fields, `gateway` and `wan`. Each
finding is an object with a `code` and, for some, evidence fields. Codes are
only ever added, never renamed or removed: a consumer ignores a code it does
not know. Batch lines diagnose the target alone (no `gateway`/`wan`). A
finding may repeat on later lines (`context_changed`, with its age).

| `code` | Evidence | Meaning |
|--------|----------|---------|
| `tcp_refused` | `port` | The last connect was refused: the host, or a firewall on the way, answered for the port |
| `recovered` | `duration` (ms) | An outage just ended, after `duration` |
| `context_changed` | `changes`, `age_s` | The target's `net_ctx` changed `age_s` seconds ago (re-detected every 15 s); repeated on every line for 30 s. `changes`: one `{"what", "from", "to"}` per field that changed, `what` a `net_ctx` key (`interface`, `local_ip`, `prefix_len`, `gateway`, `target_class`) and `from`/`to` its values as `net_ctx` writes them, `null` when unknown (`"unknown"`, `0.0.0.0`, `0`, no gateway). Single target only; never with `-I` or `-S`, where `net_ctx` is the system's route, not the probe's (added in 1.7.0) |
| `outage` | `duration` (ms) | The target has not answered for `duration` |
| `gateway_unreachable` | — | Target and gateway down: local network |
| `upstream_outage` | — | Target and WAN reference down, gateway up |
| `wan_unreachable` | — | Target and WAN reference down, gateway state unknown: no cause claimed |
| `target_unreachable` | — | Target down; gateway and WAN reference not down (see `wan`) |
| `latency_spike` | `rtt` (ms) | A latency spike, with the spike guard on |
| `high_jitter` | — | No recent loss, but the last 20 probes' replies deviate from their mean by more than half of it (the quality grade's window and measure, not the lifetime `jitter` field) |
| `intermittent_loss` | `recent_loss_pct` | Some, not all, of the last 20 probes were lost |
| `wan_degraded` | — | Target reachable, WAN reference down, gateway up |
| `name_lookup_failed` | `timed_out` | The last lookup of the target's name (repeated every 60 s) failed — `timed_out`: no answer within 5 s — while the WAN reference answers (its state `online` and its last probe answered); sping keeps probing the address it had (added in 1.7.0) |
| `lookup_without_family` | `family` (`ipv4`/`ipv6`) | The last lookup of the target's name gave no address of the family probed; not that the name has none: a resolver may leave out what the host cannot reach (added in 1.7.0) |

## active_diagnosis Object (added in 1.7.0, experimental)

With `--diagnose` (single target), when the target stops answering sping
probes further on its own sockets — the source the system has for the
target, the same name's address of the other family, TCP 443 and 80 (or the
`--tcp` port, on the other family), a bounded traceroute — and concludes from
what it observed. `diagnosis` stays the correlator's, drawn from the line's
own fields; this object comes from the extra probes. Experimental: its codes
may still change before it leaves that state.

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | Address diagnosed (no zone, as `target_ip`) |
| `state` | string | `"diagnosing"`, `"done"`, or `"incomplete"` |
| `conclusions` | array | With `"done"`: what was observed, in order (see below) |
| `gaps` | array | With `"done"`: what could not be established: `{"about": …, "reason": …, "detail"?: …}` |

`"incomplete"` appears only on the last line of a `-c N` run, when the
diagnosis did not conclude within its budget or was interrupted: that line
waits for it (still one line per probe). Without `-c`, a stream that ends
with `"diagnosing"` did not conclude either.

While the target stays down, sping checks again 5 minutes after each
diagnosis concludes (added in 1.8.0): `state` stays `"done"`, with the
conclusions and gaps standing, until the new ones replace them whole. A
`-c N` run does not wait for such a check.

| `code` | Fields | Meaning |
|--------|--------|---------|
| `no_source` | `family` | No route or source address of the target's family for it on this host |
| `reported_unreachable` | `ttl`, `from`, `kind` | Hop `ttl` (`from`) reported the target unreachable (`net`, `host`, `protocol`, `port`, `admin_prohibited`, `other`) |
| `silent_after` | `last_hop` (`{ttl, from[]}` or `null`), `silent` | The last hop that answered (every address that did, with load balancing) and how many hops after it stayed silent; `null`: none answered. Observed silence, not proof of a break: a target that filters ICMP behind silent routers looks the same |
| `target_answers_icmp` | `ttl` | The target answered the traceroute's echo at hop `ttl` |
| `answers_tcp` | `port`, `refused` | The target answered a TCP connect (`refused`: something answered for the port) |
| `other_family_works` | `family`, `address` | That address of the other family (`ipv4`/`ipv6`) answered; not every address of the family |
| `other_family_fails` | `family`, `address` | Probes to that address left and got no answer |

`gaps[].about`: `main`, `other_family`, `tcp`, `trace`, `name`.
`gaps[].reason`: `explicit_family` (`-4`/`-6`), `explicit_source` (`-S`),
`literal` (an address was given), `no_address`, `no_source`,
`resolve_failed`, `ceiling`, `unavailable` (`detail`: `permission` or
`platform`), `inconclusive`, `failed`, `unknown`; `detail` carries the
message where there is one.

## `sping --ip --view json` (added in 1.8.0)

Not a probe line: one object, written once, with the host's addresses. It has
its own fields; none of the above applies to it.

```json
{"interfaces":[{"name":"eth0","addresses":[
   {"ip":"192.168.1.100","prefix_len":24,"kind":"private"},
   {"ip":"2001:db8::5b1:c2ff:1","prefix_len":64,"kind":"global",
    "temporary":true,"deprecated":false,"tentative":false,"duplicate":false}]}],
 "source":{"ipv4":{"to":"1.1.1.1","ip":"192.168.1.100","interface":"eth0"},
           "ipv6":{"to":"2606:4700:4700::1111","ip":null}},
 "gateway":{"ipv4":{"ip":"192.168.1.1","interface":"eth0"}}}
```

| Field | Type | Description |
|-------|------|-------------|
| `interfaces[].name` | string | Interface name, in the order the system lists them |
| `interfaces[].addresses[].ip` | string | Address (no zone), IPv4 before IPv6 |
| `…addresses[].prefix_len` | number \| null | Prefix length; `null` when the system gives none |
| `…addresses[].kind` | string | `"loopback"`, `"link_local"`, `"private"` (RFC 1918, `fc00::/7`), `"shared"` (`100.64.0.0/10`), `"global"` |
| `…addresses[].temporary`, `deprecated`, `tentative`, `duplicate` | boolean \| null | IPv6 addresses only: their state; `null` when the system does not report it (`temporary` on Windows) |
| `source.ipv4`, `source.ipv6` | object | The source the system picks towards `to`, a global reference address: `ip` and `interface` (`null` when no single interface holds it); `ip` `null`: no source of that family; `{"to", "unknown"}`: it could not be told, with the reason |
| `gateway.ipv4` | object \| null | The IPv4 default gateway, `{"ip", "interface"}` (`interface` `null` when unknown); `null`: no default route; `{"unknown": reason}`: the routes could not be read |

With `--external`, the object has one more member, `external`; without it,
the object is as above, byte for byte:

```json
"external":{"server":"stun.cloudflare.com:3478",
            "ipv4":{"ip":"203.0.113.5","port":40312,"local":"192.168.1.100:51234","asked":"192.0.2.10"},
            "ipv6":{"asked":"2001:db8::10","unknown":"no route to the server"}}
```

| Field | Type | Description |
|-------|------|-------------|
| `external.server` | string | The STUN server asked, `host:port` (`[address]:port` for an IPv6 address) |
| `external.ipv4`, `external.ipv6` | object \| null | `{"ip", "port", "local", "asked"}`: the address and port the server saw, this host's socket the request left from (`null` when the system did not say) and the server's address that was asked; `{"asked", "unknown"}`: not told, with the reason (`asked` `null` when no address was asked: the name did not resolve); `null`: the server's name gave no address of that family |

Exit code: `0` when the addresses were read, whatever the source, the
gateway or the external addresses; `2` when they could not be read or
`--external` names no server (the reason on stderr).

## Semantics

- `"unknown"` is used instead of `null` for `quality`, `quality_score`, and `trend` when insufficient data (< 3 probes for quality, < 6 for trend).
- RTT values are in milliseconds as floating point numbers.
- `pulse` array contains objects like `{"Reply": 13.5}` or `"Loss"`.
- With `--tcp`, a probe is a TCP connect: an open or a refused port is a reply
  (`received`, `pulse` `Reply`, with the handshake time), no answer before the
  timeout or a local error is a loss. `ttl` is `null`. ICMP lines carry none of
  the four TCP fields.
- All numeric fields use standard JSON number representation.

## Compatibility

- New fields may be added in future versions.
- Existing field types and semantics will not change within v1.
- Consumers should ignore unknown fields (forward-compatible).
