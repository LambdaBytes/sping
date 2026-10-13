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

## diagnosis Array (added in 1.6.0)

What sping concludes from the same line's fields, `gateway` and `wan`. Each
finding is an object with a `code` and, for some, evidence fields. Codes are
only ever added, never renamed or removed: a consumer ignores a code it does
not know. Batch lines diagnose the target alone (no `gateway`/`wan`).

| `code` | Evidence | Meaning |
|--------|----------|---------|
| `tcp_refused` | `port` | The last connect was refused: the host, or a firewall on the way, answered for the port |
| `recovered` | `duration` (ms) | An outage just ended, after `duration` |
| `outage` | `duration` (ms) | The target has not answered for `duration` |
| `gateway_unreachable` | — | Target and gateway down: local network |
| `upstream_outage` | — | Target and WAN reference down, gateway up |
| `wan_unreachable` | — | Target and WAN reference down, gateway state unknown: no cause claimed |
| `target_unreachable` | — | Target down; gateway and WAN reference not down (see `wan`) |
| `latency_spike` | `rtt` (ms) | A latency spike, with the spike guard on |
| `high_jitter` | — | No recent loss, but the last 20 probes' replies deviate from their mean by more than half of it (the quality grade's window and measure, not the lifetime `jitter` field) |
| `intermittent_loss` | `recent_loss_pct` | Some, not all, of the last 20 probes were lost |
| `wan_degraded` | — | Target reachable, WAN reference down, gateway up |

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
