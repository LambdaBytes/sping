# sping JSON Contract v1

This document defines the stable JSON output format for `sping --view json`.

## Format

NDJSON (Newline-Delimited JSON) — one JSON object per probe, one per line.

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

## net_ctx Object

| Field | Type | Description |
|-------|------|-------------|
| `interface` | string | Network interface name |
| `local_ip` | string | Local IP address |
| `prefix_len` | number | Network prefix length |
| `gateway` | string \| null | Gateway IP or null |
| `target_class` | string | "SameLan", "RoutedInternal", "PublicNetwork", "DefaultGateway", "LinkLocal" |

## Semantics

- `"unknown"` is used instead of `null` for `quality`, `quality_score`, and `trend` when insufficient data (< 3 probes for quality, < 6 for trend).
- RTT values are in milliseconds as floating point numbers.
- `pulse` array contains objects like `{"Reply": 13.5}` or `"Loss"`.
- All numeric fields use standard JSON number representation.

## Compatibility

- New fields may be added in future versions.
- Existing field types and semantics will not change within v1.
- Consumers should ignore unknown fields (forward-compatible).
