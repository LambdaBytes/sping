# sping

A modern ping for humans. Terminal-native, real-time connectivity monitor that doesn't just measure packets — **it interprets network context**.

<p align="center"><img src="docs/sping-logo.png" alt="sping" width="300"></p>

![sping probing 8.8.8.8 in the compact view](docs/sping.gif)

**Status:** functional and in active use, with a frozen JSON contract.
Linux, macOS and Windows; x86_64, aarch64 and armv7 (Raspberry Pi).

Answers three questions at once:
1. **Does the target respond?** — RTT, TTL, jitter, loss, quality score, trend
2. **Do I have network from this interface?** — gateway reachable, WAN reachable
3. **What type of problem is it?** — correlated diagnostics, automatic

```
sping google.com (216.58.204.174) via eth0  ⠙ probing...

Pulse      █▇▆█▁▃█▄
Latency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms
Status     Reachable · loss 0% · sent 8 · recv 8 · ttl 112 (Windows) · hops ~16
Context    if eth0 · 192.168.1.100/24 · gw ● · wan ● · public
Quality    A (100) · stable
```

## Multi-target dashboard

```bash
sping 192.168.1.1 8.8.8.8 google.com
```

```
Target                      RTT        Avg   Loss    Qual      Trend        TTL  Hops
───────────────────────────────────────────────────────────────────────────────
192.168.1.1             0.31 ms    0.30 ms     0%    A100     stable    64(Lin)    ~0
8.8.8.8                 13.6 ms    13.6 ms     0%    A100     stable   112(Win)   ~16
google.com (216.58.…    13.7 ms    13.6 ms     0%    A100     stable   112(Win)   ~16
```

## Install

### Pre-built binaries

Download from the [Releases page](../../releases):

| Platform | Asset |
|----------|-------|
| Linux x86_64 | `sping-vX.Y.Z-linux-x86_64` |
| Linux aarch64 | `sping-vX.Y.Z-linux-aarch64` |
| Windows x86_64 | `sping-vX.Y.Z-windows-x86_64.exe` |
| macOS Apple Silicon | `sping-vX.Y.Z-macos-arm64` |
| Debian/Ubuntu amd64 | `sping_X.Y.Z-1_amd64.deb` |
| Debian/Ubuntu arm64 | `sping_X.Y.Z-1_arm64.deb` |

The Linux binaries and packages need glibc 2.34 or newer: Debian 12, Ubuntu
22.04, Raspberry Pi OS (Bookworm) or later.

Verify with `SHA256SUMS` from the same release. From v1.5.5 on, every file of
a GitHub release also has a build provenance attestation, which tells the
commit and the workflow run that produced it:

```bash
gh attestation verify sping-vX.Y.Z-linux-x86_64 --repo LambdaBytes/sping
```

### Debian / Ubuntu (.deb)

```bash
sudo dpkg -i sping_1.5.5-1_amd64.deb     # or _arm64.deb on aarch64
```

The package installs:
- binary at `/usr/bin/sping`
- man page (`man sping`)
- shell completions for bash, zsh and fish
- docs under `/usr/share/doc/sping/`

### macOS

From v1.5.5 on, the macOS binary of a release is signed with a Developer ID
and notarized by Apple, so it runs once it is made executable:

```bash
chmod +x sping-vX.Y.Z-macos-arm64
./sping-vX.Y.Z-macos-arm64 8.8.8.8
```

macOS refuses an earlier, unsigned binary until its quarantine attribute is
removed: `xattr -d com.apple.quarantine sping-vX.Y.Z-macos-arm64`.

### From crates.io

Requires Rust 1.88+. Installs the binary only (no man page or shell
completions):

```bash
cargo install sping
```

### From source

Requires Rust 1.88+ (edition 2024 + let-chains).

```bash
git clone https://github.com/LambdaBytes/sping.git
cd sping
cargo build --release
# Binary at ./target/release/sping
```

## Usage

```bash
# Single target — compact view (default)
sping 8.8.8.8

# Multiple targets — dashboard table
sping 192.168.1.1 1.1.1.1 api.example.com

# Hostname
sping google.com

# Fast probing (200ms interval)
sping 8.8.8.8 -i 200

# Bind to an interface (Linux) / a source IP (Linux, macOS)
sping 8.8.8.8 -I eth0
sping 8.8.8.8 -S 192.168.1.100

# Ping-style flags: count, timeout, payload size, TTL, quiet, family
sping 8.8.8.8 -c 5                # stop after 5 probes (any view)
sping 8.8.8.8 -W 1                # 1s per-probe timeout
sping 8.8.8.8 -s 120              # 120-byte payload
sping 8.8.8.8 -t 10               # outgoing TTL / hop limit
sping 8.8.8.8 -c 10 -q            # quiet: summary only (classic)
sping example.com -4              # force IPv4 (-6 for IPv6)
sping fe80::1%eth0                # IPv6 link-local: the zone is required

# ASCII-only output: automatic on non-UTF-8 locales and on the legacy
# Windows console (SPING_ASCII=0 forces Unicode); NO_COLOR honored
sping 8.8.8.8 --ascii

# List interfaces
sping --list-interfaces

# Debug mode
sping --debug 8.8.8.8
```

Exit codes are ping-compatible: `0` replies received, `1` no replies, `2` error.

### Batch mode

Probe a list of targets from a file:

```bash
# Create a hosts file (one target per line, # comments allowed)
cat > hosts.txt << EOF
8.8.8.8
1.1.1.1
google.com
192.168.1.20
EOF

# Summary to stdout (10 probes per host)
sping --batch hosts.txt -c 10

# JSON output
sping --batch hosts.txt -c 20 --view json

# Save to file
sping --batch hosts.txt -c 10 -o results.txt

# JSON to file
sping --batch hosts.txt -c 10 -o results.json --view json

# Fast interval
sping --batch hosts.txt -c 50 -i 200
```

Output (summary):
```
8.8.8.8                  10/10  0%  avg 13.6 ms  min 13.6 ms  max 13.7 ms  jitter 0.05 ms  ttl 112 (Windows) hops ~16  A(100) stable
1.1.1.1                  10/10  0%  avg 20.0 ms  min 19.9 ms  max 20.1 ms  jitter 0.08 ms  ttl 52 (Linux) hops ~12  A(100) stable
```

All targets are probed in parallel. Full diagnostics (quality, trend, spikes) included.

### Views

```bash
sping 8.8.8.8                    # compact (default) — fixed TUI
sping 8.8.8.8 --view extended    # compact + RTT dist + echo path
sping 8.8.8.8 --view classic     # traditional ping scrolling
sping 8.8.8.8 --view json        # NDJSON for scripting
sping 8.8.8.8 --view json | jq '{rtt: .rtt_last, ttl: .ttl, quality: .quality}'
```

### ICMP permissions

sping works without admin/sudo on all platforms. On Linux it uses unprivileged
DGRAM ICMP sockets (the `net.ipv4.ping_group_range` sysctl, which covers all
users by default on Debian and most distributions), and falls back to a RAW
socket only when DGRAM is denied.

If DGRAM ICMP is restricted, widen the allowed group range:

```bash
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
```

Two features require `CAP_NET_RAW` (the RAW fallback and interface binding with
`-I`/`--interface`). Grant it to the binary without running as root:

```bash
sudo setcap cap_net_raw+ep /usr/bin/sping
```

## Features

- **Quality score** A–D (0–100) with trend detection (stable/improving/degrading)
- **Spike detection** with adaptive threshold and cooldown
- **Outage timer** with recovery events
- **Diagnostic correlation**: "target unreachable · internet still OK", "gateway unreachable · local network issue likely"
- **TTL + OS hint + hop count**: `ttl 116 (Windows) · hops ~12`
- **Network context**: interface, gateway, IP/prefix, target classification (same LAN / public / default gateway)
- **GW/WAN auxiliary probes** with hysteresis (3 fails → offline, 2 ok → online)
- **RTT distribution** (extended view): p50, p95, p99, range, spikes
- **Echo path animation** (extended view)
- **IPv4 and IPv6**
- **JSON output** — stable NDJSON format, see [JSON_CONTRACT.md](JSON_CONTRACT.md)
- **Debug mode** — `--debug` or `SPING_LOG=debug`

## Platforms

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| IPv4 ICMP | DGRAM socket | DGRAM socket | IcmpSendEcho |
| IPv6 | ICMPv6 DGRAM | ICMPv6 DGRAM | Icmp6SendEcho2 |
| TTL / hop limit | recvmsg | IP header (IPv4), recvmsg (IPv6) | API (IPv4 only) |
| Gateway detection | /proc/net/route | `route` command | `route print` |
| Interface detection | /proc/net/route, if_inet6 | `ifconfig` | GetAdaptersAddresses |
| `-I` interface | SO_BINDTODEVICE | accepted, no effect | warning, unbound |
| `-S` source | bind() | bind() | OS routes |
| Admin required | No | No | No |
| All views | full | full | full |

## Architecture

Own ICMP implementation per platform. No third-party ping libraries.

- Linux: `socket2` DGRAM (RAW fallback) + `libc` recvmsg for TTL / hop limit
- macOS: `socket2` DGRAM + IP header parsing for the IPv4 TTL, recvmsg for the
  IPv6 hop limit
- Windows: `IcmpSendEcho` / `Icmp6SendEcho2` FFI from `iphlpapi.dll`

Async Tokio runtime, `watch` channels, single-writer renderer at 10 FPS.

### Supported architectures

`x86_64`, `aarch64` and `armv7` (armhf) are compile-checked; aarch64/armv7 cover
Raspberry Pi OS (64- and 32-bit). Release artifacts are produced for Linux
x86_64/aarch64, macOS arm64 and Windows x86_64.

## Known limitations

- `-I`/`--interface` binds only on Linux: macOS accepts the flag but it has
  no effect, Windows prints a warning and probes unbound. `-S`/`--source` is
  ignored on Windows, where the OS picks the route.
- The raw-socket fallback and `-I` need `CAP_NET_RAW` (see
  [SECURITY.md](SECURITY.md)); the unprivileged DGRAM path covers the common
  case.
- Names go through the system resolver (5 s timeout) and are resolved again
  every 60 s while monitoring; sping does no reverse DNS and keeps no DNS
  cache of its own.
- IPv6 replies carry a hop limit (`ttl`) on Linux and macOS; on Windows it
  is not shown (`0` in JSON). Gateway detection and `--list-interfaces` are
  IPv4 only.
- An IPv6 link-local target needs its zone: `fe80::1%eth0`, or the interface
  index (`fe80::1%2`), which is the only form Windows takes.

## Roadmap

- Distribution packaging: AUR, Fedora/COPR, Debian/Raspberry Pi OS, Homebrew
  (work in progress under [`packaging/`](packaging/)).

## Performance

| Metric | Value |
|--------|-------|
| Binary | 1.6 MB (stripped + LTO) |
| RAM | ~4 MB resident |
| CPU | < 1% at two probes per second |
| Code | ~8,400 lines Rust |
| Tests | 127 (108 unit + 19 E2E) |

## Tour

Every view and mode in 80 seconds: the multi-target panel, batch mode from a
file, NDJSON with `jq`, the extended view, the classic ping-compatible view
with its exit codes, the diagnostics on a failing target, and the small things
(interfaces, `NO_COLOR`, DNS timing).

![sping tour: panel, batch, NDJSON, extended, classic, diagnostics](docs/sping-tour.gif)

## What 1.5.5 fixes

Against 1.5.4: an IPv6 link-local target with its zone, IPv4, IPv6 and
link-local targets in one table, and every target with its own network
context, in the JSON too.

![sping 1.5.5 against 1.5.4: link-local zones, mixed address families, per-target context](docs/sping-1.5.5.gif)

## License

MIT
