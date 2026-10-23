<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/LambdaBytes/sping/HEAD/docs/brand/sping-logo-on-dark.png">
    <img src="docs/brand/sping-logo-on-light.png" alt="sping" width="240">
  </picture>
  <br><br>
  <a href="https://github.com/LambdaBytes/sping/releases/latest"><img src="https://img.shields.io/github/v/release/LambdaBytes/sping?style=flat&labelColor=0B0E10&color=C9A227&logo=github&logoColor=white" alt="GitHub release"></a>
  <a href="https://crates.io/crates/sping"><img src="https://img.shields.io/crates/v/sping?style=flat&labelColor=0B0E10&color=C9A227&logo=rust&logoColor=white" alt="crates.io"></a>
  <a href="https://github.com/LambdaBytes/sping/releases"><img src="https://img.shields.io/github/downloads/LambdaBytes/sping/total?style=flat&labelColor=0B0E10&color=C9A227&logo=github&logoColor=white" alt="Downloads"></a>
  <br>
  <a href="https://github.com/LambdaBytes/sping/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/LambdaBytes/sping/ci.yml?branch=main&style=flat&label=CI&labelColor=0B0E10&logo=githubactions&logoColor=white" alt="CI"></a>
  <a href="https://github.com/LambdaBytes/sping/stargazers"><img src="https://img.shields.io/github/stars/LambdaBytes/sping?style=flat&labelColor=0B0E10&color=D8DEE4&logo=github&logoColor=white" alt="GitHub stars"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/LambdaBytes/sping?style=flat&labelColor=0B0E10&color=D8DEE4" alt="License: MIT"></a>
  <br><br>
</div>

A modern ping for humans. Terminal-native, real-time connectivity monitor that doesn't just measure packets — **it interprets network context**.

![sping 1.8.0: the live view, several targets at once, --diagnose on a host that stops answering ping, a destination unreachable told apart from a timeout, and --ip --external](docs/sping-1.8.0.gif)

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
Status     Reachable · loss 0% · sent 8 · recv 8 · ttl 112 · hops ~16
Context    if eth0 · 192.168.1.100/24 · gw ● · wan ● · public
Quality    A (100) · excellent
```

## What's new in 1.8.0

- **Unreachable is not a timeout**: when a router or this host answers the
  probe with a destination unreachable, sping says who sent it and what it
  said: `From 192.0.2.1: seq=3 Destination Host Unreachable` in the classic
  view, `192.0.2.1 reports host unreachable` in Events, `icmp_unreachable`
  in JSON. On Linux, macOS (IPv4) and Windows.
- **`sping --ip`**: this host's addresses, every interface, IPv4 and IPv6,
  with their prefix, kind and IPv6 state, the source each family uses and
  the default gateway. It sends nothing; with `--external` it also asks a
  STUN server which address it sees. See
  [Host addresses](#host-addresses---ip).
- **`--diagnose` in a long outage**: while the target stays down, the same
  checks run again 5 minutes after each diagnosis concludes.
- **`--icmp`**: the ICMP probe, named. It changes nothing today; it keeps
  that probe for scripts when 2.0 changes what `sping target` does (see
  [Roadmap](#roadmap)).
- **Fixes** in `--diagnose`: on Windows, an unreachable answer for the other
  family's address now means that family fails too, as on Linux; on Linux, a
  redirect during the traceroute no longer ends its round with `recv failed`.

Every change, version by version: [CHANGELOG.md](CHANGELOG.md).

## Multi-target dashboard

```bash
sping 192.168.1.1 8.8.8.8 google.com
```

```
Target                      RTT        Avg   Loss    Qual      Trend        TTL  Hops
───────────────────────────────────────────────────────────────────────────────
192.168.1.1             0.31 ms    0.30 ms     0%    A100     stable   64(Unix)    ~0
8.8.8.8                 13.6 ms    13.6 ms     0%    A100     stable        112   ~16
google.com (216.58.…    13.7 ms    13.6 ms     0%    A100     stable        112   ~16
```

The table is live and needs a terminal: with stdout a file or a pipe, sping
prints only each target's summary at the end (`-c N` stops it). Batch mode
(`--batch`, below) prints per-host results or JSON.

## Install

| Method | Command | Platforms | Man page and completions |
|--------|---------|-----------|--------------------------|
| Homebrew | `brew install LambdaBytes/tap/sping` | macOS | yes |
| Scoop | `scoop install lambdabytes/sping`, once the bucket is added (see below) | Windows x86_64 | no |
| crates.io | `cargo install sping` | Linux, macOS, Windows, with Rust 1.88+ | no |
| Pre-built binary | from the [Releases page](https://github.com/LambdaBytes/sping/releases) | Linux, macOS, Windows | no |
| Debian / Ubuntu package | `.deb` from the [Releases page](https://github.com/LambdaBytes/sping/releases) | Debian 12, Ubuntu 22.04, Raspberry Pi OS (Bookworm) or later | yes |
| From source | `cargo build --release` | Linux, macOS, Windows, with Rust 1.88+ | no |

### Homebrew

From v1.6.0 on. Builds from source and installs the binary, the man page and
the shell completions:

```bash
brew install LambdaBytes/tap/sping
```

### Scoop

From v1.6.0 on. Installs the release's Windows binary, the one listed in its
`SHA256SUMS`:

```powershell
scoop bucket add lambdabytes https://github.com/LambdaBytes/scoop-bucket
scoop install lambdabytes/sping
```

`scoop update sping` moves it to a newer release.

### From crates.io

Requires Rust 1.88+. Installs the binary only (no man page or shell
completions):

```bash
cargo install sping
```

### Pre-built binaries

Download from the [Releases page](https://github.com/LambdaBytes/sping/releases):

| Platform | Asset |
|----------|-------|
| Linux x86_64 | `sping-vX.Y.Z-linux-x86_64` |
| Linux aarch64 | `sping-vX.Y.Z-linux-aarch64` |
| Linux x86_64, static | `sping-vX.Y.Z-linux-x86_64-musl` |
| Linux aarch64, static | `sping-vX.Y.Z-linux-aarch64-musl` |
| Windows x86_64 | `sping-vX.Y.Z-windows-x86_64.exe` |
| macOS Apple Silicon | `sping-vX.Y.Z-macos-arm64` |
| Debian/Ubuntu amd64 | `sping_X.Y.Z-1_amd64.deb` |
| Debian/Ubuntu arm64 | `sping_X.Y.Z-1_arm64.deb` |

The Linux binaries and packages need glibc 2.34 or newer: Debian 12, Ubuntu
22.04, Raspberry Pi OS (Bookworm) or later. The `-musl` binaries are static
and run on any Linux of their architecture, Alpine and older systems
included.

Verify with `SHA256SUMS` from the same release. From v1.5.5 on, every file of
a GitHub release also has a build provenance attestation, which tells the
commit and the workflow run that produced it:

```bash
gh attestation verify sping-vX.Y.Z-linux-x86_64 --repo LambdaBytes/sping
```

### Debian / Ubuntu (.deb)

```bash
sudo dpkg -i sping_1.8.0-1_amd64.deb     # or _arm64.deb on aarch64
```

The package installs:
- binary at `/usr/bin/sping`
- man page (`man sping`)
- shell completions for bash, zsh and fish
- docs under `/usr/share/doc/sping/`

### macOS binary

From v1.5.5 on, the macOS binary of a release is signed with a Developer ID
and notarized by Apple, so it runs once it is made executable:

```bash
chmod +x sping-vX.Y.Z-macos-arm64
./sping-vX.Y.Z-macos-arm64 8.8.8.8
```

macOS refuses an earlier, unsigned binary until its quarantine attribute is
removed: `xattr -d com.apple.quarantine sping-vX.Y.Z-macos-arm64`.

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

# Another WAN reference for the gateway/WAN check (default 1.1.1.1)
sping 8.8.8.8 --wan-probe 9.9.9.9

# Ping-style flags: count, timeout, payload size, TTL, quiet, family
sping 8.8.8.8 -c 5                # stop after 5 probes (any view)
sping 8.8.8.8 -W 1                # 1s per-probe timeout
sping 8.8.8.8 -s 120              # 120-byte payload
sping 8.8.8.8 -t 10               # outgoing TTL / hop limit
sping 8.8.8.8 -c 10 -q --view classic  # quiet: summary only
sping example.com -4              # force IPv4 (-6 for IPv6)
sping fe80::1%eth0                # IPv6 link-local: the zone is required

# TCP connect instead of ICMP (see "TCP connect" below)
sping example.com --tcp 443
sping 192.168.1.1 10.0.0.5 --tcp 22   # every target, the same port

# The ICMP probe, what sping runs without an option until 2.0 (see Roadmap)
sping example.com --icmp

# When the target stops answering, find out why (experimental; one target)
sping example.com --diagnose

# ASCII-only output: automatic on non-UTF-8 locales and on the legacy
# Windows console (SPING_ASCII=0 forces Unicode); NO_COLOR honored
sping 8.8.8.8 --ascii

# This host's addresses: every interface, IPv4 and IPv6, the source each
# family uses and the gateway; sends nothing (see "Host addresses" below)
sping --ip
sping --ip --view json
# ... and the address a STUN server sees (asks stun.cloudflare.com)
sping --ip --external
sping --ip --external stun.example.net:3478
sping --list-interfaces           # the IPv4 list it has always printed

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
8.8.8.8                  10/10  0%  avg 13.6 ms  min 13.6 ms  max 13.7 ms  jitter 0.05 ms  ttl 112 hops ~16  A(100) stable
1.1.1.1                  10/10  0%  avg 20.0 ms  min 19.9 ms  max 20.1 ms  jitter 0.08 ms  ttl 52 hops ~12  A(100) stable
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

### TCP connect

`--tcp PORT` times the TCP handshake with the port instead of sending ICMP
echoes. It needs no ICMP permission and gets through networks that filter
ICMP; it works in every mode (single target, multi-target, batch) and view.

- An open port (`Connected to`) and a refused one (`Refused by`) are both
  answers: something replied, with its time. A refusal may come from the
  target or from a device on the way (a firewall can refuse for it), so it
  shows the path works, not that the service is up. The summary counts them:
  `10 connects, 10 answered (3 refused), 0.0% loss`.
- No answer before `-W` is a loss; a local failure (no route, for example) is
  an error, as a failed ICMP send.
- On Windows each probe sends a single SYN, never retransmitted: Windows
  otherwise retries after a refusal and reports it only after about 2 s.
  Windows waits for the answer to that SYN about 3 s at most, so a `-W` above
  3 s ends there.
- `-W` is the connect timeout, `-t` the TTL / hop limit, `-4`/`-6` the
  family; `-S` binds the source address on every platform, Windows included;
  `-I` behaves as with ICMP. `-s` does not apply and is rejected.
- A source address that cannot be bound is an error (exit code `2`).
- TCP has no TTL to read: there is no `ttl`, OS hint or hop estimate. The
  views show the port (`tcp/443`) and how the last connect ended: the
  compact and extended views say it in Events (`TCP 443 connected · 21 ms`,
  `TCP 443 refused · host or firewall answered`, `TCP 443 timeout · no
  answer`), the table and batch lines as `open`, `refused`, `timeout` or
  `error`; JSON adds `probe`, `port`, `refused` and `tcp_state` (see
  [JSON_CONTRACT.md](JSON_CONTRACT.md)).
- The gateway and WAN probes of the compact and extended views stay ICMP.
- One new connection per probe, closed normally (no reset): each one
  established leaves a `TIME_WAIT` entry on this host, as any short
  connection does.

### Diagnose (experimental)

`--diagnose` finds out, when the target stops answering, what still answers
on the way, and says what it observed, nothing more. One target only.

```bash
sping example.com --diagnose
sping 203.0.113.7 --diagnose -c 30 --view json
```

- It starts when the target goes offline (three probes lost in a row), or at
  the end of a run that got no answer at all (`-c 1 --diagnose` too).
- It uses sockets of its own, never counted in the target's statistics, and
  checks:
  - the source address the system has for the target;
  - the same name's address in the other family: three echoes, or with
    `--tcp PORT` one connect to that port;
  - TCP 443 and 80 on the target (not with `--tcp`, whose port the probe
    already tries);
  - a bounded traceroute: 30 hops, 3 probes each, 20 s at most, stopping
    after 3 silent hops.
- While the target stays down, it checks again 5 minutes after each
  diagnosis concludes; the conclusions shown stay until the new ones are in.
- Events shows `diagnosing…`, then the conclusions:
  `silent after hop 3 (203.0.113.1)`, `hop 5 (198.51.100.9) reports host
  unreachable`, `target answers the trace at hop 7`, `TCP 443 answers`,
  `IPv6 works`.
  - The extended view adds an `Untested` line with what could not be told
    and why (`other family not tried (address given)`, `trace unavailable:
    needs privileges`).
  - The classic view prints `---` lines, again with each new check.
  - JSON lines carry `active_diagnosis` (see
    [JSON_CONTRACT.md](JSON_CONTRACT.md)).
- Traffic is bounded: at most 100 extra probes in any 60 s, three operations
  at once, the traceroute alone.
- An address given, `-4`/`-6` or `-S` keep the other family out. `-W`, `-s`,
  `-I` and `-S` apply to the extra probes; `-t` does not.
- With `-c N`, the last line waits for the diagnosis, at most what is left of
  its budget; otherwise it says `incomplete`. Ctrl+C stops it at once. The
  exit codes do not change.
- The traceroute runs on Linux (with the same sockets and permissions as the
  probe, see [ICMP permissions](#icmp-permissions)), on macOS for IPv4
  targets, without privileges, and on Windows. An IPv6 target on macOS gets
  no traceroute yet: `trace unavailable on this system`.
- Experimental: its texts and JSON codes may still change.

### Host addresses (`--ip`)

From 1.8 on, `sping --ip` shows what the system knows about this host's
addresses, and exits:

```text
eth0     192.168.1.100/24            private
         2001:db8::5b1:c2ff:1/64     global · temporary
         fe80::1c2:3ff:fe45:6789/64  link-local
lo       127.0.0.1/8                 loopback
         ::1/128                     loopback

Source   IPv4 192.168.1.100 (eth0) to 1.1.1.1 · no IPv6 source to 2606:4700:4700::1111
Gateway  IPv4 192.168.1.1 (eth0)
```

- Every address of every interface, with its prefix and kind (`loopback`,
  `link-local`, `private`, `shared (CGNAT)`, `global`). IPv6 addresses also
  show their state: `temporary`, `deprecated`, `tentative` or `duplicate`.
  Windows reports no temporary address yet: it is `null` in JSON.
- The source each family would use towards a global reference address. It
  is that route's source, so a VPN with routes of its own can make it differ
  from the default route's.
- The IPv4 default gateway.
- Without `--external`, nothing is sent and no privilege is needed: the
  source comes from a UDP connect, which sends no packet. What the system does not say is said as
  unknown, never guessed.
- `--view json` prints one object instead (see [JSON_CONTRACT.md](JSON_CONTRACT.md)).
  `--list-interfaces` still prints its IPv4 list as before.

With `--external`, `sping --ip` also asks a STUN server (RFC 8489, over UDP)
which address and port it sees each family's request come from:

```text
Source    IPv4 192.168.1.100 (eth0) to 1.1.1.1 · no IPv6 source to 2606:4700:4700::1111
Gateway   IPv4 192.168.1.1 (eth0)
External  IPv4 203.0.113.5:40312 from 192.168.1.100:51234 · IPv6 unknown (no route to the server) (STUN server stun.cloudflare.com:3478)
```

- It asks a third party, so only when given: `stun.cloudflare.com:3478` by
  default, or `--external SERVER[:PORT]` (`[address]:port` for an IPv6
  address with a port). The system resolver looks the name up once.
- At most three requests per family (at 0, 0.5 and 1.5 s) and 3 s in all,
  both families at once. An answer counts only with the request's
  transaction ID.
- `from` is this host's socket the request left from. With the address the
  server saw, it is the translation on the way out (NAT, CGNAT, a VPN, or
  none); sping does not name it.
- What the server did not say (no answer, an error, no route) is unknown,
  with the reason, and the exit code stays 0.

### ICMP permissions

sping works without admin/sudo on macOS and Windows. On Linux it uses
unprivileged DGRAM ICMP sockets (the `net.ipv4.ping_group_range` sysctl), and
falls back to a RAW socket only when DGRAM is denied. Most distributions open
DGRAM ICMP to every user by default; Debian does from Debian 13 on (the
`linux-sysctl-defaults` package, recommended by systemd), not on Debian 12, and
a system upgraded to 13 may lack that package.

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

**Measurement**
- ICMP echo over IPv4 and IPv6 with its own implementation on each platform,
  no admin rights needed (on Linux, where unprivileged ICMP is allowed: see
  [ICMP permissions](#icmp-permissions)), and a **TCP connect probe**
  (`--tcp PORT`) where ICMP is filtered
- **Quality score** A–D (excellent, good, fair, poor; 0–100) over the last
  20 probes, with a **trend** (stable/improving/degrading) that counts lost
  probes
- **Spike detection** with adaptive threshold and cooldown
- **Outage timer** with recovery events
- RTT, jitter, loss and `mdev`; **RTT distribution** p50/p95/p99, range and
  spikes (extended view); kernel receive timestamps on Linux
- **TTL + hop count**: `ttl 116 · hops ~12`; an OS hint only while the TTL
  is still an initial value (`ttl 64 (Unix-like)`, `128 (Windows)`, `255
  (network)`): past a router the TTL no longer says who answered
- A **destination unreachable** on the probe is told apart from a timeout:
  who sent it and what it said

**Network context and diagnosis**
- **Network context** of each target: interface, source address and prefix,
  default gateway and target class (same LAN, routed internal, public,
  default gateway, link-local, loopback)
- **GW/WAN auxiliary probes** with hysteresis (3 fails → offline, 2 ok →
  online); the WAN reference is `1.1.1.1` or `--wan-probe IP`
- **Diagnostic correlation**: "target unreachable · internet still OK",
  "gateway unreachable · local network issue likely"; in JSON as stable codes
  with their evidence
- While monitoring, hostnames are resolved again every 60 s: when the address
  leaves the DNS answer, sping moves to another one of the same family. A
  lookup that fails while the WAN reference answers, or that gives no address
  of the family probed, is shown
- In single-target mode the context is detected again every 15 s, and a
  change (interface, source, prefix, default gateway, target class) is shown
  for 30 s
- **`--diagnose`** (experimental): when the target stops answering, the
  other address family, TCP 443 and 80 and a bounded traceroute say what
  still answers, checked again 5 minutes after each conclusion while the
  target stays down
- **`sping --ip`**: every address of every interface with its kind and IPv6
  state, the source of each family and the default gateway; with
  `--external`, the address a STUN server sees
- IPv6 link-local targets with their zone (`fe80::1%eth0`)

**Views and modes**
- Five views: compact (default), extended (adds the RTT distribution and the
  echo path), classic (ping-style), JSON and the multi-target table; the
  compact and extended views fall back to classic when the output is not a
  terminal
- The **pulse** bar of the recent probes, scaled to their own RTT range, with
  losses marked and spikes in color
- **Multi-target dashboard** and **batch mode** from a file (summary or JSON,
  to stdout or a file)
- **JSON output** — stable NDJSON format, with the diagnosis as codes and
  the gateway/WAN state it comes from, see [JSON_CONTRACT.md](JSON_CONTRACT.md)
- Ping-style flags (`-c`, `-W`, `-s`, `-t`, `-q`, `-4`/`-6`, `-i`, `-I`,
  `-S`) and ping-compatible exit codes
- ASCII output (`--ascii`, automatic on non-UTF-8 locales and on the legacy
  Windows console) and `NO_COLOR`
- Monitoring stops cleanly on Ctrl+C and on SIGTERM (Unix) and prints the
  final summary (every view but JSON); the classic, JSON and batch output
  handle a closed pipe (`sping … | head`)
- **Debug mode** — `--debug` or `SPING_LOG=debug`

**Distribution**
- Binaries for Linux x86_64 and aarch64 (glibc 2.34+, and static with musl),
  macOS arm64 and Windows x86_64; `.deb` packages with the man page and the
  shell completions; Homebrew, Scoop and crates.io
- On GitHub releases: the macOS binary signed and notarized, and a build
  provenance attestation for every file

## Platforms

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| IPv4 ICMP | DGRAM socket | DGRAM socket | IcmpSendEcho |
| IPv6 | ICMPv6 DGRAM | ICMPv6 DGRAM | Icmp6SendEcho2 |
| TTL / hop limit | recvmsg | IP header (IPv4), recvmsg (IPv6) | API (IPv4 only) |
| Gateway detection | /proc/net/route | `/sbin/route` | `route print` |
| Interface detection | /proc/net/route, if_inet6 | `/sbin/ifconfig` | GetAdaptersAddresses |
| Host addresses (`--ip`) | getifaddrs, if_inet6 | `/sbin/ifconfig` | GetAdaptersAddresses |
| Destination unreachable | ICMP errors (`IP_RECVERR`) | DGRAM socket, IPv4 only | reply status |
| `-I` interface | SO_BINDTODEVICE | accepted, no effect | warning, unbound |
| `-S` source | bind() | bind() | OS routes (TCP: bind()) |
| TCP connect | socket2 | socket2 | socket2 (Winsock) |
| Traceroute (`--diagnose`) | ICMP errors (`IP_RECVERR`) | DGRAM socket, IPv4 only | IcmpSendEcho with TTL |
| Admin required | No, where unprivileged ICMP is allowed ([ICMP permissions](#icmp-permissions)) | No | No |
| All views | full | full | full |

## Architecture

Own ICMP implementation per platform. No third-party ping libraries.

- Linux: `socket2` DGRAM (RAW fallback) + `libc` recvmsg for TTL / hop limit
- macOS: `socket2` DGRAM + IP header parsing for the IPv4 TTL, recvmsg for the
  IPv6 hop limit
- Windows: `IcmpSendEcho` / `Icmp6SendEcho2` FFI from `iphlpapi.dll`
- TCP connect (`--tcp`): `socket2` on every platform, one connection per probe
- Traceroute (`--diagnose`): echoes with a rising TTL on an ICMP socket of
  its own. Linux reads the routers' errors from the socket's error queue
  (`IP_RECVERR`); macOS (IPv4) receives them with every other ICMP message of
  the host and keeps its own; Windows uses `IcmpSendEcho` /
  `Icmp6SendEcho2` with the TTL

Async Tokio runtime, `watch` channels, single-writer renderer at 10 FPS.

### Supported architectures

`x86_64`, `aarch64` and `armv7` (armhf) are compile-checked; aarch64/armv7 cover
Raspberry Pi OS (64- and 32-bit). Release artifacts are produced for Linux
x86_64/aarch64 (glibc, and static with musl), macOS arm64 and Windows x86_64.

## Known limitations

- `-I`/`--interface` binds only on Linux: macOS accepts the flag but it has
  no effect, Windows prints a warning and probes unbound. `-S`/`--source` is
  ignored by ICMP on Windows, where the OS picks the route; `--tcp` binds it.
- Each probe waits for its answer, up to `-W`, before the next one goes out,
  as Windows `ping` does (Linux and macOS `ping` keep sending every `-i`):
  with `-W` longer than `-i`, a target that does not answer is probed every
  `-W` (2 s by default), and `-c N` can take up to N × `-W`.
- The raw-socket fallback and `-I` need `CAP_NET_RAW` (see
  [SECURITY.md](SECURITY.md)); the unprivileged DGRAM path covers the common
  case.
- Names go through the system resolver (5 s timeout) and are resolved again
  every 60 s while monitoring; sping does no reverse DNS and keeps no DNS
  cache of its own.
- The static `-musl` binaries resolve names with musl's own resolver:
  `/etc/hosts` and the servers in `/etc/resolv.conf`, without the system's
  NSS modules (mDNS `.local` names, for example, do not resolve).
- IPv6 replies carry a hop limit (`ttl`) on Linux and macOS; on Windows it
  is not shown (`0` in JSON). The gateway is detected for IPv4 only, and
  `--list-interfaces` lists IPv4 addresses only (`--ip` lists them all).
- With `--tcp`, the gateway and WAN probes stay ICMP: without ICMP permission
  they are disabled with a warning and show `?`.
- An IPv6 link-local target needs its zone: `fe80::1%eth0`, or the interface
  index (`fe80::1%2`), which is the only form Windows takes.
- `--diagnose` is experimental and takes one target; on macOS its
  traceroute is IPv4 only.
- A destination unreachable is told apart from a timeout on Linux, Windows
  and, for IPv4 targets, macOS; on macOS an IPv6 one is still a timeout. One
  the system reports only after `-W` is a timeout as well: on Linux and
  Windows, a LAN address with no host is reported once ARP gives up, about
  3 s after it starts, so with the default `-W 2` some of its probes show as
  timeouts; `-W 4` shows them all as unreachable.

## Roadmap

- **2.0 will change what `sping target` does:** it will find out on its own
  why a target does not answer, as `--diagnose` does today. `--icmp` (from
  1.8) keeps today's probe, for scripts that rely on it; `-4`, `-6` and
  `--tcp` stay as they are.
- Distribution packaging, in progress: the AUR and Fedora/COPR (recipes
  under [`packaging/`](packaging/)), and Debian, through its Rust team.
- WinGet (`LambdaBytes.Sping`) and nixpkgs: the packages are under review.

## Performance

| Metric | Value |
|--------|-------|
| Binary | 1.9 MiB (stripped + LTO) |
| RAM | ~4 MB resident |
| CPU | < 1% at two probes per second |
| Code | ~23,400 lines Rust |
| Tests | 375 (330 unit + 45 E2E) |

## Around the web

Where sping has been reviewed, listed or written about:

- [LinuxLinks — sping: ping utility with advanced network diagnostics](https://www.linuxlinks.com/sping-ping-utility-advanced-network-diagnostics/)
- [Terminal Trove — sping](https://terminaltrove.com/sping/)
- [Awesome Rust — System tools](https://github.com/rust-unofficial/awesome-rust#system-tools)
- [DEV Community — Your ping works. Your connection doesn't. Meet sping.](https://dev.to/antonio_cotos_0e227a64226/sping-advanced-ping-cli-522c) *(by the author)*

## License

MIT
