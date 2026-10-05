# Changelog

## v1.5.5

### Fixes
- IPv6 link-local targets with a zone work: `sping fe80::1%eth0` (interface
  name, or its index: `fe80::1%2`; Windows takes the index). The zone given
  on the command line was dropped after resolution, so the probe failed with
  `send failed: Invalid argument` and the `Init:` line showed `0.0.0.0/0`.
  The same address in two zones counts as two targets, and a link-local
  `-S` source is bound in the target's zone. Without a zone a link-local
  target still cannot be reached on Linux; an unknown zone is reported as
  such.
- Windows: interface names, addresses and prefix lengths come from the
  system's adapter list instead of the text `ipconfig` prints. On a
  non-English Windows the `Init:` and `Context` lines showed the whole
  localized header (`if Adaptador de Ethernet Ethernet 3`) as the interface
  name; they now show the adapter's name (`if Ethernet 3`). IPv6 addresses get
  their real prefix length, so an IPv6 target in the local prefix is `same
  LAN`. `ipconfig` is still read if the system call fails.
- macOS: ICMPv6 replies carry their hop limit in the `ttl` column, as on
  Linux since 1.5.4.
- macOS: with several IPv6 targets a reply could be counted for the wrong
  one, since there every ICMPv6 socket receives every echo reply. Each probe
  socket now has its own echo identifier and accepts only the replies that
  carry it.
- Multi-target and batch modes: each target gets its own network context.
  Every target carried the context of the first one, so `net_ctx` in the JSON
  output (interface, source address, class) was wrong for the others.
- Single target: after a DNS failover to another address, the context is
  detected again for the new address instead of staying on the old one.

### Release
- Every file of a GitHub release has a build provenance attestation:
  `gh attestation verify <file> --repo <owner>/<repo>` tells which commit and
  workflow run produced it.
- The macOS binary is signed with a Developer ID and notarized by Apple: it
  runs without removing the quarantine attribute first.
- sping is on crates.io: `cargo install sping` builds and installs the binary.
- The Linux binaries and .deb packages of a GitHub release are built on
  Debian 12: they need glibc 2.34 instead of 2.39, so they run on Debian 12
  and Ubuntu 22.04. The release stops if a Linux binary would need a newer
  glibc.
- The arm64 .deb asks for libc6 2.34, what its binary needs, instead of 2.36,
  so it installs on Ubuntu 22.04 too.

## v1.5.4

### Fixes
- Windows: ASCII output is selected automatically on the legacy console host
  (cmd.exe / PowerShell outside Windows Terminal, VS Code, ConEmu), whose
  fonts draw the pulse blocks and the spinner as boxes. `SPING_ASCII=0` forces
  the Unicode charset on any terminal.
- The ASCII pulse uses four marks of increasing height (`_` `-` `=` `"`)
  instead of eight unrelated ones.
- IPv6 targets: the `Init:` and `Context` lines show the real source address,
  interface and prefix (`if lo · ::1/128`) instead of `0.0.0.0/0`, and the
  target is classified like IPv4 (`::1` and unique-local `fc00::/7` are
  `routed internal`, an address inside the local prefix is `same LAN`); `::1`
  was reported as `public`. Linux: ICMPv6 replies now carry their hop limit
  in the `ttl` column; it was `0`.

### Docs
- README: project logo. The logo and the recordings carry no provenance
  manifest or tool metadata, only what the image format needs.

## v1.5.3

### Fixes
- `--ascii` (and non-UTF-8 locales): the gateway/WAN indicators on the
  `Context` line (`o` up, `x` down, `?` unknown) and the `x` in the batch
  banner follow the charset; the output is now pure ASCII in that mode.

### Docs
- README: a demo recording at the top and an 80-second tour of every view and
  mode at the end; the examples are real output of this version.

## v1.5.2

### Fixes
- TUI views (compact, extended, table): a line wider than the terminal no
  longer breaks the in-place redraw. In an 80-column terminal the `Latency`
  line is 81 columns wide with typical RTT values; it wrapped, and every
  frame left the previous header line behind. Lines are now cut short of the
  terminal width and end in an ellipsis.
- A probe that fails with an error (for example when the OS refuses to send)
  is no longer shown as a timeout: the classic view prints
  `Probe error for seq=N: <reason>`, and the compact and extended views put
  the reason first on the `Events` line. JSON output is unchanged.
- Windows: the console is switched to escape-sequence processing before the
  first line is printed; the `Init:` line showed its bold sequences as text.

## v1.5.1

### Fixes
- ICMPv6 on RAW sockets (the Linux fallback when `ping_group_range` denies
  DGRAM): replies are now matched against the probed address. With two or more
  IPv6 targets, a reply from one target was counted for the others — every
  probe shares the identifier and the sequence numbers advance together — so
  an unreachable target was reported as up.
- Large payloads on RAW sockets: the receive buffer now grows with `-s`.
  Above ~1980 bytes the reply was truncated, failed the checksum check and
  every probe timed out.
- Soundness (Linux): the `recvmsg` control buffer is aligned for `cmsghdr`.
- Soundness (Windows): echo replies are read with unaligned loads, and the
  request options no longer carry implicit padding — the bytes 64-bit Windows
  reads as the options pointer are an explicit, zeroed field.
- Windows IPv6: the reply buffer reserves room for the `IO_STATUS_BLOCK` that
  `Icmp6SendEcho2` requires.
- CI: a failed release creation now fails the publish job instead of being
  ignored.

### Packaging
- Arch `PKGBUILD`/`PKGBUILD-git` and a Fedora spec under `packaging/`; a
  dh-cargo Debian packaging draft.
- `.deb` dependencies are computed automatically (`$auto`).
- MSRV is Rust 1.88 (let-chains).
- `anyhow` 1.0.104 (RUSTSEC-2026-0190).

### Internal
- Rustdoc and `SAFETY:` comments across `src/`; clippy clean on Linux, macOS
  and Windows targets.
- E2E tests use a built-in watchdog instead of `timeout(1)`, which macOS does
  not ship and Windows resolves to an unrelated tool.
- `SECURITY.md` and GitHub CI/release workflows.

## v1.5.0

### Features
- **Kernel receive timestamps (Linux)**: probes enable `SO_TIMESTAMPNS` and
  compute RTT as kernel-rx-stamp minus send wall time, removing userspace
  scheduling noise from measurements. Falls back to the monotonic userspace
  measurement when stamps are missing or a wall-clock step is detected.
- **IPv6 on Windows**: `Icmp6CreateFile` + `Icmp6SendEcho2` FFI; `sping ::1`
  and `-6` now work on Windows (no hop-limit info — the API doesn't expose it).
- **Periodic DNS re-resolution**: hostname targets are re-resolved every 60s;
  a DNS failover (same address family) redirects probes without restarting.
- **Hot network-context re-detection** (single-target mode): every 15s the
  interface/gateway context is re-detected off the async runtime. Context
  shown in views follows WiFi → Ethernet or VPN changes, and the GW auxiliary
  probe retargets to the new gateway (hysteresis resets on retarget).

### Internal
- `auxiliary::run` takes its target via `watch::Receiver<IpAddr>` (retargetable).
- `NetworkContext` derives `PartialEq` for change detection.
- Windows backend split into `ping_v4`/`ping_v6` with shared options/payload
  helpers; struct layouts verified against `windows-sys` (`IPV6_ADDRESS_EX`
  is `packed(1)`).
- Windows build now cross-checked in dev via `cargo check --target
  x86_64-pc-windows-gnu`.

## v1.4.0

### Fixes
- Terminal: a panic hook now restores the terminal (disables raw mode), so a
  crash inside a TUI view no longer leaves the shell corrupted.
- Multi-target table: hostnames are truncated by characters, not bytes —
  multibyte names (e.g. `münchen…`) no longer panic at the column boundary.
- ICMP parsing (Linux/macOS): the IPv4 IHL field is validated (20..=len),
  so a malformed packet can no longer panic the probe task; the ICMP Code
  field is checked (must be 0) and RAW-socket replies are checksum-verified.
- ICMPv6: replies are filtered by identifier on RAW sockets (no more
  cross-talk between targets in multi-target mode) and the Code is checked.
- Probe timeout: the socket read timeout shrinks to the remaining budget
  after each non-matching packet — a probe can no longer take ~2× the
  configured timeout under foreign ICMP traffic. `EINTR` is retried.
- Correlator: WAN offline with an unknown gateway state now diagnoses
  "upstream outage likely" instead of falling through to "target unreachable".
- Probe cadence: the scheduler ticks at a fixed interval (start-to-start)
  instead of sleeping after each probe, so RTT/timeouts no longer stretch
  the probing period.
- Linux gateway detection picks the default route with the lowest metric
  (WiFi + Ethernet / VPN setups chose an arbitrary one before).
- Windows `ipconfig` parsing no longer assumes an English locale.
- `snapshot.seq` is now the cumulative probe counter (previously wrapped at
  65535, freezing classic/JSON output after ~18h at 1s interval).
- EPIPE: classic/JSON/batch output handles a closed pipe (`sping … | head`)
  gracefully instead of failing mid-write.
- Auxiliary GW/WAN probes print a warning when their socket cannot be
  created instead of disappearing silently.

### Features
- Ping-parity flags: `-c/--count` works in every view (not just batch),
  `-W/--timeout <secs>`, `-s/--size <bytes>`, `-t/--ttl`, `-q/--quiet`,
  `-4` / `-6` to force the address family.
- Exit codes are ping-compatible: 0 = replies received, 1 = no replies,
  2 = error (previously always 1 on any failure).
- Final summary and classic view print `mdev` (RTT standard deviation);
  classic replies include `ttl=`. JSON gains an additive `mdev` field.
- `--wan-probe <IP>` makes the WAN reference target configurable
  (default 1.1.1.1) for networks that filter ICMP to Cloudflare.
- Consistent cross-platform appearance: `--ascii` (or `SPING_ASCII=1`, or
  a non-UTF-8 locale) switches every glyph — spinner, pulse blocks, loss
  marks, separators, table rules — to an ASCII set with identical layout;
  `NO_COLOR` is honored.
- SIGTERM triggers a clean shutdown with final summary (systemd/containers).
- Windows: TTL errors (unreachable, TTL expired) are reported as errors
  instead of being conflated with timeouts; `-t` is honored via
  `IP_OPTION_INFORMATION`; `-S` prints a warning (unsupported) instead of
  being silently ignored.

### Internal
- `tokio` features trimmed from `full` to the six actually used; release
  profile builds with `codegen-units = 1`.
- `ProbeOptions` now carries payload size, timeout and TTL end-to-end;
  scheduler/batch share `create_backend`.
- New unit tests: synthetic ICMP packet parsing (IHL/code/checksum/id),
  UTF-8-safe truncation, `mdev`, correlator WAN/gateway matrix.

## v1.3.2

### Fixes
- Diagnostics: the correlator was fed lifetime-cumulative stats, so the
  network-context interpretation (`gateway unreachable`, `upstream outage
  likely`, `target unreachable · internet still OK`) went dead after the
  first successful reply and never fired for mid-session outages. The
  primary target now tracks reachability with a `HealthTracker` (3-fail /
  2-ok hysteresis, same policy as the GW/WAN probes), and the correlator's
  loss input comes from the rolling window instead of the lifetime counter.
  `intermittent loss` no longer sticks forever after a single drop.
- `ProbeStats::record_error` now clears `rtt_last`, matching `record_timeout`
  (no stale "last" RTT shown after an errored probe).

### Internal
- `QualityScorer::grade()` and `score()` now share a single `raw_score()`
  source of truth (≈50 lines of duplicated scoring logic removed); `grade()`
  evaluates the unrounded value to preserve boundary behaviour.
- New internal `ProbeSnapshot` fields `reachability` and `recent_loss_pct`
  are `#[serde(skip)]` — the frozen JSON contract is unchanged.

## v1.3.0

### Fixes
- Linux: `EACCES` from `socket(SOCK_DGRAM, IPPROTO_ICMP)` no longer aborts.
  The backend now falls back to `SOCK_RAW` automatically when DGRAM is
  denied (typical on kernels with `ping_group_range` locked even for root).
  Fixes "permission denied" reports when the user already invoked `sudo`.
- RAW path verifies the ICMP identifier on echo replies — replies from
  unrelated `ping` sessions sharing the host no longer count as ours.
- `parse_echo_reply_v4` gained an optional `expected_id` parameter; DGRAM
  callers pass `None` (kernel rewrites id), RAW callers pass `Some(id)`.

### UX
- New `eprint_icmp_hint()` helper unifies the post-failure hint across
  `app.rs` and `probe::scheduler`. Three options instead of one:
  - `sudo sysctl net.ipv4.ping_group_range='0 2147483647'` (DGRAM)
  - `sudo setcap cap_net_raw+ep <bin>` (cap-based, no sudo at runtime)
  - `sudo sping ...` (now works thanks to the RAW fallback)

### CI / packaging
- New `build-linux-aarch64` job: cross-compiles `aarch64-unknown-linux-gnu`
  with `gcc-aarch64-linux-gnu` and produces both the raw binary and an
  arm64 `.deb`. Both are uploaded to the package registry and linked on
  the release.
- New `build-macos-arm64` job: runs on a dedicated macOS runner and
  produces a native arm64 macOS binary.
  macOS releases are now fully automated like Linux/Windows.
- `publish-release`: SHA256SUMS now merges all four platform variants
  (linux x86_64, linux aarch64, macos arm64, windows x86_64); release
  JSON exposes 6 binary asset links + SHA256SUMS.
- `scripts/release-macos.sh`: kept as a fallback for manual or
  out-of-band macOS builds (e.g. universal lipo binary). The standard
  release flow no longer needs it.

### Docs
- README install section: arm64 Linux binary + arm64 `.deb` listed,
  macOS Gatekeeper note (`xattr -d com.apple.quarantine`), explicit
  `dpkg -i` example.

## v1.2.0

### Packaging
- `LICENSE` file (MIT) added at repo root
- Cargo.toml: `authors`, `repository`, `homepage`, `readme`, `keywords`, `categories`, `rust-version` (1.87)
- `build.rs` generates man page (`sping.1`) and shell completions (bash, zsh, fish) into `target/assets/`
- `[package.metadata.deb]` section: `cargo deb` produces `sping_X.Y.Z-1_amd64.deb` with binary, man, completions and docs

### CI
- `audit` job (RustSec advisory-db scan) and `deny` job (license + wildcards + duplicate ban) added to lint stage
- `build-linux-x86_64`: produces `.deb` alongside the raw binary, both checksummed
- `publish-release`: uploads the `.deb` to the package registry and adds a 4th asset link on the release

## v1.1.0

### New: Batch mode
- `--batch <FILE>`: read targets from file (one per line, # comments)
- `-c <COUNT>`: number of probes per target (default 10)
- `-o <FILE>`: write results to file (default: stdout)
- All targets probed in parallel with full diagnostics
- Summary format: one line per host with RTT/loss/quality/TTL
- JSON format: full ProbeSnapshot per host (NDJSON)
- Example: `sping --batch hosts.txt -c 20 -o results.json --view json`

### Fixes since v1.0.0
- macOS: DGRAM sockets work without sudo (no more RAW sockets)
- macOS: interface/gateway detection via ifconfig/route commands
- macOS: IP header parsing for TTL extraction
- macOS: source IP filtering for multi-target mode
- Windows: interface detection via ipconfig, gateway via route print
- Windows: TTL column shortened (Win/Lin/Net) in multi-target table
- Windows: iphlpapi.dll linking for IcmpSendEcho
- CI: release creation with asset links in single POST
- ICMP permission error prints before raw mode (clean formatting)

## v1.0.0

First stable release.

### Features
- Real ICMP probing with own backend (no third-party ping libraries)
- 5 view modes: compact, extended, classic, JSON (NDJSON), multi-target table
- Multi-target dashboard: parallel probing with live table
- Quality scoring A–D with numeric score (0–100)
- Connection trend detection (stable/improving/degrading)
- Spike detection with cooldown and adaptive threshold
- Outage timer with recovery events
- Diagnostic correlator: "target unreachable · internet still OK", etc.
- Network context: interface, gateway, IP/prefix, target classification
- Auxiliary GW/WAN probes with hysteresis
- TTL extraction with OS fingerprint hint (Linux/Windows/network)
- Hop count estimation from TTL
- Adaptive pulse visualization (▁▂▃▄▅▆▇█)
- RTT distribution: p50, p95, p99, range, spikes
- Echo path animation in extended view
- DNS resolution with timing and 5s timeout
- IPv4 and IPv6 support
- Interface binding (-I) and source IP (-S)
- TTY auto-detection: piped output falls back to classic view
- Debug mode (--debug / SPING_LOG=debug)

### Cross-platform
- Linux: full feature set (DGRAM ICMP + recvmsg TTL + SO_BINDTODEVICE)
- macOS: full minus TTL/hops (DGRAM ICMP, TTL=unknown)
- Windows: IPv4 with TTL via IcmpSendEcho API (no admin required)

### Quality
- 61 tests (48 unit + 13 E2E)
- 0 compiler warnings
- ~4,000 lines of Rust
- 1.3 MB binary (release, stripped + LTO)
- 2 MB RAM, 0% CPU at runtime

## v0.8.0
- Windows IcmpSendEcho backend
- Cross-platform backend abstraction (IcmpBackend)
- Platform capability matrix

## v0.7.0
- 61 tests, debug mode, performance verified
- JSON snapshot tests, quality/trend/TTL heuristic tests
- Diagnostic correlation tests

## v0.6.0
- DNS hardening (5s timeout, "Resolving..." feedback, IPv4 preference)
- TTY auto-detection (piped → classic fallback)
- Input validation (-I/-S with clear errors)
- Multi-target dedup

## v0.5.x
- Multi-target dashboard mode
- Layout reorder, trend merged into quality
- Raw mode for TUI, buffered atomic writes
- Pulse as 8-level blocks, RTT distribution percentiles

## v0.4.0
- Hop distance, connection trend, simplified context
- JSON "unknown" instead of null
- OS detection from TTL

## v0.3.x
- Subpixel pulse, echo path animation
- Unified display width, horizontal histogram

## v0.2.x
- Interface binding, source IP, real TTL
- IPv6, recovery events, E2E tests

## v0.1.0
- First minor release: all 5 development phases complete
