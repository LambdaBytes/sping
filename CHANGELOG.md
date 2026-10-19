# Changelog

## v1.7.1

The first release of 1.7 on GitHub, crates.io and the package channels.
v1.7.0 was tagged but not published there: three of its integration tests
failed where sping may not open an ICMP socket, as in Nix's Linux build
sandbox and on GitHub's Ubuntu runner. Its binaries had no defect, and the
code of 1.7.1 is the same. What 1.7 brings, in detail under v1.7.0 below:

- `--diagnose` (experimental): when the target stops answering, sping probes
  further on its own (the other address family, TCP 443 and 80, a bounded
  traceroute) and says what still answers.
- The name's lookups as evidence: a lookup that fails while the WAN
  reference answers, or that gives no address of the family probed.
- Context changes while monitoring: `context changed 00:03 ago: interface
  eth0 → wlan0`, for the interface, source, prefix, default gateway and
  target class.
- Fixes on macOS (echo replies matched by identifier for IPv4 too), for a
  target routed through an interface without an address of its family, and
  for the views and options that could leave sping stuck or ignore what it
  was told (`--view table` with one target, several targets piped, a
  misspelt `--view`, `-o` without `--batch`).

### Fixes
- Tests: the two that drive the live views from a pseudo-terminal, and the
  one with several targets piped, needed an ICMP socket and failed without
  one. Where sping may not open one they now say so and skip what needs
  probes, as the other tests that need ICMP already did.

## v1.7.0

### Added
- `--diagnose` (experimental, one target). When the target stops answering
  (three probes lost in a row, or a run that gets no answer at all, even
  with `-c 1`), sping probes further and says what it observed, nothing
  more. It uses sockets of its own, never counted in the target's
  statistics, and checks:
  - the source address the system has for the target;
  - the same name's address in the other family: three echoes, or with
    `--tcp PORT` one connect to that port;
  - TCP 443 and 80 on the target (not with `--tcp`, whose port the probe
    already tries);
  - a bounded traceroute: 30 hops, 3 probes each, 20 s at most, stopping
    after 3 silent hops.

  The views show `diagnosing…` and then the conclusions on the Events line
  (`silent after hop 3 (203.0.113.1)`, `TCP 443 answers`, `IPv6 works`). The
  extended view adds an `Untested` line with what could not be told and why,
  the classic view prints `---` lines, and JSON lines gain
  `active_diagnosis`.
  - Traffic is bounded: at most 100 extra probes in any 60 s, three
    operations at once, the traceroute alone.
  - An address given, `-4`/`-6` or `-S` keep the other family out. `-W`,
    `-s`, `-I` and `-S` apply to the extra probes; `-t` does not.
  - With `-c N` the last line waits for the diagnosis, at most what is left
    of its budget; otherwise it says `incomplete`.
  - The traceroute runs on Linux, unprivileged where unprivileged ICMP is
    allowed and otherwise with `CAP_NET_RAW`; on macOS, unprivileged, for
    IPv4 targets (an IPv6 target gets `trace unavailable on this system`);
    and on Windows.

  Without the flag nothing changes.
- The target's name as evidence, from the lookup sping repeats every 60 s
  while monitoring:
  - `last name lookup failed` (`(timeout)` after 5 s without an answer),
    while the WAN reference answers;
  - `last name lookup gave no IPv6 address` (or IPv4) for the family
    probed.

  sping keeps probing the address it had. JSON codes `name_lookup_failed`
  and `lookup_without_family`. A DNS outage is not claimed: a resolver may
  leave out a family the host cannot reach.
- A change of the network context while monitoring one target, from the
  detection repeated every 15 s:
  `context changed 00:03 ago: interface eth0 → wlan0 · gateway 192.168.1.1 → 10.0.0.1`.
  It covers the interface, source, prefix, IPv4 default gateway and target
  class, and is shown for 30 s. Never with `-I` or `-S`, where the detected
  context is the system's route rather than the probe's. JSON code
  `context_changed`, each change named and valued as in `net_ctx`.

### Fixes
- macOS: an IPv4 probe takes as its reply only an echo reply that carries its
  own identifier, as IPv6 already did. A macOS ICMP socket receives every
  echo reply of the host, and one to another ping of the same target (or to
  the traceroute of `--diagnose`) with the same sequence number could pass as
  the probe's.
- An IPv6 target routed through an interface without an IPv6 address (a
  tunnel with `::/0`, for example) read `Init: if lo · ::1/128`, and JSON
  `net_ctx` `"interface": "lo"`, `"local_ip": "::1"`. It now reads
  `no IPv6 source`, and `net_ctx` says the detection failed (`"unknown"`,
  `"0.0.0.0"`, `0`). The same holds for an IPv4 target routed through an
  interface without an IPv4 address.
- `--view table` with one target: Ctrl+C and `q` did nothing, so sping could
  only be stopped from outside (closing the terminal, `kill`). With one
  target the table is the compact view, as it already looked: Ctrl+C and `q`
  quit, and with stdout not a terminal it falls back to the classic view, as
  compact does.
- Several targets with stdout not a terminal (a file, a pipe, cron): the live
  table went into it as escape sequences, under a note that said
  `falling back to classic view`, and with no terminal to read keys from a
  thread kept a CPU core busy until sping stopped. Now nothing is drawn: each
  target's summary is printed at the end (`-c N`, or Ctrl+C / SIGTERM), with
  the same exit code. A live view that cannot read a terminal no longer
  keeps a core busy either.
- Several targets with `--view extended`, `classic` or `json`: the view was
  ignored and the table drawn. It is now refused (exit 2); `--batch FILE`
  prints each host's summary or JSON.
- `--view` takes only its five names: a misspelt one was taken as the compact
  view. `-o FILE` needs `--batch`: without it the file was never written.
  Both are usage errors now (exit 2).
- macOS: `-I` was accepted and ignored without a word. It now warns, as on
  Windows, that binding to an interface is not supported there (`-S` binds
  the source address).

### Packaging
- nixpkgs package validation builds the recipe on Linux and on macOS, each
  with the build sandbox nixpkgs' builders use, so a test the sandbox breaks
  fails at the release tag.
- Scoop: `scoop bucket add lambdabytes https://github.com/LambdaBytes/scoop-bucket`,
  then `scoop install lambdabytes/sping`, installs the release's Windows
  binary. A published release goes to the bucket on its own.
- WinGet: the manifests of `LambdaBytes.Sping` are made ready from each
  published release; the package is under review at winget-pkgs.
- The Arch recipe (`packaging/arch/PKGBUILD`) is now `lambdabytes-sping`: the
  AUR's `sping` is another program. The command is still `sping`.
- The GitHub workflows run every action at a fixed commit instead of a tag
  that can be moved, and the minimum Rust (1.88) builds and passes the tests
  before each release.

## v1.6.0

### Added
- Static Linux binaries, `sping-vX.Y.Z-linux-x86_64-musl` and
  `sping-vX.Y.Z-linux-aarch64-musl`: built against musl, they need no glibc and
  run on any Linux of their architecture, Alpine and older systems included.
  They resolve names without the system's NSS modules (see the README's known
  limitations).
- TCP connect probe, `--tcp PORT`: times the TCP handshake with the port
  instead of sending ICMP echoes, in every mode and view. It needs no ICMP
  permission and gets through networks that filter ICMP. An open port and a
  refused one both count as answers (`Connected to` / `Refused by`; the
  summary counts the refusals); no answer before `-W` is a loss. On Windows a
  probe is a single SYN, so that a refusal answers at once (Windows otherwise
  retries for about 2 s); there the wait is about 3 s at most. `-t`, `-S`
  (bound on Windows too) and `-I` (as with ICMP) apply; `-s` is rejected. A
  source address that cannot be used exits with code 2. JSON lines gain
  `probe`, `port`, `refused` and `tcp_state`, in TCP mode only.
- The diagnosis in JSON: lines gain `diagnosis`, the findings shown on the
  Events line as stable codes with their evidence (`intermittent_loss` with
  `recent_loss_pct`, `upstream_outage`, `tcp_refused` with `port`…), and in
  single-target mode `gateway` and `wan`, the auxiliary probes' state
  (`online`, `offline`, `unknown`) it is drawn from. Each is absent when it
  has nothing to say; batch lines carry the target's diagnosis. See
  JSON_CONTRACT.md.

### Changed
- Quality grades have names that do not clash with the trend: `A (95) ·
  excellent`, then `good`, `fair` and `poor` (the trend keeps `stable`,
  `improving`, `degrading`). JSON keeps `"A"`…`"D"`.
- The OS hint after the TTL appears only while the TTL is still an initial
  value: `ttl 64 (Unix-like)`, `ttl 128 (Windows)`, `ttl 255 (network)`.
  Past a router the TTL no longer says what answered (8.8.8.8 was shown as
  Windows), and 64 is macOS and the BSDs as much as Linux.
- A loopback target (`127.0.0.0/8`, `::1`) is `loopback`, not `routed
  internal`. JSON keeps `"RoutedInternal"` for it.
- With no source address for the target's family (an IPv6 target on a host
  without IPv6) the `Init:` and `Context` lines say `no IPv6 source` instead
  of `0.0.0.0/0` on the default route's interface.
- A WAN outage while nothing is known about the gateway reads `WAN
  unreachable · gateway state unknown` instead of `upstream outage likely`.
- TCP: the compact and extended views say how the last connect ended at the
  head of Events: `TCP 443 connected · 21 ms`, `TCP 443 refused · host or
  firewall answered`, `TCP 443 timeout · no answer`. The Status line no
  longer repeats it.
- Batch and table: an address given with its zone (`fe80::1%eth0`) is shown
  once, not followed by the same address in parentheses.
- Scoring: the `high jitter with no loss` warning reads the same 20 probes
  and the same jitter measure as the quality grade (it read the whole
  session's jitter), and appears exactly when the grade takes its largest
  jitter penalty.
- Scoring: changes and deviations under 0.1 ms are noise. Loopback and fast
  LAN targets no longer turn `degrading`/`improving` or lose 10-20 quality
  points over tens of microseconds; a LAN going from 0.3 to 0.9 ms is still
  `degrading`.
- The trend counts losses: two or more lost probes more in the recent half
  of the window than in the older one is `degrading` (an outage was
  `unknown`), as many fewer `improving`. When loss and latency disagree,
  `degrading` wins. JSON `quality_score` and `trend` change accordingly;
  their types and values are the same.
- README: one recording of 1.6.0 replaces the three earlier ones (the
  compact view, the tour and the 1.5.5 comparison); the install methods
  and the features of every version are listed.

### Packaging
- `build.rs` writes the man page and the shell completions to Cargo's
  `OUT_DIR` (`assets/man`, `assets/completions`), no longer into the source
  tree: `cargo install` from a read-only source works. A packager that wants
  them at a fixed path sets `SPING_ASSETS_DIR` to an absolute directory (the
  release builds and the Arch recipes use `$PWD/target/assets`).
- The macOS release binary is always signed and notarized: a release build
  without the signing setup fails instead of shipping it unsigned.
- nixpkgs package validation: a workflow builds the nixpkgs recipe from each
  release tag. sping is not in nixpkgs until that recipe is merged there.
- Homebrew: `brew install LambdaBytes/tap/sping` builds the release from
  source and installs the man page and the shell completions too. A
  published release goes to the tap and to crates.io on its own.

### Fixes
- The interface of a loopback target: `if lo · 127.0.0.1/8` (`lo0` on macOS,
  the loopback adapter on Windows) instead of the default route's interface
  with `/0` — on Windows its address (`if 192.0.2.10 · 127.0.0.1/0`).
  JSON `net_ctx` gets the same `interface` and `prefix_len`.
- Without a source address no interface is looked up: JSON `net_ctx` has
  `"interface": "unknown"` and `"prefix_len": 0`, as documented, instead of
  the interface of whatever route covered `0.0.0.0` — with a VPN's
  `0.0.0.0/1` that also put the target in its subnet (`"SameLan"`). For the
  same reason a VPN's `0.0.0.0/1` no longer puts `127.0.0.1` in `"SameLan"`.
- macOS: the gateway and the interfaces were missing when sping ran with a
  `PATH` without `/sbin` (cron runs its jobs with `/usr/bin:/bin`): `route`
  and `ifconfig` now run from `/sbin`.

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
