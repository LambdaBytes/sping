//! Validated runtime config from parsed CLI args. Compact/extended views
//! fall back to classic when stdout is not a TTY.

use std::io::IsTerminal;
use std::net::IpAddr;
use std::time::Duration;

use crate::cli::Args;
use crate::context::dns::Family;

/// Validated runtime configuration shared by all execution modes.
pub struct Config {
    /// Target hosts, deduplicated case-insensitively in CLI mode; verbatim
    /// from the batch file in batch mode.
    pub targets: Vec<String>,
    pub interface: Option<String>,
    pub source: Option<IpAddr>,
    pub interval: Duration,
    pub timeout: Duration,
    pub payload_size: usize,
    /// `Some(port)` probes with a TCP connect to that port instead of ICMP.
    pub tcp_port: Option<u16>,
    /// `None` uses the OS default TTL / hop limit.
    pub ttl: Option<u8>,
    /// `None` runs until interrupted; defaults to 10 in batch mode.
    pub count: Option<u64>,
    pub quiet: bool,
    /// Forced address family; `None` lets DNS resolution decide.
    pub family: Option<Family>,
    /// `--diagnose` (single target only).
    pub diagnose: bool,
    /// Effective view after TTY auto-detection.
    pub view: ViewMode,
    /// `Some` enables batch mode.
    pub batch_file: Option<String>,
    /// `None` writes to stdout.
    pub output_file: Option<String>,
    /// WAN reference address probed for diagnostics correlation.
    pub wan_probe: IpAddr,
}

/// Output rendering mode selected with `--view`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    /// Single-line live TUI view (default; requires a TTY).
    Compact,
    /// Multi-line live TUI view (requires a TTY).
    Extended,
    /// Traditional `ping`-style line-per-probe output (several targets with
    /// stdout not a terminal: only each target's summary).
    Classic,
    /// NDJSON, one snapshot per line (contract frozen, see `JSON_CONTRACT.md`).
    Json,
    /// Multi-target dashboard table (with one target, `Compact`; with stdout
    /// not a terminal, `Classic`).
    Table,
}

/// ICMP payload size when `-s` is not given (as `ping`).
const DEFAULT_PAYLOAD: usize = 56;
/// Max ICMP payload that fits in an unfragmented-by-spec IPv4 packet.
const MAX_PAYLOAD: usize = 65_507 - 8;
/// Minimum probe interval (flood protection).
const MIN_INTERVAL_MS: u64 = 50;

impl Config {
    /// Builds a validated `Config` from parsed CLI arguments.
    ///
    /// # Errors
    ///
    /// Returns a descriptive message on invalid IPs, out-of-bounds values,
    /// or an unreadable/empty batch file.
    pub fn from_args(args: &Args) -> Result<Self, String> {
        let mut view = match args.view.as_str() {
            "extended" => ViewMode::Extended,
            "classic" => ViewMode::Classic,
            "json" => ViewMode::Json,
            "table" => ViewMode::Table,
            _ => ViewMode::Compact,
        };

        let is_batch = args.batch.is_some();

        // Batch takes its targets from the file: one on the command line is
        // refused rather than ignored. Not as a conflict in clap, which
        // would then let `-o` pass without the `--batch` it requires.
        if let (true, Some(target)) = (is_batch, args.targets.first()) {
            return Err(format!(
                "--batch takes its targets from the file: '{target}' does not go with it"
            ));
        }

        // Batch prints each target's summary, or JSON: a view it is not is
        // refused rather than ignored. Compact is the default, which cannot
        // be told from no `--view` at all.
        if is_batch
            && matches!(
                view,
                ViewMode::Extended | ViewMode::Classic | ViewMode::Table
            )
        {
            return Err(format!(
                "--view {} does not go with --batch, which prints a summary, \
                 or JSON with --view json",
                args.view
            ));
        }

        let source = match &args.source {
            Some(s) => {
                let ip: IpAddr = s
                    .parse()
                    .map_err(|_| format!("invalid source IP address: '{s}'"))?;
                // An IPv4-mapped address is the IPv4 address it stands
                // for, as a target written that way is (`ResolvedAddr`):
                // the socket the two meet at is of one family.
                Some(ip.to_canonical())
            }
            None => None,
        };

        if args.interval_ms < MIN_INTERVAL_MS {
            return Err(format!(
                "interval must be at least {MIN_INTERVAL_MS} ms (got {})",
                args.interval_ms
            ));
        }

        // A millisecond is the unit of the coarsest timeout a probe hands
        // the system (Windows' `IcmpSendEcho`); below a microsecond a
        // socket's receive timeout is zero, which is none at all.
        if !(0.001..=3600.0).contains(&args.timeout) {
            return Err(format!(
                "timeout must be in [0.001, 3600] seconds (got {})",
                args.timeout
            ));
        }

        let payload_size = args.payload_size.unwrap_or(DEFAULT_PAYLOAD);
        if payload_size > MAX_PAYLOAD {
            return Err(format!(
                "payload size must be at most {MAX_PAYLOAD} bytes (got {payload_size})"
            ));
        }

        if args.ttl == Some(0) {
            return Err("ttl must be between 1 and 255".into());
        }

        if args.count == Some(0) {
            return Err("count must be at least 1".into());
        }

        let wan_probe: IpAddr = args
            .wan_probe
            .parse()
            .map_err(|_| format!("invalid --wan-probe address: '{}'", args.wan_probe))?;
        // An IPv4-mapped address is the IPv4 address it stands for, as a
        // target or a source written that way is: left as IPv6 it was not
        // probed as that address, and the WAN was reported offline while
        // it answered.
        let wan_probe = wan_probe.to_canonical();

        let family = match (args.ipv4, args.ipv6) {
            (true, _) => Some(Family::V4),
            (_, true) => Some(Family::V6),
            _ => None,
        };

        let mut targets = Vec::new();
        if let Some(ref batch_path) = args.batch {
            let content = std::fs::read_to_string(batch_path)
                .map_err(|e| format!("cannot read batch file '{batch_path}': {e}"))?;
            // A UTF-8 byte order mark at the start of the file is not part
            // of its first line: `trim` leaves it (it is not white space),
            // and the line, a comment or a host, was taken for a target.
            let content = content.strip_prefix('\u{feff}').unwrap_or(&content);
            for (index, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                // A target is written to stderr as it is ("Resolving …"):
                // one with a control character, an escape sequence among
                // them, is refused by its line, without writing it.
                if trimmed.contains(char::is_control) {
                    return Err(format!(
                        "batch file '{batch_path}', line {}: a target with control characters",
                        index + 1
                    ));
                }
                targets.push(trimmed.to_string());
            }
            if targets.is_empty() {
                return Err(format!("batch file '{batch_path}' contains no targets"));
            }
        } else {
            let mut seen = std::collections::HashSet::new();
            targets = args
                .targets
                .iter()
                .filter(|t| seen.insert(t.to_lowercase()))
                .cloned()
                .collect();
        }

        if args.diagnose && (is_batch || targets.len() > 1) {
            return Err(
                "--diagnose works with one target (not with several or with --batch)".into(),
            );
        }

        // One target has no table: the single-target renderer draws `table`
        // as the compact view, so it is that view everywhere, with its key
        // listener (Ctrl+C, `q`) and TTY fallback. Without this it was drawn
        // in raw mode with no key listener, and Ctrl+C did nothing.
        if !is_batch && targets.len() == 1 && view == ViewMode::Table {
            view = ViewMode::Compact;
        }

        // Several targets are the live table (`app::run_multi`), a frame
        // redrawn in place in raw mode: a view it is not is refused rather
        // than ignored. With stdout not a terminal there is no table (its
        // escape sequences went into the file), only each target's summary
        // at the end: `Classic`, with no raw mode and no key listener.
        if !is_batch && targets.len() > 1 {
            if matches!(
                view,
                ViewMode::Extended | ViewMode::Classic | ViewMode::Json
            ) {
                return Err(format!(
                    "--view {} works with one target: several are shown as a table \
                     (--batch FILE prints a summary or JSON)",
                    args.view
                ));
            }
            view = if std::io::stdout().is_terminal() {
                ViewMode::Table
            } else {
                eprintln!(
                    "note: stdout is not a TTY: no live table, each target's summary at the end"
                );
                ViewMode::Classic
            };
        }

        // Piped compact/extended fall back to classic (no TTY for raw mode).
        if !is_batch
            && !std::io::stdout().is_terminal()
            && matches!(view, ViewMode::Compact | ViewMode::Extended)
        {
            eprintln!("note: stdout is not a TTY, falling back to classic view");
            view = ViewMode::Classic;
        }

        // Batch mode keeps its historical default of 10 probes per target.
        let count = args.count.or(if is_batch { Some(10) } else { None });

        Ok(Self {
            targets,
            interface: args.interface.clone(),
            source,
            interval: Duration::from_millis(args.interval_ms),
            timeout: Duration::from_secs_f64(args.timeout),
            payload_size,
            // `--icmp` is the ICMP probe; clap refuses it with `--tcp`.
            tcp_port: if args.icmp { None } else { args.tcp },
            ttl: args.ttl,
            count,
            quiet: args.quiet,
            family,
            diagnose: args.diagnose,
            view,
            batch_file: args.batch.clone(),
            output_file: args.output.clone(),
            wan_probe,
        })
    }

    /// Whether batch mode is active.
    pub fn is_batch(&self) -> bool {
        self.batch_file.is_some()
    }

    /// Probe options shared by every targeted probe loop.
    pub fn probe_options(
        &self,
        target: crate::context::dns::ResolvedAddr,
    ) -> crate::probe::types::ProbeOptions {
        crate::probe::types::ProbeOptions {
            target: target.ip,
            scope_id: target.scope_id,
            timeout: self.timeout,
            payload_size: self.payload_size,
            ttl: self.ttl,
            interface: self.interface.clone(),
            source: self.source,
            tcp_port: self.tcp_port,
        }
    }

    /// Validates settings against the live system state.
    ///
    /// # Errors
    ///
    /// Fails when `-I` names an interface not present on the system.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref iface) = self.interface {
            let ifaces = crate::context::iface::list_interfaces();
            let names: Vec<&str> = ifaces.iter().map(|i| i.name.as_str()).collect();
            // Linux and macOS ask the kernel for the name, Windows its
            // adapters that have an address: that list comes from the IPv4
            // routes (Linux) or keeps IPv4 and no loopback (macOS, Windows),
            // which leaves out the loopback interface and one with only a /32
            // or only IPv6 addresses.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let found = crate::context::iface::interface_index(iface) != 0;
            #[cfg(target_os = "windows")]
            let found = crate::context::iface::has_adapter(iface);
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            let found = names.contains(&iface.as_str());
            if !found {
                return Err(format!(
                    "interface '{}' not found. Available: {}",
                    iface,
                    if names.is_empty() {
                        "none detected".into()
                    } else {
                        names.join(", ")
                    }
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn config(args: &[&str]) -> Result<Config, String> {
        let args = Args::parse_from(std::iter::once("sping").chain(args.iter().copied()));
        Config::from_args(&args)
    }

    fn view_of(args: &[&str]) -> ViewMode {
        config(args).expect("valid arguments").view
    }

    /// `--view table` with one target is the compact view, the one its
    /// renderer draws, so it gets that view's key listener (Ctrl+C, `q`)
    /// and TTY fallback; whatever stdout is here, both end the same. Two
    /// spellings of one host are one target.
    #[test]
    fn one_target_table_is_the_compact_view() {
        let compact = view_of(&["192.0.2.1", "--view", "compact"]);
        assert_eq!(view_of(&["192.0.2.1", "--view", "table"]), compact);
        assert_eq!(
            view_of(&["Host.example", "host.example", "--view", "table"]),
            compact
        );
    }

    /// `-I` takes any interface the system has. The loopback one is in no
    /// IPv4 route of `/proc/net/route`, where the list of interfaces comes
    /// from, and every network namespace has it. A name the system does not
    /// have is refused, as is the label of an address (`lo:0`), which the
    /// kernel would take for its interface and no socket binds to.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_interface_is_one_the_system_has() {
        let lo = config(&["127.0.0.1", "-I", "lo"]).expect("valid arguments");
        assert_eq!(lo.validate(), Ok(()));
        let none = config(&["127.0.0.1", "-I", "nonexistent99"]).expect("valid arguments");
        let refused = none.validate().expect_err("no such interface");
        assert!(
            refused.starts_with("interface 'nonexistent99' not found. Available: "),
            "{refused}"
        );
        let label = config(&["127.0.0.1", "-I", "lo:0"]).expect("valid arguments");
        let refused = label.validate().expect_err("a label, not an interface");
        assert!(
            refused.starts_with("interface 'lo:0' not found. Available: "),
            "{refused}"
        );
    }

    /// macOS, as Linux: `-I` takes the loopback interface, which the list of
    /// interfaces (IPv4, no loopback) leaves out; v1.9.0-rc1 said
    /// `interface 'lo0' not found. Available: en0, en1`.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_interface_is_one_the_system_has() {
        let lo = config(&["127.0.0.1", "-I", "lo0"]).expect("valid arguments");
        assert_eq!(lo.validate(), Ok(()));
        let none = config(&["127.0.0.1", "-I", "nonexistent99"]).expect("valid arguments");
        let refused = none.validate().expect_err("no such interface");
        assert!(
            refused.starts_with("interface 'nonexistent99' not found. Available: "),
            "{refused}"
        );
        let label = config(&["127.0.0.1", "-I", "lo0:0"]).expect("valid arguments");
        let refused = label.validate().expect_err("a label, not an interface");
        assert!(
            refused.starts_with("interface 'lo0:0' not found. Available: "),
            "{refused}"
        );
    }

    /// Windows: `-I` takes any adapter that has an address, the loopback one
    /// included (the one `Init:` names for 127.0.0.1); v1.9.0-rc1 said
    /// `interface 'Loopback Pseudo-Interface 1' not found. Available:
    /// Ethernet`. Its name comes from the system: it may be translated.
    #[cfg(target_os = "windows")]
    #[test]
    fn an_interface_is_one_the_system_has() {
        let loopback =
            crate::context::iface::interface_for_ip(std::net::IpAddr::from([127, 0, 0, 1]), 0)
                .expect("an adapter holds 127.0.0.1")
                .name;
        let lo = config(&["127.0.0.1", "-I", &loopback]).expect("valid arguments");
        assert_eq!(lo.validate(), Ok(()), "{loopback}");
        let none = config(&["127.0.0.1", "-I", "nonexistent99"]).expect("valid arguments");
        let refused = none.validate().expect_err("no such interface");
        assert!(
            refused.starts_with("interface 'nonexistent99' not found. Available: "),
            "{refused}"
        );
    }

    /// `--icmp` is the probe sping runs without it: the same probe options
    /// for each target, one or several (batch takes the same options), with
    /// any other option alongside.
    #[test]
    fn icmp_is_the_probe_without_it() {
        let target = crate::context::dns::ResolvedAddr::unscoped("192.0.2.1".parse().unwrap());
        for args in [
            &["192.0.2.1"][..],
            &["192.0.2.1", "192.0.2.2"],
            &["192.0.2.1", "-s", "120", "-t", "9", "-W", "1", "-6"],
            &["192.0.2.1", "--diagnose", "--view", "json"],
        ] {
            let plain = config(args).expect("valid arguments");
            let with = config(&[args, &["--icmp"]].concat()).expect("valid arguments");
            assert_eq!(with.tcp_port, None, "{args:?}");
            assert_eq!(
                format!("{:?}", with.probe_options(target)),
                format!("{:?}", plain.probe_options(target)),
                "{args:?}"
            );
            assert_eq!((with.view, with.diagnose), (plain.view, plain.diagnose));
        }
    }

    /// `--icmp` and `--tcp` name two probes: refused as a conflict, before
    /// any configuration.
    #[test]
    fn icmp_and_tcp_conflict() {
        let err = Args::try_parse_from(["sping", "192.0.2.1", "--icmp", "--tcp", "443"])
            .expect_err("refused");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
        let text = err.to_string();
        assert!(text.contains("--icmp") && text.contains("--tcp"), "{text}");
    }

    /// `-W` is at least a millisecond, the unit of the coarsest timeout a
    /// probe hands the system (Windows' `IcmpSendEcho`). A value below a
    /// microsecond was a receive timeout of zero, which is none: every
    /// probe was a timeout.
    #[test]
    fn timeout_is_at_least_a_millisecond() {
        for refused in ["0.0000005", "0.0009", "0", "nan", "3600.1"] {
            let err = config(&["192.0.2.1", "-W", refused])
                .err()
                .expect("refused");
            assert_eq!(
                err,
                format!(
                    "timeout must be in [0.001, 3600] seconds (got {})",
                    refused.parse::<f64>().unwrap()
                )
            );
        }
        for (accepted, timeout) in [
            ("0.001", Duration::from_millis(1)),
            ("2", Duration::from_secs(2)),
            ("3600", Duration::from_secs(3600)),
        ] {
            let cfg = config(&["192.0.2.1", "-W", accepted]).expect("valid arguments");
            assert_eq!(cfg.timeout, timeout, "{accepted}");
        }
    }

    /// `--batch` takes its targets from the file and prints each one's
    /// summary, or JSON: a target on the command line and a view it is not
    /// are refused (both were ignored). The default view cannot be told
    /// from `--view compact`, so that one is taken.
    #[test]
    fn batch_refuses_what_it_would_ignore() {
        let batch = ["--batch", "no-such-batch-file"];
        let err = config(&[&batch[..], &["192.0.2.1"]].concat())
            .err()
            .expect("refused");
        assert_eq!(
            err,
            "--batch takes its targets from the file: '192.0.2.1' does not go with it"
        );
        for view in ["extended", "classic", "table"] {
            let err = config(&[&batch[..], &["--view", view]].concat())
                .err()
                .expect("refused");
            assert!(
                err.starts_with(&format!("--view {view} does not go with --batch")),
                "{err}"
            );
        }
        // The views batch has get as far as reading the file.
        for view in [&[][..], &["--view", "compact"], &["--view", "json"]] {
            let err = config(&[&batch[..], view].concat())
                .err()
                .expect("no such file");
            assert!(
                err.starts_with("cannot read batch file 'no-such-batch-file': "),
                "{err}"
            );
        }
    }

    /// A `--batch` file loses the UTF-8 byte order mark it starts with, and
    /// that one alone: a second one, or one further down, is part of the
    /// line it is in, as any other character.
    #[test]
    fn a_batch_file_loses_only_the_byte_order_mark_it_starts_with() {
        let targets = |name: &str, hosts: &str| {
            let path =
                std::env::temp_dir().join(format!("sping-{}-{name}.txt", std::process::id()));
            std::fs::write(&path, hosts).expect("a temporary directory to write in");
            let cfg = config(&["--batch", &path.to_string_lossy()]);
            let _ = std::fs::remove_file(&path);
            cfg.expect("valid arguments").targets
        };
        assert_eq!(
            targets("bom-comment", "\u{feff}# hosts\r\n192.0.2.1\r\n"),
            ["192.0.2.1"]
        );
        assert_eq!(targets("bom-host", "\u{feff}192.0.2.1\n"), ["192.0.2.1"]);
        assert_eq!(
            targets("bom-twice", "\u{feff}\u{feff}192.0.2.1\n"),
            ["\u{feff}192.0.2.1"]
        );
        assert_eq!(
            targets("bom-inside", "192.0.2.1\n\u{feff}192.0.2.2\n"),
            ["192.0.2.1", "\u{feff}192.0.2.2"]
        );
    }

    /// `-S` with an IPv4-mapped IPv6 address is the IPv4 address it stands
    /// for, as a target written that way is: the two meet at one socket,
    /// of one family.
    #[test]
    fn a_mapped_source_is_its_ipv4_address() {
        let ipv4 = "192.0.2.7".parse::<IpAddr>().ok();
        for source in ["192.0.2.7", "::ffff:192.0.2.7", "::ffff:c000:207"] {
            let cfg = config(&["192.0.2.1", "-S", source]).expect("valid arguments");
            assert_eq!(cfg.source, ipv4, "{source}");
        }
        let cfg = config(&["192.0.2.1", "-S", "::1"]).expect("valid arguments");
        assert_eq!(cfg.source, "::1".parse::<IpAddr>().ok());
    }

    /// `--wan-probe` with an IPv4-mapped IPv6 address is the IPv4 address
    /// it stands for, as `-S` and a target written that way are; any other
    /// IPv6 address stays as written.
    #[test]
    fn a_mapped_wan_probe_is_its_ipv4_address() {
        let ipv4: IpAddr = "192.0.2.7".parse().expect("an address");
        for wan in ["192.0.2.7", "::ffff:192.0.2.7", "::ffff:c000:207"] {
            let cfg = config(&["192.0.2.1", "--wan-probe", wan]).expect("valid arguments");
            assert_eq!(cfg.wan_probe, ipv4, "{wan}");
        }
        for wan in ["2001:db8::7", "::1", "::192.0.2.7"] {
            let ipv6: IpAddr = wan.parse().expect("an address");
            let cfg = config(&["192.0.2.1", "--wan-probe", wan]).expect("valid arguments");
            assert_eq!(cfg.wan_probe, ipv6, "{wan}");
        }
    }

    /// Several targets are always the table: a view it is not is refused
    /// (it was ignored), whatever stdout is.
    #[test]
    fn several_targets_refuse_a_view_the_table_is_not() {
        for view in ["extended", "classic", "json"] {
            let err = config(&["192.0.2.1", "192.0.2.2", "--view", view])
                .err()
                .expect("refused");
            assert!(
                err.starts_with(&format!("--view {view} works with one target")),
                "{err}"
            );
        }
    }
}
