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

        let source = match &args.source {
            Some(s) => {
                let ip: IpAddr = s
                    .parse()
                    .map_err(|_| format!("invalid source IP address: '{s}'"))?;
                Some(ip)
            }
            None => None,
        };

        if args.interval_ms < MIN_INTERVAL_MS {
            return Err(format!(
                "interval must be at least {MIN_INTERVAL_MS} ms (got {})",
                args.interval_ms
            ));
        }

        if !(args.timeout > 0.0 && args.timeout <= 3600.0) {
            return Err(format!(
                "timeout must be in (0, 3600] seconds (got {})",
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

        let family = match (args.ipv4, args.ipv6) {
            (true, _) => Some(Family::V4),
            (_, true) => Some(Family::V6),
            _ => None,
        };

        let mut targets = Vec::new();
        if let Some(ref batch_path) = args.batch {
            let content = std::fs::read_to_string(batch_path)
                .map_err(|e| format!("cannot read batch file '{batch_path}': {e}"))?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
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
            tcp_port: args.tcp,
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
            if !names.contains(&iface.as_str()) {
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
