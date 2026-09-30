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
    /// `None` uses the OS default TTL / hop limit.
    pub ttl: Option<u8>,
    /// `None` runs until interrupted; defaults to 10 in batch mode.
    pub count: Option<u64>,
    pub quiet: bool,
    /// Forced address family; `None` lets DNS resolution decide.
    pub family: Option<Family>,
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
    /// Traditional `ping`-style line-per-probe output.
    Classic,
    /// NDJSON, one snapshot per line (contract frozen, see `JSON_CONTRACT.md`).
    Json,
    /// Multi-target dashboard table.
    Table,
}

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

        // Piped compact/extended fall back to classic (no TTY for raw mode).
        if !is_batch
            && !std::io::stdout().is_terminal()
            && matches!(view, ViewMode::Compact | ViewMode::Extended)
        {
            eprintln!("note: stdout is not a TTY, falling back to classic view");
            view = ViewMode::Classic;
        }

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

        if args.payload_size > MAX_PAYLOAD {
            return Err(format!(
                "payload size must be at most {MAX_PAYLOAD} bytes (got {})",
                args.payload_size
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

        // Batch mode keeps its historical default of 10 probes per target.
        let count = args.count.or(if is_batch { Some(10) } else { None });

        Ok(Self {
            targets,
            interface: args.interface.clone(),
            source,
            interval: Duration::from_millis(args.interval_ms),
            timeout: Duration::from_secs_f64(args.timeout),
            payload_size: args.payload_size,
            ttl: args.ttl,
            count,
            quiet: args.quiet,
            family,
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
    pub fn probe_options(&self, target: IpAddr) -> crate::probe::types::ProbeOptions {
        crate::probe::types::ProbeOptions {
            target,
            timeout: self.timeout,
            payload_size: self.payload_size,
            ttl: self.ttl,
            interface: self.interface.clone(),
            source: self.source,
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
