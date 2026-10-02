// `clap`-derived CLI. Flags mirror `ping(8)` where applicable. Doc comments
// on `Args` and its fields are user-visible `--help` text.
//
// NOTE: plain `//` on purpose — build.rs `include!`s this file to generate
// the man page and shell completions, and inner `//!` docs are illegal at an
// include site.

use clap::Parser;

/// sping — terminal-native real-time connectivity monitor
#[derive(Parser, Debug)]
#[command(name = "sping", version, about)]
pub struct Args {
    /// Target host(s) — IP or hostname. Multiple targets enable dashboard mode.
    pub targets: Vec<String>,

    /// Network interface to bind to (e.g., eth0)
    #[arg(short = 'I', long)]
    pub interface: Option<String>,

    /// Source IP address to use
    #[arg(short = 'S', long)]
    pub source: Option<String>,

    /// Probe interval in milliseconds
    #[arg(short = 'i', long, default_value = "1000")]
    pub interval_ms: u64,

    /// Per-probe timeout in seconds
    #[arg(short = 'W', long, default_value = "2")]
    pub timeout: f64,

    /// ICMP payload size in bytes
    #[arg(short = 's', long = "size", default_value = "56")]
    pub payload_size: usize,

    /// IP TTL / IPv6 hop limit for outgoing probes
    #[arg(short = 't', long)]
    pub ttl: Option<u8>,

    /// Stop after sending N probes (any view; default in batch mode: 10)
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Quiet: suppress per-probe lines, print only the final summary (classic view)
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Force IPv4 resolution
    #[arg(short = '4', conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Force IPv6 resolution
    #[arg(short = '6')]
    pub ipv6: bool,

    /// Output view: compact, extended, classic, json, table
    #[arg(short, long, default_value = "compact")]
    pub view: String,

    /// Batch mode: read targets from file (one per line)
    #[arg(short, long)]
    pub batch: Option<String>,

    /// Output file (batch mode, default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// WAN reference probe for diagnostics
    #[arg(long, default_value = "1.1.1.1")]
    pub wan_probe: String,

    /// ASCII-only output (no Unicode glyphs); automatic on non-UTF-8 locales and on the legacy Windows console. SPING_ASCII=0 forces Unicode
    #[arg(long)]
    pub ascii: bool,

    /// List available network interfaces and exit
    #[arg(long)]
    pub list_interfaces: bool,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,
}
