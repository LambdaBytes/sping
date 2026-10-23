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
    /// Target host(s) — IP or hostname; an IPv6 link-local address needs its zone (fe80::1%eth0). Multiple targets enable dashboard mode.
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

    /// ICMP payload size in bytes (default 56)
    #[arg(short = 's', long = "size")]
    pub payload_size: Option<usize>,

    /// Probe with a TCP connect to PORT instead of ICMP: works without ICMP permission and through ICMP filters
    #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..), conflicts_with = "payload_size")]
    pub tcp: Option<u16>,

    /// Probe with an ICMP echo, what sping does without it until 2.0 changes the default: keeps this probe for scripts (--diagnose keeps its extra probes)
    #[arg(long, conflicts_with = "tcp")]
    pub icmp: bool,

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

    /// Experimental: when the target stops answering, find out why (the other address family, TCP 443 and 80, a bounded traceroute) and show what was found. One target only
    #[arg(long)]
    pub diagnose: bool,

    /// Output view; several targets are shown as the table
    #[arg(short, long, default_value = "compact", value_parser = ["compact", "extended", "classic", "json", "table"])]
    pub view: String,

    /// Batch mode: read targets from file (one per line)
    #[arg(short, long)]
    pub batch: Option<String>,

    /// Output file (batch mode, default: stdout)
    #[arg(short, long, requires = "batch")]
    pub output: Option<String>,

    /// WAN reference probe for diagnostics
    #[arg(long, default_value = "1.1.1.1")]
    pub wan_probe: String,

    /// ASCII-only output (no Unicode glyphs); automatic on non-UTF-8 locales and on the legacy Windows console. SPING_ASCII=0 forces Unicode
    #[arg(long)]
    pub ascii: bool,

    /// List available network interfaces and exit (IPv4; see --ip for every address)
    #[arg(long)]
    pub list_interfaces: bool,

    /// Show this host's addresses (every interface, IPv4 and IPv6, with prefix, kind and state), the source each family uses and the IPv4 gateway, then exit; --view json for scripts. Sends nothing unless --external
    #[arg(long, conflicts_with_all = ["targets", "batch", "diagnose", "tcp", "list_interfaces"])]
    pub ip: bool,

    /// With --ip: ask a STUN server over UDP (default stun.cloudflare.com:3478) which address and port it sees each family come from; at most 3 requests per family within 3 s. It contacts that third party, so only when given
    #[arg(
        long,
        value_name = "SERVER[:PORT]",
        requires = "ip",
        num_args = 0..=1,
        default_missing_value = "stun.cloudflare.com:3478"
    )]
    pub external: Option<String>,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,
}
