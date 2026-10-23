//! Core probe data types. Serialized `ProbeSnapshot` fields are part of the
//! frozen JSON contract (see `JSON_CONTRACT.md`); durations serialize as ms.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::context::{ContextChange, NetworkContext};
use crate::probe::quality::{QualityGrade, Trend};
use crate::probe::trace::UnreachableKind;

/// Result of a single probe.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProbeResult {
    /// ICMP echo reply.
    Reply {
        seq: u64,
        rtt: Duration,
        ttl: u8,
    },
    /// TCP: the connection was established.
    Connected {
        seq: u64,
        rtt: Duration,
    },
    /// TCP: the connection was refused (a reset, or an ICMP port-unreachable
    /// from the target or a device on the way). Something answered.
    Refused {
        seq: u64,
        rtt: Duration,
    },
    Timeout {
        seq: u64,
    },
    /// ICMP: a destination unreachable about this probe, from a router on
    /// the way or from this host. Not a reply and not a timeout: the probe
    /// is lost, and `from` said why.
    Unreachable {
        seq: u64,
        from: IpAddr,
        kind: UnreachableKind,
    },
    Error {
        seq: u64,
        message: String,
    },
}

/// The destination unreachable the latest probe got (`icmp_unreachable` in
/// JSON, added in 1.8.0): who sent it and what it said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Unreachable {
    #[serde(serialize_with = "ser_ip")]
    pub from: IpAddr,
    pub kind: UnreachableKind,
}

/// Options passed to the probe backend (ICMP or TCP) for each probe.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub target: IpAddr,
    /// IPv6 zone index of a link-local `target` (`fe80::1%eth0`); 0 = none.
    pub scope_id: u32,
    pub timeout: Duration,
    /// ICMP payload size in bytes (default 56, like `ping`).
    pub payload_size: usize,
    /// Outgoing TTL / hop limit; None = OS default.
    pub ttl: Option<u8>,
    /// Interface to bind the socket to (`-I`); platform-dependent support.
    #[allow(dead_code)]
    pub interface: Option<String>,
    #[allow(dead_code)]
    pub source: Option<IpAddr>,
    /// `Some(port)`: probe with a TCP connect to that port instead of ICMP.
    pub tcp_port: Option<u16>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            target: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            scope_id: 0,
            timeout: Duration::from_secs(2),
            payload_size: 56,
            ttl: None,
            interface: None,
            source: None,
            tcp_port: None,
        }
    }
}

/// Outcome of the latest TCP connect (`tcp_state` in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpState {
    Open,
    Refused,
    Timeout,
    Error,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TcpState::Open => "open",
            TcpState::Refused => "refused",
            TcpState::Timeout => "timeout",
            TcpState::Error => "error",
        })
    }
}

/// The last re-resolution of the target's name (names only; every 60 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameState {
    /// The answer had an address of the probed family.
    Answered,
    /// The answer had no address of the probed family (a resolver may leave
    /// one out: not proof that the name has none).
    NoAddressOfFamily,
    /// The lookup failed: no answer within the timeout, or an error.
    Failed { timed_out: bool },
}

/// The last change of the network context, while recent (`context_changed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentChange {
    pub changes: Vec<ContextChange>,
    /// Since it was applied.
    pub age: Duration,
}

/// Entry in the pulse ring buffer.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(dead_code)]
pub enum PulseEntry {
    /// Reply received; carries the RTT (serialized as milliseconds).
    Reply(#[serde(serialize_with = "ser_duration_ms")] Duration),
    /// Probe timed out or errored.
    Loss,
    /// Slot with no sample yet; rendered as blank padding.
    Empty,
}

/// Snapshot of probe stats, published via the Bus.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeSnapshot {
    /// Target as given on the command line (hostname or IP literal).
    pub target_host: String,
    #[serde(serialize_with = "ser_ip")]
    pub target_ip: IpAddr,
    /// Initial DNS resolution time; `None` for IP-literal targets.
    #[serde(
        serialize_with = "ser_opt_duration_ms",
        skip_serializing_if = "Option::is_none"
    )]
    pub dns_time: Option<Duration>,
    pub sent: u64,
    pub received: u64,
    /// Probes lost (timeout or error).
    pub lost: u64,
    /// Lifetime loss percentage (0-100).
    pub loss_pct: f64,
    /// RTT of the most recent reply; `None` after a timeout/error.
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub rtt_last: Option<Duration>,
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub rtt_avg: Option<Duration>,
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub rtt_min: Option<Duration>,
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub rtt_max: Option<Duration>,
    /// Mean absolute difference between consecutive RTTs (RFC 3550 style).
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub jitter: Option<Duration>,
    /// Standard deviation of RTT (ping-style mdev).
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub mdev: Option<Duration>,
    /// Recent samples for the pulse strip, oldest first (capacity 40).
    pub pulse: Vec<PulseEntry>,
    /// Sequence number of the last probe sent (equals `sent`).
    pub seq: u64,
    /// Quality grade over the rolling window; `None` until enough samples
    /// (serialized as `"unknown"`).
    #[serde(serialize_with = "ser_quality")]
    pub quality: Option<QualityGrade>,
    /// `None` until enough samples (serialized as `"unknown"`).
    #[serde(serialize_with = "ser_quality_score")]
    pub quality_score: Option<u8>,
    /// `None` until enough samples (serialized as `"unknown"`).
    #[serde(serialize_with = "ser_trend")]
    pub trend: Option<Trend>,
    /// Elapsed time of the ongoing outage; `None` when the target replies.
    #[serde(
        serialize_with = "ser_opt_duration_ms",
        skip_serializing_if = "Option::is_none"
    )]
    pub outage_duration: Option<Duration>,
    #[serde(
        serialize_with = "ser_opt_duration_ms",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_spike_rtt: Option<Duration>,
    /// True while the spike detector is in its post-spike cooldown.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub spike_guard: bool,
    /// Duration of the outage that just ended; set only on the snapshot
    /// immediately following recovery.
    #[serde(
        serialize_with = "ser_opt_duration_ms",
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_duration: Option<Duration>,
    /// TTL / hop limit observed on the last reply; `None` after a loss.
    pub ttl: Option<u8>,
    /// Local network context (interface, gateway, target class), if detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_ctx: Option<NetworkContext>,
    /// Hysteresis-based reachability of the primary target. Internal correlator
    /// input; not part of the frozen JSON contract.
    #[serde(skip)]
    pub reachability: crate::diagnostics::health::Reachability,
    /// Loss percentage over the recent rolling window (current condition, not
    /// lifetime). Internal correlator input; not serialized.
    #[serde(skip)]
    pub recent_loss_pct: f64,
    /// The recent window's replies vary by more than half their mean RTT
    /// (`QualityScorer::high_jitter`, the window the grade uses). Internal
    /// correlator input; not serialized.
    #[serde(skip)]
    pub high_jitter: bool,
    /// Why the most recent probe failed, when it failed with an error rather
    /// than a timeout (e.g. the OS refused to send). Shown by the views so an
    /// error is not mistaken for a lost reply; not serialized.
    #[serde(skip)]
    pub last_error: Option<String>,
    /// Destination unreachables among the lost probes so far (ICMP; the
    /// classic summary's `+N errors`). Not serialized.
    #[serde(skip)]
    pub unreachable: u64,
    /// The last re-resolution of the target's name, while it is current
    /// (none yet, a literal target, or cleared by a context change: `None`).
    /// Internal correlator input; not serialized.
    #[serde(skip)]
    pub name: Option<NameState>,
    /// The last change of the network context in the last 30 s, single
    /// target only, never with `-I`/`-S`. Internal correlator input; not
    /// serialized.
    #[serde(skip)]
    pub context_change: Option<RecentChange>,
    /// TCP mode only (added in 1.6.0; absent from ICMP lines): `"tcp"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<&'static str>,
    /// TCP mode only: the port probed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// TCP mode only: answers that were refusals (part of `received`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<u64>,
    /// TCP mode only: outcome of the latest connect; absent before the first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_state: Option<TcpState>,
    /// ICMP only: the destination unreachable the latest probe got, if it
    /// got one (added in 1.8.0; absent otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_unreachable: Option<Unreachable>,
}

impl ProbeSnapshot {
    /// Zeroed snapshot published before the first probe completes, so
    /// consumers have an initial state.
    pub fn empty(
        target_host: String,
        target_ip: IpAddr,
        dns_time: Option<Duration>,
        net_ctx: Option<NetworkContext>,
    ) -> Self {
        Self {
            target_host,
            target_ip,
            dns_time,
            sent: 0,
            received: 0,
            lost: 0,
            loss_pct: 0.0,
            rtt_last: None,
            rtt_avg: None,
            rtt_min: None,
            rtt_max: None,
            jitter: None,
            mdev: None,
            pulse: Vec::new(),
            seq: 0,
            quality: None,
            quality_score: None,
            trend: None,
            outage_duration: None,
            last_spike_rtt: None,
            spike_guard: false,
            recovery_duration: None,
            ttl: None,
            net_ctx,
            reachability: crate::diagnostics::health::Reachability::Unknown,
            recent_loss_pct: 0.0,
            high_jitter: false,
            last_error: None,
            unreachable: 0,
            name: None,
            context_change: None,
            probe: None,
            port: None,
            refused: None,
            tcp_state: None,
            icmp_unreachable: None,
        }
    }

    /// Mark the snapshot as a TCP probe of `port` (no-op for ICMP).
    pub fn with_tcp(mut self, port: Option<u16>) -> Self {
        if let Some(port) = port {
            self.probe = Some("tcp");
            self.port = Some(port);
            self.refused = Some(0);
        }
        self
    }
}

/// Serialize a `Duration` as milliseconds (a float, sub-ms kept).
pub(crate) fn ser_duration_ms<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64() * 1000.0)
}

/// Serialize an optional `Duration` as milliseconds, or `null`.
pub(crate) fn ser_opt_duration_ms<S: serde::Serializer>(
    d: &Option<Duration>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match d {
        Some(d) => s.serialize_some(&(d.as_secs_f64() * 1000.0)),
        None => s.serialize_none(),
    }
}

/// Serialize an `IpAddr` as its canonical string form.
pub fn ser_ip<S: serde::Serializer>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ip.to_string())
}

fn ser_quality<S: serde::Serializer>(q: &Option<QualityGrade>, s: S) -> Result<S::Ok, S::Error> {
    match q {
        Some(grade) => grade.serialize(s),
        None => s.serialize_str("unknown"),
    }
}

fn ser_quality_score<S: serde::Serializer>(q: &Option<u8>, s: S) -> Result<S::Ok, S::Error> {
    match q {
        Some(score) => s.serialize_u8(*score),
        None => s.serialize_str("unknown"),
    }
}

fn ser_trend<S: serde::Serializer>(t: &Option<Trend>, s: S) -> Result<S::Ok, S::Error> {
    match t {
        Some(trend) => s.serialize_str(&trend.to_string()),
        None => s.serialize_str("unknown"),
    }
}
