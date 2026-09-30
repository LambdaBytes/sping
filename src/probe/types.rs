//! Core probe data types. Serialized `ProbeSnapshot` fields are part of the
//! frozen JSON contract (see `JSON_CONTRACT.md`); durations serialize as ms.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::context::NetworkContext;
use crate::probe::quality::{QualityGrade, Trend};

/// Result of a single ICMP echo probe.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProbeResult {
    Reply { seq: u64, rtt: Duration, ttl: u8 },
    Timeout { seq: u64 },
    Error { seq: u64, message: String },
}

/// Options passed to the ICMP backend for each probe.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub target: IpAddr,
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
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            target: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            timeout: Duration::from_secs(2),
            payload_size: 56,
            ttl: None,
            interface: None,
            source: None,
        }
    }
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
        }
    }
}

fn ser_duration_ms<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64() * 1000.0)
}

fn ser_opt_duration_ms<S: serde::Serializer>(
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
