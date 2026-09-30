//! Batch probing (`--batch`): runs a fixed probe count per target and returns
//! a single final snapshot, with no intermediate publishing.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::context::NetworkContext;
use crate::diagnostics::health::HealthTracker;
use crate::diagnostics::outage::OutageTracker;
use crate::diagnostics::spikes::SpikeDetector;
use crate::probe::quality::QualityScorer;
use crate::probe::scheduler::create_backend;
use crate::probe::stats::ProbeStats;
use crate::probe::types::{ProbeOptions, ProbeResult, ProbeSnapshot};

/// Run exactly `count` probes against a target and return the final snapshot.
/// On socket-creation failure, prints a warning and returns an empty snapshot
/// (zero sent) so a failing target does not abort the batch.
pub async fn probe_target(
    target_host: String,
    target_ip: IpAddr,
    dns_time: Option<Duration>,
    net_ctx: Option<NetworkContext>,
    interval: Duration,
    opts: ProbeOptions,
    count: u64,
) -> ProbeSnapshot {
    let backend = match create_backend(&opts) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("  {target_host}: failed to create ICMP socket: {e}");
            return ProbeSnapshot::empty(target_host, target_ip, dns_time, net_ctx);
        }
    };

    let mut stats = ProbeStats::new();
    let mut quality = QualityScorer::new();
    let mut spikes = SpikeDetector::new();
    let mut outage = OutageTracker::new();
    let mut health = HealthTracker::new(3, 2);
    let mut last_ttl: Option<u8> = None;
    let mut last_error: Option<String> = None;

    // Fixed cadence, same policy as the scheduler.
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    for seq in 1..=count {
        ticker.tick().await;
        let backend = Arc::clone(&backend);
        let opts = opts.clone();
        let s = seq as u16;
        let result = tokio::task::spawn_blocking(move || backend.ping(&opts, s))
            .await
            .unwrap_or(ProbeResult::Error {
                seq,
                message: "probe task panicked".into(),
            });

        match &result {
            ProbeResult::Reply { rtt, ttl, .. } => {
                stats.record_reply(*rtt);
                quality.record_reply(*rtt);
                spikes.record(*rtt);
                outage.record_reply();
                health.record_success();
                last_ttl = Some(*ttl);
            }
            ProbeResult::Timeout { .. } => {
                stats.record_timeout();
                quality.record_loss();
                outage.record_failure();
                health.record_failure();
                last_ttl = None;
            }
            ProbeResult::Error { .. } => {
                stats.record_error();
                quality.record_loss();
                outage.record_failure();
                health.record_failure();
                last_ttl = None;
            }
        }
        last_error = match result {
            ProbeResult::Error { message, .. } => Some(message),
            _ => None,
        };
    }

    let recovery_duration = outage.take_recovery();

    ProbeSnapshot {
        target_host,
        target_ip,
        dns_time,
        sent: stats.sent,
        received: stats.received,
        lost: stats.lost,
        loss_pct: stats.loss_pct(),
        rtt_last: stats.rtt_last(),
        rtt_avg: stats.rtt_avg(),
        rtt_min: stats.rtt_min(),
        rtt_max: stats.rtt_max(),
        jitter: stats.jitter(),
        mdev: stats.mdev(),
        pulse: stats.pulse(),
        seq: count,
        quality: quality.grade(),
        quality_score: quality.score(),
        trend: quality.trend(),
        outage_duration: outage.current_outage(),
        last_spike_rtt: spikes.last_spike_rtt(),
        spike_guard: spikes.in_cooldown(),
        recovery_duration,
        ttl: last_ttl,
        net_ctx,
        reachability: health.state(),
        recent_loss_pct: quality.window_loss_pct(),
        last_error,
    }
}
