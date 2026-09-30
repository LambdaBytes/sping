//! Primary probe loop: fires one ICMP echo per tick at a fixed cadence and
//! publishes a `ProbeSnapshot` after every probe. Ticks are anchored to probe
//! start, so RTT and timeouts never stretch the period.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::backends::IcmpBackend;
use crate::context::NetworkContext;
use crate::diagnostics::health::HealthTracker;
use crate::diagnostics::outage::OutageTracker;
use crate::diagnostics::spikes::SpikeDetector;
use crate::probe::quality::QualityScorer;
use crate::probe::stats::ProbeStats;
use crate::probe::types::{ProbeOptions, ProbeResult, ProbeSnapshot};

/// How often hostname targets are re-resolved (DNS failover detection).
const RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

/// Runs the probe loop, sending ICMP at `interval` and publishing snapshots.
/// Stops after `count` probes when set, or on shutdown. `ctx_rx`, when
/// provided, delivers hot network-context updates reflected in later snapshots.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    target_host: String,
    mut target_ip: IpAddr,
    dns_time: Option<Duration>,
    mut net_ctx: Option<NetworkContext>,
    interval: Duration,
    mut opts: ProbeOptions,
    count: Option<u64>,
    probe_tx: watch::Sender<Option<ProbeSnapshot>>,
    mut shutdown: watch::Receiver<bool>,
    mut ctx_rx: Option<watch::Receiver<NetworkContext>>,
) {
    let backend = match create_backend(&opts) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("error: failed to create ICMP socket: {e}");
            crate::backends::eprint_icmp_hint();
            #[cfg(target_os = "windows")]
            eprintln!("hint: try running as Administrator");
            return;
        }
    };

    let mut stats = ProbeStats::new();
    let mut quality = QualityScorer::new();
    let mut spikes = SpikeDetector::new();
    let mut outage = OutageTracker::new();
    // Hysteresis for the primary target: 3 consecutive failures → Offline,
    // 2 successes → Online. Same policy as the GW/WAN auxiliary probes.
    let mut health = HealthTracker::new(3, 2);
    let mut seq: u16 = 0;
    let mut last_ttl: Option<u8>;

    // Empty snapshot so renderers have state before the first reply.
    let _ = probe_tx.send(Some(ProbeSnapshot::empty(
        target_host.clone(),
        target_ip,
        dns_time,
        net_ctx.clone(),
    )));

    // Periodic DNS re-resolution for hostname targets: a failover that changes
    // the record should redirect probes without restarting sping.
    let (resolve_tx, mut resolve_rx) = watch::channel(target_ip);
    if target_host.parse::<IpAddr>().is_err() {
        let host = target_host.clone();
        let mut shutdown_rx = shutdown.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RE_RESOLVE_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let current = *resolve_tx.borrow();
                        if let Some(new_ip) = crate::context::dns::re_resolve(&host, current).await {
                            let _ = resolve_tx.send(new_ip);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { return; }
                    }
                }
            }
        });
    }

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
        }

        // Apply a DNS failover (same address family, see dns::re_resolve).
        if resolve_rx.has_changed().unwrap_or(false) {
            let new_ip = *resolve_rx.borrow_and_update();
            if new_ip != target_ip {
                target_ip = new_ip;
                opts.target = new_ip;
            }
        }

        // Apply a hot network-context change (WiFi → Ethernet, VPN up/down).
        if let Some(rx) = ctx_rx.as_mut()
            && rx.has_changed().unwrap_or(false)
        {
            net_ctx = Some(rx.borrow_and_update().clone());
        }

        seq = seq.wrapping_add(1);

        let backend = Arc::clone(&backend);
        let opts = opts.clone();
        let s = seq;
        let result = tokio::task::spawn_blocking(move || backend.ping(&opts, s))
            .await
            .unwrap_or(ProbeResult::Error {
                seq: seq as u64,
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

        let recovery_duration = outage.take_recovery();

        let snapshot = ProbeSnapshot {
            target_host: target_host.clone(),
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
            seq: stats.sent,
            quality: quality.grade(),
            quality_score: quality.score(),
            trend: quality.trend(),
            outage_duration: outage.current_outage(),
            last_spike_rtt: spikes.last_spike_rtt(),
            spike_guard: spikes.in_cooldown(),
            recovery_duration,
            ttl: last_ttl,
            net_ctx: net_ctx.clone(),
            reachability: health.state(),
            recent_loss_pct: quality.window_loss_pct(),
            last_error: match result {
                ProbeResult::Error { message, .. } => Some(message),
                _ => None,
            },
        };
        let _ = probe_tx.send(Some(snapshot));

        if count.is_some_and(|c| stats.sent >= c) {
            break;
        }
    }
}

/// Create an ICMP backend matching the target's address family and apply
/// socket options. An interface-bind failure only warns and continues unbound
/// (binding is unsupported on Windows and may require privileges elsewhere).
///
/// # Errors
///
/// Fails if socket creation, source binding, or setting the TTL fails.
pub(crate) fn create_backend(opts: &ProbeOptions) -> std::io::Result<IcmpBackend> {
    let backend = match opts.target {
        IpAddr::V4(_) => IcmpBackend::new()?,
        IpAddr::V6(_) => IcmpBackend::new_v6()?,
    };

    if let Some(ref iface) = opts.interface
        && let Err(e) = backend.bind_interface(iface)
    {
        eprintln!("warning: could not bind to interface {iface}: {e}");
    }

    if let Some(src) = opts.source {
        backend.bind_source(src)?;
    }

    if let Some(ttl) = opts.ttl {
        backend.set_ttl(ttl)?;
    }

    Ok(backend)
}
