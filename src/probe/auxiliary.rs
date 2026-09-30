//! Auxiliary reachability probes (default gateway, WAN reference). Run at a
//! slower cadence and feed the correlator to localize failures (LAN vs WAN).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::backends::IcmpBackend;
use crate::diagnostics::health::{HealthTracker, Reachability};
use crate::probe::types::ProbeOptions;

/// State of an auxiliary probe (gateway or WAN).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuxiliaryState {
    /// Human-readable probe name (e.g. "gateway", "wan").
    pub label: String,
    /// Address currently being probed; may change on hot network updates.
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    pub target: IpAddr,
    /// Hysteresis-filtered reachability state.
    pub reachability: Reachability,
    /// RTT of the most recent probe; `None` if it failed.
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub last_rtt: Option<Duration>,
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

/// Run an auxiliary probe loop at a slower `interval`, publishing
/// `AuxiliaryState`. The target arrives via a watch channel so it can be
/// retargeted on hot network changes (e.g. default gateway changes on WiFi →
/// Ethernet).
pub async fn run(
    label: String,
    target_rx: watch::Receiver<IpAddr>,
    interval: Duration,
    tx: watch::Sender<Option<AuxiliaryState>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let backend = match IcmpBackend::new() {
        Ok(b) => Arc::new(b),
        Err(e) => {
            // \r\n: the TUI may already be in raw mode.
            eprint!("warning: {label} auxiliary probe disabled: {e}\r\n");
            return;
        }
    };

    // Hysteresis: 3 consecutive failures → offline, 2 successes → online
    let mut health = HealthTracker::new(3, 2);
    let mut seq: u16 = 0;
    let mut target = *target_rx.borrow();

    loop {
        seq = seq.wrapping_add(1);

        let new_target = *target_rx.borrow();
        if new_target != target {
            // Retarget: reset hysteresis, the old state is meaningless.
            target = new_target;
            health = HealthTracker::new(3, 2);
        }

        let opts = ProbeOptions {
            target,
            timeout: Duration::from_secs(2),
            payload_size: 32,
            ttl: None,
            interface: None,
            source: None,
        };

        let backend = Arc::clone(&backend);
        let s = seq;
        let result = tokio::task::spawn_blocking(move || backend.ping(&opts, s)).await;

        let mut last_rtt = None;
        match result {
            Ok(crate::probe::types::ProbeResult::Reply { rtt, .. }) => {
                health.record_success();
                last_rtt = Some(rtt);
            }
            _ => {
                health.record_failure();
            }
        }

        let state = AuxiliaryState {
            label: label.clone(),
            target,
            reachability: health.state(),
            last_rtt,
        };
        let _ = tx.send(Some(state));

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}
