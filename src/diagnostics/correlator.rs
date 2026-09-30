//! Stateless event correlator: combines target/gateway/WAN probe state into
//! human-readable diagnostic messages. Each call evaluates a single snapshot.

use std::time::Duration;

use crate::diagnostics::health::Reachability;
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::quality::QualityGrade;
use crate::render::format::{fmt_elapsed, fmt_rtt};

/// Diagnostic input for the correlator.
pub struct DiagInput<'a> {
    /// Target hysteresis state is `Online`.
    pub target_reachable: bool,
    /// Target hysteresis state is `Offline`.
    pub target_total_loss: bool,
    /// Percentage (0–100).
    pub loss_pct: f64,
    /// Reserved for future rules.
    #[allow(dead_code)]
    pub quality: Option<QualityGrade>,
    /// `None` when no gateway probe runs.
    pub gateway: Option<&'a AuxiliaryState>,
    /// `None` when no WAN probe runs.
    pub wan: Option<&'a AuxiliaryState>,
    pub outage_duration: Option<Duration>,
    /// Duration of the outage that just ended, if a recovery occurred.
    pub recovery_duration: Option<Duration>,
    pub last_spike_rtt: Option<Duration>,
    /// Spike-detector cooldown is active.
    pub spike_guard: bool,
    pub jitter: Option<Duration>,
    pub rtt_avg: Option<Duration>,
}

/// Produce diagnostic messages in priority order: recovery, then outage
/// localization (gateway vs upstream vs target), then quality events.
pub fn diagnose(input: &DiagInput) -> Vec<String> {
    let mut events = Vec::new();

    let gw_offline = input
        .gateway
        .is_some_and(|g| g.reachability == Reachability::Offline);
    let wan_offline = input
        .wan
        .is_some_and(|w| w.reachability == Reachability::Offline);
    let wan_online = input
        .wan
        .is_some_and(|w| w.reachability == Reachability::Online);
    let gw_online = input
        .gateway
        .is_some_and(|g| g.reachability == Reachability::Online);

    if let Some(dur) = input.recovery_duration {
        events.push(format!("recovered after {}", fmt_elapsed(dur)));
    }

    if input.target_total_loss {
        if let Some(dur) = input.outage_duration {
            events.push(format!("outage {}", fmt_elapsed(dur)));
        }

        if gw_offline {
            events.push("gateway unreachable".into());
            events.push("local network issue likely".into());
        } else if wan_offline && gw_online {
            events.push("upstream outage likely".into());
            events.push("local gateway OK".into());
        } else if wan_offline {
            // Gateway state unknown (no probe) but WAN is down: still an
            // upstream problem, not a target-specific one.
            events.push("upstream outage likely".into());
        } else if wan_online {
            events.push("target unreachable".into());
            events.push("internet still OK".into());
        } else {
            events.push("target unreachable".into());
        }
    } else if input.target_reachable {
        if let Some(spike_rtt) = input.last_spike_rtt
            && input.spike_guard
        {
            events.push(format!("last spike {}", fmt_rtt(spike_rtt)));
            events.push("spike guard on".into());
        }

        if let (Some(jitter), Some(avg)) = (input.jitter, input.rtt_avg) {
            let rel = if avg.as_secs_f64() > 0.0 {
                jitter.as_secs_f64() / avg.as_secs_f64() * 100.0
            } else {
                0.0
            };
            if rel > 50.0 && input.loss_pct < 1.0 {
                events.push("high jitter with no loss".into());
                events.push("unstable path".into());
            }
        }

        if input.loss_pct > 0.0 && input.loss_pct < 100.0 {
            events.push("intermittent loss".into());
        }

        if wan_offline && gw_online {
            events.push("WAN degraded".into());
            events.push("gateway OK".into());
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn base_input<'a>() -> DiagInput<'a> {
        DiagInput {
            target_reachable: true,
            target_total_loss: false,
            loss_pct: 0.0,
            quality: None,
            gateway: None,
            wan: None,
            outage_duration: None,
            recovery_duration: None,
            last_spike_rtt: None,
            spike_guard: false,
            jitter: None,
            rtt_avg: None,
        }
    }

    #[test]
    fn test_no_events_when_healthy() {
        let input = base_input();
        let events = diagnose(&input);
        assert!(events.is_empty());
    }

    #[test]
    fn test_target_unreachable() {
        let mut input = base_input();
        input.target_reachable = false;
        input.target_total_loss = true;
        let events = diagnose(&input);
        assert!(events.iter().any(|e| e.contains("target unreachable")));
    }

    #[test]
    fn test_intermittent_loss() {
        let mut input = base_input();
        input.loss_pct = 5.0;
        let events = diagnose(&input);
        assert!(events.iter().any(|e| e.contains("intermittent loss")));
    }

    #[test]
    fn test_wan_offline_gateway_unknown_is_upstream_outage() {
        let wan = AuxiliaryState {
            label: "WAN".into(),
            target: "1.1.1.1".parse().unwrap(),
            reachability: Reachability::Offline,
            last_rtt: None,
        };
        let mut input = base_input();
        input.target_reachable = false;
        input.target_total_loss = true;
        input.wan = Some(&wan);
        // gateway stays None (unknown)
        let events = diagnose(&input);
        assert!(
            events.iter().any(|e| e.contains("upstream outage")),
            "expected upstream outage, got: {events:?}"
        );
    }

    #[test]
    fn test_recovery_event() {
        let mut input = base_input();
        input.recovery_duration = Some(Duration::from_secs(92));
        let events = diagnose(&input);
        assert!(events.iter().any(|e| e.contains("recovered after")));
    }
}
