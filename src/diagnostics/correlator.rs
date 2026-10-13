//! Stateless event correlator: combines target/gateway/WAN probe state into
//! typed findings, each with a stable code. Each call evaluates a single
//! snapshot; the views turn findings into text (`render::format::describe`)
//! and the JSON line carries them as they are.

use std::time::Duration;

use serde::Serialize;

use crate::diagnostics::health::Reachability;
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::quality::QualityGrade;
use crate::probe::types::{ProbeSnapshot, TcpState};

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
    /// The recent window's replies vary by more than half their mean RTT
    /// (the same window and measure as the quality grade).
    pub high_jitter: bool,
    /// The port, when the last TCP connect was refused.
    pub tcp_refused_port: Option<u16>,
}

impl<'a> DiagInput<'a> {
    /// The input for one snapshot and the auxiliary probes' state (`None`
    /// where no such probe runs, or it has no result yet).
    pub fn from_snapshot(
        snap: &ProbeSnapshot,
        gateway: Option<&'a AuxiliaryState>,
        wan: Option<&'a AuxiliaryState>,
    ) -> Self {
        Self {
            target_reachable: snap.reachability == Reachability::Online,
            target_total_loss: snap.reachability == Reachability::Offline,
            loss_pct: snap.recent_loss_pct,
            quality: snap.quality,
            gateway,
            wan,
            outage_duration: snap.outage_duration,
            recovery_duration: snap.recovery_duration,
            last_spike_rtt: snap.last_spike_rtt,
            spike_guard: snap.spike_guard,
            high_jitter: snap.high_jitter,
            tcp_refused_port: snap
                .port
                .filter(|_| snap.tcp_state == Some(TcpState::Refused)),
        }
    }
}

/// One conclusion of the correlator. `code` (snake_case) is stable: codes
/// are only ever added. The gateway and WAN states that decide some of them
/// travel next to the diagnosis (the JSON line's `gateway` and `wan`), not
/// inside each finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Finding {
    /// The last TCP connect was refused: something on the path answered for
    /// the port (the host, or a firewall in its name).
    TcpRefused { port: u16 },
    /// An outage just ended, after `duration`.
    Recovered {
        #[serde(serialize_with = "crate::probe::types::ser_duration_ms")]
        duration: Duration,
    },
    /// The target has not answered for `duration`.
    Outage {
        #[serde(serialize_with = "crate::probe::types::ser_duration_ms")]
        duration: Duration,
    },
    /// Target and gateway down: the local network.
    GatewayUnreachable,
    /// Target and WAN reference down, gateway up: beyond the gateway.
    UpstreamOutage,
    /// Target and WAN reference down, gateway state unknown: no cause claimed.
    WanUnreachable,
    /// Target down with the gateway and WAN reference not down.
    TargetUnreachable {
        /// The WAN reference answers (shown as "internet still OK"); the
        /// JSON line has it in `wan`.
        #[serde(skip)]
        wan_online: bool,
    },
    /// A latency spike, `rtt`, with the spike guard on.
    LatencySpike {
        #[serde(serialize_with = "crate::probe::types::ser_duration_ms")]
        rtt: Duration,
    },
    /// The recent window's replies vary by more than half their mean RTT,
    /// without loss.
    HighJitter,
    /// Some, not all, of the recent window's probes were lost.
    IntermittentLoss { recent_loss_pct: f64 },
    /// Target reachable, WAN reference down, gateway up.
    WanDegraded,
}

/// Findings in priority order: the TCP refusal, recovery, then outage
/// localization (gateway vs upstream vs target), then quality events.
pub fn diagnose(input: &DiagInput) -> Vec<Finding> {
    let mut findings = Vec::new();

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

    // A refusal is an answer, whatever the target's hysteresis state says.
    if let Some(port) = input.tcp_refused_port {
        findings.push(Finding::TcpRefused { port });
    }

    if let Some(duration) = input.recovery_duration {
        findings.push(Finding::Recovered { duration });
    }

    if input.target_total_loss {
        if let Some(duration) = input.outage_duration {
            findings.push(Finding::Outage { duration });
        }

        if gw_offline {
            findings.push(Finding::GatewayUnreachable);
        } else if wan_offline && gw_online {
            findings.push(Finding::UpstreamOutage);
        } else if wan_offline {
            // The WAN probe is down too, but nothing is known about the
            // gateway (no probe, or no verdict yet): the outage may be local
            // or upstream, so neither is claimed.
            findings.push(Finding::WanUnreachable);
        } else {
            findings.push(Finding::TargetUnreachable { wan_online });
        }
    } else if input.target_reachable {
        if let Some(rtt) = input.last_spike_rtt
            && input.spike_guard
        {
            findings.push(Finding::LatencySpike { rtt });
        }

        if input.high_jitter && input.loss_pct < 1.0 {
            findings.push(Finding::HighJitter);
        }

        if input.loss_pct > 0.0 && input.loss_pct < 100.0 {
            findings.push(Finding::IntermittentLoss {
                recent_loss_pct: input.loss_pct,
            });
        }

        if wan_offline && gw_online {
            findings.push(Finding::WanDegraded);
        }
    }

    findings
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
            high_jitter: false,
            tcp_refused_port: None,
        }
    }

    fn down<'a>() -> DiagInput<'a> {
        let mut input = base_input();
        input.target_reachable = false;
        input.target_total_loss = true;
        input
    }

    fn aux(label: &str, reachability: Reachability) -> AuxiliaryState {
        AuxiliaryState {
            label: label.into(),
            target: "192.0.2.1".parse().unwrap(),
            reachability,
            last_rtt: None,
        }
    }

    #[test]
    fn test_no_events_when_healthy() {
        assert!(diagnose(&base_input()).is_empty());
    }

    /// Target down: where the outage is, from the gateway and WAN states.
    #[test]
    fn outage_localization() {
        let online = |l| aux(l, Reachability::Online);
        let offline = |l| aux(l, Reachability::Offline);
        let unknown = |l| aux(l, Reachability::Unknown);
        let (gw_on, gw_off, gw_unk) = (online("GW"), offline("GW"), unknown("GW"));
        let (wan_on, wan_off, wan_unk) = (online("WAN"), offline("WAN"), unknown("WAN"));
        let cases: [(Option<&AuxiliaryState>, Option<&AuxiliaryState>, Finding); 9] = [
            (Some(&gw_off), Some(&wan_on), Finding::GatewayUnreachable),
            (Some(&gw_off), None, Finding::GatewayUnreachable),
            (Some(&gw_on), Some(&wan_off), Finding::UpstreamOutage),
            (None, Some(&wan_off), Finding::WanUnreachable),
            (Some(&gw_unk), Some(&wan_off), Finding::WanUnreachable),
            (
                Some(&gw_on),
                Some(&wan_on),
                Finding::TargetUnreachable { wan_online: true },
            ),
            (
                None,
                Some(&wan_unk),
                Finding::TargetUnreachable { wan_online: false },
            ),
            (None, None, Finding::TargetUnreachable { wan_online: false }),
            (
                Some(&gw_on),
                None,
                Finding::TargetUnreachable { wan_online: false },
            ),
        ];
        for (gateway, wan, expected) in cases {
            let mut input = down();
            input.gateway = gateway;
            input.wan = wan;
            assert_eq!(diagnose(&input), [expected]);
        }
    }

    /// Every finding a state can produce, in priority order.
    #[test]
    fn findings_come_in_priority_order() {
        let mut input = down();
        input.tcp_refused_port = Some(443);
        input.recovery_duration = Some(Duration::from_secs(92));
        input.outage_duration = Some(Duration::from_secs(12));
        assert_eq!(
            diagnose(&input),
            [
                Finding::TcpRefused { port: 443 },
                Finding::Recovered {
                    duration: Duration::from_secs(92)
                },
                Finding::Outage {
                    duration: Duration::from_secs(12)
                },
                Finding::TargetUnreachable { wan_online: false },
            ]
        );

        let (gw, wan) = (
            aux("GW", Reachability::Online),
            aux("WAN", Reachability::Offline),
        );
        let mut input = base_input();
        input.gateway = Some(&gw);
        input.wan = Some(&wan);
        input.last_spike_rtt = Some(Duration::from_millis(120));
        input.spike_guard = true;
        input.loss_pct = 0.5;
        input.high_jitter = true;
        assert_eq!(
            diagnose(&input),
            [
                Finding::LatencySpike {
                    rtt: Duration::from_millis(120)
                },
                Finding::HighJitter,
                Finding::IntermittentLoss {
                    recent_loss_pct: 0.5
                },
                Finding::WanDegraded,
            ]
        );
    }

    /// No verdict yet on the target (hysteresis `Unknown`): only what does
    /// not depend on it, the TCP refusal.
    #[test]
    fn unknown_target_state_gives_only_the_refusal() {
        let mut input = base_input();
        input.target_reachable = false;
        input.loss_pct = 5.0;
        input.tcp_refused_port = Some(22);
        assert_eq!(diagnose(&input), [Finding::TcpRefused { port: 22 }]);
    }

    /// The warning follows the window's high-jitter flag, and only without
    /// recent loss.
    #[test]
    fn test_high_jitter_warning() {
        let mut input = base_input();
        input.high_jitter = true;
        assert_eq!(diagnose(&input), [Finding::HighJitter]);
        input.loss_pct = 5.0;
        assert_eq!(
            diagnose(&input),
            [Finding::IntermittentLoss {
                recent_loss_pct: 5.0
            }]
        );
        input.loss_pct = 0.0;
        input.high_jitter = false;
        assert!(diagnose(&input).is_empty());
    }

    /// A spike counts only while the guard is on.
    #[test]
    fn spike_needs_the_guard() {
        let mut input = base_input();
        input.last_spike_rtt = Some(Duration::from_millis(120));
        assert!(diagnose(&input).is_empty());
    }

    /// Codes and evidence as the JSON carries them; durations in ms.
    #[test]
    fn findings_serialize_as_codes_with_evidence() {
        let json = |f: &Finding| serde_json::to_string(f).unwrap();
        assert_eq!(
            json(&Finding::TcpRefused { port: 443 }),
            r#"{"code":"tcp_refused","port":443}"#
        );
        assert_eq!(
            json(&Finding::Recovered {
                duration: Duration::from_micros(92_000_500)
            }),
            r#"{"code":"recovered","duration":92000.5}"#
        );
        assert_eq!(
            json(&Finding::Outage {
                duration: Duration::from_secs(12)
            }),
            r#"{"code":"outage","duration":12000.0}"#
        );
        assert_eq!(
            json(&Finding::LatencySpike {
                rtt: Duration::from_micros(120_250)
            }),
            r#"{"code":"latency_spike","rtt":120.25}"#
        );
        assert_eq!(
            json(&Finding::IntermittentLoss {
                recent_loss_pct: 10.0
            }),
            r#"{"code":"intermittent_loss","recent_loss_pct":10.0}"#
        );
        assert_eq!(
            json(&Finding::TargetUnreachable { wan_online: true }),
            r#"{"code":"target_unreachable"}"#
        );
        for (finding, code) in [
            (Finding::GatewayUnreachable, "gateway_unreachable"),
            (Finding::UpstreamOutage, "upstream_outage"),
            (Finding::WanUnreachable, "wan_unreachable"),
            (Finding::HighJitter, "high_jitter"),
            (Finding::WanDegraded, "wan_degraded"),
        ] {
            assert_eq!(json(&finding), format!(r#"{{"code":"{code}"}}"#));
        }
    }
}
