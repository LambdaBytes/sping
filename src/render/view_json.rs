//! NDJSON view: one JSON object per probe, one per line. The output schema
//! is frozen — see `JSON_CONTRACT.md` before changing any field. No raw
//! mode, so output is safe to pipe.

use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::diagnostics::correlator::{self, DiagInput, Finding};
use crate::diagnostics::evidence::Gap;
use crate::diagnostics::health::Reachability;
use crate::diagnostics::planner::Conclusion;
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::diagnose::DiagnoseState;
use crate::probe::types::ProbeSnapshot;

/// One NDJSON line: the snapshot's fields as contract v1 fixes them, then
/// the fields added in 1.6.0 — the gateway and WAN probes' state and the
/// diagnosis drawn from that same state. Each is absent when there is
/// nothing to say, so a line with none of them is the snapshot alone, byte
/// for byte.
#[derive(Serialize)]
struct JsonLine<'a> {
    #[serde(flatten)]
    snap: &'a ProbeSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<AuxJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wan: Option<AuxJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnosis: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_diagnosis: Option<ActiveDiagnosis<'a>>,
}

/// `--diagnose` (added in 1.7.0, experimental): the diagnosis drawn from the
/// extra probes, apart from `diagnosis` (the correlator's, from the line's
/// fields): `{"target":"…","state":"done","conclusions":[…],"gaps":[…]}`.
#[derive(Serialize)]
struct ActiveDiagnosis<'a> {
    /// The address diagnosed, without a zone, as `target_ip`.
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    target: IpAddr,
    /// `diagnosing`, `done`, or `incomplete` (the last line, when it did not
    /// conclude in time).
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    conclusions: Option<Vec<&'a Conclusion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gaps: Option<&'a [Gap]>,
}

impl<'a> ActiveDiagnosis<'a> {
    /// `None` while nothing is down. On the `last` line, a diagnosis still
    /// in progress is `incomplete`.
    fn from_state(state: &'a DiagnoseState, last: bool) -> Option<Self> {
        match state {
            DiagnoseState::Idle => None,
            DiagnoseState::Diagnosing { target } => Some(Self {
                target: *target,
                state: if last { "incomplete" } else { "diagnosing" },
                conclusions: None,
                gaps: None,
            }),
            DiagnoseState::Done { target, diagnosis } => Some(Self {
                target: *target,
                state: "done",
                conclusions: Some(
                    diagnosis
                        .conclusions
                        .iter()
                        .map(|c| &c.conclusion)
                        .collect(),
                ),
                gaps: Some(&diagnosis.gaps),
            }),
        }
    }
}

/// An auxiliary probe's latest result:
/// `{"target":"192.168.1.1","state":"online","rtt_last":0.41}`.
#[derive(Serialize)]
struct AuxJson {
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    target: IpAddr,
    /// `online` / `offline` once its hysteresis has decided, else `unknown`.
    state: &'static str,
    /// Last probe's RTT in ms; `null` when it failed.
    #[serde(serialize_with = "crate::probe::types::ser_opt_duration_ms")]
    rtt_last: Option<Duration>,
}

impl AuxJson {
    fn from_state(aux: &AuxiliaryState) -> Self {
        Self {
            target: aux.target,
            state: match aux.reachability {
                Reachability::Online => "online",
                Reachability::Offline => "offline",
                Reachability::Unknown => "unknown",
            },
            rtt_last: aux.last_rtt,
        }
    }
}

/// The JSON line for a snapshot and the auxiliary probes' state at that
/// moment (`None` where no such probe runs or it has no result yet: always
/// in batch). The diagnosis is drawn from the same state the line shows.
/// With `--diagnose`, `diagnose` is its state and whether this is the last
/// line.
///
/// # Errors
///
/// Serialization failed.
pub fn line(
    snap: &ProbeSnapshot,
    gateway: Option<&AuxiliaryState>,
    wan: Option<&AuxiliaryState>,
    diagnose: Option<(&DiagnoseState, bool)>,
) -> serde_json::Result<String> {
    let diagnosis = correlator::diagnose(&DiagInput::from_snapshot(snap, gateway, wan));
    serde_json::to_string(&JsonLine {
        snap,
        gateway: gateway.map(AuxJson::from_state),
        wan: wan.map(AuxJson::from_state),
        diagnosis,
        active_diagnosis: diagnose
            .and_then(|(state, last)| ActiveDiagnosis::from_state(state, last)),
    })
}

/// JSON view state; deduplicates on `seq` so each probe prints once.
pub struct JsonView {
    last_seq: u64,
}

impl JsonView {
    pub fn new() -> Self {
        Self { last_seq: 0 }
    }

    /// Print one JSON line if `snap.seq` advanced; otherwise a no-op.
    /// Serialization failures warn on stderr without returning an error.
    pub fn draw(
        &mut self,
        w: &mut impl Write,
        snap: &ProbeSnapshot,
        gateway: Option<&AuxiliaryState>,
        wan: Option<&AuxiliaryState>,
        diagnose: Option<(&DiagnoseState, bool)>,
    ) -> io::Result<()> {
        if snap.seq == 0 || snap.seq <= self.last_seq {
            return Ok(());
        }
        self.last_seq = snap.seq;

        // Never emit a bogus "{}" line: skip and warn if serialization fails.
        match line(snap, gateway, wan, diagnose) {
            Ok(json) => {
                writeln!(w, "{json}")?;
                w.flush()?;
            }
            Err(e) => {
                eprintln!("warning: cannot serialize snapshot: {e}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::types::TcpState;
    use crate::render::golden_icmp::replying;

    fn aux(target: &str, reachability: Reachability, rtt_ms: Option<f64>) -> AuxiliaryState {
        AuxiliaryState {
            label: "probe".into(),
            target: target.parse().unwrap(),
            reachability,
            last_rtt: rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0)),
        }
    }

    /// Nothing to add: the line is the snapshot's v1 JSON, byte for byte.
    #[test]
    fn healthy_line_is_the_snapshot_alone() {
        let mut snap = replying();
        snap.recent_loss_pct = 0.0;
        assert_eq!(
            line(&snap, None, None, None).unwrap(),
            serde_json::to_string(&snap).unwrap()
        );
    }

    /// The v1 fields come first, unchanged; then gateway, WAN and the
    /// diagnosis drawn from them.
    #[test]
    fn line_appends_aux_state_and_diagnosis() {
        let snap = replying();
        let v1 = serde_json::to_string(&snap).unwrap();
        let gw = aux("192.168.1.1", Reachability::Online, Some(0.41));
        let wan = aux("1.1.1.1", Reachability::Offline, None);
        let json = line(&snap, Some(&gw), Some(&wan), None).unwrap();
        assert_eq!(
            json,
            format!(
                "{},\"gateway\":{{\"target\":\"192.168.1.1\",\"state\":\"online\",\"rtt_last\":0.41}},\"wan\":{{\"target\":\"1.1.1.1\",\"state\":\"offline\",\"rtt_last\":null}},\"diagnosis\":[{{\"code\":\"intermittent_loss\",\"recent_loss_pct\":10.0}},{{\"code\":\"wan_degraded\"}}]}}",
                &v1[..v1.len() - 1]
            )
        );
    }

    /// A gateway still undecided reads `unknown`; a WAN without its gateway
    /// is fine (no default gateway found).
    #[test]
    fn undecided_probe_and_wan_alone() {
        let mut snap = replying();
        snap.recent_loss_pct = 0.0;
        let wan = aux("1.1.1.1", Reachability::Unknown, Some(9.5));
        let json = line(&snap, None, Some(&wan), None).unwrap();
        assert!(
            json.ends_with(
                ",\"wan\":{\"target\":\"1.1.1.1\",\"state\":\"unknown\",\"rtt_last\":9.5}}"
            ),
            "{json}"
        );
        // `net_ctx` has a `gateway` string; the probe object would follow
        // the v1 fields.
        assert!(!json.contains(",\"gateway\":{"), "{json}");
        assert!(!json.contains("\"diagnosis\""), "{json}");
    }

    /// TCP: a refusal is in the diagnosis with its port; batch lines (no
    /// auxiliary probes) carry the target's diagnosis alone.
    #[test]
    fn tcp_refusal_in_a_batch_line() {
        let mut snap = replying().with_tcp(Some(443));
        snap.recent_loss_pct = 0.0;
        snap.tcp_state = Some(TcpState::Refused);
        let json = line(&snap, None, None, None).unwrap();
        assert!(
            json.ends_with(
                ",\"tcp_state\":\"refused\",\"diagnosis\":[{\"code\":\"tcp_refused\",\"port\":443}]}"
            ),
            "{json}"
        );
    }

    fn done_state() -> DiagnoseState {
        use crate::context::dns::Family;
        use crate::diagnostics::evidence::{Reason, Role};
        use crate::diagnostics::planner::{Concluded, Diagnosis, LastHop};
        use crate::probe::trace::{Unavailable, UnreachableKind};
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let conclusions = vec![
            Conclusion::NoSource { family: Family::V4 },
            Conclusion::ReportedUnreachable {
                ttl: 2,
                from: ip("10.0.2.2"),
                kind: UnreachableKind::AdminProhibited,
            },
            Conclusion::SilentAfter {
                last: Some(LastHop {
                    ttl: 1,
                    from: vec![ip("10.0.1.1")],
                }),
                silent: 3,
            },
            Conclusion::SilentAfter {
                last: None,
                silent: 3,
            },
            Conclusion::TargetAnswersIcmp { ttl: 3 },
            Conclusion::AnswersTcp {
                port: 443,
                refused: true,
            },
            Conclusion::OtherFamilyWorks {
                family: Family::V6,
                address: ip("2001:db8::7"),
            },
            Conclusion::OtherFamilyFails {
                family: Family::V6,
                address: ip("2001:db8::7"),
            },
        ];
        let gaps = vec![
            Gap {
                role: Role::OtherFamily,
                reason: Reason::Literal,
            },
            Gap {
                role: Role::Trace,
                reason: Reason::Unavailable(Unavailable::Permission),
            },
            Gap {
                role: Role::Main,
                reason: Reason::Unknown("source check unavailable with -S/-I".into()),
            },
        ];
        DiagnoseState::Done {
            target: ip("198.51.100.7"),
            diagnosis: std::sync::Arc::new(Diagnosis {
                conclusions: conclusions
                    .into_iter()
                    .map(|conclusion| Concluded {
                        conclusion,
                        because: vec![],
                    })
                    .collect(),
                gaps,
                evidence: vec![],
            }),
        }
    }

    /// `active_diagnosis` (1.7.0): absent while nothing is down, then its
    /// state; `incomplete` only on the last line; every code and gap.
    #[test]
    fn active_diagnosis_by_state() {
        let mut snap = replying();
        snap.recent_loss_pct = 0.0;
        let v1 = serde_json::to_string(&snap).unwrap();
        let active = |state: &DiagnoseState, last: bool| -> Option<serde_json::Value> {
            let json = line(&snap, None, None, Some((state, last))).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(
                json.starts_with(&v1[..v1.len() - 1]),
                "v1 fields first: {json}"
            );
            value.get("active_diagnosis").cloned()
        };
        assert_eq!(
            line(&snap, None, None, Some((&DiagnoseState::Idle, true))).unwrap(),
            v1
        );
        let diagnosing = DiagnoseState::Diagnosing {
            target: "198.51.100.7".parse().unwrap(),
        };
        assert_eq!(
            active(&diagnosing, false),
            Some(serde_json::json!({"target": "198.51.100.7", "state": "diagnosing"}))
        );
        assert_eq!(
            active(&diagnosing, true),
            Some(serde_json::json!({"target": "198.51.100.7", "state": "incomplete"}))
        );
        assert_eq!(
            active(&done_state(), true),
            Some(serde_json::json!({
                "target": "198.51.100.7",
                "state": "done",
                "conclusions": [
                    {"code": "no_source", "family": "ipv4"},
                    {"code": "reported_unreachable", "ttl": 2, "from": "10.0.2.2", "kind": "admin_prohibited"},
                    {"code": "silent_after", "last_hop": {"ttl": 1, "from": ["10.0.1.1"]}, "silent": 3},
                    {"code": "silent_after", "last_hop": null, "silent": 3},
                    {"code": "target_answers_icmp", "ttl": 3},
                    {"code": "answers_tcp", "port": 443, "refused": true},
                    {"code": "other_family_works", "family": "ipv6", "address": "2001:db8::7"},
                    {"code": "other_family_fails", "family": "ipv6", "address": "2001:db8::7"},
                ],
                "gaps": [
                    {"about": "other_family", "reason": "literal"},
                    {"about": "trace", "reason": "unavailable", "detail": "permission"},
                    {"about": "main", "reason": "unknown", "detail": "source check unavailable with -S/-I"},
                ],
            }))
        );
    }

    /// The name's findings (1.7.0) in `diagnosis`, with their fields.
    #[test]
    fn the_names_findings_in_json() {
        use crate::probe::types::NameState;
        let mut snap = replying();
        snap.recent_loss_pct = 0.0;
        let wan = aux("1.1.1.1", Reachability::Online, Some(9.5));
        let diagnosis = |snap: &ProbeSnapshot| -> serde_json::Value {
            let json = line(snap, None, Some(&wan), None).unwrap();
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["diagnosis"].clone()
        };
        snap.name = Some(NameState::Failed { timed_out: true });
        assert_eq!(
            diagnosis(&snap),
            serde_json::json!([{"code": "name_lookup_failed", "timed_out": true}])
        );
        snap.name = Some(NameState::NoAddressOfFamily);
        assert_eq!(
            diagnosis(&snap),
            serde_json::json!([{"code": "lookup_without_family", "family": "ipv4"}])
        );
        snap.name = Some(NameState::Answered);
        assert!(
            !line(&snap, None, Some(&wan), None)
                .unwrap()
                .contains("\"diagnosis\"")
        );
    }

    /// The context change (1.7.0) in `diagnosis`: each field named and
    /// valued as in `net_ctx`.
    #[test]
    fn the_context_change_in_json() {
        use crate::context::classify::TargetClass;
        use crate::context::{ContextChange, ContextField, ContextValue};
        use crate::probe::types::RecentChange;
        let mut snap = replying();
        snap.recent_loss_pct = 0.0;
        let change = |what, from, to| ContextChange { what, from, to };
        snap.context_change = Some(RecentChange {
            changes: vec![
                change(
                    ContextField::Interface,
                    Some(ContextValue::Text("eth0".into())),
                    None,
                ),
                change(
                    ContextField::LocalIp,
                    Some(ContextValue::Text("10.0.1.2".into())),
                    None,
                ),
                change(
                    ContextField::PrefixLen,
                    Some(ContextValue::Prefix(24)),
                    None,
                ),
                change(
                    ContextField::Gateway,
                    None,
                    Some(ContextValue::Text("10.0.1.1".into())),
                ),
                change(
                    ContextField::TargetClass,
                    Some(ContextValue::Class(TargetClass::PublicNetwork)),
                    Some(ContextValue::Class(TargetClass::RoutedInternal)),
                ),
            ],
            age: Duration::from_secs(3),
        });
        let json = line(&snap, None, None, None).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["diagnosis"],
            serde_json::json!([{
                "code": "context_changed",
                "changes": [
                    {"what": "interface", "from": "eth0", "to": null},
                    {"what": "local_ip", "from": "10.0.1.2", "to": null},
                    {"what": "prefix_len", "from": 24, "to": null},
                    {"what": "gateway", "from": null, "to": "10.0.1.1"},
                    {"what": "target_class", "from": "PublicNetwork", "to": "RoutedInternal"},
                ],
                "age_s": 3
            }])
        );
    }
}
