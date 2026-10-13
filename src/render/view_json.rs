//! NDJSON view: one JSON object per probe, one per line. The output schema
//! is frozen — see `JSON_CONTRACT.md` before changing any field. No raw
//! mode, so output is safe to pipe.

use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::diagnostics::correlator::{self, DiagInput, Finding};
use crate::diagnostics::health::Reachability;
use crate::probe::auxiliary::AuxiliaryState;
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
///
/// # Errors
///
/// Serialization failed.
pub fn line(
    snap: &ProbeSnapshot,
    gateway: Option<&AuxiliaryState>,
    wan: Option<&AuxiliaryState>,
) -> serde_json::Result<String> {
    let diagnosis = correlator::diagnose(&DiagInput::from_snapshot(snap, gateway, wan));
    serde_json::to_string(&JsonLine {
        snap,
        gateway: gateway.map(AuxJson::from_state),
        wan: wan.map(AuxJson::from_state),
        diagnosis,
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
    ) -> io::Result<()> {
        if snap.seq == 0 || snap.seq <= self.last_seq {
            return Ok(());
        }
        self.last_seq = snap.seq;

        // Never emit a bogus "{}" line: skip and warn if serialization fails.
        match line(snap, gateway, wan) {
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
            line(&snap, None, None).unwrap(),
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
        let json = line(&snap, Some(&gw), Some(&wan)).unwrap();
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
        let json = line(&snap, None, Some(&wan)).unwrap();
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
        let json = line(&snap, None, None).unwrap();
        assert!(
            json.ends_with(
                ",\"tcp_state\":\"refused\",\"diagnosis\":[{\"code\":\"tcp_refused\",\"port\":443}]}"
            ),
            "{json}"
        );
    }
}
