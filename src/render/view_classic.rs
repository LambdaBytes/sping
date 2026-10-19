//! Classic `ping`-style scrolling view: one line per probe plus a final
//! summary. No raw mode, so output is safe to pipe or redirect.

use std::io::{self, Write};

use crate::probe::diagnose::DiagnoseState;
use crate::probe::types::{ProbeSnapshot, TcpState};
use crate::render::format::{diagnosis_summary, fmt_rtt, untested};

/// Classic view state; deduplicates on `seq` so each probe prints once, and
/// on the diagnosis' state so each change prints once.
pub struct ClassicView {
    last_seq: u64,
    diagnosis: DiagnoseState,
}

impl ClassicView {
    pub fn new() -> Self {
        Self {
            last_seq: 0,
            diagnosis: DiagnoseState::Idle,
        }
    }

    /// `--diagnose`: a line when a diagnosis starts (again, for a new
    /// address), and its conclusions and what it could not establish when it
    /// ends. Nothing when the target comes back.
    pub fn diagnosis(&mut self, w: &mut impl Write, state: &DiagnoseState) -> io::Result<()> {
        if *state == self.diagnosis {
            return Ok(());
        }
        let sep = crate::render::icons::sep();
        match state {
            DiagnoseState::Diagnosing { target } => {
                writeln!(w, "--- diagnosing why {target} does not answer")?;
            }
            DiagnoseState::Done { .. } => {
                if let Some(summary) = diagnosis_summary(state, sep) {
                    writeln!(w, "--- {summary}")?;
                }
                if let Some(untested) = untested(state, sep) {
                    writeln!(w, "--- untested: {untested}")?;
                }
            }
            DiagnoseState::Idle => {}
        }
        w.flush()?;
        self.diagnosis = state.clone();
        Ok(())
    }

    /// Print the latest probe if `snap.seq` advanced; otherwise a no-op.
    /// Propagates `BrokenPipe` so the caller can exit when a pipe closes.
    pub fn draw(&mut self, w: &mut impl Write, snap: &ProbeSnapshot) -> io::Result<()> {
        if snap.seq == 0 || snap.seq <= self.last_seq {
            return Ok(());
        }
        self.last_seq = snap.seq;

        match snap.rtt_last {
            // TCP: which endpoint answered, and how.
            Some(rtt) if snap.port.is_some() => {
                let endpoint = std::net::SocketAddr::new(snap.target_ip, snap.port.unwrap_or(0));
                let verb = if snap.tcp_state == Some(TcpState::Refused) {
                    "Refused by"
                } else {
                    "Connected to"
                };
                writeln!(
                    w,
                    "{verb} {endpoint}: seq={} time={}",
                    snap.seq,
                    fmt_rtt(rtt)
                )?;
            }
            Some(rtt) => match snap.ttl {
                Some(ttl) if ttl > 0 => {
                    writeln!(
                        w,
                        "Reply from {}: seq={} ttl={} time={}",
                        snap.target_ip,
                        snap.seq,
                        ttl,
                        fmt_rtt(rtt),
                    )?;
                }
                _ => {
                    writeln!(
                        w,
                        "Reply from {}: seq={} time={}",
                        snap.target_ip,
                        snap.seq,
                        fmt_rtt(rtt),
                    )?;
                }
            },
            None => match &snap.last_error {
                // Not a lost reply: the probe itself failed (e.g. the OS
                // refused to send). Say why instead of calling it a timeout.
                Some(error) => writeln!(w, "Probe error for seq={}: {error}", snap.seq)?,
                None => writeln!(w, "Request timeout for seq={}", snap.seq,)?,
            },
        }
        w.flush()?;
        Ok(())
    }

    /// Print the final summary at shutdown; the RTT line is omitted when no
    /// replies were received.
    pub fn summary(&self, w: &mut impl Write, snap: &ProbeSnapshot) -> io::Result<()> {
        writeln!(w)?;
        if let Some(port) = snap.port {
            // TCP counts connects and their answers, not packets.
            writeln!(w, "--- {} tcp/{port} statistics ---", snap.target_host)?;
            writeln!(
                w,
                "{} connects, {} answered ({} refused), {:.1}% loss",
                snap.sent,
                snap.received,
                snap.refused.unwrap_or(0),
                snap.loss_pct,
            )?;
        } else {
            writeln!(w, "--- {} ping statistics ---", snap.target_host,)?;
            writeln!(
                w,
                "{} packets transmitted, {} received, {:.1}% packet loss",
                snap.sent, snap.received, snap.loss_pct,
            )?;
        }
        if let (Some(min), Some(avg), Some(max)) = (snap.rtt_min, snap.rtt_avg, snap.rtt_max) {
            writeln!(
                w,
                "rtt min/avg/max/mdev = {}/{}/{}/{}",
                fmt_rtt(min),
                fmt_rtt(avg),
                fmt_rtt(max),
                crate::render::format::fmt_rtt_opt(snap.mdev),
            )?;
        }
        w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lost_probe(last_error: Option<&str>) -> ProbeSnapshot {
        let target = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let mut snap = ProbeSnapshot::empty("192.0.2.1".into(), target, None, None);
        snap.seq = 1;
        snap.sent = 1;
        snap.lost = 1;
        snap.last_error = last_error.map(String::from);
        snap
    }

    fn drawn(snap: &ProbeSnapshot) -> String {
        let mut out = Vec::new();
        ClassicView::new().draw(&mut out, snap).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn lost_reply_is_reported_as_timeout() {
        assert_eq!(drawn(&lost_probe(None)), "Request timeout for seq=1\n");
    }

    #[test]
    fn failed_probe_reports_its_error_not_a_timeout() {
        let snap = lost_probe(Some("send failed: No route to host (os error 65)"));
        assert_eq!(
            drawn(&snap),
            "Probe error for seq=1: send failed: No route to host (os error 65)\n"
        );
    }

    /// `--diagnose`: a line when a diagnosis starts and its result when it
    /// ends, each once; nothing when the target comes back.
    #[test]
    fn diagnosis_lines_once_per_change() {
        use crate::diagnostics::evidence::{Gap, Reason, Role};
        use crate::diagnostics::planner::{Concluded, Conclusion, Diagnosis};
        let target = "198.51.100.7".parse().unwrap();
        let diagnosing = DiagnoseState::Diagnosing { target };
        let done = DiagnoseState::Done {
            target,
            diagnosis: std::sync::Arc::new(Diagnosis {
                conclusions: vec![Concluded {
                    conclusion: Conclusion::TargetAnswersIcmp { ttl: 3 },
                    because: vec![],
                }],
                gaps: vec![Gap {
                    role: Role::OtherFamily,
                    reason: Reason::Literal,
                }],
                evidence: vec![],
            }),
        };
        let mut view = ClassicView::new();
        let mut out = Vec::new();
        for state in [
            &DiagnoseState::Idle,
            &diagnosing,
            &diagnosing,
            &done,
            &done,
            &DiagnoseState::Idle,
            &DiagnoseState::Diagnosing {
                target: "198.51.100.8".parse().unwrap(),
            },
        ] {
            view.diagnosis(&mut out, state).unwrap();
        }
        let expected = [
            "--- diagnosing why 198.51.100.7 does not answer",
            "--- diagnosis: target answers the trace at hop 3",
            "--- untested: other family not tried (address given)",
            "--- diagnosing why 198.51.100.8 does not answer",
        ];
        assert_eq!(String::from_utf8(out).unwrap(), expected.join("\n") + "\n");
    }
}
