//! Classic `ping`-style scrolling view: one line per probe plus a final
//! summary. No raw mode, so output is safe to pipe or redirect.

use std::io::{self, Write};

use crate::probe::types::{ProbeSnapshot, TcpState};
use crate::render::format::fmt_rtt;

/// Classic view state; deduplicates on `seq` so each probe prints once.
pub struct ClassicView {
    last_seq: u64,
}

impl ClassicView {
    pub fn new() -> Self {
        Self { last_seq: 0 }
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
}
