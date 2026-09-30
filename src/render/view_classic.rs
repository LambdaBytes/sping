//! Classic `ping`-style scrolling view: one line per probe plus a final
//! summary. No raw mode, so output is safe to pipe or redirect.

use std::io::{self, Write};

use crate::probe::types::ProbeSnapshot;
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
            None => {
                writeln!(w, "Request timeout for seq={}", snap.seq,)?;
            }
        }
        w.flush()?;
        Ok(())
    }

    /// Print the final summary at shutdown; the RTT line is omitted when no
    /// replies were received.
    pub fn summary(&self, w: &mut impl Write, snap: &ProbeSnapshot) -> io::Result<()> {
        writeln!(w)?;
        writeln!(w, "--- {} ping statistics ---", snap.target_host,)?;
        writeln!(
            w,
            "{} packets transmitted, {} received, {:.1}% packet loss",
            snap.sent, snap.received, snap.loss_pct,
        )?;
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
