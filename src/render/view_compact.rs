//! Compact single-target TUI view: a fixed block of lines redrawn in place.
//! The frame is staged in a `Vec<u8>` and emitted with a single `write_all`
//! so partial escape sequences never reach the terminal. Requires raw mode;
//! newlines are rewritten to `\r\n` before output.

use std::io::{self, Write};

use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::{cursor, queue, terminal};

use crate::diagnostics::correlator::{self, DiagInput};
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::pulse::PulseScaler;
use crate::probe::quality::Trend;
use crate::probe::types::ProbeSnapshot;
use crate::render::format::{fmt_elapsed, fmt_loss, fmt_rtt, fmt_rtt_opt};
use crate::render::icons;

const VAL: Color = Color::DarkYellow;

/// Draw one frame, first moving the cursor up over the `lines_before` lines
/// from the previous frame. Returns the line count to pass back next call.
pub fn draw_inline(
    out: &mut impl Write,
    snap: &ProbeSnapshot,
    gw: Option<&AuxiliaryState>,
    wan: Option<&AuxiliaryState>,
    spinner_idx: usize,
    lines_before: u16,
) -> io::Result<u16> {
    let use_color = icons::use_color();
    let sep = icons::sep();

    // Buffer all output to minimize escape sequence leakage in scrollback
    let mut buf = Vec::with_capacity(2048);
    let w = &mut buf;
    let spinner = icons::spinner();
    let spin = spinner[spinner_idx % spinner.len()];
    let mut lines: u16 = 0;

    write!(
        w,
        "sping {host} ({ip})",
        host = snap.target_host,
        ip = snap.target_ip
    )?;
    if let Some(ctx) = &snap.net_ctx {
        write!(w, " via {}", ctx.interface)?;
    }
    write!(w, "  ")?;
    if use_color {
        queue!(w, SetForegroundColor(VAL))?;
    }
    write!(w, "{spin}")?;
    if use_color {
        queue!(w, ResetColor)?;
    }
    write!(w, " probing...")?;
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    queue!(w, terminal::Clear(terminal::ClearType::CurrentLine))?;
    writeln!(w)?;
    lines += 1;

    write!(w, "Pulse      ")?;
    if use_color {
        PulseScaler::render_wave(w, &snap.pulse)?;
    } else {
        write!(w, "{}", PulseScaler::render(&snap.pulse))?;
    }
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    write!(w, "Latency    now ")?;
    val(w, &fmt_rtt_opt(snap.rtt_last), use_color)?;
    write!(w, "{sep}avg ")?;
    val(w, &fmt_rtt_opt(snap.rtt_avg), use_color)?;
    write!(w, "{sep}min ")?;
    val(w, &fmt_rtt_opt(snap.rtt_min), use_color)?;
    write!(w, "{sep}max ")?;
    val(w, &fmt_rtt_opt(snap.rtt_max), use_color)?;
    write!(w, "{sep}jitter ")?;
    val(w, &fmt_rtt_opt(snap.jitter), use_color)?;
    if let Some(dns) = snap.dns_time {
        write!(w, "{sep}dns ")?;
        val(w, &fmt_rtt(dns), use_color)?;
    }
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    write!(w, "Status     ")?;
    let status = if snap.received > 0 {
        "Reachable"
    } else if snap.sent > 0 {
        "No replies"
    } else {
        "Starting"
    };
    write!(w, "{status}{sep}loss ")?;
    val(w, &fmt_loss(snap.loss_pct), use_color)?;
    write!(w, "{sep}sent ")?;
    val(w, &snap.sent.to_string(), use_color)?;
    write!(w, "{sep}recv ")?;
    val(w, &snap.received.to_string(), use_color)?;
    if let Some(dur) = snap.outage_duration {
        write!(w, "{sep}outage ")?;
        val(w, &fmt_elapsed(dur), use_color)?;
    }
    if let Some(ttl) = snap.ttl
        && ttl > 0
    {
        write!(w, "{sep}ttl ")?;
        val(w, &ttl.to_string(), use_color)?;
        if let Some(os) = guess_os(ttl) {
            write!(w, " ({os})")?;
        }
        let hops = estimate_hops(ttl);
        if hops > 0 {
            write!(w, "{sep}hops ")?;
            val(w, &format!("~{hops}"), use_color)?;
        }
    }
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    if let Some(ctx) = &snap.net_ctx {
        write!(
            w,
            "Context    if {}{sep}{}/{}",
            ctx.interface, ctx.local_ip, ctx.prefix_len
        )?;
        let gw_ind = gw
            .map(|g| format!("{}", g.reachability))
            .unwrap_or_else(|| "?".into());
        write!(w, "{sep}gw {gw_ind}")?;
        let wan_ind = wan
            .map(|w| format!("{}", w.reachability))
            .unwrap_or_else(|| "?".into());
        write!(w, "{sep}wan {wan_ind}{sep}{}", ctx.target_class)?;
        queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
        writeln!(w)?;
        lines += 1;
    }

    if let Some(q) = &snap.quality {
        write!(w, "Quality    ")?;
        let grade_letter = match q {
            crate::probe::quality::QualityGrade::A => "A",
            crate::probe::quality::QualityGrade::B => "B",
            crate::probe::quality::QualityGrade::C => "C",
            crate::probe::quality::QualityGrade::D => "D",
        };
        val(w, grade_letter, use_color)?;
        if let Some(score) = snap.quality_score {
            write!(w, " (")?;
            val(w, &score.to_string(), use_color)?;
            write!(w, ")")?;
        }
        let label = match q {
            crate::probe::quality::QualityGrade::A => "stable",
            crate::probe::quality::QualityGrade::B => "minor jitter",
            crate::probe::quality::QualityGrade::C => "unstable",
            crate::probe::quality::QualityGrade::D => "degraded",
        };
        write!(w, "{sep}{label}")?;
        if let Some(trend) = &snap.trend
            && *trend != Trend::Stable
        {
            write!(w, "{sep}{trend}")?;
        }
        if snap.spike_guard {
            write!(w, "{sep}spike guard on")?;
        }
    }
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    let input = DiagInput {
        target_reachable: snap.reachability == crate::diagnostics::health::Reachability::Online,
        target_total_loss: snap.reachability == crate::diagnostics::health::Reachability::Offline,
        loss_pct: snap.recent_loss_pct,
        quality: snap.quality,
        gateway: gw,
        wan,
        outage_duration: snap.outage_duration,
        recovery_duration: snap.recovery_duration,
        last_spike_rtt: snap.last_spike_rtt,
        spike_guard: snap.spike_guard,
        jitter: snap.jitter,
        rtt_avg: snap.rtt_avg,
    };
    let mut events = correlator::diagnose(&input);
    // A probe error goes first: it explains the loss the diagnostics describe.
    if let Some(error) = &snap.last_error {
        events.insert(0, error.clone());
    }
    if !events.is_empty() {
        write!(w, "Events     {}", events.join(sep))?;
    }
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    // Keep every line on one row, fix newlines for raw mode (\n → \r\n) and
    // prepend cursor repositioning
    let buf = crate::render::format::stage_frame(&buf, crate::render::format::term_width())?;
    let mut final_buf = Vec::with_capacity(buf.len() + 16);
    if lines_before > 0 {
        queue!(
            final_buf,
            cursor::MoveUp(lines_before),
            cursor::MoveToColumn(0)
        )?;
    }
    final_buf.extend_from_slice(&buf);
    out.write_all(&final_buf)?;
    out.flush()?;

    Ok(lines)
}

fn val(w: &mut impl Write, s: &str, color: bool) -> io::Result<()> {
    if color {
        queue!(w, SetForegroundColor(VAL))?;
    }
    write!(w, "{s}")?;
    if color {
        queue!(w, ResetColor)?;
    }
    Ok(())
}

/// Guess the OS family from a reply TTL via the common initial TTLs:
/// 64 (Linux/Unix), 128 (Windows), 255 (network gear). `None` for TTL 0.
pub fn guess_os(ttl: u8) -> Option<&'static str> {
    match ttl {
        0 => None,
        1..=64 => Some("Linux"),
        65..=128 => Some("Windows"),
        129..=255 => Some("network"),
    }
}

/// Estimate hop count as the distance below the nearest initial TTL
/// (64, 128, or 255). 0 for TTL 0.
pub fn estimate_hops(ttl: u8) -> u8 {
    match ttl {
        0 => 0,
        1..=64 => 64 - ttl,
        65..=128 => 128 - ttl,
        129..=255 => 255 - ttl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_os_linux() {
        assert_eq!(guess_os(64), Some("Linux"));
        assert_eq!(guess_os(52), Some("Linux"));
        assert_eq!(guess_os(1), Some("Linux"));
    }

    #[test]
    fn test_guess_os_windows() {
        assert_eq!(guess_os(128), Some("Windows"));
        assert_eq!(guess_os(116), Some("Windows"));
        assert_eq!(guess_os(65), Some("Windows"));
    }

    #[test]
    fn test_guess_os_network() {
        assert_eq!(guess_os(255), Some("network"));
        assert_eq!(guess_os(250), Some("network"));
    }

    #[test]
    fn test_guess_os_zero() {
        assert_eq!(guess_os(0), None);
    }

    #[test]
    fn test_estimate_hops() {
        assert_eq!(estimate_hops(64), 0); // same subnet Linux
        assert_eq!(estimate_hops(52), 12); // 12 hops Linux
        assert_eq!(estimate_hops(128), 0); // same subnet Windows
        assert_eq!(estimate_hops(116), 12); // 12 hops Windows
        assert_eq!(estimate_hops(255), 0); // router
        assert_eq!(estimate_hops(0), 0);
    }

    #[test]
    fn probe_error_leads_the_events_line() {
        let target = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let mut snap = ProbeSnapshot::empty("192.0.2.1".into(), target, None, None);
        snap.sent = 1;
        snap.lost = 1;
        snap.last_error = Some("send failed: No route to host (os error 65)".into());

        let mut out = Vec::new();
        draw_inline(&mut out, &snap, None, None, 0, 0).unwrap();
        let frame = String::from_utf8(out).unwrap();
        assert!(
            frame.contains("Events     send failed: No route to host (os error 65)"),
            "{frame}"
        );

        // Without an error the line carries diagnostics only.
        snap.last_error = None;
        let mut out = Vec::new();
        draw_inline(&mut out, &snap, None, None, 0, 0).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("send failed"));
    }
}
