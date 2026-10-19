//! Compact single-target TUI view: a fixed block of lines redrawn in place.
//! The frame is staged in a `Vec<u8>` and emitted with a single `write_all`
//! so partial escape sequences never reach the terminal. Requires raw mode;
//! newlines are rewritten to `\r\n` before output.

use std::io::{self, Write};

use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::{cursor, queue, terminal};

use crate::diagnostics::correlator::{self, DiagInput};
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::diagnose::DiagnoseState;
use crate::probe::pulse::PulseScaler;
use crate::probe::quality::Trend;
use crate::probe::types::ProbeSnapshot;
use crate::render::format::{
    events, fmt_elapsed, fmt_loss, fmt_rtt, fmt_rtt_opt, fmt_source, tcp_outcome,
};
use crate::render::icons;

const VAL: Color = Color::DarkYellow;

/// Draw one frame, first moving the cursor up over the `lines_before` lines
/// from the previous frame. Returns the line count to pass back next call.
pub fn draw_inline(
    out: &mut impl Write,
    snap: &ProbeSnapshot,
    gw: Option<&AuxiliaryState>,
    wan: Option<&AuxiliaryState>,
    diagnose: Option<&DiagnoseState>,
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
    if let Some(port) = snap.port {
        write!(w, " tcp/{port}")?;
    }
    // No source address: no interface either (the Context line says so).
    if let Some(ctx) = &snap.net_ctx
        && !ctx.local_ip.is_unspecified()
    {
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
        write!(w, "Context    {}", fmt_source(ctx, snap.target_ip, sep))?;
        let gw_ind = gw
            .map(|g| icons::reach_glyph(g.reachability).to_string())
            .unwrap_or_else(|| "?".into());
        write!(w, "{sep}gw {gw_ind}")?;
        let wan_ind = wan
            .map(|w| icons::reach_glyph(w.reachability).to_string())
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
            crate::probe::quality::QualityGrade::A => "excellent",
            crate::probe::quality::QualityGrade::B => "good",
            crate::probe::quality::QualityGrade::C => "fair",
            crate::probe::quality::QualityGrade::D => "poor",
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

    let input = DiagInput::from_snapshot(snap, gw, wan);
    let mut events = events(&correlator::diagnose(&input), diagnose, sep);
    // How the last TCP connect ended, or the probe error, goes first: it
    // explains what the diagnostics describe.
    if let Some(outcome) = tcp_outcome(snap, sep) {
        events.insert(0, outcome);
    }
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

/// Hint at the kind of system that answered, only while the reply TTL is
/// still one of the usual initial values: 64 (Unix-like: Linux, macOS, the
/// BSDs), 128 (Windows), 255 (network gear). A heuristic: an initial TTL
/// can be configured, and once a reply has crossed routers its TTL no longer
/// says which system sent it (8.8.8.8 answers with 112, from no Windows
/// host), so any other TTL gives `None`.
pub fn guess_os(ttl: u8) -> Option<&'static str> {
    match ttl {
        64 => Some("Unix-like"),
        128 => Some("Windows"),
        255 => Some("network"),
        _ => None,
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
    fn test_guess_os_initial_ttls() {
        assert_eq!(guess_os(64), Some("Unix-like"));
        assert_eq!(guess_os(128), Some("Windows"));
        assert_eq!(guess_os(255), Some("network"));
    }

    /// A TTL lowered by routers gives no hint: 112 is what 8.8.8.8 answers
    /// with, from no Windows host.
    #[test]
    fn test_guess_os_none_after_routers() {
        for ttl in [0, 1, 52, 63, 65, 112, 127, 250, 254] {
            assert_eq!(guess_os(ttl), None, "ttl {ttl}");
        }
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
        draw_inline(&mut out, &snap, None, None, None, 0, 0).unwrap();
        let frame = String::from_utf8(out).unwrap();
        assert!(
            frame.contains("Events     send failed: No route to host (os error 65)"),
            "{frame}"
        );

        // Without an error the line carries diagnostics only.
        snap.last_error = None;
        let mut out = Vec::new();
        draw_inline(&mut out, &snap, None, None, None, 0, 0).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("send failed"));
    }
}
