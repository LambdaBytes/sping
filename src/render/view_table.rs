//! Multi-target dashboard: one row per target, redrawn in place. The frame
//! is staged in a `Vec<u8>` and emitted with a single `write_all`. Requires
//! raw mode. Hostnames are truncated by characters, not bytes, so multibyte
//! names cannot split a UTF-8 sequence.

use std::io::{self, Write};

use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::{cursor, queue, terminal};

use crate::probe::types::ProbeSnapshot;
use crate::render::format::{fmt_loss, fmt_rtt_opt};
use crate::render::icons;
use crate::render::view_compact::{estimate_hops, guess_os};

const VAL: Color = Color::DarkYellow;

/// Truncate by characters (not bytes) so multibyte hostnames can't panic.
fn truncate_name(name: &str, max: usize) -> String {
    if name.chars().count() <= max {
        return name.to_string();
    }
    let mut out: String = name.chars().take(max.saturating_sub(1)).collect();
    out.push(icons::ellipsis());
    out
}

/// Draw one frame, first moving the cursor up over the `lines_before` lines
/// from the previous frame. `None` entries render as `waiting...` rows.
/// Returns the line count to pass back next call.
pub fn draw_table(
    out: &mut impl Write,
    snapshots: &[Option<ProbeSnapshot>],
    spinner_idx: usize,
    lines_before: u16,
) -> io::Result<u16> {
    let spinner = icons::spinner();
    let spin = spinner[spinner_idx % spinner.len()];
    let use_color = icons::use_color();
    let dash = icons::dash();
    let mut buf = Vec::with_capacity(2048);
    let w = &mut buf;
    let mut lines: u16 = 0;

    write!(w, "sping multi-target  ")?;
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

    write!(
        w,
        "{:<20}  {:>9}  {:>9}  {:>5}  {:>6}  {:>9}  {:>9}  {:>4}",
        "Target", "RTT", "Avg", "Loss", "Qual", "Trend", "TTL", "Hops"
    )?;
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    write!(w, "{}", icons::hline(79))?;
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    for snap_opt in snapshots {
        let Some(snap) = snap_opt else {
            write!(w, "{:<20}  waiting...", "?")?;
            queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
            writeln!(w)?;
            lines += 1;
            continue;
        };

        let name = if snap.target_host == snap.target_ip.to_string() {
            snap.target_host.clone()
        } else {
            format!("{} ({})", snap.target_host, snap.target_ip)
        };
        let name_display = truncate_name(&name, 20);

        write!(w, "{:<20}  ", name_display)?;

        if use_color {
            queue!(w, SetForegroundColor(VAL))?;
        }
        write!(w, "{:>9}", fmt_rtt_opt(snap.rtt_last))?;
        if use_color {
            queue!(w, ResetColor)?;
        }

        write!(w, "  ")?;

        if use_color {
            queue!(w, SetForegroundColor(VAL))?;
        }
        write!(w, "{:>9}", fmt_rtt_opt(snap.rtt_avg))?;
        if use_color {
            queue!(w, ResetColor)?;
        }

        write!(w, "  ")?;

        if use_color {
            queue!(w, SetForegroundColor(VAL))?;
        }
        write!(w, "{:>5}", fmt_loss(snap.loss_pct))?;
        if use_color {
            queue!(w, ResetColor)?;
        }

        write!(w, "  ")?;

        // Quality formatted compactly, e.g. "A100" or "B80".
        let q_str = match (&snap.quality, snap.quality_score) {
            (Some(g), Some(s)) => {
                let letter = match g {
                    crate::probe::quality::QualityGrade::A => "A",
                    crate::probe::quality::QualityGrade::B => "B",
                    crate::probe::quality::QualityGrade::C => "C",
                    crate::probe::quality::QualityGrade::D => "D",
                };
                format!("{letter}{s}")
            }
            _ => dash.into(),
        };
        write!(w, "{:>6}", q_str)?;

        write!(w, "  ")?;

        let trend_str = snap
            .trend
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| dash.into());
        write!(w, "{:>9}", trend_str)?;

        write!(w, "  ")?;

        // TTL with OS hint.
        let ttl_str = match snap.ttl {
            Some(t) if t > 0 => {
                let os = guess_os(t).unwrap_or("?");
                let short_os = match os {
                    "Linux" => "Lin",
                    "Windows" => "Win",
                    "network" => "Net",
                    _ => os,
                };
                format!("{t}({short_os})")
            }
            _ => dash.into(),
        };
        write!(w, "{:>9}", ttl_str)?;

        write!(w, "  ")?;

        let hops_str = match snap.ttl {
            Some(t) if t > 0 => format!("~{}", estimate_hops(t)),
            _ => dash.into(),
        };
        write!(w, "{:>4}", hops_str)?;

        queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
        writeln!(w)?;
        lines += 1;
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_name_untouched() {
        assert_eq!(truncate_name("8.8.8.8", 20), "8.8.8.8");
    }

    #[test]
    fn test_truncate_multibyte_no_panic() {
        // 'ü' at the byte-19 boundary used to panic with byte slicing.
        let name = "münchen-router-très-long.example.com";
        let out = truncate_name(name, 20);
        assert_eq!(out.chars().count(), 20);
    }

    #[test]
    fn test_truncate_exact_limit() {
        let name = "a".repeat(20);
        assert_eq!(truncate_name(&name, 20), name);
    }
}
