//! Multi-target dashboard: one row per target, redrawn in place. The frame
//! is staged in a `Vec<u8>` and emitted with a single `write_all`. Requires
//! raw mode. Hostnames are truncated by characters, not bytes, so multibyte
//! names cannot split a UTF-8 sequence.

use std::io::{self, Write};

use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::{cursor, queue, terminal};

use crate::context::dns::is_literal;
use crate::probe::types::ProbeSnapshot;
use crate::render::format::{Placement, fmt_loss, fmt_rtt_opt};
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

/// Draw one frame where `place` says: first moving the cursor up over the
/// lines of the previous frame. `None` entries render as `waiting...` rows.
/// Returns the line count to pass back next call.
pub fn draw_table(
    out: &mut impl Write,
    snapshots: &[Option<ProbeSnapshot>],
    spinner_idx: usize,
    place: Placement,
) -> io::Result<u16> {
    let spinner = icons::spinner();
    let spin = spinner[spinner_idx % spinner.len()];
    let use_color = icons::use_color();
    let dash = icons::dash();
    let mut buf = Vec::with_capacity(2048);
    let w = &mut buf;
    let mut lines: u16 = 0;

    // TCP mode: one port for every target.
    let tcp_port = snapshots.iter().flatten().find_map(|s| s.port);
    write!(w, "sping multi-target  ")?;
    if let Some(port) = tcp_port {
        write!(w, "tcp/{port}  ")?;
    }
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
        "Target",
        "RTT",
        "Avg",
        "Loss",
        "Qual",
        "Trend",
        if tcp_port.is_some() { "TCP" } else { "TTL" },
        "Hops"
    )?;
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    write!(w, "{}", icons::hline(79))?;
    queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
    writeln!(w)?;
    lines += 1;

    // In a terminal too short for every target, the rows left under the
    // lines above go to the first ones, and the last row says how many are
    // not shown: a frame cut blindly would hide them without a word. Under
    // six rows the lines above do not fit either, and the count is cut with
    // them (`fit_rows`).
    let shown = match place.max_lines() {
        Some(max) if usize::from(lines) + snapshots.len() > max => {
            max.saturating_sub(usize::from(lines) + 1)
        }
        _ => snapshots.len(),
    };

    for snap_opt in snapshots.iter().take(shown) {
        let Some(snap) = snap_opt else {
            write!(w, "{:<20}  waiting...", "?")?;
            queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
            writeln!(w)?;
            lines += 1;
            continue;
        };

        // An address given as the target (with its zone, if any) is shown
        // once; a name with the address it resolved to.
        let name = if is_literal(&snap.target_host) {
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

        // TTL with OS hint; in TCP, how the last connect ended.
        let ttl_str = match (snap.port, snap.ttl) {
            (Some(_), _) => snap
                .tcp_state
                .map_or_else(|| dash.into(), |state| state.to_string()),
            (None, Some(t)) if t > 0 => match guess_os(t) {
                Some(os) => {
                    let short_os = match os {
                        "Unix-like" => "Unix",
                        "Windows" => "Win",
                        "network" => "Net",
                        _ => os,
                    };
                    format!("{t}({short_os})")
                }
                None => t.to_string(),
            },
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

    if shown < snapshots.len() {
        let hidden = snapshots.len() - shown;
        write!(
            w,
            "{} {hidden} more (terminal too short)",
            icons::ellipsis()
        )?;
        queue!(w, terminal::Clear(terminal::ClearType::UntilNewLine))?;
        writeln!(w)?;
        lines += 1;
    }

    let (buf, lines) = crate::render::format::fit_rows(&buf, lines, place);
    let buf = crate::render::format::stage_frame(buf, place.width)?;
    let mut final_buf = Vec::with_capacity(buf.len() + 16);
    if place.lines_before > 0 {
        queue!(
            final_buf,
            cursor::MoveUp(place.lines_before),
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

    /// The table of 20 targets (24 lines) on a terminal of 100 columns and
    /// `rows` rows: the lines it says it drew, and its text.
    fn table_of_20(width: Option<usize>, rows: usize) -> (u16, String) {
        let place = Placement {
            width,
            rows,
            ..Placement::default()
        };
        let mut out = Vec::new();
        let lines = draw_table(&mut out, &vec![None; 20], 0, place).unwrap();
        (lines, crate::render::golden_icmp::visible(&out))
    }

    #[test]
    fn a_table_too_tall_for_the_terminal_says_how_many_targets_it_hides() {
        // 12 rows: the four lines above, six targets and the count of the rest.
        let (lines, text) = table_of_20(Some(100), 12);
        assert_eq!(lines, 11);
        assert_eq!(text.lines().count(), 11);
        assert_eq!(text.matches("waiting...").count(), 6);
        assert_eq!(text.lines().last(), Some("… 14 more (terminal too short)"));

        // One row short of them all.
        let (lines, text) = table_of_20(Some(100), 24);
        assert_eq!(lines, 23);
        assert_eq!(text.matches("waiting...").count(), 18);
        assert_eq!(text.lines().last(), Some("… 2 more (terminal too short)"));

        // Never more lines than rows to spare, down to none.
        for rows in 1..=6 {
            let (lines, text) = table_of_20(Some(100), rows);
            assert_eq!(usize::from(lines), rows - 1);
            assert_eq!(text.lines().count(), rows - 1);
        }
        let (_, text) = table_of_20(Some(100), 6);
        assert_eq!(text.lines().last(), Some("… 20 more (terminal too short)"));
        // Under that the heading itself is cut, and the count with it.
        let (_, text) = table_of_20(Some(100), 5);
        assert!(!text.contains("more"), "{text}");
    }

    #[test]
    fn a_table_that_fits_or_cannot_tell_shows_every_target() {
        // Rows for all, a terminal of unknown height, and not a terminal.
        for (width, rows) in [(Some(100), 25), (Some(100), 0), (None, 12)] {
            let (lines, text) = table_of_20(width, rows);
            assert_eq!(lines, 24, "{width:?} {rows}");
            assert_eq!(text.matches("waiting...").count(), 20);
            assert!(!text.contains("more"), "{text}");
        }
    }

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
