//! Value formatters shared by all views plus the `\n` → `\r\n` rewrite
//! required for raw-mode output.

use std::io::IsTerminal;
use std::time::Duration;

/// Format a `Duration` as ms ("23.4 ms"), switching to seconds at or above
/// 1000 ms. Precision decreases with magnitude (2, 1, then 0 decimals).
pub fn fmt_rtt(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms >= 1000.0 {
        format!("{:.2} s", ms / 1000.0)
    } else if ms >= 100.0 {
        format!("{:.0} ms", ms)
    } else if ms >= 10.0 {
        format!("{:.1} ms", ms)
    } else {
        format!("{:.2} ms", ms)
    }
}

/// Format an optional `Duration`, using the charset dash placeholder for `None`.
pub fn fmt_rtt_opt(d: Option<Duration>) -> String {
    match d {
        Some(d) => fmt_rtt(d),
        None => crate::render::icons::dash().into(),
    }
}

/// Format a loss percentage: "0%" for zero, no decimals at/above 10%, one below.
pub fn fmt_loss(pct: f64) -> String {
    if pct == 0.0 {
        "0%".into()
    } else if pct >= 10.0 {
        format!("{:.0}%", pct)
    } else {
        format!("{:.1}%", pct)
    }
}

/// Format an outage/elapsed duration as HH:MM:SS or MM:SS.
pub fn fmt_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// Rewrite `\n` as `\r\n`. Raw mode disables the terminal's output newline
/// translation (ONLCR), so a bare `\n` moves down without returning the
/// cursor to column 0.
pub fn fix_raw_newlines(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len() + 64);
    for &b in buf {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// Width in columns of the terminal a frame is written to: `None` when stdout
/// is not a terminal (the size query would then answer for the controlling
/// terminal, and redirected output must stay untouched), `Some(0)` for a
/// terminal that does not report its width, `Some(cols)` otherwise.
pub fn term_width() -> Option<usize> {
    if !std::io::stdout().is_terminal() {
        return None;
    }
    Some(crossterm::terminal::size().map_or(0, |(cols, _)| cols as usize))
}

/// Turn a staged frame into the bytes written to a raw-mode terminal of the
/// given [`term_width`]: every line cut to fit ([`fit_lines`]), newlines
/// rewritten ([`fix_raw_newlines`]), and the frame drawn with the terminal's
/// automatic line wrap switched off.
///
/// The views redraw in place by moving the cursor up one row per line, so a
/// line must never take two rows. `fit_lines` sees to that for every
/// character whose width it judges right, but some widths depend on the
/// terminal; with wrap off, a misjudged line is clipped at the margin instead
/// of wrapping. That protection does not need the width, so a terminal that
/// does not report one (`Some(0)`) still gets it, only without the cut.
/// `None` (stdout is not a terminal) cuts nothing and adds no sequences.
///
/// # Errors
///
/// Propagates a failure to queue the wrap commands.
pub fn stage_frame(buf: &[u8], width: Option<usize>) -> std::io::Result<Vec<u8>> {
    let Some(cols) = width else {
        return Ok(fix_raw_newlines(buf));
    };
    let body = fix_raw_newlines(&fit_lines(buf, cols));
    let mut out = Vec::with_capacity(body.len() + 16);
    crossterm::queue!(out, crossterm::terminal::DisableLineWrap)?;
    out.extend_from_slice(&body);
    crossterm::queue!(out, crossterm::terminal::EnableLineWrap)?;
    Ok(out)
}

/// Cut every line of a staged frame so that none reaches the last of `cols`
/// columns. The TUI views redraw in place by moving the cursor up one row per
/// line: a line that wraps takes two rows, and each redraw would then leave
/// the previous frame's first row behind. Staying clear of the last column
/// also keeps the erase-to-end-of-line that closes each line from touching
/// text.
///
/// Escape sequences take no columns and are always kept, so a cut line still
/// resets its colors. A cut line ends in the charset's ellipsis. `cols == 0`
/// leaves the frame untouched.
pub fn fit_lines(buf: &[u8], cols: usize) -> Vec<u8> {
    let max = cols.saturating_sub(1);
    let Ok(text) = std::str::from_utf8(buf) else {
        return buf.to_vec();
    };
    if max == 0 {
        return buf.to_vec();
    }

    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if visible_width(line) <= max {
            out.push_str(line);
            continue;
        }
        // One column is kept for the ellipsis that marks the cut.
        let mut width = 0;
        let mut cut = false;
        let mut rest = line;
        while let Some(c) = rest.chars().next() {
            let escape = escape_len(rest);
            if escape > 0 {
                out.push_str(&rest[..escape]);
                rest = &rest[escape..];
                continue;
            }
            if !cut {
                if width + char_width(c) < max {
                    out.push(c);
                    width += char_width(c);
                } else {
                    out.push(crate::render::icons::ellipsis());
                    cut = true;
                }
            }
            rest = &rest[c.len_utf8()..];
        }
    }
    out.into_bytes()
}

/// Number of columns `line` occupies: its characters, minus escape sequences.
fn visible_width(line: &str) -> usize {
    let mut width = 0;
    let mut rest = line;
    while let Some(c) = rest.chars().next() {
        let escape = escape_len(rest);
        if escape > 0 {
            rest = &rest[escape..];
        } else {
            width += char_width(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    width
}

/// Columns a character takes in a terminal, as far as that can be told
/// without the terminal: 2 for the East Asian wide and fullwidth blocks and
/// the main emoji block (a hostname or an interface name may carry them), 1
/// otherwise. This is not a full width table, and terminals disagree on some
/// characters; [`stage_frame`] keeps a misjudged line from wrapping.
fn char_width(c: char) -> usize {
    let wide = matches!(
        c as u32,
        0x1100..=0x115F       // Hangul Jamo initial consonants
            | 0x2329..=0x232A // angle brackets
            | 0x2E80..=0x303E // CJK radicals, Kangxi, CJK symbols
            | 0x3041..=0xA4CF // Hiragana through Yi
            | 0xA960..=0xA97F // Hangul Jamo Extended-A
            | 0xAC00..=0xD7A3 // Hangul syllables
            | 0xF900..=0xFAFF // CJK compatibility ideographs
            | 0xFE10..=0xFE19 // vertical forms
            | 0xFE30..=0xFE6F // CJK compatibility and small forms
            | 0xFF00..=0xFF60 // fullwidth forms
            | 0xFFE0..=0xFFE6 // fullwidth signs
            | 0x16FE0..=0x18AFF // Tangut, Khitan
            | 0x1B000..=0x1B2FF // Kana supplement and extensions
            | 0x1F000..=0x1FAFF // emoji and pictographs
            | 0x20000..=0x3FFFD // CJK extensions
    );
    if wide { 2 } else { 1 }
}

/// Byte length of the escape sequence at the start of `s`, or 0 if there is
/// none. The views emit CSI sequences (`ESC [ parameters final`); any other
/// escape is taken in its two-byte form.
fn escape_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&0x1b) {
        return 0;
    }
    if bytes.get(1) != Some(&b'[') {
        return bytes.len().min(2);
    }
    match bytes[2..].iter().position(|b| (0x40..=0x7e).contains(b)) {
        Some(end) => end + 3,
        None => bytes.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_rtt() {
        assert_eq!(fmt_rtt(Duration::from_micros(500)), "0.50 ms");
        assert_eq!(fmt_rtt(Duration::from_micros(23400)), "23.4 ms");
        assert_eq!(fmt_rtt(Duration::from_millis(150)), "150 ms");
        assert_eq!(fmt_rtt(Duration::from_millis(1500)), "1.50 s");
    }

    #[test]
    fn test_fmt_loss() {
        assert_eq!(fmt_loss(0.0), "0%");
        assert_eq!(fmt_loss(1.5), "1.5%");
        assert_eq!(fmt_loss(50.0), "50%");
    }

    #[test]
    fn test_fmt_elapsed() {
        assert_eq!(fmt_elapsed(Duration::from_secs(92)), "01:32");
        assert_eq!(fmt_elapsed(Duration::from_secs(3661)), "01:01:01");
    }

    #[test]
    fn test_fix_raw_newlines() {
        assert_eq!(fix_raw_newlines(b"hello\nworld\n"), b"hello\r\nworld\r\n");
        assert_eq!(fix_raw_newlines(b"no newlines"), b"no newlines");
    }

    fn fit(text: &str, cols: usize) -> String {
        String::from_utf8(fit_lines(text.as_bytes(), cols)).unwrap()
    }

    #[test]
    fn fit_lines_leaves_lines_that_fit() {
        // 9 visible columns fit in a 10-column terminal (last column unused).
        assert_eq!(fit("123456789\nshort\n", 10), "123456789\nshort\n");
    }

    #[test]
    fn fit_lines_cuts_a_line_that_would_reach_the_last_column() {
        // 10 columns in a 10-column terminal: cut to 9, ending in the ellipsis.
        assert_eq!(fit("1234567890\nshort\n", 10), "12345678…\nshort\n");
        assert_eq!(fit("12345678901234567890", 10), "12345678…");
    }

    #[test]
    fn fit_lines_counts_characters_not_bytes() {
        // Multi-byte glyphs are one column each.
        assert_eq!(fit("▁▂▃▄▅▆▇█·", 10), "▁▂▃▄▅▆▇█·");
        assert_eq!(fit("▁▂▃▄▅▆▇█·—✕", 10), "▁▂▃▄▅▆▇█…");
    }

    #[test]
    fn fit_lines_keeps_escape_sequences_and_ignores_their_width() {
        // Colors take no columns: 9 visible characters still fit.
        let colored = "\x1b[33m12345\x1b[0m6789\x1b[K";
        assert_eq!(fit(colored, 10), colored);
        // When cut, the sequences after the cut are kept (color reset, erase).
        assert_eq!(
            fit("\x1b[33m1234567890\x1b[0mtail\x1b[K\n", 10),
            "\x1b[33m12345678…\x1b[0m\x1b[K\n"
        );
    }

    #[test]
    fn fit_lines_counts_wide_characters_as_two_columns() {
        // Six CJK characters take 12 columns, not 6.
        assert_eq!(visible_width("日本語テスト"), 12);
        // 9 usable columns, one kept for the ellipsis: four wide characters.
        assert_eq!(fit("日本語テスト.jp", 10), "日本語テ…");
        // A wide character that would straddle the limit is dropped whole.
        assert_eq!(fit("abc日本語テスト", 10), "abc日本…");
        // 8 columns of wide characters fit a 10-column terminal untouched.
        assert_eq!(fit("日本語テ", 10), "日本語テ");
    }

    #[test]
    fn stage_frame_draws_with_line_wrap_off() {
        // Wrap off, the fitted body with raw-mode newlines, wrap back on.
        assert_eq!(
            stage_frame(b"1234567890\nok\n", Some(10)).unwrap(),
            "\x1b[?7l12345678…\r\nok\r\n\x1b[?7h".as_bytes()
        );
    }

    #[test]
    fn stage_frame_protects_a_terminal_of_unknown_width() {
        // No width to cut to, but still a terminal: wrap off around the
        // untouched lines, so the terminal clips them instead of wrapping.
        let long = "x".repeat(300) + "\n";
        let mut expected = b"\x1b[?7l".to_vec();
        expected.extend(fix_raw_newlines(long.as_bytes()));
        expected.extend(b"\x1b[?7h");
        assert_eq!(stage_frame(long.as_bytes(), Some(0)).unwrap(), expected);
    }

    #[test]
    fn stage_frame_leaves_redirected_output_alone() {
        // Not a terminal: nothing cut, no terminal sequences added.
        let long = "x".repeat(300) + "\n";
        assert_eq!(
            stage_frame(long.as_bytes(), None).unwrap(),
            fix_raw_newlines(long.as_bytes())
        );
    }

    #[test]
    fn fit_lines_unknown_width_is_a_noop() {
        let long = "x".repeat(300);
        assert_eq!(fit(&long, 0), long);
        assert_eq!(fit(&long, 1), long);
    }

    #[test]
    fn fit_lines_result_never_reaches_the_last_column() {
        let frame = "Latency    now 0.73 ms · avg 0.88 ms · min 0.73 ms · max 1.24 ms · jitter 0.17 ms\x1b[K\n";
        assert_eq!(visible_width(frame.trim_end_matches('\n')), 81);
        for cols in [20, 40, 80, 81, 82] {
            let fitted = fit(frame, cols);
            let width = visible_width(fitted.trim_end_matches('\n'));
            assert!(width < cols, "{width} columns in a {cols}-column terminal");
        }
        // Wide enough: untouched.
        assert_eq!(fit(frame, 83), frame);
    }
}
