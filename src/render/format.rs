//! Value formatters shared by all views plus the `\n` → `\r\n` rewrite
//! required for raw-mode output.

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
}
