//! Glyph/color selection, fixed once at startup via [`init`]. Both charsets
//! occupy identical column widths so the layout never shifts; color honors
//! `NO_COLOR` and requires a TTY.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// Spinner frames (Unicode braille).
const SPINNER_UTF8: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
/// Spinner frames (ASCII fallback).
const SPINNER_ASCII: &[char] = &['|', '/', '-', '\\'];

/// 8-level block characters for pulse and histogram.
const BLOCKS_UTF8: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
const BLOCKS_ASCII: [char; 8] = ['_', '.', ',', '-', '=', '+', '*', '#'];

static ASCII: OnceLock<bool> = OnceLock::new();

/// Fix the output charset once at startup: ASCII when forced by `--ascii`,
/// `SPING_ASCII=1`, or a non-UTF-8 locale.
pub fn init(force_ascii: bool) {
    let ascii = force_ascii || env_forces_ascii() || !locale_is_utf8();
    let _ = ASCII.set(ascii);
}

fn env_forces_ascii() -> bool {
    std::env::var_os("SPING_ASCII").is_some_and(|v| v != "0")
}

fn locale_is_utf8() -> bool {
    // Windows consoles render Unicode via WriteConsoleW regardless of codepage.
    if cfg!(windows) {
        return true;
    }
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            let l = v.to_lowercase();
            return l.contains("utf-8") || l.contains("utf8");
        }
    }
    // No locale info (containers, init systems): be conservative.
    false
}

fn is_ascii() -> bool {
    *ASCII.get().unwrap_or(&false)
}

/// Spinner animation frames for the active charset.
pub fn spinner() -> &'static [char] {
    if is_ascii() {
        SPINNER_ASCII
    } else {
        SPINNER_UTF8
    }
}

/// 8-level bar glyphs (low to high) for the pulse strip and histograms.
pub fn blocks() -> &'static [char; 8] {
    if is_ascii() {
        &BLOCKS_ASCII
    } else {
        &BLOCKS_UTF8
    }
}

/// Field separator.
pub fn sep() -> &'static str {
    if is_ascii() { " | " } else { " · " }
}

/// Placeholder for missing values.
pub fn dash() -> &'static str {
    if is_ascii() { "-" } else { "—" }
}

/// Truncation marker appended to shortened names.
pub fn ellipsis() -> char {
    if is_ascii() { '~' } else { '…' }
}

/// Loss marker in the pulse strip.
pub fn loss_char() -> char {
    if is_ascii() { 'x' } else { '✕' }
}

/// Horizontal rule of `n` columns.
pub fn hline(n: usize) -> String {
    if is_ascii() {
        "-".repeat(n)
    } else {
        "─".repeat(n)
    }
}

/// Echo-path glyphs: (path, probe, target, probe-at-target).
pub fn path_glyphs() -> (char, char, char, char) {
    if is_ascii() {
        ('-', 'o', 'O', '@')
    } else {
        ('─', '●', '◎', '◉')
    }
}

/// Whether to emit ANSI colors: stdout is a TTY and NO_COLOR is unset.
pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}
