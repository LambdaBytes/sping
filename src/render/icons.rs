//! Glyph/color selection, fixed once at startup via [`init`]. Both charsets
//! occupy identical column widths so the layout never shifts; color honors
//! `NO_COLOR` and requires a TTY.

use std::io::IsTerminal;
use std::sync::OnceLock;

use crate::diagnostics::health::Reachability;

/// Spinner frames (Unicode braille).
const SPINNER_UTF8: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
/// Spinner frames (ASCII fallback).
const SPINNER_ASCII: &[char] = &['|', '/', '-', '\\'];

/// 8-level block characters for pulse and histogram.
const BLOCKS_UTF8: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// ASCII ramp: four marks rising from the baseline (`_`) through the middle
/// of the cell (`-`, `=`) to its top (`"`), each covering two levels. ASCII
/// has no eighth-blocks, and eight unrelated marks read as noise.
const BLOCKS_ASCII: [char; 8] = ['_', '_', '-', '-', '=', '=', '"', '"'];

static ASCII: OnceLock<bool> = OnceLock::new();

/// Fix the output charset once at startup: ASCII when forced by `--ascii` or
/// `SPING_ASCII=1`, Unicode when forced by `SPING_ASCII=0`, otherwise
/// whatever the terminal is expected to draw correctly.
pub fn init(force_ascii: bool) {
    let env = std::env::var_os("SPING_ASCII");
    let ascii = choose_ascii(force_ascii, env.as_deref(), terminal_draws_unicode());
    let _ = ASCII.set(ascii);
}

fn choose_ascii(force_ascii: bool, env: Option<&std::ffi::OsStr>, terminal_unicode: bool) -> bool {
    if force_ascii {
        return true;
    }
    match env {
        Some(v) if v.is_empty() => !terminal_unicode,
        Some(v) => v != "0",
        None => !terminal_unicode,
    }
}

/// Whether the terminal is expected to draw the Unicode charset: a UTF-8
/// locale on Unix; on Windows, a terminal that announces itself. The console
/// accepts any Unicode (`WriteConsoleW`), but the legacy console host's fonts
/// lack the eighth-block and braille glyphs, so there they come out as boxes.
fn terminal_draws_unicode() -> bool {
    if cfg!(windows) {
        return windows_terminal_announced();
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

/// Windows Terminal (`WT_SESSION`), VS Code, WezTerm, Hyper and the like
/// (`TERM_PROGRAM`) and ConEmu/cmder (`ConEmuANSI`) export a variable; the
/// legacy console host exports none of them.
fn windows_terminal_announced() -> bool {
    ["WT_SESSION", "TERM_PROGRAM", "ConEmuANSI"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
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

/// Reachability indicator of the gateway/WAN probes on the Context line.
pub fn reach_glyph(r: Reachability) -> &'static str {
    reach_glyph_for(r, is_ascii())
}

fn reach_glyph_for(r: Reachability, ascii: bool) -> &'static str {
    match (r, ascii) {
        (Reachability::Unknown, _) => "?",
        (Reachability::Online, false) => "●",
        (Reachability::Online, true) => "o",
        (Reachability::Offline, false) => "○",
        (Reachability::Offline, true) => "x",
    }
}

/// Multiplication sign for "N targets × M probes".
pub fn times() -> &'static str {
    if is_ascii() { "x" } else { "×" }
}

/// Echo-path glyphs: (path, probe, target, probe-at-target).
pub fn path_glyphs() -> (char, char, char, char) {
    if is_ascii() {
        ('-', 'o', 'O', '@')
    } else {
        ('─', '●', '◎', '◉')
    }
}

/// Whether to emit ANSI colors: stdout is a TTY that interprets escape
/// sequences and NO_COLOR is unset.
pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() && ansi_enabled()
}

/// A Windows console only interprets escape sequences once virtual-terminal
/// processing is switched on, which crossterm does lazily, when it runs its
/// first command. Asking here switches it on before anything is printed, so
/// an early line (the `Init:` line) does not show its sequences as text.
#[cfg(windows)]
fn ansi_enabled() -> bool {
    crossterm::ansi_support::supports_ansi()
}

#[cfg(not(windows))]
fn ansi_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn charset_choice_follows_flag_env_and_terminal() {
        // Nothing forced: the terminal decides.
        assert!(!choose_ascii(false, None, true));
        assert!(choose_ascii(false, None, false));
        // --ascii wins over everything.
        assert!(choose_ascii(true, Some(OsStr::new("0")), true));
        // SPING_ASCII=1 forces ASCII; SPING_ASCII=0 forces Unicode even on a
        // terminal we would not trust; an empty value is as good as unset.
        assert!(choose_ascii(false, Some(OsStr::new("1")), true));
        assert!(!choose_ascii(false, Some(OsStr::new("0")), false));
        assert!(choose_ascii(false, Some(OsStr::new("")), false));
    }

    #[test]
    fn ascii_blocks_are_ascii_and_one_column() {
        for c in BLOCKS_ASCII {
            assert!(c.is_ascii() && !c.is_ascii_whitespace(), "{c:?}");
        }
        assert_eq!(BLOCKS_ASCII.len(), BLOCKS_UTF8.len());
    }

    #[test]
    fn reachability_glyphs_stay_ascii_in_ascii_mode() {
        for (r, unicode, ascii) in [
            (Reachability::Online, "●", "o"),
            (Reachability::Offline, "○", "x"),
            (Reachability::Unknown, "?", "?"),
        ] {
            assert_eq!(reach_glyph_for(r, false), unicode);
            assert_eq!(reach_glyph_for(r, true), ascii);
            assert!(reach_glyph_for(r, true).is_ascii());
        }
    }
}
