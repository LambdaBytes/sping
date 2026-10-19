//! Value formatters shared by all views plus the `\n` → `\r\n` rewrite
//! required for raw-mode output.

use std::io::IsTerminal;
use std::net::IpAddr;
use std::time::Duration;

use crate::context::dns::Family;
use crate::context::{ContextChange, ContextField, ContextValue, NetworkContext};
use crate::diagnostics::correlator::Finding;
use crate::diagnostics::evidence::{Gap, Outcome, Reason, Role};
use crate::diagnostics::planner::{Conclusion, Diagnosis};
use crate::probe::diagnose::DiagnoseState;
use crate::probe::trace::{HopProbe, Unavailable, UnreachableKind};
use crate::probe::types::{ProbeSnapshot, TcpState};

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

/// Where probes leave from: `if eth0 · 192.168.1.100/24`, or `no IPv6
/// source` (`no IPv4 source`) when the system has no source address for the
/// target's family — the context then holds `0.0.0.0` and no interface.
pub fn fmt_source(ctx: &NetworkContext, target: IpAddr, sep: &str) -> String {
    if ctx.local_ip.is_unspecified() {
        let family = if target.is_ipv6() { "IPv6" } else { "IPv4" };
        return format!("no {family} source");
    }
    format!(
        "if {}{sep}{}/{}",
        ctx.interface, ctx.local_ip, ctx.prefix_len
    )
}

/// How the last TCP connect ended, for a person: `TCP 443 connected · 21 ms`,
/// `TCP 443 timeout · no answer`. `None` for ICMP, before the first connect,
/// for a refusal, which the diagnosis reports (`Finding::TcpRefused`), and
/// for a local error, which the probe error itself explains.
pub fn tcp_outcome(snap: &ProbeSnapshot, sep: &str) -> Option<String> {
    let port = snap.port?;
    match snap.tcp_state? {
        TcpState::Open => Some(format!(
            "TCP {port} connected{sep}{}",
            fmt_rtt_opt(snap.rtt_last)
        )),
        TcpState::Timeout => Some(format!("TCP {port} timeout{sep}no answer")),
        TcpState::Refused | TcpState::Error => None,
    }
}

/// A finding as the Events line says it.
pub fn describe(finding: &Finding, sep: &str) -> String {
    match finding {
        // A reset or an ICMP unreachable can come from a device on the way,
        // so the host is not named.
        Finding::TcpRefused { port } => {
            format!("TCP {port} refused{sep}host or firewall answered")
        }
        Finding::Recovered { duration } => format!("recovered after {}", fmt_elapsed(*duration)),
        Finding::ContextChanged { changes, age_s } => {
            let changes: Vec<String> = changes.iter().map(describe_change).collect();
            format!(
                "context changed {} ago: {}",
                fmt_elapsed(Duration::from_secs(*age_s)),
                changes.join(sep)
            )
        }
        Finding::Outage { duration } => format!("outage {}", fmt_elapsed(*duration)),
        Finding::GatewayUnreachable => {
            format!("gateway unreachable{sep}local network issue likely")
        }
        Finding::UpstreamOutage => format!("upstream outage likely{sep}local gateway OK"),
        Finding::WanUnreachable => format!("WAN unreachable{sep}gateway state unknown"),
        Finding::TargetUnreachable { wan_online: true } => {
            format!("target unreachable{sep}internet still OK")
        }
        Finding::TargetUnreachable { wan_online: false } => "target unreachable".into(),
        Finding::LatencySpike { rtt } => format!("last spike {}{sep}spike guard on", fmt_rtt(*rtt)),
        Finding::HighJitter => format!("high jitter with no loss{sep}unstable path"),
        Finding::IntermittentLoss { .. } => "intermittent loss".into(),
        Finding::WanDegraded => format!("WAN degraded{sep}gateway OK"),
        Finding::NameLookupFailed { timed_out: true } => {
            format!("last name lookup failed (timeout){sep}WAN reference answers")
        }
        Finding::NameLookupFailed { timed_out: false } => {
            format!("last name lookup failed{sep}WAN reference answers")
        }
        Finding::LookupWithoutFamily { family } => {
            format!("last name lookup gave no {} address", family_name(*family))
        }
    }
}

/// One field of a context change: `interface eth0 → wlan0`.
fn describe_change(change: &ContextChange) -> String {
    let what = match change.what {
        ContextField::Interface => "interface",
        ContextField::LocalIp => "source",
        ContextField::PrefixLen => "prefix",
        ContextField::Gateway => "gateway",
        ContextField::TargetClass => "target",
    };
    let value = |v: &Option<ContextValue>| {
        v.as_ref().map_or_else(
            || crate::render::icons::dash().into(),
            ContextValue::to_string,
        )
    };
    format!(
        "{what} {} {} {}",
        value(&change.from),
        crate::render::icons::arrow(),
        value(&change.to)
    )
}

/// A conclusion of `--diagnose` as the views say it: what was observed, no
/// more.
pub fn describe_conclusion(conclusion: &Conclusion) -> String {
    match conclusion {
        Conclusion::NoSource { family } => {
            format!("no {} route or source for the target", family_name(*family))
        }
        Conclusion::ReportedUnreachable { ttl, from, kind } => {
            format!("hop {ttl} ({from}) reports {}", unreachable_name(*kind))
        }
        Conclusion::SilentAfter {
            last: Some(last), ..
        } => {
            let from: Vec<String> = last.from.iter().map(IpAddr::to_string).collect();
            format!("silent after hop {} ({})", last.ttl, from.join(", "))
        }
        Conclusion::SilentAfter { last: None, .. } => "no hop answers".into(),
        Conclusion::TargetAnswersIcmp { ttl } => format!("target answers the trace at hop {ttl}"),
        Conclusion::AnswersTcp {
            port,
            refused: false,
        } => format!("TCP {port} answers"),
        Conclusion::AnswersTcp {
            port,
            refused: true,
        } => format!("TCP {port} refused"),
        Conclusion::OtherFamilyWorks { family, .. } => format!("{} works", family_name(*family)),
        Conclusion::OtherFamilyFails { family, .. } => {
            format!("{} fails too", family_name(*family))
        }
    }
}

/// What `--diagnose` could not establish, and why.
pub fn describe_gap(gap: &Gap) -> String {
    let what = match gap.role {
        Role::Main => "source check",
        Role::OtherFamily => "other family",
        Role::Tcp => "TCP",
        Role::Trace => "trace",
        Role::Name => "lookup",
    };
    match &gap.reason {
        Reason::ExplicitFamily => format!("{what} not tried (-4/-6)"),
        Reason::ExplicitSource => format!("{what} not tried (-S)"),
        Reason::Literal => format!("{what} not tried (address given)"),
        Reason::NoAddress => format!("{what}: no address for the name"),
        Reason::NoSource => format!("{what}: no route or source"),
        Reason::ResolveFailed(message) | Reason::Failed(message) => {
            format!("{what} failed: {message}")
        }
        Reason::Ceiling => format!("{what} skipped: traffic ceiling"),
        Reason::Unavailable(Unavailable::Permission) => {
            format!("{what} unavailable: needs privileges")
        }
        Reason::Unavailable(Unavailable::Platform) => format!("{what} unavailable on this system"),
        Reason::Inconclusive => format!("{what} inconclusive"),
        Reason::Unknown(message) => format!("{what}: {message}"),
    }
}

fn family_name(family: Family) -> &'static str {
    match family {
        Family::V4 => "IPv4",
        Family::V6 => "IPv6",
    }
}

fn unreachable_name(kind: UnreachableKind) -> &'static str {
    match kind {
        UnreachableKind::Net => "network unreachable",
        UnreachableKind::Host => "host unreachable",
        UnreachableKind::Protocol => "protocol unreachable",
        UnreachableKind::Port => "port unreachable",
        UnreachableKind::AdminProhibited => "admin prohibited",
        UnreachableKind::Other => "unreachable",
    }
}

/// The conclusions of a diagnosis, or that it has none.
fn conclusions_text(diagnosis: &Diagnosis, sep: &str) -> String {
    if diagnosis.conclusions.is_empty() {
        return "nothing conclusive".into();
    }
    let texts: Vec<String> = diagnosis
        .conclusions
        .iter()
        .map(|c| describe_conclusion(&c.conclusion))
        .collect();
    texts.join(sep)
}

/// The Events line's findings and, with `--diagnose`, the diagnosis after
/// them: `diagnosing…` while it escalates, then its conclusions. One finding
/// gives way: `gateway_unreachable` ("local network issue likely") once
/// something beyond the host answered (a hop of the trace, or the target
/// over TCP), which shows the first hop works. The other findings stay: no
/// conclusion contradicts them.
pub fn events(findings: &[Finding], diagnose: Option<&DiagnoseState>, sep: &str) -> Vec<String> {
    let diagnosis = match diagnose {
        Some(DiagnoseState::Done { diagnosis, .. }) => Some(diagnosis.as_ref()),
        _ => None,
    };
    let contradicted = diagnosis.is_some_and(answered_beyond_the_host);
    let mut events: Vec<String> = findings
        .iter()
        .filter(|f| !(contradicted && **f == Finding::GatewayUnreachable))
        .map(|f| describe(f, sep))
        .collect();
    match diagnose {
        Some(DiagnoseState::Diagnosing { .. }) => {
            events.push(format!("diagnosing{}", crate::render::icons::in_progress()));
        }
        Some(DiagnoseState::Done { diagnosis, .. }) => {
            events.push(conclusions_text(diagnosis, sep))
        }
        _ => {}
    }
    events
}

/// A hop of the trace answered, or the target did over TCP.
fn answered_beyond_the_host(diagnosis: &Diagnosis) -> bool {
    let hop_answered = diagnosis.evidence.iter().any(|e| match &e.outcome {
        Outcome::Trace(result) => result
            .hops
            .iter()
            .flat_map(|hop| &hop.probes)
            .any(|probe| matches!(probe, HopProbe::Reply { .. })),
        _ => false,
    });
    hop_answered
        || diagnosis
            .conclusions
            .iter()
            .any(|c| matches!(c.conclusion, Conclusion::AnswersTcp { .. }))
}

/// The diagnosis for a final summary: `None` when nothing went down.
pub fn diagnosis_summary(state: &DiagnoseState, sep: &str) -> Option<String> {
    match state {
        DiagnoseState::Idle => None,
        DiagnoseState::Diagnosing { .. } => Some("diagnosis incomplete".into()),
        DiagnoseState::Done { diagnosis, .. } => {
            Some(format!("diagnosis: {}", conclusions_text(diagnosis, sep)))
        }
    }
}

/// What the diagnosis could not establish, if anything.
pub fn untested(state: &DiagnoseState, sep: &str) -> Option<String> {
    let DiagnoseState::Done { diagnosis, .. } = state else {
        return None;
    };
    let gaps: Vec<String> = diagnosis.gaps.iter().map(describe_gap).collect();
    (!gaps.is_empty()).then(|| gaps.join(sep))
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
    fn source_is_the_interface_or_its_absence() {
        use crate::context::classify::TargetClass;
        let mut ctx = NetworkContext {
            interface: "eth0".into(),
            local_ip: "192.168.1.100".parse().unwrap(),
            prefix_len: 24,
            gateway: None,
            target_class: TargetClass::PublicNetwork,
        };
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();
        assert_eq!(fmt_source(&ctx, v4, " · "), "if eth0 · 192.168.1.100/24");
        assert_eq!(fmt_source(&ctx, v4, " | "), "if eth0 | 192.168.1.100/24");

        ctx.local_ip = "0.0.0.0".parse().unwrap();
        ctx.interface = "unknown".into();
        assert_eq!(fmt_source(&ctx, v6, " · "), "no IPv6 source");
        assert_eq!(fmt_source(&ctx, v4, " · "), "no IPv4 source");
    }

    /// Each finding as the Events line has always said it; the separator is
    /// the charset's.
    #[test]
    fn findings_are_described_as_before() {
        use std::time::Duration;
        let cases = [
            (
                Finding::TcpRefused { port: 443 },
                "TCP 443 refused · host or firewall answered",
            ),
            (
                Finding::Recovered {
                    duration: Duration::from_secs(92),
                },
                "recovered after 01:32",
            ),
            (
                Finding::Outage {
                    duration: Duration::from_secs(12),
                },
                "outage 00:12",
            ),
            (
                Finding::GatewayUnreachable,
                "gateway unreachable · local network issue likely",
            ),
            (
                Finding::UpstreamOutage,
                "upstream outage likely · local gateway OK",
            ),
            (
                Finding::WanUnreachable,
                "WAN unreachable · gateway state unknown",
            ),
            (
                Finding::TargetUnreachable { wan_online: true },
                "target unreachable · internet still OK",
            ),
            (
                Finding::TargetUnreachable { wan_online: false },
                "target unreachable",
            ),
            (
                Finding::LatencySpike {
                    rtt: Duration::from_millis(120),
                },
                "last spike 120 ms · spike guard on",
            ),
            (
                Finding::HighJitter,
                "high jitter with no loss · unstable path",
            ),
            (
                Finding::IntermittentLoss {
                    recent_loss_pct: 10.0,
                },
                "intermittent loss",
            ),
            (Finding::WanDegraded, "WAN degraded · gateway OK"),
        ];
        for (finding, text) in cases {
            assert_eq!(describe(&finding, " · "), text);
        }
        assert_eq!(
            describe(&Finding::WanDegraded, " | "),
            "WAN degraded | gateway OK"
        );
    }

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

    /// The name's findings (1.7.0) as the Events line says them.
    #[test]
    fn the_names_findings_are_described() {
        use crate::context::dns::Family;
        let sep = " · ";
        for (finding, text) in [
            (
                Finding::NameLookupFailed { timed_out: true },
                "last name lookup failed (timeout) · WAN reference answers",
            ),
            (
                Finding::NameLookupFailed { timed_out: false },
                "last name lookup failed · WAN reference answers",
            ),
            (
                Finding::LookupWithoutFamily { family: Family::V6 },
                "last name lookup gave no IPv6 address",
            ),
        ] {
            assert_eq!(describe(&finding, sep), text);
        }
    }

    /// A context change as the Events line says it.
    #[test]
    fn a_context_change_is_described() {
        use crate::context::classify::TargetClass;
        use crate::context::{ContextChange, ContextField, ContextValue};
        let text = |s: &str| Some(ContextValue::Text(s.into()));
        let class = |c| Some(ContextValue::Class(c));
        let change = |what, from, to| ContextChange { what, from, to };
        let finding = Finding::ContextChanged {
            changes: vec![
                change(ContextField::Interface, text("eth0"), text("wlan0")),
                change(ContextField::LocalIp, text("10.0.0.7"), None),
                change(
                    ContextField::PrefixLen,
                    Some(ContextValue::Prefix(16)),
                    None,
                ),
                change(ContextField::Gateway, text("192.168.1.1"), None),
                change(
                    ContextField::TargetClass,
                    class(TargetClass::SameLan),
                    class(TargetClass::PublicNetwork),
                ),
            ],
            age_s: 3,
        };
        assert_eq!(
            describe(&finding, " · "),
            "context changed 00:03 ago: interface eth0 → wlan0 · source 10.0.0.7 → — · prefix 16 → — · gateway 192.168.1.1 → — · target same LAN → public"
        );
    }

    mod diagnose {
        use super::super::*;
        use crate::diagnostics::evidence::{Action, Evidence, Generation, RequestId, Via};
        use crate::diagnostics::planner::{Concluded, LastHop};
        use crate::probe::trace::{Hop, ReplyKind, TraceResult, TraceStatus};
        use std::sync::Arc;
        use std::time::Instant;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        /// A finished diagnosis of 198.51.100.7, whose trace got `hops`.
        fn done(conclusions: Vec<Conclusion>, hops: Vec<Hop>) -> DiagnoseState {
            let target = crate::context::dns::ResolvedAddr::unscoped(ip("198.51.100.7"));
            let evidence = vec![Evidence {
                id: RequestId::new(1),
                role: Role::Trace,
                action: Action::Trace { target },
                outcome: Outcome::Trace(TraceResult {
                    status: TraceStatus::SilentTail { hops: 3 },
                    hops,
                }),
                via: Via::default(),
                generation: Generation::new(0),
                at: Instant::now(),
            }];
            DiagnoseState::Done {
                target: target.ip,
                diagnosis: Arc::new(Diagnosis {
                    conclusions: conclusions
                        .into_iter()
                        .map(|conclusion| Concluded {
                            conclusion,
                            because: vec![RequestId::new(1)],
                        })
                        .collect(),
                    gaps: vec![Gap {
                        role: Role::OtherFamily,
                        reason: Reason::Literal,
                    }],
                    evidence,
                }),
            }
        }

        fn hop(ttl: u8, answered: bool) -> Hop {
            Hop {
                ttl,
                probes: vec![if answered {
                    HopProbe::Reply {
                        from: ip("192.0.2.1"),
                        rtt: Duration::from_millis(1),
                        kind: ReplyKind::TimeExceeded,
                    }
                } else {
                    HopProbe::Silent
                }],
                partial: false,
            }
        }

        #[test]
        fn conclusions_and_gaps_are_said_as_observed() {
            for (conclusion, text) in [
                (
                    Conclusion::NoSource { family: Family::V4 },
                    "no IPv4 route or source for the target",
                ),
                (
                    Conclusion::ReportedUnreachable {
                        ttl: 4,
                        from: ip("203.0.113.9"),
                        kind: UnreachableKind::AdminProhibited,
                    },
                    "hop 4 (203.0.113.9) reports admin prohibited",
                ),
                (
                    Conclusion::SilentAfter {
                        last: Some(LastHop {
                            ttl: 5,
                            from: vec![ip("203.0.113.21"), ip("203.0.113.22")],
                        }),
                        silent: 3,
                    },
                    "silent after hop 5 (203.0.113.21, 203.0.113.22)",
                ),
                (
                    Conclusion::SilentAfter {
                        last: None,
                        silent: 3,
                    },
                    "no hop answers",
                ),
                (
                    Conclusion::TargetAnswersIcmp { ttl: 7 },
                    "target answers the trace at hop 7",
                ),
                (
                    Conclusion::AnswersTcp {
                        port: 443,
                        refused: false,
                    },
                    "TCP 443 answers",
                ),
                (
                    Conclusion::AnswersTcp {
                        port: 80,
                        refused: true,
                    },
                    "TCP 80 refused",
                ),
                (
                    Conclusion::OtherFamilyWorks {
                        family: Family::V6,
                        address: ip("2001:db8::7"),
                    },
                    "IPv6 works",
                ),
                (
                    Conclusion::OtherFamilyFails {
                        family: Family::V4,
                        address: ip("198.51.100.7"),
                    },
                    "IPv4 fails too",
                ),
            ] {
                assert_eq!(describe_conclusion(&conclusion), text);
            }
            for (role, reason, text) in [
                (
                    Role::OtherFamily,
                    Reason::ExplicitFamily,
                    "other family not tried (-4/-6)",
                ),
                (
                    Role::OtherFamily,
                    Reason::ExplicitSource,
                    "other family not tried (-S)",
                ),
                (
                    Role::OtherFamily,
                    Reason::Literal,
                    "other family not tried (address given)",
                ),
                (
                    Role::OtherFamily,
                    Reason::NoAddress,
                    "other family: no address for the name",
                ),
                (
                    Role::OtherFamily,
                    Reason::NoSource,
                    "other family: no route or source",
                ),
                (
                    Role::Name,
                    Reason::ResolveFailed("timed out".into()),
                    "lookup failed: timed out",
                ),
                (
                    Role::Trace,
                    Reason::Ceiling,
                    "trace skipped: traffic ceiling",
                ),
                (
                    Role::Trace,
                    Reason::Unavailable(Unavailable::Permission),
                    "trace unavailable: needs privileges",
                ),
                (
                    Role::Trace,
                    Reason::Unavailable(Unavailable::Platform),
                    "trace unavailable on this system",
                ),
                (Role::Trace, Reason::Inconclusive, "trace inconclusive"),
                (
                    Role::Tcp,
                    Reason::Failed("connect failed: x".into()),
                    "TCP failed: connect failed: x",
                ),
                (
                    Role::Main,
                    Reason::Unknown("source check unavailable with -S/-I".into()),
                    "source check: source check unavailable with -S/-I",
                ),
            ] {
                assert_eq!(describe_gap(&Gap { role, reason }), text);
            }
        }

        /// The diagnosis goes after the findings; `gateway_unreachable` gives
        /// way only when something beyond the host answered.
        #[test]
        fn events_with_the_diagnosis() {
            let sep = " · ";
            let findings = [
                Finding::Outage {
                    duration: Duration::from_secs(12),
                },
                Finding::GatewayUnreachable,
            ];
            let outage = describe(&findings[0], sep);
            let gateway = describe(&Finding::GatewayUnreachable, sep);
            let silent_after_hop_1 = Conclusion::SilentAfter {
                last: Some(LastHop {
                    ttl: 1,
                    from: vec![ip("192.0.2.1")],
                }),
                silent: 3,
            };
            let no_hop = Conclusion::SilentAfter {
                last: None,
                silent: 3,
            };
            let tcp = Conclusion::AnswersTcp {
                port: 443,
                refused: true,
            };
            let cases: Vec<(Option<DiagnoseState>, Vec<String>)> = vec![
                (None, vec![outage.clone(), gateway.clone()]),
                (
                    Some(DiagnoseState::Idle),
                    vec![outage.clone(), gateway.clone()],
                ),
                (
                    Some(DiagnoseState::Diagnosing {
                        target: ip("198.51.100.7"),
                    }),
                    vec![outage.clone(), gateway.clone(), "diagnosing…".into()],
                ),
                // The first hop answered: the gateway works.
                (
                    Some(done(
                        vec![silent_after_hop_1],
                        vec![hop(1, true), hop(2, false)],
                    )),
                    vec![outage.clone(), "silent after hop 1 (192.0.2.1)".into()],
                ),
                // Nothing answered: compatible with a gateway down.
                (
                    Some(done(vec![no_hop], vec![hop(1, false)])),
                    vec![outage.clone(), gateway.clone(), "no hop answers".into()],
                ),
                // The target answered over TCP.
                (
                    Some(done(vec![tcp], vec![])),
                    vec![outage.clone(), "TCP 443 refused".into()],
                ),
                (
                    Some(done(vec![], vec![hop(1, false)])),
                    vec![outage.clone(), gateway.clone(), "nothing conclusive".into()],
                ),
            ];
            for (state, expected) in cases {
                assert_eq!(
                    events(&findings, state.as_ref(), sep),
                    expected,
                    "{state:?}"
                );
            }
            // Only that finding gives way.
            let target = [Finding::TargetUnreachable { wan_online: true }];
            let state = done(vec![], vec![hop(1, true)]);
            assert_eq!(
                events(&target, Some(&state), sep)[0],
                describe(&target[0], sep)
            );
        }

        #[test]
        fn summaries_of_the_diagnosis() {
            let sep = " · ";
            assert_eq!(diagnosis_summary(&DiagnoseState::Idle, sep), None);
            assert_eq!(
                diagnosis_summary(
                    &DiagnoseState::Diagnosing {
                        target: ip("198.51.100.7")
                    },
                    sep
                )
                .as_deref(),
                Some("diagnosis incomplete")
            );
            let state = done(
                vec![
                    Conclusion::TargetAnswersIcmp { ttl: 3 },
                    Conclusion::OtherFamilyWorks {
                        family: Family::V6,
                        address: ip("2001:db8::7"),
                    },
                ],
                vec![],
            );
            assert_eq!(
                diagnosis_summary(&state, sep).as_deref(),
                Some("diagnosis: target answers the trace at hop 3 · IPv6 works")
            );
            assert_eq!(
                untested(&state, sep).as_deref(),
                Some("other family not tried (address given)")
            );
            assert_eq!(untested(&DiagnoseState::Idle, sep), None);
        }
    }
}
