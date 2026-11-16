//! Render-loop drivers for all view modes. TUI views enable raw mode and
//! capture Ctrl+C / `q` via crossterm events; classic and JSON stream
//! without raw mode and treat `BrokenPipe` as a normal downstream exit.

use std::io::{Stdout, Write, stdout};
use std::net::IpAddr;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use tokio::sync::watch;

use crate::config::ViewMode;
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::diagnose::DiagnoseState;
use crate::probe::types::ProbeSnapshot;
use crate::render::format::Placement;
use crate::render::view_classic::ClassicView;
use crate::render::view_compact;
use crate::render::view_extended;
use crate::render::view_json::JsonView;
use crate::render::view_table;
use crate::runtime::frame_clock::FrameClock;

/// Latest gateway and WAN auxiliary probe states shown by the TUI views and
/// the JSON lines, and the diagnosis with `--diagnose`.
pub struct AuxChannels {
    pub gateway_rx: watch::Receiver<Option<AuxiliaryState>>,
    pub wan_rx: watch::Receiver<Option<AuxiliaryState>>,
    pub diagnose: Option<DiagnoseView>,
}

/// The diagnosis' state, and the last probe's sequence number with `-c N`:
/// its JSON line waits for the diagnosis' last state.
pub struct DiagnoseView {
    pub state_rx: watch::Receiver<DiagnoseState>,
    pub last_seq: Option<u64>,
}

impl DiagnoseView {
    fn state(&self) -> DiagnoseState {
        self.state_rx.borrow().clone()
    }

    /// The state as shown next to the main probe at `probed`. One about
    /// another address is the incident before a DNS failover the diagnosis
    /// had not applied yet (a frame or a shutdown came first): that failover
    /// ends it, and it says nothing about `probed`. The JSON names the
    /// address instead.
    fn state_about(&self, probed: IpAddr) -> DiagnoseState {
        match self.state() {
            DiagnoseState::Diagnosing { target } | DiagnoseState::Done { target, .. }
                if target != probed =>
            {
                DiagnoseState::Idle
            }
            state => state,
        }
    }
}

/// Where a live view's next frame starts. Frames are redrawn in place, over
/// the previous one, by moving up one row per line. A terminal whose width
/// changes may reflow what it shows (tmux, iTerm2, Windows Terminal and
/// conhost do): the previous frame's lines take more rows, or rows come back
/// from the scrollback, and moving up over it would leave copies of its first
/// rows above. After a width change the frame is drawn at the top of a
/// cleared screen instead.
struct InlineFrame {
    /// Lines of the previous frame; 0 before the first.
    lines: u16,
    /// The [`format::term_width`](crate::render::format::term_width) it was
    /// drawn at.
    width: Option<usize>,
}

impl InlineFrame {
    fn new() -> Self {
        Self {
            lines: 0,
            width: None,
        }
    }

    /// Whether the next frame, at `width`, starts on a cleared screen: there
    /// is a previous frame and the width changed since. A terminal that
    /// reports no width (`Some(0)`) never tells a change.
    fn clears(&self, width: Option<usize>) -> bool {
        self.lines > 0 && width != self.width && width != Some(0) && self.width != Some(0)
    }

    /// Draw one frame with `draw`, which takes where to draw it and returns
    /// the frame's line count, and write it to `out` at once, with the
    /// clearing first if any. A frame that fails, to stage or to write, counts
    /// as no lines, as it did before.
    fn draw(
        &mut self,
        out: &mut impl Write,
        draw: impl FnOnce(&mut Vec<u8>, Placement) -> std::io::Result<u16>,
    ) {
        use crate::render::format::{term_rows, term_width};
        self.draw_at(out, term_width(), term_rows(), draw);
    }

    /// [`draw`](Self::draw) on a terminal of a given `width` and `rows`.
    fn draw_at(
        &mut self,
        out: &mut impl Write,
        width: Option<usize>,
        rows: usize,
        draw: impl FnOnce(&mut Vec<u8>, Placement) -> std::io::Result<u16>,
    ) {
        let mut frame = Vec::new();
        let lines_before = if self.clears(width) {
            let _ = crossterm::queue!(
                frame,
                terminal::Clear(terminal::ClearType::All),
                crossterm::cursor::MoveTo(0, 0)
            );
            0
        } else {
            self.lines
        };
        let place = Placement {
            lines_before,
            width,
            rows,
        };
        let written = draw(&mut frame, place).and_then(|lines| {
            out.write_all(&frame)?;
            out.flush()?;
            Ok(lines)
        });
        self.lines = written.unwrap_or(0);
        self.width = width;
    }
}

/// Listen for Ctrl+C / `q` via crossterm events; send `true` on shutdown.
fn spawn_key_listener(shutdown_tx: watch::Sender<bool>) {
    tokio::task::spawn_blocking(move || {
        loop {
            // 100ms poll so externally-requested shutdown is noticed promptly.
            // An error means there is no terminal to read keys from (crossterm
            // retries EINTR itself), and every later poll fails at once: stop
            // listening instead of spinning a core. Signals still stop sping.
            let Ok(ready) = event::poll(std::time::Duration::from_millis(100)) else {
                return;
            };
            if ready && let Ok(ev) = event::read() {
                match ev {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('c'),
                        modifiers,
                        ..
                    }) if modifiers.contains(KeyModifiers::CONTROL) => {
                        let _ = shutdown_tx.send(true);
                        return;
                    }
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('q'),
                        ..
                    }) => {
                        let _ = shutdown_tx.send(true);
                        return;
                    }
                    _ => {}
                }
            }
            if *shutdown_tx.borrow() {
                return;
            }
        }
    });
}

/// Single-target renderer dispatching on `view`. `quiet` suppresses
/// per-probe lines in classic mode (the summary still prints).
///
/// # Errors
///
/// The classic and JSON views could not write to stdout.
pub async fn run(
    view: ViewMode,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    aux: AuxChannels,
    shutdown: watch::Receiver<bool>,
    quiet: bool,
) -> std::io::Result<()> {
    let mut out = stdout();

    let written = match view {
        ViewMode::Classic => run_classic(&mut out, probe_rx, aux.diagnose, shutdown, quiet).await,
        ViewMode::Json => run_json(&mut out, probe_rx, aux, shutdown).await,
        _ => {
            let extended = matches!(view, ViewMode::Extended);
            run_tui(&mut out, probe_rx, aux, shutdown, extended).await;
            Ok(())
        }
    };
    unless_reader_gone(written)
}

/// A closed pipe is the reader going away (`sping host | head -1`), not a
/// stdout that cannot be written.
fn unless_reader_gone(written: std::io::Result<()>) -> std::io::Result<()> {
    match written {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        written => written,
    }
}

/// Multi-target table renderer: raw-mode TUI loop, then per-target
/// summaries on shutdown. Not `live` (stdout not a terminal): nothing but
/// the summaries.
///
/// # Errors
///
/// Not `live`: the summaries could not be written to stdout.
pub async fn run_table(
    probe_rxs: Vec<watch::Receiver<Option<ProbeSnapshot>>>,
    shutdown: watch::Receiver<bool>,
    live: bool,
) -> std::io::Result<()> {
    let mut out = stdout();

    // Raw mode: blocks Enter, mouse scroll, captures Ctrl+C via event reader
    if live {
        let _ = terminal::enable_raw_mode();
    }

    let mut clock = FrameClock::default();
    let mut spinner: usize = 0;
    let mut inline = InlineFrame::new();
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            _ = clock.tick(), if live => {
                spinner += 1;
                let snapshots: Vec<Option<ProbeSnapshot>> = probe_rxs
                    .iter()
                    .map(|rx| rx.borrow().clone())
                    .collect();
                inline.draw(&mut out, |frame, place| {
                    view_table::draw_table(frame, &snapshots, spinner, place)
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    if live {
        let _ = terminal::disable_raw_mode();
        let _ = writeln!(out);
    }
    let mut written = Ok(());
    for rx in &probe_rxs {
        if let Some(snap) = rx.borrow().as_ref() {
            written = written.and(print_final_summary(&mut out, snap));
        }
    }
    written = written.and(out.flush());
    // After the table on a terminal, as after the single-target views:
    // nothing to report.
    if live {
        return Ok(());
    }
    unless_reader_gone(written)
}

async fn run_tui(
    out: &mut Stdout,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    aux: AuxChannels,
    shutdown: watch::Receiver<bool>,
    extended: bool,
) {
    // Raw mode: prevents Enter/scroll from corrupting display
    // Ctrl+C detected via crossterm event reader (spawn_key_listener in app.rs)
    let _ = terminal::enable_raw_mode();

    let mut clock = FrameClock::default();
    let mut spinner: usize = 0;
    let mut inline = InlineFrame::new();
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            _ = clock.tick() => {
                spinner += 1;
                if let Some(snap) = probe_rx.borrow().as_ref() {
                    let gw = aux.gateway_rx.borrow().clone();
                    let wan = aux.wan_rx.borrow().clone();
                    let diagnose = aux.diagnose.as_ref().map(|d| d.state_about(snap.target_ip));

                    inline.draw(out, |frame, place| if extended {
                        view_extended::draw_inline(frame, snap, gw.as_ref(), wan.as_ref(), diagnose.as_ref(), spinner, place)
                    } else {
                        view_compact::draw_inline(frame, snap, gw.as_ref(), wan.as_ref(), diagnose.as_ref(), spinner, place)
                    });
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    let _ = terminal::disable_raw_mode();

    if let Some(snap) = probe_rx.borrow().as_ref() {
        let _ = writeln!(out);
        let _ = print_final_summary(out, snap);
        if let Some(line) = aux.diagnose.as_ref().and_then(|d| {
            crate::render::format::diagnosis_summary(
                &d.state_about(snap.target_ip),
                crate::render::icons::sep(),
            )
        }) {
            let _ = writeln!(out, "{line}");
        }
    }
    let _ = out.flush();
}

/// The first write that fails ends it, a closed pipe included.
async fn run_classic(
    out: &mut impl Write,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    diagnose: Option<DiagnoseView>,
    shutdown: watch::Receiver<bool>,
    quiet: bool,
) -> std::io::Result<()> {
    // Scrolling output: no raw mode.
    let mut view = ClassicView::new();
    let mut last_snap: Option<ProbeSnapshot> = None;
    let mut probe_rx = probe_rx;
    let mut shutdown = shutdown;
    let mut diagnose_rx = diagnose.as_ref().map(|d| d.state_rx.clone());

    loop {
        tokio::select! {
            Some(Ok(())) = async {
                match diagnose_rx.as_mut() {
                    Some(rx) => Some(rx.changed().await),
                    None => None,
                }
            } => {
                let state = diagnose_rx.as_mut().map(|rx| rx.borrow_and_update().clone());
                if !quiet && let Some(state) = state {
                    view.diagnosis(out, &state)?;
                }
            }
            result = probe_rx.changed() => {
                if result.is_err() { break; }
                if let Some(snap) = probe_rx.borrow_and_update().as_ref() {
                    if !quiet {
                        view.draw(out, snap)?;
                    }
                    last_snap = Some(snap.clone());
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    // Drain a snapshot that may have raced with shutdown (count mode) so the
    // last probe line and the summary reflect the final state.
    if probe_rx.has_changed().unwrap_or(false)
        && let Some(snap) = probe_rx.borrow_and_update().as_ref()
    {
        if !quiet {
            view.draw(out, snap)?;
        }
        last_snap = Some(snap.clone());
    }

    // A last state published just before the shutdown.
    if !quiet && let Some(d) = diagnose.as_ref() {
        view.diagnosis(out, &d.state())?;
    }
    if let Some(snap) = last_snap.as_ref() {
        view.summary(out, snap)?;
        if let Some(line) = diagnose.as_ref().and_then(|d| {
            crate::render::format::diagnosis_summary(
                &d.state_about(snap.target_ip),
                crate::render::icons::sep(),
            )
        }) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}

/// The first write that fails ends it, a closed pipe included.
async fn run_json(
    out: &mut impl Write,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    aux: AuxChannels,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    // Streaming output: no raw mode.
    let mut view = JsonView::new();
    let mut probe_rx = probe_rx;
    let mut shutdown = shutdown;
    // With `-c N` and `--diagnose`, the line of probe N waits for the
    // diagnosis' last state: still one line per probe.
    let last_seq = aux.diagnose.as_ref().and_then(|d| d.last_seq);
    let mut held: Option<ProbeSnapshot> = None;

    loop {
        tokio::select! {
            result = probe_rx.changed() => {
                if result.is_err() { break; }
                // The gateway and WAN state of this moment: shown in the line
                // and the source of its diagnosis.
                let gw = aux.gateway_rx.borrow().clone();
                let wan = aux.wan_rx.borrow().clone();
                let diagnose = aux.diagnose.as_ref().map(DiagnoseView::state);
                let snap = probe_rx.borrow_and_update().clone();
                if let Some(snap) = snap {
                    if last_seq == Some(snap.seq) {
                        held = Some(snap);
                        continue;
                    }
                    view.draw(out, &snap, gw.as_ref(), wan.as_ref(), diagnose.as_ref().map(|d| (d, false)))?;
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    // Drain the final snapshot if it raced with shutdown (count mode), then
    // the held line with the diagnosis' last state (`incomplete` if it did
    // not conclude).
    let gw = aux.gateway_rx.borrow().clone();
    let wan = aux.wan_rx.borrow().clone();
    let diagnose = aux.diagnose.as_ref().map(DiagnoseView::state);
    if probe_rx.has_changed().unwrap_or(false)
        && let Some(snap) = probe_rx.borrow_and_update().clone()
    {
        if last_seq == Some(snap.seq) {
            held = Some(snap);
        } else {
            view.draw(
                out,
                &snap,
                gw.as_ref(),
                wan.as_ref(),
                diagnose.as_ref().map(|d| (d, false)),
            )?;
        }
    }
    if let Some(snap) = held {
        view.draw(
            out,
            &snap,
            gw.as_ref(),
            wan.as_ref(),
            diagnose.as_ref().map(|d| (d, true)),
        )?;
    }
    Ok(())
}

fn print_final_summary(out: &mut impl Write, snap: &ProbeSnapshot) -> std::io::Result<()> {
    use crate::render::format::{fmt_loss, fmt_rtt_opt};

    if let Some(port) = snap.port {
        // TCP counts connects and their answers, as the classic summary.
        writeln!(
            out,
            "--- {host} ({ip}) tcp/{port} statistics ---",
            host = snap.target_host,
            ip = snap.target_ip,
        )?;
        writeln!(
            out,
            "{sent} connects, {recv} answered ({refused} refused), {loss} loss",
            sent = snap.sent,
            recv = snap.received,
            refused = snap.refused.unwrap_or(0),
            loss = fmt_loss(snap.loss_pct),
        )?;
    } else {
        writeln!(
            out,
            "--- {host} ({ip}) sping statistics ---",
            host = snap.target_host,
            ip = snap.target_ip,
        )?;
        writeln!(
            out,
            "{sent} sent, {recv} received, {loss} loss",
            sent = snap.sent,
            recv = snap.received,
            loss = fmt_loss(snap.loss_pct),
        )?;
    }
    writeln!(
        out,
        "rtt min/avg/max/mdev = {}/{}/{}/{}{sep}jitter {}",
        fmt_rtt_opt(snap.rtt_min),
        fmt_rtt_opt(snap.rtt_avg),
        fmt_rtt_opt(snap.rtt_max),
        fmt_rtt_opt(snap.mdev),
        fmt_rtt_opt(snap.jitter),
        sep = crate::render::icons::sep(),
    )
}

/// Start the TUI keyboard listener; called from `app.rs` before the renderer.
pub fn start_key_listener(shutdown_tx: watch::Sender<bool>) {
    spawn_key_listener(shutdown_tx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::health::Reachability;
    use crate::render::golden_icmp::replying;

    fn aux(target: &str, reachability: Reachability) -> AuxiliaryState {
        AuxiliaryState {
            label: "probe".into(),
            target: target.parse().unwrap(),
            reachability,
            last_rtt: None,
        }
    }

    /// Output that hands each written chunk to the test, so it can wait for
    /// a line before sending the next snapshot.
    struct LineTap(tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

    impl Write for LineTap {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.send(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// In the loop: each snapshot is printed as it arrives, with the gateway
    /// and WAN state of that moment. The second snapshot is sent only once
    /// the first line is out, after the gateway went offline: two lines (the
    /// final drain prints at most one).
    #[tokio::test]
    async fn json_loop_prints_each_line_with_its_moment() {
        let (probe_tx, probe_rx) = watch::channel(None);
        let (gateway_tx, gateway_rx) = watch::channel(None);
        let (_wan_tx, wan_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (tap_tx, mut tap_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut out = LineTap(tap_tx);
        let channels = AuxChannels {
            gateway_rx,
            wan_rx,
            diagnose: None,
        };

        let driver = async {
            let mut text = Vec::new();
            let mut next_line = async |text: &mut Vec<u8>| {
                let lines = text.iter().filter(|&&b| b == b'\n').count();
                while text.iter().filter(|&&b| b == b'\n').count() == lines {
                    text.extend(tap_rx.recv().await.expect("output closed"));
                }
            };
            let _ = gateway_tx.send(Some(aux("192.168.1.1", Reachability::Online)));
            let _ = probe_tx.send(Some(replying()));
            next_line(&mut text).await;
            let _ = gateway_tx.send(Some(aux("192.168.1.1", Reachability::Offline)));
            let mut second = replying();
            second.seq = 11;
            let _ = probe_tx.send(Some(second));
            next_line(&mut text).await;
            let _ = shutdown_tx.send(true);
            text
        };
        let (written, text) =
            tokio::join!(run_json(&mut out, probe_rx, channels, shutdown_rx), driver);
        written.unwrap();

        let text = String::from_utf8(text).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].contains("\"seq\":10,") && lines[0].contains("\"state\":\"online\""));
        assert!(lines[1].contains("\"seq\":11,") && lines[1].contains("\"state\":\"offline\""));
    }

    /// Snapshot and shutdown ready together, as at the end of `-c N`: tokio
    /// picks a ready branch at random, so the line comes from the loop or
    /// from the final drain. Either way it is the same single line; 32 runs
    /// reach the drain unless chance says no 32 times (2^-32).
    #[tokio::test]
    async fn json_loop_prints_aux_state_and_diagnosis() {
        for _ in 0..32 {
            let (probe_tx, probe_rx) = watch::channel(None);
            let (gateway_tx, gateway_rx) = watch::channel(None);
            let (wan_tx, wan_rx) = watch::channel(None);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let _ = gateway_tx.send(Some(aux("192.168.1.1", Reachability::Online)));
            let _ = wan_tx.send(Some(aux("1.1.1.1", Reachability::Offline)));
            let _ = probe_tx.send(Some(replying()));
            let _ = shutdown_tx.send(true);

            let mut out = Vec::new();
            let aux = AuxChannels {
                gateway_rx,
                wan_rx,
                diagnose: None,
            };
            run_json(&mut out, probe_rx, aux, shutdown_rx)
                .await
                .unwrap();

            let text = String::from_utf8(out).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 1, "{text}");
            assert!(
                lines[0].ends_with(
                    ",\"gateway\":{\"target\":\"192.168.1.1\",\"state\":\"online\",\"rtt_last\":null},\"wan\":{\"target\":\"1.1.1.1\",\"state\":\"offline\",\"rtt_last\":null},\"diagnosis\":[{\"code\":\"intermittent_loss\",\"recent_loss_pct\":10.0},{\"code\":\"wan_degraded\"}]}"
                ),
                "{}",
                lines[0]
            );
        }
    }

    /// A diagnosis about another address than the probe's (a failover it had
    /// not applied yet) shows as nothing in the frames and the summary; next
    /// to its own address, as it is.
    #[test]
    fn a_diagnosis_shows_only_next_to_its_address() {
        use crate::diagnostics::planner::{Concluded, Conclusion, Diagnosis};
        let diagnosed: IpAddr = "198.51.100.7".parse().unwrap();
        let probed: IpAddr = "198.51.100.8".parse().unwrap();
        let done = DiagnoseState::Done {
            target: diagnosed,
            diagnosis: std::sync::Arc::new(Diagnosis {
                conclusions: vec![Concluded {
                    conclusion: Conclusion::TargetAnswersIcmp { ttl: 2 },
                    because: vec![],
                }],
                gaps: vec![],
                evidence: vec![],
            }),
        };
        for state in [done, DiagnoseState::Diagnosing { target: diagnosed }] {
            let (_state_tx, state_rx) = watch::channel(state.clone());
            let view = DiagnoseView {
                state_rx,
                last_seq: None,
            };
            assert_eq!(view.state_about(diagnosed), state);
            assert_eq!(view.state_about(probed), DiagnoseState::Idle, "{state:?}");
            let summary =
                |ip| crate::render::format::diagnosis_summary(&view.state_about(ip), ", ");
            assert_eq!(summary(probed), None, "{state:?}");
            let expected = match state {
                DiagnoseState::Done { .. } => "diagnosis: target answers the trace at hop 2",
                _ => "diagnosis incomplete",
            };
            assert_eq!(summary(diagnosed).as_deref(), Some(expected));
        }
    }

    /// With `-c N` and `--diagnose`, the line of probe N waits for the
    /// diagnosis' last state: `done` if it concluded, else `incomplete`;
    /// still one line per probe.
    #[tokio::test]
    async fn json_holds_the_last_probe_for_the_diagnosis() {
        use crate::diagnostics::planner::Diagnosis;
        let target: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        for concluded in [true, false] {
            let (probe_tx, probe_rx) = watch::channel(None);
            let (_gateway_tx, gateway_rx) = watch::channel(None);
            let (_wan_tx, wan_rx) = watch::channel(None);
            let (state_tx, state_rx) = watch::channel(DiagnoseState::Diagnosing { target });
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (tap_tx, mut tap_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut out = LineTap(tap_tx);
            let channels = AuxChannels {
                gateway_rx,
                wan_rx,
                diagnose: Some(DiagnoseView {
                    state_rx,
                    last_seq: Some(11),
                }),
            };

            let driver = async {
                let mut text = Vec::new();
                let _ = probe_tx.send(Some(replying()));
                while !text.contains(&b'\n') {
                    text.extend(tap_rx.recv().await.expect("output closed"));
                }
                let mut last = replying();
                last.seq = 11;
                let _ = probe_tx.send(Some(last));
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                }
                assert!(tap_rx.try_recv().is_err(), "the last line did not wait");
                if concluded {
                    let _ = state_tx.send(DiagnoseState::Done {
                        target,
                        diagnosis: std::sync::Arc::new(Diagnosis {
                            conclusions: vec![],
                            gaps: vec![],
                            evidence: vec![],
                        }),
                    });
                }
                let _ = shutdown_tx.send(true);
                text
            };
            let (written, mut text) =
                tokio::join!(run_json(&mut out, probe_rx, channels, shutdown_rx), driver);
            written.unwrap();
            while let Ok(chunk) = tap_rx.try_recv() {
                text.extend(chunk);
            }

            let text = String::from_utf8(text).unwrap();
            let lines: Vec<serde_json::Value> = text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            assert_eq!(lines.len(), 2, "{text}");
            assert_eq!(lines[0]["seq"], 10);
            assert_eq!(lines[0]["active_diagnosis"]["state"], "diagnosing");
            assert_eq!(lines[1]["seq"], 11);
            let state = if concluded { "done" } else { "incomplete" };
            assert_eq!(lines[1]["active_diagnosis"]["state"], state, "{text}");
        }
    }

    /// A stdout that cannot be written, as a file on a full disk.
    struct Full;

    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::StorageFull.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A write that fails ends the classic and JSON renderers with its
    /// error, in the loop and, when the shutdown comes first, in what is
    /// written after it: the last snapshot and the summary, which is all
    /// that classic writes with `-q`. Those last writes were not looked at.
    /// A closed pipe is not an error for the caller.
    #[tokio::test]
    async fn a_write_that_fails_is_the_renderers_error() {
        use std::io::ErrorKind::{BrokenPipe, StorageFull};

        // A snapshot and the shutdown, both there before the renderer
        // starts: which of the two it sees first is not decided.
        let (probe_tx, probe_rx) = watch::channel(None);
        let (_gateway_tx, gateway_rx) = watch::channel(None);
        let (_wan_tx, wan_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let _ = probe_tx.send(Some(replying()));
        let _ = shutdown_tx.send(true);

        for _ in 0..32 {
            for quiet in [false, true] {
                let written = run_classic(
                    &mut Full,
                    probe_rx.clone(),
                    None,
                    shutdown_rx.clone(),
                    quiet,
                )
                .await;
                assert_eq!(written.map_err(|e| e.kind()), Err(StorageFull), "{quiet}");
            }
            let aux = AuxChannels {
                gateway_rx: gateway_rx.clone(),
                wan_rx: wan_rx.clone(),
                diagnose: None,
            };
            let written = run_json(&mut Full, probe_rx.clone(), aux, shutdown_rx.clone()).await;
            assert_eq!(written.map_err(|e| e.kind()), Err(StorageFull));
        }

        let passed = |kind: std::io::ErrorKind| unless_reader_gone(Err(kind.into()));
        assert!(passed(BrokenPipe).is_ok());
        assert_eq!(passed(StorageFull).map_err(|e| e.kind()), Err(StorageFull));
        assert!(unless_reader_gone(Ok(())).is_ok());
    }

    /// The summary of each of several targets, all that is written when
    /// stdout is not a terminal, tells of the write that fails: it was not
    /// looked at.
    #[test]
    fn a_summary_that_cannot_be_written_is_an_error() {
        for snap in [replying(), crate::render::golden_tcp::open()] {
            let written = print_final_summary(&mut Full, &snap);
            assert_eq!(
                written.map_err(|e| e.kind()),
                Err(std::io::ErrorKind::StorageFull)
            );
        }
    }

    /// Clear-screen and cursor-home, as `InlineFrame` writes them.
    const CLEARED: &str = "\x1b[2J\x1b[1;1H";

    /// A two-line frame that records the lines it was asked to move up over.
    fn frame(
        asked: &mut Vec<u16>,
    ) -> impl FnOnce(&mut Vec<u8>, Placement) -> std::io::Result<u16> + '_ {
        |out, place| {
            asked.push(place.lines_before);
            out.extend_from_slice(b"one\r\ntwo\r\n");
            Ok(2)
        }
    }

    /// A frame moves up over the previous one while the width stays; after a
    /// change, narrower or wider, it starts at the top of a cleared screen,
    /// in the same write. The first frame, and a terminal that reports no
    /// width, never clear.
    #[test]
    fn a_width_change_redraws_the_frame_on_a_cleared_screen() {
        let mut inline = InlineFrame::new();
        let mut asked = Vec::new();
        let mut writes = Vec::new();
        for width in [80, 80, 50, 50, 120, 120] {
            let mut out = Vec::new();
            inline.draw_at(&mut out, Some(width), 0, frame(&mut asked));
            writes.push(String::from_utf8(out).unwrap());
        }
        assert_eq!(asked, [0, 2, 0, 2, 0, 2]);
        let cleared: Vec<bool> = writes.iter().map(|w| w.starts_with(CLEARED)).collect();
        assert_eq!(cleared, [false, false, true, false, true, false]);
        assert_eq!(writes[2], format!("{CLEARED}one\r\ntwo\r\n"));

        let mut inline = InlineFrame::new();
        let mut asked = Vec::new();
        for width in [Some(0), Some(0), Some(80), Some(0)] {
            let mut out = Vec::new();
            inline.draw_at(&mut out, width, 0, frame(&mut asked));
            assert!(
                !String::from_utf8(out).unwrap().contains(CLEARED),
                "{width:?}"
            );
        }
        assert_eq!(asked, [0, 2, 2, 2]);
    }

    /// A frame shorter than the one before it erases the rows that one left
    /// below: the extended view loses its `RTT dist` line once the pulse
    /// holds fewer than three replies, and the old last row stayed on screen.
    #[test]
    fn a_shorter_frame_erases_what_the_longer_one_left_below() {
        let replying = crate::render::golden_icmp::replying();
        let mut down = replying.clone();
        down.pulse = vec![crate::probe::types::PulseEntry::Loss; 40];

        let mut inline = InlineFrame::new();
        let mut lines = Vec::new();
        let mut writes = Vec::new();
        for snap in [&replying, &down] {
            let mut out = Vec::new();
            inline.draw_at(&mut out, Some(120), 0, |frame, place| {
                view_extended::draw_inline(frame, snap, None, None, None, 0, place)
            });
            lines.push(inline.lines);
            writes.push(String::from_utf8(out).unwrap());
        }
        assert_eq!(lines, [10, 9]);
        // Up over the ten lines, nine drawn, and from the tenth down erased.
        assert!(writes[1].starts_with("\x1b[10A"), "{:?}", writes[1]);
        assert!(writes[1].ends_with("\r\n\x1b[J\x1b[?7h"), "{:?}", writes[1]);
    }

    /// A frame is cut to the lines the terminal has rows for, leaving one for
    /// the cursor, and the next one moves up over the lines really drawn: a
    /// frame of more lines scrolled the screen on every redraw. Shorter and
    /// taller again between frames, as when the window is resized.
    #[test]
    fn a_frame_taller_than_the_terminal_is_cut_to_its_rows() {
        let snap = crate::render::golden_icmp::replying();
        let mut inline = InlineFrame::new();
        let mut drawn = Vec::new();
        // The compact view has 8 lines; 0 rows is a height not reported.
        for rows in [30, 9, 8, 4, 1, 4, 30, 0] {
            let mut out = Vec::new();
            inline.draw_at(&mut out, Some(120), rows, |frame, place| {
                view_compact::draw_inline(frame, &snap, None, None, None, 0, place)
            });
            let newlines = out.iter().filter(|&&b| b == b'\n').count();
            assert_eq!(newlines, usize::from(inline.lines), "{rows} rows");
            let text = String::from_utf8(out).unwrap();
            let up = text
                .strip_prefix("\x1b[")
                .and_then(|rest| rest.split_once('A'))
                .and_then(|(n, _)| n.parse::<u16>().ok());
            drawn.push((inline.lines, up));
        }
        assert_eq!(
            drawn,
            [
                (8, None),
                (8, Some(8)),
                (7, Some(8)),
                (3, Some(7)),
                (0, Some(3)),
                (3, None),
                (8, Some(3)),
                (8, Some(8)),
            ]
        );
    }

    /// A frame that fails to write counts as no lines: the next one does not
    /// move up over it.
    #[test]
    fn a_frame_that_fails_to_write_counts_as_no_lines() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut inline = InlineFrame::new();
        let mut asked = Vec::new();
        inline.draw_at(&mut Broken, Some(80), 0, frame(&mut asked));
        inline.draw_at(&mut Vec::new(), Some(80), 0, frame(&mut asked));
        assert_eq!(asked, [0, 0]);
    }
}
