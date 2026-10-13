//! Render-loop drivers for all view modes. TUI views enable raw mode and
//! capture Ctrl+C / `q` via crossterm events; classic and JSON stream
//! without raw mode and treat `BrokenPipe` as a normal downstream exit.

use std::io::{Stdout, Write, stdout};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use tokio::sync::watch;

use crate::config::ViewMode;
use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::types::ProbeSnapshot;
use crate::render::view_classic::ClassicView;
use crate::render::view_compact;
use crate::render::view_extended;
use crate::render::view_json::JsonView;
use crate::render::view_table;
use crate::runtime::frame_clock::FrameClock;

/// Latest gateway and WAN auxiliary probe states shown by the TUI views and
/// the JSON lines.
pub struct AuxChannels {
    pub gateway_rx: watch::Receiver<Option<AuxiliaryState>>,
    pub wan_rx: watch::Receiver<Option<AuxiliaryState>>,
}

/// Listen for Ctrl+C / `q` via crossterm events; send `true` on shutdown.
fn spawn_key_listener(shutdown_tx: watch::Sender<bool>) {
    tokio::task::spawn_blocking(move || {
        loop {
            // 100ms poll so externally-requested shutdown is noticed promptly.
            if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false)
                && let Ok(ev) = event::read()
            {
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
pub async fn run(
    view: ViewMode,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    aux: AuxChannels,
    shutdown: watch::Receiver<bool>,
    quiet: bool,
) {
    let mut out = stdout();

    match view {
        ViewMode::Classic => run_classic(&mut out, probe_rx, shutdown, quiet).await,
        ViewMode::Json => run_json(&mut out, probe_rx, aux, shutdown).await,
        _ => {
            let extended = matches!(view, ViewMode::Extended);
            run_tui(&mut out, probe_rx, aux, shutdown, extended).await;
        }
    }
}

/// Multi-target table renderer: raw-mode TUI loop, then per-target
/// summaries on shutdown.
pub async fn run_table(
    probe_rxs: Vec<watch::Receiver<Option<ProbeSnapshot>>>,
    shutdown: watch::Receiver<bool>,
) {
    let mut out = stdout();

    // Raw mode: blocks Enter, mouse scroll, captures Ctrl+C via event reader
    let _ = terminal::enable_raw_mode();

    let mut clock = FrameClock::default();
    let mut spinner: usize = 0;
    let mut lines_drawn: u16 = 0;
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            _ = clock.tick() => {
                spinner += 1;
                let snapshots: Vec<Option<ProbeSnapshot>> = probe_rxs
                    .iter()
                    .map(|rx| rx.borrow().clone())
                    .collect();
                lines_drawn = view_table::draw_table(&mut out, &snapshots, spinner, lines_drawn).unwrap_or(0);
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    let _ = terminal::disable_raw_mode();
    let _ = writeln!(out);
    for rx in &probe_rxs {
        if let Some(snap) = rx.borrow().as_ref() {
            print_final_summary(snap);
        }
    }
    let _ = out.flush();
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
    let mut lines_drawn: u16 = 0;
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            _ = clock.tick() => {
                spinner += 1;
                if let Some(snap) = probe_rx.borrow().as_ref() {
                    let gw = aux.gateway_rx.borrow().clone();
                    let wan = aux.wan_rx.borrow().clone();

                    if extended {
                        lines_drawn = view_extended::draw_inline(out, snap, gw.as_ref(), wan.as_ref(), spinner, lines_drawn).unwrap_or(0);
                    } else {
                        lines_drawn = view_compact::draw_inline(out, snap, gw.as_ref(), wan.as_ref(), spinner, lines_drawn).unwrap_or(0);
                    }
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
        print_final_summary(snap);
    }
    let _ = out.flush();
}

async fn run_classic(
    out: &mut Stdout,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    shutdown: watch::Receiver<bool>,
    quiet: bool,
) {
    // Scrolling output: no raw mode.
    let mut view = ClassicView::new();
    let mut last_snap: Option<ProbeSnapshot> = None;
    let mut probe_rx = probe_rx;
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            result = probe_rx.changed() => {
                if result.is_err() { break; }
                if let Some(snap) = probe_rx.borrow_and_update().as_ref() {
                    if !quiet && let Err(e) = view.draw(out, snap) {
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            // Downstream consumer went away (e.g. `sping x | head`).
                            return;
                        }
                        // Any other persistent stdout failure: report and stop.
                        eprintln!("error: cannot write to stdout: {e}");
                        return;
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
            let _ = view.draw(out, snap);
        }
        last_snap = Some(snap.clone());
    }

    if let Some(snap) = last_snap.as_ref() {
        let _ = view.summary(out, snap);
    }
}

async fn run_json(
    out: &mut impl Write,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    aux: AuxChannels,
    shutdown: watch::Receiver<bool>,
) {
    // Streaming output: no raw mode.
    let mut view = JsonView::new();
    let mut probe_rx = probe_rx;
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            result = probe_rx.changed() => {
                if result.is_err() { break; }
                // The gateway and WAN state of this moment: shown in the line
                // and the source of its diagnosis.
                let gw = aux.gateway_rx.borrow().clone();
                let wan = aux.wan_rx.borrow().clone();
                if let Some(snap) = probe_rx.borrow_and_update().as_ref()
                    && let Err(e) = view.draw(out, snap, gw.as_ref(), wan.as_ref())
                {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        eprintln!("error: cannot write to stdout: {e}");
                    }
                    return;
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    // Drain the final snapshot if it raced with shutdown (count mode).
    let gw = aux.gateway_rx.borrow().clone();
    let wan = aux.wan_rx.borrow().clone();
    if probe_rx.has_changed().unwrap_or(false)
        && let Some(snap) = probe_rx.borrow_and_update().as_ref()
    {
        let _ = view.draw(out, snap, gw.as_ref(), wan.as_ref());
    }
}

fn print_final_summary(snap: &ProbeSnapshot) {
    use crate::render::format::{fmt_loss, fmt_rtt_opt};

    // EPIPE-safe: never panic if stdout is gone.
    let mut out = stdout();
    if let Some(port) = snap.port {
        // TCP counts connects and their answers, as the classic summary.
        let _ = writeln!(
            out,
            "--- {host} ({ip}) tcp/{port} statistics ---",
            host = snap.target_host,
            ip = snap.target_ip,
        );
        let _ = writeln!(
            out,
            "{sent} connects, {recv} answered ({refused} refused), {loss} loss",
            sent = snap.sent,
            recv = snap.received,
            refused = snap.refused.unwrap_or(0),
            loss = fmt_loss(snap.loss_pct),
        );
    } else {
        let _ = writeln!(
            out,
            "--- {host} ({ip}) sping statistics ---",
            host = snap.target_host,
            ip = snap.target_ip,
        );
        let _ = writeln!(
            out,
            "{sent} sent, {recv} received, {loss} loss",
            sent = snap.sent,
            recv = snap.received,
            loss = fmt_loss(snap.loss_pct),
        );
    }
    let _ = writeln!(
        out,
        "rtt min/avg/max/mdev = {}/{}/{}/{}{sep}jitter {}",
        fmt_rtt_opt(snap.rtt_min),
        fmt_rtt_opt(snap.rtt_avg),
        fmt_rtt_opt(snap.rtt_max),
        fmt_rtt_opt(snap.mdev),
        fmt_rtt_opt(snap.jitter),
        sep = crate::render::icons::sep(),
    );
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
        let channels = AuxChannels { gateway_rx, wan_rx };

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
        let ((), text) = tokio::join!(run_json(&mut out, probe_rx, channels, shutdown_rx), driver);

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
            let aux = AuxChannels { gateway_rx, wan_rx };
            run_json(&mut out, probe_rx, aux, shutdown_rx).await;

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
}
