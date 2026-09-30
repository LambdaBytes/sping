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

/// Latest gateway and WAN auxiliary probe states shown by the TUI views.
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
        ViewMode::Json => run_json(&mut out, probe_rx, shutdown).await,
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
    out: &mut Stdout,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
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
                if let Some(snap) = probe_rx.borrow_and_update().as_ref()
                    && let Err(e) = view.draw(out, snap)
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
    if probe_rx.has_changed().unwrap_or(false)
        && let Some(snap) = probe_rx.borrow_and_update().as_ref()
    {
        let _ = view.draw(out, snap);
    }
}

fn print_final_summary(snap: &ProbeSnapshot) {
    use crate::render::format::{fmt_loss, fmt_rtt_opt};

    // EPIPE-safe: never panic if stdout is gone.
    let mut out = stdout();
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
