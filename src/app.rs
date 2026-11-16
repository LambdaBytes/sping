//! Orchestration: wires DNS, context detection, schedulers, GW/WAN probes
//! and the renderer for single/multi/batch modes. Exit codes 0/1/2.

use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::watch;

use crate::config::{Config, ViewMode};
use crate::context;
use crate::context::dns;
use crate::probe::types::ProbeSnapshot;
use crate::probe::{auxiliary, batch, diagnose, scheduler};
use crate::render::format::fmt_source;
use crate::render::icons;
use crate::render::terminal::{self, AuxChannels, DiagnoseView};
use crate::runtime::bus::Bus;

const AUX_PROBE_INTERVAL: Duration = Duration::from_secs(3);
/// How often the network context (interface/gateway) is re-detected.
const CTX_REDETECT_INTERVAL: Duration = Duration::from_secs(15);

/// At least one reply received.
pub const EXIT_OK: i32 = 0;
/// Probes sent but no replies arrived.
pub const EXIT_NO_REPLY: i32 = 1;
/// Usage or runtime error.
pub const EXIT_ERROR: i32 = 2;

/// `sping --ip`: the host's addresses, as text or one JSON object, and with
/// `external` (`--external SERVER[:PORT]`) what that STUN server saw. Exit 0
/// once they are read (a missing source or gateway, or an external address
/// not told, is said in the view), 2 when they cannot be read or the server
/// is not one.
pub async fn show_host_addresses(json: bool, external: Option<&str>) -> i32 {
    let server = match external.map(context::stun::parse_server).transpose() {
        Ok(server) => server,
        Err(e) => {
            eprintln!("error: --external {e}");
            return EXIT_ERROR;
        }
    };
    let view = match context::addresses::read() {
        Ok(view) => view,
        Err(e) => {
            eprintln!("error: cannot read the host's addresses: {e}");
            return EXIT_ERROR;
        }
    };
    let external = match server {
        Some((host, port)) => Some(context::stun::external(&host, port).await),
        None => None,
    };
    let out = if json {
        match crate::render::view_ip::json(&view, external.as_ref()) {
            Ok(line) => line + "\n",
            Err(e) => {
                eprintln!("error: cannot serialize the host's addresses: {e}");
                return EXIT_ERROR;
            }
        }
    } else {
        crate::render::view_ip::text(&view, external.as_ref(), icons::sep())
    };
    match std::io::stdout().lock().write_all(out.as_bytes()) {
        // A closed pipe (`sping --ip | head -1`) is not an error.
        Ok(()) => EXIT_OK,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => EXIT_OK,
        Err(e) => {
            eprintln!("error: cannot write the host's addresses: {e}");
            EXIT_ERROR
        }
    }
}

/// `sping --list-interfaces`: each interface's IPv4 address, one per line.
/// Exit 0, also when the reader went away; 2 when stdout cannot be written.
pub fn show_interfaces() -> i32 {
    let ifaces = context::iface::list_interfaces();
    let mut out = String::new();
    if ifaces.is_empty() {
        out.push_str("No interfaces detected.\n");
    }
    for iface in &ifaces {
        out.push_str(&format!(
            "{:<16} {}/{}\n",
            iface.name, iface.ip, iface.prefix_len
        ));
    }
    match std::io::stdout().lock().write_all(out.as_bytes()) {
        // A closed pipe (`sping --list-interfaces | head -1`) is not an error.
        Ok(()) => EXIT_OK,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => EXIT_OK,
        Err(e) => {
            eprintln!("error: cannot write the interfaces: {e}");
            EXIT_ERROR
        }
    }
}

/// Listen for Ctrl+C (and SIGTERM on Unix) and trigger shutdown.
/// In raw-mode TUI views Ctrl+C arrives via the key listener instead,
/// but SIGTERM (systemd, kill) still lands here.
fn spawn_signal_listener(tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            match signal(SignalKind::terminate()) {
                Ok(mut term) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = tx.send(true);
    });
}

fn eprint_socket_error(e: &std::io::Error) {
    eprintln!("error: failed to create ICMP socket: {e}");
    crate::backends::eprint_icmp_hint();
    #[cfg(target_os = "windows")]
    eprintln!("hint: try running as Administrator");
}

/// Before probing: an ICMP socket opens (else the permission hint) and every
/// target's probe can be prepared as the scheduler will (ICMP or, with
/// `--tcp`, TCP: source address, TTL). A failure is a local error, reported
/// once: the caller exits with `EXIT_ERROR`. With no targets yet (batch,
/// before resolving) only the ICMP socket is checked, without `--tcp`.
fn precheck(cfg: &Config, targets: &[dns::ResolvedAddr]) -> bool {
    if cfg.tcp_port.is_none() {
        if let Err(e) = crate::backends::IcmpBackend::new() {
            eprint_socket_error(&e);
            return false;
        }
        for &target in targets {
            if let Err(e) = scheduler::create_backend(&cfg.probe_options(target)) {
                eprintln!("error: cannot prepare the ICMP probe of {}: {e}", target.ip);
                return false;
            }
        }
        return true;
    }
    for &target in targets {
        if let Err(e) = crate::backends::tcp::TcpProber::new(&cfg.probe_options(target)) {
            eprintln!("error: cannot prepare the TCP probe of {}: {e}", target.ip);
            return false;
        }
    }
    true
}

fn exit_code_for(received: u64) -> i32 {
    if received > 0 { EXIT_OK } else { EXIT_NO_REPLY }
}

/// What a spawned task returned; `None` when it panicked, which is said on
/// stderr and is for the caller an error, not the exit code of the replies.
fn joined<T>(task: &str, result: Result<T, tokio::task::JoinError>) -> Option<T> {
    result
        .inspect_err(|e| eprintln!("error: the {task} stopped: {e}"))
        .ok()
}

/// Several targets, by the replies each received: `EXIT_OK` only if every
/// one of them answered. `unresolved`: a name among those asked for did not
/// resolve, which is a target with no replies.
fn exit_code_for_all(received: impl IntoIterator<Item = u64>, unresolved: bool) -> i32 {
    let mut received = received.into_iter().peekable();
    let all_replied = received.peek().is_some() && received.all(|r| r > 0);
    if all_replied && !unresolved {
        EXIT_OK
    } else {
        EXIT_NO_REPLY
    }
}

/// Single-target mode: one scheduler plus GW/WAN auxiliary probes feeding
/// the selected view. Returns the process exit code.
///
/// # Errors
///
/// Fails on DNS resolution failure and when the classic or JSON view
/// cannot write to stdout; socket failures yield `Ok(EXIT_ERROR)` instead.
pub async fn run(cfg: Config) -> anyhow::Result<i32> {
    eprintln!();

    let target = &cfg.targets[0];

    if !dns::is_literal(target) {
        eprint!("Resolving {target}...");
    }
    let (target_addr, dns_time) = dns::resolve(target, cfg.family).await?;
    let target_ip = target_addr.ip;
    if let Some(dt) = dns_time {
        eprintln!(" {} ({:.1} ms)", target_ip, dt.as_secs_f64() * 1000.0);
    }

    let sep = icons::sep();
    let dash = icons::dash();
    let net_ctx = context::detect(target_addr);
    let bold = if icons::use_color_stderr() {
        ("\x1b[1m", "\x1b[0m")
    } else {
        ("", "")
    };
    let mut target_label = if net_ctx.target_class == context::classify::TargetClass::DefaultGateway
    {
        format!("target {}{}{} (default gateway)", bold.0, target_ip, bold.1)
    } else {
        format!("target {}{}{}", bold.0, target_ip, bold.1)
    };
    if let Some(port) = cfg.tcp_port {
        target_label.push_str(&format!(" tcp/{port}"));
    }
    eprintln!(
        "Init: {}{sep}gw {}{sep}{}{sep}{}",
        fmt_source(&net_ctx, target_ip, sep),
        net_ctx.gateway.as_deref().unwrap_or(dash),
        target_label,
        net_ctx.target_class,
    );

    // Pre-check the probe before entering raw mode.
    if !precheck(&cfg, &[target_addr]) {
        return Ok(EXIT_ERROR);
    }

    let bus = Bus::new();
    let is_tui = matches!(cfg.view, ViewMode::Compact | ViewMode::Extended);

    // Key listener only in raw-mode TUI views.
    if is_tui {
        terminal::start_key_listener(bus.shutdown_sender());
    }
    spawn_signal_listener(bus.shutdown_sender());

    // Hot context re-detection: a watch channel feeds interface/gateway
    // changes (WiFi → Ethernet, VPN up/down) to the scheduler and retargets
    // the GW auxiliary probe. The scheduler reports a DNS failover through
    // `target_tx`: the context is always that of the address being probed.
    let (ctx_tx, ctx_rx) = watch::channel(context::Detected {
        target: target_addr,
        context: net_ctx.clone(),
    });
    let (target_tx, mut target_rx) = watch::channel(target_addr);
    // `--diagnose`: the diagnosis follows the same address and context.
    let diagnose_inputs = cfg.diagnose.then(|| diagnose::Inputs {
        probe_rx: bus.subscribe_probe(),
        target_rx: target_tx.subscribe(),
        ctx_rx: ctx_tx.subscribe(),
    });
    // The GW probe's target: none until this host has a default gateway. One
    // that appears later starts the probe, another retargets it; when the
    // gateway goes, the probe keeps the last one.
    let (gw_target_tx, gw_target_rx) = watch::channel(
        net_ctx
            .gateway
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok()),
    );

    {
        let mut shutdown_rx = bus.subscribe_shutdown();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CTX_REDETECT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    // A DNS failover moved the target: its context is stale.
                    moved = target_rx.changed() => {
                        // The scheduler is gone: nothing left to keep current.
                        if moved.is_err() { return; }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { return; }
                        continue;
                    }
                }
                let current = *target_rx.borrow_and_update();
                // detect() reads /proc or runs external tools — keep it
                // off the async runtime.
                let detected = tokio::task::spawn_blocking(move || context::detect(current)).await;
                // Sent with the address it was detected for: the scheduler
                // takes it only for the address it probes then.
                let new = detected.map(|context| context::Detected {
                    target: current,
                    context,
                });
                if let Ok(new) = new
                    && *ctx_tx.borrow() != new
                {
                    let new_ctx = &new.context;
                    if let Some(gw_ip) = new_ctx
                        .gateway
                        .as_deref()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                    {
                        let _ = gw_target_tx.send(Some(gw_ip));
                    }
                    let _ = ctx_tx.send(new);
                }
            }
        });
    }

    let probe_tx = bus.probe_sender();
    let shutdown_rx = bus.subscribe_shutdown();
    let target_host = target.clone();
    let interval = cfg.interval;
    let ctx = Some(net_ctx.clone());
    let opts = cfg.probe_options(target_addr);
    let count = cfg.count;
    let scheduler_handle = tokio::spawn(async move {
        scheduler::run(
            target_host,
            target_ip,
            dns_time,
            ctx,
            interval,
            opts,
            count,
            probe_tx,
            shutdown_rx,
            Some(ctx_rx),
            Some(target_tx),
        )
        .await;
    });

    // `--diagnose`: the planner runs next to the probe; its state goes to
    // the views.
    let (diagnose_state_tx, diagnose_state_rx) = watch::channel(diagnose::DiagnoseState::Idle);
    let diagnosis = diagnose_inputs.map(|inputs| {
        let extra = diagnose::Extra::from_config(&cfg);
        let planner = crate::diagnostics::planner::Planner::new(extra.scope());
        let budget = extra.budget();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(diagnose::run(
            planner,
            diagnose::Executor::new(extra),
            inputs,
            budget,
            finished_rx,
            bus.subscribe_shutdown(),
            diagnose_state_tx,
        ));
        (finished_tx, handle)
    });

    // When the scheduler finishes (count reached or socket error), shut down
    // the renderer so the summary prints and the process exits. With
    // `--diagnose`, the diagnosis in progress gets the rest of its budget
    // first and publishes its last state: the renderer reads it after the
    // shutdown.
    {
        let shutdown_tx = bus.shutdown_sender();
        tokio::spawn(async move {
            let _ = scheduler_handle.await;
            if let Some((finished_tx, handle)) = diagnosis {
                let _ = finished_tx.send(());
                let _ = handle.await;
            }
            let _ = shutdown_tx.send(true);
        });
    }

    // GW probe, started and retargeted via the context watcher: it waits
    // while there is no gateway.
    {
        let tx = bus.gateway_sender();
        let shutdown_rx = bus.subscribe_shutdown();
        tokio::spawn(async move {
            auxiliary::run(
                "GW".into(),
                gw_target_rx,
                AUX_PROBE_INTERVAL,
                tx,
                shutdown_rx,
            )
            .await;
        });
    }

    // WAN probe (fixed target).
    {
        let tx = bus.wan_sender();
        let shutdown_rx = bus.subscribe_shutdown();
        // The sender is dropped on purpose: the WAN target never changes, and
        // watch receivers keep serving the last value after the sender drops.
        let (_wan_tx, wan_rx) = watch::channel(Some(cfg.wan_probe));
        tokio::spawn(async move {
            auxiliary::run("WAN".into(), wan_rx, AUX_PROBE_INTERVAL, tx, shutdown_rx).await;
        });
    }

    let probe_rx = bus.subscribe_probe();
    let shutdown_rx = bus.subscribe_shutdown();
    let aux = AuxChannels {
        gateway_rx: bus.subscribe_gateway(),
        wan_rx: bus.subscribe_wan(),
        diagnose: cfg.diagnose.then(|| DiagnoseView {
            state_rx: diagnose_state_rx,
            last_seq: cfg.count,
        }),
    };
    let view = cfg.view;
    let quiet = cfg.quiet;

    if is_tui {
        let renderer = tokio::spawn(async move {
            // Frames on a terminal: nothing to report.
            let _ = terminal::run(view, probe_rx, aux, shutdown_rx, quiet).await;
        });
        if joined("renderer", renderer.await).is_none() {
            return Ok(EXIT_ERROR);
        }
    } else if let Err(e) = terminal::run(view, probe_rx, aux, shutdown_rx, quiet).await {
        anyhow::bail!("cannot write to stdout: {e}");
    }

    let received = bus
        .subscribe_probe()
        .borrow()
        .as_ref()
        .map(|s| s.received)
        .unwrap_or(0);
    Ok(exit_code_for(received))
}

/// Multi-target dashboard mode: one scheduler per target rendered as a
/// table. Returns `EXIT_OK` only if every target received replies; a name
/// that does not resolve is one that received none.
///
/// # Errors
///
/// Fails when no target resolves and when the summaries cannot be written
/// to a stdout that is not a terminal; individual failures and duplicate
/// IPs are skipped.
pub async fn run_multi(cfg: Config) -> anyhow::Result<i32> {
    eprintln!();

    let mut resolved = Vec::new();
    let mut unresolved = false;
    // Address and zone together: the same link-local address in two zones
    // is two different hosts.
    let mut seen_addrs = std::collections::HashSet::new();

    for target in &cfg.targets {
        if !dns::is_literal(target) {
            eprint!("Resolving {target}...");
        }
        match dns::resolve(target, cfg.family).await {
            Ok((addr, dns_time)) => {
                let ip = addr.ip;
                if let Some(dt) = dns_time {
                    eprintln!(" {} ({:.1} ms)", ip, dt.as_secs_f64() * 1000.0);
                }
                if seen_addrs.contains(&addr) {
                    eprintln!("note: {target} resolves to {ip} (duplicate, skipping)");
                } else {
                    seen_addrs.insert(addr);
                    resolved.push((target.clone(), addr, dns_time));
                }
            }
            Err(e) => {
                eprintln!("warning: skipping {target}: {e}");
                unresolved = true;
            }
        }
    }

    if resolved.is_empty() {
        anyhow::bail!("no targets could be resolved");
    }

    // Pre-check the probe before entering raw mode.
    let addrs: Vec<_> = resolved.iter().map(|(_, addr, _)| *addr).collect();
    if !precheck(&cfg, &addrs) {
        return Ok(EXIT_ERROR);
    }

    let sep = icons::sep();
    let dash = icons::dash();
    // Each target has its own context; the Init line shows the first one's.
    let contexts = context::detect_all(&addrs);
    let net_ctx = &contexts[0];
    eprintln!(
        "Init: {}{sep}gw {}{sep}{} targets{}",
        fmt_source(net_ctx, addrs[0].ip, sep),
        net_ctx.gateway.as_deref().unwrap_or(dash),
        resolved.len(),
        cfg.tcp_port
            .map(|p| format!(" tcp/{p}"))
            .unwrap_or_default(),
    );

    // The renderer's receiver, kept from here on: a shutdown sent with no
    // receiver left is lost, and every scheduler may end (`-c N`) before the
    // renderer starts.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // The live table, or with stdout not a terminal (`Config::from_args`)
    // only each target's summary at the end: no raw mode, no keys to read.
    let live = cfg.view == ViewMode::Table;
    if live {
        terminal::start_key_listener(shutdown_tx.clone());
    }
    spawn_signal_listener(shutdown_tx.clone());

    let mut probe_rxs: Vec<watch::Receiver<Option<ProbeSnapshot>>> = Vec::new();
    let mut scheduler_handles = Vec::new();

    for ((target_host, target_addr, dns_time), net_ctx) in resolved.iter().zip(&contexts) {
        let (probe_tx, probe_rx) = watch::channel(None);
        probe_rxs.push(probe_rx);

        let target_host = target_host.clone();
        let target_ip = target_addr.ip;
        let dns_time = *dns_time;
        let ctx = Some(net_ctx.clone());
        let interval = cfg.interval;
        let opts = cfg.probe_options(*target_addr);
        let count = cfg.count;
        let shutdown_rx = shutdown_tx.subscribe();

        scheduler_handles.push(tokio::spawn(async move {
            scheduler::run(
                target_host,
                target_ip,
                dns_time,
                ctx,
                interval,
                opts,
                count,
                probe_tx,
                shutdown_rx,
                None,
                None,
            )
            .await;
        }));
    }

    // Shut down once every scheduler finished (count mode or errors).
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            for handle in scheduler_handles {
                let _ = handle.await;
            }
            let _ = shutdown_tx.send(true);
        });
    }

    // Keep receivers to compute the exit code after the renderer is done.
    let final_rxs = probe_rxs.clone();

    let renderer =
        tokio::spawn(async move { terminal::run_table(probe_rxs, shutdown_rx, live).await });

    match joined("renderer", renderer.await) {
        None => return Ok(EXIT_ERROR),
        Some(Err(e)) => anyhow::bail!("cannot write to stdout: {e}"),
        Some(Ok(())) => {}
    }

    let received = final_rxs
        .iter()
        .map(|rx| rx.borrow().as_ref().map_or(0, |s| s.received));
    Ok(exit_code_for_all(received, unresolved))
}

/// Batch mode: read targets from file, probe each N times, output results.
/// Returns `EXIT_OK` only if every target received replies; a name that
/// does not resolve is one that received none.
///
/// # Errors
///
/// Fails when no target resolves, `-o <FILE>` cannot be written, or a
/// stdout write fails for a reason other than `BrokenPipe` (EPIPE is
/// tolerated so piping into `head` works).
pub async fn run_batch(cfg: Config) -> anyhow::Result<i32> {
    let count = cfg.count.unwrap_or(10);
    let is_json = matches!(cfg.view, ViewMode::Json);

    eprintln!(
        "Batch: {} targets {} {} probes (interval {}ms)",
        cfg.targets.len(),
        icons::times(),
        count,
        cfg.interval.as_millis()
    );

    // Pre-check the socket before probing (per target, below).
    if !precheck(&cfg, &[]) {
        return Ok(EXIT_ERROR);
    }

    let mut resolved = Vec::new();
    let mut unresolved = false;
    for target in &cfg.targets {
        if !dns::is_literal(target) {
            eprint!("  Resolving {target}...");
        }
        match dns::resolve(target, cfg.family).await {
            Ok((addr, dns_time)) => {
                if let Some(dt) = dns_time {
                    eprintln!(" {} ({:.1} ms)", addr.ip, dt.as_secs_f64() * 1000.0);
                }
                resolved.push((target.clone(), addr, dns_time));
            }
            Err(e) => {
                eprintln!("  warning: skipping {target}: {e}");
                unresolved = true;
            }
        }
    }

    if resolved.is_empty() {
        anyhow::bail!("no targets could be resolved");
    }

    let addrs: Vec<_> = resolved.iter().map(|(_, addr, _)| *addr).collect();
    // Every target's probe, now that the addresses are known.
    if !precheck(&cfg, &addrs) {
        return Ok(EXIT_ERROR);
    }

    // Each target has its own context.
    let contexts = context::detect_all(&addrs);

    // Probe all targets in parallel.
    eprintln!("Probing {} targets...", resolved.len());
    let mut handles = Vec::new();

    for ((target_host, target_addr, dns_time), net_ctx) in resolved.into_iter().zip(contexts) {
        let target_ip = target_addr.ip;
        let ctx = Some(net_ctx);
        let interval = cfg.interval;
        let opts = cfg.probe_options(target_addr);

        let host = target_host.clone();
        let handle = tokio::spawn(async move {
            batch::probe_target(target_host, target_ip, dns_time, ctx, interval, opts, count).await
        });
        handles.push((host, handle));
    }

    // A target whose task stopped has no result: the others are written,
    // and the exit code is that of an error.
    let mut results: Vec<ProbeSnapshot> = Vec::new();
    let mut stopped = false;
    for (host, handle) in handles {
        match joined(&format!("probe of {host}"), handle.await) {
            Some(snapshot) => results.push(snapshot),
            None => stopped = true,
        }
    }

    let mut output = String::new();
    if is_json {
        for snap in &results {
            // No gateway or WAN probe in batch: the target's diagnosis only.
            match crate::render::view_json::line(snap, None, None, None) {
                Ok(json) => {
                    output.push_str(&json);
                    output.push('\n');
                }
                Err(e) => {
                    eprintln!(
                        "warning: cannot serialize result for {}: {e}",
                        snap.target_host
                    );
                }
            }
        }
    } else {
        for snap in &results {
            output.push_str(&batch_line(snap));
        }
    }

    if let Some(ref path) = cfg.output_file {
        std::fs::write(path, &output)
            .map_err(|e| anyhow::anyhow!("cannot write to '{path}': {e}"))?;
        eprintln!("Results written to {path} ({} hosts)", results.len());
    } else {
        // EPIPE-safe write (e.g. `sping --batch ... | head`)
        let mut out = std::io::stdout();
        let write_result = out.write_all(output.as_bytes()).and_then(|_| out.flush());
        if let Err(e) = write_result
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(anyhow::anyhow!("cannot write to stdout: {e}"));
        }
    }

    if stopped {
        return Ok(EXIT_ERROR);
    }
    Ok(exit_code_for_all(
        results.iter().map(|s| s.received),
        unresolved,
    ))
}

/// One-line summary of a batch target (the text batch output, one per host).
fn batch_line(snap: &ProbeSnapshot) -> String {
    use crate::render::format::{fmt_loss, fmt_rtt_opt};
    use crate::render::view_compact::{estimate_hops, guess_os};

    let dash = icons::dash();
    // An address given as the target (with its zone, if any) is shown once;
    // a name with the address it resolved to.
    let host = if dns::is_literal(&snap.target_host) {
        snap.target_host.clone()
    } else {
        format!("{} ({})", snap.target_host, snap.target_ip)
    };

    let ttl_info = match (snap.port, snap.ttl) {
        // TCP: the port and how its last connect ended.
        (Some(port), _) => match snap.tcp_state {
            Some(state) => format!("tcp/{port} {state}"),
            None => format!("tcp/{port} {dash}"),
        },
        (None, Some(t)) if t > 0 => {
            let hops = estimate_hops(t);
            match guess_os(t) {
                Some(os) => format!("ttl {t} ({os}) hops ~{hops}"),
                None => format!("ttl {t} hops ~{hops}"),
            }
        }
        _ => format!("ttl {dash}"),
    };

    let quality = match (&snap.quality, snap.quality_score) {
        (Some(g), Some(s)) => {
            let letter = format!("{g}").chars().next().unwrap_or('?');
            format!("{letter}({s})")
        }
        _ => dash.into(),
    };

    let trend = snap
        .trend
        .as_ref()
        .map(|t| t.to_string())
        .unwrap_or_else(|| dash.into());

    format!(
        "{:<24} {}/{}  {}  avg {}  min {}  max {}  jitter {}  {}  {} {}\n",
        host,
        snap.received,
        snap.sent,
        fmt_loss(snap.loss_pct),
        fmt_rtt_opt(snap.rtt_avg),
        fmt_rtt_opt(snap.rtt_min),
        fmt_rtt_opt(snap.rtt_max),
        fmt_rtt_opt(snap.jitter),
        ttl_info,
        quality,
        trend,
    )
}

#[cfg(test)]
mod tests {
    use super::{EXIT_NO_REPLY, EXIT_OK, batch_line, exit_code_for_all, joined};
    use crate::render::golden_icmp::{lost, no_hop_limit, replying};
    use crate::render::golden_tcp::{open, refused, timed_out};

    // A task that ended hands over what it returned; one that panicked,
    // nothing: its result was dropped without a word, and the exit code was
    // that of the replies.
    #[tokio::test]
    async fn a_task_that_panicked_returned_nothing() {
        let ended = tokio::spawn(async { 7 });
        assert_eq!(joined("task", ended.await), Some(7));
        let panicked: tokio::task::JoinHandle<i32> = tokio::spawn(async { panic!("boom") });
        assert_eq!(joined("task", panicked.await), None);
    }

    // Several targets: 0 needs replies from every one, and a name that did
    // not resolve is one with none (the others decided: 0 with all of them
    // answering). No target probed at all is no reply.
    #[test]
    fn several_targets_exit_ok_only_if_every_one_answered() {
        assert_eq!(exit_code_for_all([3, 1], false), EXIT_OK);
        assert_eq!(exit_code_for_all([3, 0], false), EXIT_NO_REPLY);
        assert_eq!(exit_code_for_all([3, 1], true), EXIT_NO_REPLY);
        assert_eq!(exit_code_for_all([0], true), EXIT_NO_REPLY);
        assert_eq!(exit_code_for_all([], false), EXIT_NO_REPLY);
    }

    #[test]
    fn batch_line_icmp_golden() {
        assert_eq!(
            batch_line(&replying()),
            "dns.example (192.0.2.10) 9/10  10%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  ttl 57 hops ~7  A(95) stable\n"
        );
        assert_eq!(
            batch_line(&lost()),
            "dns.example (192.0.2.10) 9/11  18%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  ttl —  A(95) stable\n"
        );
        assert_eq!(
            batch_line(&no_hop_limit()),
            "dns.example (192.0.2.10) 9/10  10%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  ttl —  A(95) stable\n"
        );
    }

    // A TTL still at an initial value gives a hint; an address given with
    // its zone is shown once.
    #[test]
    fn batch_line_hint_and_zoned_literal() {
        let mut s = replying();
        s.ttl = Some(64);
        assert_eq!(
            batch_line(&s),
            "dns.example (192.0.2.10) 9/10  10%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  ttl 64 (Unix-like) hops ~0  A(95) stable\n"
        );
        s.target_host = "fe80::1%eth0".into();
        s.target_ip = "fe80::1".parse().unwrap();
        assert!(
            batch_line(&s).starts_with("fe80::1%eth0             9/10"),
            "{}",
            batch_line(&s)
        );
    }

    // TCP: the port and the last outcome where ICMP puts the TTL.
    #[test]
    fn batch_line_tcp_golden() {
        assert_eq!(
            batch_line(&open()),
            "dns.example (192.0.2.10) 9/10  10%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  tcp/443 open  A(95) stable\n"
        );
        assert_eq!(
            batch_line(&refused()),
            "dns.example (192.0.2.10) 9/10  10%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  tcp/443 refused  A(95) stable\n"
        );
        assert_eq!(
            batch_line(&timed_out()),
            "dns.example (192.0.2.10) 9/11  18%  avg 13.9 ms  min 13.6 ms  max 14.1 ms  jitter 0.19 ms  tcp/443 timeout  A(95) stable\n"
        );
        // A target whose probe could not even start: no outcome yet.
        let never = crate::probe::types::ProbeSnapshot::empty(
            "192.0.2.10".into(),
            "192.0.2.10".parse().unwrap(),
            None,
            None,
        )
        .with_tcp(Some(443));
        assert_eq!(
            batch_line(&never),
            "192.0.2.10               0/0  0%  avg —  min —  max —  jitter —  tcp/443 —  — —\n"
        );
    }
}
