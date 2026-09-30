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
use crate::probe::{auxiliary, batch, scheduler};
use crate::render::icons;
use crate::render::terminal::{self, AuxChannels};
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

fn exit_code_for(received: u64) -> i32 {
    if received > 0 { EXIT_OK } else { EXIT_NO_REPLY }
}

/// Single-target mode: one scheduler plus GW/WAN auxiliary probes feeding
/// the selected view. Returns the process exit code.
///
/// # Errors
///
/// Fails only on DNS resolution failure; socket failures yield
/// `Ok(EXIT_ERROR)` instead.
pub async fn run(cfg: Config) -> anyhow::Result<i32> {
    eprintln!();

    let target = &cfg.targets[0];

    if target.parse::<IpAddr>().is_err() {
        eprint!("Resolving {target}...");
    }
    let (target_ip, dns_time) = dns::resolve(target, cfg.family).await?;
    if let Some(dt) = dns_time {
        eprintln!(" {} ({:.1} ms)", target_ip, dt.as_secs_f64() * 1000.0);
    }

    let sep = icons::sep();
    let dash = icons::dash();
    let net_ctx = context::detect(target_ip);
    let bold = if icons::use_color() {
        ("\x1b[1m", "\x1b[0m")
    } else {
        ("", "")
    };
    let target_label = if net_ctx.target_class == context::classify::TargetClass::DefaultGateway {
        format!("target {}{}{} (default gateway)", bold.0, target_ip, bold.1)
    } else {
        format!("target {}{}{}", bold.0, target_ip, bold.1)
    };
    eprintln!(
        "Init: if {}{sep}{}/{}{sep}gw {}{sep}{}{sep}{}",
        net_ctx.interface,
        net_ctx.local_ip,
        net_ctx.prefix_len,
        net_ctx.gateway.as_deref().unwrap_or(dash),
        target_label,
        net_ctx.target_class,
    );

    // Pre-check the socket before entering raw mode.
    if let Err(e) = crate::backends::IcmpBackend::new() {
        eprint_socket_error(&e);
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
    // the GW auxiliary probe.
    let (ctx_tx, ctx_rx) = watch::channel(net_ctx.clone());
    let gw_channel = net_ctx
        .gateway
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(watch::channel);

    {
        let gw_target_tx = gw_channel.as_ref().map(|(tx, _)| tx.clone());
        let mut shutdown_rx = bus.subscribe_shutdown();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CTX_REDETECT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // detect() reads /proc or runs external tools — keep it
                        // off the async runtime.
                        let detected =
                            tokio::task::spawn_blocking(move || context::detect(target_ip)).await;
                        if let Ok(new_ctx) = detected
                            && *ctx_tx.borrow() != new_ctx
                        {
                            if let (Some(gw_tx), Some(gw_ip)) = (
                                &gw_target_tx,
                                new_ctx.gateway.as_deref().and_then(|s| s.parse::<IpAddr>().ok()),
                            ) {
                                let _ = gw_tx.send(gw_ip);
                            }
                            let _ = ctx_tx.send(new_ctx);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { return; }
                    }
                }
            }
        });
    }

    let probe_tx = bus.probe_sender();
    let shutdown_rx = bus.subscribe_shutdown();
    let target_host = target.clone();
    let interval = cfg.interval;
    let ctx = Some(net_ctx.clone());
    let opts = cfg.probe_options(target_ip);
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
        )
        .await;
    });

    // When the scheduler finishes (count reached or socket error), shut down
    // the renderer so the summary prints and the process exits.
    {
        let shutdown_tx = bus.shutdown_sender();
        tokio::spawn(async move {
            let _ = scheduler_handle.await;
            let _ = shutdown_tx.send(true);
        });
    }

    // GW probe, retargetable via the context watcher.
    if let Some((_, gw_target_rx)) = &gw_channel {
        let tx = bus.gateway_sender();
        let shutdown_rx = bus.subscribe_shutdown();
        let gw_target_rx = gw_target_rx.clone();
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
        let (_wan_tx, wan_rx) = watch::channel(cfg.wan_probe);
        tokio::spawn(async move {
            auxiliary::run("WAN".into(), wan_rx, AUX_PROBE_INTERVAL, tx, shutdown_rx).await;
        });
    }

    let probe_rx = bus.subscribe_probe();
    let shutdown_rx = bus.subscribe_shutdown();
    let aux = AuxChannels {
        gateway_rx: bus.subscribe_gateway(),
        wan_rx: bus.subscribe_wan(),
    };
    let view = cfg.view;
    let quiet = cfg.quiet;

    if is_tui {
        let renderer = tokio::spawn(async move {
            terminal::run(view, probe_rx, aux, shutdown_rx, quiet).await;
        });
        let _ = renderer.await;
    } else {
        terminal::run(view, probe_rx, aux, shutdown_rx, quiet).await;
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
/// table. Returns `EXIT_OK` only if every target received replies.
///
/// # Errors
///
/// Fails only when no target resolves; individual failures and duplicate
/// IPs are skipped.
pub async fn run_multi(cfg: Config) -> anyhow::Result<i32> {
    eprintln!();

    let mut resolved = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();

    for target in &cfg.targets {
        if target.parse::<IpAddr>().is_err() {
            eprint!("Resolving {target}...");
        }
        match dns::resolve(target, cfg.family).await {
            Ok((ip, dns_time)) => {
                if let Some(dt) = dns_time {
                    eprintln!(" {} ({:.1} ms)", ip, dt.as_secs_f64() * 1000.0);
                }
                if seen_ips.contains(&ip) {
                    eprintln!("note: {target} resolves to {ip} (duplicate, skipping)");
                } else {
                    seen_ips.insert(ip);
                    resolved.push((target.clone(), ip, dns_time));
                }
            }
            Err(e) => {
                eprintln!("warning: skipping {target}: {e}");
            }
        }
    }

    if resolved.is_empty() {
        anyhow::bail!("no targets could be resolved");
    }

    // Pre-check the socket before entering raw mode.
    if let Err(e) = crate::backends::IcmpBackend::new() {
        eprint_socket_error(&e);
        return Ok(EXIT_ERROR);
    }

    let sep = icons::sep();
    let dash = icons::dash();
    let net_ctx = context::detect(resolved[0].1);
    eprintln!(
        "Init: if {}{sep}{}/{}{sep}gw {}{sep}{} targets",
        net_ctx.interface,
        net_ctx.local_ip,
        net_ctx.prefix_len,
        net_ctx.gateway.as_deref().unwrap_or(dash),
        resolved.len(),
    );

    let (shutdown_tx, _) = watch::channel(false);

    terminal::start_key_listener(shutdown_tx.clone());
    spawn_signal_listener(shutdown_tx.clone());

    let mut probe_rxs: Vec<watch::Receiver<Option<ProbeSnapshot>>> = Vec::new();
    let mut scheduler_handles = Vec::new();

    for (target_host, target_ip, dns_time) in &resolved {
        let (probe_tx, probe_rx) = watch::channel(None);
        probe_rxs.push(probe_rx);

        let target_host = target_host.clone();
        let target_ip = *target_ip;
        let dns_time = *dns_time;
        let ctx = Some(net_ctx.clone());
        let interval = cfg.interval;
        let opts = cfg.probe_options(target_ip);
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

    let shutdown_rx = shutdown_tx.subscribe();
    let renderer = tokio::spawn(async move {
        terminal::run_table(probe_rxs, shutdown_rx).await;
    });

    let _ = renderer.await;

    let all_replied = final_rxs
        .iter()
        .all(|rx| rx.borrow().as_ref().is_some_and(|s| s.received > 0));
    Ok(if all_replied { EXIT_OK } else { EXIT_NO_REPLY })
}

/// Batch mode: read targets from file, probe each N times, output results.
/// Returns `EXIT_OK` only if every probed target received replies.
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
        "Batch: {} targets × {} probes (interval {}ms)",
        cfg.targets.len(),
        count,
        cfg.interval.as_millis()
    );

    // Pre-check the socket before probing.
    if let Err(e) = crate::backends::IcmpBackend::new() {
        eprint_socket_error(&e);
        return Ok(EXIT_ERROR);
    }

    let mut resolved = Vec::new();
    for target in &cfg.targets {
        if target.parse::<IpAddr>().is_err() {
            eprint!("  Resolving {target}...");
        }
        match dns::resolve(target, cfg.family).await {
            Ok((ip, dns_time)) => {
                if let Some(dt) = dns_time {
                    eprintln!(" {} ({:.1} ms)", ip, dt.as_secs_f64() * 1000.0);
                }
                resolved.push((target.clone(), ip, dns_time));
            }
            Err(e) => {
                eprintln!("  warning: skipping {target}: {e}");
            }
        }
    }

    if resolved.is_empty() {
        anyhow::bail!("no targets could be resolved");
    }

    let net_ctx = context::detect(resolved[0].1);

    // Probe all targets in parallel.
    eprintln!("Probing {} targets...", resolved.len());
    let mut handles = Vec::new();

    for (target_host, target_ip, dns_time) in resolved {
        let ctx = Some(net_ctx.clone());
        let interval = cfg.interval;
        let opts = cfg.probe_options(target_ip);

        let handle = tokio::spawn(async move {
            batch::probe_target(target_host, target_ip, dns_time, ctx, interval, opts, count).await
        });
        handles.push(handle);
    }

    let mut results: Vec<ProbeSnapshot> = Vec::new();
    for handle in handles {
        if let Ok(snapshot) = handle.await {
            results.push(snapshot);
        }
    }

    let mut output = String::new();
    if is_json {
        for snap in &results {
            match serde_json::to_string(snap) {
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
        // One-line summary per host.
        use crate::render::format::{fmt_loss, fmt_rtt_opt};
        use crate::render::view_compact::{estimate_hops, guess_os};

        let dash = icons::dash();
        for snap in &results {
            let host = if snap.target_host == snap.target_ip.to_string() {
                snap.target_host.clone()
            } else {
                format!("{} ({})", snap.target_host, snap.target_ip)
            };

            let ttl_info = match snap.ttl {
                Some(t) if t > 0 => {
                    let os = guess_os(t).unwrap_or("?");
                    let hops = estimate_hops(t);
                    format!("ttl {t} ({os}) hops ~{hops}")
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

            output.push_str(&format!(
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
            ));
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

    let all_replied = !results.is_empty() && results.iter().all(|s| s.received > 0);
    Ok(if all_replied { EXIT_OK } else { EXIT_NO_REPLY })
}
