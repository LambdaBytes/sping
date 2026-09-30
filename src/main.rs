//! Binary entry point: parses CLI args, builds config, dispatches to
//! single/multi/batch mode. Exit codes are ping-compatible (0/1/2).

mod app;
mod cli;
mod config;

mod backends;
mod context;
mod diagnostics;
mod probe;
mod render;
mod runtime;

use clap::Parser;

#[tokio::main]
async fn main() {
    // Restore the terminal if anything panics while raw mode is active;
    // otherwise the user is left with a corrupted shell until `reset`.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        default_hook(info);
    }));

    std::process::exit(real_main().await);
}

async fn real_main() -> i32 {
    let args = cli::Args::parse();

    render::icons::init(args.ascii);

    if args.list_interfaces {
        let ifaces = context::iface::list_interfaces();
        if ifaces.is_empty() {
            println!("No interfaces detected.");
        } else {
            for iface in &ifaces {
                println!("{:<16} {}/{}", iface.name, iface.ip, iface.prefix_len);
            }
        }
        return app::EXIT_OK;
    }

    let debug = args.debug
        || std::env::var("SPING_LOG")
            .map(|v| v == "debug")
            .unwrap_or(false);
    if debug {
        eprintln!("[debug] sping v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("[debug] args: {:?}", args);
    }

    if args.batch.is_none() && args.targets.is_empty() {
        eprintln!("error: at least one <TARGET> is required (or use --batch <FILE>)");
        eprintln!("Usage: sping <TARGET>... [OPTIONS]");
        eprintln!("       sping --batch <FILE> -c <COUNT> [OPTIONS]");
        return app::EXIT_ERROR;
    }

    let cfg = match config::Config::from_args(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return app::EXIT_ERROR;
        }
    };

    if let Err(e) = cfg.validate() {
        eprintln!("error: {e}");
        return app::EXIT_ERROR;
    }

    let result = if cfg.is_batch() {
        app::run_batch(cfg).await
    } else if cfg.targets.len() == 1 {
        app::run(cfg).await
    } else {
        app::run_multi(cfg).await
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            app::EXIT_ERROR
        }
    }
}
