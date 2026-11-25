#[cfg(not(target_os = "linux"))]
compile_error!("pent runs on Linux only");

mod cli;
mod commands;
mod daemon;
mod error;
mod monitor;
mod ui;

use clap::Parser;
use cli::{Cli, Command};
use error::CliError;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // The child owns the terminal in `run` and `watch`, and the screen owns
    // it in `monitor`.
    let quiet = match cli.command {
        Command::Run(_) | Command::Watch(_) => Quiet::Warnings,
        Command::Monitor => Quiet::All,
        _ => Quiet::No,
    };
    setup_tracing(cli.verbose, quiet);

    pent_sandbox::cleanup_stale_overlays();

    let result = dispatch(cli).await;
    if let Err(e) = result {
        ui::error(e);
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    let cwd = std::env::current_dir()?;
    match cli.command {
        Command::Run(args) => commands::run::run(args, cwd).await,
        Command::Watch(args) => commands::watch::watch(args, cwd).await,
        Command::Trust(args) => commands::trust::trust(&args, cwd),
        Command::Untrust(args) => commands::trust::untrust(&args),
        Command::Profile(args) => commands::trust::profile(&args),
        Command::Check => commands::check::check(cwd).await,
        Command::Config(args) => commands::config::config(args, &cwd),
        Command::Daemon(args) => daemon::daemon(&args).await,
        Command::Allow(args) => {
            commands::answer::answer(&args, pent_profile::Decision::Allow).await
        }
        Command::Deny(args) => commands::answer::answer(&args, pent_profile::Decision::Deny).await,
        Command::Questions(args) => commands::answer::questions(&args).await,
        Command::Monitor => monitor::monitor().await,
        Command::Denials(args) => commands::answer::denials(&args).await,
        Command::Rules(args) => commands::rules::rules(&args).await,
    }
}

/// How much of the log of pent a command shows by default.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Quiet {
    /// The log from `info` up.
    No,
    /// Only the warnings and the errors: the sandboxed process owns the
    /// terminal.
    Warnings,
    /// Nothing: a line of log would break the screen of `pent monitor`.
    All,
}

fn setup_tracing(verbose: u8, quiet: Quiet) {
    // Suppress pent's own log output unless the user explicitly requested
    // verbosity or PENT_LOG.
    let default_level = match (quiet, verbose) {
        (Quiet::Warnings, 0) => "warn",
        (Quiet::All, 0) => "off",
        _ => "info",
    };
    let level = match verbose {
        0 => default_level,
        1 => "debug",
        _ => "trace",
    };

    // The FUSE crate warns for each operation that the server of pent does
    // not implement; such a request gets an error, and the warning means
    // nothing to the user. `-v` shows it.
    let filter = std::env::var("PENT_LOG").unwrap_or_else(|_| {
        if verbose == 0 {
            format!("{level},fuser=error")
        } else {
            level.to_string()
        }
    });

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();
}
