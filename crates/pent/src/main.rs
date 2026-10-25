mod cli;
mod commands;
mod error;
mod ui;

use clap::Parser;
use cli::{Cli, Command};
use error::CliError;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // The child owns the terminal in `run` and `watch`.
    let run_mode = matches!(cli.command, Command::Run(_) | Command::Watch(_));
    setup_tracing(cli.verbose, run_mode);

    // Note: CAP_NET_ADMIN should be set on the pent binary via:
    //   sudo setcap cap_net_admin=eip $(which pent)
    // This allows pent to create veth pairs for network proxying without sudo.

    #[cfg(target_os = "linux")]
    {
        pent_sandbox::cleanup_stale_overlays();
        // Remove the veth pairs and firewall rules of pent processes that died
        // without cleanup (for example after SIGKILL).
        pent_sandbox::cleanup_stale_netns();
    }

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
    }
}

fn setup_tracing(verbose: u8, run_mode: bool) {
    // In run mode the sandboxed process owns the terminal; suppress pent's own
    // log output unless the user explicitly requested verbosity or PENT_LOG.
    let default_level = if run_mode && verbose == 0 {
        "warn"
    } else {
        "info"
    };
    let level = match verbose {
        0 => default_level,
        1 => "debug",
        _ => "trace",
    };

    let filter = std::env::var("PENT_LOG").unwrap_or_else(|_| level.to_string());

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();
}
