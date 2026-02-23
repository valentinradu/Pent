mod cli;
mod commands;
mod error;

use clap::Parser;
use cli::{Cli, Command};
use error::CliError;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    setup_tracing(cli.verbose);

    let result = dispatch(cli).await;
    if let Err(e) = result {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    let cwd = std::env::current_dir()?;
    match cli.command {
        Command::Run(args) => commands::run::run(args, cwd).await,
        Command::Check => commands::check::check(cwd).await,
        Command::Config(args) => commands::config::config(args, cwd).await,
    }
}

fn setup_tracing(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let filter = std::env::var("HALT_LOG").unwrap_or_else(|_| level.to_string());

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();
}
