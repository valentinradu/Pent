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
    let run_mode = matches!(cli.command, Command::Run(_));
    setup_tracing(cli.verbose, run_mode);

    // If running `pent run` and we detect we'll need CAP_NET_ADMIN but don't have it,
    // automatically re-execute with sudo before we start setting up sandboxing.
    if let Command::Run(ref args) = cli.command {
        if should_reexec_with_sudo(&args) {
            reexec_with_sudo(); // never returns
        }
    }

    let result = dispatch(cli).await;
    if let Err(e) = result {
        ui::error(e);
        std::process::exit(1);
    }
}

/// Check if this run command will need network proxying and if we have CAP_NET_ADMIN.
fn should_reexec_with_sudo(args: &cli::RunArgs) -> bool {
    // Already root? Don't re-exec
    // SAFETY: geteuid is always safe to call
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("[debug] Already running as root, no sudo needed");
        return false;
    }

    // Check if user requested proxy mode (--allow, --network proxy, etc.)
    let has_allow = !args.allow.is_empty();
    let is_proxy_network = args.network == Some(cli::NetworkModeArg::Proxy);
    let needs_proxy = has_allow || is_proxy_network;

    eprintln!("[debug] has_allow={}, is_proxy_network={}, needs_proxy={}", has_allow, is_proxy_network, needs_proxy);

    if !needs_proxy {
        eprintln!("[debug] Not in proxy mode, no sudo needed");
        return false;
    }

    // Check if we have CAP_NET_ADMIN
    let has_cap = has_cap_net_admin().is_ok();
    eprintln!("[debug] has_cap_net_admin={}", has_cap);

    !has_cap
}

/// Check if current process has CAP_NET_ADMIN in inheritable set.
///
/// For ambient capabilities to work (which pent uses), we need CAP_NET_ADMIN
/// in the inheritable set, not just the effective set. If it's only in effective
/// (e.g., via setcap=ep), the child process can't raise it as ambient.
fn has_cap_net_admin() -> Result<(), String> {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let mut has_inh = false;
        for line in status.lines() {
            if line.starts_with("CapInh:") {
                if let Some(hex) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(hex, 16) {
                        const CAP_NET_ADMIN: u64 = 1 << 12;
                        if caps & CAP_NET_ADMIN != 0 {
                            has_inh = true;
                            break;
                        }
                    }
                }
            }
        }
        if has_inh {
            return Ok(());
        }
    }
    Err("CAP_NET_ADMIN not in inheritable set".to_string())
}

/// Re-execute pent with sudo, preserving all arguments.
fn reexec_with_sudo() -> ! {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let pent_path = std::env::current_exe()
        .expect("failed to get current executable path");

    let args: Vec<String> = std::env::args().skip(1).collect();

    ui::status(
        "network-proxy",
        "sudo required for CAP_NET_ADMIN; re-executing with elevated privileges",
    );

    let mut cmd = Command::new("sudo");
    cmd.arg(&pent_path).args(&args);

    // Execute sudo; if successful this never returns
    let err = cmd.exec();
    eprintln!("failed to execute sudo: {}", err);
    std::process::exit(1);
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    let cwd = std::env::current_dir()?;
    match cli.command {
        Command::Run(args) => commands::run::run(args, cwd).await,
        Command::Check => commands::check::check(cwd).await,
        Command::Config(args) => commands::config::config(args, cwd).await,
    }
}

fn setup_tracing(verbose: u8, run_mode: bool) {
    // In run mode the sandboxed process owns the terminal; suppress pent's own
    // log output unless the user explicitly requested verbosity or PENT_LOG.
    let default_level = if run_mode && verbose == 0 { "warn" } else { "info" };
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
