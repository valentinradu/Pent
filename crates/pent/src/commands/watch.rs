//! `pent watch`: record what a command does, then make a draft profile.

use std::path::PathBuf;
use std::time::Duration;

use pent_profile::{guard_rules, WatchEvent};
use pent_proxy::ProxyPolicy;
use pent_sandbox::{
    build_env, spawn_watched, SandboxConfig, SandboxError, SandboxPaths, WatchOptions,
};
use pent_settings::{ConfigLoader, ProfileStore, WatchRunMode};

use crate::cli::WatchArgs;
use crate::commands::review_flow::{
    home_dir, summarize_review_and_draft, ReviewInput, TrustAnswer,
};
use crate::commands::select::{generic_warning, select_profile};
use crate::commands::session::{
    drain, forward_std, forward_tokio, start_proxy, wait_child, ForwardStop, ProxyChannels,
    SessionCleanup, SignalRelay,
};
use crate::commands::tty::Tty;
use crate::error::CliError;
use crate::ui;
use pent_profile::DraftSource;

/// The longest time to wait for the last events after the child exits.
const FINAL_DRAIN: Duration = Duration::from_secs(5);

/// The banner text after the first line. See `docs/design/watch.md`.
const BANNER: &str =
    "  Watch mode does not sandbox the program. It records what the program does.\n  \
     The program can read and change your files and use the network.\n  \
     Pent blocks only the most dangerous accesses (credentials, persistence).\n  \
     If you do not trust this binary, run it in a VM or a container.\n";

/// The banner for the profile `name`.
fn banner(name: &str) -> String {
    format!("pent watch: {name}\n{BANNER}")
}

// The function is long because it lists the steps of one watch run in
// order, with platform-specific steps under `cfg`.
#[allow(clippy::too_many_lines)]
pub(crate) async fn watch(args: WatchArgs, cwd: PathBuf) -> Result<(), CliError> {
    let selected = select_profile(args.profile.as_deref(), &args.command)?;
    if let Some(warning) = generic_warning(&selected) {
        ui::warn(warning);
    }
    let name = selected.name;

    // ── Banner ───────────────────────────────────────────────────────────────
    if args.yes {
        eprint!("{}", banner(name.as_str()));
    } else {
        let Some(mut tty) = Tty::open() else {
            return Err(CliError::Other(
                "pent watch needs a terminal to ask before the start; \
                 to start without the question, use --yes"
                    .to_string(),
            ));
        };
        tty.write(&banner(name.as_str()))?;
        if !tty.confirm("Continue?")? {
            ui::warn("pent watch did not start");
            return Ok(());
        }
    }

    let store = ProfileStore::open_default()?;
    let settings = ConfigLoader::load(&cwd)?;
    let home = home_dir()?;
    let mode = if args.append {
        WatchRunMode::Append
    } else {
        WatchRunMode::Replace
    };

    let (cmd, cmd_args) = args
        .command
        .split_first()
        .ok_or_else(|| CliError::Other("command list is empty".to_string()))?;

    // ── Proxy in observe mode ────────────────────────────────────────────────
    let (net_tx, net_rx) = tokio::sync::mpsc::unbounded_channel::<WatchEvent>();
    let proxy = start_proxy(
        &settings.proxy,
        Vec::new(),
        ProxyPolicy::Observe,
        ProxyChannels {
            trace: None,
            events: Some(net_tx),
        },
    )
    .await?;

    let sandbox_cfg = SandboxConfig::from_sandbox_settings(
        settings.sandbox,
        SandboxPaths::default(),
        cwd.clone(),
        cwd.clone(),
    )
    .with_network(proxy.network.clone())
    .with_env(build_env(&[]));
    let options = WatchOptions {
        guard: guard_rules(&home),
    };

    let mut signals = SignalRelay::install()?;
    let mut log = store.start_watch_run(&name, mode)?;
    let watched = match spawn_watched(&sandbox_cfg, &options, cmd, cmd_args) {
        Ok(watched) => watched,
        Err(e) => {
            proxy.shutdown().await;
            // The run did not start; remove its empty log. A failure here
            // leaves an empty file, which adds no events.
            let _ = std::fs::remove_file(log.path());
            return Err(spawn_error(e));
        }
    };

    #[cfg(target_os = "linux")]
    let cleanup = SessionCleanup::new(
        watched.child.child.id(),
        crate::commands::session::LinuxResources {
            overlay: watched.child.overlay,
            netns: watched.child.netns,
            trace: false,
        },
    );
    #[cfg(not(target_os = "linux"))]
    let cleanup = SessionCleanup::new(watched.child.child.id(), ());

    // ── Record ───────────────────────────────────────────────────────────────
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<WatchEvent>();
    let stop = ForwardStop::default();
    forward_std(watched.events, event_tx.clone(), |e| e);
    forward_tokio(net_rx, event_tx, |e| e, &stop);

    let mut write_failed = false;
    let mut sink = |event: WatchEvent| {
        if write_failed {
            return;
        }
        if let Err(e) = log.append(&event) {
            write_failed = true;
            ui::warn(format!("cannot record an event: {e}"));
        }
    };
    let (status, rest) =
        wait_child(watched.child.child, &mut signals, Some(event_rx), &mut sink).await;
    cleanup.finish();
    stop.stop();
    proxy.shutdown().await;
    if drain(rest, FINAL_DRAIN, &mut sink).await.is_some() {
        ui::warn("the recorder did not finish in time; a process of the command can still run");
    }
    drop(log);
    if !status.success() {
        ui::warn(format!("the command exited with {status}"));
    }

    // ── Summary, review, draft ───────────────────────────────────────────────
    let events = store.read_watch_events(&name)?;
    let runs = store.watch_runs(&name)?.len();
    let existing = store.load(&name)?.doc;
    let keep = match mode {
        WatchRunMode::Append => store.read_draft(&name)?,
        WatchRunMode::Replace => None,
    };
    summarize_review_and_draft(ReviewInput {
        store: &store,
        name: &name,
        workspace: &cwd,
        events: &events,
        existing,
        keep,
        origin: DraftSource::WatchRuns(runs),
        trust: TrustAnswer::Ask,
    })?;
    Ok(())
}

/// The error for a spawn that failed. The recorder does not exist on all
/// platforms yet.
fn spawn_error(e: SandboxError) -> CliError {
    match e {
        SandboxError::UnsupportedPlatform => CliError::Other(format!(
            "pent watch is not available on this platform yet: the access recorder for {} \
             does not exist",
            std::env::consts::OS
        )),
        other => CliError::Sandbox(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_matches_the_design() {
        let b = banner("claude");
        assert!(b.starts_with("pent watch: claude\n  Watch mode does not sandbox the program."));
        assert!(b.ends_with("run it in a VM or a container.\n"));
        assert_eq!(b.lines().count(), 5);
    }

    #[test]
    fn unsupported_platform_message() {
        let msg = spawn_error(SandboxError::UnsupportedPlatform).to_string();
        assert!(
            msg.starts_with("pent watch is not available on this platform yet"),
            "{msg}"
        );
    }
}
