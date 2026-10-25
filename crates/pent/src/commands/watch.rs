//! `pent watch`: record what a command does, then make a draft profile.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pent_profile::{guard_rules_with, ProfileName, WatchEvent};
use pent_proxy::ProxyPolicy;
use pent_sandbox::{
    build_env, spawn_watched, SandboxConfig, SandboxError, SandboxPaths, WatchOptions,
};
use pent_settings::{ConfigLoader, ProfileStore, WatchRunMode};

use crate::cli::{NetworkModeArg, WatchArgs};
use crate::commands::review_flow::{
    home_dir, summarize_review_and_draft, ReviewInput, TrustAnswer,
};
use crate::commands::run::{
    base_network_mode, network_status, network_warnings, resolve_network, NetworkChoice,
    NetworkDecision, NetworkSource,
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

/// The first lines of the banner. See `docs/design/watch.md`.
const BANNER_HEAD: &str =
    "  Watch mode does not sandbox the program. It records what the program does.\n  \
     The program can read and change your files and use the network.\n";

/// The line that the banner adds when the proxy allows each domain.
const BANNER_OPEN_NETWORK: &str =
    "  The network is open in this run. Use --allow DOMAIN or --network blocked \
     to close it.\n";

/// The last lines of the banner.
const BANNER_TAIL: &str =
    "  Pent blocks only the most dangerous accesses (credentials, persistence).\n  \
     If you do not trust this binary, run it in a VM or a container.\n";

/// The banner for the profile `name`. The banner names an open network, so
/// the user knows that the program can send out what it reads.
fn banner(name: &str, policy: ProxyPolicy) -> String {
    let network = if policy == ProxyPolicy::Observe {
        BANNER_OPEN_NETWORK
    } else {
        ""
    };
    format!("pent watch: {name}\n{BANNER_HEAD}{network}{BANNER_TAIL}")
}

/// The network of one watch run.
struct WatchNetwork {
    /// The mode and the input that decided it.
    decision: NetworkDecision,
    /// The policy of the proxy.
    policy: ProxyPolicy,
    /// The domains of the allowlist.
    domains: Vec<String>,
}

/// Decide the network of a watch run.
///
/// Without `--network` and without `--allow`, the proxy observes and allows
/// each domain: a watch run must learn what the program needs. With one of
/// the two flags, the rule of `pent run` applies, and the proxy enforces the
/// allowlist. A watch run applies no profile, so the profile domains are
/// empty.
fn watch_network(flag: Option<NetworkModeArg>, allow: &[String]) -> WatchNetwork {
    if flag.is_none() && allow.is_empty() {
        return WatchNetwork {
            decision: NetworkDecision {
                choice: NetworkChoice::Proxy,
                source: NetworkSource::Default,
            },
            policy: ProxyPolicy::Observe,
            domains: Vec::new(),
        };
    }
    WatchNetwork {
        decision: resolve_network(flag, allow, &[]),
        policy: ProxyPolicy::Enforce,
        domains: allow.to_vec(),
    }
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
    let net = watch_network(args.network, &args.allow);

    // ── Banner ───────────────────────────────────────────────────────────────
    if args.yes {
        eprint!("{}", banner(name.as_str(), net.policy));
    } else {
        let Some(mut tty) = Tty::open() else {
            return Err(CliError::Other(
                "pent watch needs a terminal to ask before the start; \
                 to start without the question, use --yes"
                    .to_string(),
            ));
        };
        tty.write(&banner(name.as_str(), net.policy))?;
        if !tty.confirm("Continue?")? {
            ui::warn("pent watch did not start");
            return Ok(());
        }
    }
    // `--trace` is a flag of `pent run`, so a watch run never traces.
    for warning in network_warnings(net.decision, &args.allow, false) {
        ui::warn(warning);
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

    // ── Proxy ────────────────────────────────────────────────────────────────
    // The proxy observes by default. With `--allow` or `--network`, it
    // enforces the allowlist, and each refused request becomes an item of
    // the summary.
    let (net_tx, net_rx) = tokio::sync::mpsc::unbounded_channel::<WatchEvent>();
    let proxy = if net.decision.choice == NetworkChoice::Proxy {
        Some(
            start_proxy(
                &settings.proxy,
                net.domains,
                net.policy,
                ProxyChannels {
                    trace: None,
                    events: Some(net_tx),
                },
            )
            .await?,
        )
    } else {
        None
    };
    let network = proxy.as_ref().map_or_else(
        || base_network_mode(net.decision.choice),
        |p| p.network.clone(),
    );
    if let Some(line) = network_status(&network, net.decision.source) {
        ui::status("network", line);
    }

    let sandbox_cfg = SandboxConfig::from_sandbox_settings(
        settings.sandbox,
        SandboxPaths::default(),
        cwd.clone(),
        cwd.clone(),
    )
    .with_network(network)
    .with_env(build_env(&[]));
    // The guard protects the files of pent at their real place, also when
    // $XDG_CONFIG_HOME or $XDG_STATE_HOME points outside of the defaults.
    let options = WatchOptions {
        guard: guard_rules_with(
            &home,
            &[store.dirs().config.clone(), store.dirs().state.clone()],
        ),
        // Watch mode does not refuse a connection to a Unix socket: a
        // refusal would change the run that pent records. The supervisor
        // marks a connection to a socket that this list does not name as
        // denied, and the review proposes the path. The list holds the
        // sockets that the profile and the current draft already name, so
        // the review does not propose them again.
        unix_sockets: known_unix_sockets(&store, &name, &cwd)?,
    };

    let mut signals = SignalRelay::install()?;
    let mut log = store.start_watch_run(&name, mode)?;
    let watched = match spawn_watched(&sandbox_cfg, &options, cmd, cmd_args) {
        Ok(watched) => watched,
        Err(e) => {
            if let Some(proxy) = proxy {
                proxy.shutdown().await;
            }
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
            trace: false,
        },
    );
    // The child made the proxy listeners in its network namespace. If the
    // proxy cannot use them, the error drops `cleanup`, which stops the
    // child.
    #[cfg(target_os = "linux")]
    if let Some(proxy) = &proxy {
        proxy.attach(watched.child.proxy_listeners)?;
    }
    #[cfg(not(target_os = "linux"))]
    let cleanup = SessionCleanup::new(watched.child.child.id(), ());

    // ── Record ───────────────────────────────────────────────────────────────
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<WatchEvent>();
    let stop = ForwardStop::default();
    forward_std(watched.events, event_tx.clone(), |e| e);
    forward_tokio(net_rx, event_tx, |e| e, &stop);

    // One event that pent cannot write must not stop the log: the rest of
    // the run would be invisible in the review, the blocked attempts too.
    // Pent skips the event, counts it, and warns one time.
    let mut skipped: usize = 0;
    let mut sink = |event: WatchEvent| {
        if let Err(e) = log.append(&event) {
            if skipped == 0 {
                ui::warn(format!("cannot record an access: {e}; pent goes on"));
            }
            skipped = skipped.saturating_add(1);
        }
    };
    let (status, rest) =
        wait_child(watched.child.child, &mut signals, Some(event_rx), &mut sink).await;
    cleanup.finish();
    stop.stop();
    if let Some(proxy) = proxy {
        proxy.shutdown().await;
    }
    if drain(rest, FINAL_DRAIN, &mut sink).await.is_some() {
        ui::warn("the recorder did not finish in time; a process of the command can still run");
    }
    if skipped > 0 {
        ui::warn(format!(
            "pent did not record {skipped} accesses; the summary does not show them"
        ));
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

/// The Unix socket paths that the profile and the current draft of `name`
/// already name.
fn known_unix_sockets(
    store: &ProfileStore,
    name: &ProfileName,
    workspace: &Path,
) -> Result<Vec<PathBuf>, CliError> {
    let mut entries = store
        .load(name)?
        .doc
        .map(|doc| doc.filesystem.unix_sockets)
        .unwrap_or_default();
    if let Some(draft) = store.read_draft(name)? {
        for entry in draft.filesystem.unix_sockets {
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
    }
    Ok(crate::commands::run::unix_socket_paths(
        &entries,
        &[],
        workspace,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_matches_the_design() {
        let b = banner("claude", ProxyPolicy::Observe);
        assert!(b.starts_with("pent watch: claude\n  Watch mode does not sandbox the program."));
        assert!(b.ends_with("run it in a VM or a container.\n"));
        assert_eq!(b.lines().count(), 6);
    }

    /// The default run has an open network, and the banner says so. With a
    /// flag the proxy enforces the allowlist, and the line goes away.
    #[test]
    fn the_banner_names_an_open_network() {
        let open = banner("claude", ProxyPolicy::Observe);
        assert!(open.contains("The network is open in this run."), "{open}");
        assert!(open.contains("--network blocked"), "{open}");
        let closed = banner("claude", ProxyPolicy::Enforce);
        assert!(!closed.contains("The network is open"), "{closed}");
        assert_eq!(closed.lines().count(), 5);
    }

    #[test]
    fn without_a_flag_the_proxy_observes_and_allows_each_domain() {
        let net = watch_network(None, &[]);
        assert_eq!(net.policy, ProxyPolicy::Observe);
        assert_eq!(net.decision.choice, NetworkChoice::Proxy);
        assert_eq!(net.decision.source, NetworkSource::Default);
        assert!(net.domains.is_empty());
    }

    #[test]
    fn allow_makes_the_proxy_enforce_the_allowlist() {
        let net = watch_network(None, &["a.example".to_string()]);
        assert_eq!(net.policy, ProxyPolicy::Enforce);
        assert_eq!(net.decision.choice, NetworkChoice::Proxy);
        assert_eq!(net.decision.source, NetworkSource::AllowFlag);
        assert_eq!(net.domains, vec!["a.example"]);
    }

    /// `--network` has precedence over `--allow`, as in `pent run`.
    #[test]
    fn the_network_flag_has_precedence() {
        let net = watch_network(Some(NetworkModeArg::Blocked), &["a.example".to_string()]);
        assert_eq!(net.decision.choice, NetworkChoice::Blocked);
        assert_eq!(net.decision.source, NetworkSource::NetworkFlag);
        let warnings = network_warnings(net.decision, &["a.example".to_string()], false);
        assert!(
            warnings.iter().any(|w| w.contains("--allow has no effect")),
            "{warnings:?}"
        );
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
