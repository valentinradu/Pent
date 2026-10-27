//! `pent run`: run a command in the sandbox with its trusted profile.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pent_profile::{Outcome, ProfileName, WatchEvent};
use pent_proxy::{ProxyPolicy, TraceEvent};
use pent_sandbox::{
    build_env, check_availability, spawn_sandboxed, LocalhostPorts, NetworkMode, SandboxConfig,
};
use pent_settings::{ConfigLoader, EventLog, ProfileStore};

use crate::cli::{NetworkModeArg, RunArgs};
use crate::commands::select::{generic_warning, load_trusted, profile_paths, select_profile};
use crate::commands::session::{
    drain, exit_like_child, forward_std, forward_tokio, is_broad_workspace, start_proxy,
    wait_child, ForwardStop, ProxyChannels, SessionCleanup, SignalRelay,
};
use crate::error::CliError;
use crate::ui;

/// The longest time to wait for the last events after the child exits and
/// the forwarders stop.
const FINAL_DRAIN: Duration = Duration::from_secs(2);

/// One event of the run: a line for the trace log, or a structured access
/// event for the log of denied accesses.
enum RunEvent {
    Trace(TraceLine),
    Access(WatchEvent),
}

// The function is long because it lists the steps of one run in order, with
// platform-specific steps under `cfg`. To split it would hide this order.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run(args: RunArgs, cwd: PathBuf) -> Result<(), CliError> {
    #[cfg(target_os = "macos")]
    if args.no_sandbox {
        return Err(CliError::Other(
            "--no-sandbox is not supported on macOS".to_string(),
        ));
    }

    // ── Profile ──────────────────────────────────────────────────────────────
    let selected = select_profile(args.profile.as_deref(), &args.command)?;
    if let Some(warning) = generic_warning(&selected) {
        ui::warn(warning);
    }
    let store = ProfileStore::open_default()?;
    let profile = load_trusted(&store, &selected, &args.command)?;
    let name = selected.name;
    let settings = ConfigLoader::load(&cwd, pent_settings::PentDirs::from_env().as_ref())?;

    let mut paths = profile_paths(&profile);
    add_cli_paths(&mut paths, &args);
    paths.resolve_relative(&cwd);
    // On Linux, read_write paths must be exact filenames — glob ('*') patterns
    // are not supported because overlayfs requires specific paths to mount over.
    #[cfg(target_os = "linux")]
    paths.validate_no_rw_globs()?;

    // Decide the network mode before `--allow` merges into the profile
    // domains, so that the two sources stay separate.
    let decision = resolve_network(args.network, &args.allow, &profile.network.domains);
    let domains = merge_domains(&profile.network.domains, &args.allow);
    let localhost_ports = if blocks_localhost(decision) {
        if let Some(source) = closed_ports_source(&profile.network.localhost, &args.localhost) {
            ui::warn(format!(
                "{source} have no effect: --network blocked closes the ports on localhost too"
            ));
        }
        Vec::new()
    } else {
        merge_ports(&profile.network.localhost, &args.localhost)
    };
    let env_map = build_run_env(&args.env);
    let trace_log_path = open_trace_log(args.trace, &store, &name);

    for warning in network_warnings(decision, &args.allow, args.trace) {
        ui::warn(warning);
    }

    // ── Events ───────────────────────────────────────────────────────────────
    // All event sources send into one channel: the proxy (trace lines and
    // structured events), the recorder of the sandbox (`--trace`), and on
    // macOS the Seatbelt log.
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<RunEvent>();
    let stop = ForwardStop::default();

    // ── Proxy ────────────────────────────────────────────────────────────────
    let proxy = if decision.choice == NetworkChoice::Proxy {
        let (access_tx, access_rx) = tokio::sync::mpsc::unbounded_channel::<WatchEvent>();
        forward_tokio(access_rx, event_tx.clone(), RunEvent::Access, &stop);
        let trace_tx = if args.trace {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
            let profile_name = name.clone();
            forward_tokio(
                rx,
                event_tx.clone(),
                move |e| RunEvent::Trace(proxy_trace_line(e, &profile_name)),
                &stop,
            );
            Some(tx)
        } else {
            None
        };
        let channels = ProxyChannels {
            trace: trace_tx,
            events: Some(access_tx),
        };
        Some(
            start_proxy(
                &settings.proxy,
                domains,
                localhost_ports.clone(),
                ProxyPolicy::Enforce,
                channels,
            )
            .await?,
        )
    } else {
        None
    };
    let resolved_network = proxy
        .as_ref()
        .map_or_else(|| base_network_mode(decision.choice), |p| p.network.clone());

    // The workspace is always read-write. If it is `/` or the home directory,
    // the sandbox gives write access to almost all user files.
    if !args.no_sandbox && is_broad_workspace(&cwd) {
        ui::warn(format!(
            "the workspace is {}; the sandboxed process can change all files below it",
            cwd.display()
        ));
    }

    let mut sandbox_cfg =
        SandboxConfig::from_sandbox_settings(settings.sandbox, paths, cwd.clone(), cwd.clone())
            .with_network(resolved_network)
            .with_env(env_map);
    sandbox_cfg.record_events = args.trace;
    sandbox_cfg.unix_sockets =
        unix_socket_paths(&profile.filesystem.unix_sockets, &args.unix_socket, &cwd);
    sandbox_cfg.localhost = LocalhostPorts::Listed(localhost_ports);

    if let Some(data_dir) = args.data_dir {
        sandbox_cfg = sandbox_cfg.with_data_dir(data_dir);
    }

    if args.no_sandbox {
        sandbox_cfg = sandbox_cfg.with_no_enforcement();
    }

    // Validate sandbox availability before spawning (skipped in --no-sandbox mode).
    if !args.no_sandbox {
        check_availability()?;
    }

    // The command gets a private `/proc` only where the kernel gives one. A
    // container runtime hides a part of `/proc`, and the kernel then refuses
    // the mount. Pent goes on, and the user learns what the command can
    // see. See `ProcIsolation` in pent-sandbox.
    #[cfg(target_os = "linux")]
    if !args.no_sandbox {
        for line in pent_sandbox::proc_isolation().warning_lines() {
            ui::warn(line);
        }
    }

    let (cmd, cmd_args) = args
        .command
        .split_first()
        .ok_or_else(|| CliError::Other("command list is empty".to_string()))?;

    // Print network mode hint BEFORE spawn so the user sees it even if spawn
    // takes time or stalls during namespace init.
    if let Some(line) = network_status(&sandbox_cfg.network, decision.source) {
        ui::status("network", line);
    }
    if let Some(line) = localhost_status(&sandbox_cfg.network, &sandbox_cfg.localhost) {
        ui::status("localhost", line);
    }

    let mut signals = SignalRelay::install()?;

    let sandbox_child = spawn_sandboxed(&sandbox_cfg, cmd, cmd_args)?;

    #[cfg(target_os = "linux")]
    let cleanup = SessionCleanup::new(
        sandbox_child.child.id(),
        crate::commands::session::LinuxResources {
            overlay: sandbox_child.overlay,
            trace: args.trace,
        },
    );
    // The child made the proxy listeners in its network namespace. If the
    // proxy cannot use them, the error drops `cleanup`, which stops the
    // child.
    #[cfg(target_os = "linux")]
    if let Some(proxy) = &proxy {
        proxy.attach(sandbox_child.proxy_listeners)?;
    }
    #[cfg(not(target_os = "linux"))]
    let cleanup = SessionCleanup::new(sandbox_child.child.id(), ());
    let child = sandbox_child.child;
    if let Some(rx) = sandbox_child.events {
        forward_std(rx, event_tx.clone(), RunEvent::Access);
    }

    // Both platforms get the denials through `SandboxChild::events`. On
    // macOS the reader of the unified log holds the channel open for a
    // moment after the child exits, and `FINAL_DRAIN` covers that.
    let drain_grace = Duration::ZERO;
    // Only the forwarders keep senders. When they stop, the channel closes.
    drop(event_tx);

    let mut denied = DeniedRecorder::new(&store, &name);
    let mut sink = |event: RunEvent| match event {
        RunEvent::Trace(line) => write_trace_line(trace_log_path.as_deref(), &line),
        RunEvent::Access(event) => {
            // The recorder sends the filesystem denials only with --trace.
            // Write them to the trace log too.
            if let Some(line) = access_trace_line(&event, &name) {
                write_trace_line(trace_log_path.as_deref(), &line);
            }
            denied.record(&event);
        }
    };
    let (exit_status, rest) = wait_child(child, &mut signals, Some(event_rx), &mut sink).await;

    // Flush overlayfs write-listed files back to real inodes and clean up
    // staging directories. This must happen after the wait, so the child's
    // mount namespace is already destroyed and no writes are in flight.
    cleanup.finish();

    // Read the late events, then stop the forwarders and read the rest.
    let rest = drain(rest, drain_grace, &mut sink).await;
    stop.stop();
    if let Some(proxy) = proxy {
        proxy.shutdown().await;
    }
    drain(rest, FINAL_DRAIN, &mut sink).await;

    if let Some(message) = denied.summary() {
        ui::warn(message);
    }

    exit_like_child(exit_status)
}

/// Add the paths of the CLI flags to the profile paths.
fn add_cli_paths(paths: &mut pent_settings::SandboxPaths, args: &RunArgs) {
    let strings = |list: &[PathBuf]| -> Vec<String> {
        list.iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    };
    paths.traversal.extend(strings(&args.traverse));
    paths.read.extend(strings(&args.read));
    paths.read_write.extend(strings(&args.write));
    paths.execute.extend(strings(&args.execute));
}

/// The Unix sockets of the profile and of `--unix-socket`, without
/// duplicates.
///
/// A leading `~` expands to the home directory, as it does for the other
/// path lists. A relative path resolves against the workspace.
pub(crate) fn unix_socket_paths(
    profile: &[String],
    flags: &[PathBuf],
    workspace: &Path,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |entry: &Path| {
        let path = pent_settings::expand_home(entry);
        let path = if path.is_absolute() {
            path
        } else {
            workspace.join(path)
        };
        if !out.contains(&path) {
            out.push(path);
        }
    };
    for entry in profile {
        add(Path::new(entry));
    }
    for entry in flags {
        add(entry);
    }
    out
}

/// Return true when the user closed the network with `--network blocked`.
/// The ports on localhost then close too. A network that is blocked only
/// because the profile has no domains keeps the ports of the profile.
fn blocks_localhost(decision: NetworkDecision) -> bool {
    decision.source == NetworkSource::NetworkFlag && decision.choice == NetworkChoice::Blocked
}

/// Name the source of the ports that `--network blocked` closes, or `None`
/// when no source has a port.
fn closed_ports_source(profile: &[NonZeroU16], flags: &[NonZeroU16]) -> Option<&'static str> {
    match (profile.is_empty(), flags.is_empty()) {
        (true, true) => None,
        (false, true) => Some("the localhost ports of the profile"),
        (true, false) => Some("the --localhost flags"),
        (false, false) => Some("the localhost ports of the profile and the --localhost flags"),
    }
}

/// The ports of the profile and of `--localhost`, without duplicates.
fn merge_ports(profile: &[NonZeroU16], flags: &[NonZeroU16]) -> Vec<NonZeroU16> {
    let mut ports = profile.to_vec();
    for port in flags {
        if !ports.contains(port) {
            ports.push(*port);
        }
    }
    ports
}

/// Return the status line for the ports on the loopback of the host, if the
/// run opens one. With `--network unrestricted` the command reaches each
/// port anyway, so the line says nothing new.
fn localhost_status(network: &NetworkMode, ports: &LocalhostPorts) -> Option<String> {
    if *network == NetworkMode::Unrestricted {
        return None;
    }
    match ports {
        LocalhostPorts::Listed(list) if list.is_empty() => None,
        LocalhostPorts::Listed(list) => Some(format!(
            "{} {}",
            if list.len() == 1 { "port" } else { "ports" },
            list.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        LocalhostPorts::All => Some("each port".to_string()),
    }
}

/// The profile domains and the `--allow` domains, without duplicates.
fn merge_domains(profile: &[String], allow: &[String]) -> Vec<String> {
    let mut domains = profile.to_vec();
    for d in allow {
        if !domains.contains(d) {
            domains.push(d.clone());
        }
    }
    domains
}

/// Parse `KEY=VALUE` and bare `KEY` env entries; return a merged env map.
fn build_run_env(args_env: &[String]) -> HashMap<String, String> {
    let mut allowlist_keys: Vec<String> = Vec::new();
    let mut explicit_env: Vec<(String, String)> = Vec::new();
    for entry in args_env {
        if let Some((key, value)) = entry.split_once('=') {
            allowlist_keys.push(key.to_string());
            explicit_env.push((key.to_string(), value.to_string()));
        } else {
            allowlist_keys.push(entry.clone());
        }
    }
    let mut env_map: HashMap<String, String> = build_env(&allowlist_keys);
    for (k, v) in explicit_env {
        env_map.insert(k, v);
    }
    env_map
}

/// Create the trace log of `name` when `trace` is true; emit a warning on
/// failure.
///
/// The log is in the state directory of pent, not in the workspace: the
/// sandboxed process can write the workspace, so it could put a symbolic link
/// there and make pent write to another file.
fn open_trace_log(trace: bool, store: &ProfileStore, name: &ProfileName) -> Option<PathBuf> {
    if !trace {
        return None;
    }
    match store.create_trace_log(name) {
        Ok(path) => {
            ui::status("tracing", path.display());
            Some(path)
        }
        Err(e) => {
            ui::warn(format!("could not create the trace log: {e}"));
            None
        }
    }
}

// ── Denied accesses ──────────────────────────────────────────────────────────

/// Writes the denied accesses of this run to the denied log of the profile.
///
/// The recorder writes each distinct event one time, and opens the log only
/// at the first denial.
struct DeniedRecorder<'a> {
    store: &'a ProfileStore,
    name: &'a ProfileName,
    log: Option<EventLog>,
    seen: HashSet<String>,
    /// True after the first write error; pent then shows no more warnings.
    failed: bool,
}

impl<'a> DeniedRecorder<'a> {
    fn new(store: &'a ProfileStore, name: &'a ProfileName) -> Self {
        Self {
            store,
            name,
            log: None,
            seen: HashSet::new(),
            failed: false,
        }
    }

    /// Record `event` if the policy denied it.
    fn record(&mut self, event: &WatchEvent) {
        if event.outcome() != Outcome::Denied {
            return;
        }
        let Ok(key) = event.to_json_line() else {
            return;
        };
        if !self.seen.insert(key) {
            return;
        }
        if self.failed {
            return;
        }
        let result = match &mut self.log {
            Some(log) => log.append(event),
            None => self.store.denied_log(self.name).and_then(|mut log| {
                let result = log.append(event);
                self.log = Some(log);
                result
            }),
        };
        if let Err(e) = result {
            self.failed = true;
            ui::warn(format!("cannot record a denied access: {e}"));
        }
    }

    /// The message for the end of the run, if the run had denied accesses.
    fn summary(&self) -> Option<String> {
        denied_message(self.seen.len(), self.name)
    }
}

/// The message for `count` denied accesses of the profile `name`.
fn denied_message(count: usize, name: &ProfileName) -> Option<String> {
    match count {
        0 => None,
        1 => Some(format!(
            "1 access denied; review it: pent trust {name} --review"
        )),
        n => Some(format!(
            "{n} accesses denied; review them: pent trust {name} --review"
        )),
    }
}

// ── Network mode resolution ──────────────────────────────────────────────────

/// The network mode that the user asks for, before pent starts a proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkChoice {
    Unrestricted,
    Localhost,
    Proxy,
    Blocked,
}

impl NetworkChoice {
    /// The value of `--network` that selects this mode.
    const fn flag_value(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Localhost => "localhost",
            Self::Proxy => "proxy",
            Self::Blocked => "blocked",
        }
    }
}

/// The input that decided the network mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkSource {
    /// An explicit `--network` flag.
    NetworkFlag,
    /// One or more `--allow` flags.
    AllowFlag,
    /// The profile has domains.
    ProfileDomains,
    /// No input; pent uses the default.
    Default,
}

/// The resolved network mode and the input that decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetworkDecision {
    /// The mode.
    pub choice: NetworkChoice,
    /// The input that decided the mode.
    pub source: NetworkSource,
}

/// Resolve the network mode. This rule is the same on all platforms.
///
/// The precedence, from high to low:
/// 1. An explicit `--network` flag.
/// 2. `--allow` (this implies proxy mode).
/// 3. Domains in the profile (this implies proxy mode).
/// 4. The default: blocked.
///
/// `--trace` is not an input: tracing never changes the network mode.
/// `profile_domains` must not contain the `--allow` values.
pub(crate) fn resolve_network(
    network_flag: Option<NetworkModeArg>,
    allow_flags: &[String],
    profile_domains: &[String],
) -> NetworkDecision {
    let decide = |choice, source| NetworkDecision { choice, source };
    if let Some(flag) = network_flag {
        let choice = match flag {
            NetworkModeArg::Unrestricted => NetworkChoice::Unrestricted,
            NetworkModeArg::Localhost => NetworkChoice::Localhost,
            NetworkModeArg::Proxy => NetworkChoice::Proxy,
            NetworkModeArg::Blocked => NetworkChoice::Blocked,
        };
        return decide(choice, NetworkSource::NetworkFlag);
    }
    if !allow_flags.is_empty() {
        return decide(NetworkChoice::Proxy, NetworkSource::AllowFlag);
    }
    if !profile_domains.is_empty() {
        return decide(NetworkChoice::Proxy, NetworkSource::ProfileDomains);
    }
    decide(NetworkChoice::Blocked, NetworkSource::Default)
}

/// The network mode for a choice without a proxy.
pub(crate) const fn base_network_mode(choice: NetworkChoice) -> NetworkMode {
    match choice {
        NetworkChoice::Unrestricted => NetworkMode::Unrestricted,
        NetworkChoice::Localhost => NetworkMode::LocalhostOnly,
        NetworkChoice::Blocked => NetworkMode::Blocked,
        // Pent starts the proxy for this choice; the proxy gives the mode.
        // Without a proxy, nothing may go out.
        NetworkChoice::Proxy => NetworkMode::Blocked,
    }
}

/// Return the warnings to show for a network decision.
pub(crate) fn network_warnings(
    decision: NetworkDecision,
    allow_flags: &[String],
    trace: bool,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if decision.source == NetworkSource::NetworkFlag
        && decision.choice != NetworkChoice::Proxy
        && !allow_flags.is_empty()
    {
        warnings.push(format!(
            "--allow has no effect: --network {} has precedence",
            decision.choice.flag_value()
        ));
    }
    if trace && decision.choice != NetworkChoice::Proxy {
        warnings.push(format!(
            "--trace records network events only in proxy mode; the network mode is {}, \
             so this run records no network events",
            decision.choice.flag_value()
        ));
    }
    warnings
}

/// Return the status line for the network mode, if there is one.
pub(crate) fn network_status(mode: &NetworkMode, source: NetworkSource) -> Option<&'static str> {
    match mode {
        // The proxy is the expected mode.
        NetworkMode::ProxyOnly { .. } => None,
        NetworkMode::Blocked if source == NetworkSource::Default => {
            Some("blocked (the profile has no domains)")
        }
        NetworkMode::Blocked => Some("blocked"),
        NetworkMode::LocalhostOnly => Some("localhost only"),
        NetworkMode::Unrestricted => Some("unrestricted"),
    }
}

// ── Trace log ────────────────────────────────────────────────────────────────

/// One entry in the trace log.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceLine {
    /// The proxy allowed an access.
    Allowed(String),
    /// The sandbox or the proxy denied an access, with an optional fix hint.
    Denied {
        message: String,
        fix: Option<String>,
    },
}

/// Format a trace line as the text for the log file.
fn format_trace_line(line: &TraceLine) -> String {
    match line {
        TraceLine::Allowed(msg) => format!("pent: [allowed] {msg}\n\n"),
        TraceLine::Denied { message, fix } => match fix {
            Some(fix) => format!("pent: [denied] {message}\npent: fix: {fix}\n\n"),
            None => format!("pent: [denied] {message}\n\n"),
        },
    }
}

/// Append a trace line to the log file, if there is a log file.
///
/// Opens the log in append mode and writes each entry with one call, so
/// entries do not mix.
fn write_trace_line(log_path: Option<&Path>, line: &TraceLine) {
    let Some(log_path) = log_path else { return };
    let result = pent_settings::open_log_nofollow(log_path, pent_settings::LogOpen::Append)
        .and_then(|mut f| f.write_all(format_trace_line(line).as_bytes()));
    if let Err(e) = result {
        tracing::warn!(path = %log_path.display(), error = %e, "could not write to the trace log");
    }
}

/// Convert one proxy event into a trace line with a fix hint.
fn proxy_trace_line(event: TraceEvent, profile: &ProfileName) -> TraceLine {
    match event {
        TraceEvent::Access(msg) => TraceLine::Allowed(msg),
        TraceEvent::Violation(msg) => TraceLine::Denied {
            fix: Some(proxy_violation_fix(&msg, profile)),
            message: msg,
        },
        TraceEvent::LocalhostClosed { message, port } => TraceLine::Denied {
            fix: Some(localhost_fix(port, profile)),
            message,
        },
    }
}

/// Convert a denied filesystem access into a trace line with a fix hint.
///
/// Returns `None` for other events and for accesses that the sandbox did not
/// deny.
fn access_trace_line(event: &WatchEvent, profile: &ProfileName) -> Option<TraceLine> {
    if let WatchEvent::LocalhostConnect {
        port,
        process,
        outcome: Outcome::Denied,
    } = event
    {
        return Some(TraceLine::Denied {
            message: format!(
                "network: \"{}\" (pid {}) was denied a connection to port {port} on localhost",
                process.name, process.pid
            ),
            fix: Some(format!(
                "allow it for one run with --localhost {port}, or add it to the profile: \
                 pent trust {profile} --review"
            )),
        });
    }
    let WatchEvent::Fs {
        op,
        path,
        process,
        outcome: Outcome::Denied,
    } = event
    else {
        return None;
    };
    let (verb, flag) = match op {
        pent_profile::FsOp::Read => ("read", "--read"),
        pent_profile::FsOp::Write => ("write", "--write"),
        pent_profile::FsOp::Create => ("create", "--write"),
        pent_profile::FsOp::Delete => ("delete", "--write"),
        pent_profile::FsOp::Exec => ("exec", "--execute"),
    };
    let path = path.display();
    Some(TraceLine::Denied {
        message: format!(
            "filesystem: \"{}\" (pid {}) was denied {verb} on \"{path}\"",
            process.name, process.pid
        ),
        fix: Some(format!(
            "allow it for one run with {flag} \"{path}\", or add it to the profile: \
             pent trust {profile} --review"
        )),
    })
}

/// The fix hint for a closed port on localhost.
fn localhost_fix(port: u16, profile: &ProfileName) -> String {
    format!(
        "allow it for one run with --localhost {port}, or add it to the profile: \
         pent trust {profile} --review"
    )
}

/// Compute a fix hint for a proxy violation message.
fn proxy_violation_fix(violation: &str, profile: &ProfileName) -> String {
    let review = format!("pent trust {profile} --review");
    let Some(rest) = violation.strip_prefix("network: ") else {
        return format!("review the denied accesses: {review}");
    };
    // The message names the domain in quotes, for example:
    //   DNS query for "x.com" (A) blocked: the domain is not in the allowlist
    //   SOCKS5 connection to "x.com" port 443 blocked: the domain is not in ...
    let quoted_domain = rest
        .split_once('"')
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(domain, _)| domain);
    if rest.contains("the domain is not in the allowlist") {
        if let Some(domain) = quoted_domain {
            return format!(
                "allow it for one run with --allow {domain}, or add it to the profile: {review}"
            );
        }
    }
    if rest.contains("the domain resolves to the") || rest.contains("blocked: the address is") {
        return "the destination address is not public; if you trust it, set \
                private_destinations = \"allow\" in the [proxy] section of pent.toml"
            .to_string();
    }
    format!(
        "make sure that the process uses DNS names, and add the domain to the profile: {review}"
    )
}

// ── macOS trace ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── resolve_network ──────────────────────────────────────────────────────

    fn domains() -> Vec<String> {
        vec!["example.com".to_string()]
    }

    fn profile_name() -> ProfileName {
        "claude".parse().unwrap()
    }

    #[test]
    fn network_flag_wins_over_everything() {
        let flags = [
            (NetworkModeArg::Unrestricted, NetworkChoice::Unrestricted),
            (NetworkModeArg::Localhost, NetworkChoice::Localhost),
            (NetworkModeArg::Proxy, NetworkChoice::Proxy),
            (NetworkModeArg::Blocked, NetworkChoice::Blocked),
        ];
        for (flag, expected) in flags {
            for allow in [vec![], domains()] {
                for profile in [vec![], domains()] {
                    let d = resolve_network(Some(flag), &allow, &profile);
                    assert_eq!(
                        d,
                        NetworkDecision {
                            choice: expected,
                            source: NetworkSource::NetworkFlag
                        },
                        "flag {expected:?}, allow {allow:?}, profile {profile:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn allow_flag_wins_over_profile() {
        for profile in [vec![], domains()] {
            let d = resolve_network(None, &domains(), &profile);
            assert_eq!(d.choice, NetworkChoice::Proxy);
            assert_eq!(d.source, NetworkSource::AllowFlag);
        }
    }

    #[test]
    fn profile_domains_imply_proxy() {
        let d = resolve_network(None, &[], &domains());
        assert_eq!(d.choice, NetworkChoice::Proxy);
        assert_eq!(d.source, NetworkSource::ProfileDomains);
    }

    #[test]
    fn default_is_blocked() {
        let d = resolve_network(None, &[], &[]);
        assert_eq!(d.choice, NetworkChoice::Blocked);
        assert_eq!(d.source, NetworkSource::Default);
        assert_eq!(
            base_network_mode(NetworkChoice::Proxy),
            NetworkMode::Blocked
        );
    }

    #[test]
    fn merge_domains_keeps_order_without_duplicates() {
        let merged = merge_domains(
            &["a.com".to_string(), "b.com".to_string()],
            &["b.com".to_string(), "c.com".to_string()],
        );
        assert_eq!(merged, vec!["a.com", "b.com", "c.com"]);
    }

    // ── network_warnings ─────────────────────────────────────────────────────

    fn decision(choice: NetworkChoice, source: NetworkSource) -> NetworkDecision {
        NetworkDecision { choice, source }
    }

    #[test]
    fn warns_when_allow_is_ignored() {
        let d = decision(NetworkChoice::Blocked, NetworkSource::NetworkFlag);
        let w = network_warnings(d, &domains(), false);
        assert_eq!(w.len(), 1);
        assert!(w.iter().any(|m| m.contains("--allow has no effect")));
    }

    #[test]
    fn no_warning_for_proxy_mode() {
        let d = decision(NetworkChoice::Proxy, NetworkSource::ProfileDomains);
        assert!(network_warnings(d, &[], false).is_empty());
        assert!(network_warnings(d, &[], true).is_empty());
    }

    #[test]
    fn trace_note_without_proxy() {
        let d = decision(NetworkChoice::Blocked, NetworkSource::Default);
        let w = network_warnings(d, &[], true);
        assert!(w.iter().any(|m| m.contains("only in proxy mode")), "{w:?}");
    }

    #[test]
    fn blocked_hint_only_for_default() {
        let hint = network_status(&NetworkMode::Blocked, NetworkSource::Default);
        assert!(hint.is_some_and(|h| h.contains("no domains")));
        let explicit = network_status(&NetworkMode::Blocked, NetworkSource::NetworkFlag);
        assert_eq!(explicit, Some("blocked"));
    }

    // ── denied accesses ──────────────────────────────────────────────────────

    #[test]
    fn denied_message_names_the_review_command() {
        let n = profile_name();
        assert_eq!(denied_message(0, &n), None);
        assert_eq!(
            denied_message(3, &n).as_deref(),
            Some("3 accesses denied; review them: pent trust claude --review")
        );
        assert_eq!(
            denied_message(1, &n).as_deref(),
            Some("1 access denied; review it: pent trust claude --review")
        );
    }

    #[test]
    fn denied_recorder_writes_distinct_denials_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(pent_settings::PentDirs {
            config: dir.path().join("c"),
            state: dir.path().join("s"),
        });
        let n = profile_name();
        let connect = |host: &str, outcome| WatchEvent::Connect {
            host: host.to_string(),
            port: 443,
            protocol: pent_profile::NetProtocol::HttpConnect,
            outcome,
        };
        {
            let mut rec = DeniedRecorder::new(&store, &n);
            rec.record(&connect("ok.com", Outcome::Allowed));
            assert!(rec.summary().is_none());
            assert!(!store.denied_path(&n).exists(), "no log without a denial");
            rec.record(&connect("evil.com", Outcome::Denied));
            rec.record(&connect("evil.com", Outcome::Denied));
            rec.record(&connect("bad.com", Outcome::Denied));
            assert!(rec
                .summary()
                .is_some_and(|m| m.starts_with("2 accesses denied")));
        }
        assert_eq!(store.read_denied(&n).unwrap().len(), 2);
    }

    // ── trace log ────────────────────────────────────────────────────────────

    #[test]
    fn proxy_fix_names_the_domain_for_connect() {
        let fix = proxy_violation_fix(
            "network: SOCKS5 connection to \"evil.example\" port 443 blocked: \
             the domain is not in the allowlist",
            &profile_name(),
        );
        assert_eq!(
            fix,
            "allow it for one run with --allow evil.example, or add it to the profile: \
             pent trust claude --review"
        );
    }

    #[test]
    fn proxy_fix_names_private_destinations() {
        let fix = proxy_violation_fix(
            "network: CONNECT connection to \"intra.example\" port 443 blocked: \
             the domain resolves to the private address 10.0.0.5",
            &profile_name(),
        );
        assert!(fix.contains("private_destinations"), "{fix}");
    }

    #[test]
    fn trace_line_without_fix_has_no_fix_line() {
        let line = TraceLine::Denied {
            message: "network: x".to_string(),
            fix: None,
        };
        assert_eq!(format_trace_line(&line), "pent: [denied] network: x\n\n");
        let line = TraceLine::Denied {
            message: "m".to_string(),
            fix: Some("f".to_string()),
        };
        assert_eq!(
            format_trace_line(&line),
            "pent: [denied] m\npent: fix: f\n\n"
        );
    }

    #[test]
    fn fs_denial_gives_a_trace_line() {
        let event = |outcome| WatchEvent::Fs {
            op: pent_profile::FsOp::Create,
            path: PathBuf::from("/srv/out.txt"),
            process: pent_profile::ProcessInfo {
                pid: 7,
                name: "sh".to_string(),
            },
            outcome,
        };
        let line = access_trace_line(&event(Outcome::Denied), &profile_name());
        assert_eq!(
            line.map(|l| format_trace_line(&l)),
            Some(format!(
                "pent: [denied] filesystem: \"sh\" (pid 7) was denied create on \"/srv/out.txt\"\n\
                 pent: fix: allow it for one run with --write \"/srv/out.txt\", or add it to the \
                 profile: pent trust {} --review\n\n",
                profile_name()
            ))
        );
        assert_eq!(
            access_trace_line(&event(Outcome::Allowed), &profile_name()),
            None
        );
    }

    #[test]
    fn a_denied_localhost_port_gives_a_trace_line_with_the_flag() {
        let event = |outcome| WatchEvent::LocalhostConnect {
            port: 5432,
            process: pent_profile::ProcessInfo {
                pid: 9,
                name: "psql".to_string(),
            },
            outcome,
        };
        let line = access_trace_line(&event(Outcome::Denied), &profile_name());
        assert_eq!(
            line.map(|l| format_trace_line(&l)),
            Some(format!(
                "pent: [denied] network: \"psql\" (pid 9) was denied a connection to port 5432 \
                 on localhost\n\
                 pent: fix: allow it for one run with --localhost 5432, or add it to the \
                 profile: pent trust {} --review\n\n",
                profile_name()
            ))
        );
        assert_eq!(
            access_trace_line(&event(Outcome::Allowed), &profile_name()),
            None
        );
    }

    #[test]
    fn the_localhost_status_names_the_ports() {
        let port = |n: u16| NonZeroU16::MIN.saturating_add(n - 1);
        let blocked = NetworkMode::Blocked;
        assert_eq!(localhost_status(&blocked, &LocalhostPorts::default()), None);
        assert_eq!(
            localhost_status(&blocked, &LocalhostPorts::Listed(vec![port(5432)])),
            Some("port 5432".to_string())
        );
        assert_eq!(
            localhost_status(
                &blocked,
                &LocalhostPorts::Listed(vec![port(5432), port(6379)])
            ),
            Some("ports 5432, 6379".to_string())
        );
        assert_eq!(
            localhost_status(&NetworkMode::Unrestricted, &LocalhostPorts::All),
            None
        );
        assert_eq!(
            merge_ports(&[port(1), port(2)], &[port(2), port(3)]),
            vec![port(1), port(2), port(3)]
        );
        let flag = resolve_network(Some(NetworkModeArg::Blocked), &[], &[]);
        assert!(blocks_localhost(flag));
        let default = resolve_network(None, &[], &[]);
        assert_eq!(default.choice, NetworkChoice::Blocked);
        assert!(!blocks_localhost(default));
        assert_eq!(closed_ports_source(&[], &[]), None);
        assert_eq!(
            closed_ports_source(&[port(1)], &[]),
            Some("the localhost ports of the profile")
        );
        assert_eq!(
            closed_ports_source(&[], &[port(1)]),
            Some("the --localhost flags")
        );
    }

    /// A closed port on localhost gets the flag that opens it, not the
    /// setting that opens every private network.
    #[test]
    fn a_closed_localhost_port_gets_the_localhost_flag() {
        let event = TraceEvent::LocalhostClosed {
            message: "network: SOCKS5 connection to 127.0.0.1 port 5432 blocked".to_string(),
            port: 5432,
        };
        let fix = match proxy_trace_line(event, &profile_name()) {
            TraceLine::Denied { fix, .. } => fix.unwrap_or_default(),
            TraceLine::Allowed(line) => format!("a closed port must be a denial: {line}"),
        };
        assert!(fix.contains("--localhost 5432"), "{fix}");
        assert!(!fix.contains("private_destinations"), "{fix}");
    }
}
