#[cfg(unix)]
extern crate libc;

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(not(target_os = "macos"))]
use pent_proxy::TraceEvent;
#[cfg(not(target_os = "macos"))]
use pent_proxy::{ProxyConfig, ProxyHandle, ProxyServer};
#[cfg(target_os = "linux")]
use pent_sandbox::teardown_overlay;
use pent_sandbox::{build_env, check_availability, spawn_sandboxed, NetworkMode, SandboxConfig};
use pent_settings::{ConfigLoader, PentConfig};
use tokio::signal::unix::{signal, Signal, SignalKind};

use crate::cli::{NetworkModeArg, RunArgs};
use crate::error::CliError;
use crate::ui;

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

    let mut config = load_config(&args, &cwd)?;
    // Decide the network mode before the CLI overrides merge `--allow` into
    // the config allowlist, so that the two sources stay separate.
    let decision = resolve_network(
        args.network,
        &args.allow,
        config.sandbox.network.as_ref(),
        &config.proxy.domain_allowlist,
    );
    apply_cli_overrides(&mut config, &args)?;
    let env_map = build_run_env(&args.env);
    let trace_log_path = open_trace_log(args.trace, &cwd);

    for warning in network_warnings(decision, &args.allow, args.trace, Platform::CURRENT) {
        ui::warn(warning);
    }

    // ── macOS path ────────────────────────────────────────────────────────────
    #[cfg(target_os = "macos")]
    let resolved_network: NetworkMode = macos_network_mode(decision.choice);

    // ── non-macOS path ────────────────────────────────────────────────────────
    #[cfg(not(target_os = "macos"))]
    let ProxySetup {
        network: resolved_network,
        handle: proxy_handle,
        event_rx,
    } = setup_proxy(&config, decision.choice, args.trace).await?;

    // Build SandboxConfig.
    // from_sandbox_settings merges user paths on top of system defaults and
    // handles mounts, replacing the previous manual path-extension loop.
    let mut sandbox_cfg = SandboxConfig::from_sandbox_settings(config.sandbox, cwd.clone(), cwd)
        .with_network(resolved_network)
        .with_env(env_map);

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

    let (cmd, cmd_args) = args
        .command
        .split_first()
        .ok_or_else(|| CliError::Other("command list is empty".to_string()))?;

    // Print network mode hint BEFORE spawn so the user sees it even if spawn
    // takes time (ProxyOnly veth setup) or stalls during namespace init.
    if let Some(line) = network_status(&sandbox_cfg.network, decision.source) {
        ui::status("network", line);
    }

    // Install the signal handlers before the spawn. A signal that comes
    // between the spawn and the wait then goes to the child and does not
    // kill pent before the cleanup.
    let mut signals = SignalRelay::install()?;

    // macOS: start `log stream` before the spawn, so that the first denials
    // of the child are in the trace log.
    #[cfg(target_os = "macos")]
    let mut tracer = if args.trace {
        macos_trace::Tracer::start()
    } else {
        None
    };

    let sandbox_child = spawn_sandboxed(&sandbox_cfg, cmd, cmd_args)?;

    #[cfg(target_os = "linux")]
    let cleanup = SessionCleanup::new(
        sandbox_child.child.id(),
        LinuxResources {
            overlay: sandbox_child.overlay,
            netns: sandbox_child.netns,
            trace: args.trace,
        },
    );
    #[cfg(not(target_os = "linux"))]
    let cleanup = SessionCleanup::new(sandbox_child.child.id(), ());
    let child = sandbox_child.child;

    // macOS: in trace mode, stream the Seatbelt denials of the child and its
    // descendants. Other platforms: in trace mode, stream proxy events.
    #[cfg(target_os = "macos")]
    let (event_rx, drain_grace) = match tracer.as_mut() {
        Some(t) => (t.attach(child.id()), macos_trace::DRAIN_GRACE),
        None => (None, Duration::ZERO),
    };
    #[cfg(not(target_os = "macos"))]
    let (event_rx, drain_grace) = (event_rx.map(proxy_trace_lines), Duration::ZERO);

    let exit_status = wait_child(
        child,
        &mut signals,
        event_rx,
        trace_log_path.as_deref(),
        drain_grace,
    )
    .await;

    // Flush overlayfs write-listed files back to real inodes, clean up
    // staging directories and drop the netns handle (this removes the
    // firewall and routing rules). This must happen after the wait, so the
    // child's mount namespace is already destroyed and no writes are in
    // flight.
    cleanup.finish();

    #[cfg(target_os = "macos")]
    drop(tracer);

    #[cfg(not(target_os = "macos"))]
    if let Some(handle) = proxy_handle {
        if let Err(e) = handle.shutdown().await {
            ui::warn(format!("proxy shutdown failed: {e}"));
        }
    }

    exit_like_child(exit_status)
}

/// Load and merge config.
/// `--no-config` skips global/project config files but `--config <extra>` still applies.
///
/// An untrusted or changed project config does not apply. Pent prints a
/// warning and continues with the global config only.
fn load_config(args: &RunArgs, cwd: &Path) -> Result<PentConfig, CliError> {
    let mut config = if args.no_config {
        PentConfig::default()
    } else {
        let loaded = ConfigLoader::load_with_status(cwd)?;
        crate::commands::config::warn_if_project_ignored(&loaded);
        loaded.config
    };
    if let Some(ref extra) = args.extra_config {
        let mut extra_cfg = PentConfig::load(extra)?;
        // Relative paths in the extra file also resolve against the workspace.
        extra_cfg.resolve_relative_paths(cwd);
        config = config.merge(extra_cfg);
    }
    Ok(config)
}

/// Merge CLI flag overrides into the loaded config.
fn apply_cli_overrides(config: &mut PentConfig, args: &RunArgs) -> Result<(), CliError> {
    config.sandbox.paths.traversal.extend(
        args.traverse
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    config
        .sandbox
        .paths
        .read
        .extend(args.read.iter().map(|p| p.to_string_lossy().into_owned()));
    config
        .sandbox
        .paths
        .read_write
        .extend(args.write.iter().map(|p| p.to_string_lossy().into_owned()));
    config.sandbox.paths.execute.extend(
        args.execute
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    config
        .proxy
        .domain_allowlist
        .extend(args.allow.iter().cloned());

    // On Linux, read_write paths must be exact filenames — glob ('*') patterns
    // are not supported because overlayfs requires specific paths to mount over.
    #[cfg(target_os = "linux")]
    config.sandbox.paths.validate_no_rw_globs()?;

    Ok(())
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

/// Tell the user about edits that pent could not save, and (in trace mode)
/// about writes that the overlay discards.
#[cfg(target_os = "linux")]
fn show_overlay_report(report: &pent_sandbox::OverlayTeardownReport, trace: bool) {
    for failure in &report.failures {
        ui::error(format!(
            "edit not saved: {}: {}",
            failure.path.display(),
            failure.error
        ));
    }
    for dir in &report.kept_staging {
        ui::warn(format!("pent keeps the unsaved edits in {}", dir.display()));
    }
    if report.killed_descendants > 0 {
        ui::warn(format!(
            "pent stopped {} sandbox processes that still ran after the command exited",
            report.killed_descendants
        ));
    }
    if trace {
        for discarded in &report.discarded {
            ui::warn(discarded);
        }
    }
}

/// Create `.pent/trace.log` when `trace` is true; emit warnings on failure.
fn open_trace_log(trace: bool, cwd: &Path) -> Option<PathBuf> {
    if !trace {
        return None;
    }
    let pent_dir = cwd.join(".pent");
    match std::fs::create_dir_all(&pent_dir) {
        Ok(()) => {
            let log_path = pent_dir.join("trace.log");
            match std::fs::File::create(&log_path) {
                Ok(_) => {
                    ui::status("tracing", log_path.display());
                    Some(log_path)
                }
                Err(e) => {
                    ui::warn(format!("could not create trace log: {e}"));
                    None
                }
            }
        }
        Err(e) => {
            ui::warn(format!("could not create .pent directory: {e}"));
            None
        }
    }
}

// ── Network mode resolution ──────────────────────────────────────────────────

/// The network mode that the user asks for, before pent starts a proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkChoice {
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
enum NetworkSource {
    /// An explicit `--network` flag.
    NetworkFlag,
    /// One or more `--allow` flags.
    AllowFlag,
    /// `[sandbox.network] mode` in the merged config.
    ConfigMode,
    /// A non-empty `[proxy] domain_allowlist` in the merged config.
    ConfigAllowlist,
    /// No input; pent uses the default.
    Default,
}

/// The resolved network mode and the input that decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkDecision {
    choice: NetworkChoice,
    source: NetworkSource,
}

/// Resolve the network mode. This rule is the same on all platforms.
///
/// The precedence, from high to low:
/// 1. An explicit `--network` flag.
/// 2. `--allow` (this implies proxy mode).
/// 3. `[sandbox.network] mode` in the config.
/// 4. A non-empty `[proxy] domain_allowlist` in the config (this implies
///    proxy mode, so a config with only profiles enables the proxy).
/// 5. The default: blocked.
///
/// `--trace` is not an input: tracing never changes the network mode.
/// `config_allowlist` must not contain the `--allow` values.
fn resolve_network(
    network_flag: Option<NetworkModeArg>,
    allow_flags: &[String],
    config_mode: Option<&NetworkMode>,
    config_allowlist: &[String],
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
    if let Some(mode) = config_mode {
        let choice = match mode {
            NetworkMode::Unrestricted => NetworkChoice::Unrestricted,
            NetworkMode::LocalhostOnly => NetworkChoice::Localhost,
            NetworkMode::ProxyOnly { .. } => NetworkChoice::Proxy,
            NetworkMode::Blocked => NetworkChoice::Blocked,
        };
        return decide(choice, NetworkSource::ConfigMode);
    }
    if !config_allowlist.is_empty() {
        return decide(NetworkChoice::Proxy, NetworkSource::ConfigAllowlist);
    }
    decide(NetworkChoice::Blocked, NetworkSource::Default)
}

/// The platform that pent runs on, for the platform-specific warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    MacOs,
}

impl Platform {
    #[cfg(target_os = "macos")]
    const CURRENT: Self = Self::MacOs;
    #[cfg(not(target_os = "macos"))]
    const CURRENT: Self = Self::Linux;
}

/// Return the warnings to show for a network decision.
fn network_warnings(
    decision: NetworkDecision,
    allow_flags: &[String],
    trace: bool,
    platform: Platform,
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
    if decision.choice == NetworkChoice::Proxy && platform == Platform::MacOs {
        warnings.push(
            "network is unrestricted: pent cannot enforce the domain allowlist on macOS \
             (see \"Platform limitations\" in the README)"
                .to_string(),
        );
    }
    if trace && decision.choice != NetworkChoice::Proxy && platform == Platform::Linux {
        warnings.push(format!(
            "--trace records network events only in proxy mode; the network mode is {}, \
             so this run records no network events",
            decision.choice.flag_value()
        ));
    }
    warnings
}

/// Return the status line for the network mode, if there is one.
fn network_status(mode: &NetworkMode, source: NetworkSource) -> Option<&'static str> {
    match mode {
        // On Linux, the proxy is the expected mode. On macOS, the warning
        // from `network_warnings` already tells the user about the proxy.
        NetworkMode::ProxyOnly { .. } => None,
        NetworkMode::Blocked if source == NetworkSource::Default => {
            Some("blocked — add domains to [proxy] domain_allowlist in pent.toml to enable")
        }
        NetworkMode::Blocked => Some("blocked"),
        NetworkMode::LocalhostOnly => Some("localhost only"),
        NetworkMode::Unrestricted => Some("unrestricted"),
    }
}

/// macOS cannot enforce proxy mode, so proxy mode becomes `Unrestricted`.
///
/// Proxy-based network enforcement is not available on macOS (no per-process
/// network namespaces; `DYLD_INSERT_LIBRARIES` is unreliable across Go binaries
/// and hardened-runtime binaries). `network_warnings` tells the user about this.
#[cfg(target_os = "macos")]
const fn macos_network_mode(choice: NetworkChoice) -> NetworkMode {
    match choice {
        NetworkChoice::Unrestricted | NetworkChoice::Proxy => NetworkMode::Unrestricted,
        NetworkChoice::Localhost => NetworkMode::LocalhostOnly,
        NetworkChoice::Blocked => NetworkMode::Blocked,
    }
}

// ── Signals, wait and exit ───────────────────────────────────────────────────

/// Receives the signals that pent handles while the child runs.
///
/// - SIGTERM, SIGHUP, SIGUSR1 and SIGUSR2 go to the child.
/// - SIGINT and SIGQUIT do not go to the child. When they come from the
///   terminal, the kernel sends them to all of the foreground process group,
///   which includes the child. To send them again would deliver them two
///   times. Pent itself ignores them, like `time` and `sudo` do, and waits
///   for the child.
/// - SIGWINCH is not handled. The kernel sends it to the foreground process
///   group, so the child gets it directly.
///
/// The handlers keep pent alive, so pent always runs its cleanup after the
/// child exits.
struct SignalRelay {
    interrupt: Signal,
    quit: Signal,
    terminate: Signal,
    hangup: Signal,
    user1: Signal,
    user2: Signal,
}

/// What pent does with a signal that it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalAction {
    /// Send the signal to the child.
    Forward(libc::c_int),
    /// Do nothing; the child gets the signal from the terminal.
    Ignore,
}

impl SignalRelay {
    /// Install the signal handlers.
    ///
    /// # Errors
    /// Returns an I/O error if tokio cannot install a handler.
    fn install() -> Result<Self, CliError> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            quit: signal(SignalKind::quit())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            user1: signal(SignalKind::user_defined1())?,
            user2: signal(SignalKind::user_defined2())?,
        })
    }

    /// Wait for the next signal and return what to do with it.
    async fn recv(&mut self) -> SignalAction {
        tokio::select! {
            Some(()) = self.interrupt.recv() => SignalAction::Ignore,
            Some(()) = self.quit.recv() => SignalAction::Ignore,
            Some(()) = self.terminate.recv() => SignalAction::Forward(libc::SIGTERM),
            Some(()) = self.hangup.recv() => SignalAction::Forward(libc::SIGHUP),
            Some(()) = self.user1.recv() => SignalAction::Forward(libc::SIGUSR1),
            Some(()) = self.user2.recv() => SignalAction::Forward(libc::SIGUSR2),
            // All streams are closed. This occurs only when the tokio runtime
            // stops. Wait forever; the child wait ends the loop.
            else => std::future::pending().await,
        }
    }
}

/// Send `sig` to the process `pid`.
fn send_signal(pid: u32, sig: libc::c_int) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        tracing::warn!(pid, "child PID does not fit in pid_t; signal not sent");
        return;
    };
    // SAFETY: kill() has no memory-safety preconditions. `pid` is the PID of
    // our child. The wait thread can reap the child just before this call;
    // then, in theory, a new process can get the same PID. This window is
    // very small, and all tools that forward signals have the same race.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc != 0 {
        // ESRCH: the child exited between the signal and the kill. The wait
        // ends soon, so there is nothing to do.
        tracing::debug!(
            pid,
            sig,
            error = %std::io::Error::last_os_error(),
            "could not send the signal to the child"
        );
    }
}

/// Synthesize exit code 1 for a `wait()` that failed.
fn failed_wait_status() -> std::process::ExitStatus {
    // wait() can only fail if the child was already waited on.
    std::os::unix::process::ExitStatusExt::from_raw(1 << 8)
}

/// Wait for `child` to exit. While it runs, send signals to it and write
/// trace lines to the log.
///
/// After the child exits, the function reads the remaining trace lines for
/// at most `drain_grace`. Use a non-zero value when the lines come with a
/// delay (the macOS unified log).
async fn wait_child(
    mut child: std::process::Child,
    signals: &mut SignalRelay,
    mut events: Option<tokio::sync::mpsc::UnboundedReceiver<TraceLine>>,
    trace_log_path: Option<&Path>,
    drain_grace: Duration,
) -> std::process::ExitStatus {
    let pid = child.id();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<std::process::ExitStatus>();
    // Wait in a thread so that tokio can handle the signals and the trace
    // events at the same time.
    std::thread::spawn(move || {
        let status = child.wait().unwrap_or_else(|_| failed_wait_status());
        if done_tx.send(status).is_err() {
            // The receiver is gone: pent is about to exit. Nothing to report.
            tracing::debug!("child exit status not delivered; pent is exiting");
        }
    });

    let status = loop {
        tokio::select! {
            biased;
            result = &mut done_rx => {
                break result.unwrap_or_else(|_| failed_wait_status());
            }
            action = signals.recv() => {
                if let SignalAction::Forward(sig) = action {
                    send_signal(pid, sig);
                }
            }
            event = next_event(&mut events) => match event {
                Some(line) => write_trace_line(trace_log_path, &line),
                // The sender is gone; stop the poll of this channel.
                None => events = None,
            },
        }
    };

    if let Some(mut rx) = events {
        let deadline = tokio::time::Instant::now() + drain_grace;
        loop {
            match rx.try_recv() {
                Ok(line) => write_trace_line(trace_log_path, &line),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(line)) => write_trace_line(trace_log_path, &line),
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
    }
    status
}

/// Receive the next trace line, or wait forever if there is no channel.
async fn next_event(
    events: &mut Option<tokio::sync::mpsc::UnboundedReceiver<TraceLine>>,
) -> Option<TraceLine> {
    match events {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Exit pent with the same status as the child.
///
/// If a signal killed the child, pent sends the same signal to itself, so the
/// parent shell or CI system sees the correct reason for the termination.
fn exit_like_child(status: std::process::ExitStatus) -> ! {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        // SAFETY: signal() and raise() have no memory-safety preconditions.
        // We are past all cleanup and about to exit. The Rust runtime sets
        // SIGPIPE to SIG_IGN and tokio installs handlers for other signals,
        // so we set the default action first; otherwise raise() has no
        // effect.
        unsafe {
            if libc::signal(sig, libc::SIG_DFL) != libc::SIG_ERR {
                libc::raise(sig);
            }
        }
        // raise() returned: the default action of the signal does not end
        // the process, or the signal is blocked. Use the shell convention.
        std::process::exit(128_i32.saturating_add(sig));
    }
    std::process::exit(status.code().unwrap_or(1));
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

/// Platform resources that pent must release after the child exits.
trait Teardown {
    /// Release the resources.
    fn teardown(self);
}

impl Teardown for () {
    fn teardown(self) {}
}

/// The Linux resources of one sandboxed run.
///
/// `N` is the network namespace handle type of `pent-sandbox`. Dropping it
/// removes the firewall and routing rules.
#[cfg(target_os = "linux")]
struct LinuxResources<N> {
    overlay: Option<pent_sandbox::OverlayHandle>,
    netns: Option<N>,
    /// Show the writes that the overlay discards (trace mode).
    trace: bool,
}

#[cfg(target_os = "linux")]
impl<N> Teardown for LinuxResources<N> {
    fn teardown(self) {
        if let Some(handle) = self.overlay {
            let report = teardown_overlay(handle);
            show_overlay_report(&report, self.trace);
        }
        drop(self.netns);
    }
}

/// Releases the sandbox resources when the run ends.
///
/// Call [`SessionCleanup::finish`] after the child exits. If the value drops
/// before `finish` (for example during a panic), the drop kills the child
/// first, so the teardown does not race with the writes of the child.
struct SessionCleanup<R: Teardown> {
    /// The child PID while the child can still run.
    running_child: Option<u32>,
    resources: Option<R>,
}

impl<R: Teardown> SessionCleanup<R> {
    const fn new(child_pid: u32, resources: R) -> Self {
        Self {
            running_child: Some(child_pid),
            resources: Some(resources),
        }
    }

    /// Mark the child as exited and release the resources.
    fn finish(mut self) {
        self.running_child = None;
        // The drop releases the resources.
    }
}

impl<R: Teardown> Drop for SessionCleanup<R> {
    fn drop(&mut self) {
        if let Some(pid) = self.running_child.take() {
            send_signal(pid, libc::SIGKILL);
        }
        if let Some(resources) = self.resources.take() {
            resources.teardown();
        }
    }
}

// ── Trace log ────────────────────────────────────────────────────────────────

/// One entry in the trace log.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceLine {
    /// The sandbox or the proxy allowed an access. Only the proxy reports
    /// these, and the proxy does not run on macOS.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
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
    let result = std::fs::OpenOptions::new()
        .append(true)
        .open(log_path)
        .and_then(|mut f| f.write_all(format_trace_line(line).as_bytes()));
    if let Err(e) = result {
        tracing::warn!(path = %log_path.display(), error = %e, "could not write to the trace log");
    }
}

/// Convert the proxy event channel into a trace line channel.
#[cfg(not(target_os = "macos"))]
fn proxy_trace_lines(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<TraceEvent>,
) -> tokio::sync::mpsc::UnboundedReceiver<TraceLine> {
    let (tx, out) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if tx.send(proxy_trace_line(event)).is_err() {
                // The wait loop is gone; stop the conversion.
                break;
            }
        }
    });
    out
}

/// Convert one proxy event into a trace line with a fix hint.
#[cfg(not(target_os = "macos"))]
fn proxy_trace_line(event: TraceEvent) -> TraceLine {
    match event {
        TraceEvent::Access(msg) => TraceLine::Allowed(msg),
        TraceEvent::Violation(msg) => TraceLine::Denied {
            fix: Some(proxy_violation_fix(&msg)),
            message: msg,
        },
    }
}

/// Compute a fix hint for a proxy violation message.
#[cfg(any(test, not(target_os = "macos")))]
fn proxy_violation_fix(violation: &str) -> String {
    let Some(rest) = violation.strip_prefix("network: ") else {
        return "review your pent config".to_string();
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
                "add \"{domain}\" to domain_allowlist in the [proxy] section of your pent config"
            );
        }
    }
    if rest.contains("the domain resolves to the") || rest.contains("blocked: the address is") {
        return "the destination address is not public; if you trust it, set \
                private_destinations = \"allow\" in the [proxy] section of your pent config"
            .to_string();
    }
    "make sure that the process uses DNS names and that the domain is in \
     domain_allowlist in the [proxy] section of your pent config"
        .to_string()
}

// ── macOS trace ──────────────────────────────────────────────────────────────

/// Read the Seatbelt denials of the child from the macOS unified log.
///
/// The parse functions are pure, so their unit tests also run on Linux.
#[cfg(any(test, target_os = "macos"))]
mod macos_trace {
    use std::collections::{HashMap, HashSet};
    #[cfg(target_os = "macos")]
    use std::path::Path;

    /// One Seatbelt denial from the kernel log.
    ///
    /// The kernel writes lines of this form:
    /// ```text
    /// Sandbox: cat(1234) deny(1) file-read-data /Users/x/.ssh/id_rsa
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct SandboxDenial {
        pub(super) process: String,
        pub(super) pid: u32,
        pub(super) operation: String,
        pub(super) target: String,
    }

    /// The kind of a Seatbelt operation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum OperationKind {
        FileRead,
        FileWrite,
        ProcessExec,
        Network,
        Other,
    }

    impl OperationKind {
        pub(super) fn of(operation: &str) -> Self {
            if operation.starts_with("file-read") {
                Self::FileRead
            } else if operation.starts_with("file-write") {
                Self::FileWrite
            } else if operation.starts_with("process-exec") {
                Self::ProcessExec
            } else if operation.starts_with("network") {
                Self::Network
            } else {
                Self::Other
            }
        }

        const fn category(self) -> &'static str {
            match self {
                Self::FileRead | Self::FileWrite | Self::ProcessExec => "filesystem",
                Self::Network => "network",
                Self::Other => "sandbox",
            }
        }
    }

    /// Whether a denied path is a directory.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum PathKind {
        Directory,
        NotDirectory,
    }

    #[cfg(target_os = "macos")]
    pub(super) fn path_kind(path: &Path) -> PathKind {
        if path.is_dir() {
            PathKind::Directory
        } else {
            PathKind::NotDirectory
        }
    }

    /// Parse a Seatbelt denial from one line of `log stream` output.
    ///
    /// Returns `None` if the line is not a denial.
    pub(super) fn parse_denial(line: &str) -> Option<SandboxDenial> {
        const DENY: &str = ") deny";
        const PREFIX: &str = "Sandbox: ";
        let marker = line.find(DENY)?;
        let head = line.get(..marker)?;
        let open = head.rfind('(')?;
        let pid: u32 = head.get(open + 1..)?.trim().parse().ok()?;
        let name_part = head.get(..open)?;
        let process = match name_part.rfind(PREFIX) {
            Some(i) => name_part.get(i + PREFIX.len()..)?,
            None => name_part.rsplit(char::is_whitespace).next()?,
        }
        .trim();
        if process.is_empty() {
            return None;
        }
        let mut rest = line.get(marker + DENY.len()..)?;
        // Skip the "(1)" count when it is present.
        if let Some(after_open) = rest.strip_prefix('(') {
            let close = after_open.find(')')?;
            rest = after_open.get(close + 1..)?;
        }
        let rest = rest.trim();
        let (operation, target) = rest
            .split_once(char::is_whitespace)
            .map_or((rest, ""), |(op, target)| (op, target.trim()));
        if operation.is_empty() {
            return None;
        }
        Some(SandboxDenial {
            process: process.to_string(),
            pid,
            operation: operation.to_string(),
            target: target.to_string(),
        })
    }

    /// Format the trace log message for a denial.
    pub(super) fn denial_message(denial: &SandboxDenial) -> String {
        let category = OperationKind::of(&denial.operation).category();
        let SandboxDenial {
            process,
            pid,
            operation,
            target,
        } = denial;
        if target.is_empty() {
            format!("{category}: \"{process}\" (pid {pid}) was denied {operation}")
        } else {
            format!("{category}: \"{process}\" (pid {pid}) was denied {operation} on \"{target}\"")
        }
    }

    /// Return a fix hint for a denial, if the config can allow it.
    ///
    /// Only filesystem operations on an absolute path get a hint. The config
    /// cannot allow network or other operations per path.
    pub(super) fn denial_fix(denial: &SandboxDenial, kind: PathKind) -> Option<String> {
        let path = denial.target.as_str();
        if !path.starts_with('/') {
            return None;
        }
        let key = match OperationKind::of(&denial.operation) {
            OperationKind::FileRead if kind == PathKind::Directory => {
                return Some(format!(
                    "add \"{path}\" to traversal (to list the directory) or to read \
                     (to read the files in it) in the [sandbox.paths] section of your pent config"
                ));
            }
            OperationKind::FileRead => "read",
            OperationKind::FileWrite => "read_write",
            OperationKind::ProcessExec => "execute",
            OperationKind::Network | OperationKind::Other => return None,
        };
        Some(format!(
            "add \"{path}\" to {key} in the [sandbox.paths] section of your pent config"
        ))
    }

    /// Parse the output of `ps -A -o pid=,ppid=` into `(pid, ppid)` pairs.
    pub(super) fn parse_ps_output(output: &str) -> Vec<(u32, u32)> {
        output
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let pid = fields.next()?.parse().ok()?;
                let ppid = fields.next()?.parse().ok()?;
                Some((pid, ppid))
            })
            .collect()
    }

    /// Return `root` and all its descendants in the `(pid, ppid)` pairs.
    pub(super) fn descendants_of(root: u32, pairs: &[(u32, u32)]) -> HashSet<u32> {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for &(pid, ppid) in pairs {
            children.entry(ppid).or_default().push(pid);
        }
        let mut found = HashSet::from([root]);
        let mut queue = vec![root];
        while let Some(pid) = queue.pop() {
            for &child in children.get(&pid).map_or(&[][..], Vec::as_slice) {
                if found.insert(child) {
                    queue.push(child);
                }
            }
        }
        found
    }

    #[cfg(target_os = "macos")]
    pub(super) use runtime::{Tracer, DRAIN_GRACE};

    #[cfg(target_os = "macos")]
    mod runtime {
        use std::collections::HashSet;
        use std::io::BufRead as _;
        use std::path::Path;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::{Receiver, RecvTimeoutError};
        use std::sync::{Arc, Mutex, MutexGuard};
        use std::time::{Duration, Instant};

        use super::{
            denial_fix, denial_message, descendants_of, parse_denial, parse_ps_output, path_kind,
        };
        use crate::commands::run::TraceLine;
        use crate::ui;

        /// The time to wait for `log stream` to print its header.
        const READY_TIMEOUT: Duration = Duration::from_secs(3);
        /// The interval of the process-tree poll.
        const POLL_INTERVAL: Duration = Duration::from_millis(200);
        /// The minimum time between two process-tree refreshes on demand.
        const MIN_REFRESH_GAP: Duration = Duration::from_millis(50);
        /// The time to read late log lines after the child exits.
        pub(in crate::commands::run) const DRAIN_GRACE: Duration = Duration::from_millis(500);

        /// The `log stream` predicate. The kernel writes each Seatbelt
        /// denial as "Sandbox: <name>(<pid>) deny(1) <operation> <target>".
        const PREDICATE: &str = r#"eventMessage CONTAINS "deny(""#;

        /// The PIDs of the child and its descendants.
        ///
        /// The set only grows, so a denial that the log reports after a
        /// process exits still matches.
        struct ProcessTree {
            root: u32,
            known: HashSet<u32>,
            last_refresh: Option<Instant>,
        }

        impl ProcessTree {
            fn new(root: u32) -> Self {
                Self {
                    root,
                    known: HashSet::from([root]),
                    last_refresh: None,
                }
            }

            fn refresh(&mut self) {
                self.last_refresh = Some(Instant::now());
                match Command::new("/bin/ps")
                    .args(["-A", "-o", "pid=,ppid="])
                    .stderr(Stdio::null())
                    .output()
                {
                    Ok(out) => {
                        let pairs = parse_ps_output(&String::from_utf8_lossy(&out.stdout));
                        self.known.extend(descendants_of(self.root, &pairs));
                    }
                    Err(e) => tracing::debug!(error = %e, "ps failed"),
                }
            }

            /// Return true if `pid` is in the tree. Refresh first if the PID
            /// is not known and the last refresh is not too recent.
            fn contains(&mut self, pid: u32) -> bool {
                if self.known.contains(&pid) {
                    return true;
                }
                if self
                    .last_refresh
                    .is_none_or(|t| t.elapsed() >= MIN_REFRESH_GAP)
                {
                    self.refresh();
                }
                self.known.contains(&pid)
            }
        }

        fn lock(tree: &Mutex<ProcessTree>) -> MutexGuard<'_, ProcessTree> {
            // A poisoned lock only means that a thread panicked during a
            // refresh; the set of PIDs is still valid.
            tree.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        /// A running `log stream` process that reads Seatbelt denials.
        pub(in crate::commands::run) struct Tracer {
            log_proc: std::process::Child,
            lines: Option<Receiver<String>>,
            stop: Arc<AtomicBool>,
        }

        impl Tracer {
            /// Start `log stream` and wait until it prints its header.
            ///
            /// Start the tracer before the child, so that the log does not
            /// miss the first denials. A small race stays: `log stream`
            /// prints its header just before it connects to the log.
            ///
            /// Returns `None` (after a warning) if `log stream` cannot start.
            pub(in crate::commands::run) fn start() -> Option<Self> {
                let mut log_proc = match Command::new("/usr/bin/log")
                    .args([
                        "stream",
                        "--predicate",
                        PREDICATE,
                        "--style",
                        // syslog avoids the column-width truncation of
                        // "compact" style, which cuts off long paths.
                        "syslog",
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(child) => child,
                    Err(e) => {
                        ui::warn(format!(
                            "could not start `log stream`; the trace log has no sandbox denials: {e}"
                        ));
                        return None;
                    }
                };
                let Some(stdout) = log_proc.stdout.take() else {
                    ui::warn(
                        "`log stream` has no output pipe; the trace log has no sandbox denials",
                    );
                    stop_log_process(&mut log_proc);
                    return None;
                };
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                std::thread::spawn(move || {
                    for line in std::io::BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if tx.send(line).is_err() {
                            // The tracer is gone; stop the read.
                            break;
                        }
                    }
                });
                match rx.recv_timeout(READY_TIMEOUT) {
                    // The first line is the header of `log stream`.
                    Ok(_header) => {}
                    Err(RecvTimeoutError::Timeout) => ui::warn(
                        "`log stream` did not start in time; the trace log can miss \
                         the first sandbox denials",
                    ),
                    Err(RecvTimeoutError::Disconnected) => {
                        ui::warn("`log stream` stopped; the trace log has no sandbox denials");
                        stop_log_process(&mut log_proc);
                        return None;
                    }
                }
                Some(Self {
                    log_proc,
                    lines: Some(rx),
                    stop: Arc::new(AtomicBool::new(false)),
                })
            }

            /// Start to filter the log for the process tree of `root_pid`.
            ///
            /// Returns the channel of trace lines. Returns `None` if the
            /// tracer is already attached.
            pub(in crate::commands::run) fn attach(
                &mut self,
                root_pid: u32,
            ) -> Option<tokio::sync::mpsc::UnboundedReceiver<TraceLine>> {
                let lines = self.lines.take()?;
                let tree = Arc::new(Mutex::new(ProcessTree::new(root_pid)));

                // Poll the process tree, so that short-lived descendants are
                // known before their denials arrive.
                {
                    let tree = Arc::clone(&tree);
                    let stop = Arc::clone(&self.stop);
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            lock(&tree).refresh();
                            std::thread::sleep(POLL_INTERVAL);
                        }
                    });
                }

                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                std::thread::spawn(move || {
                    for line in lines {
                        let Some(denial) = parse_denial(&line) else {
                            continue;
                        };
                        // Denials of other sandboxed processes on the system
                        // are also in the log. Keep only our process tree.
                        if !lock(&tree).contains(denial.pid) {
                            continue;
                        }
                        let fix = denial_fix(&denial, path_kind(Path::new(&denial.target)));
                        let message = denial_message(&denial);
                        if tx.send(TraceLine::Denied { message, fix }).is_err() {
                            // The wait loop is gone; stop the filter.
                            break;
                        }
                    }
                });
                Some(rx)
            }
        }

        impl Drop for Tracer {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                stop_log_process(&mut self.log_proc);
            }
        }

        /// Kill and reap the `log stream` process.
        fn stop_log_process(log_proc: &mut std::process::Child) {
            if let Err(e) = log_proc.kill() {
                tracing::debug!(error = %e, "could not kill `log stream`");
            }
            if let Err(e) = log_proc.wait() {
                tracing::debug!(error = %e, "could not reap `log stream`");
            }
        }
    }
}

// ── Proxy setup ──────────────────────────────────────────────────────────────

/// Non-macOS: start the proxy (if needed) and return the resolved network mode,
/// optional proxy handle, and optional event receiver for trace mode.
#[cfg(not(target_os = "macos"))]
struct ProxySetup {
    network: NetworkMode,
    handle: Option<ProxyHandle>,
    event_rx: Option<tokio::sync::mpsc::UnboundedReceiver<TraceEvent>>,
}

#[cfg(not(target_os = "macos"))]
async fn setup_proxy(
    config: &PentConfig,
    choice: NetworkChoice,
    trace: bool,
) -> Result<ProxySetup, CliError> {
    let base_network = match choice {
        NetworkChoice::Unrestricted => NetworkMode::Unrestricted,
        NetworkChoice::Localhost => NetworkMode::LocalhostOnly,
        NetworkChoice::Blocked => NetworkMode::Blocked,
        NetworkChoice::Proxy => {
            // Handled below: the proxy starts and gives the address.
            NetworkMode::LocalhostOnly
        }
    };

    if choice == NetworkChoice::Proxy {
        let (violation_tx, event_rx) = if trace {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let mut proxy_config =
            ProxyConfig::try_from(&config.proxy).map_err(|e| CliError::Other(e.to_string()))?;
        proxy_config.violation_tx = violation_tx;
        // On Linux, ProxyOnly routes child traffic from a separate network
        // namespace through a veth pair. The child's loopback is isolated, so
        // the TCP proxy and the DNS server listen on the host side of the
        // veth. Create the veth first, then bind to its outer address only.
        // Other hosts on the LAN cannot reach this address (the host firewall
        // drops packets to it from other interfaces). spawn_sandboxed uses the
        // prepared veth because proxy_addr is on its outer address.
        #[cfg(target_os = "linux")]
        {
            let outer_ip = pent_sandbox::prepare_proxy_network()?;
            let bind_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(outer_ip), 0);
            proxy_config.proxy_bind_addr = bind_addr;
            proxy_config.dns_bind_addr = bind_addr;
        }
        let handle = ProxyServer::new(proxy_config)?.start().await?;
        let proxy_addr = handle.proxy_addr();
        let dns_port = handle.dns_addr().port();
        tracing::debug!(
            http_proxy = %format!("http://127.0.0.1:{}", proxy_addr.port()),
            socks5_proxy = %format!("socks5h://127.0.0.1:{}", proxy_addr.port()),
            dns = %handle.dns_addr(),
            "proxy started (HTTP CONNECT + SOCKS5h on same port); DNS resolved server-side"
        );
        Ok(ProxySetup {
            network: NetworkMode::ProxyOnly {
                proxy_addr,
                dns_port,
            },
            handle: Some(handle),
            event_rx,
        })
    } else {
        Ok(ProxySetup {
            network: base_network,
            handle: None,
            event_rx: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── resolve_network ──────────────────────────────────────────────────────

    fn proxy_mode() -> NetworkMode {
        NetworkMode::ProxyOnly {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            dns_port: 0,
        }
    }

    fn domains() -> Vec<String> {
        vec!["example.com".to_string()]
    }

    #[test]
    fn network_flag_wins_over_everything() {
        let flags = [
            (NetworkModeArg::Unrestricted, NetworkChoice::Unrestricted),
            (NetworkModeArg::Localhost, NetworkChoice::Localhost),
            (NetworkModeArg::Proxy, NetworkChoice::Proxy),
            (NetworkModeArg::Blocked, NetworkChoice::Blocked),
        ];
        let config_modes = [
            None,
            Some(NetworkMode::Unrestricted),
            Some(NetworkMode::LocalhostOnly),
            Some(proxy_mode()),
            Some(NetworkMode::Blocked),
        ];
        for (flag, expected) in flags {
            for mode in &config_modes {
                for allow in [vec![], domains()] {
                    for config_allow in [vec![], domains()] {
                        let d = resolve_network(Some(flag), &allow, mode.as_ref(), &config_allow);
                        assert_eq!(
                            d,
                            NetworkDecision {
                                choice: expected,
                                source: NetworkSource::NetworkFlag
                            },
                            "flag {expected:?}, config {mode:?}, allow {allow:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn allow_flag_wins_over_config() {
        for mode in [
            None,
            Some(NetworkMode::Unrestricted),
            Some(NetworkMode::LocalhostOnly),
            Some(NetworkMode::Blocked),
        ] {
            let d = resolve_network(None, &domains(), mode.as_ref(), &[]);
            assert_eq!(d.choice, NetworkChoice::Proxy, "config {mode:?}");
            assert_eq!(d.source, NetworkSource::AllowFlag);
        }
    }

    #[test]
    fn config_mode_wins_over_config_allowlist() {
        let cases = [
            (NetworkMode::Unrestricted, NetworkChoice::Unrestricted),
            (NetworkMode::LocalhostOnly, NetworkChoice::Localhost),
            (proxy_mode(), NetworkChoice::Proxy),
            (NetworkMode::Blocked, NetworkChoice::Blocked),
        ];
        for (mode, expected) in cases {
            for config_allow in [vec![], domains()] {
                let d = resolve_network(None, &[], Some(&mode), &config_allow);
                assert_eq!(d.choice, expected, "config {mode:?}");
                assert_eq!(d.source, NetworkSource::ConfigMode);
            }
        }
    }

    #[test]
    fn config_allowlist_implies_proxy() {
        let d = resolve_network(None, &[], None, &domains());
        assert_eq!(d.choice, NetworkChoice::Proxy);
        assert_eq!(d.source, NetworkSource::ConfigAllowlist);
    }

    #[test]
    fn default_is_blocked() {
        let d = resolve_network(None, &[], None, &[]);
        assert_eq!(d.choice, NetworkChoice::Blocked);
        assert_eq!(d.source, NetworkSource::Default);
    }

    // ── network_warnings ─────────────────────────────────────────────────────

    fn decision(choice: NetworkChoice, source: NetworkSource) -> NetworkDecision {
        NetworkDecision { choice, source }
    }

    #[test]
    fn warns_when_allow_is_ignored() {
        let d = decision(NetworkChoice::Blocked, NetworkSource::NetworkFlag);
        let w = network_warnings(d, &domains(), false, Platform::Linux);
        assert_eq!(w.len(), 1);
        assert!(w.iter().any(|m| m.contains("--allow has no effect")));
    }

    #[test]
    fn warns_about_proxy_on_macos_only() {
        let d = decision(NetworkChoice::Proxy, NetworkSource::ConfigAllowlist);
        let mac = network_warnings(d, &[], false, Platform::MacOs);
        assert!(mac.iter().any(|m| m.contains("unrestricted")), "{mac:?}");
        let linux = network_warnings(d, &[], false, Platform::Linux);
        assert!(linux.is_empty(), "{linux:?}");
    }

    #[test]
    fn trace_note_on_linux_without_proxy() {
        let d = decision(NetworkChoice::Blocked, NetworkSource::Default);
        let w = network_warnings(d, &[], true, Platform::Linux);
        assert!(w.iter().any(|m| m.contains("only in proxy mode")), "{w:?}");
        let proxy = decision(NetworkChoice::Proxy, NetworkSource::AllowFlag);
        assert!(network_warnings(proxy, &domains(), true, Platform::Linux).is_empty());
        assert!(network_warnings(d, &[], true, Platform::MacOs).is_empty());
    }

    #[test]
    fn blocked_hint_only_for_default() {
        let hint = network_status(&NetworkMode::Blocked, NetworkSource::Default);
        assert!(hint.is_some_and(|h| h.contains("domain_allowlist")));
        let explicit = network_status(&NetworkMode::Blocked, NetworkSource::NetworkFlag);
        assert_eq!(explicit, Some("blocked"));
    }

    // ── trace log ────────────────────────────────────────────────────────────

    #[test]
    fn proxy_fix_names_the_domain_for_connect() {
        let fix = proxy_violation_fix(
            "network: SOCKS5 connection to \"evil.example\" port 443 blocked: \
             the domain is not in the allowlist",
        );
        assert!(fix.contains("add \"evil.example\" to domain_allowlist"), "{fix}");
    }

    #[test]
    fn proxy_fix_names_private_destinations() {
        let fix = proxy_violation_fix(
            "network: CONNECT connection to \"intra.example\" port 443 blocked: \
             the domain resolves to the private address 10.0.0.5",
        );
        assert!(fix.contains("private_destinations"), "{fix}");
    }

    #[test]
    fn proxy_fix_names_the_domain() {
        let fix = proxy_violation_fix(
            "network: DNS query for \"evil.example\" (A) blocked: the domain is not in the allowlist",
        );
        assert_eq!(
            fix,
            "add \"evil.example\" to domain_allowlist in the [proxy] section of your pent config"
        );
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

    // ── exit status ──────────────────────────────────────────────────────────

    #[test]
    fn failed_wait_is_exit_code_one() {
        assert_eq!(failed_wait_status().code(), Some(1));
    }

    // ── macOS log parsing ────────────────────────────────────────────────────

    mod macos_parse {
        use super::super::macos_trace::*;

        #[test]
        fn parses_kernel_syslog_line() {
            let line = "2024-01-01 12:00:00.000000+0100  localhost kernel[0]: (Sandbox) \
                        Sandbox: cat(4321) deny(1) file-read-data /Users/a/My Docs/x.txt";
            let d = parse_denial(line).unwrap();
            assert_eq!(
                d,
                SandboxDenial {
                    process: "cat".to_string(),
                    pid: 4321,
                    operation: "file-read-data".to_string(),
                    target: "/Users/a/My Docs/x.txt".to_string(),
                }
            );
        }

        #[test]
        fn parses_process_name_with_spaces_and_parens() {
            let line =
                "kernel: Sandbox: Code Helper (GPU)(77) deny(1) network-outbound 1.1.1.1:443";
            let d = parse_denial(line).unwrap();
            assert_eq!(d.process, "Code Helper (GPU)");
            assert_eq!(d.pid, 77);
            assert_eq!(d.operation, "network-outbound");
            assert_eq!(d.target, "1.1.1.1:443");
        }

        #[test]
        fn parses_line_without_target() {
            let d = parse_denial("Sandbox: node(9) deny(1) mach-lookup").unwrap();
            assert_eq!(d.operation, "mach-lookup");
            assert_eq!(d.target, "");
        }

        #[test]
        fn rejects_other_lines() {
            assert!(parse_denial(
                "Filtering the log data using \"eventMessage CONTAINS \"deny(\"\""
            )
            .is_none());
            assert!(parse_denial("Timestamp (process)[PID]").is_none());
            assert!(parse_denial("Sandbox: cat(abc) deny(1) file-read-data /x").is_none());
        }

        #[test]
        fn classifies_operations() {
            assert_eq!(OperationKind::of("file-read-data"), OperationKind::FileRead);
            assert_eq!(
                OperationKind::of("file-read-metadata"),
                OperationKind::FileRead
            );
            assert_eq!(
                OperationKind::of("file-write-create"),
                OperationKind::FileWrite
            );
            assert_eq!(
                OperationKind::of("process-exec*"),
                OperationKind::ProcessExec
            );
            assert_eq!(
                OperationKind::of("network-outbound"),
                OperationKind::Network
            );
            assert_eq!(OperationKind::of("mach-lookup"), OperationKind::Other);
        }

        fn denial(operation: &str, target: &str) -> SandboxDenial {
            SandboxDenial {
                process: "p".to_string(),
                pid: 1,
                operation: operation.to_string(),
                target: target.to_string(),
            }
        }

        #[test]
        fn message_uses_category_and_real_name() {
            let m = denial_message(&denial("network-outbound", "1.1.1.1:443"));
            assert_eq!(
                m,
                "network: \"p\" (pid 1) was denied network-outbound on \"1.1.1.1:443\""
            );
            let m = denial_message(&denial("file-write-create", "/a"));
            assert!(m.starts_with("filesystem: \"p\" (pid 1)"), "{m}");
        }

        #[test]
        fn fix_only_for_filesystem_operations() {
            let read = denial_fix(&denial("file-read-data", "/a/f"), PathKind::NotDirectory);
            assert_eq!(
                read.as_deref(),
                Some("add \"/a/f\" to read in the [sandbox.paths] section of your pent config")
            );
            let dir = denial_fix(&denial("file-read-data", "/a"), PathKind::Directory);
            assert!(dir.is_some_and(|f| f.contains("traversal")));
            let write = denial_fix(&denial("file-write-create", "/a/f"), PathKind::NotDirectory);
            assert!(write.is_some_and(|f| f.contains(" read_write ")));
            let exec = denial_fix(&denial("process-exec*", "/bin/x"), PathKind::NotDirectory);
            assert!(exec.is_some_and(|f| f.contains(" execute ")));
            let net = denial_fix(
                &denial("network-outbound", "/var/run/x.sock"),
                PathKind::NotDirectory,
            );
            assert!(net.is_none());
            let mach = denial_fix(
                &denial("mach-lookup", "com.apple.x"),
                PathKind::NotDirectory,
            );
            assert!(mach.is_none());
        }

        #[test]
        fn parses_ps_output() {
            let pairs = parse_ps_output("    1     0\n  100     1\nbad line\n  101   100\n");
            assert_eq!(pairs, vec![(1, 0), (100, 1), (101, 100)]);
        }

        #[test]
        fn finds_descendants() {
            let pairs = [(1, 0), (100, 1), (101, 100), (102, 101), (200, 1), (0, 0)];
            let d = descendants_of(100, &pairs);
            assert_eq!(d, std::collections::HashSet::from([100, 101, 102]));
            // A self-parented entry does not loop.
            let d = descendants_of(0, &pairs);
            assert!(d.contains(&102));
        }
    }
}
