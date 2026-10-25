//! `pent run`: run a command in the sandbox with its trusted profile.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pent_profile::{Outcome, ProfileName, WatchEvent};
use pent_proxy::{ProxyPolicy, TraceEvent};
use pent_sandbox::{build_env, check_availability, spawn_sandboxed, NetworkMode, SandboxConfig};
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
    let settings = ConfigLoader::load(&cwd)?;

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
    let env_map = build_run_env(&args.env);
    let trace_log_path = open_trace_log(args.trace, &cwd);

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
        Some(start_proxy(&settings.proxy, domains, ProxyPolicy::Enforce, channels).await?)
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
        SandboxConfig::from_sandbox_settings(settings.sandbox, paths, cwd.clone(), cwd)
            .with_network(resolved_network)
            .with_env(env_map);
    sandbox_cfg.record_events = args.trace;

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
        crate::commands::session::LinuxResources {
            overlay: sandbox_child.overlay,
            netns: sandbox_child.netns,
            trace: args.trace,
        },
    );
    #[cfg(not(target_os = "linux"))]
    let cleanup = SessionCleanup::new(sandbox_child.child.id(), ());
    let child = sandbox_child.child;
    if let Some(rx) = sandbox_child.events {
        forward_std(rx, event_tx.clone(), RunEvent::Access);
    }

    // macOS: in trace mode, stream the Seatbelt denials of the child and its
    // descendants. The unified log delivers them with a delay.
    #[cfg(target_os = "macos")]
    let drain_grace = match tracer
        .as_mut()
        .and_then(|t| t.attach(child.id(), name.to_string()))
    {
        Some(rx) => {
            forward_tokio(rx, event_tx.clone(), RunEvent::Trace, &stop);
            macos_trace::DRAIN_GRACE
        }
        None => Duration::ZERO,
    };
    #[cfg(not(target_os = "macos"))]
    let drain_grace = Duration::ZERO;
    // Only the forwarders keep senders. When they stop, the channel closes.
    drop(event_tx);

    let mut denied = DeniedRecorder::new(&store, &name);
    let mut sink = |event: RunEvent| match event {
        RunEvent::Trace(line) => write_trace_line(trace_log_path.as_deref(), &line),
        RunEvent::Access(event) => denied.record(&event),
    };
    let (exit_status, rest) = wait_child(child, &mut signals, Some(event_rx), &mut sink).await;

    // Flush overlayfs write-listed files back to real inodes, clean up
    // staging directories and drop the netns handle (this removes the
    // firewall and routing rules). This must happen after the wait, so the
    // child's mount namespace is already destroyed and no writes are in
    // flight.
    cleanup.finish();

    // Read the late events, then stop the forwarders and read the rest.
    let rest = drain(rest, drain_grace, &mut sink).await;
    stop.stop();
    if let Some(proxy) = proxy {
        proxy.shutdown().await;
    }
    drain(rest, FINAL_DRAIN, &mut sink).await;

    #[cfg(target_os = "macos")]
    drop(tracer);

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
    /// The profile has domains.
    ProfileDomains,
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
/// 3. Domains in the profile (this implies proxy mode).
/// 4. The default: blocked.
///
/// `--trace` is not an input: tracing never changes the network mode.
/// `profile_domains` must not contain the `--allow` values.
fn resolve_network(
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
const fn base_network_mode(choice: NetworkChoice) -> NetworkMode {
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
fn network_warnings(decision: NetworkDecision, allow_flags: &[String], trace: bool) -> Vec<String> {
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
fn network_status(mode: &NetworkMode, source: NetworkSource) -> Option<&'static str> {
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
    let result = std::fs::OpenOptions::new()
        .append(true)
        .open(log_path)
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
    }
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

    /// Return a fix hint for a denial, if a profile can allow it.
    ///
    /// Only filesystem operations on an absolute path get a hint. A profile
    /// cannot allow network or other operations per path.
    pub(super) fn denial_fix(
        denial: &SandboxDenial,
        kind: PathKind,
        profile: &str,
    ) -> Option<String> {
        let path = denial.target.as_str();
        if !path.starts_with('/') {
            return None;
        }
        let review = format!("or add it to the profile: pent trust {profile} --review");
        let flag = match OperationKind::of(&denial.operation) {
            OperationKind::FileRead if kind == PathKind::Directory => {
                return Some(format!(
                    "allow it for one run with --traverse \"{path}\" (to list the directory) \
                     or --read \"{path}\" (to read the files in it), {review}"
                ));
            }
            OperationKind::FileRead => "--read",
            OperationKind::FileWrite => "--write",
            OperationKind::ProcessExec => "--execute",
            OperationKind::Network | OperationKind::Other => return None,
        };
        Some(format!(
            "allow it for one run with {flag} \"{path}\", {review}"
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
                profile: String,
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
                        let fix =
                            denial_fix(&denial, path_kind(Path::new(&denial.target)), &profile);
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

    // ── macOS log parsing ────────────────────────────────────────────────────

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
            let read = denial_fix(
                &denial("file-read-data", "/a/f"),
                PathKind::NotDirectory,
                "claude",
            );
            assert_eq!(
                read.as_deref(),
                Some(
                    "allow it for one run with --read \"/a/f\", \
                     or add it to the profile: pent trust claude --review"
                )
            );
            let dir = denial_fix(&denial("file-read-data", "/a"), PathKind::Directory, "c");
            assert!(dir.is_some_and(|f| f.contains("--traverse")));
            let write = denial_fix(
                &denial("file-write-create", "/a/f"),
                PathKind::NotDirectory,
                "c",
            );
            assert!(write.is_some_and(|f| f.contains(" --write ")));
            let exec = denial_fix(
                &denial("process-exec*", "/bin/x"),
                PathKind::NotDirectory,
                "c",
            );
            assert!(exec.is_some_and(|f| f.contains(" --execute ")));
            let net = denial_fix(
                &denial("network-outbound", "/var/run/x.sock"),
                PathKind::NotDirectory,
                "c",
            );
            assert!(net.is_none());
            let mach = denial_fix(
                &denial("mach-lookup", "com.apple.x"),
                PathKind::NotDirectory,
                "c",
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
