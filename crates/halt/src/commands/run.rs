#[cfg(unix)]
extern crate libc;

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;

#[cfg(not(target_os = "macos"))]
use halt_proxy::{ProxyConfig, ProxyHandle, ProxyServer};
use halt_proxy::TraceEvent;
use halt_sandbox::{build_env, check_availability, spawn_sandboxed, NetworkMode, SandboxConfig};
use halt_settings::{ConfigLoader, HaltConfig};

use crate::cli::{NetworkModeArg, RunArgs};
use crate::error::CliError;

pub async fn run(args: RunArgs, cwd: PathBuf) -> Result<(), CliError> {
    // 1. Load and merge config.
    // --no-config skips global/project config files but --config <extra> still applies.
    let mut config = if args.no_config {
        HaltConfig::default()
    } else {
        ConfigLoader::load(&cwd)?
    };
    if let Some(ref extra) = args.extra_config {
        let extra_cfg = HaltConfig::load(extra)?;
        config = config.merge(extra_cfg);
    }

    // 2. Merge CLI overrides into config
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
    config
        .proxy
        .domain_allowlist
        .extend(args.allow.iter().cloned());

    // 3. Build env map
    let mut allowlist_keys: Vec<String> = Vec::new();
    let mut explicit_env: Vec<(String, String)> = Vec::new();
    for entry in &args.env {
        if let Some(eq) = entry.find('=') {
            let key = entry[..eq].to_string();
            let value = entry[eq + 1..].to_string();
            allowlist_keys.push(key.clone());
            explicit_env.push((key, value));
        } else {
            allowlist_keys.push(entry.clone());
        }
    }
    let mut env_map: HashMap<String, String> = build_env(&allowlist_keys);
    for (k, v) in explicit_env {
        env_map.insert(k, v);
    }

    // 4. Open violations log when tracing.
    let trace_log_path: Option<PathBuf> = if args.trace {
        let halt_dir = cwd.join(".halt");
        match std::fs::create_dir_all(&halt_dir) {
            Ok(()) => {
                let log_path = halt_dir.join("trace.log");
                // Truncate/create fresh for this run.
                match std::fs::File::create(&log_path) {
                    Ok(_) => {
                        tracing::info!(path = %log_path.display(), "tracing enabled");
                        Some(log_path)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "could not create trace log");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not create .halt directory");
                None
            }
        }
    } else {
        None
    };

    // 5. Resolve network mode.
    //
    // macOS — proxy-based network enforcement is not available (no per-process
    // network namespaces; DYLD_INSERT_LIBRARIES is unreliable across Go binaries
    // and hardened-runtime binaries). Any flag or config that would normally
    // start the proxy (--allow, --network proxy, domain_allowlist) silently
    // degrades to Unrestricted so the process is not blocked. Only explicit
    // --network localhost/blocked/unrestricted take effect.
    // See AGENTS.md for the full explanation.
    //
    // non-macOS — start the proxy when needed for enforcement.

    // ── macOS path ────────────────────────────────────────────────────────────
    #[cfg(target_os = "macos")]
    let resolved_network: NetworkMode = {
        let proxy_requested = args.network == Some(NetworkModeArg::Proxy)
            || !config.proxy.domain_allowlist.is_empty()
            || matches!(config.sandbox.network, Some(NetworkMode::ProxyOnly { .. }));
        if proxy_requested {
            // Proxy enforcement is unavailable; degrade silently so the process
            // is not blocked from making external connections.
            NetworkMode::Unrestricted
        } else {
            match args.network {
                // Proxy already handled above via proxy_requested.
                Some(NetworkModeArg::Unrestricted | NetworkModeArg::Proxy) => NetworkMode::Unrestricted,
                Some(NetworkModeArg::Localhost) => NetworkMode::LocalhostOnly,
                Some(NetworkModeArg::Blocked) => NetworkMode::Blocked,
                None => match config
                    .sandbox
                    .network
                    .clone()
                    .unwrap_or(NetworkMode::LocalhostOnly)
                {
                    NetworkMode::ProxyOnly { .. } => NetworkMode::Unrestricted,
                    other => other,
                },
            }
        }
    };

    // ── non-macOS path ────────────────────────────────────────────────────────
    #[cfg(not(target_os = "macos"))]
    let ProxySetup {
        network: resolved_network,
        handle: proxy_handle,
        event_rx: violation_rx,
    } = setup_proxy(&config, args.network, args.trace).await?;

    // 5. Build SandboxConfig.
    // from_sandbox_settings merges user paths on top of system defaults and
    // handles mounts, replacing the previous manual path-extension loop.
    #[cfg(not(target_os = "macos"))]
    let needs_netns_cleanup = matches!(resolved_network, NetworkMode::ProxyOnly { .. });

    let mut sandbox_cfg = SandboxConfig::from_sandbox_settings(config.sandbox, cwd.clone(), cwd)
        .with_network(resolved_network)
        .with_env(env_map);

    if let Some(data_dir) = args.data_dir {
        sandbox_cfg = sandbox_cfg.with_data_dir(data_dir);
    }

    // Validate sandbox availability before spawning
    check_availability()?;

    // 6. Spawn and wait
    let cmd_parts = &args.command;
    let cmd = cmd_parts
        .first()
        .ok_or_else(|| CliError::Other("command list is empty".to_string()))?;
    let cmd_args: Vec<String> = cmd_parts[1..].to_vec();

    let mut child = spawn_sandboxed(&sandbox_cfg, cmd, &cmd_args)?;

    // When running with a proxy, spawn a background task that warns if the
    // sandboxed process hasn't made any proxy connections after 8 seconds.
    // This catches the common case where the process doesn't honour HTTP_PROXY
    // / ALL_PROXY and its direct network connections are silently blocked by
    // the sandbox, causing it to hang.
    #[cfg(not(target_os = "macos"))]
    if let Some(ref handle) = proxy_handle {
        let handle_ref = handle.connections_accepted_ref();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
            if handle_ref.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                tracing::warn!(
                    "8s elapsed with no proxy connections; \
                     process may not honor HTTP_PROXY / ALL_PROXY — \
                     direct network connections are blocked"
                );
            }
        });
    }

    // macOS: in trace mode, stream sandboxd denials live so the user can see
    // every blocked path in one run. Without --trace just wait for the child.
    #[cfg(target_os = "macos")]
    let child_pid = child.id();
    #[cfg(target_os = "macos")]
    let exit_status = if args.trace {
        macos_trace_wait(child, child_pid, trace_log_path).await
    } else {
        child.wait()?
    };

    // non-macOS: in trace mode, stream proxy events (violations and granted
    // access) to the log while the child runs to completion.
    #[cfg(not(target_os = "macos"))]
    let exit_status = if let Some(mut event_rx) = violation_rx {
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<std::process::ExitStatus>();
        std::thread::spawn(move || {
            let status = child.wait().unwrap_or_else(|_| {
                std::process::Command::new("true").status().unwrap()
            });
            let _ = done_tx.send(status);
        });

        loop {
            tokio::select! {
                biased;
                Some(event) = event_rx.recv() => {
                    if let Some(ref p) = trace_log_path {
                        log_trace_event(p, event);
                    }
                }
                Ok(status) = &mut done_rx => {
                    // Drain any in-flight events before returning.
                    while let Ok(ev) = event_rx.try_recv() {
                        if let Some(ref p) = trace_log_path {
                            log_trace_event(p, ev);
                        }
                    }
                    break status;
                }
            }
        }
    } else {
        child.wait()?
    };

    // Clean up the named network namespace that was created for ProxyOnly mode.
    #[cfg(not(target_os = "macos"))]
    if needs_netns_cleanup {
        if let Err(e) = halt_sandbox::delete_sandbox_netns(std::process::id()) {
            tracing::warn!(error = %e, "Failed to delete network namespace; it will be reaped on process exit");
        }
    }

    #[cfg(not(target_os = "macos"))]
    if let Some(handle) = proxy_handle {
        handle.shutdown().await?;
    }

    // On Unix, if the sandboxed process was killed by a signal, re-raise that
    // signal so the parent shell / CI system sees the correct termination reason.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = exit_status.signal() {
            // SAFETY: raise() sends the signal to the calling process.
            // We are on the main thread, past all cleanup, about to exit.
            unsafe { libc::raise(signal) };
        }
    }

    std::process::exit(exit_status.code().unwrap_or(1));
}

/// Runs the child to completion, streaming every sandboxd event for the child
/// to the trace log in real time.
///
/// Used by `--trace` mode. The SBPL profile does NOT use `(with send-signal
/// SIGKILL)`, so the child receives EPERM on each denied access and keeps
/// running.  Every denial that sandboxd logs is written to `log_path`
/// immediately so the user can see the full access pattern in a single run.
#[cfg(target_os = "macos")]
async fn macos_trace_wait(
    mut child: std::process::Child,
    _child_pid: u32,
    log_path: Option<PathBuf>,
) -> std::process::ExitStatus {
    use std::io::BufRead;

    // Start `log stream` to capture file/network denials in real time.
    // We filter by operation type rather than PID because the child process may
    // spawn sub-processes (e.g. Node.js workers) with different PIDs that also
    // hit the sandbox; all of them run under our SBPL profile.
    // mach-lookup and syscall-mach noise from unrelated system processes is
    // excluded by the predicate.
    let mut log_proc = std::process::Command::new("/usr/bin/log")
        .args([
            "stream",
            "--predicate",
            r#"eventMessage CONTAINS "deny" AND (eventMessage CONTAINS "file-read" OR eventMessage CONTAINS "file-write" OR eventMessage CONTAINS "network-outbound")"#,
            "--style",
            // syslog avoids the column-width truncation of "compact" style,
            // which cuts off long paths like deep Application Support paths.
            "syslog",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();

    let (violation_tx, mut violation_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    if let Some(ref mut lp) = log_proc {
        if let Some(stdout) = lp.stdout.take() {
            let reader = std::io::BufReader::new(stdout);
            let tx = violation_tx;
            std::thread::spawn(move || {
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    // "deny(" matches actual denial records ("deny(1)")
                    // without matching the predicate description header line.
                    if line.contains("deny(") {
                        let _ = tx.send(parse_sandboxd_line(&line));
                    }
                }
            });
        }
    }

    // Wait for the child in a background thread so tokio can drive the
    // violation channel concurrently.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<std::process::ExitStatus>();
    std::thread::spawn(move || {
        let status = child.wait().unwrap_or_else(|_| {
            std::process::Command::new("true").status().unwrap()
        });
        let _ = done_tx.send(status);
    });

    let exit_status = loop {
        tokio::select! {
            biased;
            Some(violation) = violation_rx.recv() => {
                if let Some(ref p) = log_path {
                    log_trace_event(p, TraceEvent::Violation(violation));
                }
            }
            Ok(status) = &mut done_rx => {
                // Drain any violations that arrived before or just after exit.
                while let Ok(v) = violation_rx.try_recv() {
                    if let Some(ref p) = log_path {
                        log_trace_event(p, TraceEvent::Violation(v));
                    }
                }
                break status;
            }
        }
    };

    if let Some(mut lp) = log_proc {
        let _ = lp.kill();
    }

    exit_status
}

/// Convert a raw `sandboxd` log line into the `"filesystem: ..."` format that
/// `print_violation` already knows how to format into a user-friendly hint.
///
/// sandboxd compact log lines look roughly like:
/// ```text
/// 2024-01-01 12:00:00.000 Zzz  sandboxd[123:456]  deny(1) file-read-data /Users/x/.claude
/// ```
#[cfg(target_os = "macos")]
fn parse_sandboxd_line(log_line: &str) -> String {
    let tokens: Vec<&str> = log_line.split_whitespace().collect();
    // Find the operation token (starts with "file-" or "network-") and join
    // all remaining tokens as the path to handle paths with spaces
    // (e.g. "/Users/x/Library/Application Support/...").
    for (i, tok) in tokens.iter().enumerate() {
        if tok.starts_with("file-") || tok.starts_with("network-") {
            let path = tokens[i + 1..].join(" ");
            let op = if tok.contains("write") { "write" } else { "read" };
            if !path.is_empty() {
                return format!(
                    "filesystem: \"process\" was denied \"{op}\" access to \"{path}\""
                );
            }
            return format!("filesystem: sandbox denied \"{tok}\"");
        }
    }
    format!("filesystem: sandbox denied: {}", log_line.trim())
}

/// Compute a human-readable fix hint for a violation message.
fn violation_fix(violation: &str) -> String {
    if violation.starts_with("network: DNS query for") {
        // Extract domain from: network: DNS query for "domain" blocked ...
        if let Some(start) = violation.find('"') {
            if let Some(end) = violation[start + 1..].find('"') {
                let domain = &violation[start + 1..start + 1 + end];
                return format!(
                    "add \"{domain}\" to [proxy.domain_allowlist] in your halt config"
                );
            }
        }
        "add the domain to [proxy.domain_allowlist] in your halt config".to_string()
    } else if violation.starts_with("network:") {
        "verify the process uses DNS resolution and the target domain is in [proxy.domain_allowlist]".to_string()
    } else if violation.starts_with("filesystem:") {
        // Format: filesystem: "proc" was denied "operation" access to "path"
        // Extract operation (second quoted token) and path (last quoted token).
        let mut quotes = violation.match_indices('"').map(|(i, _)| i);
        let op = quotes.next().and_then(|_| {
            let o = quotes.next()?;
            let c = quotes.next()?;
            Some(&violation[o + 1..c])
        });
        // Path is the last quoted substring.
        let path = violation.rfind('"').and_then(|end| {
            let before = &violation[..end];
            before.rfind('"').map(|start| &violation[start + 1..end])
        });

        match path {
            Some(p) if !p.is_empty() => {
                let is_dir = std::path::Path::new(p).is_dir();
                let is_write = op.is_some_and(|o| o.contains("write"));
                if is_write {
                    format!("add \"{p}\" to [sandbox.paths.read_write] in your halt config")
                } else if is_dir {
                    format!(
                        "add \"{p}\" to [sandbox.paths.traversal] (directory listing) \
                         or [sandbox.paths.read] (file reads inside) in your halt config"
                    )
                } else {
                    format!(
                        "add \"{p}\" to [sandbox.paths.read] or [sandbox.paths.read_write] in your halt config"
                    )
                }
            }
            _ => "add the path to [sandbox.paths.traversal], [sandbox.paths.read], or [sandbox.paths.read_write] in your halt config".to_string(),
        }
    } else {
        "review your halt config".to_string()
    }
}

/// Write a single trace event to the log file.
///
/// Opens the log in append mode so entries accumulate across the run without
/// races between successive writes.
fn log_trace_event(log_path: &std::path::Path, event: TraceEvent) {
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(log_path) {
        match event {
            TraceEvent::Access(msg) => {
                let _ = writeln!(f, "halt: [allowed] {msg}");
            }
            TraceEvent::Violation(msg) => {
                let fix = violation_fix(&msg);
                let _ = writeln!(f, "halt: [denied] {msg}");
                let _ = writeln!(f, "halt: fix: {fix}");
            }
        }
        let _ = writeln!(f);
    }
}

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
    config: &HaltConfig,
    network_arg: Option<crate::cli::NetworkModeArg>,
    trace: bool,
) -> Result<ProxySetup, CliError> {
    use crate::cli::NetworkModeArg;

    let (violation_tx, event_rx) = if trace {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let wants_proxy = match network_arg {
        Some(NetworkModeArg::Proxy) => true,
        None if trace => true,
        None if !config.proxy.domain_allowlist.is_empty() => true,
        _ => matches!(config.sandbox.network, Some(NetworkMode::ProxyOnly { .. })),
    };

    let base_network: NetworkMode = match network_arg {
        Some(NetworkModeArg::Unrestricted) => NetworkMode::Unrestricted,
        Some(NetworkModeArg::Localhost) => NetworkMode::LocalhostOnly,
        Some(NetworkModeArg::Proxy) => NetworkMode::LocalhostOnly, // overridden below when proxy starts
        Some(NetworkModeArg::Blocked) => NetworkMode::Blocked,
        None => config
            .sandbox
            .network
            .clone()
            .unwrap_or(NetworkMode::LocalhostOnly),
    };

    if wants_proxy {
        let mut proxy_config =
            ProxyConfig::try_from(&config.proxy).map_err(CliError::Other)?;
        proxy_config.violation_tx = violation_tx;
        // On Linux, ProxyOnly routes child traffic from a separate network
        // namespace through a veth pair. The proxy must listen on all interfaces
        // (0.0.0.0) because:
        //   1. The child's loopback is isolated from the parent's loopback.
        //   2. The veth outer interface (10.200.x.1) is created inside
        //      spawn_sandboxed *after* the proxy binds.
        //   3. A socket bound to 0.0.0.0 accepts connections on interfaces
        //      added after bind, so veth traffic arrives correctly.
        #[cfg(target_os = "linux")]
        {
            proxy_config.proxy_bind_addr = "0.0.0.0:0".parse().expect("hardcoded addr");
        }
        let handle = ProxyServer::new(proxy_config)?.start().await?;
        let proxy_addr = handle.proxy_addr();
        tracing::info!(
            http_proxy = %format!("http://127.0.0.1:{}", proxy_addr.port()),
            socks5_proxy = %format!("socks5h://127.0.0.1:{}", proxy_addr.port()),
            dns = %handle.dns_addr(),
            "proxy started (HTTP CONNECT + SOCKS5h on same port); DNS resolved server-side"
        );
        Ok(ProxySetup {
            network: NetworkMode::ProxyOnly { proxy_addr },
            handle: Some(handle),
            event_rx,
        })
    } else {
        Ok(ProxySetup {
            network: base_network,
            handle: None,
            event_rx,
        })
    }
}
