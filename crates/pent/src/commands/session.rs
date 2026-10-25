//! The parts of one child session that `pent run` and `pent watch` share:
//! the proxy start, the signal relay, the wait for the child, the event
//! forwarders, the cleanup and the exit.

use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
use pent_proxy::ExternalListeners;
use pent_proxy::{ProxyConfig, ProxyHandle, ProxyPolicy, ProxyServer, TraceEvent};
#[cfg(target_os = "linux")]
use pent_sandbox::teardown_overlay;
use pent_sandbox::NetworkMode;
#[cfg(target_os = "linux")]
use pent_sandbox::ProxyListeners;
use pent_settings::ProxySettings;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::error::CliError;
use crate::ui;

// ── Proxy ────────────────────────────────────────────────────────────────────

/// A running proxy and the network mode that sends the child through it.
pub(crate) struct ProxySession {
    /// The handle of the proxy server.
    pub handle: ProxyHandle,
    /// The `ProxyOnly` mode with the address of the proxy.
    pub network: NetworkMode,
}

impl ProxySession {
    /// Give the proxy the listeners that the child made in its network
    /// namespace (Linux). Call this right after the spawn. Connections that
    /// arrive before the call wait in the queue of the listener.
    ///
    /// # Errors
    /// Returns an error if the spawn returned no listeners, or if the proxy
    /// cannot use them.
    #[cfg(target_os = "linux")]
    pub fn attach(&self, listeners: Option<ProxyListeners>) -> Result<(), CliError> {
        let listeners = listeners.ok_or_else(|| {
            CliError::Other("the sandbox did not make the proxy listeners".to_string())
        })?;
        self.handle.attach_listeners(ExternalListeners {
            tcp: listeners.tcp,
            dns_udp: listeners.dns_udp,
            dns_tcp: Some(listeners.dns_tcp),
        })?;
        Ok(())
    }

    /// Stop the proxy. A failure is not fatal: pent shows a warning.
    pub async fn shutdown(self) {
        if let Err(e) = self.handle.shutdown().await {
            ui::warn(format!("proxy shutdown failed: {e}"));
        }
    }
}

/// The channels that the proxy sends its events to.
pub(crate) struct ProxyChannels {
    /// The text events for the trace log (`--trace`).
    pub trace: Option<UnboundedSender<TraceEvent>>,
    /// The structured events (each DNS query and each connection).
    pub events: Option<UnboundedSender<pent_profile::WatchEvent>>,
}

/// Start the proxy with `domains` and `policy`.
///
/// On Linux, the proxy has no host listener. The child unshares its network
/// namespace and makes the listeners there (127.0.0.1:3128 for SOCKS5 and
/// HTTP CONNECT, 127.0.0.1:53 for DNS). Then it sends them to pent. Call
/// [`ProxySession::attach`] after the spawn. The child can reach only its
/// own loopback, so all its traffic goes through the proxy. No privilege is
/// necessary.
///
/// On macOS, the proxy listens on loopback. The Seatbelt profile lets the
/// child reach only the proxy port.
///
/// # Errors
/// Returns an error if the settings are not valid or the proxy cannot start.
pub(crate) async fn start_proxy(
    settings: &ProxySettings,
    domains: Vec<String>,
    policy: ProxyPolicy,
    channels: ProxyChannels,
) -> Result<ProxySession, CliError> {
    let mut config = ProxyConfig::try_from(settings).map_err(|e| CliError::Other(e.to_string()))?;
    config.domain_allowlist = domains;
    config.policy = policy;
    config.violation_tx = channels.trace;
    config.event_tx = channels.events;
    let server = ProxyServer::new(config)?;

    #[cfg(target_os = "linux")]
    let (handle, proxy_addr, dns_port) = (
        server.start_unbound()?,
        pent_sandbox::child_proxy_addr(),
        pent_sandbox::CHILD_DNS_PORT,
    );
    #[cfg(not(target_os = "linux"))]
    let (handle, proxy_addr, dns_port) = {
        let handle = server.start().await?;
        let (Some(proxy_addr), Some(dns_addr)) = (handle.proxy_addr(), handle.dns_addr()) else {
            return Err(CliError::Other("the proxy has no listener".to_string()));
        };
        (handle, proxy_addr, dns_addr.port())
    };
    tracing::debug!(
        proxy = %proxy_addr,
        dns_port,
        "proxy started (HTTP CONNECT + SOCKS5h on same port); DNS resolved server-side"
    );
    Ok(ProxySession {
        handle,
        network: NetworkMode::ProxyOnly {
            proxy_addr,
            dns_port,
        },
    })
}

// ── Event forwarders ─────────────────────────────────────────────────────────

/// Stops the tokio forwarders after the child exits.
///
/// A forwarder that gets the stop signal sends the events that are already
/// in its input channel, then drops its output sender. When all senders are
/// gone, the merged channel closes and the final drain ends.
pub(crate) struct ForwardStop(tokio::sync::watch::Sender<bool>);

impl Default for ForwardStop {
    fn default() -> Self {
        Self(tokio::sync::watch::Sender::new(false))
    }
}

impl ForwardStop {
    /// Stop all forwarders that use this value.
    pub fn stop(&self) {
        self.0.send_replace(true);
    }
}

/// Forward the events of a tokio channel into `tx`, converted with `map`.
pub(crate) fn forward_tokio<T, U, F>(
    mut rx: UnboundedReceiver<T>,
    tx: UnboundedSender<U>,
    map: F,
    stop: &ForwardStop,
) where
    T: Send + 'static,
    U: Send + 'static,
    F: Fn(T) -> U + Send + 'static,
{
    let mut stopped = stop.0.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                event = rx.recv() => match event {
                    Some(event) => {
                        if tx.send(map(event)).is_err() {
                            // The session is gone; stop the forwarder.
                            return;
                        }
                    }
                    None => return,
                },
                _ = stopped.wait_for(|stop| *stop) => {
                    while let Ok(event) = rx.try_recv() {
                        if tx.send(map(event)).is_err() {
                            return;
                        }
                    }
                    return;
                }
            }
        }
    });
}

/// Forward the events of a std channel (a recorder) into `tx`.
///
/// The thread ends when the recorder closes its channel.
pub(crate) fn forward_std<T, U, F>(rx: std::sync::mpsc::Receiver<T>, tx: UnboundedSender<U>, map: F)
where
    T: Send + 'static,
    U: Send + 'static,
    F: Fn(T) -> U + Send + 'static,
{
    std::thread::spawn(move || {
        for event in rx {
            if tx.send(map(event)).is_err() {
                // The session is gone; stop the forwarder.
                break;
            }
        }
    });
}

/// Read the events that remain in `rx` and give each to `sink`.
///
/// The function returns when all senders are gone, or at `grace` after the
/// call. A zero `grace` reads only the events that are already there.
pub(crate) async fn drain<T>(
    rx: Option<UnboundedReceiver<T>>,
    grace: Duration,
    sink: &mut impl FnMut(T),
) -> Option<UnboundedReceiver<T>> {
    let mut rx = rx?;
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match rx.try_recv() {
            Ok(event) => sink(event),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return None,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(event)) => sink(event),
                    Ok(None) => return None,
                    Err(_) => return Some(rx),
                }
            }
        }
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
pub(crate) struct SignalRelay {
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
    /// Install them before the spawn. A signal that comes between the spawn
    /// and the wait then goes to the child and does not kill pent before the
    /// cleanup.
    ///
    /// # Errors
    /// Returns an I/O error if tokio cannot install a handler.
    pub fn install() -> Result<Self, CliError> {
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
pub(crate) fn failed_wait_status() -> std::process::ExitStatus {
    // wait() can only fail if the child was already waited on.
    std::os::unix::process::ExitStatusExt::from_raw(1 << 8)
}

/// Wait for `child` to exit. While it runs, send signals to it and give each
/// event of `events` to `sink`.
///
/// Returns the exit status and the event channel, if it is still open. Call
/// [`drain`] to read the events that come after the exit.
pub(crate) async fn wait_child<T>(
    mut child: std::process::Child,
    signals: &mut SignalRelay,
    mut events: Option<UnboundedReceiver<T>>,
    sink: &mut impl FnMut(T),
) -> (std::process::ExitStatus, Option<UnboundedReceiver<T>>) {
    let pid = child.id();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<std::process::ExitStatus>();
    // Wait in a thread so that tokio can handle the signals and the events
    // at the same time.
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
                Some(event) => sink(event),
                // The senders are gone; stop the poll of this channel.
                None => events = None,
            },
        }
    };
    (status, events)
}

/// Receive the next event, or wait forever if there is no channel.
async fn next_event<T>(events: &mut Option<UnboundedReceiver<T>>) -> Option<T> {
    match events {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Exit pent with the same status as the child.
///
/// If a signal killed the child, pent sends the same signal to itself, so the
/// parent shell or CI system sees the correct reason for the termination.
pub(crate) fn exit_like_child(status: std::process::ExitStatus) -> ! {
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
pub(crate) trait Teardown {
    /// Release the resources.
    fn teardown(self);
}

impl Teardown for () {
    fn teardown(self) {}
}

/// The Linux resources of one session.
#[cfg(target_os = "linux")]
pub(crate) struct LinuxResources {
    pub overlay: Option<pent_sandbox::OverlayHandle>,
    /// Show the writes that the overlay discards (trace mode).
    pub trace: bool,
}

#[cfg(target_os = "linux")]
impl Teardown for LinuxResources {
    fn teardown(self) {
        if let Some(handle) = self.overlay {
            let report = teardown_overlay(handle);
            show_overlay_report(&report, self.trace);
        }
    }
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

/// Releases the session resources when the session ends.
///
/// Call [`SessionCleanup::finish`] after the child exits. If the value drops
/// before `finish` (for example during a panic), the drop kills the child
/// first, so the teardown does not race with the writes of the child.
pub(crate) struct SessionCleanup<R: Teardown> {
    /// The child PID while the child can still run.
    running_child: Option<u32>,
    resources: Option<R>,
}

impl<R: Teardown> SessionCleanup<R> {
    /// Track the child `child_pid` and the resources to release.
    pub const fn new(child_pid: u32, resources: R) -> Self {
        Self {
            running_child: Some(child_pid),
            resources: Some(resources),
        }
    }

    /// Mark the child as exited and release the resources.
    pub fn finish(mut self) {
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

// ── Misc ─────────────────────────────────────────────────────────────────────

/// Return true if `workspace` is `/` or the home directory of the user.
pub(crate) fn is_broad_workspace(workspace: &Path) -> bool {
    if workspace.parent().is_none() {
        return true;
    }
    std::env::var_os("HOME").is_some_and(|home| {
        let home = PathBuf::from(home);
        workspace == home || std::fs::canonicalize(&home).is_ok_and(|h| workspace == h)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_wait_is_exit_code_one() {
        assert_eq!(failed_wait_status().code(), Some(1));
    }

    #[test]
    fn root_is_a_broad_workspace() {
        assert!(is_broad_workspace(Path::new("/")));
        assert!(!is_broad_workspace(Path::new(
            "/definitely/not/home/pent-test"
        )));
    }

    #[tokio::test]
    async fn forwarders_stop_and_drain_ends() {
        let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
        let stop = ForwardStop::default();
        forward_tokio(in_rx, out_tx.clone(), |v| v + 1, &stop);
        let (std_tx, std_rx) = std::sync::mpsc::channel::<u32>();
        forward_std(std_rx, out_tx, |v| v * 10);
        assert!(in_tx.send(1).is_ok());
        assert!(std_tx.send(2).is_ok());
        drop(std_tx);
        // The input sender stays open, as the proxy keeps its sender.
        let mut seen = Vec::new();
        let rest = drain(Some(out_rx), Duration::from_millis(100), &mut |v| {
            seen.push(v)
        })
        .await;
        assert!(rest.is_some(), "the tokio forwarder still runs");
        stop.stop();
        let rest = drain(rest, Duration::from_secs(5), &mut |v| seen.push(v)).await;
        assert!(rest.is_none(), "all senders are gone after the stop");
        seen.sort_unstable();
        assert_eq!(seen, vec![2, 20]);
    }
}
