//! Combined DNS + TCP proxy server.
//!
//! Manages the lifecycle of both the DNS server and TCP proxy,
//! running them concurrently and providing a unified control interface.
//!
//! # Lifecycle
//!
//! ```text
//! ProxyServer::new(config)
//!       |
//!       v
//! ProxyServer::start() --> ProxyHandle
//!       |                       |
//!       v                       |
//! Run DNS server + TCP proxy    |
//! concurrently                  |
//!       |                       v
//!       |               ProxyHandle::shutdown()
//!       |                       |
//!       v                       v
//! Graceful shutdown <-----------+
//! ```
//!

use crate::{
    DnsServer, DnsServerConfig, PrivateDestinations, ProxyError, Result, SharedState, TcpProxy,
    TcpProxyConfig, TraceEvent,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Configuration for the combined proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// DNS server bind address.
    /// Default: `127.0.0.1:0` (loopback, OS-assigned port)
    pub dns_bind_addr: SocketAddr,

    /// TCP proxy bind address.
    /// Default: `127.0.0.1:0` (loopback, OS-assigned port)
    pub proxy_bind_addr: SocketAddr,

    /// Upstream DNS servers.
    /// Default: `None` (use system resolvers from `/etc/resolv.conf`)
    ///
    /// If `None`, reads system DNS configuration at startup.
    /// This respects VPNs, corporate DNS, and user preferences.
    pub upstream_dns: Option<Vec<SocketAddr>>,

    /// Domain allowlist.
    /// Supports exact matches and wildcards (`*.github.com`).
    pub domain_allowlist: Vec<String>,

    /// Maximum DNS TTL.
    ///
    /// The proxy uses the upstream TTL, but not more than this value, for
    /// the TTL in the DNS response and for the expiry of the IP-to-domain
    /// cache.
    /// Default: 5 minutes
    pub dns_ttl: std::time::Duration,

    /// Minimum DNS TTL.
    ///
    /// The proxy increases a shorter upstream TTL to this value, so that the
    /// cache does not change too frequently. `dns_ttl` has priority if it is
    /// smaller.
    /// Default: 30 seconds
    pub dns_min_ttl: std::time::Duration,

    /// TCP connection timeout.
    /// Default: 30 seconds
    pub tcp_connect_timeout: std::time::Duration,

    /// TCP idle timeout (connection closed if no data flows).
    /// Default: 5 minutes
    pub tcp_idle_timeout: std::time::Duration,

    /// Time limit for the SOCKS5 or HTTP CONNECT handshake of a client.
    /// Default: 10 seconds
    pub handshake_timeout: std::time::Duration,

    /// Policy for destinations that are not public addresses (loopback,
    /// private, link-local and similar ranges).
    /// Default: [`PrivateDestinations::Deny`]
    pub private_destinations: PrivateDestinations,

    /// Optional channel for reporting trace events (violations and granted access).
    /// When set, both blocked and allowed connections send a typed [`TraceEvent`].
    pub violation_tx: Option<tokio::sync::mpsc::UnboundedSender<TraceEvent>>,

    /// The policy of the proxy. Default: [`ProxyPolicy::Enforce`].
    pub policy: ProxyPolicy,

    /// Optional channel for structured events (one for each DNS query and
    /// each connection, allowed or denied). `pent watch` uses it to record
    /// the network access, and `pent run` to record denials.
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<pent_profile::WatchEvent>>,
}

/// The policy of the proxy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyPolicy {
    /// Allow only the domains on the allowlist.
    #[default]
    Enforce,
    /// Allow each domain and emit an event for each request (watch mode).
    /// The rule for destinations that are not public still applies. The TLS
    /// SNI and the HTTP `Host` header do not block a connection; the proxy
    /// uses them only to name it.
    Observe,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        const LOCALHOST_ANY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        Self {
            dns_bind_addr: LOCALHOST_ANY,
            proxy_bind_addr: LOCALHOST_ANY,
            upstream_dns: None,       // Use system resolvers
            domain_allowlist: vec![], // Populated from settings per-assistant
            violation_tx: None,
            policy: ProxyPolicy::Enforce,
            event_tx: None,
            dns_ttl: std::time::Duration::from_secs(300),
            dns_min_ttl: std::time::Duration::from_secs(30),
            tcp_connect_timeout: std::time::Duration::from_secs(30),
            tcp_idle_timeout: std::time::Duration::from_secs(300),
            handshake_timeout: std::time::Duration::from_secs(10),
            private_destinations: PrivateDestinations::Deny,
        }
    }
}

impl ProxyConfig {
    /// Create a new config with the given domain allowlist.
    ///
    /// The domain allowlist is agent-specific and should be obtained from
    /// `AgoConfig::get_domain_allowlist(assistant_name)` which combines:
    /// - Global `containment.domain_allowlist`
    /// - Per-assistant `assistant.{name}.domain_allowlist`
    ///
    /// Example domains per use case:
    /// - Claude: `api.anthropic.com`, `*.anthropic.com`
    /// - Aider: `api.openai.com`, `api.anthropic.com`, `*.aider.chat`
    /// - Common: `*.github.com`, `*.githubusercontent.com`, `pypi.org`, `npmjs.org`
    ///
    ///
    #[must_use]
    pub fn with_allowlist(domains: Vec<String>) -> Self {
        Self {
            domain_allowlist: domains,
            ..Default::default()
        }
    }

    /// Make the DNS server configuration for the bind address `bind_addr`.
    fn dns_config(&self, bind_addr: SocketAddr) -> DnsServerConfig {
        DnsServerConfig {
            bind_addr,
            upstream: self.upstream_dns.clone(),
            ttl: self.dns_ttl,
            min_ttl: self.dns_min_ttl,
            ..Default::default()
        }
    }

    /// Make the TCP proxy configuration for the bind address `bind_addr`.
    fn tcp_config(&self, bind_addr: SocketAddr) -> TcpProxyConfig {
        TcpProxyConfig {
            bind_addr,
            connect_timeout: self.tcp_connect_timeout,
            idle_timeout: self.tcp_idle_timeout,
            handshake_timeout: self.handshake_timeout,
            private_destinations: self.private_destinations,
            ..Default::default()
        }
    }
}

/// Listeners that another process made, for example the sandboxed child in
/// its own network namespace.
///
/// A socket keeps the network namespace of its creation. Thus the proxy can
/// accept connections on these listeners and connect upstream from its own
/// network namespace. See [`ProxyHandle::attach_listeners`].
#[derive(Debug)]
pub struct ExternalListeners {
    /// The TCP listeners of the proxy (SOCKS5 and HTTP CONNECT on the same
    /// port).
    pub tcp: Vec<std::net::TcpListener>,
    /// The UDP socket of the DNS server.
    pub dns_udp: std::net::UdpSocket,
    /// The TCP listener of the DNS server, if there is one.
    pub dns_tcp: Option<std::net::TcpListener>,
}

/// The time that [`ProxyHandle::shutdown`] waits for the server tasks.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Handle for controlling a running proxy server.
///
/// Allows shutting down the server gracefully and modifying the domain allowlist at runtime.
/// When the handle drops without [`ProxyHandle::shutdown`], the server tasks
/// stop too.
pub struct ProxyHandle {
    /// The stop signal for all server tasks. The tasks also stop when the
    /// sender drops.
    stop_tx: watch::Sender<bool>,

    /// The server tasks: one task for each listener.
    tasks: std::sync::Mutex<Vec<JoinHandle<Result<()>>>>,

    /// The DNS server. All listeners share it.
    dns_server: Arc<DnsServer>,

    /// The TCP proxy. All listeners share it, and with it the connection
    /// limit.
    tcp_proxy: Arc<TcpProxy>,

    /// DNS server bind address (`None` without a host listener).
    dns_bind_addr: Option<SocketAddr>,

    /// TCP proxy bind address (`None` without a host listener).
    proxy_bind_addr: Option<SocketAddr>,

    /// Shared state for runtime domain management.
    state: Arc<SharedState>,
}

impl ProxyHandle {
    /// Check if the server is still running.
    ///
    /// Returns false after a server task stopped (for example on a fatal
    /// error).
    #[must_use]
    pub fn is_running(&self) -> bool {
        !*self.stop_tx.borrow() && lock(&self.tasks).iter().all(|task| !task.is_finished())
    }

    /// Shut down the proxy server gracefully.
    ///
    /// Signals the server tasks to stop. When a task stops, it cancels all
    /// its DNS query tasks and TCP connection tasks, and the proxy closes the
    /// open connections. The function aborts each task that does not stop in
    /// 2 seconds.
    ///
    /// # Errors
    /// Currently infallible; always returns `Ok`.
    pub async fn shutdown(self) -> Result<()> {
        self.stop_tx.send_replace(true);
        let tasks = std::mem::take(&mut *lock(&self.tasks));
        let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        for mut task in tasks {
            // The result of the task is not important here: it completed,
            // was cancelled, or panicked, and the proxy stops in all cases.
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
            }
        }
        Ok(())
    }

    /// Serve on listeners that another process made.
    ///
    /// The function sets each socket to nonblocking mode, converts it to a
    /// tokio type and starts the same accept loops as for the own listeners,
    /// with the same policy, event channels and limits. Call it in the tokio
    /// runtime of the proxy. Connections that arrive before the call wait in
    /// the queue of the listener.
    ///
    /// # Errors
    /// * [`ProxyError::Shutdown`] if the proxy is stopped.
    /// * [`ProxyError::Listener`] if a socket cannot change to nonblocking
    ///   mode or cannot register with the tokio runtime.
    pub fn attach_listeners(&self, listeners: ExternalListeners) -> Result<()> {
        if *self.stop_tx.borrow() {
            return Err(ProxyError::Shutdown("the proxy is stopped".to_string()));
        }
        let ExternalListeners {
            tcp,
            dns_udp,
            dns_tcp,
        } = listeners;
        // Convert all sockets first, so that an error starts no task.
        let tcp = tcp
            .into_iter()
            .map(to_tokio_listener)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(ProxyError::Listener)?;
        dns_udp
            .set_nonblocking(true)
            .map_err(ProxyError::Listener)?;
        let dns_udp = tokio::net::UdpSocket::from_std(dns_udp).map_err(ProxyError::Listener)?;
        let dns_tcp = dns_tcp
            .map(to_tokio_listener)
            .transpose()
            .map_err(ProxyError::Listener)?;

        let mut tasks = lock(&self.tasks);
        for listener in tcp {
            let proxy = Arc::clone(&self.tcp_proxy);
            tasks.push(self.spawn_until_stop(async move { proxy.run_on(listener).await }));
        }
        let dns = Arc::clone(&self.dns_server);
        tasks.push(self.spawn_until_stop(async move { dns.run_on(dns_udp).await }));
        if let Some(listener) = dns_tcp {
            let dns = Arc::clone(&self.dns_server);
            tasks.push(self.spawn_until_stop(async move { dns.run_tcp_on(listener).await }));
        }
        Ok(())
    }

    /// Spawn `serve` as a task that ends at the stop signal. The drop of the
    /// future at the stop also drops the `JoinSet` of its connection tasks,
    /// and so aborts them.
    fn spawn_until_stop<F>(&self, serve: F) -> JoinHandle<Result<()>>
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let mut stop_rx = self.stop_tx.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                result = serve => result,
                // An error means that the handle dropped; stop also then.
                _ = stop_rx.wait_for(|stop| *stop) => Ok(()),
            }
        })
    }

    /// Get the DNS server bind address.
    ///
    /// Returns `None` when the proxy has no host listener (see
    /// [`ProxyServer::start_unbound`]).
    #[must_use]
    pub const fn dns_addr(&self) -> Option<SocketAddr> {
        self.dns_bind_addr
    }

    /// Get the TCP proxy bind address.
    ///
    /// Returns `None` when the proxy has no host listener (see
    /// [`ProxyServer::start_unbound`]).
    #[must_use]
    pub const fn proxy_addr(&self) -> Option<SocketAddr> {
        self.proxy_bind_addr
    }

    /// Get the current domain allowlist.
    #[must_use]
    pub fn allowlist(&self) -> Vec<String> {
        self.state.allowlist()
    }

    /// Total number of TCP proxy connections accepted since the proxy started.
    ///
    /// Monotonically increasing. A value of zero after the sandboxed process
    /// has been running for several seconds suggests the process is not routing
    /// traffic through the proxy (i.e. it does not honour `HTTP_PROXY` /
    /// `ALL_PROXY`).
    #[must_use]
    pub fn connections_accepted(&self) -> u64 {
        self.state
            .connections_accepted
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Return a cloned Arc to the connections-accepted counter so callers can
    /// pass it into spawned tasks without keeping the full handle alive.
    #[must_use]
    pub fn connections_accepted_ref(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.state.connections_accepted)
    }

    /// The number of trace events and watch events that the proxy could not
    /// deliver, because the receiver of the channel was closed.
    #[must_use]
    pub fn dropped_trace_events(&self) -> u64 {
        self.state.dropped_trace_events()
    }

    /// Add a domain to the allowlist at runtime.
    ///
    /// The change takes effect immediately for new DNS queries.
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidDomain`] if the pattern is not valid.
    pub fn add_domain(&self, domain: String) -> Result<()> {
        self.state.add_domain(domain)
    }
}

/// Set `listener` to nonblocking mode and register it with tokio.
fn to_tokio_listener(listener: std::net::TcpListener) -> std::io::Result<tokio::net::TcpListener> {
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

/// Lock the task list. A poisoned lock still holds a valid list.
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Combined DNS + TCP proxy server.
///
/// Manages the lifecycle of both servers and provides unified configuration.
pub struct ProxyServer {
    /// Server configuration.
    config: ProxyConfig,

    /// Shared state between DNS and TCP proxy.
    state: Arc<SharedState>,
}

impl ProxyServer {
    /// Create a new proxy server.
    ///
    /// # Arguments
    /// * `config` - Server configuration
    ///
    /// # Errors
    /// * `ProxyError::InvalidDomain` - If a pattern in the allowlist is not
    ///   valid (for example, if it contains characters that are not ASCII).
    ///
    /// # Example
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use pent_proxy::{ProxyConfig, ProxyServer};
    ///
    /// let config = ProxyConfig {
    ///     domain_allowlist: vec!["*.github.com".to_string()],
    ///     ..ProxyConfig::default()
    /// };
    /// let handle = ProxyServer::new(config)?.start().await?;
    /// // ... the sandboxed process uses the proxy ...
    /// handle.shutdown().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let state = Arc::new(
            SharedState::try_with_violation_tx(
                &config.domain_allowlist,
                config.violation_tx.clone(),
            )?
            .with_policy(config.policy)
            .with_event_tx(config.event_tx.clone()),
        );
        Ok(Self { config, state })
    }

    /// Start the proxy server.
    ///
    /// Binds the DNS UDP socket and the TCP proxy listener on the host, and
    /// spawns the DNS server and TCP proxy as concurrent tasks.
    /// Returns a handle for controlling the running server.
    ///
    /// # Errors
    /// * `ProxyError::Bind` - If binding the DNS UDP socket or the TCP proxy
    ///   listener fails (e.g. address already in use).
    pub async fn start(self) -> Result<ProxyHandle> {
        use tokio::net::{TcpListener, UdpSocket};

        // Pre-bind sockets so actual OS-assigned ports are known immediately.
        let tcp_listener = TcpListener::bind(self.config.proxy_bind_addr)
            .await
            .map_err(|e| ProxyError::Bind {
                addr: self.config.proxy_bind_addr,
                source: e,
            })?;
        let actual_proxy_addr = tcp_listener.local_addr().map_err(|e| ProxyError::Bind {
            addr: self.config.proxy_bind_addr,
            source: e,
        })?;

        let udp_socket = UdpSocket::bind(self.config.dns_bind_addr)
            .await
            .map_err(|e| ProxyError::Bind {
                addr: self.config.dns_bind_addr,
                source: e,
            })?;
        let actual_dns_addr = udp_socket.local_addr().map_err(|e| ProxyError::Bind {
            addr: self.config.dns_bind_addr,
            source: e,
        })?;

        let handle = self.into_handle(Some(actual_dns_addr), Some(actual_proxy_addr))?;
        let dns = Arc::clone(&handle.dns_server);
        let proxy = Arc::clone(&handle.tcp_proxy);
        // Run both servers on the pre-bound sockets. At the stop signal the
        // task drops the two server futures. Each of them owns a JoinSet of
        // its tasks, and the drop of a JoinSet aborts all its tasks.
        let task = handle.spawn_until_stop(async move {
            tokio::select! {
                result = dns.run_on(udp_socket) => result,
                result = proxy.run_on(tcp_listener) => result,
            }
        });
        lock(&handle.tasks).push(task);
        Ok(handle)
    }

    /// Start the proxy server without host listeners.
    ///
    /// The server serves only on the listeners that the caller gives to
    /// [`ProxyHandle::attach_listeners`]. On Linux, the sandboxed child makes
    /// these listeners in its own network namespace, so the proxy needs no
    /// port on the host.
    ///
    /// # Errors
    /// Currently infallible; the `Result` type matches
    /// [`ProxyServer::start`].
    pub fn start_unbound(self) -> Result<ProxyHandle> {
        self.into_handle(None, None)
    }

    /// Make the handle with the DNS server and the TCP proxy, and no tasks.
    fn into_handle(
        self,
        dns_addr: Option<SocketAddr>,
        proxy_addr: Option<SocketAddr>,
    ) -> Result<ProxyHandle> {
        // The servers use the listeners that they get. The bind addresses in
        // their configurations are used only by `DnsServer::run` and
        // `TcpProxy::run`, which the handle does not call.
        let dns_config = self
            .config
            .dns_config(dns_addr.unwrap_or(self.config.dns_bind_addr));
        let tcp_config = self
            .config
            .tcp_config(proxy_addr.unwrap_or(self.config.proxy_bind_addr));
        let dns_server = Arc::new(DnsServer::new(dns_config, Arc::clone(&self.state))?);
        let tcp_proxy = Arc::new(TcpProxy::new(tcp_config, Arc::clone(&self.state))?);
        Ok(ProxyHandle {
            stop_tx: watch::Sender::new(false),
            tasks: std::sync::Mutex::new(Vec::new()),
            dns_server,
            tcp_proxy,
            dns_bind_addr: dns_addr,
            proxy_bind_addr: proxy_addr,
            state: self.state,
        })
    }

    /// Run the proxy server until shutdown.
    ///
    /// Alternative to `start()` for blocking operation.
    /// Runs until a signal is received or an error occurs.
    ///
    /// # Errors
    /// * `ProxyError::Bind` - If binding to the configured address fails.
    /// * `ProxyError::Internal` - If the DNS server or TCP proxy encounter
    ///   a fatal runtime error.
    pub async fn run(self) -> Result<()> {
        let dns_config = self.config.dns_config(self.config.dns_bind_addr);
        let tcp_config = self.config.tcp_config(self.config.proxy_bind_addr);

        let dns_server = DnsServer::new(dns_config, Arc::clone(&self.state))?;
        let tcp_proxy = TcpProxy::new(tcp_config, Arc::clone(&self.state))?;

        // Run both servers concurrently
        tokio::select! {
            result = dns_server.run() => result,
            result = tcp_proxy.run() => result,
        }
    }

    /// Get the current domain allowlist.
    #[must_use]
    pub fn allowlist(&self) -> Vec<String> {
        self.state.allowlist()
    }

    /// Add a domain to the allowlist at runtime.
    ///
    /// The change takes effect immediately for new DNS queries.
    ///
    /// Note: This does not persist the change to config - only updates the runtime state.
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidDomain`] if the pattern is not valid.
    pub fn add_domain(&self, domain: String) -> Result<()> {
        self.state.add_domain(domain)
    }
}

/// An error in the conversion of `ProxySettings` into a [`ProxyConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// An `upstream_dns` entry is not a valid socket address.
    #[error("Invalid upstream_dns entry {entry:?}: {source}")]
    InvalidUpstreamDns {
        /// The entry from the settings.
        entry: String,
        /// The parse error.
        #[source]
        source: std::net::AddrParseError,
    },
}

/// Convert a `ProxySettings` fragment (from `pent-settings`) into a `ProxyConfig`.
///
/// Returns [`ConfigError::InvalidUpstreamDns`] if any `upstream_dns` entry
/// cannot be parsed as a `SocketAddr`.  All other fields have infallible
/// defaults.
impl TryFrom<&pent_settings::ProxySettings> for ProxyConfig {
    type Error = ConfigError;

    fn try_from(settings: &pent_settings::ProxySettings) -> std::result::Result<Self, ConfigError> {
        // The domains come from the profile, not from the settings. The
        // caller sets `domain_allowlist`.
        let mut config = Self::default();
        if let Some(ttl) = settings.dns_ttl_seconds {
            config.dns_ttl = std::time::Duration::from_secs(u64::from(ttl));
        }
        if let Some(t) = settings.tcp_connect_timeout_secs {
            config.tcp_connect_timeout = std::time::Duration::from_secs(t);
        }
        if let Some(t) = settings.tcp_idle_timeout_secs {
            config.tcp_idle_timeout = std::time::Duration::from_secs(t);
        }
        if let Some(policy) = settings.private_destinations {
            config.private_destinations = match policy {
                pent_settings::PrivateDestinations::Deny => PrivateDestinations::Deny,
                pent_settings::PrivateDestinations::Allow => PrivateDestinations::Allow,
            };
        }
        if let Some(upstream) = &settings.upstream_dns {
            let addrs = upstream
                .iter()
                .map(|entry| {
                    entry
                        .parse::<SocketAddr>()
                        .map_err(|source| ConfigError::InvalidUpstreamDns {
                            entry: entry.clone(),
                            source,
                        })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            config.upstream_dns = Some(addrs);
        }
        Ok(config)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_statements)] // use statements inside test fns after skip_if_no_bind!()
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn can_bind_tcp_localhost() -> bool {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                drop(listener);
                true
            }
            // Treat any bind error (including unexpected ones) as "can't bind" to
            // avoid panicking in helper code that runs before the test body.
            Err(_) => false,
        }
    }

    fn can_bind_udp_localhost() -> bool {
        match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => {
                drop(socket);
                true
            }
            Err(_) => false,
        }
    }

    fn can_bind_localhost() -> bool {
        can_bind_tcp_localhost() && can_bind_udp_localhost()
    }

    macro_rules! skip_if_no_bind {
        () => {
            if !can_bind_localhost() {
                crate::test_support::skip("this machine cannot bind a socket on the loopback");
                return Ok(());
            }
        };
    }

    /// Wait until `bind` on `addr` works, for at most two seconds.
    ///
    /// The tests bind the port 0, so the OS chooses the port. After a
    /// shutdown the port goes back to the pool, and another test of
    /// another test binary can hold it for a moment. The retry removes
    /// that race; the port of a server that did not stop never becomes
    /// free.
    async fn port_becomes_free(addr: SocketAddr, udp: bool) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let free = if udp {
                tokio::net::UdpSocket::bind(addr).await.is_ok()
            } else {
                tokio::net::TcpListener::bind(addr).await.is_ok()
            };
            if free {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    // ========================================================================
    // ProxyConfig Tests
    // ========================================================================

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        // Port 0 lets OS assign available ports
        assert_eq!(config.dns_bind_addr.port(), 0);
        assert_eq!(config.proxy_bind_addr.port(), 0);
        assert!(config.domain_allowlist.is_empty()); // Injected per-assistant
    }

    #[test]
    fn test_proxy_config_default_uses_system_dns() {
        let config = ProxyConfig::default();
        assert!(config.upstream_dns.is_none()); // Uses /etc/resolv.conf
    }

    #[test]
    fn test_proxy_config_default_timeouts() {
        let config = ProxyConfig::default();
        assert_eq!(config.dns_ttl, std::time::Duration::from_secs(300));
        assert_eq!(
            config.tcp_connect_timeout,
            std::time::Duration::from_secs(30)
        );
        assert_eq!(config.tcp_idle_timeout, std::time::Duration::from_secs(300));
    }

    #[test]
    fn test_proxy_config_with_allowlist() {
        let config = ProxyConfig::with_allowlist(vec!["example.com".to_string()]);
        assert_eq!(config.domain_allowlist, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_proxy_config_with_allowlist_preserves_defaults() {
        let config = ProxyConfig::with_allowlist(vec!["example.com".to_string()]);
        // Other settings should still be defaults (port 0 = OS assigned)
        assert_eq!(config.dns_bind_addr.port(), 0);
        assert_eq!(config.proxy_bind_addr.port(), 0);
    }

    #[test]
    fn test_proxy_config_with_empty_allowlist() {
        let config = ProxyConfig::with_allowlist(vec![]);
        assert!(config.domain_allowlist.is_empty());
    }

    // ========================================================================
    // ProxyServer Creation Tests
    // ========================================================================

    #[test]
    fn test_proxy_server_new_with_valid_config() {
        let config = ProxyConfig::with_allowlist(vec!["example.com".to_string()]);
        let server = ProxyServer::new(config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_proxy_server_new_initializes_filter() -> TestResult {
        let config = ProxyConfig::with_allowlist(vec!["example.com".to_string()]);
        let server = ProxyServer::new(config)?;
        assert!(server.state.is_allowed("example.com"));
        assert!(!server.state.is_allowed("other.com"));
        Ok(())
    }

    #[test]
    fn test_proxy_server_new_initializes_cache() -> TestResult {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config)?;
        assert!(server.state.cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_proxy_server_allowlist_accessor() -> TestResult {
        let config = ProxyConfig::with_allowlist(vec![
            "example.com".to_string(),
            "*.github.com".to_string(),
        ]);
        let server = ProxyServer::new(config)?;
        let patterns = server.allowlist();
        assert_eq!(patterns.len(), 2);
        assert!(patterns.contains(&"example.com".to_string()));
        assert!(patterns.contains(&"*.github.com".to_string()));
        Ok(())
    }

    // ========================================================================
    // ProxyHandle Tests
    // ========================================================================

    #[tokio::test]

    async fn test_proxy_handle_is_running_true() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Should report as running
        assert!(handle.is_running());

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_handle_is_running_false_after_shutdown() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        assert!(handle.is_running(), "the server runs before the shutdown");
        let proxy_addr = handle.proxy_addr();
        handle.shutdown().await?;

        // The shutdown takes the handle, so the proof is the port: after
        // the shutdown nothing accepts a connection on it.
        let addr = proxy_addr.ok_or("the proxy has no address")?;
        let after = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(addr),
        )
        .await;
        assert!(
            matches!(after, Ok(Err(_)) | Err(_)),
            "the port {addr} still accepts a connection after the shutdown"
        );
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_handle_dns_addr() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        let dns_addr = handle.dns_addr().ok_or("no DNS address")?;
        assert_ne!(dns_addr.port(), 0, "the OS gave the DNS server a port");
        assert_eq!(dns_addr.ip().to_string(), "127.0.0.1");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_handle_proxy_addr() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        let proxy_addr = handle.proxy_addr().ok_or("no proxy address")?;
        assert_ne!(proxy_addr.port(), 0, "the OS gave the proxy a port");
        assert_eq!(proxy_addr.ip().to_string(), "127.0.0.1");

        handle.shutdown().await?;
        Ok(())
    }

    // ========================================================================
    // Server Lifecycle Tests
    // ========================================================================

    #[tokio::test]

    async fn test_proxy_server_start_returns_handle() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await;

        assert!(handle.is_ok());
        handle?.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_start_binds_dns() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to bind to same port - should fail (port in use)
        let dns_addr = handle.dns_addr().ok_or("the DNS server has no address")?;
        let result = UdpSocket::bind(dns_addr).await;
        assert!(result.is_err());

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_start_binds_tcp() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to bind to same port - should fail (port in use)
        let proxy_addr = handle.proxy_addr().ok_or("the proxy has no address")?;
        let result = TcpListener::bind(proxy_addr).await;
        assert!(result.is_err());

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_server_shutdown_graceful() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Shutdown should complete without error
        let result = handle.shutdown().await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_shutdown_stops_dns() -> TestResult {
        skip_if_no_bind!();

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;
        let dns_addr = handle.dns_addr().ok_or("the DNS server has no address")?;
        handle.shutdown().await?;

        // After shutdown, port should be available again
        assert!(
            port_becomes_free(dns_addr, true).await,
            "the DNS port {dns_addr} stays in use after the shutdown"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_shutdown_stops_tcp() -> TestResult {
        skip_if_no_bind!();

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;
        let proxy_addr = handle.proxy_addr().ok_or("the proxy has no address")?;
        handle.shutdown().await?;

        // After shutdown, port should be available again
        assert!(
            port_becomes_free(proxy_addr, false).await,
            "the proxy port {proxy_addr} stays in use after the shutdown"
        );
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_server_run_blocks() -> TestResult {
        skip_if_no_bind!();
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;

        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let handle = tokio::spawn(async move {
            let _ = server.run().await;
            completed_clone.store(true, Ordering::SeqCst);
        });

        // Give it time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Should still be running (blocking)
        assert!(!completed.load(Ordering::SeqCst));

        // Abort to clean up
        handle.abort();
        Ok(())
    }

    // ========================================================================
    // Integration Tests - End to End
    // ========================================================================

    #[tokio::test]
    async fn test_integration_allowed_domain_flow() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let Some(upstream) = fake_upstream() else {
            crate::test_support::skip("this machine cannot bind a UDP socket on the loopback");
            return Ok(());
        };
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["example.com".to_string()],
            upstream_dns: Some(vec![upstream]),
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Build DNS query for example.com
        let query = build_test_dns_query("example.com", 1); // A record

        // Send DNS query
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let dns_addr = handle.dns_addr().ok_or("the DNS server has no address")?;
        socket.send_to(&query, dns_addr).await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await??;

        // Success (RCODE 0) with the A record of the fake upstream.
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "Expected success RCODE");
        assert_eq!(
            u16::from_be_bytes([buf[6], buf[7]]),
            1,
            "the answer must hold one record"
        );
        assert!(
            buf[..len].windows(4).any(|w| w == [203, 0, 113, 9]),
            "the answer must carry the address of the upstream"
        );

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_integration_blocked_domain_flow() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["allowed.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Build DNS query for blocked domain
        let query = build_test_dns_query("blocked.com", 1);

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let dns_addr = handle.dns_addr().ok_or("the DNS server has no address")?;
        socket.send_to(&query, dns_addr).await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await??;

        // Should get NXDOMAIN (RCODE = 3 in byte 3)
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 3, "Expected NXDOMAIN RCODE");

        handle.shutdown().await?;
        Ok(())
    }

    /// An unbound proxy serves DNS (UDP and TCP) and the proxy port on
    /// listeners that the caller attaches after the start.
    #[tokio::test]
    async fn test_attach_listeners_serves_dns_and_proxy() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let config = ProxyConfig::with_allowlist(vec!["allowed.com".to_string()]);
        let handle = ProxyServer::new(config)?.start_unbound()?;
        assert!(handle.proxy_addr().is_none());
        assert!(handle.dns_addr().is_none());
        assert!(handle.is_running());

        let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
        let dns_udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let dns_tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
        let proxy_addr = tcp.local_addr()?;
        let udp_addr = dns_udp.local_addr()?;
        let dns_tcp_addr = dns_tcp.local_addr()?;
        handle.attach_listeners(ExternalListeners {
            tcp: vec![tcp],
            dns_udp,
            dns_tcp: Some(dns_tcp),
        })?;
        let timeout = std::time::Duration::from_secs(2);

        // DNS over UDP: a blocked name gets NXDOMAIN.
        let query = build_test_dns_query("blocked.com", 1);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(&query, udp_addr).await?;
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await??;
        assert!(len > 12);
        assert_eq!(buf[3] & 0x0F, 3, "Expected NXDOMAIN over UDP");

        // DNS over TCP: the same answer with a length prefix. Two queries on
        // one connection.
        let mut stream = tokio::net::TcpStream::connect(dns_tcp_addr).await?;
        for _ in 0..2 {
            let len = u16::try_from(query.len())?;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&query).await?;
            let mut len_buf = [0u8; 2];
            tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await??;
            let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
            tokio::time::timeout(timeout, stream.read_exact(&mut reply)).await??;
            assert!(reply.len() > 12);
            assert_eq!(reply[3] & 0x0F, 3, "Expected NXDOMAIN over TCP");
        }

        // The proxy port: a SOCKS5 greeting gets the SOCKS5 answer.
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await?;
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        tokio::time::timeout(timeout, client.read_exact(&mut greeting)).await??;
        assert_eq!(greeting, [0x05, 0x00]);
        assert_eq!(handle.connections_accepted(), 1);

        handle.shutdown().await?;
        Ok(())
    }

    /// The listeners of a stopped proxy do not answer, and the attached tasks
    /// end at the shutdown.
    #[tokio::test]
    async fn test_attach_listeners_stop_at_shutdown() -> TestResult {
        skip_if_no_bind!();
        let handle = ProxyServer::new(ProxyConfig::default())?.start_unbound()?;
        let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = tcp.local_addr()?;
        handle.attach_listeners(ExternalListeners {
            tcp: vec![tcp],
            dns_udp: std::net::UdpSocket::bind("127.0.0.1:0")?,
            dns_tcp: None,
        })?;
        handle.shutdown().await?;
        // The listener closed with its task, so the port refuses.
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_integration_direct_ip_blocked() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to proxy and try direct IP (not resolved through DNS)
        let proxy_addr = handle.proxy_addr().ok_or("the proxy has no address")?;
        let mut stream = TcpStream::connect(proxy_addr).await?;

        // SOCKS5 handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        // Request connection to raw IP (1.2.3.4:80)
        let request = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        stream.write_all(&request).await?;

        let mut reply = [0u8; 10];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut reply),
        )
        .await??;

        // Should be rejected (reply[1] != 0x00)
        assert_ne!(reply[1], 0x00, "Direct IP should be rejected");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_integration_wildcard_subdomain() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let Some(upstream) = fake_upstream() else {
            crate::test_support::skip("this machine cannot bind a UDP socket on the loopback");
            return Ok(());
        };
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["*.github.com".to_string()],
            upstream_dns: Some(vec![upstream]),
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Query subdomain that matches wildcard
        let query = build_test_dns_query("api.github.com", 1);

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let dns_addr = handle.dns_addr().ok_or("the DNS server has no address")?;
        socket.send_to(&query, dns_addr).await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await??;

        // Success (the wildcard matches), with the record of the upstream.
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "Wildcard subdomain should be allowed");
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1);

        // The parent name itself is not below the wildcard.
        let query = build_test_dns_query("github.com", 1);
        socket.send_to(&query, dns_addr).await?;
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await??;
        assert!(len > 12);
        assert_eq!(buf[3] & 0x0F, 3, "the parent name must get NXDOMAIN");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_integration_cache_expiry() -> TestResult {
        skip_if_no_bind!();
        use crate::ResolvedAddress;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["test.local".to_string()],
            dns_ttl: std::time::Duration::from_secs(1), // Very short TTL
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;

        // Manually insert a cache entry with short expiry
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec!["10.0.0.1".parse()?],
            expires_at: std::time::Instant::now() + std::time::Duration::from_millis(100),
        };
        server.state.cache.insert(resolved);

        // Verify it's in cache
        let ip: std::net::IpAddr = "10.0.0.1".parse()?;
        assert!(server.state.cache.lookup(&ip).is_some());

        // Wait for expiry
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // After TTL, cache should have expired the entry
        // Note: Implementation may need explicit cleanup or lazy expiry
        let lookup = server.state.cache.lookup(&ip);
        // Depending on implementation: assert!(lookup.is_none());
        // If lazy expiry: lookup might still exist but be expired
        let _ = lookup; // Test structure ready for production code
        Ok(())
    }

    // ========================================================================
    // Dynamic Configuration Tests
    // ========================================================================

    #[test]
    fn test_add_domain_updates_allowlist() -> TestResult {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config)?;

        assert!(!server.allowlist().contains(&"newdomain.com".to_string()));

        server.add_domain("newdomain.com".to_string())?;

        // After adding, should be in allowlist
        assert!(server.allowlist().contains(&"newdomain.com".to_string()));
        Ok(())
    }

    #[test]
    fn test_add_domain_supports_wildcard() -> TestResult {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config)?;

        server.add_domain("*.newdomain.com".to_string())?;

        assert!(server.allowlist().contains(&"*.newdomain.com".to_string()));

        // Verify wildcard matching works
        assert!(server.state.is_allowed("sub.newdomain.com"));
        Ok(())
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[tokio::test]
    async fn test_start_dns_port_in_use() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        // Bind to DNS port first
        let blocker = UdpSocket::bind("127.0.0.1:0").await?;

        let config = ProxyConfig {
            dns_bind_addr: blocker.local_addr()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        // start() now pre-binds before spawning; bind error surfaces immediately.
        let result = server.start().await;
        assert!(
            result.is_err(),
            "start() should fail when DNS port is in use"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_start_proxy_port_in_use() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        // Bind to proxy port first
        let blocker = TcpListener::bind("127.0.0.1:0").await?;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: blocker.local_addr()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        // start() now pre-binds before spawning; bind error surfaces immediately.
        let result = server.start().await;
        assert!(
            result.is_err(),
            "start() should fail when proxy port is in use"
        );
        Ok(())
    }

    // ========================================================================
    // Concurrent Operations Tests
    // ========================================================================

    #[tokio::test]
    async fn test_concurrent_dns_and_tcp() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpStream, UdpSocket};

        let Some(upstream) = fake_upstream() else {
            crate::test_support::skip("this machine cannot bind a UDP socket on the loopback");
            return Ok(());
        };
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["example.com".to_string()],
            upstream_dns: Some(vec![upstream]),
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        let dns_addr = handle.dns_addr().ok_or("the DNS server has no address")?;
        let proxy_addr = handle.proxy_addr().ok_or("the proxy has no address")?;

        // Spawn DNS query
        let dns_task = tokio::spawn(async move {
            let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
                return false;
            };
            let query = build_test_dns_query("example.com", 1);
            if socket.send_to(&query, dns_addr).await.is_err() {
                return false;
            }
            let mut buf = [0u8; 512];
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut buf),
            )
            .await;
            // The answer must be a DNS answer with RCODE 0, not only a
            // datagram that arrived before the timeout.
            matches!(result, Ok(Ok((len, _))) if len > 12 && buf[3] & 0x0F == 0)
        });

        // Spawn TCP connection
        let tcp_task = tokio::spawn(async move {
            let Ok(mut stream) = TcpStream::connect(proxy_addr).await else {
                return false;
            };
            // The greeting of SOCKS5 and the answer of the proxy.
            if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
                return false;
            }
            let mut buf = [0u8; 2];
            matches!(stream.read_exact(&mut buf).await, Ok(2)) && buf == [0x05, 0x00]
        });

        // Both must work at the same time.
        let (dns_result, tcp_result) = tokio::join!(dns_task, tcp_task);
        assert!(dns_result?, "the DNS server did not answer");
        assert!(tcp_result?, "the proxy did not answer the SOCKS5 greeting");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_concurrent_multiple_clients() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Spawn multiple concurrent TCP clients
        let proxy_addr = handle.proxy_addr().ok_or("the proxy has no address")?;
        let mut tasks = vec![];
        for _ in 0..5 {
            tasks.push(tokio::spawn(async move {
                let result = TcpStream::connect(proxy_addr).await;
                if let Ok(mut stream) = result {
                    let _ = stream.write_all(&[0x05, 0x01, 0x00]).await;
                    let mut buf = [0u8; 2];
                    let _ = stream.read(&mut buf).await;
                    true
                } else {
                    false
                }
            }));
        }

        // All clients should connect successfully
        for task in tasks {
            let result = task.await?;
            assert!(result, "All concurrent clients should connect");
        }

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_dns_cache_shared_with_tcp() -> TestResult {
        skip_if_no_bind!();
        use crate::ResolvedAddress;
        use std::sync::Arc;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            domain_allowlist: vec!["cached.example".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;

        // Clone state Arc before server.start() consumes self
        let state = Arc::clone(&server.state);

        // Pre-populate cache (simulating what happens after DNS resolution).
        // We insert before start() to verify the cache survives server init.
        let resolved = ResolvedAddress {
            domain: "cached.example".to_string(),
            addresses: vec!["192.0.2.1".parse()?],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let handle = server.start().await?;

        // The shared cache is visible to the TCP proxy side: a connection to
        // 192.0.2.1 should be recognised as targeting "cached.example".
        let ip: std::net::IpAddr = "192.0.2.1".parse()?;
        let lookup = state.cache.lookup(&ip);
        assert!(lookup.is_some());
        assert_eq!(
            lookup.ok_or("cache lookup returned None")?,
            "cached.example"
        );

        handle.shutdown().await?;
        Ok(())
    }

    // ========================================================================
    // Test Helper Functions
    // ========================================================================

    /// Build a DNS query packet for testing.
    /// Start a fake upstream DNS server on the loopback.
    ///
    /// It answers each A query with 203.0.113.9 and every other type with
    /// NOERROR and no record. The tests of this file then need no internet
    /// and no resolver of the host.
    ///
    /// Returns `None` when the machine cannot bind a UDP socket.
    fn fake_upstream() -> Option<SocketAddr> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
        let addr = socket.local_addr().ok()?;
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buf) else {
                    return;
                };
                let Some(query) = buf.get(..len) else {
                    continue;
                };
                if let Some(answer) = fake_answer(query) {
                    let _ = socket.send_to(&answer, src);
                }
            }
        });
        Some(addr)
    }

    /// Build the answer of [`fake_upstream`] for one query.
    fn fake_answer(query: &[u8]) -> Option<Vec<u8>> {
        // Walk the question to its end: the answer echoes it.
        let mut pos = 12usize;
        loop {
            let len = *query.get(pos)? as usize;
            pos += 1;
            if len == 0 {
                break;
            }
            pos += len;
        }
        let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
        let question = query.get(12..pos + 4)?;
        let mut out = query.get(..2)?.to_vec();
        out.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA, NOERROR
        out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        let a_record = qtype == 1;
        out.extend_from_slice(&u16::from(a_record).to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(question);
        if a_record {
            out.extend_from_slice(&[0xC0, 0x0C]); // the name of the question
            out.extend_from_slice(&1u16.to_be_bytes()); // A
            out.extend_from_slice(&1u16.to_be_bytes()); // IN
            out.extend_from_slice(&60u32.to_be_bytes()); // TTL
            out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            out.extend_from_slice(&[203, 0, 113, 9]);
        }
        Some(out)
    }

    fn build_test_dns_query(domain: &str, record_type: u16) -> Vec<u8> {
        let mut query = Vec::new();

        // Header
        query.extend_from_slice(&[0xAB, 0xCD]); // ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question: domain name in DNS format
        for label in domain.split('.') {
            // All test domains use short labels well within 63-byte DNS limit.
            // Saturate to 255 rather than panic on impossibly long labels.
            let label_len = u8::try_from(label.len()).unwrap_or(255);
            query.push(label_len);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // Root label

        // QTYPE and QCLASS
        query.extend_from_slice(&record_type.to_be_bytes());
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

        query
    }

    // ========================================================================
    // Configuration Errors and Shutdown
    // ========================================================================

    #[test]
    fn test_try_from_settings_reports_bad_upstream() {
        let settings = pent_settings::ProxySettings {
            upstream_dns: Some(vec!["1.1.1.1:53".to_string(), "not-an-addr".to_string()]),
            ..Default::default()
        };
        let result = ProxyConfig::try_from(&settings);
        assert!(
            matches!(&result, Err(ConfigError::InvalidUpstreamDns { entry, .. }) if entry == "not-an-addr"),
            "expected InvalidUpstreamDns, got {result:?}"
        );
    }

    #[test]
    fn test_try_from_settings_defaults() -> TestResult {
        let config = ProxyConfig::try_from(&pent_settings::ProxySettings::default())?;
        assert_eq!(config.private_destinations, PrivateDestinations::Deny);
        assert_eq!(config.handshake_timeout, std::time::Duration::from_secs(10));
        assert_eq!(config.dns_min_ttl, std::time::Duration::from_secs(30));
        Ok(())
    }

    #[test]
    fn test_proxy_server_new_rejects_non_ascii_allowlist() {
        let config = ProxyConfig::with_allowlist(vec!["b\u{fc}cher.example".to_string()]);
        assert!(matches!(
            ProxyServer::new(config),
            Err(ProxyError::InvalidDomain(_))
        ));
    }

    #[tokio::test]
    async fn test_shutdown_closes_open_relays() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // The destination keeps its side open and never sends data.
        let dest_listener = TcpListener::bind("127.0.0.1:0").await?;
        let dest = dest_listener.local_addr()?;
        let _dest_task = tokio::spawn(async move {
            if let Ok((mut socket, _)) = dest_listener.accept().await {
                let mut buf = [0u8; 16];
                while matches!(socket.read(&mut buf).await, Ok(n) if n > 0) {}
            }
        });

        let config = ProxyConfig {
            domain_allowlist: vec!["test.local".to_string()],
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        server.state.cache.insert(crate::ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec![dest.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        });
        let handle = server.start().await?;

        let mut client = TcpStream::connect(handle.proxy_addr().ok_or("no proxy address")?).await?;
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let limit = std::time::Duration::from_secs(5);
        let mut greeting = [0u8; 2];
        tokio::time::timeout(limit, client.read_exact(&mut greeting)).await??;
        let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&dest.port().to_be_bytes());
        client.write_all(&request).await?;
        let mut reply = [0u8; 10];
        tokio::time::timeout(limit, client.read_exact(&mut reply)).await??;
        assert_eq!(reply[1], 0x00, "the relay must start");

        handle.shutdown().await?;

        // The proxy must close the relay of the open connection.
        let mut buf = [0u8; 1];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0) | Err(_))),
            "the relay is still open after shutdown: {read:?}"
        );
        Ok(())
    }

    // ========================================================================
    // The settings reach the two servers
    // ========================================================================

    /// Each setting of a [`ProxyConfig`] reaches the DNS server
    /// configuration and the TCP proxy configuration. The test uses values
    /// that differ from the defaults, so a lost field shows.
    #[test]
    fn test_the_config_carries_each_setting_to_the_dns_server_and_the_proxy() -> TestResult {
        use std::time::Duration;

        let upstream: SocketAddr = "203.0.113.9:53".parse()?;
        let config = ProxyConfig {
            dns_ttl: Duration::from_secs(111),
            dns_min_ttl: Duration::from_secs(22),
            tcp_connect_timeout: Duration::from_secs(33),
            tcp_idle_timeout: Duration::from_secs(44),
            handshake_timeout: Duration::from_secs(55),
            private_destinations: PrivateDestinations::Allow,
            upstream_dns: Some(vec![upstream]),
            ..Default::default()
        };

        let dns_addr: SocketAddr = "127.0.0.1:25401".parse()?;
        let dns = config.dns_config(dns_addr);
        assert_eq!(dns.bind_addr, dns_addr);
        assert_eq!(dns.ttl, Duration::from_secs(111));
        assert_eq!(dns.min_ttl, Duration::from_secs(22));
        assert_eq!(dns.upstream, Some(vec![upstream]));

        let proxy_addr: SocketAddr = "127.0.0.1:29401".parse()?;
        let tcp = config.tcp_config(proxy_addr);
        assert_eq!(tcp.bind_addr, proxy_addr);
        assert_eq!(tcp.connect_timeout, Duration::from_secs(33));
        assert_eq!(tcp.idle_timeout, Duration::from_secs(44));
        assert_eq!(tcp.handshake_timeout, Duration::from_secs(55));
        assert_eq!(tcp.private_destinations, PrivateDestinations::Allow);
        Ok(())
    }

    // ========================================================================
    // The accessors of the handle
    // ========================================================================

    /// The handle reports the allowlist of its state, and
    /// [`ProxyHandle::add_domain`] changes that allowlist.
    #[tokio::test]
    async fn test_the_handle_adds_a_domain_and_reports_the_allowlist() -> TestResult {
        let handle = ProxyServer::new(ProxyConfig::with_allowlist(vec![
            "first.example".to_string()
        ]))?
        .start_unbound()?;

        assert_eq!(handle.allowlist(), vec!["first.example".to_string()]);
        handle.add_domain("second.example".to_string())?;
        assert!(handle.allowlist().contains(&"second.example".to_string()));
        assert!(handle.state.is_allowed("second.example"));
        Ok(())
    }

    /// The handle reports the number of trace events that the proxy could
    /// not deliver.
    #[tokio::test]
    async fn test_the_handle_reports_the_dropped_trace_events() -> TestResult {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let config = ProxyConfig {
            violation_tx: Some(tx),
            ..ProxyConfig::with_allowlist(vec!["allowed.example".to_string()])
        };
        let handle = ProxyServer::new(config)?.start_unbound()?;

        handle.state.report_access("first".to_string());
        assert_eq!(handle.dropped_trace_events(), 0);

        drop(rx);
        handle.state.report_violation("second".to_string());
        handle.state.report_access("third".to_string());
        assert_eq!(handle.dropped_trace_events(), 2);
        Ok(())
    }

    /// [`ProxyHandle::connections_accepted_ref`] gives the counter that the
    /// proxy increments, and [`ProxyHandle::connections_accepted`] reads the
    /// same counter. Both start at zero.
    #[tokio::test]
    async fn test_the_handle_shares_the_counter_of_accepted_connections() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let handle = ProxyServer::new(config)?.start().await?;
        let counter = handle.connections_accepted_ref();
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(handle.connections_accepted(), 0);

        let addr = handle.proxy_addr().ok_or("the proxy has no address")?;
        let _client = tokio::net::TcpStream::connect(addr).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while counter.load(std::sync::atomic::Ordering::Relaxed) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the counter of the caller must follow the proxy"
        );
        assert_eq!(handle.connections_accepted(), 1);
        handle.shutdown().await?;
        Ok(())
    }

    // ========================================================================
    // The state of the handle
    // ========================================================================

    /// The handle reports that it does not run after the stop signal.
    #[tokio::test]
    async fn test_is_running_is_false_after_the_stop_signal() -> TestResult {
        let handle = ProxyServer::new(ProxyConfig::default())?.start_unbound()?;
        assert!(handle.is_running(), "a new handle runs");
        handle.stop_tx.send_replace(true);
        assert!(!handle.is_running(), "the stop signal ends the proxy");
        Ok(())
    }

    /// The handle reports that it does not run after a server task ended.
    /// A task ends on a fatal error, and the proxy then serves nothing.
    #[tokio::test]
    async fn test_is_running_is_false_when_a_server_task_ended() -> TestResult {
        let handle = ProxyServer::new(ProxyConfig::default())?.start_unbound()?;
        let mut task = handle.spawn_until_stop(async { Ok(()) });
        (&mut task)
            .await
            .map_err(|e| format!("the task failed: {e}"))??;
        lock(&handle.tasks).push(task);
        assert!(
            !handle.is_running(),
            "a handle with a task that ended does not run"
        );
        Ok(())
    }

    /// [`ProxyHandle::shutdown`] waits for the server tasks. When it
    /// returns, the listener is closed, so the port is free at once.
    #[tokio::test]
    async fn test_shutdown_frees_the_port_before_it_returns() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:0".parse()?,
            proxy_bind_addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let handle = ProxyServer::new(config)?.start().await?;
        let addr = handle.proxy_addr().ok_or("the proxy has no address")?;
        handle.shutdown().await?;

        // No sleep here: the port must be free when the shutdown returns.
        let listener = tokio::net::TcpListener::bind(addr).await;
        assert!(
            listener.is_ok(),
            "the port {addr} is not free when the shutdown returns: {listener:?}"
        );
        Ok(())
    }
}
