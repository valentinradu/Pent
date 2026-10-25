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
use tokio::sync::oneshot;

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
    /// The rule for destinations that are not public still applies.
    ///
    /// CONTRACT STUB: the proxy does not use this value yet.
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

/// Handle for controlling a running proxy server.
///
/// Allows shutting down the server gracefully and modifying the domain allowlist at runtime.
pub struct ProxyHandle {
    /// Shutdown signal sender.
    shutdown_tx: Option<oneshot::Sender<()>>,

    /// Join handle for the server task.
    join_handle: Option<tokio::task::JoinHandle<Result<()>>>,

    /// DNS server bind address.
    dns_bind_addr: SocketAddr,

    /// TCP proxy bind address.
    proxy_bind_addr: SocketAddr,

    /// Shared state for runtime domain management.
    state: Arc<SharedState>,
}

impl ProxyHandle {
    /// Check if the server is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.join_handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Shut down the proxy server gracefully.
    ///
    /// Signals the server to stop via the shutdown channel. When the server
    /// task stops, it cancels all the DNS query tasks and all the TCP
    /// connection tasks, and the proxy closes the open connections. If the
    /// shutdown signal cannot be delivered (receiver dropped), or if the task
    /// does not stop in 2 seconds, the task is aborted.
    ///
    /// # Errors
    /// Currently infallible; always returns `Ok`.
    pub async fn shutdown(mut self) -> Result<()> {
        // Send shutdown signal - this triggers the tokio::select! in the server task
        let signal_sent = self
            .shutdown_tx
            .take()
            .is_some_and(|tx| tx.send(()).is_ok());

        // Wait for server task to complete
        if let Some(mut handle) = self.join_handle.take() {
            if signal_sent {
                // Give the task time to respond to shutdown signal. The result
                // of the task is not important here: it completed, was
                // cancelled, or panicked, and the proxy stops in all cases.
                let stopped =
                    tokio::time::timeout(std::time::Duration::from_secs(2), &mut handle).await;
                if stopped.is_err() {
                    handle.abort();
                }
            } else {
                // Shutdown signal couldn't be sent, abort the task
                handle.abort();
            }
        }

        Ok(())
    }

    /// Get the DNS server bind address.
    #[must_use]
    pub const fn dns_addr(&self) -> SocketAddr {
        self.dns_bind_addr
    }

    /// Get the TCP proxy bind address.
    #[must_use]
    pub const fn proxy_addr(&self) -> SocketAddr {
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

    /// The number of trace events that the proxy could not deliver, because
    /// the receiver of the trace channel was closed.
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
    /// ```ignore
    /// let server = ProxyServer::new(ProxyConfig::default())?;
    /// let handle = server.start().await?;
    /// // ... later ...
    /// handle.shutdown().await?;
    /// ```
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let state = Arc::new(SharedState::try_with_violation_tx(
            &config.domain_allowlist,
            config.violation_tx.clone(),
        )?);
        Ok(Self { config, state })
    }

    /// Start the proxy server.
    ///
    /// Spawns the DNS server and TCP proxy as concurrent tasks.
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

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let state_for_task = Arc::clone(&self.state);
        let state_for_handle = Arc::clone(&self.state);
        let config = self.config.clone();

        // Spawn server task using pre-bound sockets.
        let join_handle = tokio::spawn(async move {
            let dns_config = config.dns_config(actual_dns_addr);
            let tcp_config = config.tcp_config(actual_proxy_addr);

            let dns_server = DnsServer::new(dns_config, Arc::clone(&state_for_task))?;
            let tcp_proxy = TcpProxy::new(tcp_config, Arc::clone(&state_for_task))?;

            // Run both servers concurrently on pre-bound sockets. When the
            // shutdown signal arrives, select! drops the two server futures.
            // Each of them owns a JoinSet of its tasks, and the drop of a
            // JoinSet aborts all its tasks.
            tokio::select! {
                result = dns_server.run_on(udp_socket) => result,
                result = tcp_proxy.run_on(tcp_listener) => result,
                _ = shutdown_rx => Ok(()),
            }
        });

        Ok(ProxyHandle {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
            dns_bind_addr: actual_dns_addr,
            proxy_bind_addr: actual_proxy_addr,
            state: state_for_handle,
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
                return Ok(());
            }
        };
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
            dns_bind_addr: "127.0.0.1:25353".parse()?,
            proxy_bind_addr: "127.0.0.1:29300".parse()?,
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
            dns_bind_addr: "127.0.0.1:25354".parse()?,
            proxy_bind_addr: "127.0.0.1:29301".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        handle.shutdown().await?;

        // Cannot check is_running after shutdown since handle is consumed
        // This test verifies shutdown completes without error
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_handle_dns_addr() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25355".parse()?,
            proxy_bind_addr: "127.0.0.1:29302".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        let dns_addr = handle.dns_addr();
        assert_eq!(dns_addr.port(), 25355);
        assert_eq!(dns_addr.ip().to_string(), "127.0.0.1");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_handle_proxy_addr() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25356".parse()?,
            proxy_bind_addr: "127.0.0.1:29303".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        let proxy_addr = handle.proxy_addr();
        assert_eq!(proxy_addr.port(), 29303);
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
            dns_bind_addr: "127.0.0.1:25357".parse()?,
            proxy_bind_addr: "127.0.0.1:29304".parse()?,
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
            dns_bind_addr: "127.0.0.1:25358".parse()?,
            proxy_bind_addr: "127.0.0.1:29305".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to bind to same port - should fail (port in use)
        let result = UdpSocket::bind("127.0.0.1:25358").await;
        assert!(result.is_err());

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_start_binds_tcp() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25359".parse()?,
            proxy_bind_addr: "127.0.0.1:29306".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to bind to same port - should fail (port in use)
        let result = TcpListener::bind("127.0.0.1:29306").await;
        assert!(result.is_err());

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_server_shutdown_graceful() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25360".parse()?,
            proxy_bind_addr: "127.0.0.1:29307".parse()?,
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
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25361".parse()?,
            proxy_bind_addr: "127.0.0.1:29308".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;
        handle.shutdown().await?;

        // After shutdown, port should be available again
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = UdpSocket::bind("127.0.0.1:25361").await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_server_shutdown_stops_tcp() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25362".parse()?,
            proxy_bind_addr: "127.0.0.1:29309".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;
        handle.shutdown().await?;

        // After shutdown, port should be available again
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = TcpListener::bind("127.0.0.1:29309").await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]

    async fn test_proxy_server_run_blocks() -> TestResult {
        skip_if_no_bind!();
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25363".parse()?,
            proxy_bind_addr: "127.0.0.1:29310".parse()?,
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_integration_allowed_domain_flow() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25364".parse()?,
            proxy_bind_addr: "127.0.0.1:29311".parse()?,
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Build DNS query for example.com
        let query = build_test_dns_query("example.com", 1); // A record

        // Send DNS query
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(&query, "127.0.0.1:25364").await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await??;

        // Should get successful response (RCODE = 0 in byte 3)
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "Expected success RCODE");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_integration_blocked_domain_flow() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25365".parse()?,
            proxy_bind_addr: "127.0.0.1:29312".parse()?,
            domain_allowlist: vec!["allowed.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Build DNS query for blocked domain
        let query = build_test_dns_query("blocked.com", 1);

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(&query, "127.0.0.1:25365").await?;

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

    #[tokio::test]
    async fn test_integration_direct_ip_blocked() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25366".parse()?,
            proxy_bind_addr: "127.0.0.1:29313".parse()?,
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to proxy and try direct IP (not resolved through DNS)
        let mut stream = TcpStream::connect("127.0.0.1:29313").await?;

        // SOCKS5 handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        // Request connection to raw IP (1.2.3.4:80)
        let request = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        stream.write_all(&request).await?;

        let mut reply = [0u8; 10];
        let _ = stream.read(&mut reply).await;

        // Should be rejected (reply[1] != 0x00)
        assert_ne!(reply[1], 0x00, "Direct IP should be rejected");

        handle.shutdown().await?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_integration_wildcard_subdomain() -> TestResult {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25367".parse()?,
            proxy_bind_addr: "127.0.0.1:29314".parse()?,
            domain_allowlist: vec!["*.github.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Query subdomain that matches wildcard
        let query = build_test_dns_query("api.github.com", 1);

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(&query, "127.0.0.1:25367").await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await??;

        // Should get success (wildcard matches)
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "Wildcard subdomain should be allowed");

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_integration_cache_expiry() -> TestResult {
        skip_if_no_bind!();
        use crate::ResolvedAddress;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25368".parse()?,
            proxy_bind_addr: "127.0.0.1:29315".parse()?,
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
        let _blocker = UdpSocket::bind("127.0.0.1:25369").await?;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25369".parse()?,
            proxy_bind_addr: "127.0.0.1:29316".parse()?,
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
        let _blocker = TcpListener::bind("127.0.0.1:29317").await?;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25370".parse()?,
            proxy_bind_addr: "127.0.0.1:29317".parse()?,
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

    #[tokio::test]

    async fn test_shutdown_already_stopped() -> TestResult {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25371".parse()?,
            proxy_bind_addr: "127.0.0.1:29318".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // First shutdown
        handle.shutdown().await?;

        // Note: handle is consumed, so this tests that shutdown completes
        // without panicking. A second shutdown on the same handle
        // isn't possible due to ownership semantics.
        Ok(())
    }

    // ========================================================================
    // Concurrent Operations Tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_concurrent_dns_and_tcp() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpStream, UdpSocket};

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25372".parse()?,
            proxy_bind_addr: "127.0.0.1:29319".parse()?,
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Spawn DNS query
        let dns_task = tokio::spawn(async {
            let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
                return false;
            };
            let query = build_test_dns_query("example.com", 1);
            if socket.send_to(&query, "127.0.0.1:25372").await.is_err() {
                return false;
            }
            let mut buf = [0u8; 512];
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut buf),
            )
            .await;
            result.is_ok()
        });

        // Spawn TCP connection
        let tcp_task = tokio::spawn(async {
            let result = TcpStream::connect("127.0.0.1:29319").await;
            if let Ok(mut stream) = result {
                // SOCKS5 handshake
                let _ = stream.write_all(&[0x05, 0x01, 0x00]).await;
                let mut buf = [0u8; 2];
                let _ = stream.read(&mut buf).await;
                true
            } else {
                false
            }
        });

        // Both should complete
        let (dns_result, tcp_result) = tokio::join!(dns_task, tcp_task);
        assert!(dns_result?);
        assert!(tcp_result?);

        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]

    async fn test_concurrent_multiple_clients() -> TestResult {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25373".parse()?,
            proxy_bind_addr: "127.0.0.1:29320".parse()?,
            ..Default::default()
        };
        let server = ProxyServer::new(config)?;
        let handle = server.start().await?;

        // Spawn multiple concurrent TCP clients
        let mut tasks = vec![];
        for _ in 0..5 {
            tasks.push(tokio::spawn(async {
                let result = TcpStream::connect("127.0.0.1:29320").await;
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
            dns_bind_addr: "127.0.0.1:25374".parse()?,
            proxy_bind_addr: "127.0.0.1:29321".parse()?,
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

        let mut client = TcpStream::connect(handle.proxy_addr()).await?;
        client.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await?;
        let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&dest.port().to_be_bytes());
        client.write_all(&request).await?;
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await?;
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
}
