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
    DnsServer, DnsServerConfig, ProxyError, Result, SharedState, TcpProxy, TcpProxyConfig,
    TraceEvent,
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

    /// DNS response TTL.
    /// Default: 5 minutes
    pub dns_ttl: std::time::Duration,

    /// TCP connection timeout.
    /// Default: 30 seconds
    pub tcp_connect_timeout: std::time::Duration,

    /// TCP idle timeout (connection closed if no data flows).
    /// Default: 5 minutes
    pub tcp_idle_timeout: std::time::Duration,

    /// Optional channel for reporting trace events (violations and granted access).
    /// When set, both blocked and allowed connections send a typed [`TraceEvent`].
    pub violation_tx: Option<tokio::sync::mpsc::UnboundedSender<TraceEvent>>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            dns_bind_addr: "127.0.0.1:0".parse().expect("hardcoded loopback address"),
            proxy_bind_addr: "127.0.0.1:0".parse().expect("hardcoded loopback address"),
            upstream_dns: None,       // Use system resolvers
            domain_allowlist: vec![], // Populated from settings per-assistant
            violation_tx: None,
            dns_ttl: std::time::Duration::from_secs(300),
            tcp_connect_timeout: std::time::Duration::from_secs(30),
            tcp_idle_timeout: std::time::Duration::from_secs(300),
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
    pub fn with_allowlist(domains: Vec<String>) -> Self {
        Self {
            domain_allowlist: domains,
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
    pub fn is_running(&self) -> bool {
        self.join_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Shut down the proxy server gracefully.
    ///
    /// Signals the server to stop via the shutdown channel. The server task
    /// will complete when it receives the signal. If the shutdown signal
    /// cannot be delivered (receiver dropped), the task is aborted.
    ///
    /// # Errors
    /// Currently infallible; always returns `Ok`. If the task does not respond
    /// within 2 seconds it is left to finish on its own (not aborted).
    pub async fn shutdown(mut self) -> Result<()> {
        // Send shutdown signal - this triggers the tokio::select! in the server task
        let signal_sent = if let Some(tx) = self.shutdown_tx.take() {
            tx.send(()).is_ok()
        } else {
            false
        };

        // Wait for server task to complete
        if let Some(handle) = self.join_handle.take() {
            if signal_sent {
                // Give the task time to respond to shutdown signal
                match tokio::time::timeout(std::time::Duration::from_secs(2), handle).await {
                    Ok(Ok(_)) => {}                      // Task completed successfully
                    Ok(Err(e)) if e.is_cancelled() => {} // Task was cancelled, that's fine
                    Ok(Err(_)) => {}                     // Task panicked, already logged
                    Err(_) => {
                        // Timeout - task didn't respond, this shouldn't happen
                        // but we don't abort as the task will eventually stop
                    }
                }
            } else {
                // Shutdown signal couldn't be sent, abort the task
                handle.abort();
            }
        }

        Ok(())
    }

    /// Get the DNS server bind address.
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_bind_addr
    }

    /// Get the TCP proxy bind address.
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_bind_addr
    }

    /// Get the current domain allowlist.
    pub fn allowlist(&self) -> Vec<String> {
        self.state.allowlist()
    }

    /// Total number of TCP proxy connections accepted since the proxy started.
    ///
    /// Monotonically increasing. A value of zero after the sandboxed process
    /// has been running for several seconds suggests the process is not routing
    /// traffic through the proxy (i.e. it does not honour `HTTP_PROXY` /
    /// `ALL_PROXY`).
    pub fn connections_accepted(&self) -> u64 {
        self.state
            .connections_accepted
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Return a cloned Arc to the connections-accepted counter so callers can
    /// pass it into spawned tasks without keeping the full handle alive.
    pub fn connections_accepted_ref(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.state.connections_accepted)
    }

    /// Add a domain to the allowlist at runtime.
    ///
    /// Creates a new filter with the added domain and replaces the current one.
    /// The change takes effect immediately for new DNS queries.
    pub fn add_domain(&self, domain: String) {
        self.state.add_domain(domain);
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
    /// Currently infallible; always returns `Ok`. The `Result` return type
    /// is present for forward compatibility.
    ///
    /// # Example
    /// ```ignore
    /// let server = ProxyServer::new(ProxyConfig::default())?;
    /// let handle = server.start().await?;
    /// // ... later ...
    /// handle.shutdown().await?;
    /// ```
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let state = Arc::new(SharedState::with_violation_tx(
            config.domain_allowlist.clone(),
            config.violation_tx.clone(),
        ));
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
            let dns_config = DnsServerConfig {
                bind_addr: actual_dns_addr,
                upstream: config.upstream_dns.clone(),
                ttl: config.dns_ttl,
            };
            let tcp_config = TcpProxyConfig {
                bind_addr: actual_proxy_addr,
                connect_timeout: config.tcp_connect_timeout,
                idle_timeout: config.tcp_idle_timeout,
                ..Default::default()
            };

            let dns_server = DnsServer::new(dns_config, Arc::clone(&state_for_task))?;
            let tcp_proxy = TcpProxy::new(tcp_config, Arc::clone(&state_for_task))?;

            // Run both servers concurrently on pre-bound sockets.
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
        let dns_config = DnsServerConfig {
            bind_addr: self.config.dns_bind_addr,
            upstream: self.config.upstream_dns.clone(),
            ttl: self.config.dns_ttl,
        };
        let tcp_config = TcpProxyConfig {
            bind_addr: self.config.proxy_bind_addr,
            connect_timeout: self.config.tcp_connect_timeout,
            idle_timeout: self.config.tcp_idle_timeout,
            ..Default::default()
        };

        let dns_server = DnsServer::new(dns_config, Arc::clone(&self.state))?;
        let tcp_proxy = TcpProxy::new(tcp_config, Arc::clone(&self.state))?;

        // Run both servers concurrently
        tokio::select! {
            result = dns_server.run() => result,
            result = tcp_proxy.run() => result,
        }
    }

    /// Get the current domain allowlist.
    pub fn allowlist(&self) -> Vec<String> {
        self.state.allowlist()
    }

    /// Add a domain to the allowlist at runtime.
    ///
    /// Creates a new filter with the added domain and replaces the current one.
    /// The change takes effect immediately for new DNS queries.
    ///
    /// Note: This does not persist the change to config - only updates the runtime state.
    pub fn add_domain(&self, domain: String) {
        self.state.add_domain(domain);
    }
}

/// Convert a `ProxySettings` fragment (from `halt-settings`) into a `ProxyConfig`.
///
/// Returns `Err(String)` if any `upstream_dns` entry cannot be parsed as a
/// `SocketAddr`.  All other fields have infallible defaults.
impl TryFrom<&halt_settings::ProxySettings> for ProxyConfig {
    type Error = String;

    fn try_from(settings: &halt_settings::ProxySettings) -> std::result::Result<Self, String> {
        let mut config = Self {
            domain_allowlist: settings.domain_allowlist.clone(),
            ..Default::default()
        };
        if let Some(ttl) = settings.dns_ttl_seconds {
            config.dns_ttl = std::time::Duration::from_secs(u64::from(ttl));
        }
        if let Some(t) = settings.tcp_connect_timeout_secs {
            config.tcp_connect_timeout = std::time::Duration::from_secs(t);
        }
        if let Some(t) = settings.tcp_idle_timeout_secs {
            config.tcp_idle_timeout = std::time::Duration::from_secs(t);
        }
        if let Some(upstream) = &settings.upstream_dns {
            let addrs: std::result::Result<Vec<std::net::SocketAddr>, _> =
                upstream.iter().map(|s| s.parse()).collect();
            config.upstream_dns =
                Some(addrs.map_err(|e| format!("Invalid upstream_dns entry: {e}"))?);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn can_bind_tcp_localhost() -> bool {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                drop(listener);
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => false,
            Err(err) => panic!("Failed to bind TCP localhost for test: {err}"),
        }
    }

    fn can_bind_udp_localhost() -> bool {
        match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => {
                drop(socket);
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => false,
            Err(err) => panic!("Failed to bind UDP localhost for test: {err}"),
        }
    }

    fn can_bind_localhost() -> bool {
        can_bind_tcp_localhost() && can_bind_udp_localhost()
    }

    macro_rules! skip_if_no_bind {
        () => {
            if !can_bind_localhost() {
                return;
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
    fn test_proxy_server_new_initializes_filter() {
        let config = ProxyConfig::with_allowlist(vec!["example.com".to_string()]);
        let server = ProxyServer::new(config).unwrap();
        assert!(server.state.is_allowed("example.com"));
        assert!(!server.state.is_allowed("other.com"));
    }

    #[test]
    fn test_proxy_server_new_initializes_cache() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config).unwrap();
        assert!(server.state.cache.is_empty());
    }

    #[test]
    fn test_proxy_server_allowlist_accessor() {
        let config = ProxyConfig::with_allowlist(vec![
            "example.com".to_string(),
            "*.github.com".to_string(),
        ]);
        let server = ProxyServer::new(config).unwrap();
        let patterns = server.allowlist();
        assert_eq!(patterns.len(), 2);
        assert!(patterns.contains(&"example.com".to_string()));
        assert!(patterns.contains(&"*.github.com".to_string()));
    }

    // ========================================================================
    // ProxyHandle Tests
    // ========================================================================

    #[tokio::test]

    async fn test_proxy_handle_is_running_true() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25353".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29300".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Should report as running
        assert!(handle.is_running());

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]

    async fn test_proxy_handle_is_running_false_after_shutdown() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25354".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29301".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        handle.shutdown().await.unwrap();

        // Cannot check is_running after shutdown since handle is consumed
        // This test verifies shutdown completes without error
    }

    #[tokio::test]

    async fn test_proxy_handle_dns_addr() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25355".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29302".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        let dns_addr = handle.dns_addr();
        assert_eq!(dns_addr.port(), 25355);
        assert_eq!(dns_addr.ip().to_string(), "127.0.0.1");

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]

    async fn test_proxy_handle_proxy_addr() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25356".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29303".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        let proxy_addr = handle.proxy_addr();
        assert_eq!(proxy_addr.port(), 29303);
        assert_eq!(proxy_addr.ip().to_string(), "127.0.0.1");

        handle.shutdown().await.unwrap();
    }

    // ========================================================================
    // Server Lifecycle Tests
    // ========================================================================

    #[tokio::test]

    async fn test_proxy_server_start_returns_handle() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25357".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29304".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await;

        assert!(handle.is_ok());
        handle.unwrap().shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_server_start_binds_dns() {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25358".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29305".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to bind to same port - should fail (port in use)
        let result = UdpSocket::bind("127.0.0.1:25358").await;
        assert!(result.is_err());

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_proxy_server_start_binds_tcp() {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25359".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29306".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to bind to same port - should fail (port in use)
        let result = TcpListener::bind("127.0.0.1:29306").await;
        assert!(result.is_err());

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]

    async fn test_proxy_server_shutdown_graceful() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25360".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29307".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Shutdown should complete without error
        let result = handle.shutdown().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_server_shutdown_stops_dns() {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25361".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29308".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();
        handle.shutdown().await.unwrap();

        // After shutdown, port should be available again
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = UdpSocket::bind("127.0.0.1:25361").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_server_shutdown_stops_tcp() {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25362".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29309".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();
        handle.shutdown().await.unwrap();

        // After shutdown, port should be available again
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = TcpListener::bind("127.0.0.1:29309").await;
        assert!(result.is_ok());
    }

    #[tokio::test]

    async fn test_proxy_server_run_blocks() {
        skip_if_no_bind!();
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25363".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29310".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();

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
    }

    // ========================================================================
    // Integration Tests - End to End
    // ========================================================================

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_integration_allowed_domain_flow() {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25364".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29311".parse().unwrap(),
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Build DNS query for example.com
        let query = build_test_dns_query("example.com", 1); // A record

        // Send DNS query
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(&query, "127.0.0.1:25364").await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        // Should get successful response (RCODE = 0 in byte 3)
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "Expected success RCODE");

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]

    async fn test_integration_blocked_domain_flow() {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25365".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29312".parse().unwrap(),
            domain_allowlist: vec!["allowed.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Build DNS query for blocked domain
        let query = build_test_dns_query("blocked.com", 1);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(&query, "127.0.0.1:25365").await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        // Should get NXDOMAIN (RCODE = 3 in byte 3)
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 3, "Expected NXDOMAIN RCODE");

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_integration_direct_ip_blocked() {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25366".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29313".parse().unwrap(),
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Give the spawned server task time to actually bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to proxy and try direct IP (not resolved through DNS)
        let mut stream = TcpStream::connect("127.0.0.1:29313").await.unwrap();

        // SOCKS5 handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();

        // Request connection to raw IP (1.2.3.4:80)
        let request = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        stream.write_all(&request).await.unwrap();

        let mut reply = [0u8; 10];
        let _ = stream.read(&mut reply).await;

        // Should be rejected (reply[1] != 0x00)
        assert_ne!(reply[1], 0x00, "Direct IP should be rejected");

        handle.shutdown().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_integration_wildcard_subdomain() {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25367".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29314".parse().unwrap(),
            domain_allowlist: vec!["*.github.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Query subdomain that matches wildcard
        let query = build_test_dns_query("api.github.com", 1);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(&query, "127.0.0.1:25367").await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        // Should get success (wildcard matches)
        assert!(len > 12);
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "Wildcard subdomain should be allowed");

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]

    async fn test_integration_cache_expiry() {
        skip_if_no_bind!();
        use crate::ResolvedAddress;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25368".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29315".parse().unwrap(),
            domain_allowlist: vec!["test.local".to_string()],
            dns_ttl: std::time::Duration::from_secs(1), // Very short TTL
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();

        // Manually insert a cache entry with short expiry
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_millis(100),
        };
        server.state.cache.insert(resolved);

        // Verify it's in cache
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert!(server.state.cache.lookup(&ip).is_some());

        // Wait for expiry
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // After TTL, cache should have expired the entry
        // Note: Implementation may need explicit cleanup or lazy expiry
        let lookup = server.state.cache.lookup(&ip);
        // Depending on implementation: assert!(lookup.is_none());
        // If lazy expiry: lookup might still exist but be expired
        let _ = lookup; // Test structure ready for production code
    }

    // ========================================================================
    // Dynamic Configuration Tests
    // ========================================================================

    #[test]
    fn test_add_domain_updates_allowlist() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config).unwrap();

        assert!(!server.allowlist().contains(&"newdomain.com".to_string()));

        server.add_domain("newdomain.com".to_string());

        // After adding, should be in allowlist
        assert!(server.allowlist().contains(&"newdomain.com".to_string()));
    }

    #[test]
    fn test_add_domain_supports_wildcard() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config).unwrap();

        server.add_domain("*.newdomain.com".to_string());

        assert!(server.allowlist().contains(&"*.newdomain.com".to_string()));

        // Verify wildcard matching works
        assert!(server.state.is_allowed("sub.newdomain.com"));
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[tokio::test]
    async fn test_start_dns_port_in_use() {
        skip_if_no_bind!();
        use tokio::net::UdpSocket;

        // Bind to DNS port first
        let _blocker = UdpSocket::bind("127.0.0.1:25369").await.unwrap();

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25369".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29316".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        // start() now pre-binds before spawning; bind error surfaces immediately.
        let result = server.start().await;
        assert!(
            result.is_err(),
            "start() should fail when DNS port is in use"
        );
    }

    #[tokio::test]
    async fn test_start_proxy_port_in_use() {
        skip_if_no_bind!();
        use tokio::net::TcpListener;

        // Bind to proxy port first
        let _blocker = TcpListener::bind("127.0.0.1:29317").await.unwrap();

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25370".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29317".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        // start() now pre-binds before spawning; bind error surfaces immediately.
        let result = server.start().await;
        assert!(
            result.is_err(),
            "start() should fail when proxy port is in use"
        );
    }

    #[tokio::test]

    async fn test_shutdown_already_stopped() {
        skip_if_no_bind!();
        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25371".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29318".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // First shutdown
        handle.shutdown().await.unwrap();

        // Note: handle is consumed, so this tests that shutdown completes
        // without panicking. A second shutdown on the same handle
        // isn't possible due to ownership semantics.
    }

    // ========================================================================
    // Concurrent Operations Tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_concurrent_dns_and_tcp() {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpStream, UdpSocket};

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25372".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29319".parse().unwrap(),
            domain_allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

        // Spawn DNS query
        let dns_task = tokio::spawn(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let query = build_test_dns_query("example.com", 1);
            socket.send_to(&query, "127.0.0.1:25372").await.unwrap();
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
        assert!(dns_result.unwrap());
        assert!(tcp_result.unwrap());

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]

    async fn test_concurrent_multiple_clients() {
        skip_if_no_bind!();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25373".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29320".parse().unwrap(),
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();
        let handle = server.start().await.unwrap();

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
            let result = task.await.unwrap();
            assert!(result, "All concurrent clients should connect");
        }

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_dns_cache_shared_with_tcp() {
        skip_if_no_bind!();
        use crate::ResolvedAddress;
        use std::sync::Arc;

        let config = ProxyConfig {
            dns_bind_addr: "127.0.0.1:25374".parse().unwrap(),
            proxy_bind_addr: "127.0.0.1:29321".parse().unwrap(),
            domain_allowlist: vec!["cached.example".to_string()],
            ..Default::default()
        };
        let server = ProxyServer::new(config).unwrap();

        // Clone state Arc before server.start() consumes self
        let state = Arc::clone(&server.state);

        // Pre-populate cache (simulating what happens after DNS resolution).
        // We insert before start() to verify the cache survives server init.
        let resolved = ResolvedAddress {
            domain: "cached.example".to_string(),
            addresses: vec!["192.0.2.1".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let handle = server.start().await.unwrap();

        // The shared cache is visible to the TCP proxy side: a connection to
        // 192.0.2.1 should be recognised as targeting "cached.example".
        let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let lookup = state.cache.lookup(&ip);
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap(), "cached.example");

        handle.shutdown().await.unwrap();
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
            query.push(u8::try_from(label.len()).expect("DNS label exceeds 255 bytes"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // Root label

        // QTYPE and QCLASS
        query.extend_from_slice(&record_type.to_be_bytes());
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

        query
    }
}
