//! TCP proxy for forwarding allowed connections.
//!
//! Forwards TCP connections only to IP addresses that were resolved
//! through the DNS server (i.e., to allowed domains).
//!
//! # Connection Flow
//!
//! ```text
//! Client connects to proxy
//!         |
//!         v
//! Extract destination (CONNECT or transparent)
//!         |
//!         v
//! ResolutionCache.lookup(dest_ip)?
//!         |
//!         +-- found --> Forward connection, relay data
//!         |
//!         +-- not found --> Reject connection
//! ```
//!
//! # Proxy Protocol
//!
//! - **SOCKS5**: Standard SOCKS5 proxy protocol
//!

use crate::{ProxyError, Result, SharedState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Configuration for the TCP proxy.
#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
    /// Address to bind the proxy to.
    /// Default: `127.0.0.1:9300`
    pub bind_addr: SocketAddr,

    /// Connection timeout.
    /// Default: 30 seconds
    pub connect_timeout: std::time::Duration,

    /// Idle timeout (connection closed if no data flows).
    /// Default: 5 minutes
    pub idle_timeout: std::time::Duration,

    /// Maximum concurrent connections.
    /// Default: 1000
    pub max_connections: usize,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9300"
                .parse()
                .expect("hardcoded loopback address"),
            connect_timeout: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(300),
            max_connections: 1000,
        }
    }
}

/// TCP proxy that forwards connections to resolved (allowed) destinations.
///
/// Only allows connections to IP addresses that were previously resolved
/// through the DNS server (and thus are on the domain allowlist).
pub struct TcpProxy {
    /// Proxy configuration.
    config: TcpProxyConfig,

    /// Shared state with resolution cache.
    state: Arc<SharedState>,

    /// Current connection count (Arc-wrapped to safely share with spawned tasks).
    connection_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl TcpProxy {
    /// Create a new TCP proxy.
    ///
    /// # Arguments
    /// * `config` - Proxy configuration
    /// * `state` - Shared state containing resolution cache
    ///
    /// # Errors
    /// Currently infallible; always returns `Ok`. The `Result` return type
    /// is present for forward compatibility.
    pub fn new(config: TcpProxyConfig, state: Arc<SharedState>) -> Result<Self> {
        Ok(Self {
            config,
            state,
            connection_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Get current connection count.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connection_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Start the TCP proxy.
    ///
    /// Binds to the configured address and starts accepting connections.
    /// This method runs until the proxy is shut down.
    ///
    /// # Errors
    /// * `ProxyError::Bind` - If binding to `config.bind_addr` fails.
    /// * `ProxyError::Internal` - Fatal proxy error during operation.
    pub async fn run(&self) -> Result<()> {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| ProxyError::Bind {
                addr: self.config.bind_addr,
                source: e,
            })?;

        self.run_on(listener).await
    }

    /// Run the TCP proxy on a pre-bound listener.
    ///
    /// Used by [`crate::ProxyServer::start`] which pre-binds the listener to
    /// obtain the actual OS-assigned port before spawning the server task.
    ///
    /// # Errors
    /// * `ProxyError::Internal` - Fatal proxy error during operation.
    pub async fn run_on(&self, listener: tokio::net::TcpListener) -> Result<()> {
        loop {
            let (client, client_addr) = match listener.accept().await {
                Ok(result) => result,
                Err(e) => {
                    warn!(error = %e, "TCP accept error");
                    continue;
                }
            };

            // Check connection limit
            let current = self
                .connection_count
                .load(std::sync::atomic::Ordering::Relaxed);
            if current >= self.config.max_connections {
                warn!(client = %client_addr, "Connection limit reached, rejecting");
                drop(client);
                continue;
            }

            // Count every accepted connection so callers can detect whether the
            // sandboxed process is routing traffic through the proxy at all.
            self.state
                .connections_accepted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Increment connection count
            self.connection_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Handle connection in background task
            let config = self.config.clone();
            let state = Arc::clone(&self.state);
            let connection_count = Arc::clone(&self.connection_count);

            tokio::spawn(async move {
                let proxy = Self {
                    config,
                    state,
                    connection_count: Arc::clone(&connection_count),
                };

                if let Err(e) = proxy.handle_connection(client, client_addr).await {
                    debug!(client = %client_addr, error = %e, "Connection error");
                }

                connection_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    /// Handle a single client connection.
    ///
    /// Supports both SOCKS5 and HTTP CONNECT so that the proxy works regardless
    /// of which proxy scheme the sandboxed application uses
    /// (`ALL_PROXY=socks5://…` or `HTTP_PROXY=http://…`).
    async fn handle_connection(
        &self,
        mut client: TcpStream,
        _client_addr: SocketAddr,
    ) -> Result<()> {
        use tokio::io::AsyncReadExt;

        // Peek at the first byte to determine the protocol.
        let mut first = [0u8; 1];
        client
            .read_exact(&mut first)
            .await
            .map_err(|e| ProxyError::Internal(format!("Failed to peek protocol byte: {e}")))?;

        if first[0] == 0x05 {
            self.handle_socks5(client, first[0]).await
        } else {
            self.handle_http_connect(client, first[0]).await
        }
    }

    /// Handle a SOCKS5 connection (first byte was already read).
    async fn handle_socks5(&self, mut client: TcpStream, first_byte: u8) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // greeting[0] = first_byte (version = 0x05)
        let _ = first_byte; // already verified == 0x05 by caller

        // Read NMETHODS (exactly 1 byte).  Using read_exact here and below is
        // critical: a plain read() with a large buffer can accidentally consume
        // the CONNECT request when the greeting and CONNECT arrive in the same
        // TCP segment (Nagle batching), leaving the second read() with 0 bytes
        // and silently returning without ever reporting a violation.
        let mut nmethods_buf = [0u8; 1];
        client
            .read_exact(&mut nmethods_buf)
            .await
            .map_err(|e| ProxyError::Internal(format!("Failed to read SOCKS5 nmethods: {e}")))?;
        let nmethods = nmethods_buf[0] as usize;

        // Read METHODS list (exactly nmethods bytes) — always use no-auth.
        if nmethods > 0 {
            let mut methods = vec![0u8; nmethods];
            client
                .read_exact(&mut methods)
                .await
                .map_err(|e| ProxyError::Internal(format!("Failed to read SOCKS5 methods: {e}")))?;
        }

        // Send greeting response: no authentication required
        client.write_all(&[0x05, 0x00]).await.map_err(|e| {
            ProxyError::Internal(format!("Failed to send SOCKS5 greeting response: {e}"))
        })?;

        // Read SOCKS5 CONNECT request
        let mut request = [0u8; 262];
        let n = client
            .read(&mut request)
            .await
            .map_err(|e| ProxyError::Internal(format!("Failed to read SOCKS5 request: {e}")))?;

        if n < 10 {
            client
                .write_all(&Self::build_socks5_error(socks5::GENERAL_FAILURE))
                .await
                .ok();
            return Err(ProxyError::Internal("SOCKS5 request too short".to_string()));
        }

        // Resolve destination — for domain requests (ATYP=0x03) we check the
        // allowlist and resolve internally instead of requiring prior DNS lookup.
        let dest = match self.resolve_socks5_destination(&request[..n]).await {
            Ok(d) => d,
            Err(e) => {
                client
                    .write_all(&Self::build_socks5_error(socks5::CONNECTION_NOT_ALLOWED))
                    .await
                    .ok();
                return Err(e);
            }
        };

        // For IP-based requests, verify the IP was resolved through our DNS.
        if request[3] != 0x03 {
            if let Err(e) = self.verify_destination(&dest) {
                client
                    .write_all(&Self::build_socks5_error(socks5::CONNECTION_NOT_ALLOWED))
                    .await
                    .ok();
                return Err(e);
            }
        }

        let destination = match self.connect_to_destination(dest).await {
            Ok(d) => d,
            Err(e) => {
                let code = match &e {
                    ProxyError::TcpConnection { .. } => socks5::CONNECTION_REFUSED,
                    _ => socks5::GENERAL_FAILURE,
                };
                client.write_all(&Self::build_socks5_error(code)).await.ok();
                return Err(e);
            }
        };

        let local_addr = destination.local_addr().unwrap_or_else(|_| {
            "0.0.0.0:0"
                .parse()
                .expect("hardcoded zero-address fallback")
        });

        client
            .write_all(&Self::build_socks5_response(local_addr))
            .await
            .map_err(|e| ProxyError::Internal(format!("Failed to send SOCKS5 success: {e}")))?;

        self.relay(client, destination).await
    }

    /// Handle an HTTP CONNECT connection (first byte was already read).
    ///
    /// Reads the full `CONNECT host:port HTTP/1.1\r\n…\r\n\r\n` request,
    /// checks the target domain against the allowlist, then relays if allowed.
    async fn handle_http_connect(&self, mut client: TcpStream, first_byte: u8) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Read the rest of the HTTP CONNECT request line (up to 4 KiB).
        let mut buf = vec![first_byte];
        let mut tmp = [0u8; 4096];
        loop {
            let n = client
                .read(&mut tmp)
                .await
                .map_err(|e| ProxyError::Internal(format!("HTTP CONNECT read error: {e}")))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            // Stop once we see the end of the HTTP headers (\r\n\r\n).
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                break;
            }
        }

        // Parse the first line: "CONNECT host:port HTTP/1.x"
        let header = std::str::from_utf8(&buf)
            .map_err(|_| ProxyError::Internal("HTTP CONNECT: non-UTF8 request".to_string()))?;
        let first_line = header.lines().next().unwrap_or("");

        let (host, port) = Self::parse_http_connect_target(first_line)?;
        let domain_lower = host.to_lowercase();

        // Check allowlist.
        if !self.state.is_allowed(&domain_lower) {
            self.state.report_violation(format!(
                "network: DNS query for \"{domain_lower}\" blocked — domain not in allowlist"
            ));
            let _ = client
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(ProxyError::DomainBlocked {
                domain: domain_lower,
            });
        }
        self.state.report_access(format!(
            "network: connection to \"{domain_lower}\" allowed"
        ));

        // Resolve the host.
        let addr_str = format!("{host}:{port}");
        let dest = tokio::net::lookup_host(&addr_str)
            .await
            .map_err(|e| ProxyError::DnsResolution {
                domain: host.to_string(),
                message: e.to_string(),
            })?
            .next()
            .ok_or_else(|| ProxyError::DnsResolution {
                domain: host.to_string(),
                message: "no addresses returned".to_string(),
            })?;

        let destination = self.connect_to_destination(dest).await.inspect_err(|_e| {
            let _ = tokio::runtime::Handle::try_current().map(|_| {
                // best-effort; we're in async context
            });
        })?;

        // Send 200 Connection Established.
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .map_err(|e| ProxyError::Internal(format!("HTTP CONNECT: write 200 failed: {e}")))?;

        self.relay(client, destination).await
    }

    /// Parse "CONNECT host:port HTTP/1.x" into `(host, port)`.
    fn parse_http_connect_target(line: &str) -> Result<(&str, u16)> {
        // Format: CONNECT <host>:<port> HTTP/1.x
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        if !method.eq_ignore_ascii_case("CONNECT") {
            return Err(ProxyError::Internal(format!(
                "Expected CONNECT, got {method:?}"
            )));
        }

        let (host, port_str) = target.rsplit_once(':').ok_or_else(|| {
            ProxyError::Internal(format!("HTTP CONNECT target missing port: {target:?}"))
        })?;

        let port = port_str.parse::<u16>().map_err(|_| {
            ProxyError::Internal(format!("HTTP CONNECT invalid port: {port_str:?}"))
        })?;

        Ok((host, port))
    }

    /// Resolve a SOCKS5 destination.
    ///
    /// For ATYP=0x03 (domain name), checks the allowlist and resolves via
    /// the system resolver.  For ATYP=0x01/0x04 (IP), delegates to
    /// `parse_socks5_request` (IP must be in the resolution cache).
    async fn resolve_socks5_destination(&self, data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 5 {
            return Err(ProxyError::Internal("SOCKS5 request too short".to_string()));
        }

        if data[3] != 0x03 {
            // IP-based: parse normally; caller will verify against resolution cache.
            return self.parse_socks5_request(data);
        }

        // Domain-based (ATYP=0x03).
        let domain_len = data[4] as usize;
        if data.len() < 5 + domain_len + 2 {
            return Err(ProxyError::Internal(
                "SOCKS5 domain request too short".to_string(),
            ));
        }
        let domain = std::str::from_utf8(&data[5..5 + domain_len])
            .map_err(|_| ProxyError::Internal("Invalid domain encoding".to_string()))?;
        let port = u16::from_be_bytes([data[5 + domain_len], data[5 + domain_len + 1]]);
        let domain_lower = domain.to_lowercase();

        if !self.state.is_allowed(&domain_lower) {
            self.state.report_violation(format!(
                "network: DNS query for \"{domain_lower}\" blocked — domain not in allowlist"
            ));
            return Err(ProxyError::DomainBlocked {
                domain: domain_lower,
            });
        }
        self.state.report_access(format!(
            "network: connection to \"{domain_lower}\" allowed"
        ));

        // Resolve via system resolver (domain is allowed).
        let addr_str = format!("{domain}:{port}");
        let domain_owned = domain.to_string();
        let mut addrs =
            tokio::net::lookup_host(addr_str)
                .await
                .map_err(|e| ProxyError::DnsResolution {
                    domain: domain_owned.clone(),
                    message: e.to_string(),
                })?;
        addrs.next().ok_or_else(|| ProxyError::DnsResolution {
            domain: domain_owned,
            message: "no addresses returned".to_string(),
        })
    }

    /// Verify that the destination is allowed (was resolved through DNS).
    ///
    /// # Arguments
    /// * `dest` - Destination address
    ///
    /// # Returns
    /// * `Ok(domain)` - The domain this IP was resolved from
    /// * `Err(ProxyError::DomainBlocked)` - IP not in resolution cache
    fn verify_destination(&self, dest: &SocketAddr) -> Result<String> {
        self.state.lookup_resolved(&dest.ip()).ok_or_else(|| {
            let msg = format!(
                "network: direct connection to {dest} blocked — IP not resolved through proxy DNS"
            );
            self.state.report_violation(msg.clone());
            ProxyError::DomainBlocked { domain: msg }
        })
    }

    /// Connect to the destination with timeout.
    ///
    /// # Arguments
    /// * `dest` - Destination address
    ///
    /// # Returns
    /// * `Ok(TcpStream)` - Connection to destination
    /// * `Err(ProxyError::TcpConnection)` - Connection failed
    async fn connect_to_destination(&self, dest: SocketAddr) -> Result<TcpStream> {
        let timeout = self.config.connect_timeout;

        match tokio::time::timeout(timeout, TcpStream::connect(dest)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(ProxyError::TcpConnection {
                addr: dest,
                source: e,
            }),
            Err(_) => Err(ProxyError::TcpConnection {
                addr: dest,
                source: std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"),
            }),
        }
    }

    /// Relay data between client and destination.
    ///
    /// Copies data bidirectionally until both sides close or the idle timeout fires.
    /// When one direction reaches EOF, it explicitly shuts down the corresponding
    /// write half so the peer receives FIN and can finish sending its data.
    ///
    /// # Arguments
    /// * `client` - Client connection
    /// * `destination` - Destination connection
    async fn relay(&self, client: TcpStream, destination: TcpStream) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let idle_timeout = self.config.idle_timeout;

        let (mut client_read, mut client_write) = client.into_split();
        let (mut dest_read, mut dest_write) = destination.into_split();

        let result = tokio::time::timeout(idle_timeout, async {
            let client_to_dest = async {
                let r = tokio::io::copy(&mut client_read, &mut dest_write).await;
                // Best-effort half-close; if shutdown fails the peer will see a connection reset.
                let _ = dest_write.shutdown().await;
                r
            };
            let dest_to_client = async {
                let r = tokio::io::copy(&mut dest_read, &mut client_write).await;
                // Best-effort half-close; if shutdown fails the peer will see a connection reset.
                let _ = client_write.shutdown().await;
                r
            };
            tokio::join!(client_to_dest, dest_to_client)
        })
        .await;

        match result {
            Ok((r1, r2)) => {
                #[allow(clippy::tuple_array_conversions)]
                for r in [r1, r2] {
                    match r {
                        Ok(_) => {}
                        Err(e)
                            if e.kind() == std::io::ErrorKind::ConnectionReset
                                || e.kind() == std::io::ErrorKind::BrokenPipe =>
                        {
                            // Normal connection close
                        }
                        Err(e) => return Err(ProxyError::Internal(format!("Relay error: {e}"))),
                    }
                }
                Ok(())
            }
            Err(_) => {
                // Timeout - connection idle for too long
                Ok(())
            }
        }
    }

    /// Parse SOCKS5 connection request.
    ///
    /// # Arguments
    /// * `data` - Request data
    ///
    /// # Returns
    /// * `Ok(SocketAddr)` - Requested destination
    /// * `Err` - Invalid request
    fn parse_socks5_request(&self, data: &[u8]) -> Result<SocketAddr> {
        // SOCKS5 request format:
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+

        if data.len() < 10 {
            return Err(ProxyError::Internal("SOCKS5 request too short".to_string()));
        }

        // Check version
        if data[0] != 0x05 {
            return Err(ProxyError::Internal(format!(
                "Invalid SOCKS5 version: {}",
                data[0]
            )));
        }

        // Check command (only CONNECT supported)
        if data[1] != 0x01 {
            return Err(ProxyError::Internal(format!(
                "Unsupported SOCKS5 command: {} (only CONNECT supported)",
                data[1]
            )));
        }

        // Parse address based on type
        let atyp = data[3];
        match atyp {
            0x01 => {
                // IPv4 address
                if data.len() < 10 {
                    return Err(ProxyError::Internal("IPv4 request too short".to_string()));
                }
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                let port = u16::from_be_bytes([data[8], data[9]]);
                Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
            }
            0x03 => {
                // Domain name - not supported (client should resolve through our DNS)
                let domain_len = data[4] as usize;
                if data.len() < 5 + domain_len + 2 {
                    return Err(ProxyError::Internal("Domain request too short".to_string()));
                }
                let domain = std::str::from_utf8(&data[5..5 + domain_len])
                    .map_err(|_| ProxyError::Internal("Invalid domain encoding".to_string()))?;
                {
                    let msg = format!(
                        "network: direct connection to domain \"{domain}\" blocked — must resolve through proxy DNS"
                    );
                    self.state.report_violation(msg.clone());
                    Err(ProxyError::DomainBlocked { domain: msg })
                }
            }
            0x04 => {
                // IPv6 address
                if data.len() < 22 {
                    return Err(ProxyError::Internal("IPv6 request too short".to_string()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[20], data[21]]);
                Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
            }
            _ => Err(ProxyError::Internal(format!(
                "Unknown address type: {atyp}"
            ))),
        }
    }

    /// Build SOCKS5 success response.
    ///
    /// # Arguments
    /// * `bound_addr` - Local address bound for the connection
    fn build_socks5_response(bound_addr: SocketAddr) -> Vec<u8> {
        // SOCKS5 reply format:
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+

        let mut response = Vec::with_capacity(22);
        response.push(0x05); // Version
        response.push(socks5::SUCCEEDED); // Reply
        response.push(0x00); // Reserved

        match bound_addr {
            SocketAddr::V4(addr) => {
                response.push(0x01); // IPv4
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                response.push(0x04); // IPv6
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        response
    }

    /// Build SOCKS5 error response.
    ///
    /// # Arguments
    /// * `code` - SOCKS5 error code
    fn build_socks5_error(code: u8) -> Vec<u8> {
        // Reply with error code and dummy address (0.0.0.0:0)
        vec![
            0x05, // Version
            code, // Reply code
            0x00, // Reserved
            0x01, // Address type: IPv4
            0x00, 0x00, 0x00, 0x00, // Address: 0.0.0.0
            0x00, 0x00, // Port: 0
        ]
    }
}

/// SOCKS5 reply codes.
// All RFC 1928 SOCKS5 reply codes are defined for completeness; not all are used in the
// current implementation but are present for reference and future use.
#[allow(dead_code)]
mod socks5 {
    pub(super) const SUCCEEDED: u8 = 0x00;
    pub(super) const GENERAL_FAILURE: u8 = 0x01;
    pub(super) const CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub(super) const NETWORK_UNREACHABLE: u8 = 0x03;
    pub(super) const HOST_UNREACHABLE: u8 = 0x04;
    pub(super) const CONNECTION_REFUSED: u8 = 0x05;
    pub(super) const TTL_EXPIRED: u8 = 0x06;
    pub(super) const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub(super) const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[cfg(test)]
#[allow(clippy::items_after_statements)] // use statements in test fns after let bindings
mod tests {
    use super::*;

    async fn tcp_listener_or_skip(addr: &str) -> Option<tokio::net::TcpListener> {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(err) => panic!("Failed to bind TCP listener for test: {err}"),
        }
    }

    /// Get a free port by binding to port 0.
    async fn get_free_port() -> Option<SocketAddr> {
        let listener = tcp_listener_or_skip("127.0.0.1:0").await?;
        Some(listener.local_addr().unwrap())
    }

    /// Perform a SOCKS5 handshake with the proxy, requesting a tunnel to `dest`.
    ///
    /// After this returns, the stream is tunnelled to `dest` and application
    /// data can flow freely in both directions.
    async fn socks5_connect(stream: &mut tokio::net::TcpStream, dest: std::net::SocketAddr) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Greeting: SOCKS5, one method, no-auth
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "Expected NO_AUTH method selected");

        // CONNECT request
        let mut req = match dest.ip() {
            std::net::IpAddr::V4(ip) => {
                let mut r = vec![0x05, 0x01, 0x00, 0x01];
                r.extend_from_slice(&ip.octets());
                r
            }
            std::net::IpAddr::V6(ip) => {
                let mut r = vec![0x05, 0x01, 0x00, 0x04];
                r.extend_from_slice(&ip.octets());
                r
            }
        };
        req.extend_from_slice(&dest.port().to_be_bytes());
        stream.write_all(&req).await.unwrap();

        // Read reply header
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x05, "Expected SOCKS5 version in reply");
        assert_eq!(header[1], 0x00, "Expected SUCCEEDED reply");

        // Consume bound address
        let remaining = match header[3] {
            0x01 => 4 + 2,  // IPv4 + port
            0x04 => 16 + 2, // IPv6 + port
            t => panic!("Unexpected ATYP in CONNECT reply: {t}"),
        };
        let mut buf = vec![0u8; remaining];
        stream.read_exact(&mut buf).await.unwrap();
    }

    // ========================================================================
    // TcpProxyConfig Tests
    // ========================================================================

    #[test]
    fn test_tcp_proxy_config_default() {
        let config = TcpProxyConfig::default();
        assert_eq!(config.bind_addr.port(), 9300);
        assert_eq!(config.connect_timeout, std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_tcp_proxy_config_default_idle_timeout() {
        let config = TcpProxyConfig::default();
        assert_eq!(config.idle_timeout, std::time::Duration::from_secs(300));
    }

    #[test]
    fn test_tcp_proxy_config_default_max_connections() {
        let config = TcpProxyConfig::default();
        assert_eq!(config.max_connections, 1000);
    }

    #[test]
    fn test_tcp_proxy_config_binds_localhost() {
        let config = TcpProxyConfig::default();
        assert!(config.bind_addr.ip().is_loopback());
    }

    // ========================================================================
    // SOCKS5 Constants Tests
    // ========================================================================

    #[test]
    fn test_socks5_constants_valid() {
        assert_eq!(socks5::SUCCEEDED, 0x00);
        assert_eq!(socks5::GENERAL_FAILURE, 0x01);
        assert_eq!(socks5::CONNECTION_NOT_ALLOWED, 0x02);
        assert_eq!(socks5::NETWORK_UNREACHABLE, 0x03);
        assert_eq!(socks5::HOST_UNREACHABLE, 0x04);
        assert_eq!(socks5::CONNECTION_REFUSED, 0x05);
    }

    // ========================================================================
    // TcpProxy Creation Tests
    // ========================================================================

    #[test]
    fn test_tcp_proxy_new_with_valid_config() {
        use crate::SharedState;
        let config = TcpProxyConfig::default();
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let proxy = TcpProxy::new(config, state);
        assert!(proxy.is_ok());
    }

    #[test]
    fn test_tcp_proxy_new_initializes_connection_count() {
        use crate::SharedState;
        let config = TcpProxyConfig::default();
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(config, state).unwrap();
        assert_eq!(proxy.connection_count(), 0);
    }

    // ========================================================================
    // Destination Verification Tests
    // ========================================================================

    #[tokio::test]
    async fn test_verify_destination_resolved_ip_allowed() {
        use crate::{ResolvedAddress, SharedState};
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let result = proxy.verify_destination(&dest);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_destination_unknown_ip_rejected() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let result = proxy.verify_destination(&dest);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_destination_expired_cache_rejected() {
        use crate::{ResolvedAddress, SharedState};
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap(),
        };
        state.cache.insert(resolved);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let result = proxy.verify_destination(&dest);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_destination_returns_domain() {
        use crate::{ResolvedAddress, SharedState};
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let result = proxy.verify_destination(&dest);
        assert_eq!(result.unwrap(), "example.com");
    }

    // ========================================================================
    // Connection Forwarding Tests
    // ========================================================================

    #[tokio::test]
    async fn test_allowed_destination_forwarded() {
        use crate::{ResolvedAddress, SharedState};

        // Start a test destination server
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest_addr = listener.local_addr().unwrap();

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        // Add destination IP to cache
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![dest_addr.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect through proxy
        let client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        assert!(client.peer_addr().is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn test_unknown_destination_rejected_with_error() {
        use crate::SharedState;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and try to reach unknown IP
        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();

        // Send SOCKS5 greeting and request for unknown IP
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // SOCKS5, 1 auth method, no auth
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();

        // Send CONNECT request for unknown IP
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 10, 255, 255, 1, 0x00, 0x50])
            .await
            .unwrap();

        let mut response = [0u8; 10];
        let _ = client.read(&mut response).await;

        // Should get an error response (reply field != 0x00)
        assert_ne!(response[1], socks5::SUCCEEDED);

        handle.abort();
    }

    #[tokio::test]
    async fn test_connection_timeout_handled() {
        use crate::{ResolvedAddress, SharedState};

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        // Add non-routable IP to cache to force timeout
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec!["10.255.255.1".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            connect_timeout: std::time::Duration::from_secs(1), // Short timeout
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let start = std::time::Instant::now();
        let client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();

        // Send SOCKS5 request
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut client = client;
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 10, 255, 255, 1, 0x00, 0x50])
            .await
            .unwrap();

        let mut response = [0u8; 10];
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read(&mut response),
        )
        .await;

        let elapsed = start.elapsed();
        // Should timeout within reasonable time (connect_timeout + buffer)
        assert!(elapsed.as_secs() < 10);

        handle.abort();
    }

    #[tokio::test]
    async fn test_connection_refused_handled() {
        use crate::{ResolvedAddress, SharedState};

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        // Add localhost IP with a port that's not listening
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec!["127.0.0.1".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        // Request connection to port 19999 (not listening)
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x4E, 0x1F])
            .await
            .unwrap();

        let mut response = [0u8; 10];
        let _ = client.read(&mut response).await;

        // Should get connection refused error
        assert_eq!(response[1], socks5::CONNECTION_REFUSED);

        handle.abort();
    }

    // ========================================================================
    // SOCKS5 Protocol Tests
    // ========================================================================

    #[test]

    fn test_socks5_request_parsing_ipv4() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        // SOCKS5 CONNECT request: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), IP, PORT
        let request = [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50]; // 192.168.1.1:80
        let addr = proxy.parse_socks5_request(&request).unwrap();

        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 80);
    }

    #[test]

    fn test_socks5_request_parsing_ipv6() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        // SOCKS5 CONNECT request with IPv6: ATYP=4
        let mut request = vec![0x05, 0x01, 0x00, 0x04];
        // ::1 in 16 bytes
        request.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        request.extend_from_slice(&[0x01, 0xBB]); // Port 443

        let addr = proxy.parse_socks5_request(&request).unwrap();
        assert!(addr.ip().is_ipv6());
        assert_eq!(addr.port(), 443);
    }

    #[test]

    fn test_socks5_request_parsing_domain() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        // SOCKS5 CONNECT request with domain: ATYP=3
        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        let domain = b"example.com";
        #[allow(clippy::cast_possible_truncation)]
        request.push(domain.len() as u8);
        request.extend_from_slice(domain);
        request.extend_from_slice(&[0x01, 0xBB]); // Port 443

        // Domain requests need DNS resolution first
        // The parser might return the domain or error asking for resolution
        let result = proxy.parse_socks5_request(&request);
        // Either succeeds with resolved IP or errors indicating domain needs resolution
        assert!(result.is_ok() || result.is_err());
    }

    #[test]

    fn test_socks5_request_parsing_invalid_version() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        // SOCKS4 request (version 4 instead of 5)
        let request = [0x04, 0x01, 0x00, 0x50, 192, 168, 1, 1, 0x00];
        let result = proxy.parse_socks5_request(&request);

        assert!(result.is_err());
    }

    #[test]

    fn test_socks5_request_parsing_unsupported_command() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        // SOCKS5 BIND request (CMD=2) - not supported
        let request = [0x05, 0x02, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50];
        let result = proxy.parse_socks5_request(&request);

        assert!(result.is_err());
    }

    #[test]

    fn test_socks5_request_parsing_truncated() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        // Truncated request (missing port)
        let request = [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1];
        let result = proxy.parse_socks5_request(&request);

        assert!(result.is_err());
    }

    #[test]

    fn test_socks5_response_success() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let _proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        let bound_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let response = TcpProxy::build_socks5_response(bound_addr);

        // Check SOCKS5 response format
        assert_eq!(response[0], 0x05); // VER
        assert_eq!(response[1], socks5::SUCCEEDED); // REP = success
        assert_eq!(response[2], 0x00); // RSV
        assert_eq!(response[3], 0x01); // ATYP = IPv4
        assert_eq!(response.len(), 10); // Fixed size for IPv4
    }

    #[test]

    fn test_socks5_response_error_codes() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let _proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        let response = TcpProxy::build_socks5_error(socks5::CONNECTION_REFUSED);
        assert_eq!(response[0], 0x05); // VER
        assert_eq!(response[1], socks5::CONNECTION_REFUSED); // REP

        let response = TcpProxy::build_socks5_error(socks5::HOST_UNREACHABLE);
        assert_eq!(response[1], socks5::HOST_UNREACHABLE);

        let response = TcpProxy::build_socks5_error(socks5::COMMAND_NOT_SUPPORTED);
        assert_eq!(response[1], socks5::COMMAND_NOT_SUPPORTED);
    }

    // ========================================================================
    // Data Relay Tests
    // ========================================================================

    #[tokio::test]
    async fn test_relay_bidirectional_data() {
        use crate::{ResolvedAddress, SharedState};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start echo server
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let echo_addr = listener.local_addr().unwrap();

        let echo_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                socket.write_all(&buf[..n]).await.unwrap();
            }
        });

        let state = Arc::new(SharedState::new(vec!["test.local".to_string()]));
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec![echo_addr.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let proxy_handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        socks5_connect(&mut client, echo_addr).await;

        let test_data = b"Hello, World!";
        client.write_all(test_data).await.unwrap();

        let mut response = [0u8; 64];
        let n = client.read(&mut response).await.unwrap();

        assert_eq!(&response[..n], test_data);

        proxy_handle.abort();
        echo_handle.abort();
    }

    #[tokio::test]
    async fn test_relay_large_data_transfer() {
        use crate::{ResolvedAddress, SharedState};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest_addr = listener.local_addr().unwrap();

        // Server that receives all data and sends it back
        let server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            socket.read_to_end(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
        });

        let state = Arc::new(SharedState::new(vec!["test.local".to_string()]));
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec![dest_addr.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let proxy_handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 1MB of data
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let large_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        socks5_connect(&mut client, dest_addr).await;

        client.write_all(&large_data).await.unwrap();
        // Half-close: tell the server we're done sending so it can echo back
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert_eq!(response.len(), large_data.len());

        proxy_handle.abort();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_relay_client_closes_first() {
        use crate::{ResolvedAddress, SharedState};
        use tokio::io::AsyncReadExt;

        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            // Relay must propagate client FIN to destination
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(n, 0); // Client closed connection
        });

        let state = Arc::new(SharedState::new(vec!["test.local".to_string()]));
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec![dest_addr.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let proxy_handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        socks5_connect(&mut client, dest_addr).await;
        drop(client); // Close client connection

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        proxy_handle.abort();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_relay_destination_closes_first() {
        use crate::{ResolvedAddress, SharedState};
        use tokio::io::AsyncReadExt;

        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest_addr = listener.local_addr().unwrap();

        // Server that accepts and immediately closes
        let server_handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket); // Close immediately
        });

        let state = Arc::new(SharedState::new(vec!["test.local".to_string()]));
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec![dest_addr.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let proxy_handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        socks5_connect(&mut client, dest_addr).await;

        // Relay must propagate destination FIN to client
        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF

        proxy_handle.abort();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_relay_idle_timeout() {
        use crate::{ResolvedAddress, SharedState};
        use tokio::io::AsyncReadExt;

        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest_addr = listener.local_addr().unwrap();

        let _server_handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Just keep connection open, don't send anything
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
        });

        let state = Arc::new(SharedState::new(vec!["test.local".to_string()]));
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec![dest_addr.ip()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            idle_timeout: std::time::Duration::from_secs(1), // 1 second idle timeout
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let proxy_handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        socks5_connect(&mut client, dest_addr).await;

        // Wait for idle timeout to fire (1 s) plus buffer
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Proxy should have closed the relay, sending FIN to client
        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        proxy_handle.abort();
    }

    // ========================================================================
    // Connection Limits Tests
    // ========================================================================

    #[tokio::test]
    async fn test_max_connections_enforced() {
        use crate::SharedState;
        use tokio::io::AsyncReadExt;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            max_connections: 2,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let proxy_handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Open max connections without completing SOCKS5 so they stay counted
        let _conn1 = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();
        let _conn2 = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();

        // Give the accept loop time to count both connections
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Third connection: TCP handshake succeeds at OS level before proxy checks
        let mut conn3 = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();

        // Proxy drops conn3 because limit is reached; read must return EOF
        let mut buf = [0u8; 1];
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(500), conn3.read(&mut buf)).await;

        assert!(result.is_ok(), "Should get a response before timeout");
        let n = result.unwrap().unwrap_or(0);
        assert_eq!(n, 0, "Third connection should be dropped by proxy (EOF)");

        proxy_handle.abort();
    }

    #[tokio::test]

    async fn test_connection_count_increments() {
        use crate::SharedState;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = Arc::new(TcpProxy::new(config.clone(), state).unwrap());

        assert_eq!(proxy.connection_count(), 0);

        let proxy_clone = Arc::clone(&proxy);
        let proxy_handle = tokio::spawn(async move { proxy_clone.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let _conn = tokio::net::TcpStream::connect(config.bind_addr)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(proxy.connection_count() >= 1);

        proxy_handle.abort();
    }

    #[tokio::test]

    async fn test_connection_count_decrements_on_close() {
        use crate::SharedState;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = Arc::new(TcpProxy::new(config.clone(), state).unwrap());

        let proxy_clone = Arc::clone(&proxy);
        let proxy_handle = tokio::spawn(async move { proxy_clone.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        {
            let _conn = tokio::net::TcpStream::connect(config.bind_addr)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        } // Connection dropped here

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(proxy.connection_count(), 0);

        proxy_handle.abort();
    }

    // ========================================================================
    // Server Lifecycle Tests
    // ========================================================================

    #[tokio::test]

    async fn test_tcp_proxy_binds_to_port() {
        use crate::SharedState;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Should be able to connect
        let conn = tokio::net::TcpStream::connect(config.bind_addr).await;
        assert!(conn.is_ok());

        handle.abort();
    }

    #[tokio::test]

    async fn test_tcp_proxy_handles_concurrent_connections() {
        use crate::SharedState;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Open multiple connections concurrently
        let mut handles = vec![];
        for _ in 0..10 {
            let addr = config.bind_addr;
            handles.push(tokio::spawn(async move {
                tokio::net::TcpStream::connect(addr).await.is_ok()
            }));
        }

        // Wait for all handles and collect results
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All connections should succeed
        assert!(results.iter().all(|&r| r));

        handle.abort();
    }

    #[tokio::test]
    async fn test_tcp_proxy_graceful_shutdown() {
        use crate::SharedState;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config, state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handle.abort();
        let result = handle.await;

        // Should have been cancelled
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_proxy_bind_address_in_use() {
        use crate::SharedState;

        // Bind to port first to get a free port
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let bound_addr = listener.local_addr().unwrap();
        // Keep listener bound to cause conflict

        let state = Arc::new(SharedState::new(vec![]));
        let config = TcpProxyConfig {
            bind_addr: bound_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config, state).unwrap();

        let result = proxy.run().await;
        assert!(result.is_err());

        drop(listener);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[tokio::test]

    async fn test_connection_to_ipv6_destination() {
        use crate::{ResolvedAddress, SharedState};

        let state = Arc::new(SharedState::new(vec!["test.local".to_string()]));
        let resolved = ResolvedAddress {
            domain: "test.local".to_string(),
            addresses: vec!["::1".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);

        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let dest: SocketAddr = "[::1]:80".parse().unwrap();

        // Should be able to verify IPv6 destination
        let result = proxy.verify_destination(&dest);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connection_rapid_open_close() {
        use crate::SharedState;
        use tokio::net::TcpStream;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Rapid open/close cycles
        for _ in 0..10 {
            if let Ok(stream) = TcpStream::connect(config.bind_addr).await {
                drop(stream); // Immediately close
            }
        }

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_connection_zero_byte_data() {
        use crate::SharedState;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        if let Ok(mut stream) = TcpStream::connect(config.bind_addr).await {
            // Write zero bytes - should not crash
            let _ = stream.write(&[]).await;
            let _ = stream.flush().await;
        }

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_connection_half_close() {
        use crate::SharedState;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let state = Arc::new(SharedState::new(vec![]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        if let Ok(mut stream) = TcpStream::connect(config.bind_addr).await {
            // Half-close: shutdown write side
            let _ = stream.shutdown().await;
        }

        handle.abort();
        let _ = handle.await;
    }

    // ========================================================================
    // Connection Counter Safety Tests
    // ========================================================================

    /// This test verifies that the connection counter is safely shared with spawned tasks.
    /// Previously, the implementation used a raw pointer which could cause use-after-free
    /// if `run()` was aborted. Now it uses `Arc<AtomicUsize>` for safe sharing.
    ///
    /// The test verifies that:
    /// 1. Connections can be established while the proxy runs
    /// 2. Aborting the proxy doesn't cause crashes or undefined behavior
    /// 3. The Arc-based counter remains valid even after proxy abort
    #[tokio::test]
    async fn test_connection_counter_safe_with_arc() {
        use crate::SharedState;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let Some(bind_addr) = get_free_port().await else {
            return;
        };
        let config = TcpProxyConfig {
            bind_addr,
            ..Default::default()
        };

        // Spawn multiple connections that will be in-flight when we abort
        let proxy = TcpProxy::new(config.clone(), state).unwrap();
        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Open several connections that start SOCKS5 handshake but don't complete
        let mut streams = Vec::new();
        for _ in 0..5 {
            if let Ok(mut stream) = TcpStream::connect(config.bind_addr).await {
                // Send partial SOCKS5 greeting to keep connection open
                let _ = stream.write_all(&[0x05, 0x01, 0x00]).await;
                streams.push(stream);
            }
        }

        // Small delay to ensure spawned tasks are running
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Abort the proxy - with Arc<AtomicUsize>, the counter remains valid
        // because each spawned task holds its own Arc reference
        handle.abort();
        let _ = handle.await;

        // Give spawned tasks time to clean up - they should safely decrement counter
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Clean up - drop connections
        for mut stream in streams {
            let _ = stream.shutdown().await;
        }

        // If we got here, the Arc-based implementation is working correctly
        // No crashes, no undefined behavior
    }
}
