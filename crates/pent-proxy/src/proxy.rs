//! TCP proxy for forwarding allowed connections.
//!
//! Forwards TCP connections only to allowed destinations: a domain on the
//! allowlist, or an IP address that the DNS server resolved from an allowed
//! domain.
//!
//! # Connection Flow
//!
//! ```text
//! Client connects to proxy
//!         |
//!         v
//! Read the SOCKS5 or HTTP CONNECT handshake (with a time limit)
//!         |
//!         +-- domain target --> allowlist check, resolve, drop non-public IPs
//!         |
//!         +-- IP target -----> non-public check, ResolutionCache.lookup(ip)
//!         |
//!         v
//! Connect, reply success
//!         |
//!         v
//! Port 443/80: read the TLS SNI or the HTTP Host header, check the allowlist
//!         |
//!         v
//! Relay data (idle timeout resets on each transfer)
//! ```
//!
//! # Observe mode and watch events
//!
//! With [`crate::ProxyPolicy::Observe`], the proxy permits each domain and
//! each IP address. The rule for destinations that are not public still
//! applies. The TLS SNI and the HTTP `Host` header only name the connection.
//!
//! In both policies, the proxy sends one [`WatchEvent::Connect`] for each
//! connection attempt, if the configuration has an event channel. A domain
//! that does not resolve gets the outcome `Allowed`, because the policy
//! permitted it.
//!
//! # Proxy Protocol
//!
//! - **SOCKS5**: Standard SOCKS5 proxy protocol (CONNECT command only)
//! - **HTTP CONNECT**: `CONNECT host:port HTTP/1.1`
//!

use crate::inspect::{self, Inspect};
use crate::netaddr::{self, PrivateDestinations};
use crate::{normalize_hostname, ProxyError, ProxyPolicy, Result, SharedState};
use pent_profile::{NetProtocol, Outcome, WatchEvent};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Configuration for the TCP proxy.
#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
    /// Address to bind the proxy to.
    /// Default: `127.0.0.1:9300`
    pub bind_addr: SocketAddr,

    /// Connection timeout.
    /// Default: 30 seconds
    pub connect_timeout: Duration,

    /// Idle timeout. The proxy closes a connection when no data flows in
    /// either direction for this time. Each transfer resets the timer.
    /// Default: 5 minutes
    pub idle_timeout: Duration,

    /// Maximum concurrent connections.
    /// Default: 1000
    pub max_connections: usize,

    /// Time limit for the SOCKS5 or HTTP CONNECT handshake of a client. The
    /// same limit applies to the read of the TLS ClientHello or HTTP request
    /// head that the proxy inspects.
    /// Default: 10 seconds
    pub handshake_timeout: Duration,

    /// Policy for destinations that are not public addresses.
    /// Default: [`PrivateDestinations::Deny`]
    pub private_destinations: PrivateDestinations,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9300);
        Self {
            bind_addr: DEFAULT_BIND,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_connections: 1000,
            handshake_timeout: Duration::from_secs(10),
            private_destinations: PrivateDestinations::Deny,
        }
    }
}

/// The proxy protocol of a client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Socks5,
    HttpConnect,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Socks5 => "SOCKS5",
            Self::HttpConnect => "CONNECT",
        })
    }
}

impl Protocol {
    /// The protocol as it appears in a watch event.
    const fn net_protocol(self) -> NetProtocol {
        match self {
            Self::Socks5 => NetProtocol::Socks5,
            Self::HttpConnect => NetProtocol::HttpConnect,
        }
    }
}

/// The data for the watch event of one connection attempt.
///
/// The proxy sends exactly one [`WatchEvent::Connect`] for each connection
/// attempt. It sends the event when it knows the outcome. If the task ends
/// before that (for example on an I/O error), the drop sends the event with
/// [`Outcome::Allowed`], because the policy did not reject the connection.
struct ConnectRecord<'a> {
    state: &'a SharedState,
    protocol: Protocol,
    port: u16,
    /// The domain that the client asked for (SOCKS5 ATYP=3 or a CONNECT
    /// host), normalized.
    requested: Option<String>,
    /// The name in the TLS SNI or in the HTTP `Host` header, normalized.
    peeked: Option<String>,
    /// A domain from the DNS cache for the destination IP address.
    cached: Option<String>,
    /// The destination IP address that the client asked for.
    ip: Option<IpAddr>,
    /// True after the proxy sent the event.
    sent: bool,
}

impl<'a> ConnectRecord<'a> {
    fn new(state: &'a SharedState, protocol: Protocol, target: &Target) -> Self {
        let (requested, ip) = match target {
            Target::Ip(addr) => (None, Some(addr.ip())),
            Target::Domain { host, .. } => {
                // A name that is not valid has no normalized form. The event
                // then uses the lowercase name without the trailing dot.
                let name = normalize_hostname(host)
                    .unwrap_or_else(|_| host.trim_end_matches('.').to_ascii_lowercase());
                (Some(name), None)
            }
        };
        Self {
            state,
            protocol,
            port: target.port(),
            requested,
            peeked: None,
            cached: None,
            ip,
            sent: false,
        }
    }

    /// The best name that the proxy knows for the destination: the requested
    /// domain, else the SNI or `Host` name, else the cached domain, else the
    /// IP address as text.
    fn host(&self) -> String {
        self.requested
            .as_ref()
            .or(self.peeked.as_ref())
            .or(self.cached.as_ref())
            .cloned()
            .or_else(|| self.ip.map(|ip| ip.to_string()))
            .unwrap_or_default()
    }

    /// Send the event with `outcome`, if the proxy did not send it before.
    fn finish(&mut self, outcome: Outcome) {
        if self.sent {
            return;
        }
        self.sent = true;
        self.state.emit(WatchEvent::Connect {
            host: self.host(),
            port: self.port,
            protocol: self.protocol.net_protocol(),
            outcome,
        });
    }
}

impl Drop for ConnectRecord<'_> {
    fn drop(&mut self) {
        self.finish(Outcome::Allowed);
    }
}

/// The destination that a client asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// An IP address and a port.
    Ip(SocketAddr),
    /// A host name, as the client sent it, and a port.
    Domain { host: String, port: u16 },
}

impl Target {
    const fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain { port, .. } => *port,
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{} port {}", addr.ip(), addr.port()),
            Self::Domain { host, port } => write!(f, "{host:?} port {port}"),
        }
    }
}

/// A parsed SOCKS5 request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Socks5Request {
    /// The command (`0x01` CONNECT, `0x02` BIND, `0x03` UDP ASSOCIATE).
    cmd: u8,
    /// The destination.
    target: Target,
}

/// A failure that the proxy reports to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    General,
    NotAllowed,
    Refused,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Failure {
    const fn socks5_code(self) -> u8 {
        match self {
            Self::General => socks5::GENERAL_FAILURE,
            Self::NotAllowed => socks5::CONNECTION_NOT_ALLOWED,
            Self::Refused => socks5::CONNECTION_REFUSED,
            Self::CommandNotSupported => socks5::COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported => socks5::ADDRESS_TYPE_NOT_SUPPORTED,
        }
    }

    const fn http_response(self) -> &'static [u8] {
        match self {
            Self::NotAllowed => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            Self::Refused => b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            Self::General | Self::CommandNotSupported | Self::AddressTypeNotSupported => {
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            }
        }
    }
}

/// The result of a successful handshake.
#[derive(Debug)]
struct Negotiated {
    protocol: Protocol,
    target: Target,
    /// Bytes that the client sent after the handshake (for example after the
    /// end of the HTTP CONNECT headers). The proxy forwards them.
    initial: Vec<u8>,
}

/// A handshake error, with the failure to report to the client.
struct HandshakeError {
    protocol: Protocol,
    failure: Option<Failure>,
    error: ProxyError,
}

impl HandshakeError {
    fn new(protocol: Protocol, failure: Option<Failure>, error: ProxyError) -> Self {
        Self {
            protocol,
            failure,
            error,
        }
    }
}

/// Decrements the connection count when a connection task ends, also if the
/// task is aborted.
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// TCP proxy that forwards connections to resolved (allowed) destinations.
///
/// Only allows connections to IP addresses that were previously resolved
/// through the DNS server (and thus are on the domain allowlist), or to
/// domains on the allowlist.
pub struct TcpProxy {
    /// Proxy configuration.
    config: TcpProxyConfig,

    /// Shared state with resolution cache.
    state: Arc<SharedState>,

    /// Current connection count (Arc-wrapped to safely share with spawned tasks).
    connection_count: Arc<AtomicUsize>,
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
            connection_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Get current connection count.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::Relaxed)
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
    /// The connection tasks belong to this future. When the caller drops the
    /// future (for example at shutdown), all the connection tasks stop and
    /// the proxy closes their connections.
    ///
    /// # Errors
    /// * `ProxyError::Internal` - Fatal proxy error during operation.
    pub async fn run_on(&self, listener: tokio::net::TcpListener) -> Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (client, client_addr) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(result) => result,
                    Err(e) => {
                        warn!(error = %e, "TCP accept error");
                        continue;
                    }
                },
                Some(finished) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(e) = finished {
                        if e.is_panic() {
                            warn!(error = %e, "TCP connection task panicked");
                        }
                    }
                    continue;
                }
            };

            // Check connection limit
            let current = self.connection_count.load(Ordering::Relaxed);
            if current >= self.config.max_connections {
                warn!(client = %client_addr, "Connection limit reached, rejecting");
                drop(client);
                continue;
            }

            // Count every accepted connection so callers can detect whether the
            // sandboxed process is routing traffic through the proxy at all.
            self.state
                .connections_accepted
                .fetch_add(1, Ordering::Relaxed);

            // Increment connection count. The guard decrements it when the
            // task ends or is aborted.
            self.connection_count.fetch_add(1, Ordering::Relaxed);
            let guard = ConnectionGuard(Arc::clone(&self.connection_count));

            // Handle connection in background task
            let proxy = Self {
                config: self.config.clone(),
                state: Arc::clone(&self.state),
                connection_count: Arc::clone(&self.connection_count),
            };

            tasks.spawn(async move {
                let _guard = guard;
                if let Err(e) = proxy.handle_connection(client, client_addr).await {
                    debug!(client = %client_addr, error = %e, "Connection error");
                }
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
        client_addr: SocketAddr,
    ) -> Result<()> {
        let limit = self.config.handshake_timeout;
        let negotiated = match tokio::time::timeout(limit, negotiate(&mut client)).await {
            Ok(Ok(negotiated)) => negotiated,
            Ok(Err(e)) => {
                if let Some(failure) = e.failure {
                    send_failure(&mut client, e.protocol, failure).await;
                }
                return Err(e.error);
            }
            Err(_) => {
                debug!(client = %client_addr, "client did not complete the handshake in time");
                return Err(ProxyError::HandshakeTimeout);
            }
        };
        self.serve(client, negotiated).await
    }

    /// Check the target, connect to it, inspect the first client data, and
    /// relay.
    async fn serve(&self, mut client: TcpStream, negotiated: Negotiated) -> Result<()> {
        let Negotiated {
            protocol,
            target,
            mut initial,
        } = negotiated;

        let mut record = ConnectRecord::new(&self.state, protocol, &target);
        let candidates = match self.check_target(protocol, &target, &mut record).await {
            Ok(c) => c,
            Err(e) => {
                // A name that does not resolve is not a policy decision: the
                // policy permitted the name, thus the event has the outcome
                // `Allowed`. The summary needs only the name.
                let outcome = match &e {
                    ProxyError::DnsResolution { .. } => Outcome::Allowed,
                    _ => Outcome::Denied,
                };
                record.finish(outcome);
                send_failure(&mut client, protocol, Failure::NotAllowed).await;
                return Err(e);
            }
        };

        let destination = match self.connect_any(&candidates).await {
            Ok(d) => d,
            Err(e) => {
                let failure = match &e {
                    ProxyError::TcpConnection { .. } => Failure::Refused,
                    _ => Failure::General,
                };
                send_failure(&mut client, protocol, failure).await;
                return Err(e);
            }
        };

        send_success(&mut client, protocol, &destination).await?;

        if let Some(kind) = Inspect::for_port(target.port()) {
            initial =
                inspect::read_initial(&mut client, initial, kind, self.config.handshake_timeout)
                    .await
                    .map_err(|e| {
                        ProxyError::Internal(format!("failed to read client data: {e}"))
                    })?;
            match self.check_requested_host(protocol, &target, kind, &initial) {
                Ok(peeked) => record.peeked = peeked,
                Err(e) => {
                    if let ProxyError::DomainBlocked { domain } = &e {
                        record.peeked = normalize_hostname(domain).ok();
                    }
                    record.finish(Outcome::Denied);
                    return Err(e);
                }
            }
        }
        record.finish(Outcome::Allowed);

        let mut destination = destination;
        if !initial.is_empty() {
            destination.write_all(&initial).await.map_err(|e| {
                ProxyError::Internal(format!("failed to forward initial client data: {e}"))
            })?;
        }

        self.relay(client, destination).await
    }

    /// Check a target against the policy, and return the addresses that the
    /// proxy can connect to.
    ///
    /// The function puts the names that it finds in `record`. In observe
    /// mode, the policy permits each domain and each IP address, but it still
    /// rejects destinations that are not public.
    async fn check_target(
        &self,
        protocol: Protocol,
        target: &Target,
        record: &mut ConnectRecord<'_>,
    ) -> Result<Vec<SocketAddr>> {
        match target {
            Target::Ip(addr) => {
                record.cached = self.state.lookup_resolved(&addr.ip());
                let domain = match self.state.policy() {
                    ProxyPolicy::Enforce => Some(self.verify_destination_for(protocol, addr)?),
                    ProxyPolicy::Observe => {
                        self.check_public(protocol, addr)?;
                        record.cached.clone()
                    }
                };
                match domain {
                    Some(domain) => self.state.report_access(format!(
                        "network: {protocol} connection to {target} (\"{domain}\") allowed"
                    )),
                    None => self.state.report_access(format!(
                        "network: {protocol} connection to {target} allowed"
                    )),
                }
                Ok(vec![*addr])
            }
            Target::Domain { host, port } => {
                let name = match normalize_hostname(host) {
                    Ok(name) => name,
                    Err(e) => {
                        self.state.report_violation(format!(
                            "network: {protocol} connection to {target} blocked: {e}"
                        ));
                        return Err(e.into());
                    }
                };
                if !self.state.is_permitted(&name) {
                    self.state.report_violation(format!(
                        "network: {protocol} connection to \"{name}\" port {port} blocked: \
                         the domain is not in the allowlist"
                    ));
                    return Err(ProxyError::DomainBlocked { domain: name });
                }

                // Resolve the exact normalized name that the allowlist check used.
                let resolved: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), *port))
                    .await
                    .map_err(|e| ProxyError::DnsResolution {
                        domain: name.clone(),
                        message: e.to_string(),
                    })?
                    .collect();
                if resolved.is_empty() {
                    return Err(ProxyError::DnsResolution {
                        domain: name,
                        message: "no addresses returned".to_string(),
                    });
                }

                let mut rejected = None;
                let permitted: Vec<SocketAddr> = resolved
                    .into_iter()
                    .filter(|addr| match self.non_public_reason(addr.ip()) {
                        Some(reason) => {
                            rejected = Some((*addr, reason));
                            false
                        }
                        None => true,
                    })
                    .collect();
                if permitted.is_empty() {
                    if let Some((addr, reason)) = rejected {
                        self.state.report_violation(format!(
                            "network: {protocol} connection to \"{name}\" port {port} blocked: \
                             the domain resolves to the {reason} address {}",
                            addr.ip()
                        ));
                        return Err(ProxyError::NonPublicDestination {
                            addr,
                            reason: reason.to_string(),
                        });
                    }
                }
                self.state.report_access(format!(
                    "network: {protocol} connection to \"{name}\" port {port} allowed"
                ));
                Ok(permitted)
            }
        }
    }

    /// Return the reason why the policy rejects `ip` as a non-public address.
    fn non_public_reason(&self, ip: IpAddr) -> Option<netaddr::NonPublic> {
        match self.config.private_destinations {
            PrivateDestinations::Allow => None,
            PrivateDestinations::Deny => netaddr::classify(ip),
        }
    }

    /// Verify that the destination is allowed: it must be a public address
    /// (unless the configuration permits private destinations), and the DNS
    /// server must have resolved it from an allowed domain.
    ///
    /// # Arguments
    /// * `dest` - Destination address
    ///
    /// # Returns
    /// * `Ok(domain)` - The domain this IP was resolved from
    /// * `Err(ProxyError::NonPublicDestination)` - The address is not public
    /// * `Err(ProxyError::DomainBlocked)` - IP not in resolution cache
    #[cfg(test)]
    fn verify_destination(&self, dest: &SocketAddr) -> Result<String> {
        self.verify_destination_for(Protocol::Socks5, dest)
    }

    fn verify_destination_for(&self, protocol: Protocol, dest: &SocketAddr) -> Result<String> {
        self.check_public(protocol, dest)?;
        self.state.lookup_resolved(&dest.ip()).ok_or_else(|| {
            let msg = format!(
                "network: {protocol} connection to {} port {} blocked: \
                 the proxy DNS did not resolve this IP address",
                dest.ip(),
                dest.port()
            );
            self.state.report_violation(msg.clone());
            ProxyError::DomainBlocked { domain: msg }
        })
    }

    /// Reject a destination that is not a public address, unless the
    /// configuration permits private destinations.
    fn check_public(&self, protocol: Protocol, dest: &SocketAddr) -> Result<()> {
        if let Some(reason) = self.non_public_reason(dest.ip()) {
            self.state.report_violation(format!(
                "network: {protocol} connection to {} port {} blocked: the address is {reason}",
                dest.ip(),
                dest.port()
            ));
            return Err(ProxyError::NonPublicDestination {
                addr: *dest,
                reason: reason.to_string(),
            });
        }
        Ok(())
    }

    /// Check the host name in the TLS SNI or the HTTP `Host` header.
    ///
    /// If the client data contains a host name, the name must be on the
    /// allowlist. If it contains no name (for example with ECH, or for a
    /// protocol that the proxy cannot read), the checks before the connect
    /// are the only checks. In observe mode, the name does not block the
    /// connection.
    ///
    /// Returns the normalized host name, if the data contains a valid name.
    fn check_requested_host(
        &self,
        protocol: Protocol,
        target: &Target,
        kind: Inspect,
        data: &[u8],
    ) -> Result<Option<String>> {
        let Some(raw) = kind.host_name(data) else {
            return Ok(None);
        };
        let name = normalize_hostname(&raw).ok();
        let label = match kind {
            Inspect::Tls => "TLS SNI",
            Inspect::Http => "HTTP Host header",
        };
        let allowed = match self.state.policy() {
            ProxyPolicy::Observe => true,
            ProxyPolicy::Enforce => name.as_ref().is_some_and(|n| self.state.is_allowed(n)),
        };
        if allowed {
            return Ok(name);
        }
        self.state.report_violation(format!(
            "network: {protocol} connection to {target} blocked: \
             the {label} {raw:?} is not in the allowlist"
        ));
        Err(ProxyError::DomainBlocked { domain: raw })
    }

    /// Connect to the first address that accepts the connection.
    async fn connect_any(&self, candidates: &[SocketAddr]) -> Result<TcpStream> {
        let mut last_error = None;
        for dest in candidates {
            match self.connect_to_destination(*dest).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error
            .unwrap_or_else(|| ProxyError::Internal("no destination address".to_string())))
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
    /// Copies data bidirectionally until both sides close, an error occurs,
    /// or no data flows in either direction for `idle_timeout`. Each
    /// successful read or write in either direction resets the idle timer.
    /// When one direction reaches EOF, it shuts down the corresponding write
    /// half so the peer receives FIN and can finish sending its data.
    ///
    /// # Arguments
    /// * `client` - Client connection
    /// * `destination` - Destination connection
    async fn relay(&self, client: TcpStream, destination: TcpStream) -> Result<()> {
        let peer = destination.peer_addr().ok();
        let (client_read, client_write) = client.into_split();
        let (dest_read, dest_write) = destination.into_split();
        match relay_streams(
            client_read,
            client_write,
            dest_read,
            dest_write,
            self.config.idle_timeout,
        )
        .await
        {
            RelayEnd::Closed => Ok(()),
            RelayEnd::Idle => {
                info!(
                    destination = ?peer,
                    idle_timeout = ?self.config.idle_timeout,
                    "close the proxied connection: no data flowed for the idle timeout"
                );
                Ok(())
            }
            RelayEnd::Failed(e) => Err(ProxyError::Internal(format!("Relay error: {e}"))),
        }
    }
}

/// How a relay ended.
#[derive(Debug)]
enum RelayEnd {
    /// Both directions reached EOF, or a peer reset the connection.
    Closed,
    /// No data flowed for the idle timeout.
    Idle,
    /// An I/O error occurred.
    Failed(std::io::Error),
}

/// The time of the most recent transfer, shared by the two directions.
struct Activity {
    start: tokio::time::Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(elapsed, Ordering::Relaxed);
    }

    /// Complete when no transfer occurs for `idle`.
    async fn idle_for(&self, idle: Duration) {
        loop {
            let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
            let Some(deadline) = self
                .start
                .checked_add(last)
                .and_then(|t| t.checked_add(idle))
            else {
                // The deadline is too far in the future to represent.
                std::future::pending::<()>().await;
                return;
            };
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// Copy data from `reader` to `writer` until EOF, and record each transfer.
async fn pump<R, W>(mut reader: R, mut writer: W, activity: &Activity) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        activity.touch();
        writer.write_all(buf.get(..n).unwrap_or_default()).await?;
        activity.touch();
    }
    // Best-effort half-close; if shutdown fails the peer will see a connection reset.
    let _ = writer.shutdown().await;
    Ok(())
}

/// Relay two connections in both directions with a real idle timeout.
async fn relay_streams<CR, CW, DR, DW>(
    client_read: CR,
    client_write: CW,
    dest_read: DR,
    dest_write: DW,
    idle: Duration,
) -> RelayEnd
where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    DR: AsyncRead + Unpin,
    DW: AsyncWrite + Unpin,
{
    let activity = Activity::new();
    let transfer = async {
        tokio::try_join!(
            pump(client_read, dest_write, &activity),
            pump(dest_read, client_write, &activity),
        )
    };
    tokio::select! {
        result = transfer => match result {
            Ok(((), ())) => RelayEnd::Closed,
            Err(e) if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) => RelayEnd::Closed,
            Err(e) => RelayEnd::Failed(e),
        },
        () = activity.idle_for(idle) => RelayEnd::Idle,
    }
}

/// Send a failure reply to the client.
async fn send_failure(client: &mut TcpStream, protocol: Protocol, failure: Failure) {
    let result = match protocol {
        Protocol::Socks5 => {
            client
                .write_all(&build_socks5_error(failure.socks5_code()))
                .await
        }
        Protocol::HttpConnect => client.write_all(failure.http_response()).await,
    };
    // The proxy closes the connection after a failure. If the client does not
    // get the reply, it sees the close, thus the write error is not important.
    if let Err(e) = result {
        debug!(error = %e, "failed to send the failure reply to the client");
    }
}

/// Send the success reply to the client.
async fn send_success(client: &mut TcpStream, protocol: Protocol, dest: &TcpStream) -> Result<()> {
    let reply = match protocol {
        Protocol::Socks5 => {
            let local_addr = dest.local_addr().unwrap_or_else(|_| {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            });
            build_socks5_response(local_addr)
        }
        Protocol::HttpConnect => b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
    };
    client
        .write_all(&reply)
        .await
        .map_err(|e| ProxyError::Internal(format!("Failed to send {protocol} success: {e}")))
}

/// Read the proxy handshake of a client.
async fn negotiate<S>(client: &mut S) -> std::result::Result<Negotiated, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Peek at the first byte to determine the protocol.
    let first = client.read_u8().await.map_err(|e| {
        HandshakeError::new(
            Protocol::HttpConnect,
            None,
            ProxyError::Internal(format!("Failed to read protocol byte: {e}")),
        )
    })?;

    if first == socks5::VERSION {
        negotiate_socks5(client).await
    } else {
        negotiate_http_connect(client, first).await
    }
}

/// Read the SOCKS5 greeting and request (the version byte was already read).
async fn negotiate_socks5<S>(client: &mut S) -> std::result::Result<Negotiated, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io_error = |what: &str, e: std::io::Error| {
        HandshakeError::new(
            Protocol::Socks5,
            None,
            ProxyError::Internal(format!("Failed to {what}: {e}")),
        )
    };

    // Read NMETHODS and the METHODS list with read_exact. A plain read()
    // can consume the CONNECT request too when the greeting and the request
    // arrive in the same TCP segment.
    let nmethods = client
        .read_u8()
        .await
        .map_err(|e| io_error("read SOCKS5 nmethods", e))?;
    let mut methods = vec![0u8; usize::from(nmethods)];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|e| io_error("read SOCKS5 methods", e))?;

    if !methods.contains(&socks5::METHOD_NO_AUTH) {
        // The write result is not important: the proxy closes the connection.
        if let Err(e) = client
            .write_all(&[socks5::VERSION, socks5::METHOD_NONE_ACCEPTABLE])
            .await
        {
            debug!(error = %e, "failed to send the SOCKS5 method rejection");
        }
        return Err(HandshakeError::new(
            Protocol::Socks5,
            None,
            ProxyError::Internal("SOCKS5 client does not offer the no-auth method".to_string()),
        ));
    }

    client
        .write_all(&[socks5::VERSION, socks5::METHOD_NO_AUTH])
        .await
        .map_err(|e| io_error("send SOCKS5 greeting response", e))?;

    let request = read_socks5_request(client).await?;
    if request.cmd != socks5::CMD_CONNECT {
        return Err(HandshakeError::new(
            Protocol::Socks5,
            Some(Failure::CommandNotSupported),
            ProxyError::Internal(format!(
                "Unsupported SOCKS5 command: {} (only CONNECT supported)",
                request.cmd
            )),
        ));
    }

    Ok(Negotiated {
        protocol: Protocol::Socks5,
        target: request.target,
        initial: Vec::new(),
    })
}

/// Read one SOCKS5 request with exact reads: first the fixed header, then
/// the address fields that the address type requires.
///
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
async fn read_socks5_request<R>(
    reader: &mut R,
) -> std::result::Result<Socks5Request, HandshakeError>
where
    R: AsyncRead + Unpin,
{
    let short = |e: std::io::Error| {
        HandshakeError::new(
            Protocol::Socks5,
            Some(Failure::General),
            ProxyError::Internal(format!("Failed to read SOCKS5 request: {e}")),
        )
    };

    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await.map_err(short)?;
    let [version, cmd, _reserved, atyp] = header;
    if version != socks5::VERSION {
        return Err(HandshakeError::new(
            Protocol::Socks5,
            Some(Failure::General),
            ProxyError::Internal(format!("Invalid SOCKS5 version: {version}")),
        ));
    }

    let target = match atyp {
        socks5::ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            reader.read_exact(&mut addr).await.map_err(short)?;
            let port = reader.read_u16().await.map_err(short)?;
            Target::Ip(SocketAddr::new(IpAddr::from(addr), port))
        }
        socks5::ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            reader.read_exact(&mut addr).await.map_err(short)?;
            let port = reader.read_u16().await.map_err(short)?;
            Target::Ip(SocketAddr::new(IpAddr::from(addr), port))
        }
        socks5::ATYP_DOMAIN => {
            let len = reader.read_u8().await.map_err(short)?;
            let mut name = vec![0u8; usize::from(len)];
            reader.read_exact(&mut name).await.map_err(short)?;
            let port = reader.read_u16().await.map_err(short)?;
            let host = String::from_utf8(name).map_err(|_| {
                HandshakeError::new(
                    Protocol::Socks5,
                    Some(Failure::NotAllowed),
                    ProxyError::Internal("Invalid domain encoding".to_string()),
                )
            })?;
            Target::Domain { host, port }
        }
        other => {
            return Err(HandshakeError::new(
                Protocol::Socks5,
                Some(Failure::AddressTypeNotSupported),
                ProxyError::Internal(format!("Unknown address type: {other}")),
            ));
        }
    };

    Ok(Socks5Request { cmd, target })
}

/// Read an HTTP CONNECT request (the first byte was already read).
///
/// Reads the full `CONNECT host:port HTTP/1.1\r\n…\r\n\r\n` request. The
/// bytes after the end of the headers go into [`Negotiated::initial`].
async fn negotiate_http_connect<S>(
    client: &mut S,
    first_byte: u8,
) -> std::result::Result<Negotiated, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let fail = |failure, message: String| {
        HandshakeError::new(
            Protocol::HttpConnect,
            Some(failure),
            ProxyError::Internal(message),
        )
    };

    let mut buf = vec![first_byte];
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos.saturating_add(4);
        }
        if buf.len() > inspect::MAX_HTTP_HEAD_LEN {
            return Err(fail(
                Failure::General,
                "HTTP CONNECT request head is too long".to_string(),
            ));
        }
        let n = client
            .read(&mut tmp)
            .await
            .map_err(|e| fail(Failure::General, format!("HTTP CONNECT read error: {e}")))?;
        if n == 0 {
            return Err(HandshakeError::new(
                Protocol::HttpConnect,
                None,
                ProxyError::Internal("HTTP CONNECT: the client closed the connection".to_string()),
            ));
        }
        buf.extend_from_slice(tmp.get(..n).unwrap_or_default());
    };

    let initial = buf.split_off(head_end.min(buf.len()));
    let header = std::str::from_utf8(&buf).map_err(|_| {
        fail(
            Failure::General,
            "HTTP CONNECT: non-UTF8 request".to_string(),
        )
    })?;
    let first_line = header.lines().next().unwrap_or("");
    let target = parse_http_connect_target(first_line).map_err(|e| HandshakeError {
        protocol: Protocol::HttpConnect,
        failure: Some(Failure::General),
        error: e,
    })?;

    Ok(Negotiated {
        protocol: Protocol::HttpConnect,
        target,
        initial,
    })
}

/// Parse "CONNECT host:port HTTP/1.x" into a [`Target`].
///
/// An IP literal (`1.2.3.4:443` or `[2001:db8::1]:443`) gives an IP target.
fn parse_http_connect_target(line: &str) -> Result<Target> {
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

    let port = port_str
        .parse::<u16>()
        .map_err(|_| ProxyError::Internal(format!("HTTP CONNECT invalid port: {port_str:?}")))?;

    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(Target::Ip(SocketAddr::new(ip, port)));
    }

    Ok(Target::Domain {
        host: host.to_string(),
        port,
    })
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
    response.push(socks5::VERSION); // Version
    response.push(socks5::SUCCEEDED); // Reply
    response.push(0x00); // Reserved

    match bound_addr {
        SocketAddr::V4(addr) => {
            response.push(socks5::ATYP_IPV4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(socks5::ATYP_IPV6);
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
        socks5::VERSION,
        code, // Reply code
        0x00, // Reserved
        socks5::ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00, // Address: 0.0.0.0
        0x00,
        0x00, // Port: 0
    ]
}

/// SOCKS5 protocol constants.
mod socks5 {
    pub(super) const VERSION: u8 = 0x05;
    pub(super) const METHOD_NO_AUTH: u8 = 0x00;
    pub(super) const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
    pub(super) const CMD_CONNECT: u8 = 0x01;
    pub(super) const ATYP_IPV4: u8 = 0x01;
    pub(super) const ATYP_DOMAIN: u8 = 0x03;
    pub(super) const ATYP_IPV6: u8 = 0x04;

    pub(super) const SUCCEEDED: u8 = 0x00;
    pub(super) const GENERAL_FAILURE: u8 = 0x01;
    pub(super) const CONNECTION_NOT_ALLOWED: u8 = 0x02;
    #[cfg(test)]
    pub(super) const NETWORK_UNREACHABLE: u8 = 0x03;
    #[cfg(test)]
    pub(super) const HOST_UNREACHABLE: u8 = 0x04;
    pub(super) const CONNECTION_REFUSED: u8 = 0x05;
    pub(super) const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub(super) const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[cfg(test)]
#[allow(clippy::items_after_statements)] // use statements in test fns after let bindings
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test infrastructure: parse on known-good literals
mod tests {
    use super::*;

    async fn tcp_listener_or_skip(addr: &str) -> Option<tokio::net::TcpListener> {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                crate::test_support::skip("this machine cannot bind a TCP socket on the loopback");
                None
            }
            Err(err) => panic!("Failed to bind TCP listener for test: {err}"),
        }
    }

    /// Return true if the proxy still speaks SOCKS5 on `addr`.
    ///
    /// The tests that send odd traffic use this to prove that the proxy
    /// survives it. Without this check such a test asserts nothing.
    async fn proxy_answers_greeting(addr: std::net::SocketAddr) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok(Ok(mut stream)) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        else {
            return false;
        };
        // The greeting of SOCKS5: version 5, one method, "no authentication".
        if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
            return false;
        }
        let mut answer = [0u8; 2];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut answer),
        )
        .await;
        matches!(read, Ok(Ok(2))) && answer == [0x05, 0x00]
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
    /// The time that a test waits for data from the proxy.
    const REPLY_LIMIT: Duration = Duration::from_secs(5);

    /// Read exactly `buf.len()` bytes, with a time limit.
    ///
    /// A test that waits for a reply that the proxy does not send must
    /// fail. Without the limit the whole test binary stops.
    async fn read_exact_in_time<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) {
        match tokio::time::timeout(REPLY_LIMIT, stream.read_exact(buf)).await {
            Ok(Ok(n)) => assert_eq!(n, buf.len(), "the proxy sent too few bytes"),
            Ok(Err(e)) => panic!("the read from the proxy failed: {e}"),
            Err(_) => panic!("the proxy sent no reply in {REPLY_LIMIT:?}"),
        }
    }

    /// Read one block of data, with a time limit. Returns the number of
    /// bytes; zero is the end of the data.
    async fn read_in_time<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> usize {
        match tokio::time::timeout(REPLY_LIMIT, stream.read(buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("the read from the proxy failed: {e}"),
            Err(_) => panic!("the proxy sent nothing in {REPLY_LIMIT:?}"),
        }
    }

    /// Read until the end of the data, with a time limit.
    async fn read_to_end_in_time<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) {
        match tokio::time::timeout(REPLY_LIMIT, stream.read_to_end(buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("the read from the proxy failed: {e}"),
            Err(_) => panic!("the proxy did not close the connection in {REPLY_LIMIT:?}"),
        }
    }

    async fn socks5_connect(stream: &mut tokio::net::TcpStream, dest: std::net::SocketAddr) {
        use tokio::io::AsyncWriteExt;

        // Greeting: SOCKS5, one method, no-auth
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut resp = [0u8; 2];
        read_exact_in_time(stream, &mut resp).await;
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
        read_exact_in_time(stream, &mut header).await;
        assert_eq!(header[0], 0x05, "Expected SOCKS5 version in reply");
        assert_eq!(header[1], 0x00, "Expected SUCCEEDED reply");

        // Consume bound address
        let remaining = match header[3] {
            0x01 => 4 + 2,  // IPv4 + port
            0x04 => 16 + 2, // IPv6 + port
            t => panic!("Unexpected ATYP in CONNECT reply: {t}"),
        };
        let mut buf = vec![0u8; remaining];
        read_exact_in_time(stream, &mut buf).await;
    }

    /// Parse a SOCKS5 request from a byte slice.
    async fn parse_request(data: &[u8]) -> Result<SocketAddr> {
        let mut reader = data;
        match read_socks5_request(&mut reader).await {
            Ok(Socks5Request {
                cmd: socks5::CMD_CONNECT,
                target: Target::Ip(addr),
            }) => Ok(addr),
            Ok(other) => Err(ProxyError::Internal(format!(
                "unexpected request {other:?}"
            ))),
            Err(e) => Err(e.error),
        }
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

    // `TcpProxy::new` has no fallible step, so a test of its `Ok` cannot
    // fail. `test_tcp_proxy_new_initializes_connection_count` covers the
    // constructor.

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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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

    #[tokio::test]
    async fn test_socks5_request_parsing_ipv4() {
        // SOCKS5 CONNECT request: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), IP, PORT
        let request = [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50]; // 192.168.1.1:80
        let addr = parse_request(&request).await.unwrap();

        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 80);
    }

    #[tokio::test]
    async fn test_socks5_request_parsing_ipv6() {
        // SOCKS5 CONNECT request with IPv6: ATYP=4
        let mut request = vec![0x05, 0x01, 0x00, 0x04];
        // ::1 in 16 bytes
        request.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        request.extend_from_slice(&[0x01, 0xBB]); // Port 443

        let addr = parse_request(&request).await.unwrap();
        assert!(addr.ip().is_ipv6());
        assert_eq!(addr.port(), 443);
    }

    #[tokio::test]
    async fn test_socks5_request_parsing_domain() {
        // SOCKS5 CONNECT request with domain: ATYP=3
        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        let domain = b"example.com";
        #[allow(clippy::cast_possible_truncation)]
        request.push(domain.len() as u8);
        request.extend_from_slice(domain);
        request.extend_from_slice(&[0x01, 0xBB]); // Port 443

        // The parser gives the host name as the client sent it. The proxy
        // resolves the name later, after the allowlist permits it.
        let mut reader = request.as_slice();
        let parsed = read_socks5_request(&mut reader).await;
        let Ok(parsed) = parsed else {
            panic!("the parser must accept a request with a domain");
        };
        assert_eq!(parsed.cmd, socks5::CMD_CONNECT);
        assert_eq!(
            parsed.target,
            Target::Domain {
                host: "example.com".to_string(),
                port: 443,
            }
        );
    }

    #[tokio::test]
    async fn test_socks5_request_parsing_invalid_version() {
        // SOCKS4 request (version 4 instead of 5)
        let request = [0x04, 0x01, 0x00, 0x50, 192, 168, 1, 1, 0x00];
        let result = parse_request(&request).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_request_parsing_unsupported_command() {
        // SOCKS5 BIND request (CMD=2) - not supported
        let request = [0x05, 0x02, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50];
        let result = parse_request(&request).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks5_request_parsing_truncated() {
        // Truncated request (missing port)
        let request = [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1];
        let result = parse_request(&request).await;

        assert!(result.is_err());
    }

    #[test]

    fn test_socks5_response_success() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let _proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();

        let bound_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let response = build_socks5_response(bound_addr);

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

        let response = build_socks5_error(socks5::CONNECTION_REFUSED);
        assert_eq!(response[0], 0x05); // VER
        assert_eq!(response[1], socks5::CONNECTION_REFUSED); // REP

        let response = build_socks5_error(socks5::HOST_UNREACHABLE);
        assert_eq!(response[1], socks5::HOST_UNREACHABLE);

        let response = build_socks5_error(socks5::COMMAND_NOT_SUPPORTED);
        assert_eq!(response[1], socks5::COMMAND_NOT_SUPPORTED);
    }

    // ========================================================================
    // Data Relay Tests
    // ========================================================================

    // A relay test needs more than one thread: a mutant that makes `pump`
    // loop without end must fail the test, not stop the whole test binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            private_destinations: PrivateDestinations::Allow,
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
        let n = read_in_time(&mut client, &mut response).await;

        assert_eq!(&response[..n], test_data);

        proxy_handle.abort();
        echo_handle.abort();
    }

    // A relay test needs more than one thread: a mutant that makes `pump`
    // loop without end must fail the test, not stop the whole test binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            private_destinations: PrivateDestinations::Allow,
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
        read_to_end_in_time(&mut client, &mut response).await;

        assert_eq!(response.len(), large_data.len());

        proxy_handle.abort();
        server_handle.abort();
    }

    // A relay test needs more than one thread: a mutant that makes `pump`
    // loop without end must fail the test, not stop the whole test binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            private_destinations: PrivateDestinations::Allow,
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

        // The assertion lives in the task of the server, so the test must
        // join it. A dropped join result hides a panic in the task.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;
        proxy_handle.abort();
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("the destination did not see the FIN of the client: {e}"),
            Err(_) => panic!("the destination did not see the FIN of the client after 5 s"),
        }
    }

    // A relay test needs more than one thread: a mutant that makes `pump`
    // loop without end must fail the test, not stop the whole test binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_destination_closes_first() {
        use crate::{ResolvedAddress, SharedState};

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
            private_destinations: PrivateDestinations::Allow,
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
        let n = read_in_time(&mut client, &mut buf).await;
        assert_eq!(n, 0); // EOF

        // The task of the destination accepts the connection; a panic in
        // it must fail the test.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;
        proxy_handle.abort();
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("the destination task failed: {e}"),
            Err(_) => panic!("the destination task did not end after 5 s"),
        }
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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
            private_destinations: PrivateDestinations::Allow,
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

        let config = TcpProxyConfig {
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config, state).unwrap();
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
            private_destinations: PrivateDestinations::Allow,
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

        assert!(
            proxy_answers_greeting(config.bind_addr).await,
            "the proxy must still answer a SOCKS5 greeting after this traffic"
        );

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
            private_destinations: PrivateDestinations::Allow,
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

        assert!(
            proxy_answers_greeting(config.bind_addr).await,
            "the proxy must still answer a SOCKS5 greeting after this traffic"
        );

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
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let proxy = TcpProxy::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        if let Ok(mut stream) = TcpStream::connect(config.bind_addr).await {
            // Half-close: shutdown write side
            let _ = stream.shutdown().await;
        }

        assert!(
            proxy_answers_greeting(config.bind_addr).await,
            "the proxy must still answer a SOCKS5 greeting after this traffic"
        );

        handle.abort();
        let _ = handle.await;
    }

    // ========================================================================
    // Connection Counter Safety Tests
    // ========================================================================

    /// The connection counter is an `Arc<AtomicUsize>` that the accept loop
    /// shares with each connection task. An earlier version used a raw
    /// pointer, which an abort of `run()` turned into a dangling reference.
    ///
    /// The test asserts the count at each step:
    /// 1. zero before the first connection;
    /// 2. one for each open connection while the proxy runs;
    /// 3. zero after the abort of `run()`, which ends each connection
    ///    task. The read of the counter after the abort is safe, because
    ///    each task holds its own `Arc`.
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
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };

        let proxy = TcpProxy::new(config.clone(), state).unwrap();
        // The counter of the proxy, so the test can read it after the
        // accept loop moves into its own task.
        let counter = Arc::clone(&proxy.connection_count);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        let handle = tokio::spawn(async move { proxy.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Open five connections that start the SOCKS5 greeting and never
        // finish it. Each one keeps a task of the proxy busy.
        let mut streams = Vec::new();
        for _ in 0..5 {
            if let Ok(mut stream) = TcpStream::connect(config.bind_addr).await {
                let _ = stream.write_all(&[0x05, 0x01, 0x00]).await;
                streams.push(stream);
            }
        }
        assert_eq!(streams.len(), 5, "the test could not open the connections");
        wait_for_count(&counter, 5).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            5,
            "the counter must hold one entry for each open connection"
        );

        // `run()` owns the task set, so the abort ends each connection
        // task. Every guard gives its entry back, and the counter is still
        // readable: each task holds its own `Arc`.
        handle.abort();
        let _ = handle.await;
        wait_for_count(&counter, 0).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "an aborted connection task must give its entry back"
        );

        for mut stream in streams {
            let _ = stream.shutdown().await;
        }
    }

    /// Wait up to two seconds until `counter` holds `want`.
    async fn wait_for_count(counter: &Arc<AtomicUsize>, want: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while counter.load(Ordering::Relaxed) != want && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // ========================================================================
    // Hardening Tests
    // ========================================================================

    /// Start a proxy on a free port. Returns `None` if the test cannot bind.
    async fn start_proxy(
        state: Arc<crate::SharedState>,
        config: TcpProxyConfig,
    ) -> Option<(SocketAddr, tokio::task::JoinHandle<Result<()>>)> {
        let listener = tcp_listener_or_skip("127.0.0.1:0").await?;
        let addr = listener.local_addr().unwrap();
        let proxy = TcpProxy::new(config, state).unwrap();
        let handle = tokio::spawn(async move { proxy.run_on(listener).await });
        Some((addr, handle))
    }

    /// A state with a trace channel.
    fn traced_state(
        allowlist: &[&str],
    ) -> (
        Arc<crate::SharedState>,
        tokio::sync::mpsc::UnboundedReceiver<crate::TraceEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let state = Arc::new(crate::SharedState::with_violation_tx(
            allowlist.iter().map(|s| (*s).to_string()).collect(),
            Some(tx),
        ));
        (state, rx)
    }

    fn cache(state: &crate::SharedState, domain: &str, ip: IpAddr) {
        state.cache.insert(crate::ResolvedAddress {
            domain: domain.to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + Duration::from_secs(300),
        });
    }

    /// Send a SOCKS5 greeting and a raw request, and return the reply code.
    async fn socks5_reply_code(proxy: SocketAddr, request: &[u8]) -> u8 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        reply[1]
    }

    /// Collect the trace messages that are in the channel now.
    fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::TraceEvent>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            out.push(match event {
                crate::TraceEvent::Access(m) => format!("access {m}"),
                crate::TraceEvent::Violation(m) => format!("violation {m}"),
            });
        }
        out
    }

    #[tokio::test]
    async fn test_private_ip_rejected_even_if_cached() {
        let (state, mut rx) = traced_state(&["test.local"]);
        cache(&state, "test.local", "127.0.0.1".parse().unwrap());
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };

        let code =
            socks5_reply_code(proxy, &[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 22]).await;
        assert_eq!(code, socks5::CONNECTION_NOT_ALLOWED);

        let messages = drain(&mut rx);
        assert!(
            messages
                .iter()
                .any(|m| m.starts_with("violation network: SOCKS5")
                    && m.contains("127.0.0.1 port 22")
                    && m.contains("loopback")),
            "{messages:?}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_private_ipv4_mapped_ipv6_rejected() {
        let (state, _rx) = traced_state(&["test.local"]);
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        cache(&state, "test.local", mapped);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let result = proxy.verify_destination(&SocketAddr::new(mapped, 443));
        assert!(matches!(
            result,
            Err(ProxyError::NonPublicDestination { .. })
        ));
    }

    #[tokio::test]
    async fn test_domain_resolving_to_loopback_rejected() {
        // "localhost" resolves to a loopback address without network access.
        // This is the DNS rebinding case: an allowed name points at the host.
        let (state, mut rx) = traced_state(&["localhost"]);
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };

        let mut request = vec![0x05, 0x01, 0x00, 0x03, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&80u16.to_be_bytes());
        let code = socks5_reply_code(proxy, &request).await;
        assert_eq!(code, socks5::CONNECTION_NOT_ALLOWED);

        let messages = drain(&mut rx);
        assert!(
            messages
                .iter()
                .any(|m| m.contains("\"localhost\" port 80 blocked") && m.contains("loopback")),
            "{messages:?}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_socks5_bind_and_udp_associate_rejected() {
        let (state, _rx) = traced_state(&["example.com"]);
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };

        // BIND on the domain path.
        let mut bind = vec![0x05, 0x02, 0x00, 0x03, 11];
        bind.extend_from_slice(b"example.com");
        bind.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            socks5_reply_code(proxy, &bind).await,
            socks5::COMMAND_NOT_SUPPORTED
        );

        // UDP ASSOCIATE on the IP path.
        let udp = [0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35];
        assert_eq!(
            socks5_reply_code(proxy, &udp).await,
            socks5::COMMAND_NOT_SUPPORTED
        );

        // An unknown address type.
        let bad_atyp = [0x05, 0x01, 0x00, 0x09, 0, 0];
        assert_eq!(
            socks5_reply_code(proxy, &bad_atyp).await,
            socks5::ADDRESS_TYPE_NOT_SUPPORTED
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_socks5_no_acceptable_method() {
        let (state, _rx) = traced_state(&[]);
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };
        let mut client = TcpStream::connect(proxy).await.unwrap();
        // Offer only username/password authentication (0x02).
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
        handle.abort();
    }

    #[tokio::test]
    async fn test_read_socks5_request_from_split_reads() {
        // The request arrives in many small pieces.
        let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());

        let (mut writer, mut reader) = tokio::io::duplex(8);
        let bytes = request.clone();
        let feeder = tokio::spawn(async move {
            for byte in bytes {
                writer.write_all(&[byte]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            writer
        });
        let Ok(parsed) = read_socks5_request(&mut reader).await else {
            panic!("split request did not parse");
        };
        assert_eq!(
            parsed,
            Socks5Request {
                cmd: socks5::CMD_CONNECT,
                target: Target::Domain {
                    host: "example.com".to_string(),
                    port: 443
                },
            }
        );
        drop(feeder.await.unwrap());
    }

    // A relay test needs more than one thread: a mutant that makes `pump`
    // loop without end must fail the test, not stop the whole test binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_split_socks5_request_through_proxy() {
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
        });

        let (state, _rx) = traced_state(&["test.local"]);
        cache(&state, "test.local", dest.ip());
        let config = TcpProxyConfig {
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let Some((proxy, handle)) = start_proxy(state, config).await else {
            return;
        };

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.set_nodelay(true).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        read_exact_in_time(&mut client, &mut greeting).await;

        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        if let IpAddr::V4(ip) = dest.ip() {
            request.extend_from_slice(&ip.octets());
        }
        request.extend_from_slice(&dest.port().to_be_bytes());
        for byte in request {
            client.write_all(&[byte]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut reply = [0u8; 10];
        read_exact_in_time(&mut client, &mut reply).await;
        assert_eq!(reply[1], socks5::SUCCEEDED);

        client.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        read_exact_in_time(&mut client, &mut echo).await;
        assert_eq!(&echo, b"ping");

        handle.abort();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_timeout_closes_silent_client() {
        let (state, _rx) = traced_state(&[]);
        let config = TcpProxyConfig {
            handshake_timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let addr = listener.local_addr().unwrap();
        let proxy = Arc::new(TcpProxy::new(config, state).unwrap());
        let runner = Arc::clone(&proxy);
        let handle = tokio::spawn(async move { runner.run_on(listener).await });

        // A slowloris client: it sends one byte and then nothing.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05]).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(proxy.connection_count(), 0);
        handle.abort();
    }

    #[tokio::test]
    async fn test_http_connect_forwards_trailing_bytes() {
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            socket.read_exact(&mut buf).await.unwrap();
            buf
        });

        let (state, mut rx) = traced_state(&["localhost"]);
        let config = TcpProxyConfig {
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let Some((proxy, handle)) = start_proxy(state, config).await else {
            return;
        };

        let mut client = TcpStream::connect(proxy).await.unwrap();
        let request = format!(
            "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\nHELLO",
            port = dest.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut response = vec![0u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");

        let received = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"HELLO");

        let messages = drain(&mut rx);
        assert!(
            messages.iter().any(|m| m
                == &format!(
                    "access network: CONNECT connection to \"localhost\" port {} allowed",
                    dest.port()
                )),
            "{messages:?}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_http_connect_blocked_domain_reports_port_and_protocol() {
        let (state, mut rx) = traced_state(&["allowed.com"]);
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"CONNECT evil.com:8443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        let messages = drain(&mut rx);
        assert!(
            messages.iter().any(|m| m.starts_with(
                "violation network: CONNECT connection to \"evil.com\" port 8443 blocked"
            )),
            "{messages:?}"
        );
        handle.abort();
    }

    /// An HTTP CONNECT to a port that refuses the connection gets 502.
    /// The client must see that the destination refused, not that the
    /// policy blocked the name.
    #[tokio::test]
    async fn an_http_connect_to_a_closed_port_gets_502() {
        // A port that nothing listens on: bind it, read the number, close.
        let Some(closed) = get_free_port().await else {
            return;
        };
        let (state, mut rx) = traced_state(&["localhost"]);
        let config = TcpProxyConfig {
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let Some((proxy, handle)) = start_proxy(state, config).await else {
            return;
        };
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let request = format!(
            "CONNECT localhost:{port} HTTP/1.1\r\n\r\n",
            port = closed.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 502"),
            "the client must see 502: {}",
            String::from_utf8_lossy(&response)
        );
        // The policy allowed the name; only the destination refused.
        let messages = drain(&mut rx);
        assert!(
            messages.iter().any(|m| m.starts_with("access ")),
            "the policy must allow the name: {messages:?}"
        );
        handle.abort();
    }

    #[test]
    fn test_parse_http_connect_target_ip_literal() {
        let target = parse_http_connect_target("CONNECT [2001:db8::1]:443 HTTP/1.1").unwrap();
        assert_eq!(target, Target::Ip("[2001:db8::1]:443".parse().unwrap()));
        let target = parse_http_connect_target("CONNECT 1.2.3.4:80 HTTP/1.1").unwrap();
        assert_eq!(target, Target::Ip("1.2.3.4:80".parse().unwrap()));
        let target = parse_http_connect_target("CONNECT Example.com:443 HTTP/1.1").unwrap();
        assert_eq!(
            target,
            Target::Domain {
                host: "Example.com".to_string(),
                port: 443
            }
        );
    }

    #[tokio::test]
    async fn test_non_ascii_socks5_domain_rejected() {
        // The Kelvin sign lowercases to "k" with Unicode rules.
        let (state, mut rx) = traced_state(&["kelvin.com"]);
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };
        let name = "\u{212a}elvin.com".as_bytes();
        let mut request = vec![0x05, 0x01, 0x00, 0x03, u8::try_from(name.len()).unwrap()];
        request.extend_from_slice(name);
        request.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            socks5_reply_code(proxy, &request).await,
            socks5::CONNECTION_NOT_ALLOWED
        );
        let messages = drain(&mut rx);
        assert!(
            messages.iter().any(|m| m.contains("non-ASCII")),
            "{messages:?}"
        );
        handle.abort();
    }

    #[test]
    fn test_check_requested_host_sni() {
        use crate::inspect::tests::client_hello;
        let (state, mut rx) = traced_state(&["allowed.com", "cdn.allowed.com"]);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let target = Target::Ip("93.184.216.34:443".parse().unwrap());

        let ok = client_hello(Some("cdn.allowed.com"));
        assert!(proxy
            .check_requested_host(Protocol::Socks5, &target, Inspect::Tls, &ok)
            .is_ok());

        // No SNI (for example ECH): only the IP-cache check applies.
        let none = client_hello(None);
        assert!(proxy
            .check_requested_host(Protocol::Socks5, &target, Inspect::Tls, &none)
            .is_ok());

        // Domain fronting: an allowed IP with a SNI that is not allowed.
        let fronted = client_hello(Some("evil.example"));
        assert!(proxy
            .check_requested_host(Protocol::Socks5, &target, Inspect::Tls, &fronted)
            .is_err());
        let messages = drain(&mut rx);
        assert!(
            messages.iter().any(
                |m| m.contains("TLS SNI \"evil.example\" is not in the allowlist")
                    && m.contains("93.184.216.34 port 443")
            ),
            "{messages:?}"
        );
    }

    #[test]
    fn test_check_requested_host_http() {
        let (state, _rx) = traced_state(&["allowed.com"]);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        let target = Target::Ip("93.184.216.34:80".parse().unwrap());
        let ok = b"GET / HTTP/1.1\r\nHost: Allowed.com\r\n\r\n";
        let bad = b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        assert!(proxy
            .check_requested_host(Protocol::HttpConnect, &target, Inspect::Http, ok)
            .is_ok());
        assert!(proxy
            .check_requested_host(Protocol::HttpConnect, &target, Inspect::Http, bad)
            .is_err());
    }

    // A relay test needs more than one thread: a mutant that makes `pump`
    // loop without end must fail the test, not stop the whole test binary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_idle_timeout_resets_on_activity() {
        // The connection lives longer than the idle timeout while data flows,
        // and closes when the data stops.
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let (state, _rx) = traced_state(&["test.local"]);
        cache(&state, "test.local", dest.ip());
        let config = TcpProxyConfig {
            idle_timeout: Duration::from_millis(400),
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let Some((proxy, handle)) = start_proxy(state, config).await else {
            return;
        };
        let mut client = TcpStream::connect(proxy).await.unwrap();
        socks5_connect(&mut client, dest).await;

        // 8 x 150 ms = 1.2 s, three times the idle timeout.
        for _ in 0..8 {
            client.write_all(b"x").await.unwrap();
            let mut echo = [0u8; 1];
            read_exact_in_time(&mut client, &mut echo).await;
            assert_eq!(&echo, b"x");
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        // Now stay silent: the proxy must close the connection.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
        handle.abort();
    }

    /// `pump` copies each block of data and stops at the end of the data.
    /// A read of zero bytes is the end; every other read is data.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pump_copies_the_data_and_stops_at_the_end() {
        let (mut source, reader) = tokio::io::duplex(64);
        let (writer, mut sink) = tokio::io::duplex(64);
        source.write_all(b"hello").await.unwrap();
        drop(source); // The end of the data.

        let activity = Activity::new();
        let pumped = tokio::time::timeout(REPLY_LIMIT, pump(reader, writer, &activity)).await;
        assert!(
            matches!(pumped, Ok(Ok(()))),
            "pump must stop at the end of the data: {pumped:?}"
        );

        let mut copied = Vec::new();
        read_to_end_in_time(&mut sink, &mut copied).await;
        assert_eq!(copied, b"hello", "pump must copy each block");
    }

    #[tokio::test]
    async fn test_relay_streams_reports_idle() {
        let (client_a, _client_b) = tokio::io::duplex(64);
        let (dest_a, _dest_b) = tokio::io::duplex(64);
        let (cr, cw) = tokio::io::split(client_a);
        let (dr, dw) = tokio::io::split(dest_a);
        let start = std::time::Instant::now();
        let end = relay_streams(cr, cw, dr, dw, Duration::from_millis(100)).await;
        assert!(matches!(end, RelayEnd::Idle), "{end:?}");
        assert!(start.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_ip_path_access_event_names_domain() {
        let Some(listener) = tcp_listener_or_skip("127.0.0.1:0").await else {
            return;
        };
        let dest = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let _accepted = listener.accept().await;
        });
        let (state, mut rx) = traced_state(&["test.local"]);
        cache(&state, "test.local", dest.ip());
        let config = TcpProxyConfig {
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        };
        let Some((proxy, handle)) = start_proxy(state, config).await else {
            return;
        };
        let mut client = TcpStream::connect(proxy).await.unwrap();
        socks5_connect(&mut client, dest).await;
        let messages = drain(&mut rx);
        assert!(
            messages.iter().any(|m| m
                == &format!(
                "access network: SOCKS5 connection to 127.0.0.1 port {} (\"test.local\") allowed",
                dest.port()
            )),
            "{messages:?}"
        );
        handle.abort();
    }

    // ========================================================================
    // Watch Event Tests
    // ========================================================================

    /// A state with a watch event channel and the policy `policy`.
    fn watched_state(
        allowlist: &[&str],
        policy: ProxyPolicy,
    ) -> (
        Arc<crate::SharedState>,
        tokio::sync::mpsc::UnboundedReceiver<WatchEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let state = crate::SharedState::new(allowlist.iter().map(|s| (*s).to_string()).collect())
            .with_policy(policy)
            .with_event_tx(Some(tx));
        (Arc::new(state), rx)
    }

    /// A proxy configuration that permits private destinations, so that the
    /// tests can use a local listener as the destination.
    fn private_allowed() -> TcpProxyConfig {
        TcpProxyConfig {
            private_destinations: PrivateDestinations::Allow,
            ..Default::default()
        }
    }

    /// Start a local destination that accepts connections and keeps them
    /// open. Returns `None` if the test cannot bind.
    async fn local_destination() -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = tcp_listener_or_skip("127.0.0.1:0").await?;
        let addr = listener.local_addr().ok()?;
        let handle = tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                open.push(stream);
            }
        });
        Some((addr, handle))
    }

    /// True if the system resolver resolves "localhost" without the network.
    async fn localhost_resolves() -> bool {
        tokio::net::lookup_host(("localhost", 0))
            .await
            .is_ok_and(|mut addrs| addrs.next().is_some())
    }

    /// A SOCKS5 CONNECT request for a domain (ATYP=3).
    fn socks5_domain_request(host: &str, port: u16) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00, 0x03, u8::try_from(host.len()).unwrap()];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    /// A SOCKS5 CONNECT request for an IPv4 address.
    fn socks5_ipv4_request(addr: SocketAddr) -> Vec<u8> {
        let IpAddr::V4(ip) = addr.ip() else {
            panic!("the test needs an IPv4 address");
        };
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&addr.port().to_be_bytes());
        request
    }

    /// Send an HTTP CONNECT request and return the status line.
    async fn http_connect_status(proxy: SocketAddr, authority: &str) -> String {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Wait for the next watch event.
    async fn next_event(rx: &mut tokio::sync::mpsc::UnboundedReceiver<WatchEvent>) -> WatchEvent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no watch event in time")
            .expect("the watch channel closed")
    }

    fn connect_event(host: &str, port: u16, protocol: NetProtocol, outcome: Outcome) -> WatchEvent {
        WatchEvent::Connect {
            host: host.to_string(),
            port,
            protocol,
            outcome,
        }
    }

    #[tokio::test]
    async fn test_observe_allows_unlisted_domain_over_socks5() {
        if !localhost_resolves().await {
            return;
        }
        let Some((dest, _server)) = local_destination().await else {
            return;
        };
        let (state, mut rx) = watched_state(&[], ProxyPolicy::Observe);
        let Some((proxy, handle)) = start_proxy(state, private_allowed()).await else {
            return;
        };
        let request = socks5_domain_request("LocalHost", dest.port());
        assert_eq!(socks5_reply_code(proxy, &request).await, socks5::SUCCEEDED);
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "localhost",
                dest.port(),
                NetProtocol::Socks5,
                Outcome::Allowed
            )
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_observe_allows_unlisted_domain_over_http_connect() {
        if !localhost_resolves().await {
            return;
        }
        let Some((dest, _server)) = local_destination().await else {
            return;
        };
        let (state, mut rx) = watched_state(&["other.example"], ProxyPolicy::Observe);
        let Some((proxy, handle)) = start_proxy(state, private_allowed()).await else {
            return;
        };
        let status = http_connect_status(proxy, &format!("localhost:{}", dest.port())).await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "localhost",
                dest.port(),
                NetProtocol::HttpConnect,
                Outcome::Allowed
            )
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_observe_still_denies_private_destination() {
        let Some((dest, _server)) = local_destination().await else {
            return;
        };
        let (state, mut rx) = watched_state(&[], ProxyPolicy::Observe);
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };
        assert_eq!(
            socks5_reply_code(proxy, &socks5_ipv4_request(dest)).await,
            socks5::CONNECTION_NOT_ALLOWED
        );
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "127.0.0.1",
                dest.port(),
                NetProtocol::Socks5,
                Outcome::Denied
            )
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_enforce_emits_denied_and_allowed() {
        if !localhost_resolves().await {
            return;
        }
        let Some((dest, _server)) = local_destination().await else {
            return;
        };
        let (state, mut rx) = watched_state(&["localhost"], ProxyPolicy::Enforce);
        let Some((proxy, handle)) = start_proxy(state, private_allowed()).await else {
            return;
        };

        let status = http_connect_status(proxy, "evil.example:443").await;
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "evil.example",
                443,
                NetProtocol::HttpConnect,
                Outcome::Denied
            )
        );

        let request = socks5_domain_request("localhost", dest.port());
        assert_eq!(socks5_reply_code(proxy, &request).await, socks5::SUCCEEDED);
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "localhost",
                dest.port(),
                NetProtocol::Socks5,
                Outcome::Allowed
            )
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_ip_path_event_uses_cache_domain_or_ip() {
        let Some((dest, _server)) = local_destination().await else {
            return;
        };
        let (state, mut rx) = watched_state(&[], ProxyPolicy::Observe);
        let Some((proxy, handle)) = start_proxy(Arc::clone(&state), private_allowed()).await else {
            return;
        };

        // No cache entry: the event names the IP address.
        assert_eq!(
            socks5_reply_code(proxy, &socks5_ipv4_request(dest)).await,
            socks5::SUCCEEDED
        );
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "127.0.0.1",
                dest.port(),
                NetProtocol::Socks5,
                Outcome::Allowed
            )
        );

        // A cache entry: the event names the domain.
        cache(&state, "api.example", dest.ip());
        assert_eq!(
            socks5_reply_code(proxy, &socks5_ipv4_request(dest)).await,
            socks5::SUCCEEDED
        );
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "api.example",
                dest.port(),
                NetProtocol::Socks5,
                Outcome::Allowed
            )
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_enforce_ip_path_denied_event_uses_cache_domain() {
        let Some((dest, _server)) = local_destination().await else {
            return;
        };
        let (state, mut rx) = watched_state(&[], ProxyPolicy::Enforce);
        cache(&state, "test.local", dest.ip());
        let Some((proxy, handle)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };
        assert_eq!(
            socks5_reply_code(proxy, &socks5_ipv4_request(dest)).await,
            socks5::CONNECTION_NOT_ALLOWED
        );
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(
                "test.local",
                dest.port(),
                NetProtocol::Socks5,
                Outcome::Denied
            )
        );
        handle.abort();
    }

    #[test]
    fn test_sni_names_ip_connection() {
        use crate::inspect::tests::client_hello;
        let target = Target::Ip("93.184.216.34:443".parse().unwrap());
        let hello = client_hello(Some("Evil.Example"));

        // Observe: the SNI does not block, and it names the connection.
        let (state, mut rx) = watched_state(&["allowed.com"], ProxyPolicy::Observe);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), Arc::clone(&state)).unwrap();
        let peeked = proxy
            .check_requested_host(Protocol::Socks5, &target, Inspect::Tls, &hello)
            .unwrap();
        assert_eq!(peeked.as_deref(), Some("evil.example"));
        let mut record = ConnectRecord::new(&state, Protocol::Socks5, &target);
        record.cached = Some("cached.example".to_string());
        record.peeked = peeked;
        assert_eq!(record.host(), "evil.example");
        drop(record);
        assert_eq!(
            rx.try_recv().unwrap(),
            connect_event("evil.example", 443, NetProtocol::Socks5, Outcome::Allowed)
        );
        assert!(rx.try_recv().is_err(), "exactly one event");

        // Enforce: the same SNI blocks the connection.
        let (state, _rx) = watched_state(&["allowed.com"], ProxyPolicy::Enforce);
        let proxy = TcpProxy::new(TcpProxyConfig::default(), state).unwrap();
        assert!(proxy
            .check_requested_host(Protocol::Socks5, &target, Inspect::Tls, &hello)
            .is_err());
    }

    #[test]
    fn test_connect_record_sends_one_event() {
        let (state, mut rx) = watched_state(&[], ProxyPolicy::Enforce);
        let target = Target::Domain {
            host: "Blocked.Example.".to_string(),
            port: 8443,
        };
        let mut record = ConnectRecord::new(&state, Protocol::HttpConnect, &target);
        record.finish(Outcome::Denied);
        record.finish(Outcome::Allowed);
        drop(record);
        assert_eq!(
            rx.try_recv().unwrap(),
            connect_event(
                "blocked.example",
                8443,
                NetProtocol::HttpConnect,
                Outcome::Denied
            )
        );
        assert!(rx.try_recv().is_err(), "exactly one event");
    }

    /// A name that the policy permits but that does not resolve is not a
    /// policy decision. The event keeps the outcome `Allowed`, so the
    /// summary does not show the name as a denial.
    #[tokio::test]
    async fn test_a_name_that_does_not_resolve_keeps_the_allowed_outcome() {
        // RFC 2606 reserves ".invalid". A resolver that answers it anyway
        // would give the proxy a destination, so the test stops there.
        const HOST: &str = "pent-no-such-host.invalid";
        if tokio::net::lookup_host((HOST, 443)).await.is_ok() {
            crate::test_support::skip("this machine resolves a name under \".invalid\"");
            return;
        }
        let (state, mut rx) = watched_state(&[], ProxyPolicy::Observe);
        let Some((proxy, _task)) = start_proxy(state, TcpProxyConfig::default()).await else {
            return;
        };

        let code = socks5_reply_code(proxy, &socks5_domain_request(HOST, 443)).await;
        assert_eq!(
            code,
            socks5::CONNECTION_NOT_ALLOWED,
            "the proxy cannot connect, so it reports a failure"
        );
        assert_eq!(
            next_event(&mut rx).await,
            connect_event(HOST, 443, NetProtocol::Socks5, Outcome::Allowed),
            "the policy permitted the name, so the outcome is Allowed"
        );
    }

    /// The limit of the HTTP CONNECT head is a maximum, not a threshold
    /// that the head reaches. A head of exactly the limit stays, and one
    /// byte more gets the 400 reply.
    #[tokio::test]
    async fn test_http_connect_rejects_a_head_above_the_limit_only() {
        let state = Arc::new(crate::SharedState::new(vec![]));
        let config = TcpProxyConfig {
            handshake_timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let Some((proxy, _task)) = start_proxy(state, config).await else {
            return;
        };

        // A head of exactly the limit is not too long. It has no end, so
        // the proxy closes the connection at the time limit, with no reply.
        let mut head = b"CONNECT ".to_vec();
        head.resize(inspect::MAX_HTTP_HEAD_LEN, b'a');
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&head).await.unwrap();
        let mut answer = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut answer)).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "the proxy answered a head of the maximum length: {read:?} {:?}",
            String::from_utf8_lossy(&answer)
        );

        // One byte more is too long.
        let mut longer = head;
        longer.push(b'b');
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&longer).await.unwrap();
        let mut answer = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut answer)).await;
        assert!(
            read.is_ok(),
            "the proxy did not answer a head that is too long"
        );
        assert!(
            String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400 "),
            "the proxy must answer 400 for a head that is too long: {:?}",
            String::from_utf8_lossy(&answer)
        );
    }
}

/// Property tests of the handshake readers.
///
/// The sandboxed program writes every byte of a SOCKS5 greeting, a SOCKS5
/// request and an HTTP CONNECT request. The properties here hold for each
/// of those byte strings. See `docs/testing/fuzzing-and-coverage.md`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod handshake_properties {
    use super::*;
    use crate::test_support::{rounds, Rng};

    /// The number of inputs that each property test reads by default.
    const ROUNDS: usize = 100_000;

    /// Build a byte string that looks like a SOCKS5 request.
    fn gen_socks5_request(rng: &mut Rng) -> Vec<u8> {
        if rng.one_in(8) {
            let len = rng.below(40);
            return rng.bytes(len);
        }
        let atyp = match rng.below(8) {
            0 => rng.byte(),
            1 | 2 => socks5::ATYP_IPV6,
            3 | 4 => socks5::ATYP_DOMAIN,
            _ => socks5::ATYP_IPV4,
        };
        let version = if rng.one_in(8) {
            rng.byte()
        } else {
            socks5::VERSION
        };
        let cmd = if rng.one_in(4) {
            rng.byte()
        } else {
            socks5::CMD_CONNECT
        };
        let mut out = vec![version, cmd, rng.byte(), atyp];
        match atyp {
            socks5::ATYP_IPV4 => out.extend(rng.bytes(4)),
            socks5::ATYP_IPV6 => out.extend(rng.bytes(16)),
            socks5::ATYP_DOMAIN => {
                let len = rng.below(40);
                #[allow(clippy::cast_possible_truncation, reason = "len is below 40")]
                out.push(len as u8);
                out.extend(rng.bytes(len));
            }
            _ => {
                let len = rng.below(8);
                out.extend(rng.bytes(len));
            }
        }
        out.extend(rng.bytes(2)); // The port.
                                  // Cut the request short sometimes, and add trailing bytes sometimes.
        if rng.one_in(4) {
            let keep = rng.below(out.len().max(1));
            out.truncate(keep);
        } else if rng.one_in(4) {
            let len = rng.below(8);
            out.extend(rng.bytes(len));
        }
        out
    }

    /// Build a byte string that looks like an HTTP CONNECT request head.
    fn gen_http_connect(rng: &mut Rng) -> Vec<u8> {
        if rng.one_in(8) {
            let len = rng.below(60);
            return rng.bytes(len);
        }
        const HOSTS: [&str; 8] = [
            "example.com:443",
            "example.com",
            "[2001:db8::1]:443",
            "127.0.0.1:80",
            "::1:443",
            ":443",
            "a.b.c:0",
            "example.com:99999",
        ];
        let method = if rng.one_in(4) { "GET" } else { "CONNECT" };
        let host = HOSTS.get(rng.below(HOSTS.len())).copied().unwrap_or("");
        let mut text = format!("{method} {host} HTTP/1.1\r\n");
        for _ in 0..rng.below(4) {
            let len = rng.below(12);
            let value: String = (0..len)
                .map(|_| char::from(0x20 | rng.byte() & 0x3F))
                .collect();
            text.push_str(&format!("X-Fuzz: {value}\r\n"));
        }
        if !rng.one_in(8) {
            text.push_str("\r\n");
        }
        let mut out = text.into_bytes();
        if rng.one_in(6) {
            let at = rng.below(out.len().max(1));
            if let Some(byte) = out.get_mut(at) {
                *byte = rng.byte();
            }
        }
        out
    }

    /// `read_socks5_request` must never panic, and the request that it
    /// returns must hold exactly the bytes that the client sent.
    #[tokio::test]
    async fn socks5_request_returns_the_bytes_of_the_client() {
        let mut rng = Rng::new(0x5EED_0101);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let data = gen_socks5_request(&mut rng);
            let mut reader: &[u8] = &data;
            let Ok(request) = read_socks5_request(&mut reader).await else {
                continue;
            };
            checked = checked.saturating_add(1);
            let read = data.len().saturating_sub(reader.len());
            assert_eq!(
                data.first().copied(),
                Some(socks5::VERSION),
                "the reader accepted a request with the wrong version"
            );
            match &request.target {
                Target::Ip(addr) => {
                    let expected = match addr.ip() {
                        IpAddr::V4(_) => 10,
                        IpAddr::V6(_) => 22,
                    };
                    assert_eq!(read, expected, "the reader took the wrong number of bytes");
                    let port = u16::from_be_bytes([
                        *data.get(read.saturating_sub(2)).unwrap(),
                        *data.get(read.saturating_sub(1)).unwrap(),
                    ]);
                    assert_eq!(addr.port(), port, "the port is not the one of the client");
                }
                Target::Domain { host, port } => {
                    let len = usize::from(*data.get(4).unwrap());
                    assert_eq!(
                        host.len(),
                        len,
                        "the host is not the length that the client gave"
                    );
                    assert_eq!(
                        host.as_bytes(),
                        data.get(5..5usize.saturating_add(len)).unwrap(),
                        "the host is not the text that the client sent"
                    );
                    let at = 5usize.saturating_add(len);
                    let expected = u16::from_be_bytes([
                        *data.get(at).unwrap(),
                        *data.get(at.saturating_add(1)).unwrap(),
                    ]);
                    assert_eq!(*port, expected, "the port is not the one of the client");
                    assert_eq!(read, at.saturating_add(2), "the reader took extra bytes");
                }
            }
        }
        assert!(
            checked > total / 10,
            "only {checked} of {total} inputs were a request; the test proves little"
        );
    }

    /// An HTTP CONNECT target that the parser calls a domain must not be an
    /// IP address. The proxy checks a domain against the allowlist and
    /// resolves it; it checks an IP address against the DNS cache. A literal
    /// address that reaches the domain path would take the wrong check.
    #[tokio::test]
    async fn http_connect_never_calls_an_address_a_domain() {
        let mut rng = Rng::new(0x5EED_0102);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let data = gen_http_connect(&mut rng);
            let Some((&first, rest)) = data.split_first() else {
                continue;
            };
            let mut reader: &[u8] = rest;
            let Ok(negotiated) = negotiate_http_connect(&mut reader, first).await else {
                continue;
            };
            checked = checked.saturating_add(1);
            match &negotiated.target {
                Target::Domain { host, .. } => {
                    assert!(
                        host.parse::<IpAddr>().is_err(),
                        "the parser called the address {host:?} a domain"
                    );
                    let bare = host
                        .strip_prefix('[')
                        .and_then(|h| h.strip_suffix(']'))
                        .unwrap_or(host);
                    assert!(
                        bare.parse::<IpAddr>().is_err(),
                        "the parser called the bracketed address {host:?} a domain"
                    );
                }
                Target::Ip(_) => {}
            }
            // The head always ends with the empty line, and the bytes after
            // it go to the destination without a change.
            let head_len = data.len().saturating_sub(negotiated.initial.len());
            assert!(
                data.get(..head_len)
                    .is_some_and(|head| head.ends_with(b"\r\n\r\n")),
                "the reader did not stop at the end of the head"
            );
            assert!(
                head_len <= inspect::MAX_HTTP_HEAD_LEN.saturating_add(4096),
                "the reader kept a head of {head_len} bytes"
            );
        }
        assert!(
            checked > total / 10,
            "only {checked} of {total} inputs were a CONNECT request; the test proves little"
        );
    }

    /// `parse_http_connect_target` must never panic, and it must accept only
    /// a line whose first word is `CONNECT`.
    #[test]
    fn http_connect_target_needs_the_method() {
        let mut rng = Rng::new(0x5EED_0103);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let data = gen_http_connect(&mut rng);
            let Ok(text) = std::str::from_utf8(&data) else {
                continue;
            };
            let line = text.lines().next().unwrap_or("");
            let Ok(target) = parse_http_connect_target(line) else {
                continue;
            };
            checked = checked.saturating_add(1);
            let method = line.split_whitespace().next().unwrap_or("");
            assert!(
                method.eq_ignore_ascii_case("CONNECT"),
                "the parser accepted the method {method:?}"
            );
            // A port of 0 reaches no service, but the parser must not turn
            // it into another port.
            let word = line.split_whitespace().nth(1).unwrap_or("");
            let port_text = word.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
            assert_eq!(
                port_text.parse::<u16>().ok(),
                Some(target.port()),
                "the parser changed the port of {word:?}"
            );
        }
        assert!(
            checked > total / 10,
            "only {checked} of {total} lines were a target; the test proves little"
        );
    }
}
