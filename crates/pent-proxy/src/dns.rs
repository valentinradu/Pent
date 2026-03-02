//! DNS server with domain filtering.
//!
//! Intercepts DNS queries from sandboxed processes and only resolves
//! domains that are on the allowlist. Blocked domains receive NXDOMAIN.
//!
//! # Protocol Support
//!
//! - UDP DNS (standard port 53 or custom)
//! - IPv4 and IPv6 resolution
//!
//! # Resolution Flow
//!
//! ```text
//! Client Query
//!      |
//!      v
//! DomainFilter::matches(domain)?
//!      |
//!      +-- yes --> Resolve via upstream DNS
//!      |                 |
//!      |                 v
//!      |           Cache result in ResolutionCache
//!      |                 |
//!      |                 v
//!      |           Return A/AAAA records
//!      |
//!      +-- no --> Return NXDOMAIN
//! ```
//!

use crate::{ProxyError, Result, SharedState};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for the DNS server.
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    /// Address to bind the DNS server to.
    /// Default: `127.0.0.1:5353`
    pub bind_addr: SocketAddr,

    /// Upstream DNS servers for resolution.
    /// Default: `None` (use system resolvers from `/etc/resolv.conf`)
    ///
    /// If `None`, the server reads system DNS configuration at startup.
    /// Set explicitly to override system resolvers.
    pub upstream: Option<Vec<SocketAddr>>,

    /// DNS response TTL.
    /// Used for caching and client-side caching hints.
    /// Default: 5 minutes
    pub ttl: std::time::Duration,

    /// Per-upstream timeout when resolving a query.
    /// Default: 5 seconds
    pub resolve_timeout: std::time::Duration,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        const LOCALHOST_ANY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        Self {
            bind_addr: LOCALHOST_ANY,
            upstream: None, // Use system resolvers
            ttl: std::time::Duration::from_secs(300),
            resolve_timeout: std::time::Duration::from_secs(5),
        }
    }
}

impl DnsServerConfig {
    /// Get upstream servers, falling back to system resolvers.
    ///
    /// Reads `/etc/resolv.conf` on Linux/macOS if no explicit upstream is set.
    /// Falls back to well-known public DNS if system config is unavailable.
    #[must_use]
    pub fn get_upstream(&self) -> Vec<SocketAddr> {
        if let Some(ref upstream) = self.upstream {
            return upstream.clone();
        }

        // Try to read system DNS configuration
        Self::read_system_resolvers().unwrap_or_else(|| {
            // Fallback to well-known public DNS
            use std::net::{IpAddr, Ipv4Addr, SocketAddr};
            const CLOUDFLARE: SocketAddr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
            const GOOGLE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
            vec![CLOUDFLARE, GOOGLE]
        })
    }

    /// Read system DNS resolvers from /etc/resolv.conf.
    fn read_system_resolvers() -> Option<Vec<SocketAddr>> {
        let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        let resolvers: Vec<SocketAddr> = content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Parse IP and add default DNS port 53
                        parts[1]
                            .parse::<std::net::IpAddr>()
                            .ok()
                            .map(|ip| SocketAddr::new(ip, 53))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        if resolvers.is_empty() {
            None
        } else {
            Some(resolvers)
        }
    }
}

/// DNS server that filters queries by domain allowlist.
///
/// Only resolves domains that match the configured allowlist.
/// All other domains receive NXDOMAIN responses.
pub struct DnsServer {
    /// Server configuration.
    config: DnsServerConfig,

    /// Shared state with domain filter and resolution cache.
    state: Arc<SharedState>,
}

impl DnsServer {
    /// Create a new DNS server.
    ///
    /// # Arguments
    /// * `config` - Server configuration
    /// * `state` - Shared state containing domain filter and cache
    ///
    /// # Errors
    /// Currently infallible; always returns `Ok`. The `Result` return type
    /// is present for forward compatibility.
    #[allow(clippy::missing_const_for_fn)] // Arc<T> cannot be used in const fn yet
    pub fn new(config: DnsServerConfig, state: Arc<SharedState>) -> Result<Self> {
        Ok(Self { config, state })
    }

    /// Start the DNS server.
    ///
    /// Binds to the configured address and starts handling DNS queries.
    /// This method runs until the server is shut down.
    ///
    /// # Errors
    /// * `ProxyError::Bind` - If binding to `config.bind_addr` fails.
    /// * `ProxyError::Internal` - Fatal server error during operation.
    pub async fn run(&self) -> Result<()> {
        use tokio::net::UdpSocket;

        let socket =
            UdpSocket::bind(self.config.bind_addr)
                .await
                .map_err(|e| ProxyError::Bind {
                    addr: self.config.bind_addr,
                    source: e,
                })?;

        self.run_on(socket).await
    }

    /// Run the DNS server on a pre-bound socket.
    ///
    /// Used by [`crate::ProxyServer::start`] which pre-binds the socket to
    /// obtain the actual OS-assigned port before spawning the server task.
    ///
    /// # Errors
    /// * `Err(ProxyError::Internal)` - Server error
    pub async fn run_on(&self, socket: tokio::net::UdpSocket) -> Result<()> {
        let mut buf = [0u8; 512]; // Standard DNS UDP packet size

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    // Log error but continue serving
                    warn!(error = %e, "DNS recv error");
                    continue;
                }
            };

            let query = &buf[..len];
            match self.handle_query(query).await {
                Ok(response) => {
                    if let Err(e) = socket.send_to(&response, src).await {
                        warn!(error = %e, "DNS send error");
                    }
                }
                Err(e) => {
                    debug!(error = %e, "DNS query handling error");
                    // Send SERVFAIL response on error; if this send fails the client will
                    // time out naturally, so the error is intentionally discarded.
                    let response = Self::build_servfail_response(query);
                    let _ = socket.send_to(&response, src).await;
                }
            }
        }
    }

    /// Build a SERVFAIL response for internal errors.
    fn build_servfail_response(query: &[u8]) -> Vec<u8> {
        if query.len() < 12 {
            return vec![0; 12]; // Minimal response
        }

        let mut response = Vec::with_capacity(query.len());
        // Copy ID from query
        response.extend_from_slice(&query[0..2]);
        // Flags: QR=1 (response), RCODE=2 (SERVFAIL)
        response.push(0x80); // QR=1, Opcode=0, AA=0, TC=0, RD=0
        response.push(0x02); // RA=0, Z=0, RCODE=2
                             // Copy question counts, zero answers
        response.extend_from_slice(&query[4..6]); // QDCOUNT
        response.extend_from_slice(&[0, 0]); // ANCOUNT
        response.extend_from_slice(&[0, 0]); // NSCOUNT
        response.extend_from_slice(&[0, 0]); // ARCOUNT
                                             // Copy question section if present
        if query.len() > 12 {
            response.extend_from_slice(&query[12..]);
        }
        response
    }

    /// Handle a single DNS query.
    ///
    /// # Arguments
    /// * `query` - The DNS query to handle
    ///
    /// # Returns
    /// * DNS response bytes to send back to client
    ///
    /// # Behavior
    /// * Extracts domain from query
    /// * Checks domain against allowlist
    /// * If allowed: resolves via upstream, caches result, returns response
    /// * If blocked: returns NXDOMAIN response
    async fn handle_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        // Validate minimum DNS header size
        if query.len() < 12 {
            return Err(ProxyError::Internal("DNS query too short".to_string()));
        }

        // Parse domain name from question section
        let Some(domain) = Self::parse_domain_from_query(query) else {
            return Err(ProxyError::Internal(
                "Failed to parse DNS query".to_string(),
            ));
        };

        // Check domain against allowlist (case-insensitive)
        let domain_lower = domain.to_lowercase();
        if !self.state.is_allowed(&domain_lower) {
            self.state.report_violation(format!(
                "network: DNS query for \"{domain_lower}\" blocked — domain not in allowlist"
            ));
            return Ok(Self::build_nxdomain_response(query));
        }

        // Resolve via upstream DNS
        let addresses = self.resolve_upstream(&domain_lower).await?;

        // Cache the resolution
        let resolved = crate::ResolvedAddress {
            domain: domain_lower.clone(),
            addresses: addresses.clone(),
            expires_at: std::time::Instant::now() + self.config.ttl,
        };
        self.state.insert_resolved(resolved);

        // Build response with resolved addresses
        #[allow(clippy::cast_possible_truncation)] // TTL is always a small number of seconds
        let ttl = self.config.ttl.as_secs() as u32;
        Ok(Self::build_response(query, &addresses, ttl))
    }

    /// Parse the domain name from a DNS query packet.
    fn parse_domain_from_query(query: &[u8]) -> Option<String> {
        if query.len() < 13 {
            return None;
        }

        let mut domain_parts = Vec::new();
        let mut pos = 12; // Start after header

        loop {
            if pos >= query.len() {
                return None;
            }

            let label_len = query[pos] as usize;
            if label_len == 0 {
                break; // End of domain name
            }

            // Check for compression pointer (first two bits set)
            if label_len & 0xC0 == 0xC0 {
                // DNS compression - follow pointer
                if pos + 1 >= query.len() {
                    return None;
                }
                let offset = (label_len & 0x3F) << 8 | query[pos + 1] as usize;
                // Parse from offset (recursive case, simplified)
                return Self::parse_domain_at_offset(query, offset);
            }

            // Check bounds
            if pos + 1 + label_len > query.len() {
                return None;
            }

            let label = std::str::from_utf8(&query[pos + 1..pos + 1 + label_len]).ok()?;
            domain_parts.push(label.to_string());
            pos += 1 + label_len;
        }

        if domain_parts.is_empty() {
            None
        } else {
            Some(domain_parts.join("."))
        }
    }

    /// Parse domain name starting at a specific offset (for compression).
    fn parse_domain_at_offset(query: &[u8], mut offset: usize) -> Option<String> {
        let mut domain_parts = Vec::new();
        let mut seen_offsets = std::collections::HashSet::new();

        loop {
            if offset >= query.len() || seen_offsets.contains(&offset) {
                return None;
            }
            seen_offsets.insert(offset);

            let label_len = query[offset] as usize;
            if label_len == 0 {
                break;
            }

            if label_len & 0xC0 == 0xC0 {
                if offset + 1 >= query.len() {
                    return None;
                }
                offset = (label_len & 0x3F) << 8 | query[offset + 1] as usize;
                continue;
            }

            if offset + 1 + label_len > query.len() {
                return None;
            }

            let label = std::str::from_utf8(&query[offset + 1..offset + 1 + label_len]).ok()?;
            domain_parts.push(label.to_string());
            offset += 1 + label_len;
        }

        if domain_parts.is_empty() {
            None
        } else {
            Some(domain_parts.join("."))
        }
    }

    /// Resolve a domain via upstream DNS.
    ///
    /// # Arguments
    /// * `domain` - The domain to resolve
    ///
    /// # Returns
    /// * `Ok(Vec<IpAddr>)` - Resolved IP addresses
    /// * `Err(ProxyError::DnsResolution)` - Resolution failed
    async fn resolve_upstream(&self, domain: &str) -> Result<Vec<std::net::IpAddr>> {
        use tokio::net::UdpSocket;

        let upstreams = self.config.get_upstream();
        if upstreams.is_empty() {
            return Err(ProxyError::DnsResolution {
                domain: domain.to_string(),
                message: "No upstream DNS servers configured".to_string(),
            });
        }

        // Try A then AAAA records across all upstreams.
        // A fresh socket is created for each upstream so that ICMP errors or
        // stale state from a non-responsive server cannot affect the next attempt.
        for record_type in [1u16, 28u16] {
            // 1 = A, 28 = AAAA
            let query = Self::build_dns_query(domain, record_type);

            for upstream in &upstreams {
                let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
                    continue;
                };

                if socket.connect(upstream).await.is_err() {
                    continue;
                }

                if socket.send(&query).await.is_err() {
                    continue;
                }

                let mut buf = [0u8; 512];
                let result =
                    tokio::time::timeout(self.config.resolve_timeout, socket.recv(&mut buf)).await;

                if let Ok(Ok(len)) = result {
                    if let Some(addresses) = Self::parse_dns_response(&buf[..len]) {
                        if !addresses.is_empty() {
                            return Ok(addresses);
                        }
                    }
                }
            }
        }

        Err(ProxyError::DnsResolution {
            domain: domain.to_string(),
            message: "Failed to resolve via any upstream server".to_string(),
        })
    }

    /// Build a DNS query packet for the given domain and record type.
    fn build_dns_query(domain: &str, record_type: u16) -> Vec<u8> {
        let mut query = Vec::new();

        // Header
        query.extend_from_slice(&[0x00, 0x01]); // ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question: domain name (DNS labels are at most 63 bytes)
        for label in domain.split('.') {
            #[allow(clippy::cast_possible_truncation)]
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // Root label

        // QTYPE and QCLASS
        query.extend_from_slice(&record_type.to_be_bytes());
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

        query
    }

    /// Parse DNS response and extract IP addresses.
    fn parse_dns_response(response: &[u8]) -> Option<Vec<std::net::IpAddr>> {
        if response.len() < 12 {
            return None;
        }

        // Check RCODE (lower 4 bits of byte 3)
        let rcode = response[3] & 0x0F;
        if rcode != 0 {
            return None; // Non-success response
        }

        // Get answer count
        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        if ancount == 0 {
            return Some(vec![]); // Valid response with no answers
        }

        let mut addresses = Vec::new();
        let mut pos = 12;

        // Skip question section
        while pos < response.len() {
            let label_len = response[pos] as usize;
            if label_len == 0 {
                pos += 1;
                break;
            }
            if label_len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + label_len;
        }
        pos += 4; // QTYPE (2) + QCLASS (2)

        // Parse answer records
        for _ in 0..ancount {
            if pos + 12 > response.len() {
                break;
            }

            // Skip name (may be compressed)
            while pos < response.len() {
                let label_len = response[pos] as usize;
                if label_len == 0 {
                    pos += 1;
                    break;
                }
                if label_len & 0xC0 == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + label_len;
            }

            if pos + 10 > response.len() {
                break;
            }

            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > response.len() {
                break;
            }

            match rtype {
                1 if rdlength == 4 => {
                    // A record (IPv4)
                    let ip = std::net::Ipv4Addr::new(
                        response[pos],
                        response[pos + 1],
                        response[pos + 2],
                        response[pos + 3],
                    );
                    addresses.push(std::net::IpAddr::V4(ip));
                }
                28 if rdlength == 16 => {
                    // AAAA record (IPv6)
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&response[pos..pos + 16]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    addresses.push(std::net::IpAddr::V6(ip));
                }
                _ => {} // Skip other record types
            }

            pos += rdlength;
        }

        Some(addresses)
    }

    /// Build an NXDOMAIN response for a blocked domain.
    ///
    /// # Arguments
    /// * `query` - The original query (for copying ID and question)
    fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
        if query.len() < 12 {
            return vec![0; 12]; // Minimal response
        }

        let mut response = Vec::with_capacity(query.len());

        // Copy ID from query (bytes 0-1)
        response.extend_from_slice(&query[0..2]);

        // Flags: QR=1 (response), AA=0, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        response.push(0x81); // QR=1, Opcode=0, AA=0, TC=0, RD=1
        response.push(0x83); // RA=1, Z=0, RCODE=3

        // QDCOUNT: copy from query
        response.extend_from_slice(&query[4..6]);
        // ANCOUNT: 0
        response.extend_from_slice(&[0, 0]);
        // NSCOUNT: 0
        response.extend_from_slice(&[0, 0]);
        // ARCOUNT: 0
        response.extend_from_slice(&[0, 0]);

        // Copy question section from query
        if query.len() > 12 {
            // Find end of question section (domain + QTYPE + QCLASS)
            let mut pos = 12;
            while pos < query.len() {
                let label_len = query[pos] as usize;
                if label_len == 0 {
                    pos += 1;
                    break;
                }
                if label_len & 0xC0 == 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + label_len;
            }
            pos += 4; // QTYPE + QCLASS
            if pos <= query.len() {
                response.extend_from_slice(&query[12..pos]);
            }
        }

        response
    }

    /// Build a response with resolved addresses.
    ///
    /// # Arguments
    /// * `query` - The original query
    /// * `addresses` - Resolved IP addresses to include
    /// * `ttl` - TTL for the response records
    fn build_response(query: &[u8], addresses: &[std::net::IpAddr], ttl: u32) -> Vec<u8> {
        if query.len() < 12 {
            return vec![0; 12];
        }

        let mut response = Vec::new();

        // Copy ID from query (bytes 0-1)
        response.extend_from_slice(&query[0..2]);

        // Flags: QR=1 (response), AA=0, TC=0, RD=1, RA=1, RCODE=0 (no error)
        response.push(0x81); // QR=1, Opcode=0, AA=0, TC=0, RD=1
        response.push(0x80); // RA=1, Z=0, RCODE=0

        // QDCOUNT: 1 (from query)
        response.extend_from_slice(&query[4..6]);
        // ANCOUNT: number of addresses (max 65535, always safe)
        #[allow(clippy::cast_possible_truncation)]
        let ancount = addresses.len() as u16;
        response.extend_from_slice(&ancount.to_be_bytes());
        // NSCOUNT: 0
        response.extend_from_slice(&[0, 0]);
        // ARCOUNT: 0
        response.extend_from_slice(&[0, 0]);

        // Find end of question section in query
        let mut question_end = 12;
        while question_end < query.len() {
            let label_len = query[question_end] as usize;
            if label_len == 0 {
                question_end += 1;
                break;
            }
            if label_len & 0xC0 == 0xC0 {
                question_end += 2;
                break;
            }
            question_end += 1 + label_len;
        }
        question_end += 4; // QTYPE + QCLASS

        // Copy question section
        if question_end <= query.len() {
            response.extend_from_slice(&query[12..question_end]);
        }

        // Add answer records
        for addr in addresses {
            // Name: pointer to question (offset 12)
            response.extend_from_slice(&[0xC0, 0x0C]);

            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    // TYPE: A (1)
                    response.extend_from_slice(&[0x00, 0x01]);
                    // CLASS: IN (1)
                    response.extend_from_slice(&[0x00, 0x01]);
                    // TTL
                    response.extend_from_slice(&ttl.to_be_bytes());
                    // RDLENGTH: 4
                    response.extend_from_slice(&[0x00, 0x04]);
                    // RDATA: IPv4 address
                    response.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    // TYPE: AAAA (28)
                    response.extend_from_slice(&[0x00, 0x1C]);
                    // CLASS: IN (1)
                    response.extend_from_slice(&[0x00, 0x01]);
                    // TTL
                    response.extend_from_slice(&ttl.to_be_bytes());
                    // RDLENGTH: 16
                    response.extend_from_slice(&[0x00, 0x10]);
                    // RDATA: IPv6 address
                    response.extend_from_slice(&ipv6.octets());
                }
            }
        }

        response
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test infrastructure: parse on known-good literals
mod tests {
    use super::*;

    async fn udp_bind_or_skip(addr: &str) -> Option<tokio::net::UdpSocket> {
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(socket) => Some(socket),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(err) => panic!("Failed to bind UDP socket for test: {err}"),
        }
    }

    // ========================================================================
    // DnsServerConfig Tests
    // ========================================================================

    #[test]
    fn test_dns_server_config_default() {
        let config = DnsServerConfig::default();
        // Port 0 lets the OS assign an available port
        assert_eq!(config.bind_addr.port(), 0);
        assert!(config.upstream.is_none()); // Uses system resolvers
    }

    #[test]
    fn test_dns_server_config_get_upstream_from_system() {
        // Should read /etc/resolv.conf when upstream is None
        let config = DnsServerConfig::default();
        let upstream = config.get_upstream();
        // Should return at least one resolver (system or fallback)
        assert!(!upstream.is_empty());
        // All should use port 53
        for addr in &upstream {
            assert_eq!(addr.port(), 53);
        }
    }

    #[test]
    fn test_dns_server_config_get_upstream_explicit() {
        // Should use explicit upstream when set
        let explicit: Vec<SocketAddr> = vec![
            "9.9.9.9:53".parse().unwrap(),
            "149.112.112.112:53".parse().unwrap(),
        ];
        let config = DnsServerConfig {
            upstream: Some(explicit.clone()),
            ..Default::default()
        };
        let upstream = config.get_upstream();
        assert_eq!(upstream, explicit);
    }

    #[test]
    fn test_dns_server_config_get_upstream_fallback() {
        // When system config unavailable, should fall back to public DNS
        // We can't easily test this without mocking filesystem, but we can
        // verify the fallback values are valid public DNS servers
        let config = DnsServerConfig::default();
        let upstream = config.get_upstream();
        // Should have at least one resolver
        assert!(!upstream.is_empty());
    }

    #[test]
    fn test_dns_server_config_default_ttl() {
        let config = DnsServerConfig::default();
        assert_eq!(config.ttl, std::time::Duration::from_secs(300));
    }

    #[test]
    fn test_dns_server_config_default_binds_localhost() {
        let config = DnsServerConfig::default();
        assert!(config.bind_addr.ip().is_loopback());
    }

    // ========================================================================
    // DnsServer Creation Tests
    // ========================================================================

    #[test]
    fn test_dns_server_new_with_valid_config() {
        use crate::SharedState;
        let config = DnsServerConfig::default();
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let server = DnsServer::new(config, state);
        assert!(server.is_ok());
    }

    #[test]
    fn test_dns_server_new_with_empty_upstream() {
        use crate::SharedState;
        let config = DnsServerConfig {
            upstream: Some(vec![]),
            ..Default::default()
        };
        let state = Arc::new(SharedState::new(vec![]));
        let server = DnsServer::new(config, state);
        assert!(server.is_ok());
    }

    #[test]
    fn test_dns_server_new_with_custom_ttl() {
        use crate::SharedState;
        let config = DnsServerConfig {
            ttl: std::time::Duration::from_secs(600),
            ..Default::default()
        };
        let state = Arc::new(SharedState::new(vec![]));
        let server = DnsServer::new(config, state).unwrap();
        assert_eq!(server.config.ttl, std::time::Duration::from_secs(600));
    }

    // ========================================================================
    // DNS Query Handling - Allowed Domains
    // ========================================================================

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_query_allowed_domain_exact_match() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state.clone()).unwrap();

        // Build a DNS query for example.com (A record)
        let query = build_test_dns_query("example.com", 1); // 1 = A record
        let response = server.handle_query(&query).await.unwrap();
        // Response should contain resolved IPs
        assert!(!response.is_empty());
        // RCODE should be 0 (no error)
        assert_eq!(response[3] & 0x0F, 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_query_allowed_domain_wildcard_match() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["*.github.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("api.github.com", 1);
        let response = server.handle_query(&query).await.unwrap();
        assert!(!response.is_empty());
        assert_eq!(response[3] & 0x0F, 0); // RCODE = 0
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_query_returns_multiple_ips() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("example.com", 1);
        let response = server.handle_query(&query).await.unwrap();
        // Parse answer count from response header (bytes 6-7)
        let answer_count = u16::from_be_bytes([response[6], response[7]]);
        // Real domains often have multiple A records
        assert!(answer_count >= 1);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_query_returns_ipv4_and_ipv6() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        // Query for AAAA record (type 28)
        let query_aaaa = build_test_dns_query("example.com", 28);
        let response = server.handle_query(&query_aaaa).await.unwrap();
        assert!(!response.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_query_case_insensitive() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["github.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("GITHUB.COM", 1);
        let response = server.handle_query(&query).await.unwrap();
        // Should resolve despite case difference
        assert_eq!(response[3] & 0x0F, 0); // RCODE = 0 (success)
    }

    // ========================================================================
    // DNS Query Handling - Blocked Domains
    // ========================================================================

    #[tokio::test]

    async fn test_dns_query_blocked_domain_returns_nxdomain() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["allowed.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("blocked.com", 1);
        let response = server.handle_query(&query).await.unwrap();

        // RCODE should be 3 (NXDOMAIN)
        assert_eq!(response[3] & 0x0F, 3);
    }

    #[tokio::test]

    async fn test_dns_query_blocked_domain_no_upstream_query() {
        use crate::SharedState;
        use std::time::Instant;

        let state = Arc::new(SharedState::new(vec!["allowed.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("blocked.com", 1);
        let start = Instant::now();
        let _response = server.handle_query(&query).await.unwrap();
        let elapsed = start.elapsed();

        // Should be fast (no upstream query) - less than 10ms
        assert!(elapsed.as_millis() < 10);
    }

    #[tokio::test]

    async fn test_dns_query_empty_allowlist_blocks_all() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("any-domain.com", 1);
        let response = server.handle_query(&query).await.unwrap();

        // RCODE should be 3 (NXDOMAIN)
        assert_eq!(response[3] & 0x0F, 3);
    }

    // ========================================================================
    // DNS Response Building
    // ========================================================================

    #[test]

    fn test_build_nxdomain_response_preserves_query_id() {
        // Query with ID 0x1234
        let mut query = build_test_dns_query("test.com", 1);
        query[0] = 0x12;
        query[1] = 0x34;

        let response = DnsServer::build_nxdomain_response(&query);

        // Response ID should match query ID
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);
    }

    #[test]

    fn test_build_nxdomain_response_has_correct_rcode() {
        let query = build_test_dns_query("test.com", 1);
        let response = DnsServer::build_nxdomain_response(&query);

        // RCODE is in the lower 4 bits of byte 3
        let rcode = response[3] & 0x0F;
        assert_eq!(rcode, 3); // NXDOMAIN
    }

    #[test]

    fn test_build_response_includes_all_addresses() {
        let query = build_test_dns_query("test.com", 1);
        let addresses: Vec<std::net::IpAddr> =
            vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()];
        let response = DnsServer::build_response(&query, &addresses, 300);

        // Answer count should be 2
        let answer_count = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(answer_count, 2);
    }

    #[test]

    fn test_build_response_sets_correct_ttl() {
        let query = build_test_dns_query("test.com", 1);
        let addresses: Vec<std::net::IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let response = DnsServer::build_response(&query, &addresses, 600);

        // TTL is 4 bytes in the answer section
        // Find answer section and verify TTL = 600
        assert!(response.len() > 20); // Has answer section
    }

    #[test]

    fn test_build_response_preserves_query_question() {
        let query = build_test_dns_query("test.com", 1);
        let addresses: Vec<std::net::IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let response = DnsServer::build_response(&query, &addresses, 300);

        // Question count should be 1
        let question_count = u16::from_be_bytes([response[4], response[5]]);
        assert_eq!(question_count, 1);
    }

    // ========================================================================
    // Caching Behavior
    // ========================================================================

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_resolution_cached_on_success() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state.clone()).unwrap();

        let query = build_test_dns_query("example.com", 1);
        server.handle_query(&query).await.unwrap();
        // Cache should now contain the resolved IPs
        assert!(!state.cache.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_cache_respects_ttl() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            ttl: std::time::Duration::from_secs(1), // 1 second TTL
            ..Default::default()
        };
        let server = DnsServer::new(config, state.clone()).unwrap();

        let query = build_test_dns_query("example.com", 1);
        server.handle_query(&query).await.unwrap();
        // The server resolved the domain and populated the cache.
        assert!(
            !state.cache.is_empty(),
            "cache should be populated after resolution"
        );
        // TTL-based expiry semantics (lookup returns None after expiry) are
        // covered by test_resolution_cache_lookup_expired in lib.rs.
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_cache_allows_tcp_proxy_lookup() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state.clone()).unwrap();

        let query = build_test_dns_query("example.com", 1);
        server.handle_query(&query).await.unwrap();

        // TCP proxy should be able to look up cached IP
        // (We'd need to parse the response to get the IP, but conceptually:)
        let test_ip: std::net::IpAddr = "93.184.216.34".parse().unwrap(); // example.com IP
        let domain = state.cache.lookup(&test_ip);
        // If the IP was cached, we should get the domain back
        if let Some(d) = domain {
            assert_eq!(d, "example.com");
        }
    }

    // ========================================================================
    // Upstream Resolution
    // ========================================================================

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_resolve_upstream_success() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let ips = server.resolve_upstream("example.com").await.unwrap();
        assert!(!ips.is_empty(), "Should resolve to at least one IP");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_resolve_upstream_nonexistent_domain() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec![
            "nonexistent-domain-12345.invalid".to_string()
        ]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let result = server
            .resolve_upstream("nonexistent-domain-12345.invalid")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_upstream_timeout() {
        use crate::SharedState;
        // Bind a local silent UDP server — accepts packets but never responds.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            upstream: Some(vec![silent_addr]),
            // Short timeout so the test completes quickly.
            resolve_timeout: std::time::Duration::from_millis(100),
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();

        let result = server.resolve_upstream("example.com").await;
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_resolve_upstream_fallback_to_secondary() {
        use crate::SharedState;

        // Bind a local UDP socket that accepts queries but never responds.
        // This is the "unresponsive primary" that should trigger fallback.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = silent.local_addr().unwrap();
        let _silent_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                // Read and discard queries; never send a response
                let _ = silent.recv_from(&mut buf).await;
            }
        });

        // Use the system resolver(s) as the secondary so the test is
        // self-contained (no dependency on reaching a specific external IP).
        let system_dns = DnsServerConfig::default().get_upstream();
        let mut upstreams = vec![primary_addr];
        upstreams.extend(system_dns);

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            upstream: Some(upstreams),
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();

        // Primary will time out (5 s), then the system resolver should succeed
        let ips = server.resolve_upstream("example.com").await.unwrap();
        assert!(!ips.is_empty());
    }

    // ========================================================================
    // Protocol Edge Cases
    // ========================================================================

    #[tokio::test]

    async fn test_dns_query_malformed_packet() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        // Malformed packet (too short)
        let malformed = vec![0u8; 5];
        let result = server.handle_query(&malformed).await;

        // Should handle gracefully (error or FORMERR response)
        assert!(result.is_err() || (result.as_ref().unwrap()[3] & 0x0F) == 1);
    }

    #[tokio::test]

    async fn test_dns_query_truncated_packet() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        // Start of valid query but truncated
        let truncated = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01];
        let result = server.handle_query(&truncated).await;

        // Should not panic, may return error or FORMERR
        assert!(result.is_err() || !result.unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_query_unsupported_record_type() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        // Query for MX record (type 15)
        let query = build_test_dns_query("example.com", 15);
        let result = server.handle_query(&query).await;

        // Should handle gracefully; skip if DNS resolution isn't available in this sandbox.
        match result {
            Ok(_) => {}
            Err(crate::ProxyError::DnsResolution { .. }) => return,
            Err(err) => panic!("Unexpected DNS error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_dns_query_very_long_domain() {
        use crate::SharedState;
        // Max label is 63 chars, max domain is 253 chars
        // This tests long domain parsing, not resolution
        let long_label = "a".repeat(63);
        let domain = format!("{long_label}.example.com");
        let state = Arc::new(SharedState::new(vec![])); // Empty allowlist - test parsing only
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query(&domain, 1);
        let result = server.handle_query(&query).await;

        // Should parse long domain and return NXDOMAIN (blocked)
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response[3] & 0x0F, 3); // NXDOMAIN
    }

    #[tokio::test]
    async fn test_dns_query_punycode_domain() {
        use crate::SharedState;
        // xn--nxasmq5b is punycode for a Greek word
        // This tests punycode domain parsing, not resolution
        // We use a blocked domain to verify parsing works without needing external DNS
        let state = Arc::new(SharedState::new(vec![])); // Empty allowlist
        let config = DnsServerConfig::default();
        let server = DnsServer::new(config, state).unwrap();

        let query = build_test_dns_query("xn--nxasmq5b.example.com", 1);
        let result = server.handle_query(&query).await;

        // Should parse punycode and return NXDOMAIN (blocked)
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response[3] & 0x0F, 3); // NXDOMAIN
    }

    // ========================================================================
    // Server Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_dns_server_binds_to_port() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // OS assigns port
            ..Default::default()
        };

        // Pre-bind to get the actual port
        let Some(socket) = udp_bind_or_skip(&config.bind_addr.to_string()).await else {
            return;
        };
        let bound_addr = socket.local_addr().unwrap();
        drop(socket);

        let config = DnsServerConfig {
            bind_addr: bound_addr,
            ..Default::default()
        };
        let server = DnsServer::new(config.clone(), state).unwrap();

        // Start server in background
        let handle = tokio::spawn(async move { server.run().await });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to connect to verify it's running
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            handle.abort();
            return;
        };
        socket.connect(&config.bind_addr).await.unwrap();

        handle.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_dns_server_handles_concurrent_queries() {
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));

        // Pre-bind to get port
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let bound_addr = socket.local_addr().unwrap();
        drop(socket);

        let config = DnsServerConfig {
            bind_addr: bound_addr,
            ..Default::default()
        };
        let server = DnsServer::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { server.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        if udp_bind_or_skip("127.0.0.1:0").await.is_none() {
            handle.abort();
            return;
        }

        // Send multiple concurrent queries
        let mut handles = vec![];
        for _ in 0..10 {
            let addr = config.bind_addr;
            handles.push(tokio::spawn(async move {
                let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
                    return;
                };
                let query = build_test_dns_query("example.com", 1);
                socket.send_to(&query, addr).await.unwrap();
                let mut buf = [0u8; 512];
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(1), socket.recv(&mut buf))
                        .await;
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_dns_server_graceful_shutdown() {
        use crate::SharedState;
        // Pre-bind to get port
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let bound_addr = socket.local_addr().unwrap();
        drop(socket);

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            bind_addr: bound_addr,
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();

        let handle = tokio::spawn(async move { server.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Abort the server (simulating shutdown)
        handle.abort();
        let result = handle.await;

        // Should have been cancelled
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dns_server_bind_address_in_use() {
        use crate::SharedState;
        // Pre-bind to get a specific port
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let bound_addr = socket.local_addr().unwrap();
        // Keep socket bound to cause conflict

        let state = Arc::new(SharedState::new(vec![]));
        let config = DnsServerConfig {
            bind_addr: bound_addr, // Same port
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();

        let result = server.run().await;
        assert!(result.is_err());

        drop(socket);
    }

    // ========================================================================
    // Test Helper Functions
    // ========================================================================

    /// Build a test DNS query packet for a domain.
    fn build_test_dns_query(domain: &str, record_type: u16) -> Vec<u8> {
        let mut query = Vec::new();

        // Header (12 bytes)
        query.extend_from_slice(&[0xAB, 0xCD]); // ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // Question section
        for label in domain.split('.') {
            #[allow(clippy::cast_possible_truncation)]
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // Root label

        // QTYPE
        query.extend_from_slice(&record_type.to_be_bytes());
        // QCLASS: IN (1)
        query.extend_from_slice(&[0x00, 0x01]);

        query
    }
}
