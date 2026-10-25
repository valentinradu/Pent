//! DNS server with domain filtering.
//!
//! Intercepts DNS queries from sandboxed processes and only resolves
//! domains that are on the allowlist. Blocked domains receive NXDOMAIN.
//!
//! # Protocol Support
//!
//! - UDP DNS (standard port 53 or custom)
//! - All query types. The server forwards the query type of the client to
//!   the upstream server (A, AAAA, CNAME, TXT, MX, HTTPS, SVCB and others)
//!   and returns the upstream answer. Zone transfers (AXFR, IXFR) get
//!   NOTIMP.
//! - Exactly one question per query. Other queries get FORMERR.
//!
//! # Resolution Flow
//!
//! ```text
//! Client Query
//!      |
//!      v
//! DomainFilter::matches(domain)?
//!      |
//!      +-- yes --> Forward the query (same QTYPE) to upstream DNS
//!      |                 |
//!      |                 v
//!      |           Clamp TTLs; cache A/AAAA answers in ResolutionCache
//!      |                 |
//!      |                 v
//!      |           Return the upstream answer
//!      |
//!      +-- no --> Return NXDOMAIN
//! ```
//!

use crate::{normalize_hostname, ProxyError, Result, SharedState};
use pent_profile::{Outcome, WatchEvent};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// DNS header length.
const HEADER_LEN: usize = 12;

/// The receive buffer size for client queries and upstream responses.
const UDP_BUFFER_LEN: usize = 4096;

/// The time after which the server closes an idle DNS TCP connection.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// The maximum length of a domain name in wire format.
const MAX_WIRE_NAME_LEN: usize = 255;

/// The maximum number of compression pointers that a name can follow.
const MAX_POINTER_HOPS: usize = 32;

/// The file that holds the resolvers of the host.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Read the resolvers from the text of a `resolv.conf` file.
///
/// Each `nameserver` line gives one address on port 53. The function skips
/// a line with no address and an address that it cannot parse, and it
/// returns `None` when the text has no usable address.
fn parse_resolv_conf(content: &str) -> Option<Vec<SocketAddr>> {
    let resolvers: Vec<SocketAddr> = content
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next() != Some("nameserver") {
                return None;
            }
            let entry = parts.next()?;
            // Remove a zone index such as "fe80::1%eth0": the parser does
            // not accept it.
            let ip_text = entry.split('%').next().unwrap_or(entry);
            match ip_text.parse::<IpAddr>() {
                Ok(ip) => Some(SocketAddr::new(ip, 53)),
                Err(_) => {
                    warn!(nameserver = %entry, "skip the nameserver entry that is not an IP address");
                    None
                }
            }
        })
        .collect();

    if resolvers.is_empty() {
        None
    } else {
        Some(resolvers)
    }
}

/// Header flag: the message is a response.
const FLAG_QR: u8 = 0x80;
/// Header flag: the response is truncated.
const FLAG_TC: u8 = 0x02;
/// Header flag: recursion desired.
const FLAG_RD: u8 = 0x01;
/// Header flag (second byte): recursion available.
const FLAG_RA: u8 = 0x80;

/// Response codes.
mod rcode {
    pub(super) const NOERROR: u8 = 0;
    pub(super) const FORMERR: u8 = 1;
    pub(super) const SERVFAIL: u8 = 2;
    pub(super) const NXDOMAIN: u8 = 3;
    pub(super) const NOTIMP: u8 = 4;
}

/// Record types that the server handles in a special way.
mod rtype {
    pub(super) const A: u16 = 1;
    pub(super) const AAAA: u16 = 28;
    pub(super) const OPT: u16 = 41;
    pub(super) const IXFR: u16 = 251;
    pub(super) const AXFR: u16 = 252;
}

/// The class IN.
const CLASS_IN: u16 = 1;

/// The text name of a record type, for log and trace messages.
fn qtype_name(qtype: u16) -> String {
    let name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        other => return format!("TYPE{other}"),
    };
    name.to_string()
}

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

    /// Maximum TTL.
    ///
    /// The server uses the upstream TTL, but not more than this value, for
    /// the TTLs in the response and for the expiry of the IP-to-domain
    /// cache.
    /// Default: 5 minutes
    pub ttl: Duration,

    /// Minimum TTL.
    ///
    /// The server increases a shorter upstream TTL to this value, so that
    /// the cache does not change too frequently. `ttl` has priority if it is
    /// smaller.
    /// Default: 30 seconds
    pub min_ttl: Duration,

    /// Per-upstream timeout when resolving a query.
    /// Default: 5 seconds
    pub resolve_timeout: Duration,

    /// Maximum number of client queries that the server handles at the same
    /// time. One slow upstream query does not block the other queries.
    /// Default: 256
    pub max_concurrent_queries: usize,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        const LOCALHOST_ANY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        Self {
            bind_addr: LOCALHOST_ANY,
            upstream: None, // Use system resolvers
            ttl: Duration::from_secs(300),
            min_ttl: Duration::from_secs(30),
            resolve_timeout: Duration::from_secs(5),
            max_concurrent_queries: 256,
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
            const CLOUDFLARE: SocketAddr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
            const GOOGLE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
            vec![CLOUDFLARE, GOOGLE]
        })
    }

    /// Read system DNS resolvers from /etc/resolv.conf.
    fn read_system_resolvers() -> Option<Vec<SocketAddr>> {
        Self::read_resolvers(std::path::Path::new(RESOLV_CONF))
    }

    /// Read the resolvers from the file at `path`.
    ///
    /// The caller gives the path, thus a test can give another file.
    /// Returns `None` when pent cannot read the file, and when the file
    /// holds no usable `nameserver` line.
    fn read_resolvers(path: &std::path::Path) -> Option<Vec<SocketAddr>> {
        parse_resolv_conf(&std::fs::read_to_string(path).ok()?)
    }

    /// The TTL bounds in seconds: `(min, max)`.
    fn ttl_bounds(&self) -> (u32, u32) {
        let max = u32::try_from(self.ttl.as_secs()).unwrap_or(u32::MAX);
        let min = u32::try_from(self.min_ttl.as_secs()).unwrap_or(u32::MAX);
        (min, max)
    }
}

/// Clamp a TTL to the bounds. The maximum has priority over the minimum.
fn clamp_ttl(ttl: u32, (min, max): (u32, u32)) -> u32 {
    ttl.max(min).min(max)
}

/// An error in a DNS message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum WireError {
    #[error("the message is too short")]
    Truncated,
    #[error("a label length byte uses the reserved bits 0x40 or 0x80")]
    ReservedLabelType,
    #[error("a compression pointer is not permitted here")]
    UnexpectedPointer,
    #[error("a compression pointer does not point backward")]
    BadPointer,
    #[error("a label contains a dot or a byte that is not printable ASCII")]
    BadLabelByte,
    #[error("the name is longer than 255 bytes")]
    NameTooLong,
    #[error("the upstream response does not match the query")]
    Mismatch,
}

/// Read a big-endian `u16` at `pos`.
fn read_u16(msg: &[u8], pos: usize) -> std::result::Result<u16, WireError> {
    match msg.get(pos..pos.saturating_add(2)) {
        Some([a, b]) => Ok(u16::from_be_bytes([*a, *b])),
        _ => Err(WireError::Truncated),
    }
}

/// Read a big-endian `u32` at `pos`.
fn read_u32(msg: &[u8], pos: usize) -> std::result::Result<u32, WireError> {
    match msg.get(pos..pos.saturating_add(4)) {
        Some([a, b, c, d]) => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(WireError::Truncated),
    }
}

/// How to treat compression pointers in a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pointers {
    /// Pointers are not permitted (a name in the question of a query).
    Forbidden,
    /// Pointers are permitted (names in a response).
    Allowed,
}

/// How to treat the bytes of a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LabelBytes {
    /// Accept only printable ASCII without `.` (names that the server uses).
    Strict,
    /// Accept all bytes (owner names of records that the server skips).
    Any,
}

/// Read a domain name at `start`.
///
/// Returns the name in text form (labels joined with `.`) and the position
/// after the name in the message.
fn read_name(
    msg: &[u8],
    start: usize,
    pointers: Pointers,
    bytes: LabelBytes,
) -> std::result::Result<(String, usize), WireError> {
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut hops = 0usize;
    let mut wire_len = 0usize;
    let mut labels: Vec<String> = Vec::new();

    loop {
        let len_byte = *msg.get(pos).ok_or(WireError::Truncated)?;
        match len_byte >> 6 {
            0b00 => {
                let len = usize::from(len_byte);
                wire_len = wire_len.saturating_add(len).saturating_add(1);
                if wire_len > MAX_WIRE_NAME_LEN {
                    return Err(WireError::NameTooLong);
                }
                if len == 0 {
                    pos = pos.saturating_add(1);
                    break;
                }
                let first = pos.saturating_add(1);
                let label = msg
                    .get(first..first.saturating_add(len))
                    .ok_or(WireError::Truncated)?;
                if bytes == LabelBytes::Strict
                    && label.iter().any(|b| *b == b'.' || !b.is_ascii_graphic())
                {
                    return Err(WireError::BadLabelByte);
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                pos = first.saturating_add(len);
            }
            0b11 => {
                if pointers == Pointers::Forbidden {
                    return Err(WireError::UnexpectedPointer);
                }
                let low = *msg.get(pos.saturating_add(1)).ok_or(WireError::Truncated)?;
                let target = (usize::from(len_byte & 0x3F) << 8) | usize::from(low);
                if after.is_none() {
                    after = Some(pos.saturating_add(2));
                }
                hops = hops.saturating_add(1);
                if target >= pos || hops > MAX_POINTER_HOPS {
                    return Err(WireError::BadPointer);
                }
                pos = target;
            }
            _ => return Err(WireError::ReservedLabelType),
        }
    }

    Ok((labels.join("."), after.unwrap_or(pos)))
}

/// The parsed question of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    /// The name as the client sent it (labels joined with `.`).
    name: String,
    qtype: u16,
    qclass: u16,
    /// The position after the question in the message.
    end: usize,
}

/// Read the question at offset 12.
fn read_question(msg: &[u8], pointers: Pointers) -> std::result::Result<Question, WireError> {
    let (name, pos) = read_name(msg, HEADER_LEN, pointers, LabelBytes::Strict)?;
    let qtype = read_u16(msg, pos)?;
    let qclass = read_u16(msg, pos.saturating_add(2))?;
    Ok(Question {
        name,
        qtype,
        qclass,
        end: pos.saturating_add(4),
    })
}

/// The useful parts of an upstream response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamReply {
    /// The response, with the TTLs clamped.
    message: Vec<u8>,
    /// The response code.
    rcode: u8,
    /// The A and AAAA addresses in the answer section.
    addresses: Vec<IpAddr>,
    /// The smallest clamped TTL of the address records, in seconds.
    address_ttl: Option<u32>,
}

/// Check an upstream response against the query, clamp all the TTLs in it,
/// and collect the addresses in the answer section.
fn process_upstream_response(
    mut message: Vec<u8>,
    expected_id: u16,
    name: &str,
    qtype: u16,
    bounds: (u32, u32),
) -> std::result::Result<UpstreamReply, WireError> {
    if message.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let id = read_u16(&message, 0)?;
    let flags = *message.get(2).ok_or(WireError::Truncated)?;
    let rcode = *message.get(3).ok_or(WireError::Truncated)? & 0x0F;
    if id != expected_id || flags & FLAG_QR == 0 || read_u16(&message, 4)? != 1 {
        return Err(WireError::Mismatch);
    }
    let question = read_question(&message, Pointers::Allowed)?;
    if !question.name.eq_ignore_ascii_case(name)
        || question.qtype != qtype
        || question.qclass != CLASS_IN
    {
        return Err(WireError::Mismatch);
    }

    let ancount = usize::from(read_u16(&message, 6)?);
    let nscount = usize::from(read_u16(&message, 8)?);
    let arcount = usize::from(read_u16(&message, 10)?);
    let total = ancount.saturating_add(nscount).saturating_add(arcount);

    let mut addresses = Vec::new();
    let mut address_ttl: Option<u32> = None;
    let mut pos = question.end;
    for index in 0..total {
        let (_, after_name) = read_name(&message, pos, Pointers::Allowed, LabelBytes::Any)?;
        let rr_type = read_u16(&message, after_name)?;
        let ttl_pos = after_name.saturating_add(4);
        let ttl = read_u32(&message, ttl_pos)?;
        let rdlen = usize::from(read_u16(&message, after_name.saturating_add(8))?);
        let rdata_start = after_name.saturating_add(10);
        let rdata = message
            .get(rdata_start..rdata_start.saturating_add(rdlen))
            .ok_or(WireError::Truncated)?;

        // The TTL field of an OPT record holds flags, not a TTL.
        let clamped = clamp_ttl(ttl, bounds);
        if index < ancount {
            let address = match (rr_type, rdata.len()) {
                (rtype::A, 4) => <[u8; 4]>::try_from(rdata)
                    .ok()
                    .map(|o| IpAddr::V4(Ipv4Addr::from(o))),
                (rtype::AAAA, 16) => <[u8; 16]>::try_from(rdata)
                    .ok()
                    .map(|o| IpAddr::V6(Ipv6Addr::from(o))),
                _ => None,
            };
            if let Some(address) = address {
                addresses.push(address);
                address_ttl = Some(address_ttl.map_or(clamped, |t| t.min(clamped)));
            }
        }
        if rr_type != rtype::OPT {
            if let Some(field) = message.get_mut(ttl_pos..ttl_pos.saturating_add(4)) {
                field.copy_from_slice(&clamped.to_be_bytes());
            }
        }
        pos = rdata_start.saturating_add(rdlen);
    }
    message.truncate(pos);

    Ok(UpstreamReply {
        message,
        rcode,
        addresses,
        address_ttl,
    })
}

/// Make a transaction ID that a remote host cannot easily guess.
fn random_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let [a, b, ..] = hasher.finish().to_le_bytes();
    u16::from_le_bytes([a, b])
}

/// Build a query for `name` and `qtype` with the transaction ID `id`.
fn build_dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(HEADER_LEN.saturating_add(name.len()).saturating_add(6));
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[FLAG_RD, 0x00]); // Standard query, recursion desired
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN, NS, AR
    for label in name.split('.').filter(|l| !l.is_empty()) {
        // normalize_hostname limits a label to 63 bytes.
        query.push(u8::try_from(label.len()).unwrap_or(63));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // Root label
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    query
}

/// Build a response without answers, with the response code `code`.
///
/// If `question_end` is `Some`, the response repeats the question of the
/// query; otherwise its QDCOUNT is 0.
fn build_error_response(query: &[u8], question_end: Option<usize>, code: u8) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len().max(HEADER_LEN));
    response.extend_from_slice(query.get(..2).unwrap_or(&[0, 0])); // ID
    let rd = query.get(2).map_or(0, |f| f & FLAG_RD);
    let opcode = query.get(2).map_or(0, |f| f & 0x78);
    response.push(FLAG_QR | opcode | rd);
    response.push(FLAG_RA | (code & 0x0F));
    let question = question_end.and_then(|end| query.get(HEADER_LEN..end));
    let qdcount: u16 = u16::from(question.is_some());
    response.extend_from_slice(&qdcount.to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR
    if let Some(question) = question {
        response.extend_from_slice(question);
    }
    response
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

    /// The upstream servers, read once at creation.
    upstreams: Arc<[SocketAddr]>,
}

impl DnsServer {
    /// Create a new DNS server.
    ///
    /// Reads the upstream servers once (see [`DnsServerConfig::get_upstream`]).
    ///
    /// # Arguments
    /// * `config` - Server configuration
    /// * `state` - Shared state containing domain filter and cache
    ///
    /// # Errors
    /// Currently infallible; always returns `Ok`. The `Result` return type
    /// is present for forward compatibility.
    pub fn new(config: DnsServerConfig, state: Arc<SharedState>) -> Result<Self> {
        let upstreams = config.get_upstream().into();
        Ok(Self {
            config,
            state,
            upstreams,
        })
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
    /// The server handles each query in its own task, with at most
    /// `max_concurrent_queries` tasks at the same time. The tasks belong to
    /// this future: when the caller drops the future, the tasks stop.
    ///
    /// # Errors
    /// * `Err(ProxyError::Internal)` - Server error
    pub async fn run_on(&self, socket: tokio::net::UdpSocket) -> Result<()> {
        let socket = Arc::new(socket);
        let worker = Arc::new(Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            upstreams: Arc::clone(&self.upstreams),
        });
        let limit = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_queries.max(1),
        ));
        let mut tasks = tokio::task::JoinSet::new();
        let mut buf = vec![0u8; UDP_BUFFER_LEN];

        loop {
            let (len, src) = tokio::select! {
                received = socket.recv_from(&mut buf) => match received {
                    Ok(result) => result,
                    Err(e) => {
                        // Log error but continue serving
                        warn!(error = %e, "DNS recv error");
                        continue;
                    }
                },
                Some(finished) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(e) = finished {
                        if e.is_panic() {
                            warn!(error = %e, "DNS query task panicked");
                        }
                    }
                    continue;
                }
            };

            let query = buf.get(..len).unwrap_or_default().to_vec();
            // Ignore responses: an answer to a response can cause a loop.
            if query.get(2).is_some_and(|flags| flags & FLAG_QR != 0) {
                continue;
            }

            let permit = Arc::clone(&limit)
                .acquire_owned()
                .await
                .map_err(|e| ProxyError::Internal(format!("DNS query limiter closed: {e}")))?;
            let worker = Arc::clone(&worker);
            let socket = Arc::clone(&socket);
            tasks.spawn(async move {
                let _permit = permit;
                let response = match worker.handle_query(&query).await {
                    Ok(response) => response,
                    Err(e) => {
                        debug!(error = %e, "DNS query handling error");
                        Self::build_servfail_response(&query)
                    }
                };
                if let Err(e) = socket.send_to(&response, src).await {
                    warn!(error = %e, "DNS send error");
                }
            });
        }
    }

    /// Run the DNS server over TCP on a listener that the caller made.
    ///
    /// Each message has a two-byte length prefix (RFC 1035, section 4.2.2).
    /// One connection can send more than one query. The server closes a
    /// connection that is idle for 10 seconds. At most
    /// `max_concurrent_queries` connections are open at the same time; the
    /// server closes a new connection above this limit. The connection tasks
    /// belong to this future: when the caller drops the future, the tasks
    /// stop.
    ///
    /// # Errors
    /// Currently infallible: the loop runs until the caller drops the
    /// future. The `Result` return type matches [`DnsServer::run_on`].
    pub async fn run_tcp_on(&self, listener: tokio::net::TcpListener) -> Result<()> {
        let worker = Arc::new(Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            upstreams: Arc::clone(&self.upstreams),
        });
        let limit = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_queries.max(1),
        ));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(result) => result,
                    Err(e) => {
                        warn!(error = %e, "DNS TCP accept error");
                        continue;
                    }
                },
                Some(finished) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(e) = finished {
                        if e.is_panic() {
                            warn!(error = %e, "DNS TCP task panicked");
                        }
                    }
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                debug!(client = %peer, "DNS TCP connection limit reached; closing");
                continue;
            };
            let worker = Arc::clone(&worker);
            tasks.spawn(async move {
                let _permit = permit;
                if let Err(e) = worker.serve_tcp(stream).await {
                    debug!(client = %peer, error = %e, "DNS TCP connection error");
                }
            });
        }
    }

    /// Answer the queries of one DNS TCP connection until the client closes
    /// it or it is idle for `TCP_IDLE_TIMEOUT`.
    async fn serve_tcp(&self, mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                // The client is gone: it closed the connection, the read
                // failed, or the connection was idle for too long. The
                // server holds no state between two queries of one
                // connection, thus it ends the connection in each case.
                // The server itself continues with the next client.
                Ok(Err(_)) | Err(_) => return Ok(()),
            }
            let len = usize::from(u16::from_be_bytes(len_buf));
            let mut query = vec![0u8; len];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut query)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()),
            }
            // Ignore responses: an answer to a response can cause a loop.
            if query.get(2).is_some_and(|flags| flags & FLAG_QR != 0) {
                return Ok(());
            }
            let response = match self.handle_query(&query).await {
                Ok(response) => response,
                Err(e) => {
                    debug!(error = %e, "DNS query handling error");
                    Self::build_servfail_response(&query)
                }
            };
            let Ok(response_len) = u16::try_from(response.len()) else {
                debug!(len = response.len(), "DNS response too long for TCP");
                return Ok(());
            };
            let mut out = Vec::with_capacity(response.len().saturating_add(2));
            out.extend_from_slice(&response_len.to_be_bytes());
            out.extend_from_slice(&response);
            stream.write_all(&out).await?;
        }
    }

    /// Build a SERVFAIL response for internal errors.
    fn build_servfail_response(query: &[u8]) -> Vec<u8> {
        let question_end = read_question(query, Pointers::Forbidden)
            .ok()
            .map(|q| q.end);
        build_error_response(query, question_end, rcode::SERVFAIL)
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
    /// * Answers FORMERR if the query does not have exactly one valid question
    /// * Checks the domain against the policy (in observe mode, the policy
    ///   permits each valid name)
    /// * Sends one watch event for each query with a valid question that the
    ///   server does not reject as not implemented
    /// * If allowed: forwards the query type to upstream, caches A/AAAA
    ///   answers, returns the upstream answer
    /// * If blocked: returns NXDOMAIN response
    async fn handle_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        // Validate minimum DNS header size
        if query.len() < HEADER_LEN {
            return Err(ProxyError::Internal("DNS query too short".to_string()));
        }
        let flags = query.get(2).copied().unwrap_or(0);
        let opcode = (flags >> 3) & 0x0F;
        if opcode != 0 {
            return Ok(build_error_response(query, None, rcode::NOTIMP));
        }
        if read_u16(query, 4).ok() != Some(1) {
            return Ok(build_error_response(query, None, rcode::FORMERR));
        }
        let question = match read_question(query, Pointers::Forbidden) {
            Ok(q) => q,
            Err(e) => {
                debug!(error = %e, "malformed DNS question");
                return Ok(build_error_response(query, None, rcode::FORMERR));
            }
        };
        let respond = |code| build_error_response(query, Some(question.end), code);
        let type_name = qtype_name(question.qtype);

        if question.qclass != CLASS_IN
            || question.qtype == rtype::AXFR
            || question.qtype == rtype::IXFR
        {
            return Ok(respond(rcode::NOTIMP));
        }

        // Check domain against allowlist (ASCII case-insensitive). The server
        // forwards the same normalized name that it checks.
        // In observe mode, the policy permits each valid name.
        let name = match normalize_hostname(&question.name) {
            Ok(name) if self.state.is_permitted(&name) => name,
            Ok(name) => {
                self.state.report_violation(format!(
                    "network: DNS query for \"{name}\" ({type_name}) blocked: \
                     the domain is not in the allowlist"
                ));
                self.emit_dns(name, type_name, Outcome::Denied);
                return Ok(respond(rcode::NXDOMAIN));
            }
            Err(e) => {
                self.state.report_violation(format!(
                    "network: DNS query for {:?} ({type_name}) blocked: {e}",
                    question.name
                ));
                // The name is not valid, thus it has no normalized form. The
                // event uses the lowercase name without the trailing dot.
                let raw = question.name.trim_end_matches('.').to_ascii_lowercase();
                self.emit_dns(raw, type_name, Outcome::Denied);
                return Ok(respond(rcode::NXDOMAIN));
            }
        };
        self.state.report_access(format!(
            "network: DNS query for \"{name}\" ({type_name}) allowed"
        ));
        // The event records the policy decision. An upstream failure after
        // this point does not change the outcome.
        self.emit_dns(name.clone(), type_name, Outcome::Allowed);

        let reply = self.query_upstream(&name, question.qtype).await?;

        // Cache the addresses with the same TTL that the client gets.
        if let Some(ttl) = reply.address_ttl {
            self.state.insert_resolved(crate::ResolvedAddress {
                domain: name,
                addresses: reply.addresses.clone(),
                expires_at: std::time::Instant::now()
                    .checked_add(Duration::from_secs(u64::from(ttl)))
                    .unwrap_or_else(std::time::Instant::now),
            });
        }

        Ok(Self::finish_response(query, &question, reply.message))
    }

    /// Send a watch event for one DNS query.
    fn emit_dns(&self, name: String, qtype: String, outcome: Outcome) {
        self.state.emit(WatchEvent::Dns {
            name,
            qtype,
            outcome,
        });
    }

    /// Change an upstream response into the response for the client.
    fn finish_response(query: &[u8], question: &Question, mut message: Vec<u8>) -> Vec<u8> {
        // ID of the client.
        if let (Some(dst), Some(src)) = (message.get_mut(..2), query.get(..2)) {
            dst.copy_from_slice(src);
        }
        // QR=1, opcode 0, AA=0, TC=0 (the server does not serve DNS over
        // TCP, thus the client must use the records that it gets), RD from
        // the client. RA=1, rcode from upstream.
        let rd = query.get(2).map_or(0, |f| f & FLAG_RD);
        if let Some(flags) = message.get_mut(2) {
            *flags = (FLAG_QR | rd) & !FLAG_TC;
        }
        if let Some(flags) = message.get_mut(3) {
            *flags = FLAG_RA | (*flags & 0x0F);
        }
        // Copy the question of the client, so that the case of the name is
        // the same as in the query. The names have the same length, thus
        // the compression pointers in the answers stay correct.
        let client_question = query.get(HEADER_LEN..question.end);
        let upstream_question = message.get_mut(HEADER_LEN..question.end);
        if let (Some(dst), Some(src)) = (upstream_question, client_question) {
            if dst.eq_ignore_ascii_case(src) {
                dst.copy_from_slice(src);
            }
        }
        message
    }

    /// Forward a query for `name` and `qtype` to the upstream servers.
    ///
    /// Tries each upstream in turn. A NOERROR or NXDOMAIN response ends the
    /// search; the server skips an upstream that fails, times out, or
    /// answers SERVFAIL or REFUSED, and logs each skipped upstream.
    async fn query_upstream(&self, name: &str, qtype: u16) -> Result<UpstreamReply> {
        use tokio::net::UdpSocket;

        if self.upstreams.is_empty() {
            return Err(ProxyError::DnsResolution {
                domain: name.to_string(),
                message: "No upstream DNS servers configured".to_string(),
            });
        }

        const ANY_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        const ANY_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let bounds = self.config.ttl_bounds();

        // A fresh socket is created for each upstream so that ICMP errors or
        // stale state from a non-responsive server cannot affect the next attempt.
        for upstream in self.upstreams.iter() {
            let local = if upstream.is_ipv6() { ANY_V6 } else { ANY_V4 };
            let socket = match UdpSocket::bind(local).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%upstream, error = %e, "skip the DNS upstream: bind failed");
                    continue;
                }
            };
            if let Err(e) = socket.connect(upstream).await {
                warn!(%upstream, error = %e, "skip the DNS upstream: connect failed");
                continue;
            }
            let id = random_id();
            let query = build_dns_query(id, name, qtype);
            if let Err(e) = socket.send(&query).await {
                warn!(%upstream, error = %e, "skip the DNS upstream: send failed");
                continue;
            }

            match self.receive_reply(&socket, id, name, qtype, bounds).await {
                Some(reply) if reply.rcode == rcode::NOERROR || reply.rcode == rcode::NXDOMAIN => {
                    return Ok(reply);
                }
                Some(reply) => {
                    warn!(%upstream, rcode = reply.rcode, name, "skip the DNS upstream: error response");
                }
                None => {
                    warn!(%upstream, name, "skip the DNS upstream: no valid response in time");
                }
            }
        }

        Err(ProxyError::DnsResolution {
            domain: name.to_string(),
            message: "Failed to resolve via any upstream server".to_string(),
        })
    }

    /// Receive the response that matches the query, until the resolve
    /// timeout. The server ignores datagrams that do not match.
    async fn receive_reply(
        &self,
        socket: &tokio::net::UdpSocket,
        id: u16,
        name: &str,
        qtype: u16,
        bounds: (u32, u32),
    ) -> Option<UpstreamReply> {
        let deadline = tokio::time::Instant::now().checked_add(self.config.resolve_timeout)?;
        let mut buf = vec![0u8; UDP_BUFFER_LEN];
        loop {
            let len = match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                Ok(Ok(len)) => len,
                Ok(Err(e)) => {
                    debug!(error = %e, "DNS upstream receive error");
                    return None;
                }
                Err(_) => return None,
            };
            let message = buf.get(..len).unwrap_or_default().to_vec();
            match process_upstream_response(message, id, name, qtype, bounds) {
                Ok(reply) => return Some(reply),
                Err(e) => debug!(error = %e, "ignore the DNS upstream datagram"),
            }
        }
    }

    /// Build an NXDOMAIN response for a blocked domain.
    ///
    /// # Arguments
    /// * `query` - The original query (for copying ID and question)
    #[cfg(test)]
    fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
        let question_end = read_question(query, Pointers::Forbidden)
            .ok()
            .map(|q| q.end);
        build_error_response(query, question_end, rcode::NXDOMAIN)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test infrastructure: parse on known-good literals
mod tests {
    use super::*;

    async fn udp_bind_or_skip(addr: &str) -> Option<tokio::net::UdpSocket> {
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(socket) => Some(socket),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                crate::test_support::skip("this machine cannot bind a UDP socket on the loopback");
                None
            }
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
        let upstream: SocketAddr = "198.51.100.7:53".parse().unwrap();
        let config = DnsServerConfig {
            upstream: Some(vec![upstream]),
            ..Default::default()
        };
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let Ok(server) = DnsServer::new(config.clone(), state) else {
            panic!("DnsServer::new must accept a valid configuration");
        };
        // The server keeps the configuration, reads the upstream list one
        // time, and uses the allowlist of the shared state.
        assert_eq!(server.config.bind_addr, config.bind_addr);
        assert_eq!(server.upstreams.as_ref(), [upstream]);
        assert!(server.state.is_allowed("example.com"));
        assert!(!server.state.is_allowed("other.example"));
    }

    #[test]
    fn test_dns_server_new_with_empty_upstream() {
        use crate::SharedState;
        let config = DnsServerConfig {
            upstream: Some(vec![]),
            ..Default::default()
        };
        let state = Arc::new(SharedState::new(vec![]));
        let Ok(server) = DnsServer::new(config, state) else {
            panic!("DnsServer::new must accept an empty upstream list");
        };
        // An explicit empty list stays empty: the server does not fall back
        // to the resolvers of the host.
        assert!(server.upstreams.is_empty());
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

    #[tokio::test]
    async fn test_dns_query_allowed_domain_exact_match() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        let query = build_test_dns_query("example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(first_answer(&response).0, rtype::A);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[tokio::test]
    async fn test_dns_query_allowed_domain_wildcard_match() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["*.example.com"]);

        // The wildcard allows a subdomain, and the cache keeps the name of
        // the subdomain, not the name of the rule.
        let query = build_test_dns_query("api.example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(first_answer(&response).0, rtype::A);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("api.example.com".to_string()));

        // The wildcard does not allow the parent name itself.
        let query = build_test_dns_query("example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
    }

    #[tokio::test]
    async fn test_dns_query_returns_multiple_ips() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &[MULTI_NAME]);

        // The upstream answers this name with two A records. The server
        // keeps both, and the cache holds both addresses.
        let query = build_test_dns_query(MULTI_NAME, rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 2);
        for text in ["198.51.100.1", "198.51.100.2"] {
            let ip: IpAddr = text.parse().unwrap();
            assert_eq!(
                state.cache.lookup(&ip),
                Some(MULTI_NAME.to_string()),
                "{ip}"
            );
        }
    }

    #[tokio::test]
    async fn test_dns_query_returns_ipv4_and_ipv6() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        // An A query gives an A record, and an AAAA query gives an AAAA
        // record. The cache holds the address of each one.
        let response = server
            .handle_query(&build_test_dns_query("example.com", rtype::A))
            .await
            .unwrap();
        assert_eq!(first_answer(&response).0, rtype::A);
        let response = server
            .handle_query(&build_test_dns_query("example.com", rtype::AAAA))
            .await
            .unwrap();
        assert_eq!(first_answer(&response).0, rtype::AAAA);
        for text in ["93.184.216.34", "2606:2800:220:1::1"] {
            let ip: IpAddr = text.parse().unwrap();
            assert_eq!(
                state.cache.lookup(&ip),
                Some("example.com".to_string()),
                "{ip}"
            );
        }
    }

    #[tokio::test]
    async fn test_dns_query_case_insensitive() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        // The allowlist folds the case of the name of the query.
        let query = build_test_dns_query("ExAmPlE.COM", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(first_answer(&response).0, rtype::A);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
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

    // ========================================================================
    // Caching Behavior
    // ========================================================================

    #[tokio::test]
    async fn test_dns_resolution_cached_on_success() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        // A blocked name reaches no upstream, so it leaves the cache empty.
        server
            .handle_query(&build_test_dns_query("other.example", rtype::A))
            .await
            .unwrap();
        assert!(state.cache.is_empty());

        // An allowed name puts its address in the cache.
        server
            .handle_query(&build_test_dns_query("example.com", rtype::A))
            .await
            .unwrap();
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[tokio::test]
    async fn test_dns_cache_respects_ttl() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        // The entry lives as long as the TTL of the answer. The upstream
        // gives 5 s for an A record, and the server raises it to the floor
        // of 30 s, so the entry is still there after the query.
        let response = server
            .handle_query(&build_test_dns_query("example.com", rtype::A))
            .await
            .unwrap();
        assert_eq!(first_answer(&response), (rtype::A, 30));
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
        // The expiry itself is in test_resolution_cache_lookup_expired of
        // lib.rs, which moves the clock of the entry.
    }

    #[tokio::test]
    async fn test_dns_cache_allows_tcp_proxy_lookup() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        let query = build_test_dns_query("example.com", rtype::A);
        server.handle_query(&query).await.unwrap();

        // The TCP proxy asks the cache for the domain of an address. This
        // is the only way it knows which name a connection belongs to.
        let resolved: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(
            state.cache.lookup(&resolved),
            Some("example.com".to_string())
        );
        let other: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(state.cache.lookup(&other), None);
    }

    // ========================================================================
    // Upstream Resolution
    // ========================================================================

    #[tokio::test]
    async fn test_resolve_upstream_success() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);

        let reply = server
            .query_upstream("example.com", rtype::A)
            .await
            .unwrap();
        let expected: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(reply.addresses, vec![expected]);
    }

    #[tokio::test]
    async fn test_resolve_upstream_nonexistent_domain() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["*.example.com"]);

        // The upstream answers NXDOMAIN for this name. The server passes
        // the answer on and gives no address.
        let Ok(reply) = server.query_upstream("nx.example.com", rtype::A).await else {
            panic!("an NXDOMAIN answer is an answer, not an error");
        };
        assert!(reply.addresses.is_empty());
        assert_eq!(rcode_of(&reply.message), rcode::NXDOMAIN);
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

        let result = server.query_upstream("example.com", 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_upstream_fallback_to_secondary() {
        use crate::SharedState;

        // A local UDP socket that accepts a query and never answers. This
        // is the primary that does not work.
        let Some(silent) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let primary_addr = silent.local_addr().unwrap();
        let _silent_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                // Read and discard each query; never answer.
                let _ = silent.recv_from(&mut buf).await;
            }
        });

        // The fake upstream is the secondary, so the test needs no
        // internet and the answer is a known address.
        let Some((secondary, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            upstream: Some(vec![primary_addr, secondary]),
            resolve_timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();

        // The primary runs into the timeout; the secondary answers.
        let reply = server
            .query_upstream("example.com", rtype::A)
            .await
            .unwrap();
        let expected: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(reply.addresses, vec![expected]);
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

    #[tokio::test]
    async fn test_dns_query_unsupported_record_type() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);

        // An MX query (type 15) for an allowed name goes upstream like any
        // other type. The fake upstream has no MX record, so the answer is
        // NOERROR with no record, and nothing reaches the address cache.
        let query = build_test_dns_query("example.com", 15);
        let Ok(response) = server.handle_query(&query).await else {
            panic!("the server must answer an MX query, not fail");
        };
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert!(state.cache.is_empty());

        // The same type for a name that the allowlist does not have gets
        // NXDOMAIN, like every other type.
        let query = build_test_dns_query("other.example", 15);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
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

        // The proof is an answer, not a connect: a UDP connect to a port
        // that nothing serves also succeeds.
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            handle.abort();
            return;
        };
        let query = build_test_dns_query("blocked.example", 1);
        socket.send_to(&query, config.bind_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let answer =
            tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv(&mut buf)).await;
        handle.abort();
        let Ok(Ok(len)) = answer else {
            panic!("the DNS server did not answer the query");
        };
        assert!(len >= 12, "the answer is shorter than a DNS header");
        assert_eq!(&buf[0..2], &query[0..2], "the answer has the query id");
        assert_eq!(buf[2] & 0x80, 0x80, "the answer has the response bit");
    }

    #[tokio::test]
    async fn test_dns_server_handles_concurrent_queries() {
        use crate::SharedState;
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let state = Arc::new(SharedState::new(vec!["*.example.com".to_string()]));

        // Pre-bind to get a free port.
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let bound_addr = socket.local_addr().unwrap();
        drop(socket);

        let config = DnsServerConfig {
            bind_addr: bound_addr,
            upstream: Some(vec![upstream]),
            resolve_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let server = DnsServer::new(config.clone(), state).unwrap();

        let handle = tokio::spawn(async move { server.run().await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        /// Send one query and wait for the answer. Returns the answer.
        async fn ask(addr: SocketAddr, name: &str) -> Option<Vec<u8>> {
            let socket = udp_bind_or_skip("127.0.0.1:0").await?;
            let query = build_test_dns_query(name, rtype::A);
            socket.send_to(&query, addr).await.ok()?;
            let mut buf = [0u8; 512];
            let got = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await;
            match got {
                Ok(Ok(len)) => buf.get(..len).map(<[u8]>::to_vec),
                _ => None,
            }
        }

        // One query for which the upstream waits one second, and nine
        // queries that the upstream answers at once.
        let addr = config.bind_addr;
        let slow = tokio::spawn(async move { ask(addr, SLOW_NAME).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let fast: Vec<_> = (0..9)
            .map(|_| tokio::spawn(async move { ask(addr, "fast.example.com").await }))
            .collect();

        let start = std::time::Instant::now();
        let mut answered = 0;
        for task in fast {
            if matches!(task.await, Ok(Some(ref answer)) if rcode_of(answer) == rcode::NOERROR) {
                answered += 1;
            }
        }
        let fast_time = start.elapsed();

        // The nine fast answers come back while the slow one still waits.
        // A server that handles one query at a time needs more than the
        // second of the slow query.
        assert_eq!(answered, 9, "the server answered {answered} of 9 queries");
        assert!(
            fast_time < Duration::from_millis(800),
            "a slow query blocked the others: the fast answers took {fast_time:?}"
        );

        // The slow query gets its answer too.
        let slow = slow.await;
        handle.abort();
        let Ok(Some(answer)) = slow else {
            panic!("the server lost the slow query");
        };
        assert_eq!(rcode_of(&answer), rcode::NOERROR);
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

    // ========================================================================
    // Local Fake Upstream Tests (no network access)
    // ========================================================================

    /// The name for which the fake upstream waits before it answers.
    const SLOW_NAME: &str = "slow.example.com";

    /// The name for which the fake upstream gives two A records.
    const MULTI_NAME: &str = "multi.example.com";

    /// Build the answer of the fake upstream for one query.
    fn fake_answer(query: &[u8]) -> Option<Vec<u8>> {
        let question = read_question(query, Pointers::Forbidden).ok()?;
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut code = rcode::NOERROR;
        let record = |rr_type: u16, ttl: u32, rdata: &[u8]| {
            let mut r = vec![0xC0, 0x0C];
            r.extend_from_slice(&rr_type.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            r.extend_from_slice(rdata);
            r
        };
        if question.name.eq_ignore_ascii_case("nx.example.com") {
            code = rcode::NXDOMAIN;
        } else if question.name.eq_ignore_ascii_case(MULTI_NAME) {
            if question.qtype == rtype::A {
                records.push(record(rtype::A, 60, &[198, 51, 100, 1]));
                records.push(record(rtype::A, 60, &[198, 51, 100, 2]));
            }
        } else {
            match question.qtype {
                rtype::A => records.push(record(rtype::A, 5, &[93, 184, 216, 34])),
                rtype::AAAA => {
                    let ip: Ipv6Addr = "2606:2800:220:1::1".parse().unwrap();
                    records.push(record(rtype::AAAA, 100_000, &ip.octets()));
                }
                16 => records.push(record(16, 60, b"\x05hello")),
                _ => {}
            }
        }
        let mut response = query.get(..2)?.to_vec();
        response.extend_from_slice(&[0x81, 0x80 | code]);
        response.extend_from_slice(&[0, 1]);
        response.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        response.extend_from_slice(&[0, 0, 0, 0]);
        response.extend_from_slice(query.get(HEADER_LEN..question.end)?);
        for r in records {
            response.extend_from_slice(&r);
        }
        Some(response)
    }

    /// Start a fake upstream DNS server on `bind`. Returns `None` if the
    /// test cannot bind the address.
    async fn fake_upstream(bind: &str) -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let socket = Arc::new(tokio::net::UdpSocket::bind(bind).await.ok()?);
        let addr = socket.local_addr().ok()?;
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let query = buf[..len].to_vec();
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    let slow = read_question(&query, Pointers::Forbidden)
                        .is_ok_and(|q| q.name == SLOW_NAME);
                    if slow {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    if let Some(answer) = fake_answer(&query) {
                        let _ = socket.send_to(&answer, src).await;
                    }
                });
            }
        });
        Some((addr, handle))
    }

    fn server_with_upstream(
        upstream: SocketAddr,
        allowlist: &[&str],
    ) -> (
        DnsServer,
        Arc<SharedState>,
        tokio::sync::mpsc::UnboundedReceiver<crate::TraceEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let state = Arc::new(SharedState::with_violation_tx(
            allowlist.iter().map(|s| (*s).to_string()).collect(),
            Some(tx),
        ));
        let config = DnsServerConfig {
            upstream: Some(vec![upstream]),
            resolve_timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let server = DnsServer::new(config, Arc::clone(&state)).unwrap();
        (server, state, rx)
    }

    /// Return `(type, ttl)` of the first answer record of a response.
    fn first_answer(response: &[u8]) -> (u16, u32) {
        let question = read_question(response, Pointers::Allowed).unwrap();
        let (_, pos) =
            read_name(response, question.end, Pointers::Allowed, LabelBytes::Any).unwrap();
        (
            read_u16(response, pos).unwrap(),
            read_u32(response, pos + 4).unwrap(),
        )
    }

    fn rcode_of(response: &[u8]) -> u8 {
        response[3] & 0x0F
    }

    #[tokio::test]
    async fn test_a_query_forwards_a_and_clamps_ttl_floor() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let query = build_test_dns_query("example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();

        assert_eq!(&response[..2], &[0xAB, 0xCD], "client ID kept");
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        // Upstream TTL 5 is raised to the 30 s floor.
        assert_eq!(first_answer(&response), (rtype::A, 30));
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[tokio::test]
    async fn test_aaaa_query_gets_aaaa_and_ttl_max() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, mut rx) = server_with_upstream(upstream, &["example.com"]);
        let query = build_test_dns_query("example.com", rtype::AAAA);
        let response = server.handle_query(&query).await.unwrap();

        // Never an A record for an AAAA query; upstream TTL 100000 is
        // reduced to the 300 s maximum.
        assert_eq!(first_answer(&response), (rtype::AAAA, 300));
        let ip: IpAddr = "2606:2800:220:1::1".parse().unwrap();
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(state.cache.lookup(&v4), None);

        match rx.try_recv() {
            Ok(crate::TraceEvent::Access(m)) => {
                assert_eq!(m, "network: DNS query for \"example.com\" (AAAA) allowed");
            }
            other => panic!("expected an access event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_txt_query_passes_through() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let query = build_test_dns_query("example.com", 16);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(first_answer(&response), (16, 60));
        assert!(state.cache.is_empty());
    }

    #[tokio::test]
    async fn test_upstream_nxdomain_passes_through() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["*.example.com"]);
        let query = build_test_dns_query("nx.example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
    }

    #[tokio::test]
    async fn test_response_keeps_client_case() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let query = build_test_dns_query("ExAmPlE.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        let question_end = read_question(&query, Pointers::Forbidden).unwrap().end;
        assert_eq!(&response[12..question_end], &query[12..question_end]);
    }

    #[tokio::test]
    async fn test_ipv6_upstream_uses_ipv6_socket() {
        let Some((upstream, _task)) = fake_upstream("[::1]:0").await else {
            return; // No IPv6 loopback in this environment.
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let reply = server
            .query_upstream("example.com", rtype::A)
            .await
            .unwrap();
        assert_eq!(
            reply.addresses,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn test_qdcount_not_one_gets_formerr() {
        let (server, _state, _rx) = server_with_upstream("127.0.0.1:9".parse().unwrap(), &[]);
        let mut two = build_test_dns_query("example.com", rtype::A);
        two[5] = 2;
        let response = server.handle_query(&two).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::FORMERR);
        assert_eq!(&response[4..6], &[0, 0]);

        let mut zero = build_test_dns_query("example.com", rtype::A);
        zero[5] = 0;
        let response = server.handle_query(&zero).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::FORMERR);
    }

    #[tokio::test]
    async fn test_bad_labels_get_formerr() {
        let (server, _state, _rx) =
            server_with_upstream("127.0.0.1:9".parse().unwrap(), &["*.example.com"]);
        let header = [0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let tail = [0, 0, 1, 0, 1]; // root, QTYPE A, QCLASS IN
        let cases: [&[u8]; 5] = [
            &[0x41, b'a'],                    // length byte with 0x40 set
            &[0x81, b'a'],                    // length byte with 0x80 set
            &[3, b'a', b'.', b'b'],           // '.' inside a label
            &[3, b'a', 0x01, b'b'],           // byte that is not printable
            &[3, b'w', b'w', b'w', 0xC0, 12], // pointer in the question
        ];
        for case in cases {
            let mut query = header.to_vec();
            query.extend_from_slice(case);
            query.extend_from_slice(&tail);
            let response = server.handle_query(&query).await.unwrap();
            assert_eq!(rcode_of(&response), rcode::FORMERR, "case {case:?}");
        }
    }

    #[test]
    fn test_read_name_rejects_forward_pointer_loop() {
        // A pointer to itself.
        let msg = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 12];
        assert_eq!(
            read_name(&msg, 12, Pointers::Allowed, LabelBytes::Any),
            Err(WireError::BadPointer)
        );
    }

    /// A compression pointer must point backwards. A pointer that points
    /// forward lets a message send the parser ahead in the message.
    #[test]
    fn read_name_rejects_a_pointer_that_points_forward() {
        let mut msg = vec![0x01, b'a', 0x00]; // offset 0: the name "a"
        msg.extend_from_slice(&[0xC0, 0x08]); // offset 3: a pointer to 8
        msg.extend_from_slice(&[0x00, 0x00, 0x00]); // offsets 5, 6, 7
        msg.extend_from_slice(&[0x01, b'b', 0x00]); // offset 8: the name "b"
        assert_eq!(
            read_name(&msg, 3, Pointers::Allowed, LabelBytes::Any),
            Err(WireError::BadPointer)
        );
        // The same name, read without the pointer, is valid. Thus the
        // rejection comes from the direction of the pointer.
        assert_eq!(
            read_name(&msg, 8, Pointers::Allowed, LabelBytes::Any),
            Ok(("b".to_string(), 11))
        );
    }

    /// The parser follows at most `MAX_POINTER_HOPS` pointers. The limit
    /// stops a chain that is long but has no loop.
    #[test]
    fn read_name_follows_at_most_the_permitted_number_of_pointers() {
        // The name "a" at offset 0, then a chain of backward pointers: the
        // pointer at offset p points to p - 2, and the first one points to 0.
        let mut msg = vec![0x01, b'a', 0x00];
        for i in 0..=MAX_POINTER_HOPS {
            let target = if i == 0 { 0 } else { 1 + 2 * i };
            msg.push(0xC0);
            msg.push(u8::try_from(target).unwrap());
        }
        let last = 3 + 2 * MAX_POINTER_HOPS;
        // From the second-last pointer the chain has exactly
        // `MAX_POINTER_HOPS` pointers, which is permitted.
        assert_eq!(
            read_name(&msg, last - 2, Pointers::Allowed, LabelBytes::Any),
            Ok(("a".to_string(), last))
        );
        // One pointer more is not permitted.
        assert_eq!(
            read_name(&msg, last, Pointers::Allowed, LabelBytes::Any),
            Err(WireError::BadPointer)
        );
    }

    /// A pointer can name an offset above 255, so the parser must use the
    /// low six bits of the first byte as the high bits of the offset.
    #[test]
    fn read_name_follows_a_pointer_above_offset_255() {
        let mut msg = vec![0u8; 300];
        msg.extend_from_slice(&[0x04, b'd', b'e', b'e', b'p', 0x00]); // offset 300
        msg.extend_from_slice(&[0xC1, 0x2C]); // offset 306: a pointer to 0x012C
        assert_eq!(
            read_name(&msg, 306, Pointers::Allowed, LabelBytes::Any),
            Ok(("deep".to_string(), 308))
        );
    }

    /// The resolvers of the host come from the `nameserver` lines of
    /// `resolv.conf`. A wrong answer here sends each query of the sandbox
    /// to the wrong server, or to no server.
    #[test]
    fn resolv_conf_gives_each_nameserver_on_port_53() {
        let text = "# a comment\n\
                    domain example.com\n\
                    search example.com lan\n\
                    nameserver 192.0.2.1\n\
                    nameserver 2001:db8::1\n\
                    nameserver fe80::1%eth0\n\
                    nameserver not-an-address\n\
                    nameserver\n\
                    options edns0\n";
        assert_eq!(
            parse_resolv_conf(text),
            Some(vec![
                "192.0.2.1:53".parse().unwrap(),
                "[2001:db8::1]:53".parse().unwrap(),
                "[fe80::1]:53".parse().unwrap(),
            ])
        );
        // A file with no usable address gives nothing, so the caller takes
        // the fallback resolvers.
        assert_eq!(parse_resolv_conf(""), None);
        assert_eq!(parse_resolv_conf("search example.com\n"), None);
        assert_eq!(parse_resolv_conf("nameserver not-an-address\n"), None);
        // A line that only starts with "nameserver" is not a nameserver
        // line.
        assert_eq!(parse_resolv_conf("nameservers 192.0.2.1\n"), None);
    }

    /// The read of the resolver file gives the resolvers of the file, and
    /// `None` for each file that holds no usable address. The caller then
    /// takes the fallback resolvers.
    #[test]
    fn the_resolver_file_gives_the_resolvers_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let read = |name: &str| DnsServerConfig::read_resolvers(&dir.path().join(name));

        // A file that is not there.
        assert_eq!(read("missing"), None);
        // A directory at the path: the read fails with another error.
        std::fs::create_dir(dir.path().join("a-directory")).unwrap();
        assert_eq!(read("a-directory"), None);
        // An empty file.
        std::fs::write(dir.path().join("empty"), "").unwrap();
        assert_eq!(read("empty"), None);
        // A file with no nameserver line.
        std::fs::write(dir.path().join("no-nameserver"), "search example.com\n").unwrap();
        assert_eq!(read("no-nameserver"), None);
        // A file with an address that the parser does not accept.
        std::fs::write(dir.path().join("bad-address"), "nameserver 300.1.2.3\n").unwrap();
        assert_eq!(read("bad-address"), None);
        // A file with one good address and one bad address.
        std::fs::write(
            dir.path().join("good"),
            "nameserver 300.1.2.3\nnameserver 192.0.2.1\n",
        )
        .unwrap();
        assert_eq!(read("good"), Some(vec!["192.0.2.1:53".parse().unwrap()]));
    }

    /// The resolvers of the system come from the file of the system. The
    /// test reads the same file and compares, thus it does not depend on
    /// the content. It ends when the machine has no usable file.
    #[test]
    fn the_system_resolvers_come_from_the_file_of_the_system() {
        let expected = std::fs::read_to_string(RESOLV_CONF)
            .ok()
            .and_then(|text| parse_resolv_conf(&text));
        let Some(expected) = expected else {
            crate::test_support::skip("this machine has no usable /etc/resolv.conf");
            return;
        };
        assert_eq!(DnsServerConfig::read_system_resolvers(), Some(expected));
    }

    /// The transaction ID of an upstream query must not be the same each
    /// time. A fixed ID lets a remote host answer before the real server.
    #[test]
    fn the_upstream_transaction_id_changes() {
        let seen: std::collections::HashSet<u16> = (0..1000).map(|_| random_id()).collect();
        assert!(
            seen.len() > 1,
            "the transaction ID is always the same: {seen:?}"
        );
    }

    /// An error response is a server answer: it repeats the ID, it sets QR
    /// and RA, it keeps the opcode and the RD bit of the query, and it
    /// carries the response code.
    #[test]
    fn an_error_response_has_the_flags_of_a_server_answer() {
        let query = build_test_dns_query("example.com", rtype::A); // RD = 1
        let r = build_error_response(&query, None, rcode::NXDOMAIN);
        assert_eq!(&r[..2], &[0xAB, 0xCD], "the ID of the query");
        assert_eq!(r[2] & 0x80, 0x80, "QR is set");
        assert_eq!(r[2] & 0x78, 0x00, "the opcode stays 0");
        assert_eq!(r[2] & 0x01, 0x01, "RD comes from the query");
        assert_eq!(r[2] & 0x02, 0x00, "TC is not set");
        assert_eq!(r[3] & 0x80, 0x80, "RA is set");
        assert_eq!(rcode_of(&r), rcode::NXDOMAIN);

        let mut no_rd = query.clone();
        no_rd[2] = 0x00;
        let r = build_error_response(&no_rd, None, rcode::NXDOMAIN);
        assert_eq!(
            r[2] & 0x01,
            0x00,
            "a query without RD gives a response without RD"
        );
        assert_eq!(r[2] & 0x80, 0x80, "QR is set");
    }

    /// A SERVFAIL response is a real response: the ID of the query, the QR
    /// bit, the code and the question.
    #[test]
    fn a_servfail_response_answers_the_query() {
        let query = build_test_dns_query("example.com", rtype::A);
        let r = DnsServer::build_servfail_response(&query);
        assert_eq!(&r[..2], &[0xAB, 0xCD], "the ID of the query");
        assert_eq!(r[2] & 0x80, 0x80, "QR is set");
        assert_eq!(rcode_of(&r), rcode::SERVFAIL);
        assert_eq!(
            u16::from_be_bytes([r[4], r[5]]),
            1,
            "the response repeats the question"
        );
    }

    /// A query with a header and no question is a malformed query, not an
    /// internal error. A query shorter than the header is an error.
    #[test]
    fn a_header_without_a_question_gets_formerr() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (server, _state, _rx) = server_with_upstream(dead, &["example.com"]);
        let header_only = vec![0xAB, 0xCD, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = runtime
            .block_on(server.handle_query(&header_only))
            .expect("a malformed query gets a response");
        assert_eq!(rcode_of(&r), rcode::FORMERR);
        assert!(
            runtime
                .block_on(server.handle_query(&header_only[..11]))
                .is_err(),
            "a query shorter than the header is an error"
        );
    }

    /// A zone transfer, and a class other than IN, get NOTIMP. The proxy
    /// does not forward them.
    #[tokio::test]
    async fn zone_transfers_and_other_classes_get_notimp() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (server, _state, _rx) = server_with_upstream(dead, &["example.com"]);
        for qtype in [rtype::AXFR, rtype::IXFR] {
            let query = build_test_dns_query("example.com", qtype);
            let r = server.handle_query(&query).await.unwrap();
            assert_eq!(rcode_of(&r), rcode::NOTIMP, "the query type {qtype}");
        }
        // The class CH (3) instead of IN.
        let mut query = build_test_dns_query("example.com", rtype::A);
        let last = query.len() - 1;
        query[last] = 0x03;
        let r = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&r), rcode::NOTIMP, "the class is not IN");
    }

    /// The response that the client gets is a server answer: QR and RA are
    /// set, TC is not, the opcode stays 0, and RD comes from the query.
    #[tokio::test]
    async fn the_forwarded_response_has_the_flags_of_a_server_answer() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) =
            server_with_upstream(upstream, &["example.com", "two.example.com"]);
        let query = build_test_dns_query("example.com", rtype::A);
        let r = server.handle_query(&query).await.unwrap();
        assert_eq!(r[2] & 0x80, 0x80, "QR is set");
        assert_eq!(r[2] & 0x78, 0x00, "the opcode stays 0");
        assert_eq!(r[2] & 0x01, 0x01, "RD comes from the query");
        assert_eq!(r[2] & 0x02, 0x00, "TC is not set");
        assert_eq!(r[3] & 0x80, 0x80, "RA is set");
        assert_eq!(rcode_of(&r), rcode::NOERROR);

        let mut no_rd = build_test_dns_query("two.example.com", rtype::A);
        no_rd[2] = 0x00;
        let r = server.handle_query(&no_rd).await.unwrap();
        assert_eq!(
            r[2] & 0x01,
            0x00,
            "a query without RD gives a response without RD"
        );
        assert_eq!(r[2] & 0x80, 0x80, "QR is set");
    }

    /// An upstream server that answers SERVFAIL gives no answer: the
    /// server asks the next upstream.
    #[tokio::test]
    async fn an_upstream_that_fails_is_not_the_answer() {
        let Some((bad, _t1)) = servfail_upstream().await else {
            return;
        };
        let Some((good, _t2)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let state = Arc::new(SharedState::with_violation_tx(
            vec!["example.com".to_string()],
            Some(tx),
        ));
        let config = DnsServerConfig {
            upstream: Some(vec![bad, good]),
            resolve_timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();
        let query = build_test_dns_query("example.com", rtype::A);
        let r = server.handle_query(&query).await.unwrap();
        assert_eq!(
            rcode_of(&r),
            rcode::NOERROR,
            "the server must ask the next upstream after SERVFAIL"
        );
        assert_eq!(
            u16::from_be_bytes([r[6], r[7]]),
            1,
            "the answer comes from the upstream that works"
        );
    }

    /// A fake upstream that answers SERVFAIL to each query.
    async fn servfail_upstream() -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?);
        let addr = socket.local_addr().ok()?;
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let query = &buf[..len];
                let Ok(question) = read_question(query, Pointers::Forbidden) else {
                    continue;
                };
                let mut reply = query[..2].to_vec();
                reply.extend_from_slice(&[0x81, 0x80 | rcode::SERVFAIL]);
                reply.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
                reply.extend_from_slice(&query[HEADER_LEN..question.end]);
                let _ = socket.send_to(&reply, src).await;
            }
        });
        Some((addr, handle))
    }

    #[test]
    fn test_clamp_ttl_bounds() {
        assert_eq!(clamp_ttl(5, (30, 300)), 30);
        assert_eq!(clamp_ttl(100, (30, 300)), 100);
        assert_eq!(clamp_ttl(100_000, (30, 300)), 300);
        // The maximum has priority if it is smaller than the minimum.
        assert_eq!(clamp_ttl(5, (30, 1)), 1);
    }

    /// The longest name in wire format is 255 bytes. The parser must
    /// accept a name of exactly 255 bytes, and reject one byte more. A
    /// wrong limit rejects a name that the allowlist permits.
    #[test]
    fn a_name_of_255_wire_bytes_is_accepted_and_256_is_not() {
        let wire_name = |lengths: &[usize]| -> Vec<u8> {
            let mut message = Vec::new();
            for &len in lengths {
                message.push(u8::try_from(len).unwrap());
                message.extend(std::iter::repeat_n(b'a', len));
            }
            message.push(0);
            message
        };

        // Each label takes its length byte too, and the name ends with
        // the byte of the root label. Three labels of 63 bytes and one
        // label of 61 bytes give 64 + 64 + 64 + 62 + 1 = 255.
        let longest = wire_name(&[63, 63, 63, 61]);
        let read = read_name(&longest, 0, Pointers::Forbidden, LabelBytes::Any);
        assert!(
            read.is_ok(),
            "a name of 255 bytes must be accepted: {read:?}"
        );

        let too_long = wire_name(&[63, 63, 63, 62]);
        assert_eq!(
            read_name(&too_long, 0, Pointers::Forbidden, LabelBytes::Any),
            Err(WireError::NameTooLong)
        );
    }

    /// The parser of an upstream reply takes the response code from the low
    /// four bits of the second flag byte, and it takes the addresses from
    /// the answer section only. A record of the authority section or of the
    /// additional section must not reach the cache of the proxy.
    #[test]
    fn the_upstream_reply_gives_the_code_and_only_the_answer_addresses() {
        let query = build_dns_query(0x1234, "example.com", rtype::A);
        let question = read_question(&query, Pointers::Forbidden).unwrap();
        let record = |rr_type: u16, ttl: u32, rdata: &[u8]| {
            let mut r = vec![0xC0, 0x0C];
            r.extend_from_slice(&rr_type.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            r.extend_from_slice(rdata);
            r
        };

        let mut reply = query[..2].to_vec();
        reply.extend_from_slice(&[0x81, 0x80 | rcode::NOERROR]);
        reply.extend_from_slice(&[0, 1]); // one question
        reply.extend_from_slice(&[0, 1]); // one answer
        reply.extend_from_slice(&[0, 1]); // one record in the authority section
        reply.extend_from_slice(&[0, 0]); // no record in the additional section
        reply.extend_from_slice(&query[HEADER_LEN..question.end]);
        reply.extend_from_slice(&record(rtype::A, 60, &[93, 184, 216, 34]));
        reply.extend_from_slice(&record(rtype::A, 60, &[203, 0, 113, 9]));

        let result =
            process_upstream_response(reply.clone(), 0x1234, "example.com", rtype::A, (30, 300));
        let code = result.as_ref().ok().map(|reply| reply.rcode);
        assert_eq!(code, Some(rcode::NOERROR), "{result:?}");
        let addresses = result.as_ref().ok().map(|reply| reply.addresses.clone());
        assert_eq!(
            addresses,
            Some(vec!["93.184.216.34".parse::<IpAddr>().unwrap()]),
            "only the answer section gives addresses"
        );

        // A message with no QR bit is a query, not a response. The server
        // must not take it as an answer: an answer to a response can make
        // a loop, and a query of another host must not reach the cache.
        let mut not_a_response = reply;
        not_a_response[2] = 0x01;
        assert_eq!(
            process_upstream_response(not_a_response, 0x1234, "example.com", rtype::A, (30, 300)),
            Err(WireError::Mismatch)
        );

        // A reply that holds only a header has no question. The length
        // guard accepts it, and the rule for one question rejects it.
        let header_only = vec![0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            process_upstream_response(header_only, 0x1234, "example.com", rtype::A, (30, 300)),
            Err(WireError::Mismatch)
        );
        // A reply that is shorter than the header is truncated.
        assert_eq!(
            process_upstream_response(vec![0x12, 0x34], 0x1234, "example.com", rtype::A, (30, 300)),
            Err(WireError::Truncated)
        );
    }

    #[test]
    fn test_upstream_response_with_wrong_id_rejected() {
        let query = build_dns_query(0x1234, "example.com", rtype::A);
        let answer = fake_answer(&query).unwrap();
        assert_eq!(
            process_upstream_response(answer.clone(), 0x4321, "example.com", rtype::A, (30, 300)),
            Err(WireError::Mismatch)
        );
        assert_eq!(
            process_upstream_response(answer.clone(), 0x1234, "other.com", rtype::A, (30, 300)),
            Err(WireError::Mismatch)
        );
        assert_eq!(
            process_upstream_response(answer, 0x1234, "example.com", rtype::AAAA, (30, 300)),
            Err(WireError::Mismatch)
        );
    }

    #[tokio::test]
    async fn test_slow_upstream_does_not_block_other_queries() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let Some(server_socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let server_addr = server_socket.local_addr().unwrap();
        let (server, _state, _rx) = server_with_upstream(upstream, &["*.example.com"]);
        let run = tokio::spawn(async move { server.run_on(server_socket).await });

        let client = udp_bind_or_skip("127.0.0.1:0").await.unwrap();
        let mut slow = build_test_dns_query(SLOW_NAME, rtype::A);
        slow[0] = 0x01;
        let mut fast = build_test_dns_query("fast.example.com", rtype::A);
        fast[0] = 0x02;
        client.send_to(&slow, server_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.send_to(&fast, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(700), client.recv_from(&mut buf))
            .await
            .expect("the fast query must not wait for the slow query")
            .unwrap();
        assert!(len > 12);
        assert_eq!(buf[0], 0x02, "the first answer is for the fast query");

        let (_, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf[0], 0x01);
        run.abort();
    }

    // ========================================================================
    // Watch Event Tests
    // ========================================================================

    fn watched_server(
        upstream: SocketAddr,
        allowlist: &[&str],
        policy: crate::ProxyPolicy,
    ) -> (
        DnsServer,
        Arc<SharedState>,
        tokio::sync::mpsc::UnboundedReceiver<WatchEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let state = Arc::new(
            SharedState::new(allowlist.iter().map(|s| (*s).to_string()).collect())
                .with_policy(policy)
                .with_event_tx(Some(tx)),
        );
        let config = DnsServerConfig {
            upstream: Some(vec![upstream]),
            resolve_timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let server = DnsServer::new(config, Arc::clone(&state)).unwrap();
        (server, state, rx)
    }

    fn dns_event(name: &str, qtype: &str, outcome: Outcome) -> WatchEvent {
        WatchEvent::Dns {
            name: name.to_string(),
            qtype: qtype.to_string(),
            outcome,
        }
    }

    #[tokio::test]
    async fn test_observe_answers_unlisted_name_and_emits_event() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, state, mut rx) =
            watched_server(upstream, &["allowed.example"], crate::ProxyPolicy::Observe);
        let query = build_test_dns_query("Unlisted.Example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(
            state.cache.lookup(&ip),
            Some("unlisted.example.com".to_string())
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            dns_event("unlisted.example.com", "A", Outcome::Allowed)
        );
        assert!(rx.try_recv().is_err(), "exactly one event");

        let query = build_test_dns_query("unlisted.example.com", 65);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(
            rx.try_recv().unwrap(),
            dns_event("unlisted.example.com", "HTTPS", Outcome::Allowed)
        );
    }

    #[tokio::test]
    async fn test_enforce_emits_dns_events_with_outcome() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, mut rx) = watched_server(
            upstream,
            &["example.com", "nx.example.com"],
            crate::ProxyPolicy::Enforce,
        );

        let query = build_test_dns_query("blocked.test", rtype::AAAA);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
        assert_eq!(
            rx.try_recv().unwrap(),
            dns_event("blocked.test", "AAAA", Outcome::Denied)
        );

        let query = build_test_dns_query("example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(
            rx.try_recv().unwrap(),
            dns_event("example.com", "A", Outcome::Allowed)
        );

        // An upstream NXDOMAIN does not change the policy outcome.
        let query = build_test_dns_query("nx.example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
        assert_eq!(
            rx.try_recv().unwrap(),
            dns_event("nx.example.com", "A", Outcome::Allowed)
        );
    }

    // ========================================================================
    // The decisions and the error paths that the coverage run found open.
    // See docs/testing/fuzzing-and-coverage.md.
    // ========================================================================

    /// An upstream that answers with an error code is not an answer. The
    /// server tries the next upstream. Without this rule one upstream that
    /// answers REFUSED would block every name.
    #[tokio::test]
    async fn an_upstream_error_code_makes_the_server_try_the_next_one() {
        use crate::SharedState;
        // The first upstream answers REFUSED for every query.
        let Some(refusing) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let Ok(first) = refusing.local_addr() else {
            panic!("the socket of the test must have an address");
        };
        let refuse = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, src)) = refusing.recv_from(&mut buf).await else {
                    return;
                };
                let query = &buf[..len];
                let Ok(question) = read_question(query, Pointers::Forbidden) else {
                    continue;
                };
                let mut answer = query[..2].to_vec();
                answer.extend_from_slice(&[0x81, 0x80 | 5]); // REFUSED
                answer.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
                answer.extend_from_slice(&query[HEADER_LEN..question.end]);
                let _ = refusing.send_to(&answer, src).await;
            }
        });
        let Some((second, _task)) = fake_upstream("127.0.0.1:0").await else {
            refuse.abort();
            return;
        };
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            upstream: Some(vec![first, second]),
            resolve_timeout: Duration::from_secs(3),
            ..Default::default()
        };
        let Ok(server) = DnsServer::new(config, state) else {
            panic!("DnsServer::new must accept two upstream servers");
        };
        let query = build_test_dns_query("example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        refuse.abort();
    }

    /// The TCP server closes a connection that sends nothing, and it
    /// refuses a connection above the limit. Without the limit one client
    /// could hold every connection slot.
    #[tokio::test]
    async fn the_tcp_server_closes_an_empty_connection_and_holds_its_limit() {
        use tokio::io::AsyncReadExt;
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                crate::test_support::skip("this machine cannot bind a TCP socket on the loopback");
                return;
            }
            Err(err) => panic!("Failed to bind TCP listener for test: {err}"),
        };
        let Ok(bound) = listener.local_addr() else {
            panic!("the listener of the test must have an address");
        };
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        use crate::SharedState;
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let config = DnsServerConfig {
            upstream: Some(vec![upstream]),
            // One connection at a time.
            max_concurrent_queries: 1,
            ..Default::default()
        };
        let Ok(server) = DnsServer::new(config, state) else {
            panic!("DnsServer::new must accept the configuration");
        };
        let run = tokio::spawn(async move {
            let _ = server.run_tcp_on(listener).await;
        });

        // The first connection stays open and holds the only slot.
        let mut held = tokio::net::TcpStream::connect(bound).await.unwrap();
        // Wait until the server took the connection and the permit.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The second connection is above the limit: the server closes it.
        let mut extra = tokio::net::TcpStream::connect(bound).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "the server must close the connection above the limit: {read:?}"
        );

        // The first connection closes with no query, and the server frees
        // the slot, so a new connection gets served.
        drop(held);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let third = tokio::net::TcpStream::connect(bound).await;
        assert!(third.is_ok(), "the server must accept a new connection");
        held = third.unwrap();
        drop(held);
        run.abort();
    }

    /// Every query type has a text. The text goes into the violation
    /// message and into the watch event, so a wrong or empty text makes
    /// the record of the run wrong.
    #[test]
    fn every_query_type_has_a_text() {
        let known = [
            (1u16, "A"),
            (2, "NS"),
            (5, "CNAME"),
            (6, "SOA"),
            (12, "PTR"),
            (15, "MX"),
            (16, "TXT"),
            (28, "AAAA"),
            (33, "SRV"),
            (64, "SVCB"),
            (65, "HTTPS"),
            (255, "ANY"),
        ];
        for (qtype, text) in known {
            assert_eq!(qtype_name(qtype), text, "the type {qtype} has another text");
        }
        // A type that the list does not hold keeps its number.
        assert_eq!(qtype_name(99), "TYPE99");
        assert_eq!(qtype_name(0), "TYPE0");
        assert_eq!(qtype_name(u16::MAX), "TYPE65535");
    }

    /// A query with an opcode that is not 0 gets NOTIMP, and the server
    /// does not forward it. An UPDATE query (opcode 5) must never reach an
    /// upstream server.
    #[tokio::test]
    async fn a_query_with_another_opcode_gets_notimp() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, mut rx) = server_with_upstream(upstream, &["example.com"]);
        let mut query = build_test_dns_query("example.com", rtype::A);
        // Opcode 5 (UPDATE) in the four bits above the recursion flag.
        query[2] = 0x28;
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOTIMP);
        // The response holds no question, so the client cannot read a name
        // that the server did not check.
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 0);
        assert!(response[2] & FLAG_QR != 0, "the answer has no QR bit");
        assert!(rx.try_recv().is_err(), "a NOTIMP query makes no event");
    }

    /// A zone transfer gets NOTIMP, also for a domain that the allowlist
    /// holds. A zone transfer would give the program the whole zone.
    #[tokio::test]
    async fn a_zone_transfer_gets_notimp() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, mut rx) = server_with_upstream(upstream, &["example.com"]);
        for qtype in [rtype::AXFR, rtype::IXFR] {
            let query = build_test_dns_query("example.com", qtype);
            let response = server.handle_query(&query).await.unwrap();
            assert_eq!(
                rcode_of(&response),
                rcode::NOTIMP,
                "the query type {qtype} must get NOTIMP"
            );
            // The server repeats the question of the client.
            assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
            assert!(rx.try_recv().is_err(), "a zone transfer makes no event");
        }
    }

    /// A query in a class that is not IN gets NOTIMP. The allowlist has no
    /// meaning in another class.
    #[tokio::test]
    async fn a_query_in_another_class_gets_notimp() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let mut query = build_test_dns_query("example.com", rtype::A);
        // The class CHAOS (3) in the last two bytes.
        let len = query.len();
        query[len - 2] = 0x00;
        query[len - 1] = 0x03;
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOTIMP);
    }

    /// A question whose name is not a valid host name gets NXDOMAIN, the
    /// server reports a violation, and the event holds the name in
    /// lowercase without the trailing dot.
    #[tokio::test]
    async fn a_name_that_is_not_a_host_name_is_blocked() {
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        // The allowlist holds "*", so only the shape of the name blocks it.
        let (server, _state, mut rx) = server_with_upstream(upstream, &["**"]);
        // A label with a character that a host name cannot hold.
        let query = build_test_dns_query("BAD$NAME.example", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
        let Ok(crate::TraceEvent::Violation(message)) = rx.try_recv() else {
            panic!("the server must report a violation");
        };
        assert!(
            message.contains("BAD$NAME.example"),
            "the message must name the query: {message}"
        );
    }

    /// The SERVFAIL answer of an internal error is a response, and it
    /// repeats the question of the client.
    #[test]
    fn the_servfail_answer_repeats_the_question() {
        let query = build_test_dns_query("example.com", rtype::A);
        let response = DnsServer::build_servfail_response(&query);
        assert_eq!(rcode_of(&response), rcode::SERVFAIL);
        assert!(response[2] & FLAG_QR != 0, "the answer has no QR bit");
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(&response[HEADER_LEN..], &query[HEADER_LEN..]);
        // A query that holds no question gives a header with no question.
        let short = DnsServer::build_servfail_response(&query[..HEADER_LEN]);
        assert_eq!(u16::from_be_bytes([short[4], short[5]]), 0);
        assert_eq!(short.len(), HEADER_LEN);
    }

    /// With no upstream server the query fails with `DnsResolution`, and
    /// the name of the domain is in the error.
    #[tokio::test]
    async fn a_server_without_an_upstream_cannot_resolve() {
        use crate::SharedState;
        let config = DnsServerConfig {
            upstream: Some(vec![]),
            ..Default::default()
        };
        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));
        let Ok(server) = DnsServer::new(config, state) else {
            panic!("DnsServer::new must accept an empty upstream list");
        };
        let query = build_test_dns_query("example.com", rtype::A);
        match server.handle_query(&query).await {
            Err(ProxyError::DnsResolution { domain, .. }) => {
                assert_eq!(domain, "example.com");
            }
            other => panic!("the server must report a resolution error: {other:?}"),
        }
    }

    /// The server ignores an upstream datagram that does not match the
    /// query, and it takes the one that does. A remote host that guesses
    /// the port must also guess the transaction ID and the question.
    #[tokio::test]
    async fn the_server_ignores_an_upstream_datagram_that_does_not_match() {
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let Ok(upstream) = socket.local_addr() else {
            panic!("the socket of the test must have an address");
        };
        // The fake upstream answers twice: first with a wrong transaction
        // ID, then with the right one.
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let query = buf[..len].to_vec();
            let mut spoof = query.clone();
            spoof[0] ^= 0xFF;
            spoof[2] = FLAG_QR;
            spoof[3] = 0;
            let _ = socket.send_to(&spoof, src).await;
            let Some(answer) = fake_answer(&query) else {
                return;
            };
            let _ = socket.send_to(&answer, src).await;
        });
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let query = build_test_dns_query("example.com", rtype::A);
        let response = server.handle_query(&query).await.unwrap();
        assert_eq!(rcode_of(&response), rcode::NOERROR);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        task.abort();
    }

    /// The server never answers a message that already has the QR bit. An
    /// answer to an answer makes a loop between two servers.
    #[tokio::test]
    async fn the_server_does_not_answer_a_response() {
        let Some(socket) = udp_bind_or_skip("127.0.0.1:0").await else {
            return;
        };
        let Ok(bound) = socket.local_addr() else {
            panic!("the socket of the test must have an address");
        };
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let run = tokio::spawn(async move {
            let _ = server.run_on(socket).await;
        });
        let Some(client) = udp_bind_or_skip("127.0.0.1:0").await else {
            run.abort();
            return;
        };
        // A message with the QR bit: the server must stay silent.
        let mut message = build_test_dns_query("example.com", rtype::A);
        message[2] = FLAG_QR;
        let _ = client.send_to(&message, bound).await;
        let mut buf = [0u8; 512];
        let answer =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
        assert!(answer.is_err(), "the server answered a response");
        // The same server still answers a real query, so the test proves
        // the rule and not a dead server.
        let query = build_test_dns_query("example.com", rtype::A);
        let _ = client.send_to(&query, bound).await;
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("the server must answer a query")
            .expect("the client must receive the answer");
        assert_eq!(rcode_of(&buf[..len]), rcode::NOERROR);
        run.abort();
    }

    /// The TCP server answers a query with the two-byte length prefix, and
    /// it closes the connection when the client sends a response.
    #[tokio::test]
    async fn the_tcp_server_answers_and_closes_on_a_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                crate::test_support::skip("this machine cannot bind a TCP socket on the loopback");
                return;
            }
            Err(err) => panic!("Failed to bind TCP listener for test: {err}"),
        };
        let Ok(bound) = listener.local_addr() else {
            panic!("the listener of the test must have an address");
        };
        let Some((upstream, _task)) = fake_upstream("127.0.0.1:0").await else {
            return;
        };
        let (server, _state, _rx) = server_with_upstream(upstream, &["example.com"]);
        let run = tokio::spawn(async move {
            let _ = server.run_tcp_on(listener).await;
        });

        let query = build_test_dns_query("example.com", rtype::A);
        let mut stream = tokio::net::TcpStream::connect(bound).await.unwrap();
        let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        stream.write_all(&framed).await.unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(rcode_of(&answer), rcode::NOERROR);

        // A message with the QR bit closes the connection.
        let mut response = build_test_dns_query("example.com", rtype::A);
        response[2] = FLAG_QR;
        let mut framed = u16::try_from(response.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&response);
        stream.write_all(&framed).await.unwrap();
        let mut tail = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut tail)).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "the server must close the connection: {read:?}"
        );
        run.abort();
    }
    /// A client that closes the connection in the middle of the length
    /// prefix must not stop the server, and it must not hold its place.
    /// The next client gets its answer on a new connection.
    ///
    /// The server of the test serves one connection at a time
    /// (`max_concurrent_queries` is 1). Thus the test sees the end of the
    /// broken connection: the next connection gets an answer only when the
    /// server gave the place of the broken connection back.
    #[tokio::test]
    async fn a_broken_length_prefix_does_not_stop_the_tcp_server() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            crate::test_support::skip("this machine cannot bind a TCP socket on the loopback");
            return;
        };
        let Ok(addr) = listener.local_addr() else {
            crate::test_support::skip("this machine gives no address for a TCP listener");
            return;
        };
        let state = Arc::new(SharedState::new(vec!["allowed.com".to_string()]));
        let config = DnsServerConfig {
            max_concurrent_queries: 1,
            ..Default::default()
        };
        let server = DnsServer::new(config, state).unwrap();
        let task = tokio::spawn(async move {
            let _ = server.run_tcp_on(listener).await;
        });

        // One byte of the two-byte length prefix, then the close.
        let mut broken = tokio::net::TcpStream::connect(addr).await.unwrap();
        broken.write_all(&[0x00]).await.unwrap();
        drop(broken);

        // A new connection with a complete query. The name is not on the
        // allowlist, thus the server answers NXDOMAIN and asks no upstream.
        let query = build_test_dns_query("blocked.example", rtype::A);
        let mut request = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
        request.extend_from_slice(&query);

        let mut answer = None;
        // The server ends the broken connection in its own task. The test
        // gives it up to two seconds for that.
        for _ in 0..20u32 {
            let Ok(mut client) = tokio::net::TcpStream::connect(addr).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            if client.write_all(&request).await.is_err() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let mut len_buf = [0u8; 2];
            let read = client.read_exact(&mut len_buf);
            let complete = matches!(
                tokio::time::timeout(Duration::from_millis(100), read).await,
                Ok(Ok(_))
            );
            if !complete {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let mut response = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
            let read = client.read_exact(&mut response);
            assert!(
                tokio::time::timeout(Duration::from_secs(5), read)
                    .await
                    .is_ok(),
                "the answer is shorter than its length"
            );
            answer = Some(response);
            break;
        }

        let Some(response) = answer else {
            task.abort();
            panic!("the server gave no answer after the broken connection");
        };
        assert_eq!(rcode_of(&response), rcode::NXDOMAIN);
        assert_eq!(response.get(..2), query.get(..2), "another transaction");

        task.abort();
    }
}

/// Property tests of the DNS wire parser and the DNS builder.
///
/// A hostile program chooses every byte of a query, and a hostile upstream
/// server chooses every byte of a response. The properties here hold for
/// each of those byte strings. See `docs/testing/fuzzing-and-coverage.md`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod wire_properties {
    use super::*;
    use crate::test_support::{rounds, Rng};

    /// The number of messages that each property test reads by default.
    const ROUNDS: usize = 200_000;

    /// Append a domain name to `out`.
    ///
    /// The generator writes normal labels, labels that are too long, labels
    /// with the reserved length bits, and compression pointers, so that the
    /// parser sees every label type.
    fn push_name(rng: &mut Rng, out: &mut Vec<u8>) {
        let labels = rng.below(6);
        for _ in 0..labels {
            match rng.below(16) {
                0 => {
                    // A compression pointer to a random place.
                    let target = rng.below(out.len().max(1));
                    #[allow(clippy::cast_possible_truncation, reason = "the pointer is 14 bits")]
                    let hi = 0xC0 | ((target >> 8) & 0x3F) as u8;
                    #[allow(clippy::cast_possible_truncation, reason = "the low byte")]
                    let lo = (target & 0xFF) as u8;
                    out.push(hi);
                    out.push(lo);
                    return;
                }
                1 => {
                    // A length byte with a reserved bit pattern.
                    out.push(0x40 | rng.byte() & 0x3F);
                }
                2 => {
                    // A label that says more bytes than the message holds.
                    out.push(0x3F);
                    let len = rng.below(10);
                    out.extend(rng.bytes(len));
                    return;
                }
                3 => {
                    // A label at the limit of 63 bytes, to reach the length
                    // check of a name of 253 characters.
                    out.push(63);
                    out.extend(std::iter::repeat_n(b'a', 63));
                }
                _ => {
                    let len = rng.below(20);
                    #[allow(clippy::cast_possible_truncation, reason = "len is below 20")]
                    out.push(len as u8);
                    if rng.one_in(2) {
                        // A label that a host name can hold, so that the
                        // test reaches the normalization and the builder.
                        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-_";
                        for _ in 0..len {
                            let at = rng.below(ALPHABET.len());
                            out.push(*ALPHABET.get(at).unwrap_or(&b'a'));
                        }
                    } else {
                        out.extend(rng.bytes(len));
                    }
                }
            }
        }
        out.push(0);
    }

    /// The shape of a generated message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        /// A message as a client sends it.
        Query,
        /// A message as an upstream server sends it: the QR bit is set, the
        /// question count is 1, and the class is IN. Without this shape
        /// `process_upstream_response` rejects nearly every input before it
        /// reads one record.
        Response,
    }

    /// Build a message that looks like a DNS query or a DNS response.
    fn gen_message(rng: &mut Rng, shape: Shape) -> Vec<u8> {
        if rng.one_in(8) {
            // Pure noise, of a length that can be shorter than the header.
            let len = rng.below(40);
            return rng.bytes(len);
        }
        let mut msg = rng.bytes(HEADER_LEN);
        // A plausible question count, and plausible record counts.
        let questions = if shape == Shape::Response {
            1
        } else {
            rng.below(3)
        };
        let counts = [questions, rng.below(3), rng.below(3), rng.below(3)];
        for (index, count) in counts.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation, reason = "the count is below 3")]
            let bytes = (*count as u16).to_be_bytes();
            let at = 4usize.saturating_add(index.saturating_mul(2));
            if let Some(field) = msg.get_mut(at..at.saturating_add(2)) {
                field.copy_from_slice(&bytes);
            }
        }
        if shape == Shape::Response {
            if let Some(flags) = msg.get_mut(2) {
                *flags |= FLAG_QR;
            }
        }
        push_name(rng, &mut msg);
        msg.extend(rng.bytes(2)); // QTYPE
        if shape == Shape::Response {
            msg.extend(CLASS_IN.to_be_bytes());
        } else {
            msg.extend(rng.bytes(2)); // QCLASS
        }
        let records = counts[1]
            .saturating_add(counts[2])
            .saturating_add(counts[3]);
        for _ in 0..records {
            push_name(rng, &mut msg);
            msg.extend(rng.bytes(2)); // TYPE
            msg.extend(rng.bytes(2)); // CLASS
            msg.extend(rng.bytes(4)); // TTL
            let rdlen = rng.below(20);
            #[allow(clippy::cast_possible_truncation, reason = "rdlen is below 20")]
            msg.extend((rdlen as u16).to_be_bytes());
            msg.extend(rng.bytes(rdlen));
        }
        // Flip a few bytes, so that the structure breaks in every place.
        // A response keeps its header, so that the test reaches the records.
        let flips = if shape == Shape::Response {
            rng.below(2)
        } else {
            rng.below(4)
        };
        for _ in 0..flips {
            let first = if shape == Shape::Response {
                HEADER_LEN
            } else {
                0
            };
            let at = first.saturating_add(rng.below(msg.len().saturating_sub(first).max(1)));
            if let Some(byte) = msg.get_mut(at) {
                *byte = rng.byte();
            }
        }
        msg
    }

    /// `read_name` must return a name that follows its own rules, and it
    /// must always stop.
    #[test]
    fn read_name_holds_its_rules() {
        let mut rng = Rng::new(0x5EED_0001);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let msg = gen_message(&mut rng, Shape::Query);
            let start = rng.below(msg.len().max(1));
            for pointers in [Pointers::Forbidden, Pointers::Allowed] {
                if let Ok((name, after)) = read_name(&msg, start, pointers, LabelBytes::Strict) {
                    checked = checked.saturating_add(1);
                    assert!(
                        after <= msg.len(),
                        "the end {after} is after the message {}",
                        msg.len()
                    );
                    assert!(
                        name.len() <= MAX_WIRE_NAME_LEN,
                        "the name {name:?} is too long"
                    );
                    assert!(
                        name.bytes().all(|b| b.is_ascii_graphic()),
                        "the strict name {name:?} holds a byte that is not printable"
                    );
                }
                // The lenient mode takes every byte, but the length limit
                // and the end of the message still hold.
                if let Ok((name, after)) = read_name(&msg, start, pointers, LabelBytes::Any) {
                    assert!(after <= msg.len(), "the end {after} is after the message");
                    // A byte that is not valid UTF-8 becomes one replacement
                    // character, so the test counts characters, not bytes.
                    assert!(
                        name.chars().count() <= MAX_WIRE_NAME_LEN,
                        "the lenient name {name:?} is too long"
                    );
                }
            }
        }
        assert!(
            checked > total / 10,
            "only {checked} of {total} starts held a name; the test proves little"
        );
    }

    /// `read_question` must never return an end after the message.
    #[test]
    fn read_question_stays_in_the_message() {
        let mut rng = Rng::new(0x5EED_0002);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let msg = gen_message(&mut rng, Shape::Query);
            for pointers in [Pointers::Forbidden, Pointers::Allowed] {
                if let Ok(question) = read_question(&msg, pointers) {
                    checked = checked.saturating_add(1);
                    assert!(
                        question.end <= msg.len(),
                        "the question ends at {} after the message {}",
                        question.end,
                        msg.len()
                    );
                    assert!(
                        question.end >= HEADER_LEN,
                        "the question ends inside the header"
                    );
                }
            }
        }
        assert!(
            checked > total / 10,
            "only {checked} of {total} messages held a question; the test proves little"
        );
    }

    /// An error response is always a response: the QR bit is set, the header
    /// is complete, and the question count matches the question that the
    /// response holds. Without the QR bit the server would answer its own
    /// answer and make a loop.
    #[test]
    fn error_response_is_a_response() {
        let mut rng = Rng::new(0x5EED_0003);
        for _ in 0..rounds(ROUNDS) {
            let query = gen_message(&mut rng, Shape::Query);
            let end = read_question(&query, Pointers::Forbidden)
                .ok()
                .map(|q| q.end);
            for code in [
                rcode::FORMERR,
                rcode::SERVFAIL,
                rcode::NXDOMAIN,
                rcode::NOTIMP,
            ] {
                for question_end in [None, end] {
                    let response = build_error_response(&query, question_end, code);
                    assert!(
                        response.len() >= HEADER_LEN,
                        "the response is shorter than the header"
                    );
                    let flags = *response.get(2).unwrap();
                    assert!(flags & FLAG_QR != 0, "the response has no QR bit");
                    assert_eq!(
                        *response.get(3).unwrap() & 0x0F,
                        code,
                        "the response has the wrong code"
                    );
                    let qdcount = read_u16(&response, 4).unwrap();
                    let body = response.get(HEADER_LEN..).unwrap_or_default();
                    if qdcount == 0 {
                        assert!(body.is_empty(), "a response with no question has a body");
                    } else {
                        assert_eq!(qdcount, 1, "the question count is not 0 or 1");
                        let expected = question_end
                            .and_then(|e| query.get(HEADER_LEN..e))
                            .unwrap_or_default();
                        assert_eq!(body, expected, "the question is not the one of the query");
                    }
                }
            }
        }
    }

    /// `process_upstream_response` must never panic, and every TTL that it
    /// reports must be inside the bounds of the configuration.
    #[test]
    fn upstream_response_clamps_every_ttl() {
        let mut rng = Rng::new(0x5EED_0004);
        let bounds = (30u32, 300u32);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let msg = gen_message(&mut rng, Shape::Response);
            let id = read_u16(&msg, 0).unwrap_or(0);
            let name = read_question(&msg, Pointers::Allowed)
                .map(|q| q.name)
                .unwrap_or_default();
            let qtype = read_question(&msg, Pointers::Allowed)
                .map(|q| q.qtype)
                .unwrap_or(rtype::A);
            let len = msg.len();
            if let Ok(reply) = process_upstream_response(msg, id, &name, qtype, bounds) {
                checked = checked.saturating_add(1);
                assert!(
                    reply.message.len() <= len,
                    "the reply grew from {len} to {}",
                    reply.message.len()
                );
                if let Some(ttl) = reply.address_ttl {
                    assert!(
                        (bounds.0..=bounds.1).contains(&ttl),
                        "the TTL {ttl} is outside the bounds {bounds:?}"
                    );
                }
                assert!(reply.rcode <= 0x0F, "the rcode has more than four bits");
            }
        }
        assert!(
            checked > total / 100,
            "only {checked} of {total} messages were a usable response; the test proves little"
        );
    }

    /// The name that the server checks is the name that it sends upstream.
    ///
    /// The server reads the question, normalizes the name, checks the
    /// allowlist with it, and then builds a new query from the same text. If
    /// the build changed the name, the allowlist decision would apply to
    /// another name.
    #[test]
    fn the_checked_name_is_the_forwarded_name() {
        let mut rng = Rng::new(0x5EED_0005);
        let total = rounds(ROUNDS);
        let mut checked = 0usize;
        for _ in 0..total {
            let msg = gen_message(&mut rng, Shape::Query);
            let Ok(question) = read_question(&msg, Pointers::Forbidden) else {
                continue;
            };
            let Ok(name) = crate::normalize_hostname(&question.name) else {
                continue;
            };
            checked = checked.saturating_add(1);
            let query = build_dns_query(0x1234, &name, question.qtype);
            match read_question(&query, Pointers::Forbidden) {
                Ok(built) => {
                    assert_eq!(
                        built.name, name,
                        "the forwarded name is not the checked one"
                    );
                    assert_eq!(built.qtype, question.qtype, "the query type changed");
                    assert_eq!(built.qclass, CLASS_IN, "the query class is not IN");
                    assert_eq!(built.end, query.len(), "the built query has extra bytes");
                }
                Err(e) => panic!("the built query for {name:?} does not parse: {e}"),
            }
        }
        assert!(
            checked > total / 100,
            "only {checked} of {total} questions held a valid host name; the test proves little"
        );
    }

    /// Build a query and the answer of an upstream server for it. The
    /// answer holds the flags `flags` in the second byte of the header.
    fn query_and_answer(flags: u8) -> (Vec<u8>, Vec<u8>) {
        let query = build_dns_query(0x1234, "example.com", rtype::A);
        let mut answer = query.clone();
        if let Some(byte) = answer.get_mut(2) {
            *byte = flags;
        }
        (query, answer)
    }

    /// OPEN FUZZ-2. The server must keep the truncation bit of the
    /// upstream answer. Without the bit the client takes a short answer as
    /// the whole answer and never asks again over TCP. The server does
    /// serve DNS over TCP (`DnsServer::run_tcp_on`), so the retry works.
    #[test]
    #[ignore = "OPEN FUZZ-2: the server clears the truncation bit of the upstream answer"]
    fn the_server_keeps_the_truncation_bit() {
        let (query, answer) = query_and_answer(FLAG_QR | FLAG_TC);
        let Ok(question) = read_question(&query, Pointers::Forbidden) else {
            panic!("the query of the test must parse");
        };
        let response = DnsServer::finish_response(&query, &question, answer);
        let Some(flags) = response.get(2) else {
            panic!("the response has no header");
        };
        assert!(
            flags & FLAG_TC != 0,
            "the server removed the truncation bit of the upstream answer"
        );
    }

    /// The result of today for the input of FUZZ-2. This test passes; it
    /// fails when somebody fixes the flag.
    #[test]
    fn the_server_clears_the_truncation_bit_today() {
        let (query, answer) = query_and_answer(FLAG_QR | FLAG_TC);
        let Ok(question) = read_question(&query, Pointers::Forbidden) else {
            panic!("the query of the test must parse");
        };
        let response = DnsServer::finish_response(&query, &question, answer);
        assert_eq!(
            response.get(2).map(|f| f & FLAG_TC),
            Some(0),
            "the server now keeps the truncation bit; update FUZZ-2"
        );
        // The rest of the header is correct: the answer is a response, and
        // the server offers recursion.
        assert_eq!(response.get(2).map(|f| f & FLAG_QR), Some(FLAG_QR));
        assert_eq!(response.get(3).map(|f| f & FLAG_RA), Some(FLAG_RA));
    }

    /// A clamped TTL is always inside the bounds, for every pair of bounds.
    #[test]
    fn clamp_ttl_stays_in_the_bounds() {
        let mut rng = Rng::new(0x5EED_0006);
        for _ in 0..rounds(ROUNDS) {
            #[allow(clippy::cast_possible_truncation, reason = "the test wants 32 bits")]
            let ttl = rng.next_u64() as u32;
            #[allow(clippy::cast_possible_truncation, reason = "the test wants 32 bits")]
            let min = rng.next_u64() as u32;
            #[allow(clippy::cast_possible_truncation, reason = "the test wants 32 bits")]
            let max = rng.next_u64() as u32;
            let clamped = clamp_ttl(ttl, (min, max));
            if min <= max {
                assert!(
                    (min..=max).contains(&clamped),
                    "clamp_ttl({ttl}, ({min}, {max})) gave {clamped}"
                );
            } else {
                // The maximum has priority, as the doc comment says.
                assert_eq!(clamped, max, "the maximum must win over the minimum");
            }
        }
    }
}
