//! Domain-filtered proxy for sandbox network isolation.
//!
//! `pent-proxy` provides DNS + TCP proxying with domain allowlist enforcement.
//! Sandboxed processes can only reach the internet through this proxy,
//! which enforces domain-level access control.
//!
//! # Architecture
//!
//! ```text
//! Sandboxed Process
//!       |
//!       | (only allowed outbound)
//!       v
//! pent-proxy (127.0.0.1:PROXY_PORT)
//!       |
//!       +-- DNS Server (intercepts queries)
//!       |      |
//!       |      +-- allowed domain? --> resolve via upstream
//!       |      +-- blocked domain? --> return NXDOMAIN
//!       |
//!       +-- TCP Proxy (forwards connections)
//!              |
//!              +-- destination in resolved set? --> forward
//!              +-- unknown destination? --> reject
//! ```
//!
//! # Components
//!
//! - [`DnsServer`]: Intercepts DNS queries, resolves only allowed domains
//! - [`TcpProxy`]: Forwards TCP connections to resolved (allowed) destinations
//! - [`DomainFilter`]: Matches domains against allowlist (supports wildcards)
//! - [`ProxyServer`]: Combined DNS + TCP proxy server
//!
//! # Usage
//!
//! ```ignore
//! use pent_proxy::{ProxyServer, ProxyConfig};
//!
//! let config = ProxyConfig {
//!     bind_addr: "127.0.0.1:9300".parse()?,
//!     dns_port: 5353,
//!     domain_allowlist: vec![
//!         "api.anthropic.com".to_string(),
//!         "*.github.com".to_string(),
//!     ],
//! };
//!
//! let server = ProxyServer::new(config)?;
//! server.run().await?;
//! ```
//!
//! # Security Model
//!
//! - Binds to `127.0.0.1` only (not reachable from network)
//! - Sandboxed processes forced to use this proxy via network namespace (Linux)
//!   or sandbox-exec localhost-only rule (macOS)
//! - No authentication needed (localhost-only binding is the security boundary)
//!

mod dns;
mod filter;
mod proxy;
mod server;

pub use dns::{DnsServer, DnsServerConfig};
pub use filter::{DomainFilter, DomainMatch};
pub use proxy::{TcpProxy, TcpProxyConfig};
pub use server::{ProxyConfig, ProxyHandle, ProxyServer};

use std::net::SocketAddr;
use std::sync::Arc;

/// Result type for proxy operations.
pub type Result<T> = std::result::Result<T, ProxyError>;

/// A structured event emitted by the proxy during trace mode.
///
/// Replaces the previous stringly-typed `"access:..."` prefix convention,
/// giving receivers a proper discriminant without string parsing.
#[derive(Debug, Clone)]
pub enum TraceEvent {
    /// A connection or DNS query was blocked by the allowlist.
    Violation(String),
    /// A connection or DNS query was permitted.
    Access(String),
}

// ── Lock helpers ─────────────────────────────────────────────────────────────
//
// These centralise the `unwrap_or_else(|e| e.into_inner())` poisoning-recovery
// pattern so it isn't repeated at every lock site.

fn read_lock<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

/// Errors that can occur in proxy operations.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to bind to address.
    #[error("Failed to bind to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// DNS resolution failed.
    #[error("DNS resolution failed for {domain}: {message}")]
    DnsResolution { domain: String, message: String },

    /// Domain blocked by allowlist.
    #[error("Domain blocked: {domain}")]
    DomainBlocked { domain: String },

    /// TCP connection failed.
    #[error("TCP connection to {addr} failed: {source}")]
    TcpConnection {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// Server shutdown error.
    #[error("Server shutdown error: {0}")]
    Shutdown(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Resolved address with associated domain.
///
/// Tracks which domain a resolved IP belongs to,
/// allowing the TCP proxy to verify connections are to allowed destinations.
#[derive(Debug, Clone)]
pub struct ResolvedAddress {
    /// The domain that was resolved.
    pub domain: String,

    /// The resolved IP addresses.
    pub addresses: Vec<std::net::IpAddr>,

    /// When this resolution expires (TTL-based).
    pub expires_at: std::time::Instant,
}

/// Default maximum number of IP entries in the resolution cache.
const DEFAULT_MAX_CACHE_ENTRIES: usize = 4096;

/// Cache of resolved domains.
///
/// Maps IP addresses back to domains for TCP proxy validation.
/// Entries expire based on DNS TTL.
///
/// The cache is bounded by `max_entries`. On insert, expired entries are
/// evicted first; if the cache is still full, the oldest-by-insertion-time
/// entries are evicted until there is room.
pub struct ResolutionCache {
    /// Map from IP address to `(resolved info, insertion time)`.
    entries: std::sync::RwLock<
        std::collections::HashMap<std::net::IpAddr, (ResolvedAddress, std::time::Instant)>,
    >,
    /// Maximum number of IP entries to retain.
    max_entries: usize,
}

impl ResolutionCache {
    /// Create a new empty cache with the default capacity limit.
    pub fn new() -> Self {
        Self::new_with_max(DEFAULT_MAX_CACHE_ENTRIES)
    }

    /// Create a new empty cache with a custom capacity limit.
    pub fn new_with_max(max_entries: usize) -> Self {
        Self {
            entries: std::sync::RwLock::new(std::collections::HashMap::new()),
            max_entries,
        }
    }

    /// Insert a resolved address into the cache.
    ///
    /// Evicts expired entries first, then evicts the oldest-by-insertion-time
    /// entries if the cache is still at capacity.
    ///
    /// # Arguments
    /// * `resolved` - The resolved address to cache
    pub fn insert(&self, resolved: ResolvedAddress) {
        let mut entries = write_lock(&self.entries);
        let now = std::time::Instant::now();

        // 1. Evict expired entries
        entries.retain(|_, (r, _)| r.expires_at > now);

        // 2. If still at or over capacity, evict oldest-by-insertion-time
        while !entries.is_empty() && entries.len() + resolved.addresses.len() > self.max_entries {
            if let Some(&oldest_ip) = entries
                .iter()
                .min_by_key(|(_, (_, inserted_at))| *inserted_at)
                .map(|(ip, _)| ip)
            {
                entries.remove(&oldest_ip);
            } else {
                break;
            }
        }

        // 3. Insert new entries
        for addr in &resolved.addresses {
            entries.insert(*addr, (resolved.clone(), now));
        }
    }

    /// Look up a domain for an IP address.
    ///
    /// Returns `Some(domain)` if the IP was resolved from an allowed domain
    /// and the cache entry hasn't expired.
    ///
    /// # Arguments
    /// * `addr` - The IP address to look up
    pub fn lookup(&self, addr: &std::net::IpAddr) -> Option<String> {
        let entries = read_lock(&self.entries);
        entries.get(addr).and_then(|(resolved, _)| {
            if resolved.expires_at > std::time::Instant::now() {
                Some(resolved.domain.clone())
            } else {
                None
            }
        })
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        read_lock(&self.entries).is_empty()
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> usize {
        read_lock(&self.entries).len()
    }
}

impl Default for ResolutionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state between DNS server and TCP proxy.
///
/// Contains the domain filter and resolution cache.
/// The filter is wrapped in RwLock to support runtime domain additions.
pub struct SharedState {
    /// Domain filter for allowlist matching (wrapped for mutation).
    filter: std::sync::RwLock<DomainFilter>,

    /// Cache of resolved addresses.
    pub(crate) cache: ResolutionCache,

    /// Optional channel for reporting trace events (violations and granted access).
    violation_tx: Option<tokio::sync::mpsc::UnboundedSender<TraceEvent>>,

    /// Total number of proxy connections ever accepted (DNS queries + TCP
    /// CONNECT requests).  Monotonically increasing; used by the caller to
    /// detect whether the sandboxed process is actually routing traffic
    /// through the proxy.  Stored as an Arc so callers can cheaply clone
    /// a reference for use in background tasks.
    pub connections_accepted: Arc<std::sync::atomic::AtomicU64>,
}

impl SharedState {
    /// Create new shared state with the given domain allowlist.
    ///
    /// # Arguments
    /// * `allowlist` - List of allowed domains (supports wildcards like `*.github.com`)
    pub fn new(allowlist: Vec<String>) -> Self {
        Self::with_violation_tx(allowlist, None)
    }

    /// Create new shared state, optionally wiring up a violation channel.
    pub fn with_violation_tx(
        allowlist: Vec<String>,
        violation_tx: Option<tokio::sync::mpsc::UnboundedSender<TraceEvent>>,
    ) -> Self {
        Self {
            filter: std::sync::RwLock::new(DomainFilter::new(allowlist)),
            cache: ResolutionCache::new(),
            violation_tx,
            connections_accepted: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Report a policy violation (denied access) if a trace channel is configured.
    pub fn report_violation(&self, message: String) {
        if let Some(tx) = &self.violation_tx {
            let _ = tx.send(TraceEvent::Violation(message));
        }
    }

    /// Report a granted-access event if a trace channel is configured.
    pub fn report_access(&self, message: String) {
        if let Some(tx) = &self.violation_tx {
            let _ = tx.send(TraceEvent::Access(message));
        }
    }

    /// Check if a domain is allowed by the filter.
    pub fn is_allowed(&self, domain: &str) -> bool {
        read_lock(&self.filter).is_allowed(domain)
    }

    /// Add a domain to the allowlist.
    ///
    /// Mutates the filter in-place in O(1) amortized time.
    pub fn add_domain(&self, domain: String) {
        write_lock(&self.filter).push(domain);
    }

    /// Insert a resolved address into the cache.
    ///
    /// This is the canonical way for the DNS server to populate the cache.
    /// The DNS server has already verified the domain is allowed before calling this.
    pub fn insert_resolved(&self, resolved: ResolvedAddress) {
        self.cache.insert(resolved);
    }

    /// Look up a cached domain for a given IP address.
    ///
    /// Returns the domain name if the IP was resolved through the DNS server
    /// and the cache entry has not expired. Used by the TCP proxy to verify
    /// that a destination IP came from an allowed domain.
    pub fn lookup_resolved(&self, addr: &std::net::IpAddr) -> Option<String> {
        self.cache.lookup(addr)
    }

    /// Get the current allowlist patterns.
    pub fn allowlist(&self) -> Vec<String> {
        read_lock(&self.filter)
            .patterns()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ResolutionCache Tests
    // ========================================================================

    #[test]
    fn test_resolution_cache_new_is_empty() {
        let cache = ResolutionCache::new();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_resolution_cache_insert_single() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_insert_multiple_ips_same_domain() {
        let cache = ResolutionCache::new();
        let ip1: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: std::net::IpAddr = "5.6.7.8".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip1, ip2],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip1), Some("example.com".to_string()));
        assert_eq!(cache.lookup(&ip2), Some("example.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_lookup_missing() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_resolution_cache_lookup_expired() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("system monotonic clock predates program start"),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip), None);
    }

    #[test]
    fn test_resolution_cache_lookup_not_expired() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_overwrite_same_ip() {
        let cache = ResolutionCache::new();
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved1 = ResolvedAddress {
            domain: "first.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved1);
        let resolved2 = ResolvedAddress {
            domain: "second.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved2);
        assert_eq!(cache.lookup(&ip), Some("second.com".to_string()));
    }

    #[test]
    fn test_resolution_cache_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(ResolutionCache::new());
        let mut handles = vec![];

        for i in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                let ip: std::net::IpAddr = format!("1.2.3.{}", i).parse().unwrap();
                let resolved = ResolvedAddress {
                    domain: format!("domain{}.com", i),
                    addresses: vec![ip],
                    expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
                };
                cache.insert(resolved);
                cache.lookup(&ip);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(cache.len(), 10);
    }

    #[test]
    fn test_resolution_cache_ipv4_and_ipv6() {
        let cache = ResolutionCache::new();
        let ipv4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let ipv6: std::net::IpAddr = "::1".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ipv4, ipv6],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(resolved);
        assert_eq!(cache.lookup(&ipv4), Some("example.com".to_string()));
        assert_eq!(cache.lookup(&ipv6), Some("example.com".to_string()));
    }

    // ========================================================================
    // SharedState Tests
    // ========================================================================

    #[test]
    fn test_shared_state_new_with_empty_allowlist() {
        let state = SharedState::new(vec![]);
        assert!(!state.is_allowed("any.com"));
        assert!(state.cache.is_empty());
    }

    #[test]
    fn test_shared_state_new_with_domains() {
        let state = SharedState::new(vec!["example.com".to_string(), "*.github.com".to_string()]);
        assert!(state.is_allowed("example.com"));
        assert!(state.is_allowed("api.github.com"));
        assert!(!state.is_allowed("other.com"));
    }

    #[test]
    fn test_shared_state_filter_and_cache_connected() {
        let state = SharedState::new(vec!["example.com".to_string()]);
        assert!(state.is_allowed("example.com"));
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resolved = ResolvedAddress {
            domain: "example.com".to_string(),
            addresses: vec![ip],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        state.cache.insert(resolved);
        assert_eq!(state.cache.lookup(&ip), Some("example.com".to_string()));
    }

    // ========================================================================
    // ProxyError Tests
    // ========================================================================

    #[test]
    fn test_proxy_error_display_bind() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let err = ProxyError::Bind {
            addr,
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"),
        };
        assert!(err.to_string().contains("127.0.0.1:8080"));
    }

    #[test]
    fn test_proxy_error_display_domain_blocked() {
        let err = ProxyError::DomainBlocked {
            domain: "evil.com".to_string(),
        };
        assert!(err.to_string().contains("evil.com"));
    }

    #[test]
    fn test_proxy_error_display_dns_resolution() {
        let err = ProxyError::DnsResolution {
            domain: "test.com".to_string(),
            message: "NXDOMAIN".to_string(),
        };
        assert!(err.to_string().contains("test.com"));
        assert!(err.to_string().contains("NXDOMAIN"));
    }

    // ========================================================================
    // RwLock Poisoning Consistency Tests
    // ========================================================================

    /// This test verifies that SharedState handles RwLock poisoning consistently.
    /// Both `cache` and `filter` now use `unwrap_or_else(|e| e.into_inner())` to
    /// recover from poisoned locks, so operations continue to work even after
    /// a thread panics while holding a lock.
    #[test]
    fn test_shared_state_filter_handles_poisoning() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(SharedState::new(vec!["example.com".to_string()]));

        // Poison the filter's RwLock by panicking while holding a write lock
        let state_clone = Arc::clone(&state);
        let handle = thread::spawn(move || {
            // Get write lock on filter and panic
            let _guard = state_clone.filter.write().unwrap();
            panic!("Intentionally poisoning the filter RwLock");
        });

        // Wait for the thread to panic (poisoning the lock)
        let _ = handle.join();

        // Now try to use the filter - should NOT panic because is_allowed uses
        // unwrap_or_else to recover from poisoned lock
        let result = state.is_allowed("example.com");

        // The filter should still work correctly
        assert!(
            result,
            "Filter should still allow example.com after poisoning"
        );

        // add_domain should also work
        state.add_domain("test.com".to_string());

        // allowlist should work too
        let patterns = state.allowlist();
        assert!(patterns.len() >= 2, "Should have at least 2 patterns");
    }

    /// Verify that cache handles poisoning gracefully (control test).
    #[test]
    fn test_resolution_cache_evicts_when_full() {
        // Create a cache that holds at most 2 entries
        let cache = ResolutionCache::new_with_max(2);

        let make_resolved = |suffix: u8, secs: u64| ResolvedAddress {
            domain: format!("d{}.com", suffix),
            addresses: vec![format!("1.2.3.{}", suffix).parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(secs),
        };

        // Fill cache to capacity
        cache.insert(make_resolved(1, 300));
        cache.insert(make_resolved(2, 300));
        assert_eq!(cache.len(), 2);

        // Inserting a third should evict the oldest
        cache.insert(make_resolved(3, 300));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_resolution_cache_evicts_expired_before_oldest() {
        // When inserting into a full cache, expired entries are evicted first,
        // even if they were inserted after other (still-valid) entries.
        let cache = ResolutionCache::new_with_max(2);

        // long_ttl is inserted first (oldest by insertion time)
        let long_ttl = ResolvedAddress {
            domain: "old.com".to_string(),
            addresses: vec!["1.2.3.1".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(3600),
        };
        // short_ttl is inserted second but has a very short TTL
        let short_ttl = ResolvedAddress {
            domain: "short.com".to_string(),
            addresses: vec!["1.2.3.2".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_millis(10),
        };
        cache.insert(long_ttl);
        cache.insert(short_ttl);
        assert_eq!(cache.len(), 2);

        // Wait for short_ttl to expire
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Insert a new entry into the full cache.
        // The expired short_ttl entry should be evicted, not the older long_ttl.
        let new_entry = ResolvedAddress {
            domain: "new.com".to_string(),
            addresses: vec!["1.2.3.3".parse().unwrap()],
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
        };
        cache.insert(new_entry);
        assert_eq!(cache.len(), 2);

        // old.com (long_ttl, inserted first) should still be accessible
        let ip_old: std::net::IpAddr = "1.2.3.1".parse().unwrap();
        assert_eq!(cache.lookup(&ip_old), Some("old.com".to_string()));

        // short.com should be gone (it expired)
        let ip_short: std::net::IpAddr = "1.2.3.2".parse().unwrap();
        assert_eq!(cache.lookup(&ip_short), None);
    }

    #[test]
    fn test_resolution_cache_handles_poisoning() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(ResolutionCache::new());

        // Poison the RwLock
        let cache_clone = Arc::clone(&cache);
        let handle = thread::spawn(move || {
            let _guard = cache_clone.entries.write().unwrap();
            panic!("Intentionally poisoning the cache RwLock");
        });

        let _ = handle.join();

        // Cache should still work (won't panic) because it uses unwrap_or_else
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let result = cache.lookup(&ip); // Should NOT panic
        assert_eq!(result, None);

        // is_empty should also work
        let empty = cache.is_empty(); // Should NOT panic
        assert!(empty);
    }
}
