//! Inspection of the first bytes that a client sends through a tunnel.
//!
//! A client can connect by IP address to a shared CDN address that an allowed
//! domain resolved to, and then ask the CDN for a different host (domain
//! fronting). To make this more difficult, the proxy reads the first TLS
//! record (port 443) or the HTTP request head (port 80) before it relays
//! data, and gets the requested host name from the TLS SNI extension or from
//! the HTTP `Host` header.
//!
//! # Residual risk
//!
//! - Encrypted Client Hello (ECH) hides the real SNI. The outer SNI that the
//!   proxy sees can be a public name of the CDN.
//! - A client can send an allowed SNI and then send a different HTTP `Host`
//!   header inside the TLS session. The proxy cannot see the encrypted data,
//!   thus it cannot find this type of domain fronting.
//! - A client that sends no SNI, or a ClientHello that the parser cannot
//!   read, gets only the IP-cache check.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The TLS record content type for a handshake.
const TLS_HANDSHAKE: u8 = 0x16;

/// The TLS handshake message type for a ClientHello.
const TLS_CLIENT_HELLO: u8 = 0x01;

/// The TLS extension type for `server_name`.
const TLS_EXT_SERVER_NAME: u16 = 0x0000;

/// The length of a TLS record header.
const TLS_RECORD_HEADER_LEN: usize = 5;

/// The maximum length of a TLS record body (2^14 plus the permitted expansion).
const TLS_MAX_RECORD_LEN: usize = 16_384 + 2_048;

/// The maximum length of an HTTP request head that the proxy reads.
pub(crate) const MAX_HTTP_HEAD_LEN: usize = 8_192;

/// The usual port of TLS.
const TLS_PORT_DEFAULT: u16 = 443;

/// The usual port of HTTP.
const HTTP_PORT_DEFAULT: u16 = 80;

/// The ports where the proxy inspects the first bytes of the client.
///
/// The usual ports are the default. A test gives other ports, because an
/// unprivileged process cannot bind a port below 1024.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InspectPorts {
    /// The port of TLS. The proxy reads the first TLS record there and
    /// takes the host name from the SNI extension.
    pub(crate) tls: u16,
    /// The port of HTTP. The proxy reads the request head there and takes
    /// the host name from the `Host` header.
    pub(crate) http: u16,
}

impl Default for InspectPorts {
    fn default() -> Self {
        Self {
            tls: TLS_PORT_DEFAULT,
            http: HTTP_PORT_DEFAULT,
        }
    }
}

/// The port of TLS of this process.
static TLS_PORT: AtomicU16 = AtomicU16::new(TLS_PORT_DEFAULT);

/// The port of HTTP of this process.
static HTTP_PORT: AtomicU16 = AtomicU16::new(HTTP_PORT_DEFAULT);

/// The ports that the proxy inspects in this process.
fn inspect_ports() -> InspectPorts {
    InspectPorts {
        tls: TLS_PORT.load(Ordering::Relaxed),
        http: HTTP_PORT.load(Ordering::Relaxed),
    }
}

/// Set the ports that the proxy inspects in this process.
///
/// Only a test calls this function. The proxy of a session keeps the usual
/// ports, because [`crate::ProxyConfig`] has no setting for them yet.
#[cfg(test)]
fn set_inspect_ports(ports: InspectPorts) {
    TLS_PORT.store(ports.tls, Ordering::Relaxed);
    HTTP_PORT.store(ports.http, Ordering::Relaxed);
}

/// The protocol that the proxy expects on a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inspect {
    /// Read the first TLS record and get the SNI.
    Tls,
    /// Read the HTTP request head and get the `Host` header.
    Http,
}

impl Inspect {
    /// Select the inspection for a destination port.
    ///
    /// The proxy inspects only ports where the client always sends data
    /// first. On other ports the proxy must not wait for client data,
    /// because the server can speak first.
    pub(crate) fn for_port(port: u16) -> Option<Self> {
        Self::for_port_in(port, inspect_ports())
    }

    /// Select the inspection for a destination port and a set of ports.
    ///
    /// The port of TLS comes first: when the two ports of `ports` are the
    /// same, the proxy reads a TLS record.
    pub(crate) const fn for_port_in(port: u16, ports: InspectPorts) -> Option<Self> {
        if port == ports.tls {
            Some(Self::Tls)
        } else if port == ports.http {
            Some(Self::Http)
        } else {
            None
        }
    }

    /// Return `true` when `buf` holds enough data for the inspection.
    fn is_complete(self, buf: &[u8]) -> bool {
        match self {
            Self::Tls => match buf.first() {
                None => false,
                Some(&first) if first != TLS_HANDSHAKE => true,
                Some(_) => match buf.get(3..TLS_RECORD_HEADER_LEN) {
                    None => false,
                    Some(len) => {
                        let body = usize::from(u16::from_be_bytes([len[0], len[1]]));
                        let body = body.min(TLS_MAX_RECORD_LEN);
                        buf.len() >= TLS_RECORD_HEADER_LEN.saturating_add(body)
                    }
                },
            },
            Self::Http => {
                buf.len() >= MAX_HTTP_HEAD_LEN
                    || buf.first().is_some_and(|b| !b.is_ascii_uppercase())
                    || buf.windows(4).any(|w| w == b"\r\n\r\n")
            }
        }
    }

    /// Get the host name that the client asks for, if the data contains one.
    pub(crate) fn host_name(self, buf: &[u8]) -> Option<String> {
        match self {
            Self::Tls => extract_sni(buf),
            Self::Http => extract_http_host(buf),
        }
    }
}

/// Read from `reader` until `buf` holds enough data for `inspect`, the peer
/// closes its side, or `limit` elapses.
///
/// The function keeps all the bytes that it reads, also on timeout, so that
/// the caller can forward them to the destination.
///
/// # Errors
/// Returns the I/O error of a failed read.
pub(crate) async fn read_initial<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buf: Vec<u8>,
    inspect: Inspect,
    limit: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now().checked_add(limit);
    let mut chunk = [0u8; 4096];
    while !inspect.is_complete(&buf) {
        let read = reader.read(&mut chunk);
        let result = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, read).await {
                Ok(result) => result,
                Err(_) => break, // The client sent no more data in time.
            },
            None => read.await,
        };
        let n = result?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    Ok(buf)
}

/// A bounds-checked reader over a byte slice.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.data.len() {
            return None;
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|b| b.first().copied())
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(
            (usize::from(*b.first()?) << 16)
                | (usize::from(*b.get(1)?) << 8)
                | usize::from(*b.get(2)?),
        )
    }

    /// Read a vector that has a one-byte length prefix.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    /// Read a vector that has a two-byte length prefix.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

/// Get the SNI host name from a TLS record that holds a ClientHello.
///
/// Returns `None` if the data is not a TLS handshake record, is not a
/// ClientHello, has no `server_name` extension, or is malformed. The function
/// reads only the first record. If the ClientHello continues in a second
/// record and the extension is not in the first record, the function
/// returns `None`.
pub(crate) fn extract_sni(record: &[u8]) -> Option<String> {
    let mut rec = Cursor::new(record);
    if rec.u8()? != TLS_HANDSHAKE {
        return None;
    }
    let _legacy_version = rec.u16()?;
    let record_len = usize::from(rec.u16()?);
    // Use the available part of the record body if the record is cut short.
    let body = rec.take(record_len).unwrap_or(rec.data);

    let mut hs = Cursor::new(body);
    if hs.u8()? != TLS_CLIENT_HELLO {
        return None;
    }
    let hello_len = hs.u24()?;
    let hello = hs.take(hello_len).unwrap_or(hs.data);

    let mut ch = Cursor::new(hello);
    let _client_version = ch.u16()?;
    let _random = ch.take(32)?;
    let _session_id = ch.vec8()?;
    let _cipher_suites = ch.vec16()?;
    let _compression = ch.vec8()?;
    let mut extensions = Cursor::new(ch.vec16()?);

    while !extensions.data.is_empty() {
        let ext_type = extensions.u16()?;
        let ext_data = extensions.vec16()?;
        if ext_type != TLS_EXT_SERVER_NAME {
            continue;
        }
        let mut list = Cursor::new(Cursor::new(ext_data).vec16()?);
        while !list.data.is_empty() {
            let name_type = list.u8()?;
            let name = list.vec16()?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(str::to_string);
            }
        }
        return None;
    }
    None
}

/// Get the host name from the `Host` header of an HTTP/1.x request head.
///
/// The function removes the port. It returns `None` if there is no `Host`
/// header, if the head is not valid UTF-8, or if the host is an IP literal
/// (an IP literal gives no domain name to check).
pub(crate) fn extract_http_host(head: &[u8]) -> Option<String> {
    let end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(head.len());
    let text = std::str::from_utf8(head.get(..end)?).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    if !request_line.contains(" HTTP/") {
        return None;
    }
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("host") {
            continue;
        }
        let value = value.trim();
        if value.starts_with('[') {
            // An IPv6 literal such as "[::1]:80" gives no name to check.
            return None;
        }
        let host = value.rsplit_once(':').map_or(value, |(h, _)| h);
        if host.parse::<IpAddr>().is_ok() {
            return None;
        }
        return Some(host.to_string());
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // test infrastructure
pub(crate) mod tests {
    use super::*;

    /// Build a TLS 1.3 style ClientHello record with an SNI extension for
    /// `host`, and with other extensions before and after it, as real
    /// clients send.
    pub(crate) fn client_hello(host: Option<&str>) -> Vec<u8> {
        client_hello_padded(host, 0)
    }

    /// The same ClientHello, with a padding extension of `pad` bytes after
    /// the `server_name` extension. With enough padding the handshake is
    /// longer than 255 bytes, so its 24-bit length needs more than the low
    /// byte.
    fn client_hello_padded(host: Option<&str>, pad: usize) -> Vec<u8> {
        fn push_u16(v: &mut Vec<u8>, n: usize) {
            v.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
        }

        let mut extensions = Vec::new();
        // supported_groups (0x000a): x25519
        extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        if let Some(host) = host {
            let mut sni = Vec::new();
            sni.push(0x00); // host_name
            push_u16(&mut sni, host.len());
            sni.extend_from_slice(host.as_bytes());
            let mut list = Vec::new();
            push_u16(&mut list, sni.len());
            list.extend_from_slice(&sni);
            extensions.extend_from_slice(&[0x00, 0x00]);
            push_u16(&mut extensions, list.len());
            extensions.extend_from_slice(&list);
        }
        if pad > 0 {
            // padding (0x0015)
            extensions.extend_from_slice(&[0x00, 0x15]);
            push_u16(&mut extensions, pad);
            extensions.extend(std::iter::repeat_n(0x00, pad));
        }
        // supported_versions (0x002b): TLS 1.3
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&[0x42; 32]); // random
        hello.push(32); // session id length
        hello.extend_from_slice(&[0x07; 32]);
        hello.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher suites
        hello.extend_from_slice(&[0x01, 0x00]); // compression: null
        push_u16(&mut hello, extensions.len());
        hello.extend_from_slice(&extensions);

        let mut handshake = vec![TLS_CLIENT_HELLO];
        let len = u32::try_from(hello.len()).unwrap().to_be_bytes();
        handshake.extend_from_slice(&len[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01];
        push_u16(&mut record, handshake.len());
        record.extend_from_slice(&handshake);
        record
    }

    /// A ClientHello record in the byte layout that `openssl s_client
    /// -servername example.com` sends. The bytes are written out by hand,
    /// with fewer extensions, so that the test does not use the builder above.
    const CAPTURED_HELLO_PREFIX: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x49, // record header, 73-byte body
        0x01, 0x00, 0x00, 0x45, // ClientHello, 69 bytes
        0x03, 0x03, // legacy_version TLS 1.2
        0x8f, 0x3c, 0x2a, 0x11, 0x5e, 0x90, 0x7b, 0x1d, 0x63, 0x0e, 0xa4, 0x52, 0x29, 0xd1, 0x88,
        0x04, 0x6b, 0xf2, 0x37, 0x9a, 0x15, 0xc0, 0x4e, 0x71, 0x2d, 0xb8, 0x03, 0x96, 0x5f, 0xe1,
        0x0c, 0x7a, // random (32 bytes)
        0x00, // session id: empty
        0x00, 0x04, 0x13, 0x02, 0x13, 0x01, // cipher suites
        0x01, 0x00, // compression methods: null
        0x00, 0x18, // extensions length: 24
        0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', b'.', b'c', b'o', b'm', // server_name: example.com
        0x00, 0x17, 0x00, 0x00, // extended_master_secret (empty)
    ];

    #[test]
    fn test_extract_sni_from_captured_client_hello() {
        assert_eq!(
            extract_sni(CAPTURED_HELLO_PREFIX),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_sni_from_built_client_hello() {
        let record = client_hello(Some("api.github.com"));
        assert_eq!(extract_sni(&record), Some("api.github.com".to_string()));
        assert!(Inspect::Tls.is_complete(&record));
        assert!(!Inspect::Tls.is_complete(&record[..record.len() - 1]));
    }

    #[test]
    fn test_extract_sni_absent() {
        let record = client_hello(None);
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn test_extract_sni_rejects_garbage() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(extract_sni(&[0x16, 0x03, 0x01]), None);
        assert_eq!(
            extract_sni(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff]),
            None
        );
        let mut record = client_hello(Some("example.com"));
        record.truncate(60);
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn test_extract_http_host() {
        let head = b"GET /x HTTP/1.1\r\nUser-Agent: t\r\nHOST: Example.com:8080\r\n\r\nbody";
        assert_eq!(extract_http_host(head), Some("Example.com".to_string()));
        assert_eq!(
            extract_http_host(b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"),
            None
        );
        assert_eq!(
            extract_http_host(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"),
            None
        );
        assert_eq!(extract_http_host(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(extract_http_host(b"\x16\x03\x01"), None);
    }

    #[tokio::test]
    async fn test_read_initial_reads_split_record() {
        use tokio::io::AsyncWriteExt;
        let record = client_hello(Some("example.com"));
        let (mut a, mut b) = tokio::io::duplex(64);
        let to_send = record.clone();
        let writer = tokio::spawn(async move {
            for part in to_send.chunks(7) {
                a.write_all(part).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            a
        });
        let buf = read_initial(&mut b, Vec::new(), Inspect::Tls, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(buf, record);
        drop(writer.await.unwrap());
    }

    /// The lock of the ports of the process. A test that changes the ports
    /// holds it, so that two tests do not see the ports of each other.
    static PORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The ports of the process, for one test. The drop gives the usual
    /// ports back.
    ///
    /// The field holds the lock for the life of the guard. Nothing reads
    /// it, thus the `allow`.
    pub(crate) struct PortGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    impl PortGuard {
        /// Take the lock and set `ports`.
        pub(crate) fn set(ports: InspectPorts) -> Self {
            let lock = PORT_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            set_inspect_ports(ports);
            Self(lock)
        }
    }

    impl Drop for PortGuard {
        fn drop(&mut self) {
            set_inspect_ports(InspectPorts::default());
        }
    }

    /// The proxy inspects the host name on port 443 and on port 80. If this
    /// selection gives `None`, the proxy relays without any check of the SNI
    /// or of the `Host` header, and domain fronting works.
    #[test]
    fn inspection_runs_on_port_443_and_on_port_80() {
        let _guard = PortGuard::set(InspectPorts::default());
        assert_eq!(Inspect::for_port(443), Some(Inspect::Tls));
        assert_eq!(Inspect::for_port(80), Some(Inspect::Http));
        assert_eq!(Inspect::for_port(8443), None);
        assert_eq!(Inspect::for_port(22), None);
    }

    /// The end-to-end proof against domain fronting: the client asks for a
    /// host that the allowlist permits, and then it names another host in
    /// the TLS record. The proxy must not relay the connection, and the
    /// destination must get no byte of the client.
    ///
    /// The test needs a server on the port that the proxy inspects. An
    /// unprivileged process cannot bind the port 443, thus the test sets
    /// the port of the inspection to the port of its own server.
    #[test]
    fn the_proxy_does_not_relay_a_fronted_host() {
        use std::net::SocketAddr;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let Ok(destination) = std::net::TcpListener::bind("127.0.0.1:0") else {
            crate::test_support::skip("this machine cannot bind a TCP socket on the loopback");
            return;
        };
        let Ok(dest_addr) = destination.local_addr() else {
            crate::test_support::skip("this machine gives no address for a TCP listener");
            return;
        };
        let _guard = PortGuard::set(InspectPorts {
            tls: dest_addr.port(),
            ..InspectPorts::default()
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current thread runtime");

        runtime.block_on(async move {
            destination.set_nonblocking(true).unwrap();
            let destination = tokio::net::TcpListener::from_std(destination).unwrap();

            // The destination server: it sends what each connection gave it.
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                while let Ok((mut socket, _)) = destination.accept().await {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let mut got = Vec::new();
                        let _ = socket.read_to_end(&mut got).await;
                        let _ = tx.send(got);
                    });
                }
            });

            // The proxy: "localhost" is the only name of the allowlist.
            let state = Arc::new(crate::SharedState::new(vec!["localhost".to_string()]));
            let config = crate::TcpProxyConfig {
                private_destinations: crate::PrivateDestinations::Allow,
                ..crate::TcpProxyConfig::default()
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = listener.local_addr().unwrap();
            let proxy = crate::TcpProxy::new(config, state).unwrap();
            let proxy_task = tokio::spawn(async move { proxy.run_on(listener).await });

            // Ask for "localhost", then send the first TLS record.
            async fn tunnel(proxy: SocketAddr, port: u16, hello: &[u8]) {
                let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
                let request = format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n");
                client.write_all(request.as_bytes()).await.unwrap();
                let mut head = [0u8; 12];
                client.read_exact(&mut head).await.unwrap();
                assert_eq!(&head, b"HTTP/1.1 200", "the proxy refused the tunnel");
                client.write_all(hello).await.unwrap();
                // The client goes away. The destination then reads the end
                // of its connection, also when the proxy relayed the data.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            async fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .expect("the destination got no connection")
                    .expect("the destination server ended")
            }

            // The fronted host: the destination must get nothing.
            let fronted = client_hello(Some("evil.example"));
            tunnel(proxy_addr, dest_addr.port(), &fronted).await;
            assert_eq!(
                next(&mut rx).await,
                Vec::<u8>::new(),
                "the proxy relayed a fronted host"
            );

            // The same path with the host of the allowlist: the data goes
            // through. Without this the test would also pass with a proxy
            // that relays nothing.
            let allowed = client_hello(Some("localhost"));
            tunnel(proxy_addr, dest_addr.port(), &allowed).await;
            assert_eq!(next(&mut rx).await, allowed);

            proxy_task.abort();
            server.abort();
        });
    }

    /// The ports come from a value, thus a test can inspect another port.
    /// The usual ports stay the default.
    #[test]
    fn the_ports_of_the_inspection_come_from_a_value() {
        assert_eq!(InspectPorts::default(), InspectPorts { tls: 443, http: 80 });
        let ports = InspectPorts {
            tls: 18_443,
            http: 18_080,
        };
        assert_eq!(Inspect::for_port_in(18_443, ports), Some(Inspect::Tls));
        assert_eq!(Inspect::for_port_in(18_080, ports), Some(Inspect::Http));
        assert_eq!(Inspect::for_port_in(443, ports), None);
        assert_eq!(Inspect::for_port_in(80, ports), None);
    }

    /// A real ClientHello is longer than 255 bytes, so the 24-bit length of
    /// the handshake needs its high bytes. The parser must still find the
    /// SNI.
    #[test]
    fn sni_is_found_in_a_client_hello_longer_than_255_bytes() {
        let record = client_hello_padded(Some("api.github.com"), 400);
        assert!(
            record.len() > 400,
            "the record must be long: {}",
            record.len()
        );
        assert_eq!(extract_sni(&record), Some("api.github.com".to_string()));
    }

    /// `is_complete` says when the proxy has enough data. A wrong answer
    /// makes the proxy wait for data that never comes, or inspect a head
    /// that is not complete.
    #[test]
    fn tls_inspection_waits_only_for_a_handshake_record() {
        // Not a handshake record: there is nothing to wait for.
        assert!(Inspect::Tls.is_complete(&[0x17, 0x03, 0x03, 0x00, 0x10]));
        // A handshake record header with no body: wait.
        assert!(!Inspect::Tls.is_complete(&[0x16, 0x03, 0x01, 0x00, 0x10]));
    }

    /// A record header can declare a body that is longer than a TLS record
    /// can be. The proxy waits for at most the maximum record length, so a
    /// client cannot hold the connection with a false length.
    #[test]
    fn tls_inspection_waits_at_most_one_maximum_record() {
        let header = |body: usize| {
            let mut v = vec![TLS_HANDSHAKE, 0x03, 0x01];
            v.extend_from_slice(&u16::try_from(body).unwrap_or(0).to_be_bytes());
            v
        };
        // The record declares 17,000 bytes, which is below the maximum. The
        // proxy waits for all of them.
        let mut short = header(17_000);
        short.extend(std::iter::repeat_n(0x00, 14_500));
        assert!(!Inspect::Tls.is_complete(&short));
        // The record declares 60,000 bytes, which is above the maximum
        // (16,384 plus the permitted expansion of 2,048). The proxy stops at
        // the maximum.
        let mut long = header(60_000);
        long.extend(std::iter::repeat_n(0x00, 18_432));
        assert!(Inspect::Tls.is_complete(&long));
    }

    /// The HTTP head is complete at the empty line, at the maximum length,
    /// or as soon as the first byte cannot start a method.
    #[test]
    fn http_inspection_stops_at_the_end_of_the_head() {
        assert!(Inspect::Http.is_complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
        assert!(!Inspect::Http.is_complete(b"GET / HTTP/1.1\r\nHost: a\r\n"));
        // The first byte is not an uppercase letter, thus this is not an
        // HTTP request and the proxy does not wait.
        assert!(Inspect::Http.is_complete(b"\x00\x01\x02\x03"));
        // A head that reaches the maximum length is complete.
        assert!(Inspect::Http.is_complete(&vec![b'G'; MAX_HTTP_HEAD_LEN]));
        assert!(!Inspect::Http.is_complete(&vec![b'G'; MAX_HTTP_HEAD_LEN - 1]));
    }

    #[tokio::test]
    async fn test_read_initial_keeps_bytes_on_timeout() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0x16, 0x03]).await.unwrap();
        let buf = read_initial(&mut b, vec![], Inspect::Tls, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(buf, vec![0x16, 0x03]);
        drop(a);
    }
}
