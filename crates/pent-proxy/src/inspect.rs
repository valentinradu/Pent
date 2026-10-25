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
    pub(crate) const fn for_port(port: u16) -> Option<Self> {
        match port {
            443 => Some(Self::Tls),
            80 => Some(Self::Http),
            _ => None,
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
