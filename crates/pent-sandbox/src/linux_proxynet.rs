//! The `ProxyOnly` network on Linux. It needs no privileges.
//!
//! # Architecture
//!
//! ```text
//! Host network namespace                 Child network namespace
//!                                        (only `lo`)
//! pent (parent)                          sandboxed process
//!   proxy tasks  <--- accept() ---------  127.0.0.1:3128  (SOCKS5 + CONNECT)
//!     |          <--- recv()   ---------  127.0.0.1:53    (DNS, UDP)
//!     |          <--- accept() ---------  127.0.0.1:53    (DNS, TCP)
//!     v
//!   upstream connections (host network)
//! ```
//!
//! The child unshares a user namespace and a network namespace. In the
//! `pre_exec` hook, after it brings up `lo`, the child still has all
//! capabilities in its new user namespace, which owns the new network
//! namespace. Thus it can bind port 53. It creates the listeners, sends them
//! to the parent with `SCM_RIGHTS` over a socket pair, closes its copies and
//! continues to `exec`.
//!
//! A socket keeps the network namespace of its creation. The parent owns
//! the listeners, and the proxy accepts connections on them, but the
//! listeners stay in the network namespace of the child. The proxy connects
//! upstream from the host network namespace.
//!
//! The child has no route out of its namespace. It can reach only its own
//! loopback, so each connection must go through the proxy. The child gets a
//! `resolv.conf` with `nameserver 127.0.0.1`. A program that uses a fixed
//! resolver (for example 8.8.8.8) cannot resolve names: the request fails.
//!
//! The DNS listeners are IPv4 only (`resolv.conf` names 127.0.0.1). The
//! proxy port also listens on `[::1]` when IPv6 works in the namespace.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use crate::SandboxError;

/// The port of the proxy (SOCKS5 and HTTP CONNECT) in the network namespace
/// of the child.
pub const CHILD_PROXY_PORT: u16 = 3128;

/// The DNS port in the network namespace of the child. `resolv.conf` cannot
/// name another port.
pub const CHILD_DNS_PORT: u16 = 53;

/// The address of the proxy in the network namespace of the child.
#[must_use]
pub const fn child_proxy_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, CHILD_PROXY_PORT))
}

/// The content of the `resolv.conf` file of the child.
const RESOLV_CONF: &str = "nameserver 127.0.0.1\n";

/// The backlog of the listeners.
const BACKLOG: libc::c_int = 1024;

/// The proxy listeners that the child made in its network namespace.
///
/// Give them to the proxy (`pent_proxy::ProxyHandle::attach_listeners`).
/// The sockets are in blocking mode.
#[derive(Debug)]
pub struct ProxyListeners {
    /// The listeners of the proxy port ([`CHILD_PROXY_PORT`]): one on
    /// 127.0.0.1, and one on `[::1]` when IPv6 works in the namespace.
    pub tcp: Vec<std::net::TcpListener>,
    /// The DNS socket on 127.0.0.1:53 (UDP).
    pub dns_udp: std::net::UdpSocket,
    /// The DNS listener on 127.0.0.1:53 (TCP).
    pub dns_tcp: std::net::TcpListener,
}

/// The data that the `pre_exec` hook needs to make the listeners.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProxySocketsChild {
    /// The socket end of the child. The child sends the listeners on it.
    sock: RawFd,
}

impl ProxySocketsChild {
    /// Make the listeners, send them to the parent, and close the copies of
    /// the child.
    ///
    /// The order of the descriptors in the message: the DNS UDP socket, the
    /// DNS TCP listener, the IPv4 proxy listener, and then the IPv6 proxy
    /// listener if there is one.
    ///
    /// # Safety
    /// Call this only in a `pre_exec` hook, in the new network namespace,
    /// after `lo` is up. The function uses only raw system calls on data that
    /// the parent prepared.
    ///
    /// # Errors
    /// Returns the OS error if a socket, a bind, a listen or the send fails.
    pub(crate) unsafe fn create_and_send(self) -> std::io::Result<()> {
        let mut fds: [RawFd; 4] = [-1; 4];
        let result = make_sockets(&mut fds).and_then(|count| {
            let sent = fds.get(..count).unwrap_or_default();
            // SAFETY: `self.sock` and each descriptor in `sent` are open
            // descriptors of this process.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { crate::linux_fdpass::send_fds(self.sock, sent) }
        });
        for fd in fds.into_iter().filter(|fd| *fd >= 0) {
            // SAFETY: close the copies of this process; the parent has the
            // listeners now (or the spawn fails).
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(fd) };
        }
        // SAFETY: `exec` does not need the socket.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(self.sock) };
        result
    }
}

/// Make the sockets into `fds` and return their number. Async-signal-safe.
fn make_sockets(fds: &mut [RawFd; 4]) -> std::io::Result<usize> {
    let lo4 = Ipv4Addr::LOCALHOST.octets();
    fds[0] = socket_v4(libc::SOCK_DGRAM, lo4, CHILD_DNS_PORT)?;
    fds[1] = socket_v4(libc::SOCK_STREAM, lo4, CHILD_DNS_PORT)?;
    fds[2] = socket_v4(libc::SOCK_STREAM, lo4, CHILD_PROXY_PORT)?;
    // IPv6 is best effort: the kernel can have IPv6 off.
    match listen_v6_loopback(CHILD_PROXY_PORT) {
        Some(fd) => {
            fds[3] = fd;
            Ok(4)
        }
        None => Ok(3),
    }
}

/// Return the last OS error, after the close of `fd`.
fn close_with_error(fd: RawFd) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    // SAFETY: `fd` is a descriptor that the caller opened.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(fd) };
    err
}

/// Create an IPv4 socket of type `kind`, bind it to `addr:port`, and listen
/// on it if it is a stream socket. Async-signal-safe.
fn socket_v4(kind: libc::c_int, addr: [u8; 4], port: u16) -> std::io::Result<RawFd> {
    // SAFETY: socket(2) with constant arguments.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::socket(libc::AF_INET, kind | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `sa` is a valid `sockaddr_in`, and the length matches it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(close_with_error(fd));
    }
    // SAFETY: listen(2) on a socket that this function owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if kind == libc::SOCK_STREAM && unsafe { libc::listen(fd, BACKLOG) } != 0 {
        return Err(close_with_error(fd));
    }
    Ok(fd)
}

/// Create a TCP listener on `[::1]:port` with `IPV6_V6ONLY`. Returns `None`
/// if a step fails. Async-signal-safe.
fn listen_v6_loopback(port: u16) -> Option<RawFd> {
    // SAFETY: socket(2) with constant arguments.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let one: libc::c_int = 1;
    let sa = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: std::net::Ipv6Addr::LOCALHOST.octets(),
        },
        sin6_scope_id: 0,
    };
    // SAFETY: setsockopt with a valid `int`, then bind with a valid
    // `sockaddr_in6` and its length, then listen. All on a socket that this
    // function owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ok = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
            && libc::bind(
                fd,
                std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ) == 0
            && libc::listen(fd, BACKLOG) == 0
    };
    if ok {
        Some(fd)
    } else {
        // SAFETY: `fd` is a descriptor that this function opened.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
        None
    }
}

/// The proxy sockets before the spawn: the data for the child and the
/// socket pair.
pub(crate) struct ProxySocketsSetup {
    /// The data for the `pre_exec` hook.
    pub(crate) child: ProxySocketsChild,
    parent_sock: OwnedFd,
    child_sock: OwnedFd,
}

impl ProxySocketsSetup {
    /// Create the socket pair.
    ///
    /// # Errors
    /// Returns `SpawnFailed` if the socket pair cannot be created.
    pub(crate) fn new() -> Result<Self, SandboxError> {
        let (parent_sock, child_sock) = crate::linux_fdpass::seqpacket_pair()?;
        Ok(Self {
            child: ProxySocketsChild {
                sock: child_sock.as_raw_fd(),
            },
            parent_sock,
            child_sock,
        })
    }

    /// Close the parent copy of the socket end of the child, and receive
    /// the listeners. Call this after a successful `spawn`: the child sent
    /// the listeners before its `exec`, so the message is in the queue.
    ///
    /// # Errors
    /// Returns `NetworkSetupFailed` if the child sent no listeners or a
    /// message that is not valid.
    pub(crate) fn receive(self) -> Result<ProxyListeners, SandboxError> {
        drop(self.child_sock);
        let fail = |msg: String| SandboxError::NetworkSetupFailed(msg);
        let fds = crate::linux_fdpass::recv_fds(&self.parent_sock)
            .map_err(|e| fail(format!("cannot receive the proxy listeners: {e}")))?
            .ok_or_else(|| fail("the child sent no proxy listeners".to_string()))?;
        let mut fds = fds.into_iter();
        let (Some(udp), Some(dns_tcp), Some(tcp4)) = (fds.next(), fds.next(), fds.next()) else {
            return Err(fail("the child sent too few proxy listeners".to_string()));
        };
        let mut tcp = vec![std::net::TcpListener::from(tcp4)];
        tcp.extend(fds.map(std::net::TcpListener::from));
        Ok(ProxyListeners {
            tcp,
            dns_udp: std::net::UdpSocket::from(udp),
            dns_tcp: std::net::TcpListener::from(dns_tcp),
        })
    }
}

/// Write the `resolv.conf` file for the child and return its path.
///
/// The file has the same content for each child, so all pent processes of
/// this user share one file. The function writes it only if it is absent or
/// different, with a write to a temporary file and a rename.
///
/// # Errors
/// Returns `NetworkSetupFailed` if the directory is not safe or the file
/// cannot be written.
pub(crate) fn resolv_conf() -> Result<PathBuf, SandboxError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = ensure_runtime_dir()?;
    let path = dir.join("resolv.conf");
    if std::fs::read(&path).is_ok_and(|c| c == RESOLV_CONF.as_bytes()) {
        return Ok(path);
    }
    let tmp = dir.join(format!("resolv.conf.{}", std::process::id()));
    let fail = |e: std::io::Error| {
        SandboxError::NetworkSetupFailed(format!("cannot write {}: {e}", path.display()))
    };
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&tmp)
        .and_then(|mut f| f.write_all(RESOLV_CONF.as_bytes()))
        .map_err(fail)?;
    std::fs::rename(&tmp, &path).map_err(fail)?;
    Ok(path)
}

/// Return the directory for the runtime files of pent.
fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        if dir.is_absolute() && dir.is_dir() {
            return dir.join("pent");
        }
    }
    // SAFETY: getuid has no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("pent-{uid}"))
}

/// Create the runtime directory with mode 0700 and check that this user
/// owns it and that no other user can write to it.
fn ensure_runtime_dir() -> Result<PathBuf, SandboxError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let dir = runtime_dir();
    let fail = |msg: String| SandboxError::NetworkSetupFailed(msg);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| fail(format!("cannot create {}: {e}", dir.display())))?;
    let meta = std::fs::symlink_metadata(&dir)
        .map_err(|e| fail(format!("cannot read {}: {e}", dir.display())))?;
    // SAFETY: getuid has no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let uid = unsafe { libc::getuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(fail(format!(
            "{} is not a private directory of this user",
            dir.display()
        )));
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn child_address_is_loopback() {
        assert_eq!(child_proxy_addr().to_string(), "127.0.0.1:3128");
    }

    #[test]
    fn resolv_conf_names_loopback() -> TestResult {
        let path = resolv_conf()?;
        assert_eq!(std::fs::read_to_string(&path)?, RESOLV_CONF);
        // A second call keeps the file.
        assert_eq!(resolv_conf()?, path);
        Ok(())
    }

    /// The child side makes the listeners, and the parent side receives
    /// them. The test sends host sockets on free ports in place of the hook,
    /// because the hook needs a new network namespace. It checks the
    /// message format, not the namespace.
    #[test]
    fn parent_receives_the_listeners() -> TestResult {
        let setup = ProxySocketsSetup::new()?;
        let fake_listeners = || -> std::io::Result<Vec<OwnedFd>> {
            Ok(vec![
                std::net::UdpSocket::bind("127.0.0.1:0")?.into(),
                std::net::TcpListener::bind("127.0.0.1:0")?.into(),
                std::net::TcpListener::bind("127.0.0.1:0")?.into(),
            ])
        };
        let fds = fake_listeners()?;
        let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        // SAFETY: all descriptors are open.
        unsafe { crate::linux_fdpass::send_fds(setup.child.sock, &raw) }?;
        drop(fds);
        let listeners = setup.receive()?;
        assert_eq!(listeners.tcp.len(), 1);
        assert!(listeners.dns_udp.local_addr()?.ip().is_loopback());
        assert!(listeners.dns_tcp.local_addr()?.ip().is_loopback());
        Ok(())
    }

    #[test]
    fn parent_rejects_too_few_listeners() -> TestResult {
        let setup = ProxySocketsSetup::new()?;
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        // SAFETY: both descriptors are open.
        unsafe { crate::linux_fdpass::send_fds(setup.child.sock, &[udp.as_raw_fd()]) }?;
        assert!(setup.receive().is_err());
        Ok(())
    }

    #[test]
    fn parent_reports_a_child_that_sent_nothing() -> TestResult {
        let setup = ProxySocketsSetup::new()?;
        assert!(setup.receive().is_err());
        Ok(())
    }
}
