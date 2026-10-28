//! The loopback of the host on Linux.
//!
//! With its own network namespace, the child has its own loopback. A
//! `connect(2)` to `127.0.0.1:5432` in the child reaches the loopback of the
//! sandbox, not a database on the loopback of the host. The profile opens
//! such a port with `[network] localhost = [5432]`
//! ([`crate::SandboxConfig::localhost`]).
//!
//! The supervisor already traps each `connect(2)` for the control of the
//! Unix sockets ([`crate::linux_unixconn`]). For a TCP socket of the child
//! (`AF_INET` or `AF_INET6`, `SOCK_STREAM`) with a loopback address, it
//! decides in this order:
//!
//! 1. The child listens on the port in its own namespace: the call runs as
//!    it is, and the connection stays in the sandbox. A program that starts
//!    its own server and connects to it needs no rule. The supervisor reads
//!    the listening sockets from `/proc/<tid>/net/tcp` and `tcp6`, which
//!    show the namespace of the child.
//! 2. The policy opens the port: the supervisor connects a socket of its
//!    own on the network of the host, and gives it to the child with
//!    `SECCOMP_IOCTL_NOTIF_ADDFD` at the descriptor number of the child.
//! 3. Else the call runs as it is, in the namespace of the child. Nothing
//!    listens there on the port, so the child gets `ECONNREFUSED`. In the
//!    blocked network mode the namespace has no loopback at all (pent
//!    brings up `lo` only for the proxy and localhost modes), so the child
//!    gets `ENETUNREACH`, and a server that the program itself starts does
//!    not work either. Step 2 still works there.
//!
//! Before step 1 the supervisor reads the socket of the child itself. It
//! acts only on a new TCP socket (`IPPROTO_TCP`, state `TCP_CLOSE`): a
//! second `connect(2)` on a socket that is connecting or connected must get
//! the answer of the kernel (`EALREADY`, `EISCONN`), and a socket of
//! another stream protocol (MPTCP) must keep its protocol. A socket with
//! `IPV6_V6ONLY` that connects to an IPv4-mapped address also keeps the
//! answer of the kernel. The connections to the listeners of pent in the
//! namespace of the child (the proxy and the DNS server) stay there with no
//! look at the tables.
//!
//! The supervisor reads the address one time and connects to that copy, so
//! another thread of the child cannot change the target of a connection to
//! the host. A `CONTINUE` lets the kernel read the address again, but the
//! kernel then connects in the namespace of the child, which reaches
//! nothing outside the sandbox.
//!
//! # What the new descriptor cannot keep
//!
//! The same limits as for a Unix socket apply (see
//! [`crate::linux_unixconn`]): the socket options and a `bind(2)` that the
//! child made before the `connect(2)` are lost, and a blocking connection
//! stops after [`crate::linux_unixconn::CONNECT_LIMIT`] with `ETIMEDOUT`. A
//! non-blocking socket keeps its timing: the child gets `EINPROGRESS` and
//! the socket of the supervisor, which finishes the connection.
//!
//! # What stays open
//!
//! - The check of step 1 and the `connect(2)` of the child are two steps. A
//!   program that connects to its own server before the server listens
//!   reaches the port of the host instead, when the policy opens the port.
//!   Without a rule for the port, it gets the answer of step 3 as before.
//! - Only TCP goes to the host. A UDP socket stays in the namespace of the
//!   child.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use pent_profile::{GuardClass, Outcome};

use crate::linux_unixconn::{errno, set_nonblock, FdFlags};
use crate::LocalhostPorts;

/// The longest address that the supervisor reads: `struct sockaddr_in6`.
pub(crate) const SOCKADDR_INET_LEN: usize = std::mem::size_of::<libc::sockaddr_in6>();

/// The shortest `sockaddr_in6` that the kernel takes (`SIN6_LEN_RFC2133`:
/// no `sin6_scope_id`).
const SOCKADDR_IN6_MIN_LEN: usize = 24;

/// The state `TCP_LISTEN` in `/proc/<pid>/net/tcp`.
const TCP_LISTEN: &str = "0A";

/// Where the loopback of the child is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoopbackControl {
    /// The child uses the network namespace of the host
    /// (`--network unrestricted`), so its loopback is the loopback of the
    /// host. The supervisor does nothing.
    Shared,
    /// The child has its own network namespace.
    Private {
        /// The ports of the host that are open.
        ports: LocalhostPorts,
        /// The listeners that pent makes in the namespace of the child (the
        /// proxy and the DNS server). A connection to one of them stays in
        /// the namespace, and the supervisor reads no table for it.
        pent: Vec<SocketAddr>,
    },
}

impl LoopbackControl {
    /// Return true if the control can change a call: the child has its own
    /// namespace and the policy opens at least one port.
    pub(crate) fn is_active(&self) -> bool {
        matches!(self, Self::Private { ports, .. } if !ports.is_empty())
    }
}

/// The TCP state `TCP_CLOSE` of `struct tcp_info`: a socket that is not
/// connecting and not connected.
const TCP_CLOSE: u8 = 7;

/// What the supervisor reads from the socket of the child before it acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketFacts {
    /// The protocol is `IPPROTO_TCP` (not MPTCP, not SCTP).
    pub(crate) tcp: bool,
    /// The socket is new: its TCP state is `TCP_CLOSE`.
    pub(crate) fresh: bool,
    /// The socket has `IPV6_V6ONLY`.
    pub(crate) v6only: bool,
}

impl SocketFacts {
    /// Read the facts of the socket `fd` of the family `domain`. Return
    /// `None` when a read fails; the supervisor then lets the call run.
    pub(crate) fn of(fd: std::os::fd::BorrowedFd<'_>, domain: libc::c_int) -> Option<Self> {
        let protocol = int_opt(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)?;
        // The first byte of `struct tcp_info` is the state. The kernel
        // copies as many bytes as the buffer holds.
        let mut info = [0u8; 8];
        let mut len = libc::socklen_t::try_from(info.len()).ok()?;
        // SAFETY: the kernel writes at most `len` bytes into `info` and the
        // length into `len`; both live until the call returns.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        let state = if ret == 0 {
            info.first().copied()
        } else {
            None
        };
        let v6only = domain == libc::AF_INET6
            && int_opt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY).is_some_and(|v| v != 0);
        Some(Self {
            tcp: protocol == libc::IPPROTO_TCP,
            fresh: state? == TCP_CLOSE,
            v6only,
        })
    }

    /// Return true if the supervisor may make the connection to `dest`
    /// itself. Else the kernel gives its own answer.
    pub(crate) fn takes(self, dest: SocketAddr) -> bool {
        let mapped = matches!(dest, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some());
        self.tcp && self.fresh && !(self.v6only && mapped)
    }
}

/// Read the integer socket option `name` at `level`.
fn int_opt(
    fd: std::os::fd::BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: the kernel writes one `c_int` into `value` and the length into
    // `len`; both live until the call returns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    (ret == 0).then_some(value)
}

/// What the policy says about one port of the host, before the supervisor
/// looks at the sockets of the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortPolicy {
    /// The policy opens the port.
    Open,
    /// The policy does not open the port.
    Closed,
    /// The watch guard blocks the port (a control port).
    Guarded,
}

impl PortPolicy {
    /// The policy of `port` under `ports`.
    pub(crate) fn of(ports: &LocalhostPorts, port: u16) -> Self {
        if ports.permits(port) {
            Self::Open
        } else if ports.guards(port) {
            Self::Guarded
        } else {
            Self::Closed
        }
    }
}

/// What the supervisor does with a TCP connection to the loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopbackDecision {
    /// The child listens on the port: the call runs in its namespace, and
    /// the recorder makes no event.
    Child,
    /// The supervisor connects to the port of the host.
    Host,
    /// The policy does not open the port: the call runs in the namespace of
    /// the child, where nothing listens.
    Refuse,
    /// The watch guard blocks the port: the call runs in the namespace of
    /// the child, and the event has the guard class.
    Guarded,
}

impl LoopbackDecision {
    /// The outcome of the decision for the recorded event, or `None` when
    /// the decision makes no event.
    pub(crate) const fn outcome(self) -> Option<Outcome> {
        match self {
            Self::Child => None,
            Self::Host => Some(Outcome::Allowed),
            Self::Refuse => Some(Outcome::Denied),
            Self::Guarded => Some(Outcome::Blocked(GuardClass::ControlPort)),
        }
    }
}

/// Decide a TCP connection to a loopback port with the policy `policy`.
///
/// `child_listens` reads the listening sockets of the child. The function
/// calls it first, because a server of the child has priority over a port
/// of the host.
pub(crate) fn decide(policy: PortPolicy, child_listens: impl FnOnce() -> bool) -> LoopbackDecision {
    if child_listens() {
        return LoopbackDecision::Child;
    }
    match policy {
        PortPolicy::Open => LoopbackDecision::Host,
        PortPolicy::Closed => LoopbackDecision::Refuse,
        PortPolicy::Guarded => LoopbackDecision::Guarded,
    }
}

pub(crate) use pent_profile::is_loopback;

/// Parse the bytes of an address for a socket of the family `domain`.
///
/// Returns `None` for an address of another family and for an address that
/// is too short. The kernel gives its own error for these, so the
/// supervisor lets the call run.
pub(crate) fn parse_inet(bytes: &[u8], domain: libc::c_int) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?);
    if libc::c_int::from(family) != domain {
        return None;
    }
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    match domain {
        libc::AF_INET => {
            if bytes.len() < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        libc::AF_INET6 => {
            if bytes.len() < SOCKADDR_IN6_MIN_LEN {
                return None;
            }
            let flowinfo = u32::from_ne_bytes(bytes.get(4..8)?.try_into().ok()?);
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            let scope = bytes
                .get(24..28)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(0, u32::from_ne_bytes);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flowinfo,
                scope,
            )))
        }
        _ => None,
    }
}

/// Return true if a socket of the task `tid` listens on an address that
/// takes a connection to `dest`.
///
/// `/proc/<tid>/net/tcp` and `tcp6` show the sockets of the network
/// namespace of the task, so the answer is about the namespace of the
/// child.
pub(crate) fn child_listens(tid: u32, dest: SocketAddr) -> bool {
    ["tcp", "tcp6"].iter().any(|table| {
        std::fs::read_to_string(format!("/proc/{tid}/net/{table}"))
            .is_ok_and(|text| table_listens(&text, dest))
    })
}

/// Return true if the text of `/proc/<pid>/net/tcp` or `tcp6` has a
/// listening socket that takes a connection to `dest`. The columns are
/// `sl local_address rem_address st ...`; `local_address` is
/// `<address>:<port>` in hexadecimal.
fn table_listens(text: &str, dest: SocketAddr) -> bool {
    text.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(state)) = (fields.get(1), fields.get(3)) else {
            return false;
        };
        let Some((addr, port)) = local.rsplit_once(':') else {
            return false;
        };
        *state == TCP_LISTEN
            && u16::from_str_radix(port, 16).ok() == Some(dest.port())
            && parse_proc_addr(addr).is_some_and(|listener| takes(listener, dest.ip()))
    })
}

/// Parse an address of `/proc/<pid>/net/tcp` (8 hexadecimal digits) or
/// `tcp6` (32 digits). The kernel prints each 32-bit word of the address as
/// it is in memory, in the byte order of the machine.
fn parse_proc_addr(hex: &str) -> Option<IpAddr> {
    let mut bytes = Vec::with_capacity(16);
    for start in (0..hex.len()).step_by(8) {
        let word = u32::from_str_radix(hex.get(start..start.checked_add(8)?)?, 16).ok()?;
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes.as_slice())
            .ok()
            .map(|b| IpAddr::V4(Ipv4Addr::from(b))),
        16 => <[u8; 16]>::try_from(bytes.as_slice())
            .ok()
            .map(|b| IpAddr::V6(Ipv6Addr::from(b))),
        _ => None,
    }
}

/// Return true if a socket that listens on `listener` takes a connection to
/// `dest`: the same address, or an unspecified address of a family that
/// reaches `dest`.
///
/// A socket on `::` takes IPv4 too, unless it has `IPV6_V6ONLY`, which the
/// table does not show. The function then answers yes, and the connection
/// stays in the namespace of the child.
fn takes(listener: IpAddr, dest: IpAddr) -> bool {
    let dest_v4 = match dest {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };
    match listener {
        IpAddr::V4(v4) => dest_v4.is_some_and(|d| v4.is_unspecified() || v4 == d),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || listener == dest
                || (dest_v4.is_some() && v6.to_ipv4_mapped() == dest_v4)
        }
    }
}

/// A connection that the supervisor made on the network of the host.
pub(crate) struct HostConnection {
    /// The socket of the supervisor.
    pub(crate) fd: OwnedFd,
    /// The connection is not complete yet: the child gets `EINPROGRESS`, as
    /// the kernel gives it for a non-blocking socket.
    pub(crate) in_progress: bool,
}

/// Start a TCP connection to `addr` on the network of the host, with a new
/// non-blocking socket. The call does not wait: a connection that does not
/// complete at once comes back with `in_progress`.
///
/// # Errors
/// Returns the error number for the child: the error of `socket(2)` or of
/// `connect(2)` (for example `ECONNREFUSED`).
pub(crate) fn start_on_host(addr: SocketAddr) -> Result<HostConnection, i32> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: socket(2) with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let raw = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(errno());
    }
    // SAFETY: `raw` is a new, open descriptor that nothing else owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let (storage, len) = sockaddr_of(addr)?;
    // SAFETY: `storage` holds an address of `len` bytes, and `fd` is an
    // open socket.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&storage).cast::<libc::sockaddr>(),
            len,
        )
    };
    let in_progress = if ret == 0 {
        false
    } else {
        match errno() {
            // A signal does not stop a connection of a non-blocking socket:
            // the kernel goes on with it.
            libc::EINPROGRESS | libc::EINTR => true,
            e => return Err(e),
        }
    };
    Ok(HostConnection { fd, in_progress })
}

/// Give a connection from [`start_on_host`] the flags of the socket of the
/// child.
///
/// A non-blocking socket of the child gets the socket at once, also when
/// the connection is still in progress. For a blocking socket of the child
/// the function waits until the connection completes, or until `limit`.
/// This wait can be long, so the supervisor runs it on a thread of its own
/// (see `Supervisor::control_loopback` in `linux_watch.rs`).
///
/// # Errors
/// Returns the error number for the child: the error of the connection, or
/// `ETIMEDOUT` when it does not complete within `limit`.
pub(crate) fn finish_on_host(
    conn: HostConnection,
    flags: FdFlags,
    limit: Duration,
) -> Result<HostConnection, i32> {
    if conn.in_progress && !flags.nonblock {
        wait_connected(&conn.fd, limit)?;
    }
    set_nonblock(&conn.fd, flags.nonblock)?;
    Ok(HostConnection {
        fd: conn.fd,
        in_progress: conn.in_progress && flags.nonblock,
    })
}

/// Connect a new TCP socket to `addr` on the network of the host, with the
/// flags of the socket of the child ([`start_on_host`], then
/// [`finish_on_host`]).
#[cfg(test)]
fn connect_on_host(
    addr: SocketAddr,
    flags: FdFlags,
    limit: Duration,
) -> Result<HostConnection, i32> {
    finish_on_host(start_on_host(addr)?, flags, limit)
}

/// Build the `sockaddr` of `addr`.
fn sockaddr_of(addr: SocketAddr) -> Result<(libc::sockaddr_storage, libc::socklen_t), i32> {
    // SAFETY: a zeroed `sockaddr_storage` is a valid, empty address.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: a zeroed `sockaddr_in` is a valid, empty address.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            // The cast is exact: AF_INET is 2.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
            }
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            // SAFETY: `sockaddr_storage` is larger than `sockaddr_in` and
            // has a stricter alignment.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                std::ptr::write(
                    std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in>(),
                    sin,
                );
            };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            // SAFETY: a zeroed `sockaddr_in6` is a valid, empty address.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            // The cast is exact: AF_INET6 is 10.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            }
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_scope_id = v6.scope_id();
            // SAFETY: `sockaddr_storage` is larger than `sockaddr_in6` and
            // has a stricter alignment.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                std::ptr::write(
                    std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in6>(),
                    sin6,
                );
            };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    let len = libc::socklen_t::try_from(len).map_err(|_| libc::EINVAL)?;
    Ok((storage, len))
}

/// Wait until the connection of `fd` completes, and return its result.
///
/// # Errors
/// Returns `ETIMEDOUT` after `limit`, or the error of the connection
/// (`SO_ERROR`).
fn wait_connected(fd: &OwnedFd, limit: Duration) -> Result<(), i32> {
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(libc::ETIMEDOUT);
        }
        let timeout = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `pfd` is one valid pollfd.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout) };
        if ret < 0 {
            match errno() {
                libc::EINTR => continue,
                e => return Err(e),
            }
        }
        if ret > 0 {
            break;
        }
    }
    let mut error: libc::c_int = 0;
    let mut len =
        libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).map_err(|_| libc::EINVAL)?;
    // SAFETY: the kernel writes one `c_int` into `error` and the length into
    // `len`; both live until the call returns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            std::ptr::from_mut(&mut error).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret != 0 {
        return Err(errno());
    }
    if error != 0 {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::num::NonZeroU16;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The bytes of a `sockaddr_in` for `127.0.0.1:port`.
    fn v4_bytes(octets: [u8; 4], port: u16) -> Vec<u8> {
        // The cast is exact: AF_INET is 2.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mut bytes = (libc::AF_INET as u16).to_ne_bytes().to_vec();
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes.extend_from_slice(&octets);
        bytes.extend_from_slice(&[0u8; 8]);
        bytes
    }

    /// The bytes of a `sockaddr_in6` for `[ip]:port`.
    fn v6_bytes(ip: Ipv6Addr, port: u16) -> Vec<u8> {
        // The cast is exact: AF_INET6 is 10.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mut bytes = (libc::AF_INET6 as u16).to_ne_bytes().to_vec();
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend_from_slice(&ip.octets());
        bytes.extend_from_slice(&[0u8; 4]);
        bytes
    }

    #[test]
    fn an_address_parses_only_for_its_own_family() {
        let v4 = v4_bytes([127, 0, 0, 1], 5432);
        assert_eq!(
            parse_inet(&v4, libc::AF_INET),
            Some(SocketAddr::from(([127, 0, 0, 1], 5432)))
        );
        assert_eq!(parse_inet(&v4, libc::AF_INET6), None);
        assert_eq!(
            parse_inet(v4.get(..8).unwrap_or_default(), libc::AF_INET),
            None
        );

        let v6 = v6_bytes(Ipv6Addr::LOCALHOST, 11434);
        let parsed = parse_inet(&v6, libc::AF_INET6);
        assert_eq!(
            parsed.map(|a| (a.ip(), a.port())),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 11434))
        );
        // The kernel takes a `sockaddr_in6` without the scope field.
        assert!(parse_inet(v6.get(..24).unwrap_or_default(), libc::AF_INET6).is_some());
        assert_eq!(
            parse_inet(v6.get(..20).unwrap_or_default(), libc::AF_INET6),
            None
        );
        assert_eq!(parse_inet(&[], libc::AF_INET), None);
    }

    #[test]
    // The table holds each word in the byte order of the machine; the
    // texts below are those of a little-endian machine.
    #[cfg(target_endian = "little")]
    fn the_table_shows_only_listening_ports() {
        let at = |text: &str| -> SocketAddr { text.parse().unwrap_or(([0, 0, 0, 0], 0).into()) };
        let text = "  sl  local_address rem_address   st tx_queue rx_queue\n\
                    \x20  0: 0100007F:1538 00000000:0000 0A 00000000:00000000\n\
                    \x20  1: 0100007F:0CEA 0100007F:9C40 01 00000000:00000000\n\
                    \x20  2: 00000000:1F90 00000000:0000 0A 00000000:00000000\n";
        assert!(table_listens(text, at("127.0.0.1:5432")));
        // Another loopback address: the server on 127.0.0.1 does not take it.
        assert!(!table_listens(text, at("127.0.0.2:5432")));
        // An established connection is not a server.
        assert!(!table_listens(text, at("127.0.0.1:3306")));
        assert!(!table_listens(text, at("127.0.0.1:80")));
        // A server on 0.0.0.0 takes each IPv4 address and the mapped form.
        assert!(table_listens(text, at("127.0.0.9:8080")));
        assert!(table_listens(text, at("[::ffff:127.0.0.1]:8080")));
        // An IPv4 server does not take `::1`.
        assert!(!table_listens(text, at("[::1]:5432")));

        let v6 = "  sl  local_address                         remote_address                        st\n\
                  \x20  0: 00000000000000000000000001000000:2CAA 00000000000000000000000000000000:0000 0A\n\
                  \x20  1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A\n";
        assert!(table_listens(v6, at("[::1]:11434")));
        // A server on `::1` does not take 127.0.0.1.
        assert!(!table_listens(v6, at("127.0.0.1:11434")));
        // A server on `::` takes both families.
        assert!(table_listens(v6, at("127.0.0.1:80")));
        assert!(table_listens(v6, at("[::1]:80")));
    }

    #[test]
    fn our_own_listener_is_in_the_table() -> TestResult {
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return Ok(()); // This machine cannot bind on the loopback.
        };
        let addr = listener.local_addr()?;
        assert!(child_listens(std::process::id(), addr));
        Ok(())
    }

    #[test]
    fn a_server_of_the_child_has_priority() {
        let port = NonZeroU16::MIN.saturating_add(5431);
        let listed = LocalhostPorts::Listed(vec![port]);
        let policy = |ports: &LocalhostPorts, port| PortPolicy::of(ports, port);
        assert_eq!(
            decide(policy(&listed, 5432), || true),
            LoopbackDecision::Child
        );
        assert_eq!(
            decide(policy(&listed, 5432), || false),
            LoopbackDecision::Host
        );
        assert_eq!(
            decide(policy(&listed, 5433), || false),
            LoopbackDecision::Refuse
        );
        assert_eq!(
            decide(policy(&LocalhostPorts::All, 1), || false),
            LoopbackDecision::Host
        );
        // The watch guard blocks a control port, unless the child itself
        // serves it.
        assert_eq!(
            decide(policy(&LocalhostPorts::All, 2375), || false),
            LoopbackDecision::Guarded
        );
        assert_eq!(
            decide(policy(&LocalhostPorts::All, 2375), || true),
            LoopbackDecision::Child
        );
        assert_eq!(
            LoopbackDecision::Guarded.outcome(),
            Some(Outcome::Blocked(GuardClass::ControlPort))
        );
        assert_eq!(LoopbackDecision::Child.outcome(), None);
        assert_eq!(LoopbackDecision::Host.outcome(), Some(Outcome::Allowed));
        assert_eq!(LoopbackDecision::Refuse.outcome(), Some(Outcome::Denied));
        assert!(!LoopbackControl::Shared.is_active());
        let private = |ports| LoopbackControl::Private {
            ports,
            pent: Vec::new(),
        };
        assert!(!private(LocalhostPorts::default()).is_active());
        assert!(private(listed).is_active());
    }

    /// A new TCP socket. Return `None` when the machine cannot make one.
    fn new_socket(domain: libc::c_int) -> Option<OwnedFd> {
        // SAFETY: socket(2) with integer arguments only.
        let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        // SAFETY: `raw` is a new, open descriptor that nothing else owns.
        (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) })
    }

    /// The supervisor acts only on a new TCP socket. A connected socket, and
    /// a socket with `IPV6_V6ONLY` for an IPv4-mapped address, keep the
    /// answer of the kernel.
    #[test]
    fn only_a_new_tcp_socket_goes_to_the_host() -> TestResult {
        use std::os::fd::AsFd as _;
        let Some(fresh) = new_socket(libc::AF_INET) else {
            return Ok(());
        };
        let facts = SocketFacts::of(fresh.as_fd(), libc::AF_INET).ok_or("no facts")?;
        assert!(facts.tcp && facts.fresh && !facts.v6only, "{facts:?}");
        assert!(facts.takes(SocketAddr::from(([127, 0, 0, 1], 5432))));

        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return Ok(());
        };
        let connected = TcpStream::connect(listener.local_addr()?)?;
        let facts = SocketFacts::of(connected.as_fd(), libc::AF_INET).ok_or("no facts")?;
        assert!(!facts.fresh, "{facts:?}");
        assert!(!facts.takes(SocketAddr::from(([127, 0, 0, 1], 5432))));

        let Some(v6) = new_socket(libc::AF_INET6) else {
            return Ok(());
        };
        let one: libc::c_int = 1;
        // SAFETY: setsockopt(2) reads one `c_int` that lives until it returns.
        let ret = unsafe {
            libc::setsockopt(
                v6.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                std::ptr::from_ref(&one).cast::<libc::c_void>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())?,
            )
        };
        assert_eq!(ret, 0);
        let facts = SocketFacts::of(v6.as_fd(), libc::AF_INET6).ok_or("no facts")?;
        assert!(facts.v6only, "{facts:?}");
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5432".parse()?;
        assert!(!facts.takes(mapped));
        assert!(facts.takes("[::1]:5432".parse()?));
        Ok(())
    }

    /// The supervisor connects on the host and the socket carries data.
    #[test]
    fn a_blocking_connection_to_the_host_completes() -> TestResult {
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return Ok(());
        };
        let addr = listener.local_addr()?;
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"HELLO");
            }
        });
        let conn = match connect_on_host(addr, FdFlags::default(), Duration::from_secs(5)) {
            Ok(conn) => conn,
            Err(e) => return Err(format!("connect failed with {e}").into()),
        };
        assert!(!conn.in_progress);
        let mut stream = TcpStream::from(conn.fd);
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf)?;
        assert_eq!(&buf, b"HELLO");
        server.join().map_err(|_| "the server thread failed")?;
        Ok(())
    }

    /// A non-blocking socket gets the socket at once and keeps
    /// `O_NONBLOCK`.
    #[test]
    fn a_non_blocking_connection_keeps_its_flag() -> TestResult {
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return Ok(());
        };
        let addr = listener.local_addr()?;
        let flags = FdFlags {
            nonblock: true,
            cloexec: true,
        };
        let conn = match connect_on_host(addr, flags, Duration::from_secs(5)) {
            Ok(conn) => conn,
            Err(e) => return Err(format!("connect failed with {e}").into()),
        };
        // SAFETY: fcntl(2) reads the flags of an open descriptor.
        let status = unsafe { libc::fcntl(conn.fd.as_raw_fd(), libc::F_GETFL) };
        assert!(status & libc::O_NONBLOCK != 0, "{status:o}");
        drop(listener);
        Ok(())
    }

    /// A port with no server gives the error of the kernel.
    #[test]
    fn a_closed_port_is_refused() -> TestResult {
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            return Ok(());
        };
        let addr = listener.local_addr()?;
        drop(listener);
        let result = connect_on_host(addr, FdFlags::default(), Duration::from_secs(5));
        assert_eq!(result.err(), Some(libc::ECONNREFUSED));
        Ok(())
    }
}
