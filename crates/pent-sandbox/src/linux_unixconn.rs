//! The control of `connect(2)` and of an addressed send to a Unix socket
//! on Linux.
//!
//! Landlock up to ABI v6 does not control a connection to a Unix socket
//! that has a path, and the kernel needs no file right to walk through a
//! directory. The private `/tmp` and `/run` of the sandbox remove the
//! sockets that they cover, but a socket in another directory stays
//! reachable (finding LS-1 in `docs/security/linux-sandbox.md`).
//!
//! A check in the supervisor that answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
//! does not close the hole: the kernel reads the address again after the
//! answer, so another thread of the child can change it (a time-of-check to
//! time-of-use race). Thus the supervisor **makes the call itself**:
//!
//! 1. It reads the address one time from the memory of the child.
//! 2. It compares the path with the allowlist
//!    ([`crate::SandboxConfig::unix_sockets`]). The compare uses the
//!    canonical form of both paths. A path that does not canonicalize is
//!    refused.
//! 3. For a path on the list it makes its own socket of the same kind.
//!    `connect(2)` gives that socket to the child with
//!    `SECCOMP_IOCTL_NOTIF_ADDFD` at the descriptor number of the child,
//!    and the child sees the value 0. A send writes the payload of the
//!    child on that socket and gives the byte count back.
//! 4. For every other `AF_UNIX` path the child gets `EACCES`.
//!
//! The supervisor never answers `CONTINUE` after it reads an `AF_UNIX`
//! path, so the race above cannot change the result.
//!
//! # The four calls
//!
//! A datagram socket reaches a path with no `connect(2)`, so the control
//! covers each call that carries an address. The supervisor has two
//! answers for a permitted path — it performs the call, or it refuses it —
//! and never a third, because `CONTINUE` would let the kernel read the
//! address a second time.
//!
//! | Call | A path on the list | Why |
//! |------|--------------------|-----|
//! | `connect(2)` | performed | The supervisor connects its own socket and gives it to the child, so the child keeps a working connection. |
//! | `sendto(2)` | performed | One message with one address. The supervisor copies the payload and sends it. |
//! | `sendmsg(2)` | performed | One message too. The supervisor reads the payload from the `iovec` array of the message. A message with ancillary data gets `EOPNOTSUPP`: the supervisor cannot pass the descriptors or the credentials of the child. |
//! | `sendmmsg(2)` | refused with `EACCES` | One call carries several messages, and a partial failure has no clean form. A program that must reach a named socket uses `sendto(2)`, `sendmsg(2)`, or a `connect(2)` and then a send with no address. |
//!
//! A call with no address (a connected socket) and a call with an address
//! of another family keep the behaviour that they have without the
//! control: the kernel runs them. The filter tests the address argument of
//! `sendto(2)` in the BPF program, so a `send(2)` costs no notification.
//!
//! # The abstract names
//!
//! An abstract name (the first byte of `sun_path` is zero) belongs to the
//! network namespace of the socket, not to the filesystem. With its own
//! network namespace the child reaches only the abstract names of the
//! sandbox, so the policy permits them ([`AbstractNames::Private`]) and
//! the kernel runs the call. With `--network unrestricted` the child shares
//! the names of the host, so the policy refuses each abstract address
//! ([`AbstractNames::Shared`]).
//!
//! # What the new descriptor cannot keep
//!
//! The socket of the child goes away and the socket of the supervisor takes
//! its number, so a few properties of the original socket do not survive:
//!
//! - `SO_PEERCRED` on the other side names pent, not the child. The user
//!   and the group are the same; the process identifier is not.
//! - Socket options and a `bind(2)` that the child made before the
//!   `connect(2)` are lost. A datagram client that bound its own path gets
//!   no answer.
//! - A blocking `connect(2)` in the supervisor stops after
//!   [`CONNECT_LIMIT`] and gives `ETIMEDOUT`, where the kernel would wait.
//!   The limit also stops one notification from holding the supervisor
//!   forever.
//! - A refused call gives `EACCES`, also for a path that does not exist,
//!   where the kernel would give `ENOENT`.
//!
//! A non-blocking socket keeps its timing: the supervisor connects without
//! blocking and gives `EAGAIN` back, as the kernel does when the queue of
//! the server is full. The new descriptor keeps `O_NONBLOCK` and
//! `FD_CLOEXEC` of the descriptor of the child.
//!
//! # What a performed send cannot keep
//!
//! The supervisor sends the payload from a socket of its own, so the
//! socket of the child keeps its state and only the message changes hands:
//!
//! - The sender address of the message is the socket of the supervisor,
//!   which has no name. An answer of the server reaches nobody. A datagram
//!   protocol that waits for an answer does not work; a notification
//!   protocol (`NOTIFY_SOCKET`, the log socket of the system) does.
//! - `SO_PASSCRED` on the other side names pent, not the child.
//! - A payload longer than [`SEND_PAYLOAD_LIMIT`] gets `EMSGSIZE`.
//!
//! # What stays open
//!
//! - The supervisor answers `CONTINUE` for an address family that is not
//!   `AF_UNIX`, so the family itself is a time-of-check value. A program
//!   with two threads can show `AF_INET` to the supervisor and `AF_UNIX` to
//!   the kernel.
//! - A descriptor that the child inherited (its standard streams) can be a
//!   Unix socket. The control covers `connect(2)` and an addressed send on
//!   it, not the data that the child already can send on a connected
//!   socket.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pent_profile::Outcome;

/// The longest time that the supervisor waits for one connection. A
/// notification holds the thread of the child and the supervisor loop, so
/// the wait must end.
pub(crate) const CONNECT_LIMIT: Duration = Duration::from_secs(5);

/// The longest payload that the supervisor sends for the child. The
/// kernel takes at most the send buffer of the socket for one datagram,
/// which is of the same order. A longer payload gets `EMSGSIZE`.
pub(crate) const SEND_PAYLOAD_LIMIT: usize = 256 * 1024;

/// The time between two tries of a connection that the server cannot take
/// yet (its queue is full).
const RETRY_PAUSE: Duration = Duration::from_millis(2);

/// The address of a `connect(2)` to a Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnixAddr {
    /// A path in the filesystem.
    Path(PathBuf),
    /// An abstract name: the first byte of `sun_path` is zero. The name
    /// belongs to the network namespace of the socket.
    Abstract(String),
}

impl UnixAddr {
    /// The form of the address for a [`pent_profile::WatchEvent`]: the path,
    /// or `@name` for an abstract name.
    pub(crate) fn display(&self) -> String {
        match self {
            Self::Path(p) => p.to_string_lossy().into_owned(),
            Self::Abstract(n) => format!("@{n}"),
        }
    }
}

/// Where the abstract Unix names of the child live.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum AbstractNames {
    /// The child has its own network namespace, so its abstract names are
    /// separate from the names of the host. The policy permits an abstract
    /// address.
    #[default]
    Private,
    /// The child uses the network namespace of the host
    /// (`--network unrestricted`), so an abstract name of a host process is
    /// in reach. The policy refuses an abstract address.
    Shared,
}

/// What the supervisor does with one `AF_UNIX` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnixDecision {
    /// The supervisor makes the call itself, to this canonical path.
    Perform(PathBuf),
    /// The supervisor makes the call on the socket of the child itself.
    /// Only an abstract address of a child with its own network
    /// namespace gets this answer: the name belongs to the network
    /// namespace of that socket, which a socket of the supervisor does
    /// not reach, and it is out of reach of the host.
    Child,
    /// The child gets `EACCES`.
    Refuse,
}

impl UnixDecision {
    /// The outcome of the decision for the recorded event.
    pub(crate) const fn outcome(&self) -> Outcome {
        match self {
            Self::Perform(_) | Self::Child => Outcome::Allowed,
            Self::Refuse => Outcome::Denied,
        }
    }
}

/// The Unix socket addresses that the child can reach.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnixPolicy {
    /// The canonical form of each path of the allowlist.
    allowed: Vec<PathBuf>,
    /// Where the abstract names of the child live.
    abstract_names: AbstractNames,
}

impl UnixPolicy {
    /// Build the policy from the paths of the profile. A path that does not
    /// canonicalize does not enter the list: no path can match it.
    /// `abstract_names` says whether the child has its own network
    /// namespace.
    pub(crate) fn new(paths: &[PathBuf], abstract_names: AbstractNames) -> Self {
        let mut allowed: Vec<PathBuf> = paths
            .iter()
            .filter_map(|p| std::fs::canonicalize(p).ok())
            .collect();
        allowed.sort();
        allowed.dedup();
        Self {
            allowed,
            abstract_names,
        }
    }

    /// What the supervisor does with the address `addr`.
    ///
    /// The compare uses the canonical form of both paths, so a symbolic
    /// link to a permitted socket also matches. A path that does not
    /// canonicalize is not on the list. The supervisor uses the canonical
    /// path, so a symbolic link cannot change the target between the
    /// compare and the call.
    pub(crate) fn decide(&self, addr: &UnixAddr) -> UnixDecision {
        let path = match addr {
            UnixAddr::Abstract(_) => {
                return match self.abstract_names {
                    AbstractNames::Private => UnixDecision::Child,
                    AbstractNames::Shared => UnixDecision::Refuse,
                }
            }
            UnixAddr::Path(path) => path,
        };
        let Ok(real) = std::fs::canonicalize(path) else {
            return UnixDecision::Refuse;
        };
        self.allowed
            .iter()
            .find(|a| **a == real)
            .map_or(UnixDecision::Refuse, |a| UnixDecision::Perform(a.clone()))
    }

    /// The decision for an address in a `sendmmsg(2)`.
    ///
    /// One `sendmmsg(2)` carries several messages, and the supervisor does
    /// not perform it (see the module documentation), so a path address is
    /// refused also when the profile names it.
    pub(crate) fn decide_many(&self, addr: &UnixAddr) -> UnixDecision {
        match self.decide(addr) {
            UnixDecision::Child => UnixDecision::Child,
            UnixDecision::Perform(_) | UnixDecision::Refuse => UnixDecision::Refuse,
        }
    }
}

/// What the supervisor does with a `connect(2)` to a Unix socket.
pub(crate) enum UnixControl {
    /// `pent run`: the supervisor makes each permitted connection itself
    /// and refuses every other address.
    Enforce(UnixPolicy),
    /// `pent watch` and `--no-sandbox`: the call runs, and the event holds
    /// the decision that `pent run` would make.
    Observe(UnixPolicy),
}

impl UnixControl {
    /// The policy of this control.
    pub(crate) fn policy(&self) -> &UnixPolicy {
        match self {
            Self::Enforce(p) | Self::Observe(p) => p,
        }
    }

    /// True if the supervisor enforces the allowlist.
    pub(crate) fn enforces(&self) -> bool {
        matches!(self, Self::Enforce(_))
    }
}

/// The flags of the socket descriptor of the child that the new descriptor
/// must keep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FdFlags {
    /// The descriptor has `O_NONBLOCK`.
    pub(crate) nonblock: bool,
    /// The descriptor has `FD_CLOEXEC`.
    pub(crate) cloexec: bool,
}

/// Read the flags of the descriptor `fd` of the process `tid` from
/// `/proc/<tid>/fdinfo/<fd>`. The `flags` line holds the status flags and
/// `O_CLOEXEC` when the descriptor is close-on-exec.
pub(crate) fn fd_flags(tid: u32, fd: RawFd) -> FdFlags {
    let text = std::fs::read_to_string(format!("/proc/{tid}/fdinfo/{fd}")).unwrap_or_default();
    let flags = parse_fdinfo_flags(&text).unwrap_or(0);
    FdFlags {
        nonblock: flags & libc::O_NONBLOCK != 0,
        cloexec: flags & libc::O_CLOEXEC != 0,
    }
}

/// Return the `flags` field of the text of `/proc/<pid>/fdinfo/<fd>`. The
/// value is octal.
fn parse_fdinfo_flags(text: &str) -> Option<libc::c_int> {
    let value = text
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))?
        .trim()
        .trim_start_matches('0');
    if value.is_empty() {
        return Some(0);
    }
    libc::c_int::from_str_radix(value, 8).ok()
}

/// The socket of the child that a trapped call names.
///
/// The supervisor takes a copy of the descriptor with `pidfd_getfd(2)`
/// and reads the domain and the type of the socket from it. Both are
/// properties of the socket, which no thread of the child can change,
/// unlike the family in the `sockaddr` (finding CT-1 in
/// `docs/security/containment.md`).
pub(crate) struct ChildSocket {
    /// The copy of the descriptor of the child. The two descriptors name
    /// the same socket, so a call on this one changes the socket of the
    /// child.
    fd: OwnedFd,
    /// `SO_DOMAIN`: the address family of the socket.
    domain: libc::c_int,
    /// `SO_TYPE`: `SOCK_STREAM`, `SOCK_DGRAM` or `SOCK_SEQPACKET`.
    kind: libc::c_int,
}

impl ChildSocket {
    /// True when the socket belongs to the `AF_UNIX` family.
    pub(crate) fn is_unix(&self) -> bool {
        self.domain == libc::AF_UNIX
    }

    /// True when the kernel uses the address of a send on this socket.
    ///
    /// Only a datagram socket does. A stream socket refuses a send that
    /// carries an address (`EISCONN` or `ENOTCONN`), and a sequential
    /// packet socket drops the address and sends to its peer. Thus a send
    /// on either of them cannot reach another socket, whatever another
    /// thread writes in the address.
    pub(crate) fn send_uses_the_address(&self) -> bool {
        self.kind == libc::SOCK_DGRAM
    }

    /// The type of the socket.
    pub(crate) fn kind(&self) -> libc::c_int {
        self.kind
    }
}

/// Take a copy of the socket `fd` of the process `pid` and read its
/// domain and its type.
///
/// Returns `None` when the copy fails (the task died, or the kernel has
/// no `pidfd_getfd(2)`) or when the descriptor is not a socket.
pub(crate) fn child_socket(pid: u32, fd: RawFd) -> Option<ChildSocket> {
    let pidfd = crate::linux_fdpass::open_pidfd(pid).ok()?;
    let fd = crate::linux_fdpass::take_remote_fd(&pidfd, fd).ok()?;
    let domain = sock_opt(&fd, libc::SO_DOMAIN)?;
    let kind = sock_opt(&fd, libc::SO_TYPE)?;
    Some(ChildSocket { fd, domain, kind })
}

/// Read the integer socket option `name` at the level `SOL_SOCKET`.
fn sock_opt(sock: &OwnedFd, name: libc::c_int) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: the kernel writes one `c_int` into `value` and the length
    // into `len`; both live until the call returns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    (ret == 0).then_some(value)
}

/// True when the descriptor `fd` of the task `tid` is a Unix socket.
///
/// This is the answer for a kernel without `pidfd_getfd(2)`. It costs a
/// read of `/proc/<tid>/net/unix`, so [`child_socket`] comes first.
pub(crate) fn is_unix_socket(tid: u32, fd: RawFd) -> bool {
    socket_kind(tid, fd).is_some()
}

/// Return the kind of the Unix socket `fd` of the process `tid`
/// (`SOCK_STREAM`, `SOCK_DGRAM` or `SOCK_SEQPACKET`).
///
/// `getsockopt(SO_TYPE)` needs the descriptor, and a socket cannot be
/// opened again through `/proc/<tid>/fd/<fd>`. Thus the supervisor reads
/// the inode number of the socket from that symbolic link and finds the
/// line of the inode in `/proc/<tid>/net/unix`, which holds the type. The
/// file belongs to the network namespace of the child, so it stays short.
fn socket_kind(tid: u32, fd: RawFd) -> Option<libc::c_int> {
    let link = std::fs::read_link(format!("/proc/{tid}/fd/{fd}")).ok()?;
    let inode = parse_socket_inode(link.to_str()?)?;
    let table = std::fs::read_to_string(format!("/proc/{tid}/net/unix")).ok()?;
    parse_unix_table(&table, inode)
}

/// Return the inode number of the target of `/proc/<pid>/fd/<fd>` when the
/// descriptor is a socket (`socket:[12345]`).
fn parse_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Return the socket type of the line of `inode` in the text of
/// `/proc/<pid>/net/unix`. The columns are `Num RefCount Protocol Flags
/// Type St Inode [Path]`; `Type` is hexadecimal.
fn parse_unix_table(text: &str, inode: u64) -> Option<libc::c_int> {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(kind), Some(ino)) = (fields.get(4), fields.get(6)) else {
            continue;
        };
        if ino.parse::<u64>() != Ok(inode) {
            continue;
        }
        return libc::c_int::from_str_radix(kind, 16).ok();
    }
    None
}

/// Build a `sockaddr_un` for `path`.
///
/// Returns `ENAMETOOLONG` if the path does not fit in `sun_path`.
fn sockaddr_un(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t), i32> {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: a zeroed `sockaddr_un` is a valid, empty address.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    // The last byte stays zero: `sun_path` holds a NUL-terminated string.
    if bytes.len() >= addr.sun_path.len() {
        return Err(libc::ENAMETOOLONG);
    }
    // The cast is exact: AF_UNIX is 1.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        // The cast only changes the sign of a byte above 127.
        #[allow(clippy::cast_possible_wrap)]
        {
            *slot = *byte as libc::c_char;
        }
    }
    let len = std::mem::size_of::<libc::sockaddr_un>();
    let len = libc::socklen_t::try_from(len).map_err(|_| libc::EINVAL)?;
    Ok((addr, len))
}

/// The error number of the last failed system call.
fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Make a Unix socket of the kind `kind`, without blocking and
/// close-on-exec.
fn make_socket(kind: libc::c_int) -> Result<OwnedFd, i32> {
    // SAFETY: socket(2) with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: `fd` is a new, open descriptor that nothing else owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Set or clear `O_NONBLOCK` on `sock`.
fn set_nonblock(sock: &OwnedFd, want: bool) -> Result<(), i32> {
    // SAFETY: fcntl(2) reads the flags of an open descriptor.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let flags = unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(errno());
    }
    let next = if want {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: fcntl(2) with integer arguments on an open descriptor.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_SETFL, next) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Connect `sock` to `addr`. The socket has `O_NONBLOCK`, so the call
/// returns at once. `nonblock` tells whether the socket of the child also
/// has it: a blocking socket of the child gets a retry until `limit`, a
/// non-blocking socket gets `EAGAIN` back.
fn connect_once(
    sock: &OwnedFd,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    nonblock: bool,
    limit: Duration,
) -> Result<(), i32> {
    let deadline = Instant::now() + limit;
    loop {
        // SAFETY: `addr` points to `len` readable bytes of an address and
        // `sock` is an open socket.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::connect(sock.as_raw_fd(), addr, len) };
        if ret == 0 {
            return Ok(());
        }
        match errno() {
            libc::EINTR => {}
            // The queue of the server is full. The kernel gives the same
            // error to a non-blocking socket, and makes a blocking socket
            // wait.
            libc::EAGAIN | libc::EINPROGRESS if !nonblock => {
                if Instant::now() >= deadline {
                    return Err(libc::ETIMEDOUT);
                }
                std::thread::sleep(RETRY_PAUSE);
            }
            e => return Err(e),
        }
    }
}

/// Make a socket of the same kind as the socket `fd` of the process `tid`,
/// connect it to `path`, and return it.
///
/// # Errors
/// Returns the error number for the child: `EACCES` if the kind of the
/// socket of the child is not known, `ETIMEDOUT` if the server does not
/// take the connection within `limit`, or the error of `socket(2)` or
/// `connect(2)`.
pub(crate) fn connect_for_child(
    tid: u32,
    fd: RawFd,
    kind: Option<libc::c_int>,
    path: &Path,
    flags: FdFlags,
    limit: Duration,
) -> Result<OwnedFd, i32> {
    // Without the kind of the socket of the child, a new socket would have
    // the wrong semantics. Refuse instead of guessing.
    let kind = kind.or_else(|| socket_kind(tid, fd)).ok_or(libc::EACCES)?;
    let (addr, len) = sockaddr_un(path)?;
    let sock = make_socket(kind)?;
    connect_once(
        &sock,
        std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
        len,
        flags.nonblock,
        limit,
    )?;
    set_nonblock(&sock, flags.nonblock)?;
    Ok(sock)
}

/// Connect the socket of the child itself to the address `addr`, as the
/// child wrote it.
///
/// The supervisor uses this for an address that it must not hand to the
/// kernel through `CONTINUE` and that it cannot reach with a socket of
/// its own: an abstract name, which belongs to the network namespace of
/// the socket, and an address of another family, which includes the
/// `AF_UNSPEC` address that breaks the association of a datagram socket.
///
/// The call sets `O_NONBLOCK` on the socket of the child while it runs,
/// so that the wait ends at `limit`, and it puts the flag back after.
///
/// # Errors
/// Returns the error number for the child: the error of `connect(2)`, or
/// `ETIMEDOUT` when the server does not take the connection within
/// `limit`.
pub(crate) fn connect_child_socket(
    sock: &ChildSocket,
    addr: &[u8],
    flags: FdFlags,
    limit: Duration,
) -> Result<(), i32> {
    let len = libc::socklen_t::try_from(addr.len()).map_err(|_| libc::EINVAL)?;
    if !flags.nonblock {
        set_nonblock(&sock.fd, true)?;
    }
    let done = connect_once(
        &sock.fd,
        addr.as_ptr().cast::<libc::sockaddr>(),
        len,
        flags.nonblock,
        limit,
    );
    if !flags.nonblock {
        // The socket of the child keeps the flags that it had.
        set_nonblock(&sock.fd, false)?;
    }
    done
}

/// Send `payload` on the socket of the child itself, with no address.
///
/// The supervisor uses this for a send on a connected datagram socket of
/// the `AF_UNIX` family: the kernel would read the address of the message
/// again after a `CONTINUE`, and another thread could put one there.
///
/// # Errors
/// Returns the error number for the child: the error of `sendto(2)`, or
/// `ETIMEDOUT` when the peer does not take the message within `limit`.
pub(crate) fn send_on_child_socket(
    sock: &ChildSocket,
    payload: &[u8],
    flags: libc::c_int,
    fd_flags: FdFlags,
    limit: Duration,
) -> Result<usize, i32> {
    let nonblock = fd_flags.nonblock || flags & libc::MSG_DONTWAIT != 0;
    if !fd_flags.nonblock {
        set_nonblock(&sock.fd, true)?;
    }
    let done = send_once(
        &sock.fd,
        std::ptr::null(),
        0,
        payload,
        flags,
        nonblock,
        limit,
    );
    if !fd_flags.nonblock {
        // The socket of the child keeps the flags that it had.
        set_nonblock(&sock.fd, false)?;
    }
    done
}

/// Send `payload` to the address `addr` on the socket of the child
/// itself.
///
/// The supervisor uses this for an abstract name: the name belongs to the
/// network namespace of the socket, which only the socket of the child
/// reaches.
///
/// # Errors
/// Returns the error number for the child: the error of `sendto(2)`, or
/// `ETIMEDOUT` when the receiver does not take the message within
/// `limit`.
pub(crate) fn send_to_name_on_child_socket(
    sock: &ChildSocket,
    addr: &[u8],
    payload: &[u8],
    flags: libc::c_int,
    fd_flags: FdFlags,
    limit: Duration,
) -> Result<usize, i32> {
    let len = libc::socklen_t::try_from(addr.len()).map_err(|_| libc::EINVAL)?;
    let nonblock = fd_flags.nonblock || flags & libc::MSG_DONTWAIT != 0;
    if !fd_flags.nonblock {
        set_nonblock(&sock.fd, true)?;
    }
    let done = send_once(
        &sock.fd,
        addr.as_ptr().cast::<libc::sockaddr>(),
        len,
        payload,
        flags,
        nonblock,
        limit,
    );
    if !fd_flags.nonblock {
        // The socket of the child keeps the flags that it had.
        set_nonblock(&sock.fd, false)?;
    }
    done
}

/// Send `payload` to `path` from a socket of the same kind as the socket
/// `fd` of the process `tid`.
///
/// `flags` are the flags of the call of the child. The supervisor adds
/// `MSG_NOSIGNAL`: a closed socket must give an error, not a signal in
/// pent.
///
/// # Errors
/// Returns the error number for the child: `EACCES` if the kind of the
/// socket of the child is not known, `ETIMEDOUT` if the server does not
/// take the message within `limit`, or the error of `socket(2)` or
/// `sendto(2)`.
pub(crate) fn send_for_child(
    tid: u32,
    fd: RawFd,
    kind: Option<libc::c_int>,
    path: &Path,
    payload: &[u8],
    flags: libc::c_int,
    limit: Duration,
) -> Result<usize, i32> {
    // Without the kind of the socket of the child, a new socket would have
    // the wrong semantics. Refuse instead of guessing.
    let kind = kind.or_else(|| socket_kind(tid, fd)).ok_or(libc::EACCES)?;
    let (addr, len) = sockaddr_un(path)?;
    let sock = make_socket(kind)?;
    let nonblock = flags & libc::MSG_DONTWAIT != 0;
    send_once(
        &sock,
        std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
        len,
        payload,
        flags,
        nonblock,
        limit,
    )
}

/// Send `payload` on `sock`. The socket has `O_NONBLOCK`, so the call
/// returns at once. `nonblock` tells whether the call of the child also
/// asked for it: a blocking call gets a retry until `limit`, a
/// non-blocking call gets `EAGAIN` back.
fn send_once(
    sock: &OwnedFd,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    payload: &[u8],
    flags: libc::c_int,
    nonblock: bool,
    limit: Duration,
) -> Result<usize, i32> {
    let deadline = Instant::now() + limit;
    loop {
        // SAFETY: `payload` has `payload.len()` readable bytes, and `addr`
        // is either null with `len` 0 or an address of `len` bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sent = unsafe {
            libc::sendto(
                sock.as_raw_fd(),
                payload.as_ptr().cast::<libc::c_void>(),
                payload.len(),
                flags | libc::MSG_NOSIGNAL,
                addr,
                len,
            )
        };
        if sent >= 0 {
            return usize::try_from(sent).map_err(|_| libc::EIO);
        }
        match errno() {
            libc::EINTR => {}
            // The queue of the server is full. The kernel gives the same
            // error to a non-blocking call, and makes a blocking call
            // wait.
            libc::EAGAIN if !nonblock => {
                if Instant::now() >= deadline {
                    return Err(libc::ETIMEDOUT);
                }
                std::thread::sleep(RETRY_PAUSE);
            }
            e => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixDatagram, UnixListener};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn fdinfo_flags_are_octal() {
        assert_eq!(
            parse_fdinfo_flags("pos:\t0\nflags:\t02000002\n"),
            Some(0o2000002)
        );
        assert_eq!(parse_fdinfo_flags("flags:\t0\n"), Some(0));
        assert_eq!(parse_fdinfo_flags("pos:\t0\n"), None);
    }

    #[test]
    fn socket_inode_comes_from_the_link() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("/etc/passwd"), None);
        assert_eq!(parse_socket_inode("pipe:[7]"), None);
    }

    #[test]
    fn unix_table_gives_the_socket_type() {
        let text = "Num       RefCount Protocol Flags    Type St Inode Path\n\
                    ffff0000: 00000002 00000000 00010000 0001 01 4242 /run/a.sock\n\
                    ffff0001: 00000002 00000000 00000000 0002 01 4243\n";
        assert_eq!(parse_unix_table(text, 4242), Some(libc::SOCK_STREAM));
        assert_eq!(parse_unix_table(text, 4243), Some(libc::SOCK_DGRAM));
        assert_eq!(parse_unix_table(text, 9999), None);
    }

    #[test]
    fn the_kind_of_our_own_socket_is_correct() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("s");
        let listener = UnixListener::bind(&path)?;
        let tid = std::process::id();
        let kind = socket_kind(tid, listener.as_raw_fd());
        assert_eq!(kind, Some(libc::SOCK_STREAM), "{kind:?}");
        let dgram = UnixDatagram::unbound()?;
        assert_eq!(socket_kind(tid, dgram.as_raw_fd()), Some(libc::SOCK_DGRAM));
        Ok(())
    }

    #[test]
    fn the_policy_compares_canonical_paths() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = std::fs::canonicalize(tmp.path())?;
        let real = dir.join("real.sock");
        let _listener = UnixListener::bind(&real)?;
        std::os::unix::fs::symlink(&real, dir.join("link.sock"))?;
        let policy = UnixPolicy::new(std::slice::from_ref(&real), AbstractNames::Private);
        let perform = UnixDecision::Perform(real.clone());
        assert_eq!(policy.decide(&UnixAddr::Path(real.clone())), perform);
        assert_eq!(
            policy.decide(&UnixAddr::Path(dir.join("link.sock"))),
            perform
        );
        assert_eq!(
            policy.decide(&UnixAddr::Path(dir.join("other.sock"))),
            UnixDecision::Refuse
        );
        assert_eq!(perform.outcome(), Outcome::Allowed);
        assert_eq!(UnixDecision::Refuse.outcome(), Outcome::Denied);
        assert_eq!(UnixDecision::Child.outcome(), Outcome::Allowed);
        // A path that does not exist yet matches nothing.
        let pending = UnixPolicy::new(&[dir.join("missing.sock")], AbstractNames::Private);
        assert_eq!(
            pending.decide(&UnixAddr::Path(dir.join("missing.sock"))),
            UnixDecision::Refuse
        );
        Ok(())
    }

    /// An abstract name follows the network namespace of the child, not
    /// the allowlist of the paths.
    #[test]
    fn the_policy_permits_an_abstract_name_in_a_private_namespace() {
        let name = UnixAddr::Abstract("own".into());
        let private = UnixPolicy::new(&[], AbstractNames::Private);
        assert_eq!(private.decide(&name), UnixDecision::Child);
        let shared = UnixPolicy::new(&[], AbstractNames::Shared);
        assert_eq!(shared.decide(&name), UnixDecision::Refuse);
    }

    /// `sendmmsg(2)` carries several messages, so the supervisor refuses a
    /// path address, also one that the profile names. An abstract address
    /// keeps the answer of the policy.
    #[test]
    fn sendmmsg_refuses_each_path() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = std::fs::canonicalize(tmp.path())?;
        let real = dir.join("real.sock");
        let _listener = UnixListener::bind(&real)?;
        let policy = UnixPolicy::new(std::slice::from_ref(&real), AbstractNames::Private);
        assert_eq!(
            policy.decide_many(&UnixAddr::Path(real)),
            UnixDecision::Refuse
        );
        assert_eq!(
            policy.decide_many(&UnixAddr::Abstract("own".into())),
            UnixDecision::Child
        );
        Ok(())
    }

    /// The supervisor sends the payload of the child to a socket that the
    /// profile names, and gives the byte count back.
    #[test]
    fn the_supervisor_sends_a_datagram() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let path = std::fs::canonicalize(tmp.path())?.join("d.sock");
        let server = UnixDatagram::bind(&path)?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        // A datagram socket of this process stands for the socket of the
        // child: only its kind matters.
        let client = UnixDatagram::unbound()?;
        let sent = send_for_child(
            std::process::id(),
            client.as_raw_fd(),
            None,
            &path,
            b"HELLO",
            0,
            CONNECT_LIMIT,
        );
        assert_eq!(sent, Ok(5), "{sent:?}");
        let mut buf = [0u8; 8];
        let n = server.recv(&mut buf)?;
        assert_eq!(buf.get(..n), Some(b"HELLO".as_slice()));
        Ok(())
    }

    /// A send to a path with no socket gives the error of the kernel.
    #[test]
    fn a_send_to_a_missing_socket_fails() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let path = std::fs::canonicalize(tmp.path())?.join("none.sock");
        let client = UnixDatagram::unbound()?;
        let sent = send_for_child(
            std::process::id(),
            client.as_raw_fd(),
            None,
            &path,
            b"x",
            0,
            CONNECT_LIMIT,
        );
        assert_eq!(sent, Err(libc::ENOENT), "{sent:?}");
        Ok(())
    }

    #[test]
    fn the_supervisor_connects_a_stream_socket() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let path = std::fs::canonicalize(tmp.path())?.join("s");
        let listener = UnixListener::bind(&path)?;
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"HELLO");
            }
        });
        // A stream socket of this process stands for the socket of the
        // child: only its kind matters.
        let client = UnixListener::bind(tmp.path().join("client"))?;
        let flags = FdFlags::default();
        let fd = connect_for_child(
            std::process::id(),
            client.as_raw_fd(),
            None,
            &path,
            flags,
            CONNECT_LIMIT,
        );
        let fd = match fd {
            Ok(fd) => fd,
            Err(e) => return Err(format!("connect failed with {e}").into()),
        };
        let mut stream = std::os::unix::net::UnixStream::from(fd);
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf)?;
        assert_eq!(&buf, b"HELLO");
        server.join().map_err(|_| "the server thread failed")?;
        Ok(())
    }

    #[test]
    fn a_path_that_is_too_long_is_refused() {
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(200)));
        assert_eq!(sockaddr_un(&long).err(), Some(libc::ENAMETOOLONG));
    }

    #[test]
    fn the_address_has_a_display_form() {
        assert_eq!(UnixAddr::Path("/run/a".into()).display(), "/run/a");
        assert_eq!(UnixAddr::Abstract("bus".into()).display(), "@bus");
    }
}
