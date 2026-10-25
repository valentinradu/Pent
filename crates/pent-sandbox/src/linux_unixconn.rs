//! The control of `connect(2)` to a Unix socket on Linux.
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
//! time-of-use race). Thus the supervisor **makes the connection itself**:
//!
//! 1. It reads the address one time from the memory of the child.
//! 2. It compares the path with the allowlist
//!    ([`crate::SandboxConfig::unix_sockets`]). The compare uses the
//!    canonical form of both paths. A path that does not canonicalize is
//!    refused.
//! 3. For a path on the list it makes its own socket of the same kind,
//!    connects it, and gives it to the child with
//!    `SECCOMP_IOCTL_NOTIF_ADDFD` at the descriptor number of the child.
//!    The child continues with a connected socket and sees the value 0.
//! 4. For every other `AF_UNIX` address the child gets `EACCES`.
//!
//! The supervisor never answers `CONTINUE` after it reads an `AF_UNIX`
//! address, so the race above cannot change the result.
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
//! # What stays open
//!
//! - The supervisor answers `CONTINUE` for an address family that is not
//!   `AF_UNIX`, so the family itself is a time-of-check value. A program
//!   with two threads can show `AF_INET` to the supervisor and `AF_UNIX` to
//!   the kernel. The filter removes this way when the allowlist is empty:
//!   it then refuses `socket(AF_UNIX, ...)` in the BPF program, where the
//!   domain is a register and no memory can change.
//! - `sendto(2)` on a datagram socket carries an address too, and the
//!   supervisor does not trap it. The refusal of `socket(AF_UNIX, ...)`
//!   covers this way as well, again only when the allowlist is empty.
//! - A descriptor that the child inherited (its standard streams) can be a
//!   Unix socket. The control covers `connect(2)` on it, not the data that
//!   the child already can send on it.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(test)]
use pent_profile::Outcome;

/// The longest time that the supervisor waits for one connection. A
/// notification holds the thread of the child and the supervisor loop, so
/// the wait must end.
pub(crate) const CONNECT_LIMIT: Duration = Duration::from_secs(5);

/// The time between two tries of a connection that the server cannot take
/// yet (its queue is full).
const RETRY_PAUSE: Duration = Duration::from_millis(2);

/// The address of a `connect(2)` to a Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnixAddr {
    /// A path in the filesystem.
    Path(PathBuf),
    /// An abstract name: the first byte of `sun_path` is zero. The network
    /// namespace of the sandbox already separates these names from the
    /// host, and the supervisor refuses them.
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

/// The Unix socket paths that the child can reach.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnixPolicy {
    /// The canonical form of each path of the allowlist.
    allowed: Vec<PathBuf>,
}

impl UnixPolicy {
    /// Build the policy from the paths of the profile. A path that does not
    /// canonicalize does not enter the list: no path can match it.
    pub(crate) fn new(paths: &[PathBuf]) -> Self {
        let mut allowed: Vec<PathBuf> = paths
            .iter()
            .filter_map(|p| std::fs::canonicalize(p).ok())
            .collect();
        allowed.sort();
        allowed.dedup();
        Self { allowed }
    }

    /// True if the allowlist has no path. The child then reaches no Unix
    /// socket, and the filter refuses `socket(AF_UNIX, ...)` already.
    pub(crate) fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// The canonical path to connect to, if `addr` is on the allowlist.
    ///
    /// The compare uses the canonical form of both paths, so a symbolic
    /// link to a permitted socket also matches. A path that does not
    /// canonicalize is not on the list. The supervisor connects to the
    /// canonical path, so a symbolic link cannot change the target between
    /// the compare and the connection.
    pub(crate) fn allowed_target(&self, addr: &UnixAddr) -> Option<PathBuf> {
        let UnixAddr::Path(path) = addr else {
            return None;
        };
        let real = std::fs::canonicalize(path).ok()?;
        self.allowed.iter().find(|a| **a == real).cloned()
    }

    /// True if `addr` is on the allowlist.
    #[cfg(test)]
    pub(crate) fn permits(&self, addr: &UnixAddr) -> bool {
        self.allowed_target(addr).is_some()
    }

    /// The outcome of a `connect(2)` to `addr` for the recorded event.
    #[cfg(test)]
    pub(crate) fn outcome(&self, addr: &UnixAddr) -> Outcome {
        if self.permits(addr) {
            Outcome::Allowed
        } else {
            Outcome::Denied
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
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
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
    addr: &libc::sockaddr_un,
    len: libc::socklen_t,
    nonblock: bool,
    limit: Duration,
) -> Result<(), i32> {
    let deadline = Instant::now() + limit;
    loop {
        // SAFETY: `addr` is a valid `sockaddr_un` of `len` bytes and `sock`
        // is an open Unix socket.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::connect(
                sock.as_raw_fd(),
                std::ptr::from_ref(addr).cast::<libc::sockaddr>(),
                len,
            )
        };
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
    path: &Path,
    flags: FdFlags,
    limit: Duration,
) -> Result<OwnedFd, i32> {
    // Without the kind of the socket of the child, a new socket would have
    // the wrong semantics. Refuse instead of guessing.
    let kind = socket_kind(tid, fd).ok_or(libc::EACCES)?;
    let (addr, len) = sockaddr_un(path)?;
    let sock = make_socket(kind)?;
    connect_once(&sock, &addr, len, flags.nonblock, limit)?;
    set_nonblock(&sock, flags.nonblock)?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixDatagram, UnixListener};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn fdinfo_flags_are_octal() {
        assert_eq!(parse_fdinfo_flags("pos:\t0\nflags:\t02000002\n"), Some(0o2000002));
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
        assert_eq!(
            socket_kind(tid, dgram.as_raw_fd()),
            Some(libc::SOCK_DGRAM)
        );
        Ok(())
    }

    #[test]
    fn the_policy_compares_canonical_paths() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = std::fs::canonicalize(tmp.path())?;
        let real = dir.join("real.sock");
        let _listener = UnixListener::bind(&real)?;
        std::os::unix::fs::symlink(&real, dir.join("link.sock"))?;
        let policy = UnixPolicy::new(std::slice::from_ref(&real));
        assert!(!policy.is_empty());
        assert!(policy.permits(&UnixAddr::Path(real.clone())));
        assert!(policy.permits(&UnixAddr::Path(dir.join("link.sock"))));
        assert!(!policy.permits(&UnixAddr::Path(dir.join("other.sock"))));
        assert!(!policy.permits(&UnixAddr::Abstract("name".into())));
        assert_eq!(policy.outcome(&UnixAddr::Path(real)), Outcome::Allowed);
        assert_eq!(
            policy.outcome(&UnixAddr::Abstract("n".into())),
            Outcome::Denied
        );
        assert!(UnixPolicy::new(&[dir.join("missing.sock")]).is_empty());
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
