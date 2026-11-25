//! The FUSE areas and the graft helper (design, sections 5.4 and 5.5).
//!
//! Pent covers each area outside the base with its FUSE server. On an
//! answer "allow", the helper grafts the real subtree over the FUSE
//! directory, so each later access goes to the real filesystem.
//!
//! - **The areas.** In the `pre_exec` hook, after the other mounts, the
//!   child opens an `O_PATH` descriptor of each area (the source), mounts
//!   FUSE over it ([`mount_fuse`]), and opens the FUSE root (the target).
//!   It sends the three descriptors to pent, which serves the FUSE
//!   connection in a thread that starts before the spawn. The child then
//!   does one `stat` of each FUSE root (FU-8) before the program starts.
//! - **The helper** is the outer supervisor of the session: the stub of the
//!   PID namespace, or one more fork when the session has no PID
//!   namespace. It is in the user namespace and the mount namespace of the
//!   session, it keeps its capabilities there, and it never runs `exec`.
//!   It keeps no state: each request of pent carries the source and the
//!   target of its area with `SCM_RIGHTS`, and a relative path.
//! - **A graft** is `open_tree(OPEN_TREE_CLONE | AT_RECURSIVE)` of the real
//!   subtree, `mount_setattr(MOUNT_ATTR_RDONLY)` for a read grant, and
//!   `move_mount` over the FUSE directory. `AT_RECURSIVE` keeps each mount
//!   below the subtree, so a mask of pent inside it stays.
//! - **The program** runs in a nested user namespace, so it has no
//!   capability over the mounts of the session.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::thread::JoinHandle;

use thiserror::Error;

use crate::linux_fdpass::{self, MAX_FDS};
use crate::linux_fuse::{self, FuseServer};
use crate::SandboxError;

/// `OPEN_TREE_CLONE` of `open_tree(2)`.
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// `MOVE_MOUNT_F_EMPTY_PATH` of `move_mount(2)`: the source is the
/// descriptor itself.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x04;
/// `MOVE_MOUNT_T_EMPTY_PATH` of `move_mount(2)`: the target is the
/// descriptor itself.
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;
/// `MOUNT_ATTR_RDONLY` of `mount_setattr(2)`.
const MOUNT_ATTR_RDONLY: u64 = 1;

/// `struct mount_attr` of `mount_setattr(2)`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `struct open_how` of `openat2(2)`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// The longest relative path of a graft, in bytes.
const MAX_GRAFT_PATH: usize = 4096;

/// The access of a graft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraftAccess {
    /// The graft is read-only (`MOUNT_ATTR_RDONLY` on each mount in it).
    ReadOnly,
    /// The graft keeps the access of the real filesystem.
    ReadWrite,
}

impl GraftAccess {
    const fn byte(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::ReadWrite => 1,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::ReadOnly),
            1 => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

/// An error of a graft.
#[derive(Debug, Error)]
pub(crate) enum GraftError {
    /// The path is not relative, or it has an empty, `.` or `..` component.
    #[error("the path of a graft must be relative, with no `.` or `..`: {0}")]
    BadPath(PathBuf),
    /// No area has this number.
    #[error("no FUSE area has the number {0}")]
    NoArea(usize),
    /// The helper ended, so no graft is possible.
    #[error("the graft helper is gone")]
    HelperGone,
    /// The request or the reply did not go through.
    #[error("cannot reach the graft helper: {0}")]
    Channel(#[source] std::io::Error),
    /// The helper refused the graft, or a system call of the graft failed.
    #[error("the graft failed: {0}")]
    Failed(#[source] std::io::Error),
}

/// Return true if `rel` is a relative path for a graft: empty (the root of
/// the area), or components with no empty, `.` or `..` component and no
/// NUL byte. Async-signal-safe.
fn valid_relative(rel: &[u8]) -> bool {
    if rel.is_empty() {
        return true;
    }
    if rel.len() > MAX_GRAFT_PATH || rel.contains(&0) {
        return false;
    }
    rel.split(|b| *b == b'/')
        .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// One area that the FUSE server covers.
pub(crate) struct FuseArea {
    /// The path of the area.
    pub(crate) path: PathBuf,
    /// An `O_PATH` descriptor of the real directory, from the child.
    source: OwnedFd,
    /// An `O_PATH` descriptor of the FUSE root, from the child.
    target: OwnedFd,
    /// The server of the area. The session ends with the mount namespace.
    _server: FuseServer,
}

/// The FUSE areas of a session and the channel to its graft helper.
pub(crate) struct FileAreas {
    areas: Vec<FuseArea>,
    ctl: Mutex<OwnedFd>,
}

impl FileAreas {
    /// The areas, in the order of [`crate::SandboxConfig::file_areas`].
    pub(crate) fn areas(&self) -> &[FuseArea] {
        &self.areas
    }

    /// Graft `rel` of the area number `area` over its FUSE directory.
    ///
    /// # Errors
    /// Returns [`GraftError::BadPath`] or [`GraftError::NoArea`] for a bad
    /// request, [`GraftError::HelperGone`] when the session ended, and
    /// [`GraftError::Failed`] with the error of the helper.
    pub(crate) fn graft(
        &self,
        area: usize,
        rel: &Path,
        access: GraftAccess,
    ) -> Result<(), GraftError> {
        let bytes = rel.as_os_str().as_bytes();
        if !valid_relative(bytes) {
            return Err(GraftError::BadPath(rel.to_path_buf()));
        }
        let area = self.areas.get(area).ok_or(GraftError::NoArea(area))?;
        let mut msg = Vec::with_capacity(bytes.len().saturating_add(1));
        msg.push(access.byte());
        msg.extend_from_slice(bytes);
        // One request at a time: the reply carries no number.
        let ctl = self.ctl.lock().unwrap_or_else(PoisonError::into_inner);
        let fds = [area.source.as_raw_fd(), area.target.as_raw_fd()];
        // SAFETY: the socket and both descriptors are open.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        match unsafe { linux_fdpass::send_with_fds(ctl.as_raw_fd(), &msg, &fds) } {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => return Err(GraftError::HelperGone),
            Err(e) => return Err(GraftError::Channel(e)),
        }
        let mut reply = [0u8; 4];
        // SAFETY: the socket is open.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        match unsafe { linux_fdpass::read_message(ctl.as_raw_fd(), &mut reply) } {
            Ok(true) => {}
            Ok(false) => return Err(GraftError::HelperGone),
            Err(e) => return Err(GraftError::Channel(e)),
        }
        match i32::from_ne_bytes(reply) {
            0 => Ok(()),
            errno => Err(GraftError::Failed(std::io::Error::from_raw_os_error(errno))),
        }
    }
}

/// The parent side of the FUSE areas before and during the spawn.
pub(crate) struct FileAreasSetup {
    /// The ends of the child: the parent drops them after the spawn, so
    /// the receiver sees EOF if the child died before it sent the areas.
    child_fuse: OwnedFd,
    child_ctl: OwnedFd,
    ctl: OwnedFd,
    receiver: JoinHandle<Result<Vec<FuseArea>, SandboxError>>,
}

/// The data of the `pre_exec` hook for the FUSE areas.
pub(crate) struct FileAreasChild {
    /// The socket that carries the descriptors of each area to pent.
    fuse_sock: RawFd,
    /// The socket of the graft helper.
    pub(crate) ctl: RawFd,
    /// The path of each area.
    areas: Vec<CString>,
}

impl FileAreasSetup {
    /// Make the sockets and start the thread that receives and serves the
    /// areas. Returns the setup and the data of the `pre_exec` hook. The
    /// thread must run during the spawn: the child waits for the first
    /// `GETATTR` of each root before the program starts.
    ///
    /// # Errors
    /// Returns `SpawnFailed` if a socket pair or the thread fails, and
    /// `InvalidConfig` for a path with a NUL byte.
    pub(crate) fn new(areas: &[PathBuf]) -> Result<(Self, FileAreasChild), SandboxError> {
        let paths: Vec<CString> = areas
            .iter()
            .map(|p| {
                CString::new(p.as_os_str().as_bytes()).map_err(|_| {
                    SandboxError::InvalidConfig(format!("a FUSE area has a NUL byte: {p:?}"))
                })
            })
            .collect::<Result<_, _>>()?;
        let (fuse_parent, child_fuse) = linux_fdpass::seqpacket_pair()?;
        let (ctl, child_ctl) = linux_fdpass::seqpacket_pair()?;
        let owned: Vec<PathBuf> = areas.to_vec();
        let receiver = std::thread::Builder::new()
            .name("pent-fuse-areas".to_string())
            .spawn(move || receive_areas(&fuse_parent, owned))
            .map_err(SandboxError::SpawnFailed)?;
        let child = FileAreasChild {
            fuse_sock: child_fuse.as_raw_fd(),
            ctl: child_ctl.as_raw_fd(),
            areas: paths,
        };
        let setup = Self {
            child_fuse,
            child_ctl,
            ctl,
            receiver,
        };
        Ok((setup, child))
    }

    /// Finish after the spawn: drop the ends of the child and take the
    /// areas from the receiver.
    ///
    /// # Errors
    /// Returns the error of the receiver.
    pub(crate) fn finish(self) -> Result<FileAreas, SandboxError> {
        drop(self.child_fuse);
        drop(self.child_ctl);
        let areas = self.receiver.join().map_err(|_| {
            SandboxError::SpawnFailed(std::io::Error::other("the FUSE receiver panicked"))
        })??;
        Ok(FileAreas {
            areas,
            ctl: Mutex::new(self.ctl),
        })
    }
}

/// Receive the three descriptors of each area and serve its FUSE
/// connection.
fn receive_areas(sock: &OwnedFd, paths: Vec<PathBuf>) -> Result<Vec<FuseArea>, SandboxError> {
    let lost = |what: &str| SandboxError::SpawnFailed(std::io::Error::other(what.to_string()));
    let mut areas = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(fds) = linux_fdpass::recv_fds(sock).map_err(SandboxError::SpawnFailed)? else {
            return Err(lost("the child sent no FUSE area"));
        };
        let [dev, source, target]: [OwnedFd; 3] = fds
            .try_into()
            .map_err(|_| lost("a FUSE area needs three descriptors"))?;
        let root = source.try_clone().map_err(SandboxError::SpawnFailed)?;
        let server = linux_fuse::serve(dev, root)
            .map_err(|e| SandboxError::SpawnFailed(std::io::Error::other(e.to_string())))?;
        areas.push(FuseArea {
            path,
            source,
            target,
            _server: server,
        });
    }
    Ok(areas)
}

impl FileAreasChild {
    /// Cover each area with FUSE and send its descriptors to pent, then do
    /// the first `GETATTR` of each root. Runs in the `pre_exec` hook, in
    /// the user namespace and the mount namespace of the session.
    /// Async-signal-safe.
    ///
    /// # Errors
    /// Returns the OS error of the first step that fails.
    pub(crate) fn mount_all(&self) -> std::io::Result<()> {
        // SAFETY: getuid/getgid have no preconditions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let dir = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        for area in &self.areas {
            // SAFETY: `area` is NUL-terminated.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let source = unsafe { libc::open(area.as_ptr(), dir) };
            if source < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `area` names a directory (the open above).
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let dev = match unsafe { linux_fuse::mount_fuse(area, uid, gid) } {
                Ok(dev) => dev,
                Err(e) => {
                    close(source);
                    return Err(e);
                }
            };
            // The path now gives the root of the FUSE mount.
            // SAFETY: `area` is NUL-terminated.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let target = unsafe { libc::open(area.as_ptr(), dir) };
            let sent = if target < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                // SAFETY: the socket and the three descriptors are open.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { linux_fdpass::send_fds(self.fuse_sock, &[dev, source, target]) }
            };
            close(dev);
            close(source);
            if target >= 0 {
                close(target);
            }
            sent?;
        }
        for area in &self.areas {
            // The first `GETATTR` of the root (FU-8). Pent serves it in the
            // thread of `FileAreasSetup`.
            // SAFETY: all zero bytes is a valid `stat`.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
            // SAFETY: `area` is NUL-terminated, and `st` is writable.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::stat(area.as_ptr(), &raw mut st) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        close(self.fuse_sock);
        Ok(())
    }
}

/// Close `fd`. Async-signal-safe.
fn close(fd: RawFd) {
    // SAFETY: the caller owns `fd`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(fd) };
}

/// Serve the graft requests on `ctl` until the process `child` ends. Runs
/// in the helper, after `fork`, so it is async-signal-safe: it uses only
/// raw system calls on fixed buffers.
///
/// The helper becomes non-dumpable first, so that no process of the user
/// can read its memory or its descriptors through `ptrace` or `/proc`.
pub(crate) fn serve_grafts(ctl: RawFd, child: libc::pid_t) {
    // SAFETY: prctl(2) with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // SAFETY: pidfd_open(2) takes integers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) };
    let Ok(pidfd) = libc::c_int::try_from(pidfd) else {
        return;
    };
    if pidfd < 0 {
        // Without a pidfd the helper cannot see the end of the child, so
        // it serves nothing; each graft then fails with `HelperGone`.
        return;
    }
    let mut ctl_open = true;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if ctl_open { ctl } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a valid array of two entries.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let [child_end, request] = fds;
        if child_end.revents != 0 {
            break;
        }
        if request.revents & libc::POLLIN != 0 {
            if !serve_one(ctl) {
                ctl_open = false;
            }
        } else if request.revents != 0 {
            // Pent closed its end: no more requests.
            ctl_open = false;
        }
    }
    close(pidfd);
}

/// Read one request from `ctl`, do it, and write the reply. Returns false
/// when the channel is closed. Async-signal-safe.
fn serve_one(ctl: RawFd) -> bool {
    let mut buf = [0u8; MAX_GRAFT_PATH + 2];
    let mut fds = [-1; MAX_FDS];
    // SAFETY: `ctl` is an open socket.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (len, count) = match unsafe { linux_fdpass::recv_with_fds(ctl, &mut buf, &mut fds) } {
        Ok((0, _)) => return false,
        Ok(got) => got,
        Err(e) => return reply(ctl, e.raw_os_error().unwrap_or(libc::EPROTO)),
    };
    let result = match (buf.get(..len), fds.get(..count)) {
        (Some([access, path @ ..]), Some(&[source, target])) => {
            match GraftAccess::from_byte(*access) {
                Some(access) if valid_relative(path) => graft(source, target, path, access),
                _ => Err(libc::EINVAL),
            }
        }
        _ => Err(libc::EPROTO),
    };
    for fd in fds.iter().take(count) {
        close(*fd);
    }
    reply(ctl, result.err().unwrap_or(0))
}

/// Write the reply `errno` (0 for success). Returns false when the channel
/// is closed. Async-signal-safe.
fn reply(ctl: RawFd, errno: i32) -> bool {
    // SAFETY: `ctl` is an open socket.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { linux_fdpass::write_all(ctl, &errno.to_ne_bytes()) }.is_ok()
}

/// Open `rel` below `dir` with `O_PATH`, with no symbolic link and no step
/// out of `dir`. Async-signal-safe.
fn open_beneath(dir: RawFd, rel: &[u8]) -> Result<RawFd, i32> {
    let mut path = [0u8; MAX_GRAFT_PATH + 2];
    let text: &[u8] = if rel.is_empty() { b"." } else { rel };
    let Some(slot) = path.get_mut(..text.len()) else {
        return Err(libc::ENAMETOOLONG);
    };
    slot.copy_from_slice(text);
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path` is NUL-terminated (the buffer is longer than the
    // text), and `how` is a valid `open_how` of its own size.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    match libc::c_int::try_from(fd) {
        Ok(fd) if fd >= 0 => Ok(fd),
        _ => Err(errno()),
    }
}

/// The error number of the last system call. Async-signal-safe.
fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Graft `rel` of the real directory `source` over `rel` of the FUSE root
/// `target`. Async-signal-safe.
fn graft(source: RawFd, target: RawFd, rel: &[u8], access: GraftAccess) -> Result<(), i32> {
    let src = open_beneath(source, rel)?;
    // The lookup of the target goes through FUSE; pent answers it in
    // another thread.
    let dst = match open_beneath(target, rel) {
        Ok(fd) => fd,
        Err(e) => {
            close(src);
            return Err(e);
        }
    };
    let result = move_tree(src, dst, access);
    close(src);
    close(dst);
    result
}

/// Clone the tree at `src`, make it read-only for a read grant, and mount
/// it on `dst`. Async-signal-safe.
fn move_tree(src: RawFd, dst: RawFd, access: GraftAccess) -> Result<(), i32> {
    // `AT_RECURSIVE` keeps each mount below the subtree: a mask of pent in
    // it stays.
    let flags = OPEN_TREE_CLONE
        | libc::O_CLOEXEC as libc::c_uint
        | libc::AT_RECURSIVE as libc::c_uint
        | libc::AT_EMPTY_PATH as libc::c_uint;
    // SAFETY: the empty path is NUL-terminated; the rest are integers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let tree = unsafe { libc::syscall(libc::SYS_open_tree, src, c"".as_ptr(), flags) };
    let tree = match libc::c_int::try_from(tree) {
        Ok(fd) if fd >= 0 => fd,
        _ => return Err(errno()),
    };
    if access == GraftAccess::ReadOnly {
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        let flags = (libc::AT_EMPTY_PATH | libc::AT_RECURSIVE) as libc::c_uint;
        // SAFETY: the empty path is NUL-terminated, and `attr` is a valid
        // `mount_attr` of its own size.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                tree,
                c"".as_ptr(),
                flags,
                &raw const attr,
                std::mem::size_of::<MountAttr>(),
            )
        };
        if ret != 0 {
            let e = errno();
            close(tree);
            return Err(e);
        }
    }
    // SAFETY: both paths are empty and NUL-terminated; the rest are
    // integers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree,
            c"".as_ptr(),
            dst,
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    let result = if ret == 0 { Ok(()) } else { Err(errno()) };
    close(tree);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_graft_path_is_relative_with_no_dot_component() {
        for good in ["", "a", "a/b", ".cargo/registry", "...", "a..b"] {
            assert!(valid_relative(good.as_bytes()), "{good:?}");
        }
        for bad in [
            "/", "/a", "a/", "a//b", ".", "..", "a/../b", "a/.", "./a", "a\0b",
        ] {
            assert!(!valid_relative(bad.as_bytes()), "{bad:?}");
        }
        assert!(!valid_relative(&vec![b'a'; MAX_GRAFT_PATH + 1]));
    }

    #[test]
    fn the_access_byte_survives_a_round_trip() {
        for access in [GraftAccess::ReadOnly, GraftAccess::ReadWrite] {
            assert_eq!(GraftAccess::from_byte(access.byte()), Some(access));
        }
        assert_eq!(GraftAccess::from_byte(2), None);
    }

    // ── A graft during a run ───────────────────────────────────────────────

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Return true if this host can run a sandbox with a FUSE area.
    fn ready() -> bool {
        let reason = if crate::check_availability().is_err() {
            "no Landlock or no user namespaces"
        } else if !crate::linux_fuse::tests::fuse_available() {
            "no unprivileged FUSE mount in a user namespace"
        } else if crate::find_in_path("python3", &std::env::var("PATH").unwrap_or_default())
            .is_none()
        {
            "no python3 in PATH"
        } else {
            return true;
        };
        // The pipelines set the variable: there a skip is a defect.
        assert!(
            std::env::var_os("PENT_REQUIRE_ALL_TESTS").is_none(),
            "the test does not run, and PENT_REQUIRE_ALL_TESTS is set: {reason}"
        );
        eprintln!("skip: {reason}");
        false
    }

    /// Wait until `path` exists.
    fn wait_for(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !path.exists() {
            if std::time::Instant::now() > deadline {
                return Err(format!("{} did not appear", path.display()).into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(())
    }

    /// The process IDs (on the host) of each `sh -c` whose script contains
    /// `marker`, with the parent of each one.
    fn find_processes(marker: &str) -> Vec<(u32, u32)> {
        let mut found = Vec::new();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return found;
        };
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            // The program is `sh -c SCRIPT`; another process can hold the
            // marker in a longer command line.
            let text = String::from_utf8_lossy(&cmdline);
            if !text.starts_with("sh\0-c\0") || !text.contains(marker) {
                continue;
            }
            let ppid = std::fs::read_to_string(entry.path().join("stat"))
                .ok()
                .and_then(|stat| {
                    let after = stat.rsplit_once(')')?.1.to_string();
                    after.split_whitespace().nth(1)?.parse::<u32>().ok()
                });
            if let Some(ppid) = ppid {
                found.push((pid, ppid));
            }
        }
        found
    }

    fn user_ns(pid: u32) -> std::io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/ns/user"))
    }

    /// The program creates a file in the root of the second area, which no
    /// process has touched yet (FU-8), checks
    /// that its working directory is in FUSE, reads a file through FUSE,
    /// and waits for the grafts. Then it tries to remove a graft and the
    /// FUSE mount, and it writes in the read-write graft, in its read-only
    /// `.pent` and in the read-only graft. `umount2` gives its error number
    /// through `python3`.
    const SCRIPT: &str = r#"set -e
exec > "$T/out" 2>&1
: pent-graft-test-marker
: > "$B/new-in-root"
[ "$(stat -c %d .)" = "$(stat -c %d "$A")" ] && echo cwd-in-fuse
cat "$A/sub/file"
(echo x > "$A/sub/.pent/f0") 2>/dev/null && echo fuse-pent-writable || echo fuse-pent-readonly
: > "$T/ready"
i=0
while [ ! -e "$T/grafted" ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done
grep -c " $A/sub " /proc/self/mountinfo
grep -c " $A/other " /proc/self/mountinfo
python3 -I -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
for p in (os.environ["A"] + "/sub", os.environ["A"]):
    r = libc.umount2(p.encode(), 0)
    print(0 if r == 0 else ctypes.get_errno())
'
(echo x > "$A/sub/file2") 2>/dev/null && echo wrote || echo readonly
(echo x > "$A/sub/.pent/f") 2>/dev/null && echo pent-writable || echo pent-readonly
(echo x > "$A/other/file") 2>/dev/null && echo wrote || echo readonly
cat "$A/other/file"
ls /proc/self/fd | tr '\n' ' '
"#;

    #[test]
    fn a_graft_during_a_run_holds_and_the_program_cannot_remove_it() -> TestResult {
        if !ready() {
            return Ok(());
        }
        let tmp = tempfile::tempdir()?;
        let base = std::fs::canonicalize(tmp.path())?;
        let (ws, area, outer) = (base.join("ws"), base.join("area"), base.join("outer"));
        // The Landlock rule of the second area is on its parent. The
        // child opens each path of a rule, and an open of the area itself
        // would do the first `GETATTR` of its root (FU-8) in place of the
        // hook.
        let area2 = outer.join("area2");
        std::fs::create_dir_all(&area2)?;
        std::fs::create_dir_all(area.join("sub/.pent"))?;
        std::fs::create_dir_all(area.join("other"))?;
        std::fs::create_dir(&ws)?;
        std::fs::write(area.join("sub/file"), "real\n")?;
        std::fs::write(area.join("other/file"), "other\n")?;
        std::os::unix::fs::symlink("sub", area.join("link"))?;

        let mut env = crate::build_env(&[]);
        env.insert("T".to_string(), ws.to_string_lossy().into_owned());
        env.insert("A".to_string(), area.to_string_lossy().into_owned());
        env.insert("B".to_string(), area2.to_string_lossy().into_owned());
        // The working directory is in the area, and its `.pent` gets a
        // read-only mount in the session before FUSE covers the area.
        let mut config =
            crate::SandboxConfig::new(ws.clone(), crate::system_default_paths(), area.join("sub"))
                .with_env(env.clone())
                .with_network(crate::NetworkMode::LocalhostOnly);
        for dir in [&area, &outer] {
            config
                .paths
                .read_write
                .push(dir.to_string_lossy().into_owned());
        }
        config.file_areas = vec![area.clone(), area2.clone()];
        let args = vec!["-c".to_string(), SCRIPT.to_string()];
        let path_dirs = crate::resolve_path_directories();
        let spawned = crate::linux::spawn_linux(
            &config,
            "sh",
            &args,
            &env,
            &path_dirs,
            crate::linux::SpawnMode::Sandbox,
        )?;
        let mut child = spawned.child;
        let files = spawned.files.ok_or("the spawn gave no FUSE areas")?;
        let result = (|| -> TestResult {
            wait_for(&ws.join("ready"))?;
            let paths: Vec<&Path> = files.areas().iter().map(|a| a.path.as_path()).collect();
            assert_eq!(paths, [area.as_path(), area2.as_path()]);

            // The program is in a user namespace of its own, below the one
            // of the session: PID 1 of the sandbox, its parent, is in the
            // namespace of the session.
            let procs = find_processes("pent-graft-test-marker");
            let [(program, init)] = procs[..] else {
                return Err(format!("not one program in /proc: {procs:?}").into());
            };
            let (program_ns, init_ns) = (user_ns(program)?, user_ns(init)?);
            let own_ns = std::fs::read_link("/proc/self/ns/user")?;
            assert_ne!(
                program_ns, init_ns,
                "the program is not in a nested namespace"
            );
            assert_ne!(init_ns, own_ns, "the session has no user namespace");
            // The helper is the direct child, and it is not dumpable: a
            // process of the same user cannot look into it.
            match user_ns(child.id()) {
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
                Ok(ns) => return Err(format!("the helper is dumpable: {ns:?}").into()),
            }

            // A symbolic link and a step out of the area never become a
            // graft.
            match files.graft(0, Path::new("link"), GraftAccess::ReadOnly) {
                Err(GraftError::Failed(e)) => assert_eq!(e.raw_os_error(), Some(libc::ELOOP)),
                other => return Err(format!("a graft of a link: {other:?}").into()),
            }
            assert!(matches!(
                files.graft(0, Path::new("../ws"), GraftAccess::ReadOnly),
                Err(GraftError::BadPath(_))
            ));
            assert!(matches!(
                files.graft(2, Path::new("sub"), GraftAccess::ReadOnly),
                Err(GraftError::NoArea(2))
            ));
            files.graft(0, Path::new("sub"), GraftAccess::ReadWrite)?;
            files.graft(0, Path::new("other"), GraftAccess::ReadOnly)?;
            std::fs::write(ws.join("grafted"), "")?;
            Ok(())
        })();
        if result.is_err() {
            // Unblock the program, so that the wait below ends.
            let _ = std::fs::write(ws.join("grafted"), "");
            let _ = child.kill();
        }
        let status = child.wait()?;
        result?;
        let out = std::fs::read_to_string(ws.join("out"))?;
        assert!(status.success(), "the program failed: {status}\n{out}");
        // EPERM is 1: the program has no capability over the mounts.
        assert_eq!(
            out,
            // The last line: `ls` has only the standard three and its own
            // listing, so no socket of pent reached the program.
            "cwd-in-fuse\nreal\nfuse-pent-readonly\n1\n1\n1\n1\nwrote\npent-readonly\nreadonly\nother\n0 1 2 3 "
        );
        assert!(area2.join("new-in-root").exists());
        assert_eq!(std::fs::read_to_string(area.join("sub/file2"))?, "x\n");
        // The helper ended with the session.
        assert!(matches!(
            files.graft(0, Path::new("sub"), GraftAccess::ReadOnly),
            Err(GraftError::HelperGone)
        ));
        Ok(())
    }
}
