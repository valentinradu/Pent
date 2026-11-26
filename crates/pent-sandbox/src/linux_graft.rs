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
//!   It keeps no state: each request of pent carries the source of its
//!   area with `SCM_RIGHTS`, the path of the area and a relative path. The
//!   helper finds the target in its mount namespace, so pent holds no
//!   descriptor of a FUSE root: such a descriptor would keep the FUSE
//!   mount, and the session of its server, alive after the run.
//! - **A graft** is `open_tree(OPEN_TREE_CLONE | AT_RECURSIVE)` of the real
//!   subtree, `mount_setattr(MOUNT_ATTR_RDONLY)` for a read grant, and
//!   `move_mount` over the FUSE directory. `AT_RECURSIVE` keeps each mount
//!   below the subtree, so a mask of pent inside it stays.
//! - **The program** runs in a nested user namespace, so it has no
//!   capability over the mounts of the session.

use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
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
/// `MOUNT_ATTR_NOEXEC` of `mount_setattr(2)`.
const MOUNT_ATTR_NOEXEC: u64 = 8;

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

/// The most holes of one graft.
const MAX_HOLES: usize = 16;

/// The access of a graft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraftAccess {
    /// Read and list (`MOUNT_ATTR_RDONLY` and `MOUNT_ATTR_NOEXEC`).
    Read,
    /// Read, list and run programs (`MOUNT_ATTR_RDONLY`).
    ReadExec,
    /// Read, list and write (`MOUNT_ATTR_NOEXEC`).
    Write,
    /// Each access of the real filesystem.
    WriteExec,
}

impl GraftAccess {
    const fn byte(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::ReadExec => 1,
            Self::Write => 2,
            Self::WriteExec => 3,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Read),
            1 => Some(Self::ReadExec),
            2 => Some(Self::Write),
            3 => Some(Self::WriteExec),
            _ => None,
        }
    }

    /// The attributes of `mount_setattr(2)` that the graft gets.
    const fn attributes(self) -> u64 {
        match self {
            Self::Read => MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC,
            Self::ReadExec => MOUNT_ATTR_RDONLY,
            Self::Write => MOUNT_ATTR_NOEXEC,
            Self::WriteExec => 0,
        }
    }

    /// The access of a graft of `kind`, or `None` for a kind that a graft
    /// cannot give alone: a listing would also give the content.
    pub(crate) const fn of_kind(kind: pent_profile::FileKind) -> Option<Self> {
        match kind {
            pent_profile::FileKind::Read => Some(Self::Read),
            pent_profile::FileKind::Exec => Some(Self::ReadExec),
            pent_profile::FileKind::Write => Some(Self::Write),
            pent_profile::FileKind::List => None,
        }
    }

    /// Return true if this access gives each access of `other`.
    const fn covers(self, other: Self) -> bool {
        let (w, x) = self.parts();
        let (ow, ox) = other.parts();
        (w || !ow) && (x || !ox)
    }

    /// Write and exec.
    const fn parts(self) -> (bool, bool) {
        match self {
            Self::Read => (false, false),
            Self::ReadExec => (false, true),
            Self::Write => (true, false),
            Self::WriteExec => (true, true),
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
    /// The server of the area. The session ends with the mount namespace.
    _server: FuseServer,
}

/// The FUSE areas of a session and the channel to its graft helper.
pub(crate) struct FileAreas {
    areas: Vec<FuseArea>,
    grafter: Arc<Grafter>,
}

/// The channel to the graft helper of one sandbox.
pub(crate) struct Grafter {
    ctl: Mutex<OwnedFd>,
}

impl Grafter {
    /// Graft `rel` of the area `area`, whose real directory is `source`.
    /// Each path of `holes` (relative to `rel`) keeps its FUSE node.
    ///
    /// # Errors
    /// Returns [`GraftError::BadPath`] for a bad path,
    /// [`GraftError::HelperGone`] when the session ended, and
    /// [`GraftError::Failed`] with the error of the helper.
    pub(crate) fn graft(
        &self,
        source: BorrowedFd<'_>,
        area: &Path,
        rel: &Path,
        holes: &[PathBuf],
        access: GraftAccess,
    ) -> Result<(), GraftError> {
        let bytes = rel.as_os_str().as_bytes();
        let area_bytes = area.as_os_str().as_bytes();
        if !valid_relative(bytes) || !valid_area(area_bytes) || holes.len() > MAX_HOLES {
            return Err(GraftError::BadPath(rel.to_path_buf()));
        }
        let mut msg = Vec::with_capacity(
            bytes
                .len()
                .saturating_add(area_bytes.len())
                .saturating_add(2),
        );
        msg.push(access.byte());
        msg.extend_from_slice(area_bytes);
        msg.push(0);
        msg.extend_from_slice(bytes);
        for hole in holes {
            let hole_bytes = hole.as_os_str().as_bytes();
            if hole_bytes.is_empty() || !valid_relative(hole_bytes) {
                return Err(GraftError::BadPath(hole.clone()));
            }
            msg.push(0);
            msg.extend_from_slice(hole_bytes);
        }
        // One request at a time: the reply carries no number.
        let ctl = self.ctl.lock().unwrap_or_else(PoisonError::into_inner);
        let fds = [source.as_raw_fd()];
        // SAFETY: the socket and the descriptor are open.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        match unsafe { linux_fdpass::send_with_fds(ctl.as_raw_fd(), &msg, &fds) } {
            Ok(()) => {}
            Err(e) if peer_gone(&e) => return Err(GraftError::HelperGone),
            Err(e) => return Err(GraftError::Channel(e)),
        }
        let mut reply = [0u8; 4];
        // SAFETY: the socket is open.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        match unsafe { linux_fdpass::read_message(ctl.as_raw_fd(), &mut reply) } {
            Ok(true) => {}
            Ok(false) => return Err(GraftError::HelperGone),
            Err(e) if peer_gone(&e) => return Err(GraftError::HelperGone),
            Err(e) => return Err(GraftError::Channel(e)),
        }
        match i32::from_ne_bytes(reply) {
            0 => Ok(()),
            errno => Err(GraftError::Failed(std::io::Error::from_raw_os_error(errno))),
        }
    }
}

/// Return true if `e` says that the peer of the socket is gone.
fn peer_gone(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EPIPE | libc::ECONNRESET | libc::ENOTCONN)
    )
}

/// Return true if `area` is an absolute path with no empty, `.` or `..`
/// component and no NUL byte. Async-signal-safe.
fn valid_area(area: &[u8]) -> bool {
    match area.strip_prefix(b"/") {
        Some(rest) => !rest.is_empty() && valid_relative(rest),
        None => false,
    }
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
        let area = self.areas.get(area).ok_or(GraftError::NoArea(area))?;
        self.grafter
            .graft(area.source.as_fd(), &area.path, rel, &[], access)
    }
}

/// The policy of the FUSE areas of one sandbox.
pub(crate) struct FilePolicy {
    /// The grants, as Landlock rules without the rules of the FUSE roots.
    pub(crate) grants: Arc<crate::linux::AccessPolicy>,
    /// The decider of an access that the grants do not give.
    pub(crate) decider: Option<Arc<dyn crate::AccessDecider>>,
    /// The channel of the events of the run.
    pub(crate) events: Option<std::sync::mpsc::Sender<pent_profile::WatchEvent>>,
}

/// The parent side of the FUSE areas before and during the spawn.
pub(crate) struct FileAreasSetup {
    /// The ends of the child: the parent drops them after the spawn, so
    /// the receiver sees EOF if the child died before it sent the areas.
    child_fuse: OwnedFd,
    child_ctl: OwnedFd,
    grafter: Arc<Grafter>,
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
    pub(crate) fn new(
        areas: &[PathBuf],
        policy: Option<FilePolicy>,
    ) -> Result<(Self, FileAreasChild), SandboxError> {
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
        let grafter = Arc::new(Grafter {
            ctl: Mutex::new(ctl),
        });
        let owned: Vec<PathBuf> = areas.to_vec();
        let theirs = Arc::clone(&grafter);
        let receiver = std::thread::Builder::new()
            .name("pent-fuse-areas".to_string())
            .spawn(move || {
                let areas = receive_areas(&fuse_parent, owned, policy, &theirs);
                // The child waits for this byte before the program starts:
                // after the grafts of the grants, or after a failure. A
                // child that is gone gives an error here, which means
                // nothing.
                // SAFETY: the socket is open.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let _ = unsafe { linux_fdpass::write_all(fuse_parent.as_raw_fd(), b"g") };
                areas
            })
            .map_err(SandboxError::SpawnFailed)?;
        let child = FileAreasChild {
            fuse_sock: child_fuse.as_raw_fd(),
            ctl: child_ctl.as_raw_fd(),
            areas: paths,
        };
        let setup = Self {
            child_fuse,
            child_ctl,
            grafter,
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
            grafter: self.grafter,
        })
    }
}

/// Receive the two descriptors of each area and serve its FUSE
/// connection, with the policy of the grants when there is one. Then graft
/// the grants of the policy (see [`start_grafts`]).
fn receive_areas(
    sock: &OwnedFd,
    paths: Vec<PathBuf>,
    policy: Option<FilePolicy>,
    grafter: &Arc<Grafter>,
) -> Result<Vec<FuseArea>, SandboxError> {
    let lost = |what: &str| SandboxError::SpawnFailed(std::io::Error::other(what.to_string()));
    // The first message holds the `/proc` of the child.
    let Some(mut first) = linux_fdpass::recv_fds(sock).map_err(SandboxError::SpawnFailed)? else {
        return Err(lost("the child sent no /proc"));
    };
    let proc_dir = first.pop();
    let shared = policy.map(|p| {
        (
            p.grants,
            Arc::new(linux_fuse::FileContext {
                decider: p.decider,
                events: p.events,
                proc_dir,
                grafter: Arc::clone(grafter),
                grafted: Mutex::new(std::collections::HashSet::new()),
            }),
        )
    });
    let mut areas = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(fds) = linux_fdpass::recv_fds(sock).map_err(SandboxError::SpawnFailed)? else {
            return Err(lost("the child sent no FUSE area"));
        };
        let [dev, source]: [OwnedFd; 2] = fds
            .try_into()
            .map_err(|_| lost("a FUSE area needs two descriptors"))?;
        let root = source.try_clone().map_err(SandboxError::SpawnFailed)?;
        let area_policy = shared
            .as_ref()
            .map(|(grants, context)| linux_fuse::AreaPolicy {
                area: path.clone(),
                grants: Arc::clone(grants),
                private_above: crate::linux::private_roots()
                    .into_iter()
                    .filter(|p| path.starts_with(p) && path != *p)
                    .collect(),
                shared: Arc::clone(context),
            });
        let server = linux_fuse::serve(dev, root, area_policy)
            .map_err(|e| SandboxError::SpawnFailed(std::io::Error::other(e.to_string())))?;
        areas.push(FuseArea {
            path,
            source,
            _server: server,
        });
    }
    if let Some((grants, context)) = &shared {
        start_grafts(&areas, grants, context);
    }
    Ok(areas)
}

/// The holes `holes` (absolute paths) relative to the width `width`, or
/// `None` when a hole is not below the width.
pub(crate) fn relative_holes(width: &Path, holes: &[PathBuf]) -> Option<Vec<PathBuf>> {
    holes
        .iter()
        .map(|h| h.strip_prefix(width).ok().map(Path::to_path_buf))
        .collect()
}

/// The access of a graft that the Landlock rights `rights` of a grant
/// give, or `None` when a graft would give more: a graft needs the right to
/// read files and to list.
fn access_of_rights(rights: u64) -> Option<GraftAccess> {
    use crate::linux_landlock::access;
    if rights & access::READ != access::READ {
        return None;
    }
    let write = rights & access::WRITE_FILE != 0;
    let exec = rights & access::EXECUTE != 0;
    Some(match (write, exec) {
        (false, false) => GraftAccess::Read,
        (false, true) => GraftAccess::ReadExec,
        (true, false) => GraftAccess::Write,
        (true, true) => GraftAccess::WriteExec,
    })
}

/// The kind of a rule that a graft of `access` stands for.
const fn kind_of_access(access: GraftAccess) -> pent_profile::FileKind {
    match access {
        GraftAccess::Read => pent_profile::FileKind::Read,
        GraftAccess::ReadExec => pent_profile::FileKind::Exec,
        GraftAccess::Write | GraftAccess::WriteExec => pent_profile::FileKind::Write,
    }
}

/// Graft each grant that a graft can hold, before the program starts: a
/// directory in an area, with the right to read files and to list. The
/// decider must agree ([`crate::AccessDecider::graft_plan`]): a file of pent
/// or a deny rule inside the width keeps it with FUSE, and each sensitive
/// place inside it becomes a hole that FUSE keeps serving. Without a
/// decider there is no graft. A grant inside a graft that
/// gives it already needs no graft of its own. A failed graft only means
/// that FUSE serves the width.
fn start_grafts(
    areas: &[FuseArea],
    grants: &crate::linux::AccessPolicy,
    context: &linux_fuse::FileContext,
) {
    let Some(decider) = &context.decider else {
        return;
    };
    // The rights of each path: Landlock joins the rules of one path.
    let mut by_path: std::collections::BTreeMap<PathBuf, u64> = std::collections::BTreeMap::new();
    for (path, rights) in grants.rules() {
        *by_path.entry(path.clone()).or_default() |= *rights;
    }
    let mut done: Vec<(PathBuf, GraftAccess)> = Vec::new();
    for (path, rights) in by_path {
        let Some(area) = areas.iter().find(|a| path.starts_with(&a.path)) else {
            continue;
        };
        let Some(access) = access_of_rights(rights) else {
            continue;
        };
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        if done
            .iter()
            .any(|(p, a)| path.starts_with(p) && a.covers(access))
        {
            continue;
        }
        let Ok(base) = pent_profile::RulePath::new(path.clone()) else {
            continue;
        };
        let target = pent_profile::Target::File {
            kind: kind_of_access(access),
            width: pent_profile::PathWidth::Subtree(base),
        };
        let Some(holes) = decider
            .graft_plan(&target)
            .and_then(|holes| relative_holes(&path, &holes))
        else {
            continue;
        };
        let Ok(rel) = path.strip_prefix(&area.path) else {
            continue;
        };
        match context
            .grafter
            .graft(area.source.as_fd(), &area.path, rel, &holes, access)
        {
            Ok(()) => done.push((path, access)),
            Err(e) => tracing::debug!("no graft of {}: {e}", path.display()),
        }
    }
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
        // The `/proc` of the child first: pent reads the name of the
        // process of a request there.
        // SAFETY: a static NUL-terminated path.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let proc_dir = unsafe { libc::open(c"/proc".as_ptr(), dir) };
        if proc_dir < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the socket and the descriptor are open.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sent = unsafe { linux_fdpass::send_fds(self.fuse_sock, &[proc_dir]) };
        close(proc_dir);
        sent?;
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
            // SAFETY: the socket and the two descriptors are open.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let sent = unsafe { linux_fdpass::send_fds(self.fuse_sock, &[dev, source]) };
            close(dev);
            close(source);
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
        // Pent grafts the grants now, and then it sends one byte. The end of
        // the socket also lets the program start: FUSE serves each width.
        let mut go = [0u8; 1];
        // SAFETY: the socket is open; `go` has one writable byte.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { linux_fdpass::read_message(self.fuse_sock, &mut go) };
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
    // The access byte, the area, a NUL byte, the relative path, and a NUL
    // byte before each hole.
    let mut buf = [0u8; 4 * MAX_GRAFT_PATH + 3];
    let mut fds = [-1; MAX_FDS];
    // SAFETY: `ctl` is an open socket.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (len, count) = match unsafe { linux_fdpass::recv_with_fds(ctl, &mut buf, &mut fds) } {
        Ok((0, _)) => return false,
        Ok(got) => got,
        Err(e) => return reply(ctl, e.raw_os_error().unwrap_or(libc::EPROTO)),
    };
    let result = match (buf.get(..len), fds.get(..count)) {
        (Some([access, rest @ ..]), Some(&[source])) => {
            let mut parts = rest.splitn(3, |b| *b == 0);
            let (area, path) = (parts.next().unwrap_or_default(), parts.next());
            let holes = Holes::parse(parts.next().unwrap_or_default());
            match (GraftAccess::from_byte(*access), path, holes) {
                (Some(access), Some(path), Some(holes))
                    if valid_area(area) && valid_relative(path) =>
                {
                    graft(source, area, path, &holes, access)
                }
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
    open_resolved(
        dir,
        rel,
        libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )
}

/// Open the absolute path `area` with `O_PATH`, with no symbolic link.
/// Async-signal-safe.
fn open_area(area: &[u8]) -> Result<RawFd, i32> {
    open_resolved(
        libc::AT_FDCWD,
        area,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )
}

/// `openat2(2)` of `rel` below `dir` with `O_PATH` and the resolve flags
/// `resolve`. Async-signal-safe.
fn open_resolved(dir: RawFd, rel: &[u8], resolve: u64) -> Result<RawFd, i32> {
    let mut path = [0u8; MAX_GRAFT_PATH + 2];
    let text: &[u8] = if rel.is_empty() { b"." } else { rel };
    let Some(slot) = path.get_mut(..text.len()) else {
        return Err(libc::ENAMETOOLONG);
    };
    slot.copy_from_slice(text);
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve,
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

/// Graft `rel` of the real directory `source` over `rel` of the area
/// `area`, which the helper finds in its mount namespace. Each hole (a
/// path below `rel`) gets the FUSE node of its place back, so FUSE keeps
/// serving it. The helper builds the whole tree while it is detached and
/// mounts it at the end, so a hole is never native, not for a moment.
/// When a step fails, nothing is mounted. Async-signal-safe.
fn graft(
    source: RawFd,
    area: &[u8],
    rel: &[u8],
    holes: &Holes<'_>,
    access: GraftAccess,
) -> Result<(), i32> {
    let src = open_beneath(source, rel)?;
    let tree = clone_tree(src, access);
    close(src);
    let tree = tree?;
    // The root of the area in the mount namespace of the helper: the FUSE
    // root, or a graft on it.
    let root = match open_area(area) {
        Ok(fd) => fd,
        Err(e) => {
            close(tree);
            return Err(e);
        }
    };
    let result = holes
        .iter()
        .try_for_each(|hole| attach_hole(root, rel, hole, tree))
        // The lookup of the target goes through FUSE; pent answers it in
        // another thread.
        .and_then(|()| open_beneath(root, rel))
        .and_then(|dst| {
            let moved = move_mount(tree, dst);
            close(dst);
            moved
        });
    close(root);
    close(tree);
    result
}

/// The holes of a request: at most [`MAX_HOLES`] paths, each relative to
/// the width.
struct Holes<'a> {
    paths: [&'a [u8]; MAX_HOLES],
    count: usize,
}

impl<'a> Holes<'a> {
    /// Split `rest` at each NUL byte. Returns `None` for too many holes or
    /// for a path that is not relative.
    fn parse(rest: &'a [u8]) -> Option<Self> {
        let mut holes = Self {
            paths: [&[]; MAX_HOLES],
            count: 0,
        };
        if rest.is_empty() {
            return Some(holes);
        }
        for path in rest.split(|b| *b == 0) {
            if path.is_empty() || !valid_relative(path) {
                return None;
            }
            let slot = holes.paths.get_mut(holes.count)?;
            *slot = path;
            holes.count = holes.count.saturating_add(1);
        }
        Some(holes)
    }

    fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.paths.iter().take(self.count).copied()
    }
}

/// Put the FUSE node of `hole` back over its place in the detached `tree`:
/// clone the FUSE subtree at `rel/hole` below `root` (the graft is not
/// mounted yet, so the path still reaches FUSE), and move the clone onto
/// `hole` inside the tree. Async-signal-safe.
fn attach_hole(root: RawFd, rel: &[u8], hole: &[u8], tree: RawFd) -> Result<(), i32> {
    let mut full = [0u8; MAX_GRAFT_PATH + 1];
    let mut len = 0usize;
    let sep: &[u8] = if rel.is_empty() { b"" } else { b"/" };
    for part in [rel, sep, hole] {
        let Some(slot) = full.get_mut(len..len.saturating_add(part.len())) else {
            return Err(libc::ENAMETOOLONG);
        };
        slot.copy_from_slice(part);
        len = len.saturating_add(part.len());
    }
    let fuse = open_beneath(root, full.get(..len).unwrap_or_default())?;
    let flags =
        OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint | libc::AT_EMPTY_PATH as libc::c_uint;
    // SAFETY: the empty path is NUL-terminated; the rest are integers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let clone = unsafe { libc::syscall(libc::SYS_open_tree, fuse, c"".as_ptr(), flags) };
    close(fuse);
    let clone = match libc::c_int::try_from(clone) {
        Ok(fd) if fd >= 0 => fd,
        _ => return Err(errno()),
    };
    let result = open_beneath(tree, hole).and_then(|at| {
        let moved = move_mount(clone, at);
        close(at);
        moved
    });
    close(clone);
    result
}

/// Clone the tree at `src` with each mount below it, and give it the
/// attributes of `access`. Async-signal-safe.
fn clone_tree(src: RawFd, access: GraftAccess) -> Result<RawFd, i32> {
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
    let set = access.attributes();
    if set != 0 {
        let attr = MountAttr {
            attr_set: set,
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
    Ok(tree)
}

/// Mount the detached tree `tree` on `dst`. Async-signal-safe.
fn move_mount(tree: RawFd, dst: RawFd) -> Result<(), i32> {
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
    if ret == 0 {
        Ok(())
    } else {
        Err(errno())
    }
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
        for access in [
            GraftAccess::Read,
            GraftAccess::ReadExec,
            GraftAccess::Write,
            GraftAccess::WriteExec,
        ] {
            assert_eq!(GraftAccess::from_byte(access.byte()), Some(access));
        }
        assert_eq!(GraftAccess::from_byte(4), None);
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
        config.file_areas = crate::FuseAreas::Listed(vec![area.clone(), area2.clone()]);
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
            match files.graft(0, Path::new("link"), GraftAccess::Read) {
                Err(GraftError::Failed(e)) => assert_eq!(e.raw_os_error(), Some(libc::ELOOP)),
                other => return Err(format!("a graft of a link: {other:?}").into()),
            }
            assert!(matches!(
                files.graft(0, Path::new("../ws"), GraftAccess::Read),
                Err(GraftError::BadPath(_))
            ));
            assert!(matches!(
                files.graft(2, Path::new("sub"), GraftAccess::Read),
                Err(GraftError::NoArea(2))
            ));
            files.graft(0, Path::new("sub"), GraftAccess::Write)?;
            files.graft(0, Path::new("other"), GraftAccess::Read)?;
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
            files.graft(0, Path::new("sub"), GraftAccess::Read),
            Err(GraftError::HelperGone)
        ));
        Ok(())
    }

    /// The program in the home area. Each line names the result of one
    /// access; see the expected text in the test.
    const HOME_SCRIPT: &str = r#"set -e
exec > "$T/out" 2>&1
: pent-home-area-test-marker
cat "$H/open.txt"
(cat "$H/secret.txt") 2>/dev/null || echo read-refused
[ -e "$H/secret.txt" ] && echo see-free
("$H/bin/run.sh") 2>/dev/null || echo exec-refused
"$H/xbin/run.sh"
(echo x > "$H/new.txt") 2>/dev/null || echo create-refused
echo a > "$H/w/tmp"
mv "$H/w/tmp" "$H/w/target"
mkdir "$H/w/d"
mv "$H/w/target" "$H/w/d/t"
cat "$H/w/d/t"
echo new > "$H/w/next"
mv "$H/w/next" "$H/cfg"
echo again >> "$H/cfg"
mkdir "$H/made"
echo m > "$H/made/f"
ln -s d/t "$H/w/link"
readlink "$H/w/link"
mkfifo "$H/w/fifo"
[ -p "$H/w/fifo" ] && echo fifo
(mv "$H/w/d/t" "$H/stolen") 2>/dev/null || echo move-out-refused
(mv "$H/open.txt" "$H/w/taken") 2>/dev/null || echo remove-refused
: > "$T/ready"
i=0
while [ ! -e "$T/grafted" ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done
cat "$H/graft/file"
"#;

    /// A home directory below `/tmp`: the home is its own area, which the
    /// child binds back, and the rules on `/tmp` do not reach into it.
    #[test]
    fn the_home_area_applies_the_grants_and_its_rule_covers_a_graft() -> TestResult {
        if !ready() {
            return Ok(());
        }
        let tmp = tempfile::tempdir()?;
        home_area_run(&std::fs::canonicalize(tmp.path())?)
    }

    /// A home directory next to the test binary, below `/home` on each
    /// machine of the tests: the home is inside an area of the host, and
    /// only the rule on that FUSE root gives Landlock rights there.
    #[test]
    fn an_area_of_the_host_applies_the_grants_and_its_rule_covers_a_graft() -> TestResult {
        if !ready() {
            return Ok(());
        }
        let exe = std::env::current_exe()?;
        let dir = exe.parent().ok_or("the test binary has no directory")?;
        let tmp = tempfile::tempdir_in(dir)?;
        let base = std::fs::canonicalize(tmp.path())?;
        let areas = crate::linux::default_fuse_areas(None);
        if !areas.iter().any(|a| base.starts_with(a)) {
            let reason = "the directory of the test binary is in no area of the host";
            assert!(
                std::env::var_os("PENT_REQUIRE_ALL_TESTS").is_none(),
                "the test does not run, and PENT_REQUIRE_ALL_TESTS is set: {reason}"
            );
            eprintln!("skip: {reason}");
            return Ok(());
        }
        home_area_run(&base)
    }

    /// Run [`HOME_SCRIPT`] with a home directory below `base`.
    fn home_area_run(base: &Path) -> TestResult {
        let (ws, home) = (base.join("ws"), base.join("home"));
        for dir in ["bin", "xbin", "w", "graft"] {
            std::fs::create_dir_all(home.join(dir))?;
        }
        std::fs::create_dir(&ws)?;
        std::fs::write(home.join("open.txt"), "open\n")?;
        std::fs::write(home.join("secret.txt"), "SECRET\n")?;
        std::fs::write(home.join("cfg"), "old\n")?;
        std::fs::write(home.join("graft/file"), "grafted\n")?;
        for dir in ["bin", "xbin"] {
            let script = home.join(dir).join("run.sh");
            std::fs::write(&script, format!("#!/bin/sh\necho ran-{dir}\n"))?;
            std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        }

        let text = |p: &Path| p.to_string_lossy().into_owned();
        let mut env = crate::build_env(&[]);
        env.insert("T".to_string(), text(&ws));
        env.insert("H".to_string(), text(&home));
        env.insert("HOME".to_string(), text(&home));
        let mut config =
            crate::SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone())
                .with_env(env.clone())
                .with_network(crate::NetworkMode::LocalhostOnly);
        config.file_areas = crate::FuseAreas::OutsideBase;
        config.paths.read.push(text(&home.join("open.txt")));
        config.paths.read.push(text(&home.join("bin")));
        // A script needs a read by its interpreter too; an execute-only
        // grant is for a binary.
        config.paths.execute.push(text(&home.join("xbin")));
        config.paths.read.push(text(&home.join("xbin")));
        // A directory, a file and a directory that does not exist yet.
        for p in ["w", "cfg", "made"] {
            config.paths.read_write.push(text(&home.join(p)));
        }
        let args = vec!["-c".to_string(), HOME_SCRIPT.to_string()];
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
            let index = files
                .areas()
                .iter()
                .position(|a| home.starts_with(&a.path))
                .ok_or("no area holds the home directory")?;
            let area = files.areas().get(index).ok_or("no area")?;
            let graft = home.strip_prefix(&area.path)?.join("graft");
            // Only the rule on the FUSE root covers this graft: no grant
            // names it.
            files.graft(index, &graft, GraftAccess::Read)?;
            std::fs::write(ws.join("grafted"), "")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::write(ws.join("grafted"), "");
            let _ = child.kill();
        }
        let status = child.wait()?;
        let out = std::fs::read_to_string(ws.join("out")).unwrap_or_default();
        if let Err(e) = result {
            return Err(format!("{e}; the program wrote:\n{out}").into());
        }
        assert!(status.success(), "the program failed: {status}\n{out}");
        assert_eq!(
            out,
            "open\nread-refused\nsee-free\nexec-refused\nran-xbin\n\
             create-refused\na\nd/t\nfifo\nmove-out-refused\nremove-refused\ngrafted\n"
        );
        // The renames went to the real tree, and the file rule still holds
        // after the rename put a new inode at its path.
        assert_eq!(std::fs::read_to_string(home.join("cfg"))?, "new\nagain\n");
        assert_eq!(std::fs::read_to_string(home.join("made/f"))?, "m\n");
        assert!(home.join("w/d/t").exists());
        assert!(!home.join("new.txt").exists() && !home.join("stolen").exists());
        Ok(())
    }

    /// A decider for the tests: it allows the listed requests, refuses the
    /// rest, hides the paths below `pent`, and records each question.
    #[derive(Debug)]
    struct FakeDecider {
        allow: Vec<pent_profile::Request>,
        pent: PathBuf,
        asked: std::sync::Mutex<Vec<(String, pent_profile::Request)>>,
        /// The widths that a graft may give.
        graftable: Vec<PathBuf>,
        /// The target of an allowed request, for the graft of an answer.
        targets: Vec<(pent_profile::Request, pent_profile::Target)>,
        /// How long `graft_plan` waits: a slow decider shows that the
        /// program waits for the grafts at the start.
        graft_delay: std::time::Duration,
        /// The holes of each graft: the paths below a graftable width.
        holes: Vec<PathBuf>,
        /// The requests that a rule allows: the decider knows them with no
        /// question, as the chain of `pent run` knows a rule.
        rules: Vec<pent_profile::Request>,
    }

    impl FakeDecider {
        fn new(allow: Vec<pent_profile::Request>, pent: PathBuf) -> Self {
            Self {
                allow,
                pent,
                asked: std::sync::Mutex::new(Vec::new()),
                graftable: Vec::new(),
                targets: Vec::new(),
                graft_delay: std::time::Duration::ZERO,
                holes: Vec::new(),
                rules: Vec::new(),
            }
        }
    }

    impl crate::AccessDecider for FakeDecider {
        fn known(&self, request: &pent_profile::Request) -> Option<pent_profile::Decision> {
            self.rules
                .contains(request)
                .then_some(pent_profile::Decision::Allow)
        }

        fn decide(
            &self,
            program: &str,
            request: pent_profile::Request,
            _deadline: std::time::Duration,
        ) -> pent_profile::Decision {
            let decision = if self.allow.contains(&request) {
                pent_profile::Decision::Allow
            } else {
                pent_profile::Decision::Deny
            };
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((program.to_string(), request));
            decision
        }

        fn hidden(&self, path: &Path) -> bool {
            path.starts_with(&self.pent)
        }

        fn graft_plan(&self, target: &pent_profile::Target) -> Option<Vec<PathBuf>> {
            std::thread::sleep(self.graft_delay);
            let pent_profile::Target::File {
                width: pent_profile::PathWidth::Subtree(base),
                ..
            } = target
            else {
                return None;
            };
            let base = base.as_path();
            self.graftable.iter().any(|g| g == base).then(|| {
                self.holes
                    .iter()
                    .filter(|h| h.starts_with(base))
                    .cloned()
                    .collect()
            })
        }

        fn decide_target(
            &self,
            program: &str,
            request: pent_profile::Request,
            deadline: std::time::Duration,
        ) -> (pent_profile::Decision, Option<pent_profile::Target>) {
            let target = self
                .targets
                .iter()
                .find(|(r, _)| *r == request)
                .map(|(_, t)| t.clone());
            (self.decide(program, request, deadline), target)
        }
    }

    /// The program of the test of the kinds and the classes. Each line
    /// names the result of one access.
    const KINDS_SCRIPT: &str = r#"set -e
exec > "$T/out" 2>&1
: pent-kinds-test-marker
[ -e "$H/notes.txt" ] && echo see
ls "$H/docs" > /dev/null && echo listed
(ls "$H/private") 2>/dev/null || echo list-refused
cat "$H/notes.txt"
(cat "$H/other.txt") 2>/dev/null || echo read-refused
(cat "$H/notes.txt.secret") 2>/dev/null || echo old-sibling-refused
(echo w > "$H/docs/new.txt") && echo wrote
(echo x > "$H/unrelated") 2>/dev/null || echo create-refused
(mkdir "$H/docs/dir") 2>/dev/null || echo mkdir-refused
(rm "$H/docs/keep") 2>/dev/null || echo delete-refused
"$H/bin/tool.sh"
[ -e "$H/.config/pent" ] || echo pent-hidden
(cat "$H/.config/pent/rules.toml") 2>&1 | grep -q "No such file" && echo pent-enoent
ls -a "$H/.config" | grep -c pent || true
echo new > "$H/.claude.json.tmp.1"
mv "$H/.claude.json.tmp.1" "$H/.claude.json"
cat "$H/.claude.json"
(rm "$H/.claude.json.bak") 2>/dev/null || echo old-sibling-kept
"#;

    /// Each row of the tables of sections 5.2 and 5.3 of the design that
    /// the FUSE server decides: "see" is free, list, read, write and exec
    /// ask, a refusal gives `EACCES`, the files of pent give `ENOENT` and
    /// are not in a listing, and an atomic write of one file in a
    /// directory with no rule works through its temporary sibling.
    #[test]
    fn each_kind_asks_and_the_files_of_pent_are_hidden() -> TestResult {
        if !ready() {
            return Ok(());
        }
        let tmp = tempfile::tempdir()?;
        let base = std::fs::canonicalize(tmp.path())?;
        let (ws, home) = (base.join("ws"), base.join("home"));
        for dir in ["docs", "private", "bin", ".config/pent", ".config/app"] {
            std::fs::create_dir_all(home.join(dir))?;
        }
        std::fs::create_dir(&ws)?;
        for (file, text) in [
            ("notes.txt", "notes\n"),
            ("notes.txt.secret", "SECRET\n"),
            ("other.txt", "other\n"),
            ("docs/keep", "keep\n"),
            (".config/pent/rules.toml", "RULES\n"),
            (".claude.json", "old\n"),
            (".claude.json.bak", "backup\n"),
        ] {
            std::fs::write(home.join(file), text)?;
        }
        let tool = home.join("bin/tool.sh");
        std::fs::write(&tool, "#!/bin/sh\necho ran-tool\n")?;
        std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;

        let text = |p: &Path| p.to_string_lossy().into_owned();
        let file = |kind, p: &Path| -> Result<pent_profile::Request, Box<dyn std::error::Error>> {
            Ok(pent_profile::Request::File {
                kind,
                path: pent_profile::RulePath::new(p.to_path_buf())?,
            })
        };
        use pent_profile::FileKind::{Exec, List, Read, Write};
        let decider = Arc::new(FakeDecider::new(
            vec![
                file(List, &home.join("docs"))?,
                file(List, &home.join(".config"))?,
                file(Read, &home.join("notes.txt"))?,
                file(Write, &home.join("docs/new.txt"))?,
                file(Read, &tool)?,
                file(Exec, &tool)?,
            ],
            home.join(".config/pent"),
        ));
        let mut env = crate::build_env(&[]);
        env.insert("T".to_string(), text(&ws));
        env.insert("H".to_string(), text(&home));
        env.insert("HOME".to_string(), text(&home));
        let mut config =
            crate::SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone())
                .with_env(env.clone())
                .with_network(crate::NetworkMode::LocalhostOnly);
        config.file_areas = crate::FuseAreas::OutsideBase;
        // The only grant in the home: one file, in a directory with no
        // rule, so its atomic write goes through a temporary sibling.
        config
            .paths
            .read_write
            .push(text(&home.join(".claude.json")));
        config.file_decider = Some(decider.clone());
        let args = vec!["-c".to_string(), KINDS_SCRIPT.to_string()];
        let spawned = crate::linux::spawn_linux(
            &config,
            "sh",
            &args,
            &env,
            &crate::resolve_path_directories(),
            crate::linux::SpawnMode::Sandbox,
        )?;
        let mut child = spawned.child;
        let events = spawned.events.ok_or("the run has no event channel")?;
        // The test grafts nothing itself.
        drop(spawned.files);
        let status = child.wait()?;
        let out = std::fs::read_to_string(ws.join("out")).unwrap_or_default();
        assert!(status.success(), "the program failed: {status}\n{out}");
        // Each decision of the decider is an event of the run.
        let mut seen = Vec::new();
        while let Ok(event) = events.recv_timeout(std::time::Duration::from_secs(5)) {
            seen.push(event);
        }
        assert!(
            seen.iter()
                .any(|e| matches!(e, pent_profile::WatchEvent::Fs {
                op: pent_profile::FsOp::List,
                path,
                outcome: pent_profile::Outcome::Denied,
                ..
            } if *path == home.join("private"))),
            "{seen:?}"
        );
        assert_eq!(
            out,
            "see\nlisted\nlist-refused\nnotes\nread-refused\nold-sibling-refused\nwrote\n\
             create-refused\nmkdir-refused\ndelete-refused\nran-tool\npent-hidden\n\
             pent-enoent\n0\nnew\nold-sibling-kept\n"
        );
        assert_eq!(std::fs::read_to_string(home.join(".claude.json"))?, "new\n");
        assert!(!home.join("unrelated").exists() && home.join("docs/keep").exists());
        assert!(home.join(".claude.json.bak").exists());

        let asked = decider
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let requests: Vec<&pent_profile::Request> = asked.iter().map(|(_, r)| r).collect();
        let asks_for = |p: PathBuf| {
            requests
                .iter()
                .filter(|r| matches!(r, pent_profile::Request::File { path, .. } if path.as_path() == p))
                .count()
        };
        // The files of pent ask nothing, and neither does the grant and
        // its temporary sibling.
        for p in [
            ".config/pent",
            ".config/pent/rules.toml",
            ".claude.json",
            ".claude.json.tmp.1",
        ] {
            assert_eq!(asks_for(home.join(p)), 0, "{p} asked: {requests:?}");
        }
        // "See" asks nothing: only the read of `notes.txt` asks.
        assert_eq!(asks_for(home.join("notes.txt")), 1, "{requests:?}");
        // An old file with a name like a sibling asks as itself.
        assert!(requests.contains(&&file(Read, &home.join("notes.txt.secret"))?));
        assert!(requests.contains(&&file(List, &home.join("private"))?));
        assert!(requests.contains(&&file(Write, &home.join("unrelated"))?));
        // The question names the program that made the access.
        let other = ("cat".to_string(), file(Read, &home.join("other.txt"))?);
        assert!(asked.contains(&other), "{asked:?}");
        Ok(())
    }

    /// The program of the test of the grafts. It reads the mounts first,
    /// before any access to the home directory.
    const GRAFT_SCRIPT: &str = r#"set -e
exec > "$T/out" 2>&1
: pent-graft-start-marker
for d in proj ws2 nograft xonly ans keep; do
  grep -q " $H/$d " /proc/self/mountinfo && echo "graft-$d" || true
done
cat "$H/proj/f"
(echo x > "$H/proj/f") 2>/dev/null || echo proj-readonly
("$H/proj/run.sh") 2>/dev/null || echo proj-noexec
echo w > "$H/ws2/new"
cat "$H/ans/one"
i=0
while ! grep -q " $H/ans " /proc/self/mountinfo && [ $i -lt 100 ]; do sleep 0.02; i=$((i+1)); done
grep -q " $H/ans " /proc/self/mountinfo && echo graft-ans-later
cat "$H/ans/two"
cat "$H/keep/one"
cat "$H/keep/two"
"#;

    /// The grants at the start and the width of an answer become grafts,
    /// with the right attributes; the decider can keep a width with FUSE.
    #[test]
    fn the_grants_and_an_answer_become_grafts() -> TestResult {
        if !ready() {
            return Ok(());
        }
        let tmp = tempfile::tempdir()?;
        let base = std::fs::canonicalize(tmp.path())?;
        let (ws, home) = (base.join("ws"), base.join("home"));
        for dir in ["proj", "ws2", "nograft", "xonly", "ans", "keep"] {
            std::fs::create_dir_all(home.join(dir))?;
        }
        std::fs::create_dir(&ws)?;
        for (file, text) in [
            ("proj/f", "proj\n"),
            ("ans/one", "one\n"),
            ("ans/two", "two\n"),
            ("keep/one", "kept1\n"),
            ("keep/two", "kept2\n"),
        ] {
            std::fs::write(home.join(file), text)?;
        }
        let script = home.join("proj/run.sh");
        std::fs::write(&script, "#!/bin/sh\necho ran\n")?;
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;

        let text = |p: &Path| p.to_string_lossy().into_owned();
        let rule_path = |p: &Path| pent_profile::RulePath::new(p.to_path_buf());
        let file = |kind, p: &Path| -> Result<pent_profile::Request, Box<dyn std::error::Error>> {
            Ok(pent_profile::Request::File {
                kind,
                path: rule_path(p)?,
            })
        };
        let subtree =
            |kind, p: &Path| -> Result<pent_profile::Target, Box<dyn std::error::Error>> {
                Ok(pent_profile::Target::File {
                    kind,
                    width: pent_profile::PathWidth::Subtree(rule_path(p)?),
                })
            };
        use pent_profile::FileKind::Read;
        let mut fake = FakeDecider::new(
            vec![
                file(Read, &home.join("ans/one"))?,
                file(Read, &home.join("keep/one"))?,
                file(Read, &home.join("keep/two"))?,
            ],
            home.join(".config/pent"),
        );
        // `nograft` and `keep` hold, say, a credential: no graft.
        fake.graftable = ["proj", "ws2", "xonly", "ans"]
            .iter()
            .map(|d| home.join(d))
            .collect();
        fake.graft_delay = std::time::Duration::from_millis(300);
        fake.targets = vec![
            (
                file(Read, &home.join("ans/one"))?,
                subtree(Read, &home.join("ans"))?,
            ),
            (
                file(Read, &home.join("keep/one"))?,
                subtree(Read, &home.join("keep"))?,
            ),
        ];
        let decider = Arc::new(fake);
        let mut env = crate::build_env(&[]);
        env.insert("T".to_string(), text(&ws));
        env.insert("H".to_string(), text(&home));
        env.insert("HOME".to_string(), text(&home));
        let mut config =
            crate::SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone())
                .with_env(env.clone())
                .with_network(crate::NetworkMode::LocalhostOnly);
        config.file_areas = crate::FuseAreas::OutsideBase;
        config.paths.read.push(text(&home.join("proj")));
        config.paths.read.push(text(&home.join("nograft")));
        config.paths.read_write.push(text(&home.join("ws2")));
        // An execute-only grant gives no read, and a graft would.
        config.paths.execute.push(text(&home.join("xonly")));
        config.file_decider = Some(decider.clone());
        let args = vec!["-c".to_string(), GRAFT_SCRIPT.to_string()];
        let spawned = crate::linux::spawn_linux(
            &config,
            "sh",
            &args,
            &env,
            &crate::resolve_path_directories(),
            crate::linux::SpawnMode::Sandbox,
        )?;
        let mut child = spawned.child;
        drop(spawned.files);
        let status = child.wait()?;
        let out = std::fs::read_to_string(ws.join("out")).unwrap_or_default();
        assert!(status.success(), "the program failed: {status}\n{out}");
        assert_eq!(
            out,
            "graft-proj\ngraft-ws2\nproj\nproj-readonly\nproj-noexec\none\ngraft-ans-later\ntwo\n\
             kept1\nkept2\n"
        );
        assert_eq!(std::fs::read_to_string(home.join("ws2/new"))?, "w\n");
        let asked = decider
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let asked_for = |p: &str| -> Result<bool, Box<dyn std::error::Error>> {
            let wanted = file(Read, &home.join(p))?;
            Ok(asked.iter().any(|(_, r)| *r == wanted))
        };
        // The graft of the answer serves `ans/two` with no question; the
        // width that the decider keeps with FUSE asks for each file.
        assert!(asked_for("ans/one")? && !asked_for("ans/two")?, "{asked:?}");
        assert!(
            asked_for("keep/one")? && asked_for("keep/two")?,
            "{asked:?}"
        );
        // The grants at the start ask nothing.
        assert!(!asked_for("proj/f")?, "{asked:?}");
        Ok(())
    }

    /// The program of the test of the holes.
    const HOLES_SCRIPT: &str = r#"set -e
exec > "$T/out" 2>&1
: pent-graft-holes-marker
cat "$H/cfg/open.txt"
i=0
while ! grep -q " $H/cfg " /proc/self/mountinfo && [ $i -lt 100 ]; do sleep 0.02; i=$((i+1)); done
for d in cfg cfg/secret cfg/key.txt; do
  grep -q " $H/$d " /proc/self/mountinfo && echo "mount-$d" || true
done
cat "$H/cfg/open2.txt"
(cat "$H/cfg/secret/x") 2>/dev/null || echo secret-refused
(cat "$H/cfg/key.txt") 2>/dev/null || echo key-refused
(echo n > "$H/cfg/secret/new") 2>/dev/null || echo secret-create-refused
"#;

    /// A rule on a width with a sensitive directory and a sensitive file
    /// inside it becomes a graft with two holes at its first access: the
    /// rest is native, and each access in a hole still asks. The CLI holds
    /// such a rule back from the static grants, so the test gives it as the
    /// decider would: an allow with the target of the rule.
    #[test]
    fn a_graft_keeps_its_holes_with_fuse() -> TestResult {
        if !ready() {
            return Ok(());
        }
        let tmp = tempfile::tempdir()?;
        let base = std::fs::canonicalize(tmp.path())?;
        let (ws, home) = (base.join("ws"), base.join("home"));
        std::fs::create_dir_all(home.join("cfg/secret"))?;
        std::fs::create_dir(&ws)?;
        std::fs::write(home.join("cfg/open.txt"), "open\n")?;
        std::fs::write(home.join("cfg/open2.txt"), "open2\n")?;
        std::fs::write(home.join("cfg/secret/x"), "SECRET\n")?;
        std::fs::write(home.join("cfg/key.txt"), "KEY\n")?;

        let text = |p: &Path| p.to_string_lossy().into_owned();
        let open = pent_profile::Request::File {
            kind: pent_profile::FileKind::Read,
            path: pent_profile::RulePath::new(home.join("cfg/open.txt"))?,
        };
        let rule = pent_profile::Target::File {
            kind: pent_profile::FileKind::Read,
            width: pent_profile::PathWidth::Subtree(pent_profile::RulePath::new(home.join("cfg"))?),
        };
        let mut fake = FakeDecider::new(vec![open.clone()], home.join(".config/pent"));
        fake.rules = vec![open.clone()];
        fake.targets = vec![(open, rule)];
        fake.graftable = vec![home.join("cfg")];
        fake.holes = vec![home.join("cfg/secret"), home.join("cfg/key.txt")];
        let decider = Arc::new(fake);
        let mut env = crate::build_env(&[]);
        env.insert("T".to_string(), text(&ws));
        env.insert("H".to_string(), text(&home));
        env.insert("HOME".to_string(), text(&home));
        let mut config =
            crate::SandboxConfig::new(ws.clone(), crate::system_default_paths(), ws.clone())
                .with_env(env.clone())
                .with_network(crate::NetworkMode::LocalhostOnly);
        config.file_areas = crate::FuseAreas::OutsideBase;
        config.file_decider = Some(decider.clone());
        let args = vec!["-c".to_string(), HOLES_SCRIPT.to_string()];
        let spawned = crate::linux::spawn_linux(
            &config,
            "sh",
            &args,
            &env,
            &crate::resolve_path_directories(),
            crate::linux::SpawnMode::Sandbox,
        )?;
        let mut child = spawned.child;
        drop(spawned.files);
        let status = child.wait()?;
        let out = std::fs::read_to_string(ws.join("out")).unwrap_or_default();
        assert!(status.success(), "the program failed: {status}\n{out}");
        assert_eq!(
            out,
            "open\nmount-cfg\nmount-cfg/secret\nmount-cfg/key.txt\nopen2\nsecret-refused\n\
             key-refused\nsecret-create-refused\n"
        );
        let asked = decider
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let asked_for = |p: &str| {
            asked.iter().any(|(_, r)| {
                matches!(r, pent_profile::Request::File { path, .. }
                    if path.as_path() == home.join(p))
            })
        };
        // The graft serves the rest with no question; the holes ask.
        assert!(
            asked_for("cfg/open.txt") && !asked_for("cfg/open2.txt"),
            "{asked:?}"
        );
        assert!(
            asked_for("cfg/secret/x") && asked_for("cfg/key.txt"),
            "{asked:?}"
        );
        assert!(asked_for("cfg/secret/new"), "{asked:?}");
        Ok(())
    }
}
