//! Overlayfs-based file shadowing for write-listed files on Linux.
#![allow(unreachable_pub)]
//!
//! # Problem
//!
//! Landlock rules are bound to **inodes**. Programs that atomically write files
//! (create a temp file, then `rename()` it into place) produce a new inode at
//! the target path. The old Landlock rule no longer covers the new inode, so
//! subsequent accesses fail with `EACCES`.
//!
//! # Solution
//!
//! For each unique parent directory of write-listed files, this module:
//!
//! 1. Creates a private staging directory in the parent process before fork.
//!    The staging root is `/tmp/pent-<uid>/` (mode 0700, owned by the user).
//!    When another user owns that path, pent uses `$XDG_RUNTIME_DIR/pent/`.
//!    Each session gets a new leaf `ovl-<pid>-<start time>-<n>/`. Pent
//!    refuses to reuse a leaf that already exists.
//! 2. Pre-populates `upper/` with stub entries for non-manifest content:
//!    - Directories with no manifest descendants → `user.overlay.opaque=y`
//!      (entire subtree invisible: `ENOENT` on any access).
//!    - Non-manifest files (kernel ≥ 6.7) → zero-size file + `user.overlay.whiteout`
//!      xattr (`ENOENT` on `open`/`stat`; name hidden from `readdir` when parent
//!      has `user.overlay.opaque=x`).
//!    - Non-manifest files (kernel < 6.7) → empty stub file (empty content).
//!
//!    When pent cannot create a stub that hides content, the spawn fails.
//! 3. In the child's `pre_exec` hook, mounts overlayfs on the parent directory
//!    inside the child's mount namespace (lower = real dir, upper = staging),
//!    using `-o userxattr` so `user.overlay.*` xattrs are honoured.
//! 4. Starts an `inotify` watcher thread in the **parent** that watches `upper/`.
//! 5. On each event for a write-listed path, flushes the upper-layer content
//!    back to the real file **in place** — never via `rename()` — so that the
//!    inode that Landlock is bound to stays the same.
//! 6. On teardown, waits until no process of the session remains, does a
//!    final flush pass and removes the staging directories. When a flush
//!    fails, teardown keeps the staging directory so that the data stays
//!    recoverable.
//!
//! # Symbolic links
//!
//! The child controls the content of `upper/`. The flush never follows a
//! symbolic link in `upper/`: it opens every upper entry with `O_NOFOLLOW`
//! relative to a directory fd. A symbolic link that the child creates is
//! **not** copied to the real filesystem, also not as a link. The teardown
//! report lists it as a discarded write. This prevents two attacks: a link
//! that makes pent copy a secret into the workspace, and a link that makes a
//! later process outside the sandbox write through it.
//!
//! On the real side, the flush resolves each path relative to an fd of the
//! overlay root with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. On
//! kernels without `openat2`, it opens each component with `O_NOFOLLOW`. When
//! a component of a real path is a symbolic link, the flush of that path
//! fails and the failure goes into the teardown report.
//!
//! Inside the child's namespace the process can write freely (writes go to upper);
//! from the real filesystem's perspective only write-listed files are ever modified.
//! Non-manifest files in the overlay parent directory are invisible (`ENOENT`) or
//! empty, depending on kernel version.

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The maximum depth of the walks over `upper/` and of the inotify watch tree.
const MAX_WALK_DEPTH: u32 = 64;

/// The maximum depth of the stub population in `upper/`.
const MAX_STUB_DEPTH: u32 = 32;

/// The time that a deletion in an `rw_dir` waits before pent applies it.
///
/// Editors often rename a file away and write a new file at the same path.
/// The delay lets the new file arrive before pent deletes the real file.
const DELETE_SETTLE: Duration = Duration::from_millis(500);

/// The time that teardown waits for the remaining session processes.
const DESCENDANT_GRACE: Duration = Duration::from_secs(5);

/// The time that teardown waits after it sends `SIGKILL`.
const DESCENDANT_KILL_TIMEOUT: Duration = Duration::from_secs(5);

/// The name of the marker file in a staging directory that keeps unsaved edits.
const RECOVERY_MARKER: &str = "UNSAVED-EDITS";

/// The xattr that marks a userspace whiteout (kernel ≥ 6.7).
const XATTR_WHITEOUT: &CStr = c"user.overlay.whiteout";

/// The xattr that marks an opaque directory.
const XATTR_OPAQUE: &CStr = c"user.overlay.opaque";

/// One overlayfs mount — one per unique parent directory of write-listed files.
#[derive(Clone)]
#[allow(clippy::struct_field_names)] // _dir suffix is meaningful here
pub struct OverlayMount {
    /// Real parent directory. Overlayfs is mounted here inside the child namespace.
    pub real_dir: PathBuf,
    /// Upper layer directory. The parent's inotify watcher monitors this path.
    pub upper_dir: PathBuf,
    /// Overlayfs work directory (required by the kernel, sibling of `upper_dir`).
    pub work_dir: PathBuf,
    /// Base staging directory (`<staging root>/ovl-<pid>-<start>-<n>`).
    pub base_dir: PathBuf,
    /// An `O_PATH` fd of `real_dir`. Pent opens it before the child starts.
    /// All real-side flush operations resolve paths relative to it.
    real_fd: Arc<OwnedFd>,
    /// An fd of `base_dir`. Pent opens it when it creates the directory.
    base_fd: Arc<OwnedFd>,
}

/// The kind of a write that the overlay discards at teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardKind {
    /// The child wrote a file at a path that is not write-listed.
    Write,
    /// The child deleted a file at a path that is not write-listed.
    Delete,
    /// The child created a symbolic link. Pent never copies a symbolic link
    /// to the real filesystem.
    Symlink,
}

/// One write that the overlay discards at teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedWrite {
    /// The real path of the entry.
    pub path: PathBuf,
    /// The kind of the discarded write.
    pub kind: DiscardKind,
}

impl fmt::Display for DiscardedWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.kind {
            DiscardKind::Write => "write discarded",
            DiscardKind::Delete => "deletion discarded",
            DiscardKind::Symlink => "symbolic link discarded",
        };
        write!(f, "{label}: {}", self.path.display())
    }
}

/// The cause of a failed flush.
#[derive(Debug, thiserror::Error)]
pub enum FlushError {
    /// A component of the real path is a symbolic link. Pent does not follow it.
    #[error("a path component is a symbolic link; pent does not follow it")]
    SymlinkInPath,
    /// The real or the upper entry is not a regular file.
    #[error("the entry is not a regular file")]
    NotRegularFile,
    /// The path is not a plain relative path below the overlay root.
    #[error("the path is not a plain relative path")]
    InvalidPath,
    /// The directory tree is deeper than the walk limit.
    #[error("the directory tree is deeper than the walk limit")]
    DepthLimit,
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One path that pent could not flush to the real filesystem.
#[derive(Debug)]
pub struct FlushFailure {
    /// The real path that keeps its old state.
    pub path: PathBuf,
    /// The cause of the failure.
    pub error: FlushError,
}

/// The result of [`teardown`].
#[derive(Debug, Default)]
pub struct OverlayTeardownReport {
    /// The paths that pent could not flush. When this list is not empty,
    /// some edits of the session are not in the real filesystem.
    pub failures: Vec<FlushFailure>,
    /// The writes that the overlay discards because their paths are not
    /// write-listed.
    pub discarded: Vec<DiscardedWrite>,
    /// The upper directories that teardown keeps because a flush failed.
    /// They contain the unsaved data.
    pub kept_staging: Vec<PathBuf>,
    /// The number of session processes that teardown stopped with `SIGKILL`
    /// because they did not exit in the grace time.
    pub killed_descendants: usize,
}

impl OverlayTeardownReport {
    /// Returns `true` when pent flushed all edits of the session.
    pub fn all_saved(&self) -> bool {
        self.failures.is_empty()
    }
}

/// The worker that flushes the upper layer during the session.
enum Worker {
    /// The inotify watcher thread. It returns the flush engine when it stops.
    Thread {
        shutdown_tx: std::sync::mpsc::SyncSender<()>,
        thread: std::thread::JoinHandle<FlushEngine>,
    },
    /// No thread could start. Teardown does all the flush work.
    Inline(Box<FlushEngine>),
}

/// Handle for the overlay subsystem returned by [`spawn_watcher`].
pub struct OverlayHandle {
    worker: Worker,
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
    /// Directories from `read_write` config entries (as opposed to individual
    /// files).  All files created or modified inside these directories during
    /// the sandbox session should be flushed back to the real filesystem.
    rw_dirs: HashSet<PathBuf>,
    /// The session that teardown waits for, when pent can identify it.
    session: Option<Session>,
}

/// The identity of the processes of one sandbox session.
struct Session {
    /// The PID of the direct child.
    child_pid: libc::pid_t,
    /// The user namespace of the direct child.
    user_ns: NsId,
    /// The user namespace of pent.
    own_ns: NsId,
}

/// The identity of a namespace: the device and inode of its nsfs file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct NsId {
    dev: u64,
    ino: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level fd helpers
// ─────────────────────────────────────────────────────────────────────────────

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

/// Converts an error into one that carries a raw `errno`.
///
/// The pre-exec error pipe of the standard library forwards only
/// `raw_os_error()`. Other errors become `EINVAL`.
fn raw_os(e: &io::Error) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO))
}

fn c_bytes(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// Takes ownership of a raw fd that a syscall returned.
fn owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: the caller passes the return value of a syscall that creates a
    // new fd. The fd is valid (not negative) and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens an absolute or relative path. This function always adds `O_CLOEXEC`.
fn open_path(path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let c = c_bytes(path.as_os_str().as_bytes())?;
    // SAFETY: `c` is a NUL-terminated string that lives across the call.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
    owned_fd(fd)
}

/// Opens `name` relative to `dir`. This function always adds `O_CLOEXEC`.
fn open_at(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    let c = c_bytes(name.as_bytes())?;
    // SAFETY: `dir` is an open fd for the lifetime of the borrow, and `c` is
    // a NUL-terminated string that lives across the call. The mode argument
    // has the type that the variadic `openat` expects (`mode_t` is promoted
    // to an unsigned int).
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            flags | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    owned_fd(fd)
}

/// Opens a subdirectory of `dir` without a follow of a symbolic link.
fn open_dir_at(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<OwnedFd> {
    let fd = open_at(
        dir,
        name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )?;
    if file_type(&fstat_fd(fd.as_fd())?) != libc::S_IFDIR {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(fd)
}

fn fstat_fd(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is open for the lifetime of the borrow, and `st` points
    // to writable memory of the size of `struct stat`.
    let ret = unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) };
    if ret != 0 {
        return Err(last_err());
    }
    // SAFETY: `fstat` returned 0, so the kernel filled the whole struct.
    Ok(unsafe { st.assume_init() })
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`.
fn lstat_at(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<libc::stat> {
    let c = c_bytes(name.as_bytes())?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir` is open, `c` is NUL-terminated and `st` points to
    // writable memory of the size of `struct stat`.
    let ret = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        return Err(last_err());
    }
    // SAFETY: `fstatat` returned 0, so the kernel filled the whole struct.
    Ok(unsafe { st.assume_init() })
}

fn mkdir_at(dir: BorrowedFd<'_>, name: &OsStr, mode: libc::mode_t) -> io::Result<()> {
    let c = c_bytes(name.as_bytes())?;
    // SAFETY: `dir` is open and `c` is a NUL-terminated string.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) } != 0 {
        return Err(last_err());
    }
    Ok(())
}

fn unlink_at(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    let c = c_bytes(name.as_bytes())?;
    // SAFETY: `dir` is open and `c` is a NUL-terminated string. `unlinkat`
    // never follows a symbolic link in the last component.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(last_err());
    }
    Ok(())
}

const fn file_type(st: &libc::stat) -> libc::mode_t {
    st.st_mode & libc::S_IFMT
}

/// Returns a path that refers to the open fd `fd` (and `name` in it).
///
/// The kernel resolves `/proc/self/fd/<n>` to the open file, not to a path
/// name. Thus the path stays correct when someone renames or replaces a
/// component of the original path. `name` must be one plain component; the
/// last component is the only one that a `*_nofollow` call does not follow.
fn proc_fd_path(fd: BorrowedFd<'_>, name: Option<&OsStr>) -> PathBuf {
    let mut path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    if let Some(name) = name {
        path.push(name);
    }
    path
}

/// Splits a relative path into its parent and its last component.
///
/// Returns `None` when the path is empty or has a component that is not a
/// plain name (for example `..`).
fn split_rel(rel: &Path) -> Option<(&Path, &OsStr)> {
    if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return None;
    }
    Some((rel.parent()?, rel.file_name()?))
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel version probe
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the running kernel is ≥ 6.7.
///
/// Kernel 6.7 added `OVL_XATTR_XWHITEOUT` (`user.overlay.whiteout`), which
/// allows unprivileged creation of per-file whiteouts in the overlayfs upper
/// layer when the filesystem is mounted with `-o userxattr`.
fn kernel_supports_xwhiteout() -> bool {
    // SAFETY: `utsname` contains only `c_char` arrays. All-zero bytes are a
    // valid value, and the zeroes make sure that each field ends with NUL.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is a valid, writable `utsname` for the call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::uname(&raw mut uts) } != 0 {
        return false;
    }
    // SAFETY: `uname` succeeded and wrote a NUL-terminated string into
    // `release`. The zeroed init also makes sure of a NUL in the array.
    // `uts` lives longer than the borrow.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
    let s = release.to_string_lossy();
    let mut parts = s.splitn(3, '.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts
        .next()
        .and_then(|p| {
            p.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|d| d.parse().ok())
        })
        .unwrap_or(0);
    (major, minor) >= (6, 7)
}

// ─────────────────────────────────────────────────────────────────────────────
// xattr helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the xattr `name` of `path`. This function does not follow a symbolic
/// link in the last component.
fn lgetxattr_value(path: &Path, name: &CStr) -> Option<Vec<u8>> {
    let path_c = c_bytes(path.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 64];
    // SAFETY: `path_c` and `name` are NUL-terminated strings, and `buf` is a
    // writable buffer of `buf.len()` bytes for the call.
    let ret = unsafe {
        libc::lgetxattr(
            path_c.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    if ret >= 0 {
        let len = usize::try_from(ret).ok()?;
        return buf.get(..len).map(<[u8]>::to_vec);
    }
    if last_err().raw_os_error() == Some(libc::ERANGE) {
        // The value is longer than the buffer. The xattr is present.
        return Some(Vec::new());
    }
    None
}

/// Set an extended attribute on `path`. This function does not follow a
/// symbolic link in the last component.
fn set_xattr(path: &Path, name: &CStr, value: &[u8]) -> io::Result<()> {
    let path_c = c_bytes(path.as_os_str().as_bytes())?;
    let ptr = if value.is_empty() {
        std::ptr::null()
    } else {
        value.as_ptr().cast::<libc::c_void>()
    };
    // SAFETY: `path_c` and `name` are NUL-terminated strings. `ptr` is null
    // with a length of 0, or it points to `value.len()` readable bytes.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::lsetxattr(path_c.as_ptr(), name.as_ptr(), ptr, value.len(), 0) };
    if ret != 0 {
        Err(last_err())
    } else {
        Ok(())
    }
}

/// Writes a diagnostic line to stderr from the pre-exec hook.
///
/// The hook runs in a forked child of a multithreaded process. `tracing`
/// can deadlock there, so this function uses `write(2)` directly.
fn child_diag(msg: &str) {
    // SAFETY: `msg` points to `msg.len()` readable bytes. A failed or short
    // write only loses the diagnostic; the caller does not depend on it.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let _written = unsafe {
        libc::write(
            libc::STDERR_FILENO,
            msg.as_ptr().cast::<libc::c_void>(),
            msg.len(),
        )
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessibility helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if any strict ancestor of `path` is in `accessible`,
/// meaning `path` lies within an accessible subtree.
fn is_in_accessible_subtree(path: &Path, accessible: &HashSet<PathBuf>) -> bool {
    path.ancestors().skip(1).any(|a| accessible.contains(a))
}

/// Returns `true` if `accessible` contains any path that is strictly inside
/// `dir` (i.e. `dir` has at least one accessible descendant).
fn has_accessible_descendant(dir: &Path, accessible: &HashSet<PathBuf>) -> bool {
    accessible.iter().any(|a| a != dir && a.starts_with(dir))
}

// ─────────────────────────────────────────────────────────────────────────────
// Upper-layer stub population
// ─────────────────────────────────────────────────────────────────────────────

/// Creates a stub file in `upper` that hides a non-manifest file or link.
///
/// When the whiteout xattr cannot be set, the stub stays an empty file. The
/// child then sees an empty file instead of `ENOENT`, but not the content.
fn create_file_stub(upper_path: &Path, use_xwhiteout: bool) -> io::Result<bool> {
    std::fs::File::create(upper_path).map_err(|e| {
        child_diag(&format!(
            "pent: cannot create the overlay stub '{}': {e}\n",
            upper_path.display()
        ));
        raw_os(&e)
    })?;
    if !use_xwhiteout {
        return Ok(false);
    }
    match set_xattr(upper_path, XATTR_WHITEOUT, b"") {
        Ok(()) => Ok(true),
        Err(e) => {
            child_diag(&format!(
                "pent: warning: cannot set the whiteout xattr on '{}': {e}; \
                 the file stays visible as an empty file\n",
                upper_path.display()
            ));
            Ok(false)
        }
    }
}

/// Pre-populate the overlayfs `upper_dir` with stub entries that make
/// non-manifest content invisible to the sandboxed child process.
///
/// **Directories** with no accessible descendants receive `user.overlay.opaque=y`:
/// the merged view shows an empty directory; any path within returns `ENOENT`.
///
/// **Non-manifest files** (kernel ≥ 6.7, `use_xwhiteout = true`): a zero-size
/// regular file is created in `upper_dir` with `user.overlay.whiteout` set.
/// `open()`/`stat()` on the file returns `ENOENT`.  The containing directory
/// also gets `user.overlay.opaque=x` so the kernel hides the whiteout entry
/// from `readdir` as well.
///
/// **Non-manifest files** (kernel < 6.7 fallback): an empty regular file is
/// created — the child sees empty content rather than `ENOENT`.
///
/// Manifest files and directories within accessible subtrees are left untouched;
/// the lower layer shows through for them.
///
/// The function fails closed. When a step that hides content fails, or when
/// the tree is deeper than `depth_limit`, it returns an error and the spawn
/// stops. Steps that only hide names log a warning.
fn populate_upper_stubs(
    real_dir: &Path,
    upper_dir: &Path,
    accessible: &HashSet<PathBuf>,
    use_xwhiteout: bool,
    depth_limit: u32,
) -> io::Result<()> {
    if depth_limit == 0 {
        child_diag(&format!(
            "pent: the overlay stub depth limit is reached at '{}'; \
             pent stops because files below it would stay visible\n",
            real_dir.display()
        ));
        return Err(io::Error::from_raw_os_error(libc::ELOOP));
    }

    let entries = match std::fs::read_dir(real_dir) {
        Ok(entries) => entries,
        // After exec, the child has the same uid as pent and no extra
        // capabilities. A directory that pent cannot read is also closed
        // to the child, so no stub is necessary.
        Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::ENOENT)) => return Ok(()),
        Err(e) => return Err(raw_os(&e)),
    };

    let mut upper_has_xwhiteouts = false;

    for entry in entries {
        let entry = entry.map_err(|e| raw_os(&e))?;
        let real_path = entry.path();
        let upper_path = upper_dir.join(entry.file_name());
        let ft = entry.file_type().map_err(|e| raw_os(&e))?;
        let visible =
            accessible.contains(&real_path) || is_in_accessible_subtree(&real_path, accessible);
        if visible {
            continue; // The lower layer shows through.
        }

        if ft.is_dir() {
            std::fs::create_dir(&upper_path).map_err(|e| raw_os(&e))?;
            if has_accessible_descendant(&real_path, accessible) {
                // Partially accessible: recurse (no opaque xattr).
                populate_upper_stubs(
                    &real_path,
                    &upper_path,
                    accessible,
                    use_xwhiteout,
                    depth_limit - 1,
                )?;
            } else {
                // No accessible descendants: make the directory opaque so lower
                // contents don't bleed through, AND set mode 0000 so even the
                // directory itself returns EACCES on traversal or listing.
                // Without opaque=y the lower content is visible, so a failure
                // stops the spawn.
                set_xattr(&upper_path, XATTR_OPAQUE, b"y").map_err(|e| {
                    child_diag(&format!(
                        "pent: cannot set the opaque xattr on '{}': {e}\n",
                        upper_path.display()
                    ));
                    raw_os(&e)
                })?;
                if let Err(e) =
                    std::fs::set_permissions(&upper_path, std::fs::Permissions::from_mode(0o000))
                {
                    child_diag(&format!(
                        "pent: warning: cannot set mode 0000 on '{}': {e}\n",
                        upper_path.display()
                    ));
                }
            }
        } else if ft.is_file() || ft.is_symlink() {
            // Non-manifest file, or a symbolic link that can lead the child
            // into non-manifest content.
            if create_file_stub(&upper_path, use_xwhiteout)? {
                upper_has_xwhiteouts = true;
            }
        }
        // Sockets, FIFOs, device files: skip.
    }

    // Mark this directory as containing xwhiteout-format entries.
    // The kernel uses this during readdir to hide the whiteout files from
    // directory listings (requires kernel ≥ 6.7 + -o userxattr).
    if upper_has_xwhiteouts {
        if let Err(e) = set_xattr(upper_dir, XATTR_OPAQUE, b"x") {
            child_diag(&format!(
                "pent: warning: cannot set opaque=x on '{}': {e}; \
                 hidden file names can show in listings\n",
                upper_dir.display()
            ));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the minimal set of overlay mount roots from the accessible path set.
///
/// For each accessible path that lives under `home_dir`, takes its immediate
/// parent directory.  Then applies a domination filter: if directory A is an
/// ancestor of directory B, B is already covered by A's overlay and is dropped.
/// The result is the most-specific set of directories that collectively cover
/// all home-directory-scoped accessible paths.
///
/// System paths (outside `home_dir`) are excluded — they are handled by
/// Landlock alone and never need overlay stubs.
fn overlay_roots_for_accessible(
    accessible: &std::collections::HashSet<std::path::PathBuf>,
    home_dir: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    use std::collections::BTreeSet;

    // Collect unique parent dirs of accessible paths under home_dir.
    let mut parent_set: BTreeSet<std::path::PathBuf> = BTreeSet::new();
    for path in accessible {
        if !path.starts_with(home_dir) {
            continue; // system / temp / device paths — no overlay needed
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && parent.starts_with(home_dir) {
                parent_set.insert(parent.to_path_buf());
            }
        }
    }

    // Sort shortest-first so we process the most general (shallowest) dirs first.
    let mut sorted: Vec<std::path::PathBuf> = parent_set.into_iter().collect();
    sorted.sort_by_key(|p| p.as_os_str().len());

    // Keep only non-dominated entries: if an ancestor is already a root,
    // the descendant is covered by that ancestor's overlay.
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for dir in sorted {
        if !roots.iter().any(|root| dir.starts_with(root)) {
            roots.push(dir);
        }
    }
    roots
}

// ─────────────────────────────────────────────────────────────────────────────
// Staging directories
// ─────────────────────────────────────────────────────────────────────────────

/// Tells [`open_private_dir`] if it can create the directory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RootCreate {
    /// Create the directory when it does not exist.
    Create,
    /// Open only a directory that exists.
    Existing,
}

fn current_uid() -> libc::uid_t {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Returns the possible staging roots, in the order of preference.
///
/// The first root is `/tmp/pent-<uid>`. It keeps the filesystem that older
/// versions used. The second root is `$XDG_RUNTIME_DIR/pent`. Pent uses it
/// when another user owns the first root.
fn staging_root_candidates() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from(format!("/tmp/pent-{}", current_uid()))];
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if runtime.is_absolute() {
            roots.push(runtime.join("pent"));
        }
    }
    roots
}

/// Opens `path` as a private directory of the current user.
///
/// The last component must be a real directory (not a symbolic link) that
/// the current user owns. When the directory gives access to the group or
/// to others, this function sets its mode to 0700.
///
/// # Errors
///
/// Returns an error when the path is a symbolic link, when another user
/// owns it, or when a syscall fails.
fn open_private_dir(path: &Path, create: RootCreate) -> io::Result<OwnedFd> {
    if create == RootCreate::Create {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let fd = open_path(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    let st = fstat_fd(fd.as_fd())?;
    if st.st_uid != current_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("another user owns '{}'", path.display()),
        ));
    }
    if st.st_mode & 0o077 != 0 {
        std::fs::File::from(fd.try_clone()?)
            .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(fd)
}

/// Opens (and creates if necessary) the first usable staging root.
fn open_staging_root() -> io::Result<(PathBuf, OwnedFd)> {
    let mut last_error = io::Error::from_raw_os_error(libc::ENOENT);
    for root in staging_root_candidates() {
        match open_private_dir(&root, RootCreate::Create) {
            Ok(fd) => return Ok((root, fd)),
            Err(e) => {
                tracing::warn!(
                    "pent cannot use '{}' as the overlay staging root: {e}",
                    root.display()
                );
                last_error = e;
            }
        }
    }
    Err(last_error)
}

/// Returns the start time of process `pid` (field 22 of `/proc/<pid>/stat`).
///
/// The start time and the PID together identify a process, also when the
/// kernel reuses the PID.
fn process_start_time(pid: libc::pid_t) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name (field 2) can contain spaces and parentheses. The
    // fields after the last ')' start with field 3.
    let rest = stat.get(stat.rfind(')')?.checked_add(1)?..)?;
    rest.split_whitespace().nth(22 - 3)?.parse().ok()
}

/// Parses a staging leaf name `ovl-<pid>-<start>-<n>`.
fn parse_staging_name(name: &OsStr) -> Option<(libc::pid_t, u64)> {
    let name = name.to_str()?;
    let mut parts = name.strip_prefix("ovl-")?.splitn(3, '-');
    let pid = parts.next()?.parse().ok()?;
    let start = parts.next()?.parse().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    Some((pid, start))
}

/// The counter for staging leaf names in this process.
static STAGING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Compute overlay mount plans for all accessible paths under the user's home directory.
///
/// Uses the minimal common-ancestor algorithm: for each accessible path under
/// `home_dir`, takes its parent directory, then removes dominated entries so
/// that the resulting set is the most specific coverage possible.  This ensures
/// that non-accessible siblings within covered directories are hidden by the
/// overlay's stub mechanism, without blanketing the entire home directory.
///
/// Write-set files are already part of `accessible` (they are in `read_write`),
/// so write-isolation for those files is preserved automatically.
///
/// For each mount, this function creates a new private staging directory
/// (mode 0700) and opens an fd of the real directory. `pid` must be the PID
/// of the current process.
///
/// # Errors
///
/// Returns an error when no private staging root is usable, when a staging
/// directory already exists, or when a real directory cannot be opened.
pub fn prepare_overlay_dirs(
    accessible: &HashSet<PathBuf>,
    home_dir: &Path,
    pid: u32,
) -> io::Result<Vec<OverlayMount>> {
    let roots: Vec<PathBuf> = overlay_roots_for_accessible(accessible, home_dir)
        .into_iter()
        .filter(|root| root.is_dir())
        .collect();
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let pid_t = libc::pid_t::try_from(pid).map_err(io::Error::other)?;
    let start = process_start_time(pid_t).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot read the start time of process {pid}"),
        )
    })?;
    let (staging_root, staging_fd) = open_staging_root()?;

    let mut mounts: Vec<OverlayMount> = Vec::new();
    for root in &roots {
        // A process can run many sessions at the same time (pent-sandbox is a
        // library), so a process-wide counter makes each leaf name unique.
        let seq = STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let leaf = format!("ovl-{pid}-{start}-{seq}");
        match create_mount(root, &staging_root, staging_fd.as_fd(), &leaf) {
            Ok(mount) => mounts.push(mount),
            Err(e) => {
                for mount in &mounts {
                    if let Err(rm) = remove_staging_dir(&mount.base_dir) {
                        tracing::warn!("cannot remove '{}': {rm}", mount.base_dir.display());
                    }
                }
                return Err(io::Error::new(
                    e.kind(),
                    format!("overlay staging for '{}': {e}", root.display()),
                ));
            }
        }
    }
    Ok(mounts)
}

/// Opens the real directory `root` and creates the staging leaf `leaf`.
fn create_mount(
    root: &Path,
    staging_root: &Path,
    staging_fd: BorrowedFd<'_>,
    leaf: &str,
) -> io::Result<OverlayMount> {
    let base_dir = staging_root.join(leaf);
    // The configured path is trusted, so this open can follow symbolic
    // links. The child cannot change the path before this point.
    let real_fd = open_path(root, libc::O_PATH | libc::O_DIRECTORY)?;
    // mkdirat fails with EEXIST when the leaf exists. Pent never reuses a
    // directory that someone else can have prepared.
    mkdir_at(staging_fd, OsStr::new(leaf), 0o700)?;
    let base_fd = open_at(
        staging_fd,
        OsStr::new(leaf),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )?;
    Ok(OverlayMount {
        real_dir: root.to_path_buf(),
        upper_dir: base_dir.join("upper"),
        work_dir: base_dir.join("work"),
        base_dir,
        real_fd: Arc::new(real_fd),
        base_fd: Arc::new(base_fd),
    })
}

/// Create upper/work directories and populate content stubs.
///
/// Must be called in the child's `pre_exec` hook, **after**
/// `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and UID/GID mapping, and **before**
/// [`mount_overlays`].  Running inside the user namespace ensures the
/// directories and their xattrs are created in the same security context as
/// the overlay mount itself, which is required on kernels ≥ 5.11.
///
/// The parent created each base directory as a new, empty directory. This
/// function creates `upper` and `work` in it relative to the base fd, and
/// fails when they already exist.
///
/// # Errors
///
/// Returns an error with a raw `errno` when a directory or a stub cannot be
/// created. The spawn must then stop.
pub fn setup_overlay_dirs(
    overlays: &[OverlayMount],
    accessible: &HashSet<PathBuf>,
) -> io::Result<()> {
    let use_xwhiteout = kernel_supports_xwhiteout();
    for overlay in overlays {
        mkdir_at(overlay.base_fd.as_fd(), OsStr::new("upper"), 0o700)?;
        mkdir_at(overlay.base_fd.as_fd(), OsStr::new("work"), 0o700)?;
        // Pre-populate upper/ with stubs for non-manifest content.
        populate_upper_stubs(
            &overlay.real_dir,
            &overlay.upper_dir,
            accessible,
            use_xwhiteout,
            MAX_STUB_DEPTH,
        )?;
    }
    Ok(())
}

/// Mount overlayfs for each entry in `overlays`.
///
/// All mount failures are fatal.  If the overlayfs cannot be established for
/// any directory, an error is returned immediately and the spawn must be
/// aborted.  Silently degrading to a sandbox without overlayfs protection
/// would leave the broad `write_access` Landlock rule (covering the entire
/// parent directory) in place without the overlay's opaque stubs to limit
/// what content the child can actually reach — a security violation.
///
/// # Errors
///
/// Returns the `errno` of the first failed mount.
///
/// # Safety
///
/// Must be called in a post-fork, single-threaded child process that has already
/// called `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and written the UID/GID mappings.
/// These mounts exist **only** in the child's mount namespace; the parent process
/// sees the original directories untouched.
pub unsafe fn mount_overlays(overlays: &[OverlayMount]) -> io::Result<()> {
    for overlay in overlays {
        if !overlay.real_dir.is_dir() {
            continue;
        }
        let Some(real_str) = overlay.real_dir.to_str() else {
            continue;
        };
        let Some(upper_str) = overlay.upper_dir.to_str() else {
            continue;
        };
        let Some(work_str) = overlay.work_dir.to_str() else {
            continue;
        };

        let Ok(target) = CString::new(real_str) else {
            continue;
        };
        // userxattr: use user.overlay.* namespace for opaque/whiteout xattrs,
        //   which works in unprivileged user namespaces.
        // index=off: disable the index directory feature, which is required to
        //   allow overlay-on-overlay (e.g. when pent runs inside a Docker
        //   container whose root filesystem is already overlayfs/overlay2).
        let options = format!(
            "lowerdir={real_str},upperdir={upper_str},workdir={work_str},userxattr,index=off"
        );
        let Ok(options_c) = CString::new(options) else {
            continue;
        };

        // SAFETY: all strings are NUL-terminated and live across the call.
        // The caller guarantees that this process owns a private mount
        // namespace, so the mount does not change the parent's view.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = libc::mount(
            c"overlay".as_ptr(),
            target.as_ptr(),
            c"overlay".as_ptr(),
            0,
            options_c.as_ptr().cast::<libc::c_void>(),
        );

        if ret != 0 {
            // All failures are fatal. Without the overlay, the broad write_access
            // Landlock rule on the parent directory would grant ReadFile access
            // to all siblings of the write-listed files — a security violation.
            //
            // IMPORTANT: We must return std::io::Error::last_os_error() (not
            // io::Error::other()) because Rust's pre_exec error pipe only
            // forwards raw_os_error(). Custom errors (raw_os_error() == None)
            // are replaced with EINVAL by the stdlib, hiding the real errno.
            // Write the diagnostic to stderr directly instead.
            let errno = last_err();
            child_diag(&format!(
                "pent: overlayfs mount on '{real_str}' failed: {errno}\n\
                 pent: hint: check sysctl kernel.unprivileged_userns_clone=1,\n\
                 pent:       user.max_user_namespaces > 0,\n\
                 pent:       and no AppArmor/LSM profile blocking overlay mounts.\n"
            ));
            return Err(errno);
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Safe path resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Opens the directory `rel` below `root` and never follows a symbolic link.
///
/// This variant is for the upper layer. It never creates a directory.
fn open_dir_beneath_nofollow(root: BorrowedFd<'_>, rel: &Path) -> io::Result<OwnedFd> {
    let mut cur = root.try_clone_to_owned()?;
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        cur = open_dir_at(cur.as_fd(), name)?;
    }
    Ok(cur)
}

/// `struct open_how` from `<linux/openat2.h>`. The `libc` type cannot be
/// built outside the crate (it is `non_exhaustive`).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Opens `rel` below `root` with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.
fn openat2_beneath(root: BorrowedFd<'_>, rel: &Path) -> io::Result<OwnedFd> {
    let c = c_bytes(rel.as_os_str().as_bytes())?;
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let how = OpenHow {
        flags: u64::from(flags.cast_unsigned()),
        mode: 0,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `root` is open, `c` is NUL-terminated, and `how` is a valid
    // `open_how` whose size the last argument gives. The kernel only reads
    // these buffers.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            c.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        return Err(last_err());
    }
    let fd = libc::c_int::try_from(ret).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))?;
    owned_fd(fd)
}

/// Maps an error of a no-follow open to a [`FlushError`].
///
/// `ELOOP` (and `EXDEV` from `RESOLVE_BENEATH`) mean that a component is a
/// symbolic link or leaves the root.
fn resolve_error(e: io::Error) -> FlushError {
    match e.raw_os_error() {
        Some(libc::ELOOP | libc::EXDEV) => FlushError::SymlinkInPath,
        _ => FlushError::Io(e),
    }
}

/// Opens the real directory `rel` below the overlay root `root`.
///
/// No component may be a symbolic link. The fast path uses `openat2`. When
/// the kernel does not have `openat2` (`ENOSYS`), or a filter blocks it
/// (`EPERM`), or a directory is missing and `create` is given, the function
/// opens each component with `O_NOFOLLOW` relative to the previous one.
///
/// With `create`, missing directories are created with `mkdirat`. The mode
/// comes from `create(prefix)`. The function adds each created directory to
/// `created`.
///
/// Returns `Ok(None)` when a directory is missing and `create` is `None`.
fn open_real_dir(
    root: BorrowedFd<'_>,
    rel: &Path,
    create: Option<&dyn Fn(&Path) -> libc::mode_t>,
    created: &mut Vec<PathBuf>,
) -> Result<Option<OwnedFd>, FlushError> {
    if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(FlushError::InvalidPath);
    }
    if rel.as_os_str().is_empty() {
        return Ok(Some(root.try_clone_to_owned()?));
    }
    match openat2_beneath(root, rel) {
        Ok(fd) => return Ok(Some(fd)),
        Err(e) => match e.raw_os_error() {
            Some(libc::ELOOP | libc::EXDEV) => return Err(FlushError::SymlinkInPath),
            Some(libc::ENOENT) if create.is_none() => return Ok(None),
            // Fall back to the walk per component.
            Some(libc::ENOENT | libc::ENOSYS | libc::EPERM | libc::E2BIG) => {}
            _ => return Err(FlushError::Io(e)),
        },
    }

    let mut cur = root.try_clone_to_owned()?;
    let mut prefix = PathBuf::new();
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            return Err(FlushError::InvalidPath);
        };
        prefix.push(name);
        let next = match open_dir_at(cur.as_fd(), name) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let Some(mode_for) = create else {
                    return Ok(None);
                };
                match mkdir_at(cur.as_fd(), name, mode_for(&prefix)) {
                    Ok(()) => created.push(prefix.clone()),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(FlushError::Io(e)),
                }
                open_dir_at(cur.as_fd(), name).map_err(resolve_error)?
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                // O_PATH | O_NOFOLLOW opens a symbolic link itself; the
                // type check then fails. Tell a link from a file.
                let is_link =
                    lstat_at(cur.as_fd(), name).is_ok_and(|st| file_type(&st) == libc::S_IFLNK);
                return Err(if is_link {
                    FlushError::SymlinkInPath
                } else {
                    FlushError::Io(e)
                });
            }
            Err(e) => return Err(resolve_error(e)),
        };
        cur = next;
    }
    Ok(Some(cur))
}

/// Returns the permission bits of the upper directory `rel`, or 0700.
fn upper_dir_mode(upper_root: Option<BorrowedFd<'_>>, rel: &Path) -> libc::mode_t {
    upper_root
        .and_then(|root| open_dir_beneath_nofollow(root, rel).ok())
        .and_then(|fd| fstat_fd(fd.as_fd()).ok())
        .map_or(0o700, |st| st.st_mode & 0o777)
}

// ─────────────────────────────────────────────────────────────────────────────
// Flush primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Flush the upper-layer copy of a file back to the real path in place.
///
/// Both sides are opened relative to directory fds with `O_NOFOLLOW`, so a
/// symbolic link in the last component makes the flush fail.
///
/// On an existing real file, the function writes over the old content from
/// offset 0, then truncates the file to the new length. The inode stays the
/// same, so the Landlock rule bound to it stays valid. The function does not
/// use `O_TRUNC`: a crash during the copy leaves the old length with a mix of
/// new and old bytes, not an empty file. The flush is not atomic: a reader
/// can see a mix of old and new content during the copy.
///
/// A new real file gets the permission bits of the upper file at `open`
/// time, so a file with mode 0600 is never readable by others. The function
/// also copies the permission bits (without setuid, setgid and sticky bits)
/// and the access and modification times.
///
/// Returns `true` when the function created the real file.
fn flush_file(
    upper_dir: BorrowedFd<'_>,
    real_dir: BorrowedFd<'_>,
    name: &OsStr,
) -> Result<bool, FlushError> {
    let upper = open_at(
        upper_dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        0,
    )
    .map_err(resolve_error)?;
    let upper_st = fstat_fd(upper.as_fd())?;
    if file_type(&upper_st) != libc::S_IFREG {
        return Err(FlushError::NotRegularFile);
    }
    let mode = upper_st.st_mode & 0o777;

    let write_flags = libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
    let (real, created) = match open_at(real_dir, name, write_flags, 0) {
        Ok(fd) => (fd, false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let fd = open_at(
                real_dir,
                name,
                write_flags | libc::O_CREAT | libc::O_EXCL,
                mode,
            )
            .map_err(resolve_error)?;
            (fd, true)
        }
        Err(e) => return Err(resolve_error(e)),
    };
    if file_type(&fstat_fd(real.as_fd())?) != libc::S_IFREG {
        return Err(FlushError::NotRegularFile);
    }

    let mut src = std::fs::File::from(upper);
    let mut dst = std::fs::File::from(real);
    // Set the mode before the copy: when the new mode is narrower, the new
    // content is never readable with the old, wider mode.
    dst.set_permissions(std::fs::Permissions::from_mode(mode))?;
    let len = io::copy(&mut src, &mut dst)?;
    dst.set_len(len)?;
    let src_meta = src.metadata()?;
    let times = std::fs::FileTimes::new()
        .set_accessed(src_meta.accessed()?)
        .set_modified(src_meta.modified()?);
    dst.set_times(times)?;
    dst.sync_data()?;
    Ok(created)
}

/// Deletes the real entry `rel` below `root`. A missing entry is a success.
///
/// The parent is resolved without a follow of a symbolic link. `unlinkat`
/// removes a symbolic link itself, never its target. A directory is removed
/// recursively; the standard library opens each level with `O_NOFOLLOW`.
fn delete_real(root: BorrowedFd<'_>, rel: &Path) -> Result<(), FlushError> {
    let (parent_rel, name) = split_rel(rel).ok_or(FlushError::InvalidPath)?;
    let Some(parent) = open_real_dir(root, parent_rel, None, &mut Vec::new())? else {
        return Ok(());
    };
    match unlink_at(parent.as_fd(), name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EISDIR | libc::EPERM)) => {
            match std::fs::remove_dir_all(proc_fd_path(parent.as_fd(), Some(name))) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(FlushError::Io(e)),
            }
        }
        Err(e) => Err(FlushError::Io(e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flush engine
// ─────────────────────────────────────────────────────────────────────────────

/// The state of one entry in the upper layer.
enum UpperState {
    /// No entry. The lower layer shows through, or the entry was upper-only
    /// and the child removed it.
    Absent,
    /// A whiteout (char device 0/0 or `user.overlay.whiteout`).
    Whiteout,
    /// A regular file. The fd is the upper parent directory.
    File(OwnedFd),
    /// A directory.
    Dir,
    /// A symbolic link. Pent never follows or copies it.
    Symlink,
    /// A FIFO, socket or device.
    Other,
}

/// Returns `true` if the upper entry `name` in `dir` is an overlay whiteout.
///
/// Two whiteout formats exist depending on kernel version and mount options:
///
/// 1. **Traditional (char device 0/0)**: overlayfs creates a character device
///    with major=0, minor=0 when unlinking a file that exists in the lower
///    layer.  This is what the kernel produces internally during `unlink(2)`
///    inside the sandbox — regardless of the `-o userxattr` mount option.
///
/// 2. **Userxattr (kernel ≥ 6.7)**: a zero-size regular file with the
///    `user.overlay.whiteout` extended attribute.  This is what *userspace*
///    creates via `populate_upper_stubs` to pre-hide non-manifest files.
fn is_whiteout(dir: BorrowedFd<'_>, name: &OsStr, st: &libc::stat) -> bool {
    match file_type(st) {
        libc::S_IFCHR => st.st_rdev == 0,
        libc::S_IFREG => lgetxattr_value(&proc_fd_path(dir, Some(name)), XATTR_WHITEOUT).is_some(),
        _ => false,
    }
}

/// Classifies the upper entry `rel` below `upper_root` without a follow of
/// a symbolic link.
fn upper_state(upper_root: BorrowedFd<'_>, rel: &Path) -> Result<UpperState, FlushError> {
    let (parent_rel, name) = split_rel(rel).ok_or(FlushError::InvalidPath)?;
    let parent = match open_dir_beneath_nofollow(upper_root, parent_rel) {
        Ok(fd) => fd,
        // A missing parent, a whiteout or a link at a parent position: the
        // entry is not in the merged view of the child.
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
            ) =>
        {
            return Ok(UpperState::Absent)
        }
        Err(e) => return Err(FlushError::Io(e)),
    };
    let st = match lstat_at(parent.as_fd(), name) {
        Ok(st) => st,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(UpperState::Absent),
        Err(e) => return Err(FlushError::Io(e)),
    };
    if is_whiteout(parent.as_fd(), name, &st) {
        return Ok(UpperState::Whiteout);
    }
    Ok(match file_type(&st) {
        libc::S_IFREG => UpperState::File(parent),
        libc::S_IFDIR => UpperState::Dir,
        libc::S_IFLNK => UpperState::Symlink,
        _ => UpperState::Other,
    })
}

/// Tells [`FlushEngine::reconcile`] if a deletion can wait.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// The session runs. Deletions wait (see [`DELETE_SETTLE`]); deletions
    /// of write-listed files wait until teardown.
    Live,
    /// Teardown. All decisions are final.
    Final,
}

/// One overlay as the flush engine sees it.
struct Tree {
    real_dir: PathBuf,
    real_fd: Arc<OwnedFd>,
    /// `None` when pent cannot open the upper directory.
    upper_fd: Option<OwnedFd>,
}

/// The flush state of one session.
///
/// The watcher thread owns the engine during the session and returns it
/// when it stops. Teardown then does the final pass with the same state.
struct FlushEngine {
    trees: Vec<Tree>,
    write_set: HashSet<PathBuf>,
    rw_dirs: HashSet<PathBuf>,
    /// The entries `(tree, relative path)` that this session wrote or created
    /// in the real filesystem. When such an entry disappears from upper, pent
    /// deletes it from the real filesystem. This also cleans up an upper-only
    /// temp file when inotify lost its `IN_MOVED_FROM` or `IN_DELETE` event.
    flushed: HashSet<(usize, PathBuf)>,
    /// The deletions that wait, with the time of their first event.
    pending_del: HashMap<(usize, PathBuf), Instant>,
    /// The current flush failures, by real path.
    failures: HashMap<PathBuf, FlushError>,
}

impl FlushEngine {
    fn new(trees: Vec<Tree>, write_set: HashSet<PathBuf>, rw_dirs: HashSet<PathBuf>) -> Self {
        let mut engine = Self {
            trees,
            write_set,
            rw_dirs,
            flushed: HashSet::new(),
            pending_del: HashMap::new(),
            failures: HashMap::new(),
        };
        let missing: Vec<PathBuf> = engine
            .trees
            .iter()
            .filter(|t| t.upper_fd.is_none())
            .map(|t| t.real_dir.clone())
            .collect();
        for real in missing {
            engine.fail(
                real,
                FlushError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "pent cannot open the upper directory",
                )),
            );
        }
        engine
    }

    /// Builds the engine for `overlays`. It opens each upper directory
    /// relative to the base fd, without a follow of a symbolic link.
    fn for_overlays(
        overlays: &[OverlayMount],
        write_set: HashSet<PathBuf>,
        rw_dirs: HashSet<PathBuf>,
    ) -> Self {
        let trees = overlays
            .iter()
            .map(|o| Tree {
                real_dir: o.real_dir.clone(),
                real_fd: Arc::clone(&o.real_fd),
                upper_fd: open_dir_at(o.base_fd.as_fd(), OsStr::new("upper"))
                    .map_err(|e| {
                        tracing::warn!("cannot open '{}': {e}", o.upper_dir.display());
                    })
                    .ok(),
            })
            .collect();
        Self::new(trees, write_set, rw_dirs)
    }

    /// Returns `true` if pent copies changes of `real` to the real filesystem.
    fn is_tracked(&self, real: &Path) -> bool {
        self.write_set.contains(real) || self.rw_dirs.iter().any(|d| real.starts_with(d))
    }

    /// Returns `true` if `real` is tracked or contains a tracked path.
    fn leads_to_tracked(&self, real: &Path) -> bool {
        self.is_tracked(real)
            || self
                .write_set
                .iter()
                .chain(self.rw_dirs.iter())
                .any(|p| p.starts_with(real))
    }

    fn real_path(&self, t: usize, rel: &Path) -> Option<PathBuf> {
        self.trees.get(t).map(|tree| tree.real_dir.join(rel))
    }

    fn fail(&mut self, real: PathBuf, error: FlushError) {
        tracing::warn!("pent cannot flush '{}': {error}", real.display());
        self.failures.insert(real, error);
    }

    /// Brings the real entry `rel` of tree `t` in line with the upper layer.
    fn reconcile(&mut self, t: usize, rel: &Path, phase: Phase) {
        let Some(real) = self.real_path(t, rel) else {
            return;
        };
        if !self.is_tracked(&real) {
            return;
        }
        let Some(upper_root) = self.trees.get(t).and_then(|tree| tree.upper_fd.as_ref()) else {
            return;
        };
        let state = match upper_state(upper_root.as_fd(), rel) {
            Ok(state) => state,
            Err(e) => {
                self.fail(real, e);
                return;
            }
        };
        let key = (t, rel.to_path_buf());
        match state {
            UpperState::File(upper_parent) => self.flush_one(t, rel, real, &upper_parent),
            UpperState::Dir => self.ensure_real_dir(t, rel, real),
            UpperState::Absent if !self.flushed.contains(&key) => {
                // Not changed in this session, or created and removed before
                // a flush. The real filesystem is already correct.
                self.pending_del.remove(&key);
            }
            UpperState::Absent | UpperState::Whiteout => match phase {
                Phase::Final => self.delete_one(t, rel, real),
                Phase::Live => {
                    self.pending_del.entry(key).or_insert_with(Instant::now);
                }
            },
            UpperState::Symlink => {
                // Policy: pent never copies a symbolic link (see the module
                // documentation). Teardown reports it as discarded.
                tracing::debug!("symbolic link not copied: {}", real.display());
                self.pending_del.remove(&key);
            }
            UpperState::Other => {}
        }
    }

    fn flush_one(&mut self, t: usize, rel: &Path, real: PathBuf, upper_parent: &OwnedFd) {
        let Some((parent_rel, name)) = split_rel(rel) else {
            self.fail(real, FlushError::InvalidPath);
            return;
        };
        let Some(tree) = self.trees.get(t) else {
            return;
        };
        let upper_root = tree.upper_fd.as_ref().map(AsFd::as_fd);
        let mode_for = |prefix: &Path| upper_dir_mode(upper_root, prefix);
        let mut created = Vec::new();
        let result = open_real_dir(
            tree.real_fd.as_fd(),
            parent_rel,
            Some(&mode_for),
            &mut created,
        )
        .and_then(|parent| {
            let parent =
                parent.ok_or_else(|| FlushError::Io(io::Error::from_raw_os_error(libc::ENOENT)))?;
            flush_file(upper_parent.as_fd(), parent.as_fd(), name)
        });
        for dir in created {
            self.flushed.insert((t, dir));
        }
        let key = (t, rel.to_path_buf());
        match result {
            Ok(_) => {
                self.flushed.insert(key.clone());
                self.pending_del.remove(&key);
                self.failures.remove(&real);
            }
            Err(e) => self.fail(real, e),
        }
    }

    fn ensure_real_dir(&mut self, t: usize, rel: &Path, real: PathBuf) {
        let Some(tree) = self.trees.get(t) else {
            return;
        };
        let upper_root = tree.upper_fd.as_ref().map(AsFd::as_fd);
        let mode_for = |prefix: &Path| upper_dir_mode(upper_root, prefix);
        let mut created = Vec::new();
        let result = open_real_dir(tree.real_fd.as_fd(), rel, Some(&mode_for), &mut created);
        for dir in created {
            self.flushed.insert((t, dir));
        }
        self.pending_del.remove(&(t, rel.to_path_buf()));
        match result {
            Ok(_) => {
                self.failures.remove(&real);
            }
            Err(e) => self.fail(real, e),
        }
    }

    fn delete_one(&mut self, t: usize, rel: &Path, real: PathBuf) {
        let Some(tree) = self.trees.get(t) else {
            return;
        };
        match delete_real(tree.real_fd.as_fd(), rel) {
            Ok(()) => {
                self.flushed
                    .retain(|(tt, r)| !(*tt == t && r.starts_with(rel)));
                self.pending_del
                    .retain(|(tt, r), _| !(*tt == t && r.starts_with(rel)));
                self.failures.retain(|p, _| !p.starts_with(&real));
            }
            Err(e) => {
                self.pending_del.remove(&(t, rel.to_path_buf()));
                self.fail(real, e);
            }
        }
    }

    /// Applies the deletions that waited long enough at `now`.
    ///
    /// A deletion of a write-listed file waits until `force` (teardown).
    /// Before a deletion, pent checks the upper layer again: when the child
    /// wrote a new file at the path in the meantime, pent flushes it in place
    /// and the real inode stays the same.
    fn process_settled(&mut self, now: Instant, force: bool) {
        let due: Vec<(usize, PathBuf)> = self
            .pending_del
            .iter()
            .filter(|((t, rel), since)| {
                if force {
                    return true;
                }
                let write_listed = self
                    .real_path(*t, rel)
                    .is_some_and(|real| self.write_set.contains(&real));
                !write_listed && now.saturating_duration_since(**since) >= DELETE_SETTLE
            })
            .map(|(key, _)| key.clone())
            .collect();
        for (t, rel) in due {
            self.pending_del.remove(&(t, rel.clone()));
            self.reconcile(t, &rel, Phase::Final);
        }
    }

    /// Walks the upper directory `rel_dir` of tree `t` and reconciles each
    /// entry. With `watches`, the walk also adds an inotify watch on each
    /// directory. The walk skips subtrees that contain no tracked path.
    fn walk(
        &mut self,
        t: usize,
        rel_dir: &Path,
        phase: Phase,
        mut watches: Option<&mut Watches>,
        depth: u32,
    ) {
        let Some(real_dir) = self.real_path(t, rel_dir) else {
            return;
        };
        if !self.leads_to_tracked(&real_dir) {
            return;
        }
        let Some(upper_root) = self.trees.get(t).and_then(|tree| tree.upper_fd.as_ref()) else {
            return;
        };
        let dir = match open_dir_beneath_nofollow(upper_root.as_fd(), rel_dir) {
            Ok(fd) => fd,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
                ) =>
            {
                return;
            }
            Err(e) => {
                self.fail(real_dir, FlushError::Io(e));
                return;
            }
        };
        if let Some(w) = watches.as_deref_mut() {
            w.add(dir.as_fd(), t, rel_dir);
        }
        if depth == 0 {
            self.fail(real_dir, FlushError::DepthLimit);
            return;
        }
        let entries = match std::fs::read_dir(proc_fd_path(dir.as_fd(), None)) {
            Ok(entries) => entries,
            Err(e) => {
                self.fail(real_dir, FlushError::Io(e));
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    self.fail(real_dir.clone(), FlushError::Io(e));
                    continue;
                }
            };
            let rel = rel_dir.join(entry.file_name());
            // DirEntry::file_type does not follow a symbolic link.
            let is_dir = entry.file_type().is_ok_and(|ft| ft.is_dir());
            self.reconcile(t, &rel, phase);
            if is_dir {
                self.walk(t, &rel, phase, watches.as_deref_mut(), depth - 1);
            }
        }
    }

    /// Rescans all upper directories and reconciles every tracked entry.
    ///
    /// Pent uses this after `IN_Q_OVERFLOW` (the kernel dropped events) and
    /// at teardown. It also checks every entry in `flushed`, so a lost event
    /// for an upper-only file cannot leave a stale real file.
    fn resync(&mut self, mut watches: Option<&mut Watches>, phase: Phase) {
        for t in 0..self.trees.len() {
            self.walk(
                t,
                Path::new(""),
                phase,
                watches.as_deref_mut(),
                MAX_WALK_DEPTH,
            );
        }
        let flushed: Vec<(usize, PathBuf)> = self.flushed.iter().cloned().collect();
        for (t, rel) in flushed {
            self.reconcile(t, &rel, phase);
        }
    }

    /// The final pass of teardown. Returns the discarded writes.
    fn final_pass(&mut self) -> Vec<DiscardedWrite> {
        self.resync(None, Phase::Final);
        self.process_settled(Instant::now(), true);
        self.scan_discarded()
    }

    fn take_failures(&mut self) -> Vec<FlushFailure> {
        let mut failures: Vec<FlushFailure> = self
            .failures
            .drain()
            .map(|(path, error)| FlushFailure { path, error })
            .collect();
        failures.sort_by(|a, b| a.path.cmp(&b.path));
        failures
    }

    /// Lists the upper entries that pent does not copy to the real filesystem.
    ///
    /// Pent's own stubs are not in the list: whiteouts with the xattr, and
    /// zero-size files over an existing real entry (kernel < 6.7 stubs).
    fn scan_discarded(&self) -> Vec<DiscardedWrite> {
        let mut out = Vec::new();
        for tree in &self.trees {
            if let Some(upper) = &tree.upper_fd {
                self.scan_dir(tree, upper.as_fd(), Path::new(""), MAX_WALK_DEPTH, &mut out);
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    fn scan_dir(
        &self,
        tree: &Tree,
        dir: BorrowedFd<'_>,
        rel_dir: &Path,
        depth: u32,
        out: &mut Vec<DiscardedWrite>,
    ) {
        if depth == 0 {
            tracing::warn!(
                "the discarded-write scan stops at the depth limit in '{}'",
                tree.real_dir.join(rel_dir).display()
            );
            return;
        }
        // Pent's opaque stubs have mode 0000 and cannot be listed. The child
        // cannot write in them either.
        let Ok(entries) = std::fs::read_dir(proc_fd_path(dir, None)) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let rel = rel_dir.join(&name);
            let real = tree.real_dir.join(&rel);
            let Ok(st) = lstat_at(dir, &name) else {
                continue;
            };
            let tracked = self.is_tracked(&real);
            match file_type(&st) {
                libc::S_IFDIR => {
                    if let Ok(sub) = open_dir_at(dir, &name) {
                        self.scan_dir(tree, sub.as_fd(), &rel, depth - 1, out);
                    }
                }
                libc::S_IFLNK => out.push(DiscardedWrite {
                    path: real,
                    kind: DiscardKind::Symlink,
                }),
                libc::S_IFCHR if st.st_rdev == 0 && !tracked => out.push(DiscardedWrite {
                    path: real,
                    kind: DiscardKind::Delete,
                }),
                libc::S_IFREG if !tracked => {
                    if is_whiteout(dir, &name, &st) {
                        continue; // Pent's stub.
                    }
                    if st.st_size == 0 && real_entry_exists(tree, &rel) {
                        continue; // Pent's empty stub (kernel < 6.7).
                    }
                    out.push(DiscardedWrite {
                        path: real,
                        kind: DiscardKind::Write,
                    });
                }
                _ => {}
            }
        }
    }
}

/// Returns `true` if the real entry `rel` exists (without a link follow).
fn real_entry_exists(tree: &Tree, rel: &Path) -> bool {
    let Some((parent_rel, name)) = split_rel(rel) else {
        return false;
    };
    match open_real_dir(tree.real_fd.as_fd(), parent_rel, None, &mut Vec::new()) {
        Ok(Some(parent)) => lstat_at(parent.as_fd(), name).is_ok(),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// inotify watcher
// ─────────────────────────────────────────────────────────────────────────────

/// The events that the watcher monitors on each upper directory.
const WATCH_MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CREATE
    | libc::IN_ATTRIB
    | libc::IN_DELETE
    | libc::IN_ONLYDIR;

/// The inotify instance and the map from watch descriptor to directory.
struct Watches {
    fd: OwnedFd,
    /// Watch descriptor → (tree index, upper path relative to the tree root).
    map: HashMap<libc::c_int, (usize, PathBuf)>,
}

impl Watches {
    fn new() -> io::Result<Self> {
        // SAFETY: `inotify_init1` has no memory preconditions. It returns a
        // new fd or -1.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let fd = owned_fd(unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) })?;
        Ok(Self {
            fd,
            map: HashMap::new(),
        })
    }

    /// Adds a watch on the open directory `dir`.
    ///
    /// The watch goes through `/proc/self/fd/<n>`, so it is on the directory
    /// that pent opened without a link follow, also when the child replaced
    /// the path in the meantime.
    fn add(&mut self, dir: BorrowedFd<'_>, t: usize, rel: &Path) {
        let path = proc_fd_path(dir, None);
        let Ok(path_c) = c_bytes(path.as_os_str().as_bytes()) else {
            return;
        };
        // SAFETY: the inotify fd is open and `path_c` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let wd =
            unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), path_c.as_ptr(), WATCH_MASK) };
        if wd < 0 {
            tracing::warn!(
                "cannot watch an overlay directory ({}): {}; \
                 its changes are flushed at teardown",
                rel.display(),
                last_err()
            );
            return;
        }
        self.map.insert(wd, (t, rel.to_path_buf()));
    }
}

/// Start the inotify watcher thread.
///
/// Watches each `upper_dir` in `overlays` (recursively) for `IN_CLOSE_WRITE`,
/// `IN_MOVED_TO`, `IN_MOVED_FROM`, `IN_CREATE`, `IN_ATTRIB`, and `IN_DELETE`
/// events.  A file is flushed to the real filesystem when it matches an entry
/// in `write_set` OR lives inside a directory listed in `rw_dirs`.
///
/// `rw_dirs` should contain every directory-type path from the `read_write`
/// config — i.e. all entries that `is_dir()` at spawn time.  All files created
/// or modified inside those directories during the session are flushed back.
///
/// `child_pid` is the PID of the sandboxed child. Pent reads its user
/// namespace now, so that [`teardown`] can wait for all processes of the
/// session. This works only when the process is a child subreaper (see
/// [`enable_child_subreaper`]).
///
/// Returns an [`OverlayHandle`] that must be passed to [`teardown`] after the
/// sandboxed child process exits.
pub fn spawn_watcher(
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
    rw_dirs: HashSet<PathBuf>,
    child_pid: u32,
) -> OverlayHandle {
    let session = identify_session(child_pid);
    let engine = FlushEngine::for_overlays(&overlays, write_set.clone(), rw_dirs.clone());
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let worker = match std::thread::Builder::new()
        .name("pent-overlay".to_string())
        .spawn(move || run_watcher(engine, &shutdown_rx))
    {
        Ok(thread) => Worker::Thread {
            shutdown_tx,
            thread,
        },
        Err(e) => {
            tracing::warn!(
                "cannot start the overlay watcher thread: {e}; edits are flushed at teardown"
            );
            Worker::Inline(Box::new(FlushEngine::for_overlays(
                &overlays,
                write_set.clone(),
                rw_dirs.clone(),
            )))
        }
    };
    OverlayHandle {
        worker,
        overlays,
        write_set,
        rw_dirs,
        session,
    }
}

/// Reads all pending inotify events and handles them.
///
/// Returns `true` when the kernel reported `IN_Q_OVERFLOW`.
fn drain_events(engine: &mut FlushEngine, watches: &mut Watches, buf: &mut [u8]) -> bool {
    let event_hdr = std::mem::size_of::<libc::inotify_event>();
    let mut overflow = false;
    loop {
        // SAFETY: the inotify fd is open and `buf` is writable for
        // `buf.len()` bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe {
            libc::read(
                watches.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = last_err();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {}
                _ => tracing::warn!("cannot read overlay inotify events: {e}"),
            }
            return overflow;
        }
        let Ok(n) = usize::try_from(n) else {
            return overflow;
        };
        if n == 0 {
            return overflow;
        }

        let mut offset = 0usize;
        while let Some(hdr) = offset
            .checked_add(event_hdr)
            .filter(|end| *end <= n)
            .and_then(|end| buf.get(offset..end))
        {
            // SAFETY: `hdr` has exactly `size_of::<inotify_event>()` bytes.
            // `read_unaligned` copies them and has no alignment requirement.
            // `inotify_event` is plain old data, so any bytes are valid.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let event: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(hdr.as_ptr().cast::<libc::inotify_event>()) };
            let name_start = offset + event_hdr;
            let Some(name_end) = usize::try_from(event.len)
                .ok()
                .and_then(|len| name_start.checked_add(len))
                .filter(|end| *end <= n)
            else {
                break;
            };
            offset = name_end;
            let name_bytes = buf.get(name_start..name_end).unwrap_or_default();
            let name_len = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name = OsStr::from_bytes(name_bytes.get(..name_len).unwrap_or_default());

            if event.mask & libc::IN_Q_OVERFLOW != 0 {
                tracing::warn!(
                    "the overlay inotify queue overflowed; pent rescans the upper layer"
                );
                overflow = true;
                continue;
            }
            if event.mask & libc::IN_IGNORED != 0 {
                watches.map.remove(&event.wd);
                continue;
            }
            if name.is_empty() {
                continue;
            }
            let Some((t, rel_dir)) = watches.map.get(&event.wd).cloned() else {
                continue;
            };
            let rel = rel_dir.join(name);
            engine.reconcile(t, &rel, Phase::Live);
            if event.mask & libc::IN_ISDIR != 0
                && event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0
            {
                // A new directory: watch it and flush the files that are
                // already in it. They can arrive before the watch exists.
                engine.walk(t, &rel, Phase::Live, Some(watches), MAX_WALK_DEPTH);
            }
        }
    }
}

fn run_watcher(
    mut engine: FlushEngine,
    shutdown_rx: &std::sync::mpsc::Receiver<()>,
) -> FlushEngine {
    let mut watches = match Watches::new() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("inotify is not available ({e}); edits are flushed at teardown");
            return engine;
        }
    };
    // The first walk adds the watches and flushes what the child wrote
    // before the watches existed.
    engine.resync(Some(&mut watches), Phase::Live);

    // Room for many events with names of up to NAME_MAX bytes.
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        match shutdown_rx.try_recv() {
            Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }

        let mut pfd = libc::pollfd {
            fd: watches.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid `pollfd` and the count is 1.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::poll(&raw mut pfd, 1, 50 /* ms */)
        };
        if ret > 0
            && (pfd.revents & libc::POLLIN) != 0
            && drain_events(&mut engine, &mut watches, &mut buf)
        {
            engine.resync(Some(&mut watches), Phase::Live);
        }
        engine.process_settled(Instant::now(), false);
    }
    engine
}

// ─────────────────────────────────────────────────────────────────────────────
// Session processes
// ─────────────────────────────────────────────────────────────────────────────

/// Makes the current process a child subreaper (`PR_SET_CHILD_SUBREAPER`).
///
/// When a process of the sandbox session loses its parent, the kernel then
/// gives it to pent instead of to init. [`teardown`] needs this to wait
/// until no process of the session can write to the overlay. The setting
/// applies to the whole process.
///
/// # Errors
///
/// Returns the `errno` of `prctl`.
pub fn enable_child_subreaper() -> io::Result<()> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes one integer argument and changes
    // only an attribute of the calling process.
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_CHILD_SUBREAPER,
            libc::c_ulong::from(1u8),
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        return Err(last_err());
    }
    Ok(())
}

fn is_child_subreaper() -> bool {
    let mut value: libc::c_int = 0;
    // SAFETY: PR_GET_CHILD_SUBREAPER writes one `c_int` to the pointer, and
    // `value` is valid and writable for the call.
    let ret = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut value) };
    ret == 0 && value != 0
}

fn ns_id(fd: BorrowedFd<'_>) -> io::Result<NsId> {
    let st = fstat_fd(fd)?;
    Ok(NsId {
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

fn open_user_ns(pid: Option<libc::pid_t>) -> io::Result<OwnedFd> {
    let path = pid.map_or_else(
        || PathBuf::from("/proc/self/ns/user"),
        |pid| PathBuf::from(format!("/proc/{pid}/ns/user")),
    );
    open_path(&path, libc::O_RDONLY)
}

/// Reads the namespaces that identify the session of `child_pid`.
fn identify_session(child_pid: u32) -> Option<Session> {
    if !is_child_subreaper() {
        tracing::warn!(
            "pent is not a child subreaper; teardown cannot wait for \
             background processes of the sandbox"
        );
        return None;
    }
    let child_pid = libc::pid_t::try_from(child_pid).ok()?;
    let own_ns = open_user_ns(None).and_then(|fd| ns_id(fd.as_fd())).ok()?;
    let user_ns = match open_user_ns(Some(child_pid)).and_then(|fd| ns_id(fd.as_fd())) {
        Ok(ns) => ns,
        Err(e) => {
            tracing::warn!("cannot read the user namespace of the sandbox: {e}");
            return None;
        }
    };
    if user_ns == own_ns {
        // Without a separate user namespace, pent cannot tell the session
        // processes from other children. Do not wait.
        return None;
    }
    Some(Session {
        child_pid,
        user_ns,
        own_ns,
    })
}

/// `NS_GET_PARENT` from `<linux/nsfs.h>`: `_IO(0xb7, 0x2)`.
const NS_GET_PARENT: libc::Ioctl = 0xb702;

/// Returns `true` if the user namespace of `pid` is `session.user_ns` or a
/// descendant of it.
fn in_session_ns(pid: libc::pid_t, session: &Session) -> bool {
    let Ok(mut fd) = open_user_ns(Some(pid)) else {
        return false;
    };
    // The kernel limits the nesting of user namespaces to 32 levels.
    for _ in 0..33 {
        let Ok(id) = ns_id(fd.as_fd()) else {
            return false;
        };
        if id == session.user_ns {
            return true;
        }
        if id == session.own_ns {
            return false;
        }
        // SAFETY: `fd` is an open nsfs fd. NS_GET_PARENT takes no argument
        // and returns a new fd or -1.
        let parent = unsafe { libc::ioctl(fd.as_raw_fd(), NS_GET_PARENT) };
        match owned_fd(parent) {
            Ok(parent) => fd = parent,
            Err(_) => return false,
        }
    }
    false
}

/// Lists the direct children of the current process.
fn list_children() -> Vec<libc::pid_t> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return out;
    };
    for task in tasks.flatten() {
        if let Ok(list) = std::fs::read_to_string(task.path().join("children")) {
            out.extend(
                list.split_whitespace()
                    .filter_map(|p| p.parse::<libc::pid_t>().ok()),
            );
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Returns `true` if `pid` is a zombie (it exited, but nobody reaped it).
///
/// A zombie has no mount namespace any more, so it cannot write.
fn is_zombie(pid: libc::pid_t) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true;
    };
    stat.rfind(')')
        .and_then(|i| stat.get(i + 1..))
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|state| state == "Z" || state == "X")
}

/// Waits until no process of the session is alive.
///
/// Background processes of the session become children of pent when their
/// parent exits (pent is a child subreaper). This function reaps them. When
/// they do not exit in `grace`, it sends `SIGKILL` to them. It never reaps
/// the direct child; the caller owns that `Child` handle.
///
/// Returns the number of processes that got `SIGKILL`.
fn wait_for_session(session: &Session, grace: Duration) -> usize {
    let start = Instant::now();
    let mut killed: HashSet<libc::pid_t> = HashSet::new();
    loop {
        let live: Vec<libc::pid_t> = list_children()
            .into_iter()
            .filter(|&pid| pid == session.child_pid || in_session_ns(pid, session))
            .filter(|&pid| {
                if !is_zombie(pid) {
                    return true;
                }
                if pid != session.child_pid {
                    let mut status: libc::c_int = 0;
                    // SAFETY: `pid` is a child of this process, so waitpid
                    // cannot affect another process. `status` is writable.
                    let _reaped = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
                }
                false
            })
            .collect();
        if live.is_empty() {
            break;
        }
        let elapsed = start.elapsed();
        if elapsed >= grace.saturating_add(DESCENDANT_KILL_TIMEOUT) {
            tracing::warn!(
                "{} sandbox processes do not exit after SIGKILL; pent continues the teardown",
                live.len()
            );
            break;
        }
        if elapsed >= grace {
            for &pid in &live {
                if killed.insert(pid) {
                    tracing::warn!(
                        "pent stops sandbox process {pid}: it still runs after the command exited"
                    );
                }
                // SAFETY: `pid` is an unreaped child of this process, so the
                // kernel cannot have given the PID to another process.
                if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
                    tracing::debug!("kill({pid}) failed: {}", last_err());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    killed.len()
}

// ─────────────────────────────────────────────────────────────────────────────
// Teardown and cleanup
// ─────────────────────────────────────────────────────────────────────────────

/// Writes the recovery marker into the staging directory of `overlay`.
fn write_recovery_marker(overlay: &OverlayMount) -> io::Result<()> {
    let fd = open_at(
        overlay.base_fd.as_fd(),
        OsStr::new(RECOVERY_MARKER),
        libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_TRUNC,
        0o600,
    )?;
    let mut file = std::fs::File::from(fd);
    io::Write::write_all(
        &mut file,
        b"pent could not save all edits of this session.\nThe upper/ directory contains them.\n",
    )
}

/// Wait for the session, shut down the watcher, do a final flush, and remove
/// the staging directories.
///
/// Call this **after** the sandboxed child process has exited. When pent is
/// a child subreaper, this function first waits until no other process of
/// the session is alive (see [`enable_child_subreaper`]). Background processes
/// that run longer than a grace time get `SIGKILL`.
///
/// When a flush fails, this function keeps the staging directory and lists
/// it in [`OverlayTeardownReport::kept_staging`], so the data stays
/// recoverable.
pub fn teardown(handle: OverlayHandle) -> OverlayTeardownReport {
    let OverlayHandle {
        worker,
        overlays,
        write_set,
        rw_dirs,
        session,
    } = handle;
    let mut report = OverlayTeardownReport::default();

    // The watcher keeps the flush going while pent waits.
    if let Some(session) = &session {
        report.killed_descendants = wait_for_session(session, DESCENDANT_GRACE);
    }

    let mut engine = match worker {
        Worker::Inline(engine) => *engine,
        Worker::Thread {
            shutdown_tx,
            thread,
        } => {
            if shutdown_tx.send(()).is_err() {
                // The thread stopped before; the join below gives its result.
                tracing::debug!("the overlay watcher thread already stopped");
            }
            thread.join().unwrap_or_else(|_| {
                tracing::warn!("the overlay watcher thread panicked; pent rescans the upper layer");
                FlushEngine::for_overlays(&overlays, write_set, rw_dirs)
            })
        }
    };

    report.discarded = engine.final_pass();
    for discarded in &report.discarded {
        tracing::debug!("{discarded}");
    }
    report.failures = engine.take_failures();
    drop(engine);

    for overlay in &overlays {
        if report.failures.is_empty() {
            // Overlayfs mounts are already gone — they existed only inside
            // the mount namespace of the session.
            if let Err(e) = remove_staging_dir(&overlay.base_dir) {
                tracing::warn!("cannot remove '{}': {e}", overlay.base_dir.display());
            }
        } else {
            if let Err(e) = write_recovery_marker(overlay) {
                tracing::warn!("cannot mark '{}' as kept: {e}", overlay.base_dir.display());
            }
            tracing::warn!(
                "pent keeps the unsaved edits in '{}'",
                overlay.upper_dir.display()
            );
            report.kept_staging.push(overlay.upper_dir.clone());
        }
    }
    report
}

/// Returns `true` when the process `pid` that started at `start` is gone.
///
/// Only `ESRCH` from `kill(pid, 0)` means that no process has the PID. When
/// a process has the PID (also with `EPERM`), the start time tells if it is
/// the same process. Without a start time, pent keeps the directory.
fn session_is_dead(pid: libc::pid_t, start: Option<u64>) -> bool {
    // SAFETY: signal 0 only checks if the process exists and if the caller
    // can signal it. It sends nothing.
    if unsafe { libc::kill(pid, 0) } != 0 && last_err().raw_os_error() == Some(libc::ESRCH) {
        return true;
    }
    match (start, process_start_time(pid)) {
        (Some(expected), Some(actual)) => expected != actual,
        _ => false,
    }
}

/// Removes the stale staging directories in `root`.
fn cleanup_stale_in(root: &Path) {
    let root_fd = match open_private_dir(root, RootCreate::Existing) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::debug!("pent does not clean '{}': {e}", root.display());
            return;
        }
    };
    let Ok(entries) = std::fs::read_dir(proc_fd_path(root_fd.as_fd(), None)) else {
        return;
    };
    let uid = current_uid();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some((pid, start)) = parse_staging_name(&name) else {
            continue;
        };
        let Ok(st) = lstat_at(root_fd.as_fd(), &name) else {
            continue;
        };
        if file_type(&st) != libc::S_IFDIR || st.st_uid != uid {
            continue;
        }
        let kept = open_dir_at(root_fd.as_fd(), &name)
            .and_then(|dir| lstat_at(dir.as_fd(), OsStr::new(RECOVERY_MARKER)))
            .is_ok();
        if kept {
            tracing::warn!(
                "unsaved edits of an earlier pent session are in '{}'",
                root.join(&name).join("upper").display()
            );
            continue;
        }
        if session_is_dead(pid, Some(start)) {
            if let Err(e) = remove_staging_dir(&proc_fd_path(root_fd.as_fd(), Some(&name))) {
                tracing::warn!("cannot remove '{}': {e}", root.join(&name).display());
            }
        }
    }
}

/// Remove a staging directory and all its content.
///
/// The kernel creates the overlayfs `work/work` directory with the mode 0000.
/// Thus a plain `remove_dir_all` cannot read it and fails with EACCES. On
/// EACCES, this function gives the owner access to each directory in the
/// tree and tries again. It never follows a symbolic link.
fn remove_staging_dir(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            make_dirs_accessible(path)?;
            std::fs::remove_dir_all(path)
        }
        other => other,
    }
}

/// Set the mode 0700 on `dir` and on each directory below it.
fn make_dirs_accessible(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Ok(());
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            make_dirs_accessible(&entry.path())?;
        }
    }
    Ok(())
}

/// Removes `/tmp/pent-ovl-<pid>-<n>` directories of older pent versions.
fn cleanup_legacy_tmp() {
    let Ok(entries) = std::fs::read_dir("/tmp") else {
        return;
    };
    let uid = current_uid();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix("pent-ovl-"))
            .and_then(|rest| rest.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || std::os::unix::fs::MetadataExt::uid(&meta) != uid {
            continue;
        }
        if session_is_dead(pid, None) {
            if let Err(e) = remove_staging_dir(&path) {
                tracing::warn!("cannot remove '{}': {e}", path.display());
            }
        }
    }
}

/// Remove the staging directories of sessions that stopped before teardown.
///
/// Called once at startup. Pent removes a directory only when the current
/// user owns it and its session process is gone: `kill(pid, 0)` gives
/// `ESRCH`, or the process with that PID has a different start time. Pent
/// keeps directories with unsaved edits and logs their paths.
pub fn cleanup_stale_overlays() {
    for root in staging_root_candidates() {
        cleanup_stale_in(&root);
    }
    cleanup_legacy_tmp();
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        cleanup_stale_in, create_mount, open_path, overlay_roots_for_accessible,
        populate_upper_stubs, process_start_time, set_xattr, spawn_watcher, teardown, DiscardKind,
        FlushEngine, FlushError, Phase, Tree, DELETE_SETTLE, RECOVERY_MARKER, XATTR_WHITEOUT,
    };
    use std::collections::HashSet;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn set(paths: &[&str]) -> HashSet<PathBuf> {
        paths.iter().map(|s| p(s)).collect()
    }

    /// Builds a flush engine over two plain directories (no overlayfs).
    fn engine_for(
        real: &Path,
        upper: &Path,
        write_set: HashSet<PathBuf>,
        rw_dirs: HashSet<PathBuf>,
    ) -> Result<FlushEngine, Box<dyn std::error::Error>> {
        let real_fd = open_path(real, libc::O_PATH | libc::O_DIRECTORY)?;
        let upper_fd = open_path(upper, libc::O_PATH | libc::O_DIRECTORY)?;
        let tree = Tree {
            real_dir: real.to_path_buf(),
            real_fd: Arc::new(real_fd),
            upper_fd: Some(upper_fd),
        };
        Ok(FlushEngine::new(vec![tree], write_set, rw_dirs))
    }

    /// Creates `real/ws` and `upper/ws` in a new temp dir.
    #[test]
    fn remove_staging_dir_handles_mode_zero_work_dir() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir()?;
        let base = tmp.path().join("ovl-1-2-0");
        let inner = base.join("work").join("work");
        std::fs::create_dir_all(inner.join("sub"))?;
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o000))?;
        super::remove_staging_dir(&base)?;
        assert!(!base.exists());
        Ok(())
    }

    fn layout() -> Result<(tempfile::TempDir, PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let real = tmp.path().join("real");
        let upper = tmp.path().join("upper");
        std::fs::create_dir_all(real.join("ws"))?;
        std::fs::create_dir_all(upper.join("ws"))?;
        Ok((tmp, real, upper))
    }

    /// Two files under the same subdirectory collapse to one overlay root —
    /// the minimal common ancestor — not to the home directory itself.
    ///
    /// This is the canonical case: `~/.config/claude.json` and
    /// `~/.config/gemini.toml` must produce a single root `~/.config`,
    /// NOT `~`.  Mounting `~` as an overlay would hide every other home-dir
    /// file, breaking any other tool that reads from home.
    #[test]
    fn two_files_same_subdir_gives_one_root() {
        let home = p("/home/user");
        let accessible = set(&[
            "/home/user/.config/claude.json",
            "/home/user/.config/gemini.toml",
        ]);
        let roots = overlay_roots_for_accessible(&accessible, &home);
        assert_eq!(
            roots,
            vec![p("/home/user/.config")],
            "expected ~/.config as root, not ~ — MCA must not go all the way up to home"
        );
    }

    /// Files in disjoint subdirectories produce two independent overlay roots,
    /// one per subtree.  There is no blanket home-dir overlay.
    #[test]
    fn files_in_different_subdirs_give_separate_roots() {
        let home = p("/home/user");
        let accessible = set(&[
            "/home/user/.config/claude.json",
            "/home/user/.ssh/known_hosts",
        ]);
        let mut roots = overlay_roots_for_accessible(&accessible, &home);
        roots.sort();
        let mut expected = vec![p("/home/user/.config"), p("/home/user/.ssh")];
        expected.sort();
        assert_eq!(roots, expected);
    }

    /// A shallower ancestor dominates a deeper one: if both `~/.config` and
    /// `~/.config/tool/` appear as parents, only `~/.config` is kept.
    #[test]
    fn ancestor_dominates_deeper_descendant() {
        let home = p("/home/user");
        let accessible = set(&[
            "/home/user/.config/claude.json",
            "/home/user/.config/tool/settings.toml",
        ]);
        let roots = overlay_roots_for_accessible(&accessible, &home);
        // Both parents (~/.config and ~/.config/tool) are candidates, but
        // ~/.config/tool is dominated by ~/.config.
        assert_eq!(
            roots,
            vec![p("/home/user/.config")],
            "~/.config/tool should be dominated by ~/.config"
        );
    }

    /// Paths that live outside `home_dir` (system and temp paths) are excluded
    /// from overlay root computation — only the Landlock layer covers them.
    #[test]
    fn system_paths_outside_home_are_excluded() {
        let home = p("/home/user");
        let accessible = set(&[
            "/usr/lib/libfoo.so",
            "/tmp/scratch.txt",
            "/etc/hosts",
            "/proc/self/status",
        ]);
        let roots = overlay_roots_for_accessible(&accessible, &home);
        assert!(
            roots.is_empty(),
            "system / temp paths must not produce overlay roots"
        );
    }

    /// A file directly under home (e.g. `~/.bashrc`) produces `~` as the root.
    #[test]
    fn file_directly_under_home_gives_home_root() {
        let home = p("/home/user");
        let accessible = set(&["/home/user/.bashrc"]);
        let roots = overlay_roots_for_accessible(&accessible, &home);
        assert_eq!(roots, vec![p("/home/user")]);
    }

    /// A mix of home and system paths — only the home paths contribute roots;
    /// system paths are silently ignored.
    #[test]
    fn mix_home_and_system_gives_only_home_roots() {
        let home = p("/home/user");
        let accessible = set(&[
            "/usr/bin/bash",
            "/home/user/.config/tool.cfg",
            "/tmp/work.txt",
        ]);
        let roots = overlay_roots_for_accessible(&accessible, &home);
        assert_eq!(roots, vec![p("/home/user/.config")]);
    }

    /// Three files under two distinct home subdirectories produce exactly two
    /// roots, with no spurious intermediate or parent entries.
    #[test]
    fn three_files_two_subdirs_gives_two_roots() {
        let home = p("/home/user");
        let accessible = set(&[
            "/home/user/.config/claude.json",
            "/home/user/.config/gemini.toml",
            "/home/user/.local/share/app/data.db",
        ]);
        let mut roots = overlay_roots_for_accessible(&accessible, &home);
        roots.sort();
        let mut expected = vec![p("/home/user/.config"), p("/home/user/.local/share/app")];
        expected.sort();
        assert_eq!(roots, expected);
    }

    /// A symbolic link that the child puts in upper/ must not make pent copy
    /// the target. Pent copies neither the content nor the link, and the
    /// report lists the link as discarded. A link to a directory is not
    /// walked.
    #[test]
    fn symlink_in_upper_is_not_followed() -> TestResult {
        let (tmp, real, upper) = layout()?;
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(outside.join("dir"))?;
        std::fs::write(outside.join("id_rsa"), "PRIVATE KEY")?;
        std::fs::write(outside.join("dir/inner"), "INNER")?;
        std::os::unix::fs::symlink(outside.join("id_rsa"), upper.join("ws/k"))?;
        std::os::unix::fs::symlink(outside.join("dir"), upper.join("ws/d"))?;

        let mut engine = engine_for(&real, &upper, HashSet::new(), [real.join("ws")].into())?;
        engine.reconcile(0, Path::new("ws/k"), Phase::Live);
        let discarded = engine.final_pass();
        let failures = engine.take_failures();

        assert!(
            std::fs::symlink_metadata(real.join("ws/k")).is_err(),
            "the link target must not be copied to the real filesystem"
        );
        assert!(std::fs::symlink_metadata(real.join("ws/d")).is_err());
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");
        for name in ["ws/k", "ws/d"] {
            assert!(
                discarded
                    .iter()
                    .any(|d| d.path == real.join(name) && d.kind == DiscardKind::Symlink),
                "the report must list {name} as a discarded link: {discarded:?}"
            );
        }
        Ok(())
    }

    /// A symbolic link in the real filesystem (an ancestor directory or the
    /// last component) must stop the flush. Pent must not write through it.
    #[test]
    fn real_symlink_component_is_refused() -> TestResult {
        let (tmp, real, upper) = layout()?;
        let victim = tmp.path().join("victim");
        std::fs::create_dir_all(&victim)?;
        std::fs::write(victim.join("bashrc"), "ORIGINAL")?;
        std::os::unix::fs::symlink(&victim, real.join("ws/link"))?;
        std::os::unix::fs::symlink(victim.join("bashrc"), real.join("ws/t.txt"))?;
        std::fs::create_dir_all(upper.join("ws/link"))?;
        std::fs::write(upper.join("ws/link/f.txt"), "PWN")?;
        std::fs::write(upper.join("ws/t.txt"), "PWN")?;

        let mut engine = engine_for(&real, &upper, HashSet::new(), [real.join("ws")].into())?;
        let _discarded = engine.final_pass();
        let failures = engine.take_failures();

        assert!(
            !victim.join("f.txt").exists(),
            "write escaped through a dir link"
        );
        assert_eq!(std::fs::read_to_string(victim.join("bashrc"))?, "ORIGINAL");
        assert!(
            failures.iter().any(|f| f.path == real.join("ws/t.txt")),
            "the flush through the file link must fail: {failures:?}"
        );
        assert!(
            failures
                .iter()
                .any(|f| f.path.starts_with(real.join("ws/link"))),
            "the flush through the dir link must fail: {failures:?}"
        );
        assert!(
            failures
                .iter()
                .all(|f| matches!(f.error, FlushError::SymlinkInPath)),
            "all failures must be SymlinkInPath: {failures:?}"
        );
        Ok(())
    }

    /// A new file gets the mode of the upper file at creation time. An
    /// existing file keeps its inode, gets the new mode, the new length and
    /// the modification time of the upper file.
    #[test]
    fn flush_preserves_mode_inode_and_mtime() -> TestResult {
        let (_tmp, real, upper) = layout()?;
        std::fs::write(upper.join("ws/secret"), "S")?;
        std::fs::set_permissions(
            upper.join("ws/secret"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        std::fs::write(upper.join("ws/tool"), "#!/bin/sh\n")?;
        std::fs::set_permissions(
            upper.join("ws/tool"),
            std::fs::Permissions::from_mode(0o755),
        )?;

        std::fs::write(real.join("ws/existing"), "a long old content")?;
        std::fs::set_permissions(
            real.join("ws/existing"),
            std::fs::Permissions::from_mode(0o644),
        )?;
        let ino = std::fs::metadata(real.join("ws/existing"))?.ino();
        std::fs::write(upper.join("ws/existing"), "new")?;
        std::fs::set_permissions(
            upper.join("ws/existing"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(upper.join("ws/existing"))?
            .set_modified(mtime)?;

        let mut engine = engine_for(&real, &upper, HashSet::new(), [real.join("ws")].into())?;
        let _discarded = engine.final_pass();
        let failures = engine.take_failures();
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");

        let mode = |name: &str| -> std::io::Result<u32> {
            Ok(std::fs::metadata(real.join(name))?.permissions().mode() & 0o7777)
        };
        assert_eq!(mode("ws/secret")?, 0o600);
        assert_eq!(mode("ws/tool")?, 0o755);
        assert_eq!(mode("ws/existing")?, 0o600);
        let meta = std::fs::metadata(real.join("ws/existing"))?;
        assert_eq!(meta.ino(), ino, "the flush must keep the inode");
        assert_eq!(std::fs::read_to_string(real.join("ws/existing"))?, "new");
        assert_eq!(meta.modified()?, mtime);
        Ok(())
    }

    /// After a lost event (as after `IN_Q_OVERFLOW`), the resync flushes the
    /// new file and deletes the flushed temp file that left upper/.
    #[test]
    fn overflow_resync_reconciles_lost_events() -> TestResult {
        let (_tmp, real, upper) = layout()?;
        let mut engine = engine_for(&real, &upper, HashSet::new(), [real.join("ws")].into())?;

        std::fs::write(upper.join("ws/file.rs.tmp.1"), "data")?;
        engine.reconcile(0, Path::new("ws/file.rs.tmp.1"), Phase::Live);
        assert!(real.join("ws/file.rs.tmp.1").exists());

        // The rename events are lost.
        std::fs::rename(upper.join("ws/file.rs.tmp.1"), upper.join("ws/file.rs"))?;
        engine.resync(None, Phase::Live);
        assert_eq!(std::fs::read_to_string(real.join("ws/file.rs"))?, "data");

        let later = Instant::now()
            .checked_add(DELETE_SETTLE * 2)
            .ok_or("instant overflow")?;
        engine.process_settled(later, false);
        assert!(
            !real.join("ws/file.rs.tmp.1").exists(),
            "the resync must delete the flushed temp file"
        );
        assert!(engine.take_failures().is_empty());
        Ok(())
    }

    /// `mv config.json config.json~` and a new `config.json` must not delete
    /// the real write-listed file. Pent writes the new content into the
    /// same inode.
    #[test]
    fn backup_rename_keeps_write_listed_inode() -> TestResult {
        let (_tmp, real, upper) = layout()?;
        let target = real.join("ws/config.json");
        std::fs::write(&target, "old")?;
        let ino = std::fs::metadata(&target)?.ino();

        // State after the rename: a backup copy and a whiteout.
        std::fs::write(upper.join("ws/config.json~"), "old")?;
        std::fs::write(upper.join("ws/config.json"), "")?;
        if set_xattr(&upper.join("ws/config.json"), XATTR_WHITEOUT, b"").is_err() {
            eprintln!("skip: the filesystem of the temp dir has no user xattrs");
            return Ok(());
        }

        let mut engine = engine_for(&real, &upper, [target.clone()].into(), HashSet::new())?;
        engine.reconcile(0, Path::new("ws/config.json"), Phase::Live);
        let later = Instant::now()
            .checked_add(Duration::from_secs(3600))
            .ok_or("instant overflow")?;
        engine.process_settled(later, false);
        assert!(
            target.exists(),
            "a write-listed file must not be deleted during the session"
        );

        // The editor writes the new file.
        std::fs::remove_file(upper.join("ws/config.json"))?;
        std::fs::write(upper.join("ws/config.json"), "new")?;
        engine.reconcile(0, Path::new("ws/config.json"), Phase::Live);
        let discarded = engine.final_pass();

        assert_eq!(std::fs::read_to_string(&target)?, "new");
        assert_eq!(
            std::fs::metadata(&target)?.ino(),
            ino,
            "the inode must not change"
        );
        assert!(
            discarded
                .iter()
                .any(|d| d.path == real.join("ws/config.json~") && d.kind == DiscardKind::Write),
            "the backup is not write-listed and must be reported: {discarded:?}"
        );
        Ok(())
    }

    /// A whiteout that is still there at teardown deletes the real file.
    #[test]
    fn whiteout_at_teardown_deletes_write_listed_file() -> TestResult {
        let (_tmp, real, upper) = layout()?;
        let target = real.join("ws/config.json");
        std::fs::write(&target, "old")?;
        std::fs::write(upper.join("ws/config.json"), "")?;
        if set_xattr(&upper.join("ws/config.json"), XATTR_WHITEOUT, b"").is_err() {
            eprintln!("skip: the filesystem of the temp dir has no user xattrs");
            return Ok(());
        }
        let mut engine = engine_for(&real, &upper, [target.clone()].into(), HashSet::new())?;
        engine.reconcile(0, Path::new("ws/config.json"), Phase::Live);
        assert!(target.exists());
        let _discarded = engine.final_pass();
        assert!(!target.exists(), "teardown must apply the deletion");
        Ok(())
    }

    /// The watcher thread flushes a new file during the session, and
    /// teardown removes the staging directory when all edits are saved.
    #[test]
    fn watcher_flushes_and_teardown_cleans_up() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let real = tmp.path().join("real");
        let staging = tmp.path().join("staging");
        std::fs::create_dir_all(real.join("ws"))?;
        std::fs::create_dir_all(&staging)?;
        let staging_fd = open_path(&staging, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let mount = create_mount(&real, &staging, staging_fd.as_fd(), "ovl-1-1-0")?;
        std::fs::create_dir_all(mount.upper_dir.join("ws"))?;
        let upper = mount.upper_dir.clone();
        let base = mount.base_dir.clone();

        let handle = spawn_watcher(
            vec![mount],
            HashSet::new(),
            [real.join("ws")].into(),
            std::process::id(),
        );
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(upper.join("ws/new.txt"), "hello")?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !real.join("ws/new.txt").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            real.join("ws/new.txt").exists(),
            "the watcher must flush during the session"
        );

        let report = teardown(handle);
        assert!(
            report.all_saved(),
            "unexpected failures: {:?}",
            report.failures
        );
        assert!(!base.exists(), "teardown must remove the staging directory");
        Ok(())
    }

    /// Pent never reuses a staging leaf that exists.
    #[test]
    fn staging_leaf_is_never_reused() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real)?;
        let staging_fd = open_path(tmp.path(), libc::O_RDONLY | libc::O_DIRECTORY)?;
        let first = create_mount(&real, tmp.path(), staging_fd.as_fd(), "ovl-1-1-0");
        assert!(first.is_ok());
        let second = create_mount(&real, tmp.path(), staging_fd.as_fd(), "ovl-1-1-0");
        assert!(
            matches!(&second, Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "an existing leaf must be refused"
        );
        Ok(())
    }

    /// The stub population fails closed at the depth limit.
    #[test]
    fn stub_depth_limit_fails_closed() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let result = populate_upper_stubs(tmp.path(), tmp.path(), &HashSet::new(), false, 0);
        assert!(
            matches!(&result, Err(e) if e.raw_os_error() == Some(libc::ELOOP)),
            "the depth limit must stop the spawn: {result:?}"
        );
        Ok(())
    }

    /// The cleanup removes directories of dead sessions and of reused PIDs.
    /// It keeps live sessions and directories with unsaved edits.
    #[test]
    fn cleanup_stale_overlays_removes_only_dead_sessions() -> TestResult {
        // Fork a child, record its PID, let it exit and reap it.
        // SAFETY: the child calls only `_exit`, which is async-signal-safe.
        let dead_pid = unsafe {
            let pid = libc::fork();
            if pid == 0 {
                libc::_exit(0);
            }
            let mut status = 0i32;
            libc::waitpid(pid, &raw mut status, 0);
            pid
        };
        let own_pid = libc::pid_t::try_from(std::process::id())?;
        let own_start = process_start_time(own_pid).ok_or("no start time")?;

        let root = tempfile::tempdir()?;
        let stale = root.path().join(format!("ovl-{dead_pid}-1-0"));
        let live = root.path().join(format!("ovl-{own_pid}-{own_start}-0"));
        let reused = root
            .path()
            .join(format!("ovl-{own_pid}-{}-0", own_start + 1));
        let kept = root.path().join(format!("ovl-{dead_pid}-1-1"));
        for dir in [&stale, &live, &reused, &kept] {
            std::fs::create_dir_all(dir.join("upper"))?;
        }
        std::fs::write(kept.join(RECOVERY_MARKER), "")?;

        cleanup_stale_in(root.path());

        assert!(
            !stale.exists(),
            "dead session (PID {dead_pid}) must be removed"
        );
        assert!(
            !reused.exists(),
            "a reused PID with another start time must be removed"
        );
        assert!(live.exists(), "the live session must stay");
        assert!(kept.exists(), "unsaved edits must stay");
        Ok(())
    }
}
