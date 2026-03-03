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
//! 1. Creates staging directories (`upper/` and `work/`) under
//!    `/tmp/pent-ovl-<pid>-N/` in the parent process before fork.
//! 2. Pre-populates `upper/` with stub entries for non-manifest content:
//!    - Directories with no manifest descendants → `user.overlay.opaque=y`
//!      (entire subtree invisible: `ENOENT` on any access).
//!    - Non-manifest files (kernel ≥ 6.7) → zero-size file + `user.overlay.whiteout`
//!      xattr (`ENOENT` on `open`/`stat`; name hidden from `readdir` when parent
//!      has `user.overlay.opaque=x`).
//!    - Non-manifest files (kernel < 6.7) → empty stub file (empty content).
//! 3. In the child's `pre_exec` hook, mounts overlayfs on the parent directory
//!    inside the child's mount namespace (lower = real dir, upper = staging),
//!    using `-o userxattr` so `user.overlay.*` xattrs are honoured.
//! 4. Starts an `inotify` watcher thread in the **parent** that watches `upper/`
//!    for `IN_CLOSE_WRITE` and `IN_MOVED_TO` events.
//! 5. On each matching event for a write-listed file: flushes the upper-layer
//!    content back to the real file **in-place** (`O_WRONLY | O_TRUNC`) — never
//!    via `rename()` — preserving the inode that Landlock is bound to.
//! 6. On child exit, performs a final flush pass then removes staging directories.
//!
//! Inside the child's namespace the process can write freely (writes go to upper);
//! from the real filesystem's perspective only write-listed files are ever modified.
//! Non-manifest files in the overlay parent directory are invisible (`ENOENT`) or
//! empty, depending on kernel version.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    /// Base staging directory (`/tmp/pent-ovl-<pid>-<n>`); removed on teardown.
    pub base_dir: PathBuf,
}

/// Handle for the overlay subsystem returned by [`spawn_watcher`].
pub struct OverlayHandle {
    shutdown_tx: std::sync::mpsc::SyncSender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
    /// Directories from `read_write` config entries (as opposed to individual
    /// files).  All files created or modified inside these directories during
    /// the sandbox session should be flushed back to the real filesystem.
    rw_dirs: HashSet<PathBuf>,
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::uname(&raw mut uts) } != 0 {
        return false;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    let s = release.to_string_lossy();
    let mut parts = s.splitn(3, '.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor) >= (6, 7)
}

// ─────────────────────────────────────────────────────────────────────────────
// xattr helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `path` is an overlayfs whiteout entry (userxattr mode).
///
/// In `-o userxattr` mode the kernel represents whiteouts as zero-size regular
/// files with the `user.overlay.whiteout` extended attribute.  Flushing such a
/// file back to the real filesystem would truncate the real file to zero bytes,
/// which is never the intent — whiteouts are overlay-internal bookkeeping.
fn is_overlay_whiteout(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path_c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let Ok(name_c) = CString::new("user.overlay.whiteout") else {
        return false;
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::getxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
    ret >= 0
}

/// Set an extended attribute on `path`.
fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let name_c = CString::new(name).map_err(std::io::Error::other)?;
    let ptr = if value.is_empty() {
        std::ptr::null()
    } else {
        value.as_ptr().cast::<libc::c_void>()
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::setxattr(path_c.as_ptr(), name_c.as_ptr(), ptr, value.len(), 0) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
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
/// `depth_limit` prevents runaway recursion on unusually deep directory trees.
fn populate_upper_stubs(
    real_dir: &Path,
    upper_dir: &Path,
    accessible: &HashSet<PathBuf>,
    use_xwhiteout: bool,
    depth_limit: u32,
) -> std::io::Result<()> {
    if depth_limit == 0 {
        return Ok(());
    }

    let Ok(entries) = std::fs::read_dir(real_dir) else {
        return Ok(());
    }; // unreadable dir — skip gracefully

    let mut upper_has_xwhiteouts = false;

    for entry in entries.flatten() {
        let real_path = entry.path();
        let name = entry.file_name();
        let upper_path = upper_dir.join(&name);

        let Ok(ft) = entry.file_type() else { continue };

        if ft.is_symlink() {
            // Symlinks that point into an accessible subtree pass through.
            // All others get a whiteout/stub so the child cannot follow them
            // into non-manifest content.
            if accessible.contains(&real_path) || is_in_accessible_subtree(&real_path, accessible) {
                continue; // accessible symlink — lower shows through
            }
            if use_xwhiteout {
                if std::fs::File::create(&upper_path).is_ok() {
                    let _ = set_xattr(&upper_path, "user.overlay.whiteout", b"");
                    upper_has_xwhiteouts = true;
                }
            } else {
                // Kernel < 6.7: empty file stub shadows the symlink.
                let _ = std::fs::File::create(&upper_path);
            }
            continue;
        }

        if ft.is_dir() {
            // Is this directory explicitly accessible or inside an accessible subtree?
            // If so, the lower layer shows through — don't create an upper entry.
            if accessible.contains(&real_path) || is_in_accessible_subtree(&real_path, accessible) {
                continue;
            }

            // Does this directory contain any accessible paths?
            let _ = std::fs::create_dir(&upper_path);
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
                // opaque=y hides lower content at the overlayfs level.
                // mode 0000 adds VFS-level enforcement (EACCES on readdir/chdir).
                let _ = set_xattr(&upper_path, "user.overlay.opaque", b"y");
                let _ = std::fs::set_permissions(
                    &upper_path,
                    <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o000),
                );
            }
        } else if ft.is_file() {
            // Is this file accessible (explicitly listed or within an accessible subtree)?
            if accessible.contains(&real_path) || is_in_accessible_subtree(&real_path, accessible) {
                continue; // Lower shows through.
            }

            // Non-manifest file: hide it.
            if use_xwhiteout {
                // Zero-size file + user.overlay.whiteout → ENOENT on open/stat.
                if std::fs::File::create(&upper_path).is_ok() {
                    let _ = set_xattr(&upper_path, "user.overlay.whiteout", b"");
                    upper_has_xwhiteouts = true;
                }
            } else {
                // Kernel < 6.7 fallback: empty stub (empty content, not ENOENT).
                let _ = std::fs::File::create(&upper_path);
            }
        }
        // Sockets, FIFOs, device files: skip.
    }

    // Mark this directory as containing xwhiteout-format entries.
    // The kernel uses this during readdir to hide the whiteout files from
    // directory listings (requires kernel ≥ 6.7 + -o userxattr).
    if upper_has_xwhiteouts {
        let _ = set_xattr(upper_dir, "user.overlay.opaque", b"x");
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
pub fn prepare_overlay_dirs(
    accessible: &std::collections::HashSet<PathBuf>,
    home_dir: &Path,
    pid: u32,
) -> Vec<OverlayMount> {
    let roots = overlay_roots_for_accessible(accessible, home_dir);
    let mut mounts = Vec::new();
    for (idx, root) in roots.iter().enumerate() {
        if !root.is_dir() {
            continue;
        }
        let base_dir = PathBuf::from(format!("/tmp/pent-ovl-{pid}-{idx}"));
        let upper_dir = base_dir.join("upper");
        let work_dir = base_dir.join("work");
        mounts.push(OverlayMount {
            real_dir: root.clone(),
            upper_dir,
            work_dir,
            base_dir,
        });
    }
    mounts
}

/// Create upper/work directories and populate content stubs.
///
/// Must be called in the child's `pre_exec` hook, **after**
/// `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and UID/GID mapping, and **before**
/// [`mount_overlays`].  Running inside the user namespace ensures the
/// directories and their xattrs are created in the same security context as
/// the overlay mount itself, which is required on kernels ≥ 5.11.
///
/// Any leftover staging directories from a previous crashed run (same PID
/// reuse) are removed first to guarantee a clean upper and work directory.
pub fn setup_overlay_dirs(
    overlays: &[OverlayMount],
    accessible: &HashSet<PathBuf>,
) -> std::io::Result<()> {
    let use_xwhiteout = kernel_supports_xwhiteout();
    for overlay in overlays {
        // Remove any leftovers from a previous crashed run with the same PID.
        let _ = std::fs::remove_dir_all(&overlay.base_dir);
        std::fs::create_dir_all(&overlay.upper_dir)?;
        std::fs::create_dir_all(&overlay.work_dir)?;
        // Pre-populate upper/ with stubs for non-manifest content.
        // Depth limit of 32 prevents runaway on deeply nested home directories.
        populate_upper_stubs(
            &overlay.real_dir,
            &overlay.upper_dir,
            accessible,
            use_xwhiteout,
            32,
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
/// # Safety
///
/// Must be called in a post-fork, single-threaded child process that has already
/// called `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and written the UID/GID mappings.
/// These mounts exist **only** in the child's mount namespace; the parent process
/// sees the original directories untouched.
pub unsafe fn mount_overlays(overlays: &[OverlayMount]) -> std::io::Result<()> {
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
            let errno = std::io::Error::last_os_error();
            let msg = format!(
                "pent: overlayfs mount on '{real_str}' failed: {errno}\n\
                 pent: hint: check sysctl kernel.unprivileged_userns_clone=1,\n\
                 pent:       user.max_user_namespaces > 0,\n\
                 pent:       and no AppArmor/LSM profile blocking overlay mounts.\n"
            );
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            libc::write(
                libc::STDERR_FILENO,
                msg.as_ptr().cast::<libc::c_void>(),
                msg.len(),
            );
            return Err(errno);
        }
    }
    Ok(())
}

/// Delete the real file, propagating a deletion that occurred inside the sandbox.
///
/// Called when a whiteout entry is detected in the upper layer for a path that
/// is in `write_set` or under an `rw_dir`. `NotFound` is treated as success —
/// the file may have been created and deleted entirely within the same session
/// and never flushed to the real filesystem.
fn flush_deletion(real_path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(real_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Flush the upper-layer copy of a file back to the real path in-place.
///
/// Opens the real file with `O_WRONLY | O_CREAT | O_TRUNC`. On an existing file
/// this truncates in place — the inode number is unchanged and Landlock's rule
/// bound to it remains valid. On a new file (first write ever) a fresh inode is
/// created, which subsequent pent invocations will cover in their own rulesets.
fn flush_file(upper_path: &Path, real_path: &Path) -> std::io::Result<()> {
    let content = std::fs::read(upper_path)?;
    let upper_mode = std::fs::metadata(upper_path)
        .map(|m| m.permissions())
        .ok();
    let mut real_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(real_path)?;
    real_file.write_all(&content)?;
    real_file.sync_data()?;
    drop(real_file);
    if let Some(perms) = upper_mode {
        let _ = std::fs::set_permissions(real_path, perms);
    }
    Ok(())
}

/// Start the inotify watcher thread.
///
/// Watches each `upper_dir` in `overlays` (recursively) for `IN_CLOSE_WRITE`,
/// `IN_MOVED_TO`, and `IN_CREATE` events.  A file is flushed to the real
/// filesystem when it matches an entry in `write_set` OR lives inside a
/// directory listed in `rw_dirs`.
///
/// `rw_dirs` should contain every directory-type path from the `read_write`
/// config — i.e. all entries that `is_dir()` at spawn time.  All files created
/// or modified inside those directories during the session are flushed back.
///
/// Returns an [`OverlayHandle`] that must be passed to [`teardown`] after the
/// sandboxed child process exits.
pub fn spawn_watcher(
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
    rw_dirs: HashSet<PathBuf>,
) -> OverlayHandle {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let overlays_thread = overlays.clone();
    let write_set_thread = write_set.clone();
    let rw_dirs_thread = rw_dirs.clone();
    let thread = std::thread::spawn(move || {
        run_watcher(
            overlays_thread,
            write_set_thread,
            rw_dirs_thread,
            shutdown_rx,
        );
    });
    OverlayHandle {
        shutdown_tx,
        thread: Some(thread),
        overlays,
        write_set,
        rw_dirs,
    }
}

/// Add an inotify watch on `upper_dir` and recurse into all existing
/// subdirectories (up to `depth` levels).  Each watch descriptor is mapped to
/// the corresponding `(upper_dir, real_dir)` pair so that event filenames can
/// be resolved to both their upper-layer and real-filesystem paths.
fn add_inotify_watches(
    inotify_fd: libc::c_int,
    upper_dir: &Path,
    real_dir: &Path,
    wd_map: &mut HashMap<libc::c_int, (PathBuf, PathBuf)>,
    depth: u32,
) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path_c) = CString::new(upper_dir.as_os_str().as_bytes()) else {
        return;
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            path_c.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE,
        )
    };
    if wd >= 0 {
        wd_map.insert(wd, (upper_dir.to_path_buf(), real_dir.to_path_buf()));
    }

    if depth == 0 {
        return;
    }

    let Ok(entries) = std::fs::read_dir(upper_dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            let name = entry.file_name();
            add_inotify_watches(
                inotify_fd,
                &upper_dir.join(&name),
                &real_dir.join(&name),
                wd_map,
                depth - 1,
            );
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // Vec/HashSet/Receiver must be owned for thread
fn run_watcher(
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
    rw_dirs: HashSet<PathBuf>,
    shutdown_rx: std::sync::mpsc::Receiver<()>,
) {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        // inotify unavailable; final flush on teardown is the fallback.
        return;
    }

    // Map watch descriptor → (upper_dir, real_dir).  Covers both the overlay
    // root and any subdirectories added recursively at startup or at runtime
    // when the sandbox creates new directories.
    let mut wd_map: HashMap<libc::c_int, (PathBuf, PathBuf)> = HashMap::new();
    for overlay in &overlays {
        add_inotify_watches(
            inotify_fd,
            &overlay.upper_dir,
            &overlay.real_dir,
            &mut wd_map,
            8,
        );
    }

    let event_hdr = std::mem::size_of::<libc::inotify_event>();
    // Buffer sized for the event header plus up to 255 filename bytes + NUL.
    let mut buf = vec![0u8; 4096];

    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        let mut pfd = libc::pollfd {
            fd: inotify_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::poll(&raw mut pfd, 1, 50 /* ms */)
        };
        if ret <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            continue;
        }

        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe {
            libc::read(
                inotify_fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n <= 0 {
            continue;
        }

        let n = n.cast_unsigned();
        let mut offset = 0usize;

        while offset + event_hdr <= n {
            // SAFETY: verified there are at least event_hdr bytes at offset.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            #[allow(clippy::cast_ptr_alignment)] // inotify buffer is properly aligned
            let event = unsafe { &*(buf.as_ptr().add(offset).cast::<libc::inotify_event>()) };
            let name_len = event.len as usize;
            if offset + event_hdr + name_len > n {
                break;
            }

            let name_bytes = &buf[offset + event_hdr..offset + event_hdr + name_len];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
            let filename = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");

            if !filename.is_empty() {
                if let Some((upper_dir, real_dir)) = wd_map.get(&event.wd).cloned() {
                    let upper_path = upper_dir.join(filename);
                    let real_path = real_dir.join(filename);

                    if (event.mask & libc::IN_ISDIR) != 0 {
                        // The sandbox created or renamed a directory into place.
                        // Add a watch so we catch writes to files inside it.
                        if (event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0 {
                            add_inotify_watches(
                                inotify_fd,
                                &upper_path,
                                &real_path,
                                &mut wd_map,
                                4,
                            );
                            // Flush any files already present in the new directory.
                            // This handles the race where IN_CLOSE_WRITE fires for a
                            // file written immediately after mkdir — before our watcher
                            // thread woke up and added the watch on the new directory.
                            flush_upper_recursive(&upper_path, &real_path, &write_set, &rw_dirs);
                        }
                    } else {
                        // File write/rename/delete event: flush if in write_set or under an rw_dir.
                        let under_rw = rw_dirs.iter().any(|d| real_path.starts_with(d));
                        if (write_set.contains(&real_path) || under_rw) && upper_path.is_file() {
                            if is_overlay_whiteout(&upper_path) {
                                // The sandbox deleted this file — propagate to real FS.
                                let _ = flush_deletion(&real_path);
                            } else {
                                // Ensure parent directory exists on real FS.
                                // The sandbox may have created new subdirectories under
                                // an rw_dir; without this, flush_file returns ENOENT.
                                if let Some(parent) = real_path.parent() {
                                    if !parent.exists() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                }
                                let _ = flush_file(&upper_path, &real_path);
                            }
                        }
                    }
                }
            }

            offset += event_hdr + name_len;
        }
    }

    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(inotify_fd) };
}

fn final_flush_overlay(
    overlay: &OverlayMount,
    write_set: &HashSet<PathBuf>,
    rw_dirs: &HashSet<PathBuf>,
) {
    flush_upper_recursive(&overlay.upper_dir, &overlay.real_dir, write_set, rw_dirs);
}

/// Recursively walk the upper layer and flush file changes back to the real filesystem.
///
/// For each file whose real path is in `write_set` or under an `rw_dir`:
/// - Regular file: content is flushed back in-place.
/// - Overlay whiteout (deletion): the real file is removed.
///
/// New directories created by the sandbox process are created on the real
/// filesystem as needed before their contents are flushed.
fn flush_upper_recursive(
    upper_dir: &Path,
    real_dir: &Path,
    write_set: &HashSet<PathBuf>,
    rw_dirs: &HashSet<PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(upper_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let upper_path = entry.path();
        let real_path = real_dir.join(entry.file_name());
        if upper_path.is_file() {
            let under_rw = rw_dirs.iter().any(|d| real_path.starts_with(d));
            if write_set.contains(&real_path) || under_rw {
                if is_overlay_whiteout(&upper_path) {
                    // The sandbox deleted this file — propagate to real FS.
                    let _ = flush_deletion(&real_path);
                } else {
                    // Ensure the parent directory exists on the real filesystem.
                    // The sandbox may have created new subdirectories under an rw_dir.
                    if let Some(parent) = real_path.parent() {
                        if !parent.exists() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                    }
                    let _ = flush_file(&upper_path, &real_path);
                }
            }
        } else if upper_path.is_dir() {
            // If this directory is new (doesn't exist on the real FS) and is
            // inside an rw_dir, create it so files within can be flushed.
            let under_rw = rw_dirs
                .iter()
                .any(|d| real_path.starts_with(d) || *d == real_path);
            if under_rw && !real_path.exists() {
                let _ = std::fs::create_dir_all(&real_path);
            }
            flush_upper_recursive(&upper_path, &real_path, write_set, rw_dirs);
        }
    }
}

/// Shut down the watcher, perform a final flush, and remove staging directories.
///
/// Call this **after** the sandboxed child process has exited. The child's mount
/// namespace (and all overlayfs mounts within it) are destroyed when the child
/// exits; this function only handles staging directory cleanup and ensures any
/// writes not caught by inotify are flushed to the real inodes.
pub fn teardown(handle: OverlayHandle) {
    let OverlayHandle {
        shutdown_tx,
        mut thread,
        overlays,
        write_set,
        rw_dirs,
    } = handle;
    let _ = shutdown_tx.send(());
    if let Some(t) = thread.take() {
        let _ = t.join();
    }
    // Final flush: catch any writes that arrived between the last inotify event
    // delivery and process exit.
    for overlay in &overlays {
        final_flush_overlay(overlay, &write_set, &rw_dirs);
    }
    // Clean up staging directories. Overlayfs mounts are already gone —
    // they existed only inside the child's mount namespace.
    for overlay in &overlays {
        let _ = std::fs::remove_dir_all(&overlay.base_dir);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::overlay_roots_for_accessible;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn set(paths: &[&str]) -> HashSet<PathBuf> {
        paths.iter().map(|s| p(s)).collect()
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
}
