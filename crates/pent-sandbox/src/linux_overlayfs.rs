//! Overlayfs-based file shadowing for write-listed files on Linux.
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
    if unsafe { libc::uname(&mut uts) } != 0 {
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
// xattr helper
// ─────────────────────────────────────────────────────────────────────────────

/// Set an extended attribute on `path`.
fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(std::io::Error::other)?;
    let name_c = CString::new(name).map_err(std::io::Error::other)?;
    let ptr = if value.is_empty() {
        std::ptr::null()
    } else {
        value.as_ptr() as *const libc::c_void
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::setxattr(path_c.as_ptr(), name_c.as_ptr(), ptr, value.len(), 0) };
    if ret != 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
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

    let entries = match std::fs::read_dir(real_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // unreadable dir — skip gracefully
    };

    let mut upper_has_xwhiteouts = false;

    for entry in entries.flatten() {
        let real_path = entry.path();
        let name = entry.file_name();
        let upper_path = upper_dir.join(&name);

        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

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
            if has_accessible_descendant(&real_path, accessible) {
                // Partially accessible: create the dir in upper (no xattr) and recurse.
                let _ = std::fs::create_dir(&upper_path);
                populate_upper_stubs(
                    &real_path,
                    &upper_path,
                    accessible,
                    use_xwhiteout,
                    depth_limit - 1,
                )?;
            } else {
                // No accessible descendants: make the directory opaque.
                // The merged view shows an empty directory; contents return ENOENT.
                let _ = std::fs::create_dir(&upper_path);
                let _ = set_xattr(&upper_path, "user.overlay.opaque", b"y");
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

/// Create staging directories for each unique parent directory of write-listed files.
///
/// Call this from the **parent** process before `Command::spawn()`. The staging
/// directories are created on the host filesystem so they are visible to both
/// the parent (for inotify watching and final flush) and the child (as the
/// overlayfs upper and work directories inside its mount namespace).
///
/// Only parent directories that currently exist on disk get an overlay entry;
/// non-existent parents are skipped.
///
/// `accessible` is the set of paths (files and directories) that the sandboxed
/// process is allowed to read — built from the `read`, `execute`, and `read_write`
/// manifest expansions plus `workspace`, `data_dir`, configured mounts, and
/// system paths.  Any file or directory in `real_dir` that is **not** covered by
/// `accessible` will be stubbed out in `upper/` to prevent reads.
///
/// # Errors
///
/// Returns an error if a staging directory cannot be created.
pub fn prepare_overlay_dirs(
    write_files: &[PathBuf],
    accessible: &HashSet<PathBuf>,
    pid: u32,
) -> std::io::Result<Vec<OverlayMount>> {
    let use_xwhiteout = kernel_supports_xwhiteout();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut mounts = Vec::new();
    let mut idx = 0usize;

    for file_path in write_files {
        let parent = match file_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => continue,
        };
        // Only create overlays for directories that already exist.
        if !parent.is_dir() {
            continue;
        }
        if !seen.insert(parent.clone()) {
            continue; // already seen this parent
        }

        let base_dir = PathBuf::from(format!("/tmp/pent-ovl-{}-{}", pid, idx));
        let upper_dir = base_dir.join("upper");
        let work_dir = base_dir.join("work");
        std::fs::create_dir_all(&upper_dir)?;
        std::fs::create_dir_all(&work_dir)?;

        // Pre-populate upper/ with stubs for non-manifest content.
        // Depth limit of 32 prevents runaway on deeply nested home directories.
        populate_upper_stubs(&parent, &upper_dir, accessible, use_xwhiteout, 32)?;

        mounts.push(OverlayMount { real_dir: parent, upper_dir, work_dir, base_dir });
        idx += 1;
    }

    Ok(mounts)
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
        let real_str = match overlay.real_dir.to_str() {
            Some(s) => s,
            None => continue,
        };
        let upper_str = match overlay.upper_dir.to_str() {
            Some(s) => s,
            None => continue,
        };
        let work_str = match overlay.work_dir.to_str() {
            Some(s) => s,
            None => continue,
        };

        let target = match CString::new(real_str) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // userxattr: use user.overlay.* namespace for opaque/whiteout xattrs,
        // which works in unprivileged user namespaces.
        let options =
            format!("lowerdir={real_str},upperdir={upper_str},workdir={work_str},userxattr");
        let options_c = match CString::new(options) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = libc::mount(
            b"overlay\0".as_ptr() as *const libc::c_char,
            target.as_ptr(),
            b"overlay\0".as_ptr() as *const libc::c_char,
            0,
            options_c.as_ptr() as *const libc::c_void,
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
                "pent: overlayfs mount on '{}' failed: {}\n\
                 pent: hint: check sysctl kernel.unprivileged_userns_clone=1,\n\
                 pent:       user.max_user_namespaces > 0,\n\
                 pent:       and no AppArmor/LSM profile blocking overlay mounts.\n",
                real_str, errno
            );
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            libc::write(
                libc::STDERR_FILENO,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
            );
            return Err(errno);
        }
    }
    Ok(())
}

/// Flush the upper-layer copy of a file back to the real path in-place.
///
/// Opens the real file with `O_WRONLY | O_CREAT | O_TRUNC`. On an existing file
/// this truncates in place — the inode number is unchanged and Landlock's rule
/// bound to it remains valid. On a new file (first write ever) a fresh inode is
/// created, which subsequent pent invocations will cover in their own rulesets.
fn flush_file(upper_path: &Path, real_path: &Path) -> std::io::Result<()> {
    let content = std::fs::read(upper_path)?;
    let mut real_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(real_path)?;
    real_file.write_all(&content)?;
    real_file.sync_data()?;
    Ok(())
}

/// Start the inotify watcher thread.
///
/// Watches each `upper_dir` in `overlays` for `IN_CLOSE_WRITE` and `IN_MOVED_TO`
/// events. When a file matching an entry in `write_set` appears, it is flushed
/// to the corresponding real path in-place, preserving the real inode.
///
/// Returns an [`OverlayHandle`] that must be passed to [`teardown`] after the
/// sandboxed child process exits.
pub fn spawn_watcher(
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
) -> OverlayHandle {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let overlays_thread = overlays.clone();
    let write_set_thread = write_set.clone();
    let thread = std::thread::spawn(move || {
        run_watcher(overlays_thread, write_set_thread, shutdown_rx);
    });
    OverlayHandle { shutdown_tx, thread: Some(thread), overlays, write_set }
}

fn run_watcher(
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
    shutdown_rx: std::sync::mpsc::Receiver<()>,
) {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let inotify_fd =
        unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        // inotify unavailable; final flush on teardown is the fallback.
        return;
    }

    // Map watch descriptor → overlay index.
    let mut wd_map: HashMap<libc::c_int, usize> = HashMap::new();
    for (i, overlay) in overlays.iter().enumerate() {
        let path = match CString::new(overlay.upper_dir.to_str().unwrap_or("")) {
            Ok(p) => p,
            Err(_) => continue,
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let wd = unsafe {
            libc::inotify_add_watch(
                inotify_fd,
                path.as_ptr(),
                libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
            )
        };
        if wd >= 0 {
            wd_map.insert(wd, i);
        }
    }

    let event_hdr = std::mem::size_of::<libc::inotify_event>();
    // Buffer sized for the event header plus up to 255 filename bytes + NUL.
    let mut buf = vec![0u8; 4096];

    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        let mut pfd =
            libc::pollfd { fd: inotify_fd, events: libc::POLLIN, revents: 0 };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::poll(&mut pfd as *mut _, 1, 50 /* ms */) };
        if ret <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            continue;
        }

        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe {
            libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n <= 0 {
            continue;
        }

        let n = n as usize;
        let mut offset = 0usize;

        while offset + event_hdr <= n {
            // SAFETY: verified there are at least event_hdr bytes at offset.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let event =
                unsafe { &*(buf.as_ptr().add(offset) as *const libc::inotify_event) };
            let name_len = event.len as usize;
            if offset + event_hdr + name_len > n {
                break;
            }

            let name_bytes =
                &buf[offset + event_hdr..offset + event_hdr + name_len];
            let name_end =
                name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
            let filename = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");

            if !filename.is_empty() {
                if let Some(&oi) = wd_map.get(&event.wd) {
                    let overlay = &overlays[oi];
                    let upper_file = overlay.upper_dir.join(filename);
                    let real_file = overlay.real_dir.join(filename);
                    if write_set.contains(&real_file) && upper_file.is_file() {
                        let _ = flush_file(&upper_file, &real_file);
                    }
                }
            }

            offset += event_hdr + name_len;
        }
    }

    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(inotify_fd) };
}

fn final_flush_overlay(overlay: &OverlayMount, write_set: &HashSet<PathBuf>) {
    let entries = match std::fs::read_dir(&overlay.upper_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let upper_file = entry.path();
        if !upper_file.is_file() {
            continue;
        }
        let real_file = overlay.real_dir.join(entry.file_name());
        if write_set.contains(&real_file) {
            let _ = flush_file(&upper_file, &real_file);
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
    let OverlayHandle { shutdown_tx, mut thread, overlays, write_set } = handle;
    let _ = shutdown_tx.send(());
    if let Some(t) = thread.take() {
        let _ = t.join();
    }
    // Final flush: catch any writes that arrived between the last inotify event
    // delivery and process exit.
    for overlay in &overlays {
        final_flush_overlay(overlay, &write_set);
    }
    // Clean up staging directories. Overlayfs mounts are already gone —
    // they existed only inside the child's mount namespace.
    for overlay in &overlays {
        let _ = std::fs::remove_dir_all(&overlay.base_dir);
    }
}
