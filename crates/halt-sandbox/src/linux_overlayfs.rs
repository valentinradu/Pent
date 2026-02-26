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
//!    `/tmp/halt-ovl-<pid>-N/` in the parent process before fork.
//! 2. In the child's `pre_exec` hook, mounts overlayfs on the parent directory
//!    inside the child's mount namespace (lower = real dir, upper = tmpfs staging).
//! 3. Starts an `inotify` watcher thread in the **parent** that watches `upper/`
//!    for `IN_CLOSE_WRITE` and `IN_MOVED_TO` events.
//! 4. On each matching event for a write-listed file: flushes the upper-layer
//!    content back to the real file **in-place** (`O_WRONLY | O_TRUNC`) — never
//!    via `rename()` — preserving the inode that Landlock is bound to.
//! 5. On child exit, performs a final flush pass then removes staging directories.
//!
//! Inside the child's namespace the process can write freely (writes go to upper);
//! from the real filesystem's perspective only write-listed files are ever modified.

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
    /// Base staging directory (`/tmp/halt-ovl-<pid>-<n>`); removed on teardown.
    pub base_dir: PathBuf,
}

/// Handle for the overlay subsystem returned by [`spawn_watcher`].
pub struct OverlayHandle {
    shutdown_tx: std::sync::mpsc::SyncSender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
    overlays: Vec<OverlayMount>,
    write_set: HashSet<PathBuf>,
}

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
/// # Errors
///
/// Returns an error if a staging directory cannot be created.
pub fn prepare_overlay_dirs(
    write_files: &[PathBuf],
    pid: u32,
) -> std::io::Result<Vec<OverlayMount>> {
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

        let base_dir = PathBuf::from(format!("/tmp/halt-ovl-{}-{}", pid, idx));
        let upper_dir = base_dir.join("upper");
        let work_dir = base_dir.join("work");
        std::fs::create_dir_all(&upper_dir)?;
        std::fs::create_dir_all(&work_dir)?;

        mounts.push(OverlayMount { real_dir: parent, upper_dir, work_dir, base_dir });
        idx += 1;
    }

    Ok(mounts)
}

/// Mount overlayfs for each entry in `overlays`.
///
/// # Safety
///
/// Must be called in a post-fork, single-threaded child process that has already
/// called `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and written the UID/GID mappings.
/// These mounts exist **only** in the child's mount namespace; the parent process
/// sees the original directories untouched.
///
/// If overlayfs is unavailable (kernel module not loaded) or a mount fails for a
/// non-fatal reason (`ENODEV`, `ENOSYS`, `EPERM`), the error is silently ignored
/// and the sandbox continues without inode protection for that directory.
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
        let options =
            format!("lowerdir={real_str},upperdir={upper_str},workdir={work_str}");
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
            let err = std::io::Error::last_os_error();
            // Non-fatal: overlayfs module not loaded, or unprivileged user
            // namespaces disabled. Skip gracefully — sandbox runs without inode
            // protection for this directory.
            match err.raw_os_error() {
                Some(libc::ENODEV) | Some(libc::ENOSYS) | Some(libc::EPERM) => continue,
                _ => return Err(err),
            }
        }
    }
    Ok(())
}

/// Flush the upper-layer copy of a file back to the real path in-place.
///
/// Opens the real file with `O_WRONLY | O_CREAT | O_TRUNC`. On an existing file
/// this truncates in place — the inode number is unchanged and Landlock's rule
/// bound to it remains valid. On a new file (first write ever) a fresh inode is
/// created, which subsequent halt invocations will cover in their own rulesets.
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
