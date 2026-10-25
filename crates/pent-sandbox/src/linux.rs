//! Linux sandbox implementation using Landlock LSM.
// Items in this private module use `pub` so they are accessible through
// `super::linux::*` within the crate.  The `unreachable_pub` lint is
// suppressed because the lint fires on `pub` items in a private module even
// when those items are accessed crate-internally.
#![allow(unreachable_pub)]
//!
//! Uses Landlock for filesystem access control. Pent requires Landlock ABI v3
//! (Linux 6.2) and uses the highest ABI up to v6 (see `linux_landlock.rs`).
//!
//! # Namespaces
//!
//! With enforcement, the child always creates a user namespace and a mount
//! namespace (and a network namespace unless the network is `Unrestricted`):
//! - `LocalhostOnly`: new network namespace, the child brings up loopback.
//! - `ProxyOnly`: new network namespace; the parent moves a veth into it and
//!   configures it.
//! - `Blocked`: new network namespace with no interfaces.
//! - `Unrestricted`: no network namespace.
//!
//! The private mount namespace hides the Unix sockets that Landlock cannot
//! control (`/run/user/<uid>`, the Docker and Podman sockets) and makes
//! `<workspace>/.pent` read-only.
//!
//! # Landlock architecture
//!
//! ```text
//! Ruleset (deny-all baseline)
//!   |
//!   +-- Allow workspace (rw)
//!   +-- Allow data_dir (rw)
//!   +-- Allow mounts (per config)
//!   +-- Allow PATH dirs (read+exec)
//!   +-- Allow execute paths (exec, no read)
//!   +-- Allow read paths (read only)
//!   +-- Allow system libs and /nix/store (read+exec)
//!   +-- Allow /tmp, /var/tmp (rw)
//!   +-- Allow /dev/null, /dev/tty, /dev/pts, ... (rw); /dev/urandom, ... (ro)
//!   +-- Allow /proc (ro)
//! ```
//!
//! # `pre_exec` and async-signal safety
//!
//! The parent is multithreaded. Between `fork` and `exec` the child may only
//! use async-signal-safe functions. Thus the parent prepares all data before
//! `fork`: the Landlock ruleset file descriptor and its rules as C strings,
//! the UID and GID maps, the mount targets and the working directory. The
//! `pre_exec` hook uses only raw system calls on this data. The parent
//! configures the `ProxyOnly` network of the child from a helper thread.
//!
//! The overlayfs helpers (`linux_overlayfs::setup_overlay_dirs` and
//! `mount_overlays`) still allocate in the child. They run only when write
//! listed files need an overlay.
//!
//! # Limits
//!
//! Landlock (ABI v6 and earlier) does not control `connect(2)` on Unix
//! sockets that have a path. A sandboxed process can connect to a socket file
//! that it finds, if the socket is not hidden by a mount. Pent hides only the
//! well-known sockets.

use crate::linux_landlock::{access, PreparedRuleset};
use crate::linux_netns::write_stderr_static;
use crate::{NetworkMode, SandboxConfig, SandboxError};
use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

#[cfg(test)]
/// Minimum required Landlock ABI version.
pub const MIN_LANDLOCK_ABI: u32 = crate::linux_landlock::MIN_ABI;

/// System paths to allow read and execute access (libraries, config, etc.).
///
/// On NixOS, all binaries and libraries live in the immutable, world-readable
/// `/nix/store`. `/run/current-system` points into it. A missing path is
/// skipped.
const SYSTEM_PATHS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/share",
    "/etc",
    "/nix/store",
    "/run/current-system",
];

/// Temp paths to allow read/write access.
const TEMP_PATHS: &[&str] = &["/tmp", "/var/tmp"];

/// Device nodes with read/write access. `/dev/shm` and `/dev/mqueue` are not
/// in the list: add them to the configuration if a tool needs them.
pub(crate) const DEV_RW_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/pts",
    "/dev/ptmx",
];

/// Device nodes with read-only access.
///
/// `/dev/fd` and `/dev/std*` are not in the list: they are symbolic links
/// into `/proc/self/fd`. The `/proc` rule covers the link, and Landlock does
/// not control pipes and sockets that a process opens through it.
pub(crate) const DEV_READ_PATHS: &[&str] = &["/dev/random", "/dev/urandom"];

/// Proc paths to allow read access.
const PROC_PATHS: &[&str] = &["/proc"];

/// Unix sockets that give a way out of the sandbox. The child hides each one
/// that exists with a bind mount of `/dev/null`, unless the configuration
/// names it.
const ESCAPE_SOCKETS: &[&str] = &[
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
];

/// Compute the set of paths the sandboxed process is allowed to read/execute.
///
/// This mirrors the accessible set built inside `spawn_with_landlock` and is used
/// by the filesystem trace watcher (`--no-sandbox --trace`) to determine which
/// file opens would have been denied by the sandbox policy.
#[must_use]
pub fn compute_accessible_set(config: &SandboxConfig, path_dirs: &[PathBuf]) -> HashSet<PathBuf> {
    let (_, read_expanded, execute_expanded, rw_expanded) = config.paths.expand_paths();
    let mut accessible: HashSet<PathBuf> = HashSet::new();
    for (p, _) in read_expanded
        .iter()
        .chain(&execute_expanded)
        .chain(&rw_expanded)
    {
        accessible.insert(p.clone());
    }
    accessible.insert(config.workspace.clone());
    accessible.insert(config.data_dir.clone());
    for mount in &config.mounts {
        accessible.insert(mount.path.clone());
    }
    for p in SYSTEM_PATHS
        .iter()
        .chain(TEMP_PATHS)
        .chain(DEV_RW_PATHS)
        .chain(DEV_READ_PATHS)
        .chain(PROC_PATHS)
    {
        accessible.insert(PathBuf::from(p));
    }
    for path_dir in path_dirs {
        accessible.insert(path_dir.clone());
    }
    accessible
}

/// Check that Landlock is enabled and supports the minimum ABI.
///
/// # Errors
/// Returns `SandboxUnavailable` with a remediation if Landlock is absent,
/// disabled at boot, or too old.
pub fn check_available() -> Result<(), SandboxError> {
    crate::linux_landlock::abi_version().map(|_| ())
}

/// Add all filesystem rules for `config` to `ruleset`.
///
/// * `write_set` - write-listed files that an overlay covers (skipped here;
///   the overlay parent directory rule covers them).
/// * `overlay_dirs` - directories with an overlay mount (read/write).
fn add_ruleset_rules(
    ruleset: &mut PreparedRuleset,
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
    write_set: &HashSet<PathBuf>,
    overlay_dirs: &HashSet<PathBuf>,
) {
    ruleset.add(&config.workspace, access::ALL);
    ruleset.add(&config.data_dir, access::ALL);
    for mount in &config.mounts {
        let a = if mount.readonly {
            access::READ
        } else {
            access::ALL
        };
        ruleset.add(&mount.path, a);
    }

    // Configured SandboxPaths (from profiles and TOML config).
    // traversal = ReadDir only (stat/list, no file reads or exec).
    // read = ReadFile | ReadDir (config files, libraries, data; no exec).
    // execute = ReadDir | Execute (binary directories, installed tools; no ReadFile).
    // read_write = all access rights.
    let (traversal, read, execute, rw) = config.paths.expand_paths();
    for (path, _) in &traversal {
        ruleset.add(path, access::TRAVERSAL);
    }
    for (path, _) in &read {
        ruleset.add(path, access::READ);
    }
    for (path, _) in &execute {
        ruleset.add(path, access::EXECUTE_ONLY);
    }
    for (path, _) in &rw {
        if !write_set.contains(path) {
            ruleset.add(path, access::ALL);
        }
    }
    // Overlay parent directories: inside the namespace, writes go to the
    // upper layer; the watcher of the parent flushes write-listed files.
    for dir in overlay_dirs {
        ruleset.add(dir, access::ALL);
    }
    // PATH directories and system libraries: the dynamic linker must open()
    // binaries and shared libraries, so these get ReadFile too.
    for path_dir in path_dirs {
        ruleset.add(path_dir, access::READ_EXECUTE);
    }
    for p in SYSTEM_PATHS {
        ruleset.add(Path::new(p), access::READ_EXECUTE);
    }
    for p in TEMP_PATHS.iter().chain(DEV_RW_PATHS) {
        ruleset.add(Path::new(p), access::ALL);
    }
    for p in DEV_READ_PATHS.iter().chain(PROC_PATHS) {
        ruleset.add(Path::new(p), access::READ);
    }
}

/// Build the Landlock ruleset for `config` (test helper).
///
/// # Errors
/// Returns `SandboxUnavailable` if Landlock is not usable.
#[cfg(test)]
pub fn build_landlock_ruleset(
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
) -> Result<PreparedRuleset, SandboxError> {
    let mut ruleset = PreparedRuleset::create()?;
    add_ruleset_rules(
        &mut ruleset,
        config,
        path_dirs,
        &HashSet::new(),
        &HashSet::new(),
    );
    Ok(ruleset)
}

// ── Raw helpers for the pre_exec hook ──────────────────────────────────────

/// Return the last OS error. `std::io::Error::last_os_error` does not
/// allocate, so this is async-signal-safe.
fn last_err(msg: &'static [u8]) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    write_stderr_static(msg);
    err
}

/// Write all of `buf` to `fd`. Retries on EINTR and on a short write.
/// Async-signal-safe.
fn write_all_fd(fd: libc::c_int, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is a valid slice for `buf.len()` bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        buf = buf.get(n.unsigned_abs()..).unwrap_or_default();
    }
    Ok(())
}

/// Fill `buf` from `fd`. Retries on EINTR. Returns `Ok(false)` on EOF before
/// any byte. Async-signal-safe.
fn read_exact_fd(fd: libc::c_int, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut done = 0usize;
    while done < buf.len() {
        let Some(rest) = buf.get_mut(done..) else {
            break;
        };
        // SAFETY: `rest` is a valid, writable slice for `rest.len()` bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::read(fd, rest.as_mut_ptr().cast(), rest.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            if done == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::from_raw_os_error(libc::EPIPE));
        }
        done = done.saturating_add(n.unsigned_abs());
    }
    Ok(true)
}

/// Open `path` for writing and write all of `buf` to it. Async-signal-safe.
fn write_proc_file(path: &std::ffi::CStr, buf: &[u8]) -> std::io::Result<()> {
    // SAFETY: `path` is a valid NUL-terminated string.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = write_all_fd(fd, buf);
    // SAFETY: `fd` is a file descriptor that this function opened.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(fd) };
    result
}

/// Bring up the loopback interface in the current network namespace.
///
/// Called after `unshare(CLONE_NEWNET)` for `LocalhostOnly`. Async-signal-safe.
fn bring_up_loopback() -> std::io::Result<()> {
    const IFNAMSIZ: usize = 16;
    const IFF_UP: i16 = 0x1;

    /// Mirrors the C `struct ifreq` layout for SIOCGIFFLAGS / SIOCSIFFLAGS.
    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; IFNAMSIZ],
        ifr_flags: i16,
        _pad: [u8; 22],
    }
    // Compile-time check that our hand-written layout matches the expected size.
    const _: () = assert!(std::mem::size_of::<IfReq>() == 40);

    let mut req = IfReq {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: 0,
        _pad: [0; 22],
    };
    req.ifr_name[0] = b'l';
    req.ifr_name[1] = b'o';

    // SAFETY: socket(2) with constant arguments.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(last_err(b"pent: socket for loopback setup failed\n"));
    }
    // SAFETY: `req` is a valid `struct ifreq` for SIOCGIFFLAGS, and `sock`
    // is a socket that this function owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let got = unsafe {
        libc::ioctl(
            sock,
            libc::SIOCGIFFLAGS as _,
            std::ptr::addr_of_mut!(req).cast::<libc::c_void>(),
        )
    };
    let result = if got == 0 {
        req.ifr_flags |= IFF_UP;
        // SAFETY: as above, for SIOCSIFFLAGS.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let set = unsafe {
            libc::ioctl(
                sock,
                libc::SIOCSIFFLAGS as _,
                std::ptr::addr_of_mut!(req).cast::<libc::c_void>(),
            )
        };
        if set == 0 {
            Ok(())
        } else {
            Err(last_err(b"pent: SIOCSIFFLAGS on lo failed\n"))
        }
    } else {
        Err(last_err(b"pent: SIOCGIFFLAGS on lo failed\n"))
    };
    // SAFETY: `sock` is a file descriptor that this function opened.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(sock) };
    result
}

/// Write the UID and GID maps for a new user namespace.
///
/// The maps are identity maps that the parent prepared: the real UID and GID
/// map to themselves. The sandboxed process thus has the real UID of the
/// user (not root, not 65534). Async-signal-safe.
///
/// # Errors
/// Returns the OS error of the first write that fails. A failure is fatal:
/// without the maps the child runs as the overflow UID 65534.
fn setup_userns_mappings(uid_map: &[u8], gid_map: &[u8]) -> std::io::Result<()> {
    // An unprivileged process must write "deny" to setgroups before gid_map.
    write_proc_file(c"/proc/self/setgroups", b"deny")
        .map_err(|_| last_err(b"pent: write /proc/self/setgroups failed\n"))?;
    write_proc_file(c"/proc/self/gid_map", gid_map)
        .map_err(|_| last_err(b"pent: write /proc/self/gid_map failed\n"))?;
    write_proc_file(c"/proc/self/uid_map", uid_map)
        .map_err(|_| last_err(b"pent: write /proc/self/uid_map failed\n"))?;
    Ok(())
}

/// Clear the inheritable capability set and make the process dumpable.
///
/// The pent binary can carry `cap_net_admin=eip` file capabilities. These
/// have two effects that break the user namespace setup:
///
/// 1. The process is not dumpable. Its `/proc/self` files belong to root,
///    so the writes to `uid_map` fail with EACCES. `PR_SET_DUMPABLE` fixes
///    this.
/// 2. Linux 5.11 and later refuse `unshare(CLONE_NEWUSER)` with a non-empty
///    inheritable set. `capset` clears it.
///
/// Async-signal-safe.
fn prepare_caps_for_userns() -> std::io::Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const CAP_V3: u32 = 0x2008_0522;

    // SAFETY: prctl with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(last_err(b"pent: prctl(PR_SET_DUMPABLE) failed\n"));
    }
    let mut hdr = CapHeader {
        version: CAP_V3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `hdr` and `data` have the layout that capget(2) expects for
    // version 3 (two data words) and are writable.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) } != 0 {
        return Err(last_err(b"pent: capget failed\n"));
    }
    if data.iter().all(|d| d.inheritable == 0) {
        return Ok(());
    }
    for d in &mut data {
        d.inheritable = 0;
    }
    // SAFETY: the same valid buffers, now read by capset(2).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) } != 0 {
        return Err(last_err(b"pent: capset failed\n"));
    }
    Ok(())
}

/// Mark all file descriptors from 3 up as close-on-exec, so that file
/// descriptors of the embedding program that are not `O_CLOEXEC` do not leak
/// into the child. The sync pipes and the ruleset stay usable until `exec`.
/// Async-signal-safe.
fn cloexec_inherited_fds() {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    // SAFETY: close_range(2) with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if ret == 0 {
        return;
    }
    // Fallback for kernels before 5.11 (only possible with `no_enforcement`,
    // because Landlock ABI v3 needs Linux 6.2).
    for fd in 3..4096 {
        // SAFETY: fcntl(2) on a number; EBADF for a closed number is harmless.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
}

/// Mount flags that a bind mount inherits and must keep on a remount.
///
/// A remount that drops a flag of a mount from a less privileged mount
/// namespace fails with EPERM. Async-signal-safe.
fn locked_mount_flags(path: &std::ffi::CStr) -> std::io::Result<libc::c_ulong> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `path` is NUL-terminated and `st` is writable. glibc
    // implements statvfs with the statfs system call and the ST_* flags
    // that the kernel returns; it does not allocate.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded, so the struct is initialized.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let st = unsafe { st.assume_init() };
    let f = st.f_flag;
    let pairs: [(libc::c_ulong, libc::c_ulong); 6] = [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ];
    Ok(pairs
        .iter()
        .filter(|(st_flag, _)| f & st_flag != 0)
        .fold(0, |acc, (_, ms)| acc | ms))
}

// ── Mount plan ─────────────────────────────────────────────────────────────

/// The private mounts that the child makes before Landlock applies.
#[derive(Debug, Default)]
struct MountPlan {
    /// Make the mount tree private (only in a new mount namespace).
    make_private: bool,
    /// `resolv.conf` source to bind-mount over `/etc/resolv.conf`.
    resolv: Option<CString>,
    /// Paths to bind-mount read-only onto themselves (`<workspace>/.pent`).
    readonly: Vec<CString>,
    /// Directories to hide with an empty tmpfs (`/run/user/<uid>`).
    mask_dirs: Vec<CString>,
    /// Socket files to hide with a bind mount of `/dev/null`.
    mask_files: Vec<CString>,
}

fn to_cstring(path: &Path) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).ok()
}

/// Return true if the configuration names `mask` or a path inside it.
///
/// A grant on an ancestor (for example the traversal grant on `/`) does not
/// count: the user must name the hidden path itself.
#[must_use]
pub(crate) fn is_explicitly_allowed(mask: &Path, configured: &[PathBuf]) -> bool {
    configured.iter().any(|p| p.starts_with(mask))
}

/// Return all paths that the configuration names explicitly.
fn configured_paths(config: &SandboxConfig) -> Vec<PathBuf> {
    let (traversal, read, execute, rw) = config.paths.expand_paths();
    let mut v: Vec<PathBuf> = traversal
        .into_iter()
        .chain(read)
        .chain(execute)
        .chain(rw)
        .map(|(p, _)| p)
        .collect();
    v.extend(config.mounts.iter().map(|m| m.path.clone()));
    v.push(config.workspace.clone());
    v.push(config.data_dir.clone());
    v.push(config.cwd.clone());
    v
}

/// Compute the directories and socket files to hide.
fn mask_targets(config: &SandboxConfig, uid: libc::uid_t) -> (Vec<PathBuf>, Vec<PathBuf>) {
    use std::os::unix::fs::FileTypeExt;
    let configured = configured_paths(config);
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut runtime_dirs = vec![PathBuf::from(format!("/run/user/{uid}"))];
    if let Some(xdg) = config.env.get("XDG_RUNTIME_DIR") {
        runtime_dirs.push(PathBuf::from(xdg));
    }
    for d in runtime_dirs {
        let Ok(real) = std::fs::canonicalize(&d) else {
            continue;
        };
        if real != Path::new("/")
            && real.is_dir()
            && !is_explicitly_allowed(&d, &configured)
            && !is_explicitly_allowed(&real, &configured)
            && !dirs.contains(&real)
        {
            dirs.push(real);
        }
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for s in ESCAPE_SOCKETS {
        let p = Path::new(s);
        let Ok(real) = std::fs::canonicalize(p) else {
            continue;
        };
        let is_socket = std::fs::symlink_metadata(&real).is_ok_and(|m| m.file_type().is_socket());
        if is_socket
            && !is_explicitly_allowed(p, &configured)
            && !is_explicitly_allowed(&real, &configured)
            && !dirs.iter().any(|d| real.starts_with(d))
            && !files.contains(&real)
        {
            files.push(real);
        }
    }
    (dirs, files)
}

impl MountPlan {
    /// Make the private mounts. Async-signal-safe.
    ///
    /// # Errors
    /// A failure to make the tree private, to make a path read-only or to
    /// hide a path is fatal. A failure of the `resolv.conf` mount is only
    /// reported.
    fn apply(&self) -> std::io::Result<()> {
        if !self.make_private {
            return Ok(());
        }
        // After unshare(CLONE_NEWNS) in a user namespace, inherited mounts
        // are slaves. Make the tree private before new mounts, so that no
        // mount propagates to the host. This must come after the overlayfs
        // mounts: a private tree before overlayfs gives EACCES on some
        // kernels.
        // SAFETY: mount(2) with static NUL-terminated strings.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::mount(
                c"none".as_ptr(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(last_err(b"pent: mount --make-rprivate / failed\n"));
        }

        if let Some(src) = &self.resolv {
            // MS_BIND follows a symbolic link at the target, so this also
            // covers a /etc/resolv.conf that points into /run.
            // SAFETY: mount(2) with NUL-terminated strings that the parent
            // prepared.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    src.as_ptr(),
                    c"/etc/resolv.conf".as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                write_stderr_static(
                    b"pent: bind-mount /etc/resolv.conf failed; DNS may not work\n",
                );
            }
        }

        for path in &self.readonly {
            // SAFETY: mount(2) with NUL-terminated strings that the parent
            // prepared.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    path.as_ptr(),
                    path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: bind-mount of .pent failed\n"));
            }
            let locked = locked_mount_flags(path)
                .map_err(|_| last_err(b"pent: statfs of .pent failed\n"))?;
            // SAFETY: as above.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    std::ptr::null(),
                    path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: read-only remount of .pent failed\n"));
            }
        }

        for dir in &self.mask_dirs {
            // SAFETY: mount(2) with NUL-terminated strings.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    dir.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    c"size=16k,mode=0700".as_ptr().cast(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: cannot hide the user runtime directory\n"));
            }
        }

        for file in &self.mask_files {
            // SAFETY: mount(2) with NUL-terminated strings.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"/dev/null".as_ptr(),
                    file.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: cannot hide a container socket\n"));
            }
        }
        Ok(())
    }
}

/// Everything that the `pre_exec` hook needs, prepared before `fork`.
struct ChildPlan {
    parent_pid: libc::pid_t,
    unshare_flags: libc::c_int,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    /// ProxyOnly sync pipes: (ready write end, go read end).
    proxy_sync: Option<(libc::c_int, libc::c_int)>,
    overlays: Vec<super::linux_overlayfs::OverlayMount>,
    accessible: HashSet<PathBuf>,
    mounts: MountPlan,
    cwd: Option<CString>,
    bring_up_lo: bool,
    /// `None` when enforcement is off (`--no-sandbox`).
    ruleset: Option<PreparedRuleset>,
}

impl ChildPlan {
    /// The body of the `pre_exec` hook.
    ///
    /// Order matters:
    /// 1. Parent-death signal and close-on-exec for inherited fds.
    /// 2. All namespace work while `/proc/self` is still writable: unshare,
    ///    UID/GID maps, the ProxyOnly handshake, overlay and private mounts,
    ///    loopback.
    /// 3. `PR_SET_NO_NEW_PRIVS`, the seccomp filter and Landlock last.
    fn run(&self) -> std::io::Result<()> {
        // SAFETY: prctl with integer arguments only. PDEATHSIG fires when the
        // *thread* that forked exits, so `spawn_sandboxed` must run on a
        // thread that lives as long as the child (see its documentation).
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(last_err(b"pent: prctl(PR_SET_PDEATHSIG) failed\n"));
        }
        // The parent can exit before the prctl call; then no signal comes.
        // SAFETY: getppid has no preconditions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::getppid() } != self.parent_pid {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        cloexec_inherited_fds();

        if self.unshare_flags != 0 {
            if self.unshare_flags & libc::CLONE_NEWUSER != 0 {
                prepare_caps_for_userns()?;
            }
            // SAFETY: unshare(2) with integer flags.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::unshare(self.unshare_flags) } != 0 {
                return Err(last_err(b"pent: unshare failed\n"));
            }
            if self.unshare_flags & libc::CLONE_NEWUSER != 0 {
                setup_userns_mappings(&self.uid_map, &self.gid_map)?;
            }
        }

        if let Some((ready_w, go_r)) = self.proxy_sync {
            // Send our PID to the helper thread of the parent. The thread
            // moves the inner veth into our network namespace, configures
            // it, and then sends one byte.
            // SAFETY: getpid has no preconditions.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let pid = unsafe { libc::getpid() };
            let sent = write_all_fd(ready_w, &pid.to_ne_bytes());
            // SAFETY: close our copy of the pipe end; exec closes it anyway.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(ready_w) };
            sent.map_err(|_| last_err(b"pent: cannot send the PID to the parent\n"))?;
            let mut go = [0u8; 1];
            let got = read_exact_fd(go_r, &mut go);
            // SAFETY: as above.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(go_r) };
            match got {
                Ok(true) if go == *b"1" => {}
                _ => {
                    write_stderr_static(b"pent: the parent did not configure the network\n");
                    return Err(std::io::Error::from_raw_os_error(libc::ENETDOWN));
                }
            }
        }

        if !self.overlays.is_empty() {
            // These helpers live in linux_overlayfs.rs. They create the
            // upper/work directories inside the user namespace (doing so in
            // the parent gives EACCES on the overlay mount with a btrfs
            // lower layer) and mount the overlays.
            super::linux_overlayfs::setup_overlay_dirs(&self.overlays, &self.accessible)?;
            // SAFETY: we are in the post-fork child, after
            // unshare(CLONE_NEWUSER | CLONE_NEWNS) and the UID/GID maps.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { super::linux_overlayfs::mount_overlays(&self.overlays) }?;
        }

        self.mounts.apply()?;

        // Re-chdir after the mounts: std calls chdir() before pre_exec hooks,
        // so the CWD can point to an inode under a new mount. Landlock rules
        // bind to the inodes that the new mounts show.
        if let Some(cwd) = &self.cwd {
            // SAFETY: `cwd` is a NUL-terminated string that the parent prepared.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
                return Err(last_err(b"pent: chdir to the working directory failed\n"));
            }
        }

        if self.bring_up_lo {
            bring_up_loopback()?;
        }

        if let Some(ruleset) = &self.ruleset {
            // SAFETY: prctl with integer arguments only.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(last_err(b"pent: prctl(PR_SET_NO_NEW_PRIVS) failed\n"));
            }
            // SAFETY: we are in the pre_exec hook and NO_NEW_PRIVS is set.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { crate::linux_landlock::install_tiocsti_filter() }
                .map_err(|_| last_err(b"pent: seccomp filter failed\n"))?;
            // SAFETY: we are in the pre_exec hook and NO_NEW_PRIVS is set;
            // the function uses only raw system calls on prepared data.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { ruleset.apply_in_child() }
                .map_err(|_| last_err(b"pent: Landlock restriction failed\n"))?;
        }
        Ok(())
    }
}

/// Create a pipe with `O_CLOEXEC` and return (read end, write end).
fn cloexec_pipe() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 writes two file descriptors into `fds`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SandboxError::SpawnFailed(std::io::Error::last_os_error()));
    }
    // SAFETY: pipe2 succeeded, so both numbers are new file descriptors
    // that this process owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Add the proxy variables to the environment of the child.
fn proxy_env(
    env: &std::collections::HashMap<String, String>,
    outer_ip: std::net::Ipv4Addr,
    port: u16,
) -> std::collections::HashMap<String, String> {
    let http_url = format!("http://{outer_ip}:{port}");
    // socks5h = hostname resolved by the proxy, so the sandboxed process
    // never calls getaddrinfo for external hosts — DNS stays on the proxy side.
    let socks_url = format!("socks5h://{outer_ip}:{port}");
    let no_proxy = "localhost,127.0.0.1,::1";
    let mut e = env.clone();
    e.insert("HTTP_PROXY".to_string(), http_url.clone());
    e.insert("HTTPS_PROXY".to_string(), http_url.clone());
    e.insert("http_proxy".to_string(), http_url.clone());
    e.insert("https_proxy".to_string(), http_url);
    e.insert("ALL_PROXY".to_string(), socks_url.clone());
    e.insert("all_proxy".to_string(), socks_url.clone());
    e.insert("GRPC_PROXY".to_string(), socks_url.clone());
    e.insert("grpc_proxy".to_string(), socks_url);
    e.insert("NO_PROXY".to_string(), no_proxy.to_string());
    e.insert("no_proxy".to_string(), no_proxy.to_string());
    // Route git-over-SSH through the SOCKS5 proxy (nc -X 5 = SOCKS5).
    e.insert(
        "GIT_SSH_COMMAND".to_string(),
        format!("ssh -o ProxyCommand='nc -X 5 -x {outer_ip}:{port} %h %p'"),
    );
    // Signal to the sandboxed process that it is running inside a proxy sandbox.
    // Claude Code checks this flag to activate its own proxy-aware networking.
    e.insert("SANDBOX_RUNTIME".to_string(), "1".to_string());
    e
}

/// Spawn command with Landlock sandbox using `pre_exec`.
///
/// For write-listed file paths, overlayfs is mounted over their parent directories
/// inside the child's mount namespace so that atomic writes (rename-based) go to
/// the overlay upper layer. An inotify watcher in the parent flushes completed
/// writes back to the real file inodes in-place, preserving the inodes that
/// Landlock rules are bound to.
///
/// The child gets `PR_SET_PDEATHSIG(SIGKILL)`. Call this function on a thread
/// that lives as long as the child: the signal fires when the forking thread
/// exits.
///
/// # Returns
/// `(child_handle, overlay_handle, netns_handle)` — `overlay_handle` is `Some`
/// when overlayfs is in use; pass it to [`super::linux_overlayfs::teardown`]
/// after the child exits.
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock unavailable
/// * `NetworkSetupFailed` / `PrivilegeRequired` - If the proxy network fails
/// * `SpawnFailed` - If spawn fails
#[allow(clippy::too_many_lines)]
pub fn spawn_with_landlock(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
) -> Result<
    (
        std::process::Child,
        Option<super::linux_overlayfs::OverlayHandle>,
        Option<super::linux_netns::NetnsHandle>,
    ),
    SandboxError,
> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let enforce = !config.no_enforcement;

    // Identify write-listed file paths (as opposed to directories) and prepare
    // overlayfs staging directories for them. Directories use regular Landlock
    // write rules; files get inode-stable access via the overlayfs + inotify path.
    let (_, read_expanded, execute_expanded, rw_expanded) = config.paths.expand_paths();
    let overlay_file_paths: Vec<PathBuf> = rw_expanded
        .iter()
        .filter_map(|(path, _)| {
            // Include paths that are files, or don't exist yet but whose parent
            // directory exists (will be created as a file on first write).
            if path.is_file() || (!path.exists() && path.parent().is_some_and(Path::is_dir)) {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    let write_set: HashSet<PathBuf> = overlay_file_paths.iter().cloned().collect();

    // Directory-type read_write entries: all files created or modified inside
    // these directories during the session should be flushed back to the real FS.
    // Include paths that are directories AND paths that don't exist yet but
    // whose parent does (they may be created as directories in the sandbox).
    let mut rw_dirs: HashSet<PathBuf> = rw_expanded
        .iter()
        .filter_map(|(path, _)| {
            if path.is_dir()
                || (!path.is_file() && !path.exists() && path.parent().is_some_and(Path::is_dir))
            {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    // The workspace and data_dir are always flushed back: they may fall inside
    // an overlayfs mount (e.g. the home-dir overlay).
    rw_dirs.insert(config.workspace.clone());
    rw_dirs.insert(config.data_dir.clone());

    // Build the set of paths the sandboxed process is allowed to read.
    // Traversal-only paths are intentionally excluded (ReadDir but not ReadFile).
    let mut accessible: HashSet<PathBuf> = HashSet::new();
    for (p, _) in read_expanded
        .iter()
        .chain(&execute_expanded)
        .chain(&rw_expanded)
    {
        accessible.insert(p.clone());
    }
    accessible.extend(write_set.iter().cloned());
    accessible.extend(compute_accessible_set(config, path_dirs));

    let home_dir: PathBuf = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.workspace.clone());

    let pid = std::process::id();
    let overlay_mounts = if enforce {
        super::linux_overlayfs::prepare_overlay_dirs(&accessible, &home_dir, pid)
    } else {
        Vec::new()
    };
    let overlay_dirs: HashSet<PathBuf> =
        overlay_mounts.iter().map(|m| m.real_dir.clone()).collect();

    // Landlock ruleset: created in the parent, rules applied in the child.
    let ruleset = if enforce {
        let mut rs = PreparedRuleset::create()?;
        add_ruleset_rules(&mut rs, config, path_dirs, &write_set, &overlay_dirs);
        Some(rs)
    } else {
        None
    };

    // ProxyOnly: use the network that `prepare_proxy_network` created for the
    // proxy address, or create one now.
    let mut proxy_netns: Option<super::linux_netns::NetnsHandle> = if let NetworkMode::ProxyOnly {
        proxy_addr,
        dns_port,
    } = &config.network
    {
        let mut handle = match super::linux_netns::take_prepared(proxy_addr.ip()) {
            Some(h) => h,
            None => super::linux_netns::create_netns()?,
        };
        handle.install_firewall(proxy_addr.port(), *dns_port)?;
        Some(handle)
    } else {
        None
    };
    let resolv_src: Option<PathBuf> = match (&mut proxy_netns, &config.network) {
        (Some(h), NetworkMode::ProxyOnly { dns_port, .. }) if *dns_port != 0 => {
            Some(h.write_resolv_conf()?)
        }
        _ => None,
    };

    // Namespaces.
    let net_flag = match config.network {
        NetworkMode::Unrestricted => 0,
        _ => libc::CLONE_NEWNET,
    };
    let unshare_flags = if enforce {
        libc::CLONE_NEWUSER | libc::CLONE_NEWNS | net_flag
    } else if net_flag != 0 {
        let ns = if proxy_netns.is_some() {
            libc::CLONE_NEWNS
        } else {
            0
        };
        libc::CLONE_NEWUSER | net_flag | ns
    } else {
        0
    };
    let has_mntns = unshare_flags & libc::CLONE_NEWNS != 0;

    // SAFETY: getuid/getgid have no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    let mut mounts = MountPlan {
        make_private: has_mntns,
        resolv: resolv_src.as_deref().and_then(to_cstring),
        ..MountPlan::default()
    };
    if enforce {
        let dot_pent = config.workspace.join(".pent");
        if dot_pent.exists() {
            mounts.readonly.extend(to_cstring(&dot_pent));
        }
        let (mask_dirs, mask_files) = mask_targets(config, uid);
        mounts
            .mask_dirs
            .extend(mask_dirs.iter().filter_map(|p| to_cstring(p)));
        mounts
            .mask_files
            .extend(mask_files.iter().filter_map(|p| to_cstring(p)));
    }

    // Sync pipes for ProxyOnly.
    // ready: child writes its PID → helper thread reads it.
    // go:    helper thread writes one byte → child reads it.
    let pipes = if proxy_netns.is_some() {
        let (ready_r, ready_w) = cloexec_pipe()?;
        let (go_r, go_w) = cloexec_pipe()?;
        Some((ready_r, ready_w, go_r, go_w))
    } else {
        None
    };

    let plan = ChildPlan {
        // The PID fits in pid_t: the kernel limit is 2^22.
        #[allow(clippy::cast_possible_wrap)]
        parent_pid: pid as libc::pid_t,
        unshare_flags,
        uid_map: format!("{uid} {uid} 1\n").into_bytes(),
        gid_map: format!("{gid} {gid} 1\n").into_bytes(),
        proxy_sync: pipes
            .as_ref()
            .map(|(_, ready_w, go_r, _)| (ready_w.as_raw_fd(), go_r.as_raw_fd())),
        overlays: overlay_mounts.clone(),
        accessible,
        mounts,
        cwd: if has_mntns {
            to_cstring(&config.cwd)
        } else {
            None
        },
        bring_up_lo: config.network == NetworkMode::LocalhostOnly,
        ruleset,
    };

    let effective_env = match (&config.network, &proxy_netns) {
        (NetworkMode::ProxyOnly { proxy_addr, .. }, Some(handle)) => {
            proxy_env(env, handle.outer_ip, proxy_addr.port())
        }
        _ => env.clone(),
    };

    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(&config.cwd);
    command.env_clear();
    command.envs(&effective_env);
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    // SAFETY: `ChildPlan::run` uses only async-signal-safe raw system calls
    // on data prepared before fork (except the overlayfs helpers, see the
    // module documentation).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        command.pre_exec(move || plan.run());
    }

    // The helper thread configures the child network. It must start before
    // `spawn`, because the child blocks on the go pipe inside `spawn`.
    let (parent_ends, helper) = match pipes {
        Some((ready_r, ready_w, go_r, go_w)) => {
            let net = proxy_netns
                .as_ref()
                .map(super::linux_netns::NetnsHandle::child_config);
            let helper = std::thread::spawn(move || -> Result<bool, SandboxError> {
                let mut pid_bytes = [0u8; 4];
                match read_exact_fd(ready_r.as_raw_fd(), &mut pid_bytes) {
                    Ok(true) => {}
                    // EOF: the child failed before the handshake.
                    Ok(false) => return Ok(false),
                    Err(e) => {
                        return Err(SandboxError::NetworkSetupFailed(format!(
                            "cannot read the child PID: {e}"
                        )))
                    }
                }
                let child_pid = libc::pid_t::from_ne_bytes(pid_bytes);
                if let Some(net) = &net {
                    net.configure(child_pid)?;
                }
                write_all_fd(go_w.as_raw_fd(), b"1").map_err(|e| {
                    SandboxError::NetworkSetupFailed(format!("cannot signal the child: {e}"))
                })?;
                Ok(true)
            });
            (Some((ready_w, go_r)), Some(helper))
        }
        None => (None, None),
    };

    let spawn_result = command.spawn();
    // Drop the closure (and with it the ruleset fd) and the parent copies of
    // the child-side pipe ends. The helper then sees EOF if the child died
    // before the handshake.
    drop(command);
    drop(parent_ends);

    let helper_result = match helper {
        Some(h) => h.join().map_err(|_| {
            SandboxError::NetworkSetupFailed("the network helper thread panicked".to_string())
        })?,
        None => Ok(true),
    };

    // On error, `proxy_netns` drops here and removes the network.
    let child = match (spawn_result, helper_result) {
        (Ok(child), Ok(_)) => child,
        // The helper failure is the root cause of the spawn failure.
        (_, Err(e)) => return Err(e),
        (Err(e), Ok(_)) => return Err(SandboxError::SpawnFailed(e)),
    };

    // Start the inotify watcher now that the child is running.
    let overlay_handle = if overlay_mounts.is_empty() {
        None
    } else {
        Some(super::linux_overlayfs::spawn_watcher(
            overlay_mounts,
            write_set,
            rw_dirs,
        ))
    };

    Ok((child, overlay_handle, proxy_netns))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPaths;
    use serial_test::serial;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct TestDirs {
        workspace: PathBuf,
        data_dir: PathBuf,
        _temp: TempDir,
    }

    fn make_test_dirs() -> TestDirs {
        #[allow(clippy::unwrap_used)] // infra-only helper, no meaningful error recovery
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&workspace).ok();
        std::fs::create_dir_all(&data_dir).ok();
        TestDirs {
            workspace,
            data_dir,
            _temp: temp,
        }
    }

    // ========================================================================
    // Constants tests
    // ========================================================================

    #[test]
    fn test_min_landlock_abi() {
        assert_eq!(MIN_LANDLOCK_ABI, 3);
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    fn test_check_available_returns_result() {
        // Should return Ok if Landlock ABI v4 available, Err otherwise
        // Either result is valid depending on kernel version
        let result = check_available();
        // Just ensure it doesn't panic
        let _ = result;
    }

    // ========================================================================
    // build_landlock_ruleset tests
    // ========================================================================

    fn make_test_config() -> SandboxConfig {
        SandboxConfig::new(
            PathBuf::from("/tmp/test-workspace"),
            SandboxPaths::default(),
            PathBuf::from("/tmp/test-workspace"),
        )
        .with_data_dir(PathBuf::from("/tmp/test-data"))
    }

    #[test]
    fn test_build_landlock_ruleset_basic() {
        let config = make_test_config();
        let result = build_landlock_ruleset(&config, &[]);
        // May fail if Landlock not available, that's ok
        if check_available().is_ok() {
            assert!(
                result.is_ok(),
                "Should build ruleset on Landlock-enabled system"
            );
        }
    }

    #[test]
    fn test_build_landlock_ruleset_with_path_dirs() {
        let config = make_test_config();
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let result = build_landlock_ruleset(&config, &path_dirs);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_build_landlock_ruleset_with_mounts() {
        use crate::Mount;
        let config = make_test_config()
            .with_mount(Mount {
                path: PathBuf::from("/opt/tools"),
                readonly: true,
            })
            .with_mount(Mount {
                path: PathBuf::from("/var/data"),
                readonly: false,
            });
        let result = build_landlock_ruleset(&config, &[]);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_build_landlock_ruleset_skips_nonexistent_paths() {
        let config = SandboxConfig::new(
            PathBuf::from("/nonexistent/workspace/12345"),
            SandboxPaths::default(),
            PathBuf::from("/tmp"),
        )
        .with_data_dir(PathBuf::from("/nonexistent/data/12345"));
        let result = build_landlock_ruleset(&config, &[]);
        // Should not fail due to nonexistent paths - they're skipped
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    // ========================================================================
    // spawn_with_landlock tests
    // ========================================================================

    #[test]
    #[serial]
    fn test_spawn_with_landlock_true_command() -> TestResult {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir);
        let Some(true_bin) = which("true") else {
            return Ok(()); // skip: no `true` in PATH
        };
        let path_dirs = test_path_dirs(&true_bin);
        let env = HashMap::new();

        let result =
            spawn_with_landlock(&config, &true_bin.to_string_lossy(), &[], &env, &path_dirs);

        if check_available().is_ok() {
            match result {
                Ok((mut child, _overlay, _netns)) => {
                    let status = child
                        .wait()
                        .map_err(|e| format!("Failed to wait on child: {e}"))?;
                    assert!(status.success(), "true command should succeed");
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    // Some CI/container environments expose Landlock but deny
                    // applying it in pre_exec.
                }
                Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    fn test_spawn_with_landlock_echo_command() -> TestResult {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir);
        let Some(echo_bin) = which("echo") else {
            return Ok(()); // skip: no `echo` in PATH
        };
        let path_dirs = test_path_dirs(&echo_bin);
        let env = HashMap::new();

        let result = spawn_with_landlock(
            &config,
            &echo_bin.to_string_lossy(),
            &["hello".to_string()],
            &env,
            &path_dirs,
        );

        if check_available().is_ok() {
            match result {
                Ok((mut child, _overlay, _netns)) => {
                    let status = child
                        .wait()
                        .map_err(|e| format!("Failed to wait on child: {e}"))?;
                    assert!(status.success());
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    // Some CI/container environments expose Landlock but deny
                    // applying it in pre_exec.
                }
                Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    fn test_spawn_with_landlock_nonexistent_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir);
        let env = HashMap::new();

        let result = spawn_with_landlock(&config, "/nonexistent/command/12345", &[], &env, &[]);

        if check_available().is_ok() {
            // Should fail to spawn nonexistent command
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // Live inotify flush test (writes flushed mid-session, not just at exit)
    //
    // This is the scenario that matters for long-running apps like Claude:
    // writes happen throughout the session and must reach the real FS as they
    // occur (inotify path), not only when the process exits (teardown flush).
    // ========================================================================

    /// Spawn a long-running process that writes files in phases separated by
    /// sleeps, and verify that each write reaches the real filesystem while
    /// the process is still running (inotify live-flush), not only at teardown.
    ///
    /// This reproduces the "files are gone when I leave the sandbox" failure
    /// mode: if only the teardown flush worked, the files would appear at exit
    /// but not during the session — but since we check mid-session they would
    /// be missing here if the live path is broken.
    #[test]
    #[serial]
    fn test_overlay_live_flush_during_long_running_session() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let rw_dir = temp.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("create_dir_all: {e}"))?;

        // Marker files the sandbox will create at different phases.
        let file_a = rw_dir.join("phase_a.txt");
        let file_b = rw_dir.join("sub").join("phase_b.txt");

        // Flag files must be inside rw_dir so they are under an rw_dirs entry
        // and get live-flushed to the real FS (the parent polls the real path).
        let flag_a = rw_dir.join("flag_a");
        let flag_b = rw_dir.join("flag_b");

        // The shell script:
        //  1. Write phase_a.txt, signal flag_a
        //  2. Sleep briefly
        //  3. Create sub/, write phase_b.txt, signal flag_b
        //  4. Sleep briefly so the parent can check before exit
        let cmd = format!(
            "printf 'content-a' > '{file_a}' && touch '{flag_a}' && \
             sleep 0.2 && \
             mkdir -p '{subdir}' && printf 'content-b' > '{file_b}' && touch '{flag_b}' && \
             sleep 0.5",
            file_a = file_a.display(),
            flag_a = flag_a.display(),
            subdir = rw_dir.join("sub").display(),
            file_b = file_b.display(),
            flag_b = flag_b.display(),
        );

        let Some((mut child, overlay_handle)) =
            spawn_rw(temp.path(), &[rw_dir.to_str().unwrap_or("")], &cmd)
        else {
            return Ok(()); // overlayfs unavailable
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(()); // overlay not active, skip
        };

        // Wait for the sandbox to write phase_a (flag_a appears).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !flag_a.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for flag_a"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // Give the inotify watcher time to pick up the event (polls at 50 ms).
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Phase A: file_a must be on the real FS NOW — process still running.
        assert!(
            file_a.exists(),
            "live inotify flush failed: file_a not on real FS while sandbox is still running"
        );
        assert_eq!(
            std::fs::read_to_string(&file_a).unwrap_or_default(),
            "content-a",
            "file_a content wrong after live flush"
        );

        // Wait for phase_b.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !flag_b.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for flag_b"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Phase B: nested file in a new subdir must also be on real FS mid-session.
        assert!(
            file_b.exists(),
            "live inotify flush failed: file_b (nested) not on real FS while sandbox is still running"
        );
        assert_eq!(
            std::fs::read_to_string(&file_b).unwrap_or_default(),
            "content-b",
            "file_b content wrong after live flush"
        );

        let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
        crate::linux_overlayfs::teardown(handle);
        assert!(status.success());
        Ok(())
    }

    // ========================================================================
    // Overlay flush correctness tests
    //
    // These tests verify that writes made inside the sandbox are flushed back
    // to the real filesystem on teardown.  All tests use /tmp (always rw, no
    // network required) and fall back gracefully when overlayfs is unavailable.
    // ========================================================================

    /// Helper: spawn a sandboxed shell command with the given `read_write` paths
    /// and return `(child, overlay_handle)`.  Falls back gracefully when the
    /// kernel does not support user namespaces or overlayfs.
    ///
    /// The overlay subsystem is only activated when `read_write` contains at
    /// least one **file** entry (or a path that does not yet exist but whose
    /// parent does — treated as a future file).  A config that lists only
    /// directories produces no overlay and the handle will be `None`.
    ///
    /// To ensure the overlay is always active, this helper adds a sentinel
    /// file (`workspace/.pent_sentinel`) to the `read_write` list.  Because
    /// the sentinel lives in `workspace`, the overlay is mounted on `workspace`
    /// itself — which is also the root of every `rw_paths` directory used in
    /// these tests.  All rw directories therefore fall inside the overlay and
    /// are covered by the `rw_dirs` flush path.
    fn spawn_rw(
        workspace: &std::path::Path,
        rw_paths: &[&str],
        cmd: &str,
    ) -> Option<(
        std::process::Child,
        Option<crate::linux_overlayfs::OverlayHandle>,
    )> {
        use std::collections::HashMap;

        if check_available().is_err() {
            return None;
        }

        let mut paths = SandboxPaths::default();
        for p in rw_paths {
            paths.read_write.push((*p).to_string());
        }
        // Add a sentinel file entry so the overlay is always mounted on
        // `workspace`.  Without at least one file-type entry the overlay is
        // never created and all directory-based flush tests would skip.
        let sentinel = workspace.join(".pent_sentinel");
        std::fs::write(&sentinel, "sentinel").ok();
        #[allow(clippy::unwrap_used)] // path always valid UTF-8 in tests
        paths
            .read_write
            .push(sentinel.to_str().unwrap().to_string());

        let config = SandboxConfig::new(workspace.to_path_buf(), paths, workspace.to_path_buf())
            .with_data_dir(workspace.to_path_buf())
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();

        match spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd.to_string()],
            &test_env,
            &path_dirs,
        ) {
            Ok((child, handle, _netns)) => Some((child, handle)),
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                None
            }
            #[allow(clippy::panic)] // unexpected spawn error — fail loudly in test helper
            Err(e) => panic!("spawn_with_landlock failed: {e:?}"),
        }
    }

    /// Run `spawn_rw`, wait for the child, call teardown, then return whether
    /// the overlay was active (`Some` handle → true, `None` → false).
    fn run_sandboxed_rw(workspace: &std::path::Path, rw_paths: &[&str], cmd: &str) -> bool {
        let Some((mut child, overlay_handle)) = spawn_rw(workspace, rw_paths, cmd) else {
            return false;
        };
        #[allow(clippy::expect_used)] // infra helper — unexpected wait failure should fail loudly
        let status = child.wait().expect("wait failed");
        assert!(status.success(), "sandboxed command failed: {cmd}");
        overlay_handle.is_some_and(|handle| {
            crate::linux_overlayfs::teardown(handle);
            true
        })
    }

    /// Reproduce the real Claude-session failure mode:
    ///
    /// In a typical Claude session `~/.claude.json` is in `read_write` (file),
    /// which causes the overlay to be mounted on `~`.  The workspace
    /// `~/projects/myrepo` is under `~`, so all its writes go to the upper
    /// layer.  But the workspace was NOT in `rw_dirs`, so those writes were
    /// never flushed — every edit Claude made disappeared on session exit.
    ///
    /// This test fails before the fix (workspace added to `rw_dirs`) and passes
    /// after it.
    #[test]
    #[serial]
    fn test_overlay_flush_workspace_under_home_overlay() -> TestResult {
        use std::collections::HashMap;

        if check_available().is_err() {
            return Ok(());
        }

        // fake_home/ mimics ~/.  fake_home/workspace/ mimics ~/projects/myrepo.
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = fake_home.path().join("workspace");
        std::fs::create_dir_all(&workspace).map_err(|e| format!("create_dir_all: {e}"))?;

        // Pre-create a source file the sandbox will edit.
        let src_dir = workspace.join("src");
        std::fs::create_dir_all(&src_dir).map_err(|e| format!("create_dir_all src: {e}"))?;
        let target = src_dir.join("main.rs");
        std::fs::write(&target, "fn main() {}").map_err(|e| format!("write: {e}"))?;

        // Only the dot-file at home level is in read_write — this triggers the
        // overlay on fake_home/, the same as ~/.claude.json does in production.
        let dot_file = fake_home.path().join(".app.json");
        std::fs::write(&dot_file, "{}").map_err(|e| format!("write dot_file: {e}"))?;

        let mut paths = SandboxPaths::default();
        paths
            .read_write
            .push(dot_file.to_str().unwrap_or("").to_string());
        // workspace is intentionally NOT in read_write — it's the workspace arg.

        let config = SandboxConfig::new(workspace.clone(), paths, workspace.clone())
            .with_data_dir(workspace)
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();
        let cmd = format!(
            "printf 'fn main() {{ println!(\"hi\"); }}' > '{}'",
            target.display()
        );

        let result = spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd],
            &test_env,
            &path_dirs,
        );

        let (mut child, overlay_handle, _netns) = match result {
            Ok(r) => r,
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(())
            }
            Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
        };

        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(()); // no overlay active
        };

        let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
        assert!(status.success(), "sandboxed command failed");
        crate::linux_overlayfs::teardown(handle);

        let content = std::fs::read_to_string(&target).unwrap_or_default();
        assert_eq!(
            content, "fn main() { println!(\"hi\"); }",
            "workspace file edited inside sandbox must be flushed to real FS \
             (overlay mounted on parent dir, workspace not in read_write)"
        );
        Ok(())
    }

    /// Modify an existing file that is listed directly in `read_write` (file-level
    /// entry).  This is the original `write_set` path.
    #[test]
    #[serial]
    fn test_overlay_flush_direct_file_entry() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let target = temp.path().join("config.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[target.to_str().unwrap_or("")],
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(
            content, r#"{"v":2}"#,
            "direct file-level write_set entry must be flushed"
        );
        Ok(())
    }

    /// Modify a file inside a directory listed in `read_write` (directory-level
    /// entry — the `rw_dirs` path that was broken before this fix).
    #[test]
    #[serial]
    fn test_overlay_flush_file_inside_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("mydir");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("settings.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")], // directory, not file
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(content, r#"{"v":2}"#, "file inside rw_dir must be flushed");
        Ok(())
    }

    /// Modify multiple files inside the same rw directory in one session.
    #[test]
    #[serial]
    fn test_overlay_flush_multiple_files_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("store");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "old-a").map_err(|e| format!("write a: {e}"))?;
        std::fs::write(&b, "old-b").map_err(|e| format!("write b: {e}"))?;

        let cmd = format!(
            "printf 'new-a' > '{}' && printf 'new-b' > '{}'",
            a.display(),
            b.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert_eq!(
            std::fs::read_to_string(&a).map_err(|e| format!("read a: {e}"))?,
            "new-a",
            "a.txt must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&b).map_err(|e| format!("read b: {e}"))?,
            "new-b",
            "b.txt must be flushed"
        );
        Ok(())
    }

    /// Create a new file inside an rw directory (file did not exist at spawn time).
    #[test]
    #[serial]
    fn test_overlay_flush_newly_created_file_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("newdir");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("created.txt");
        assert!(!target.exists());

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")],
            &format!("printf 'hello' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        assert!(
            target.exists(),
            "newly created file must exist on real FS after teardown"
        );
        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            "hello"
        );
        Ok(())
    }

    /// Edit an existing file that is deeply nested inside an rw directory.
    /// All parent directories exist at spawn time.
    #[test]
    #[serial]
    fn test_overlay_flush_deeply_nested_existing_file() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let rw_dir = temp.path().join("store");
        // Pre-create the full hierarchy before spawning.
        let deep = rw_dir.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).map_err(|e| format!("create_dir: {e}"))?;
        let target = deep.join("state.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[rw_dir.to_str().unwrap_or("")],
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(
            content, r#"{"v":2}"#,
            "deeply nested existing file must be flushed to real FS"
        );
        Ok(())
    }

    /// Create a new subdirectory and file inside an rw directory.
    /// The subdirectory did not exist at spawn time.
    #[test]
    #[serial]
    fn test_overlay_flush_file_in_new_subdir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let rw_dir = temp.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("create_dir: {e}"))?;
        // subdir does NOT exist at spawn time
        let subdir = rw_dir.join("projects").join("alpha");
        let target = subdir.join("state.json");

        let cmd = format!(
            "mkdir -p '{}' && printf '{{\"ok\":true}}' > '{}'",
            subdir.display(),
            target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert!(
            subdir.exists(),
            "new subdirectory must exist on real FS after teardown"
        );
        assert!(
            target.exists(),
            "file in new subdir must be flushed to real FS"
        );
        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            r#"{"ok":true}"#
        );
        Ok(())
    }

    /// Atomic write (write-to-tmp then rename) inside an rw directory.
    #[test]
    #[serial]
    fn test_overlay_flush_atomic_write_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("cfg");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("config.toml");
        std::fs::write(&target, "version = 1").map_err(|e| format!("write: {e}"))?;
        let tmp = dir.join("config.toml.tmp");

        let cmd = format!(
            "printf 'version = 2' > '{}' && mv '{}' '{}'",
            tmp.display(),
            tmp.display(),
            target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            "version = 2",
            "atomic write (tmp→rename) in rw_dir must be flushed"
        );
        Ok(())
    }

    /// Mix of a direct file entry and a directory entry in the same session.
    #[test]
    #[serial]
    fn test_overlay_flush_mixed_file_and_dir_entries() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let file_entry = temp.path().join("config.json");
        let dir_entry = temp.path().join("cache");
        std::fs::write(&file_entry, "old").map_err(|e| format!("write file_entry: {e}"))?;
        std::fs::create_dir_all(&dir_entry).map_err(|e| format!("create_dir: {e}"))?;
        let cache_file = dir_entry.join("data.bin");
        std::fs::write(&cache_file, "stale").map_err(|e| format!("write cache_file: {e}"))?;

        let cmd = format!(
            "printf 'new' > '{}' && printf 'fresh' > '{}'",
            file_entry.display(),
            cache_file.display()
        );
        let active = run_sandboxed_rw(
            temp.path(),
            &[
                file_entry.to_str().unwrap_or(""),
                dir_entry.to_str().unwrap_or(""),
            ],
            &cmd,
        );
        if !active {
            return Ok(());
        }

        assert_eq!(
            std::fs::read_to_string(&file_entry).map_err(|e| format!("read file_entry: {e}"))?,
            "new",
            "direct file entry must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&cache_file).map_err(|e| format!("read cache_file: {e}"))?,
            "fresh",
            "file inside directory entry must be flushed"
        );
        Ok(())
    }

    /// Append to an existing file inside an rw directory.
    #[test]
    #[serial]
    fn test_overlay_flush_append_to_file_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("logs");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("app.log");
        std::fs::write(&target, "line1\n").map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")],
            &format!("printf 'line2\\n' >> '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(
            content, "line1\nline2\n",
            "appended content must be flushed"
        );
        Ok(())
    }

    /// A `read_write` path that does not exist at spawn time and is created as a
    /// directory by the sandbox process.  Its contents must be flushed.
    #[test]
    #[serial]
    fn test_overlay_flush_nonexistent_rw_path_created_as_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        // rw_dir does NOT exist at spawn time — it will be created by the sandbox.
        let rw_dir = temp.path().join("cache");
        assert!(!rw_dir.exists());
        let target = rw_dir.join("state.json");

        let cmd = format!(
            "mkdir -p '{}' && printf '{{\"ok\":true}}' > '{}'",
            rw_dir.display(),
            target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert!(
            rw_dir.exists(),
            "directory created by sandbox must exist on real FS"
        );
        assert!(
            target.exists(),
            "file inside newly-created rw dir must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            r#"{"ok":true}"#
        );
        Ok(())
    }

    /// Files outside both the workspace and all `read_write` directories must NOT
    /// be flushed to the real FS.  The overlay covers the entire parent
    /// directory, so writes from the sandbox land in the upper layer, but the
    /// flush logic only persists files that are in `write_set` or `rw_dirs`
    /// (which includes the workspace).  Files in a sibling directory that is
    /// neither the workspace nor an explicit rw path are protected on two
    /// levels: Landlock denies the write entirely, and even if a write somehow
    /// reached the upper layer, the flush condition would not match.
    #[test]
    #[serial]
    fn test_overlay_no_flush_for_non_rw_dir() -> TestResult {
        use std::collections::HashMap;

        if check_available().is_err() {
            return Ok(());
        }

        // base/ is the overlay root (triggered by base/.sentinel file entry).
        // workspace/ is the workspace — its contents ARE flushed.
        // sibling/ is a sibling directory outside the workspace — writes are
        // blocked by Landlock and must not be flushed.
        // The default temp dir is under /tmp, which the sandbox can always
        // write. This test needs a directory outside of it.
        let Some(base) = non_tmp_tempdir() else {
            return Ok(());
        };
        let workspace = base.path().join("workspace");
        let sibling = base.path().join("sibling");
        std::fs::create_dir_all(&workspace).map_err(|e| format!("create workspace: {e}"))?;
        std::fs::create_dir_all(&sibling).map_err(|e| format!("create sibling: {e}"))?;

        let ws_file = workspace.join("ok.txt");
        let sibling_file = sibling.join("secret.txt");
        std::fs::write(&ws_file, "original-ws").map_err(|e| format!("write ws_file: {e}"))?;
        std::fs::write(&sibling_file, "original-sibling")
            .map_err(|e| format!("write sibling_file: {e}"))?;

        // Sentinel in base/ triggers overlay on base/ (covering both workspace/
        // and sibling/).
        let sentinel = base.path().join(".sentinel");
        std::fs::write(&sentinel, "s").map_err(|e| format!("write sentinel: {e}"))?;

        let mut paths = SandboxPaths::default();
        paths
            .read_write
            .push(sentinel.to_str().unwrap_or("").to_string());
        // workspace is NOT in read_write but is the workspace arg — it gets
        // added to rw_dirs automatically and its files are flushed.

        let config = SandboxConfig::new(workspace.clone(), paths, workspace.clone())
            .with_data_dir(workspace)
            .with_env(HashMap::new());
        let (test_env, path_dirs) = host_path_env();

        // The sandbox can write to workspace (Landlock allows it) but not to
        // sibling (Landlock denies it — the write fails silently).
        let cmd = format!(
            "printf 'modified-ws' > '{}'; printf 'should-not-persist' > '{}' 2>/dev/null; true",
            ws_file.display(),
            sibling_file.display()
        );

        let result = spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd],
            &test_env,
            &path_dirs,
        );
        let (mut child, overlay_handle, _netns) = match result {
            Ok(r) => r,
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(())
            }
            Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };
        let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
        assert!(status.success());
        crate::linux_overlayfs::teardown(handle);

        assert_eq!(
            std::fs::read_to_string(&ws_file).map_err(|e| format!("read ws_file: {e}"))?,
            "modified-ws",
            "workspace file must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&sibling_file)
                .map_err(|e| format!("read sibling_file: {e}"))?,
            "original-sibling",
            "file outside workspace and rw_dirs must NOT be modified on real FS"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_overlay_atomic_write_preserves_inode() -> TestResult {
        // Verify that the overlayfs + inotify pipeline correctly:
        //   1. lets the child atomically replace a write-listed file
        //      (create-temp → rename), and
        //   2. flushes the new content to the *real* inode so the inode
        //      number is unchanged after teardown.
        //
        // The test only asserts inode-preservation when the overlay handle is
        // `Some` (i.e. overlayfs mounted successfully). If the kernel lacks
        // user namespaces or the overlayfs module, the handle will be `None`
        // and the test exits without assertion failures.
        use std::collections::HashMap;
        use std::os::unix::fs::MetadataExt;
        if check_available().is_err() {
            return Ok(());
        }

        // The default temp dir is under /tmp, which the sandbox can always
        // write. This test needs a directory outside of it.
        let Some(temp) = non_tmp_tempdir() else {
            return Ok(());
        };
        let target = temp.path().join("target.json");
        std::fs::write(&target, r#"{"version":1}"#).map_err(|e| format!("write: {e}"))?;
        let inode_before = std::fs::metadata(&target)
            .map_err(|e| format!("metadata: {e}"))?
            .ino();

        // A SandboxConfig that lists target.json in read_write.
        let workspace = temp.path().to_path_buf();
        let mut paths = SandboxPaths::default();
        paths
            .read_write
            .push(target.to_str().unwrap_or("").to_string());

        let config = SandboxConfig::new(workspace.clone(), paths, workspace)
            .with_data_dir(temp.path().to_path_buf())
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();

        let new_content = r#"{"version":2}"#;
        // Atomic write: write to a sibling tmp file then rename into place.
        let tmp_path = temp.path().join("target.json.tmp");
        let cmd = format!(
            "printf '{}' > '{}' && mv '{}' '{}'",
            new_content,
            tmp_path.display(),
            tmp_path.display(),
            target.display(),
        );

        let result = spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd],
            &test_env,
            &path_dirs,
        );

        let (mut child, overlay_handle, _netns) = match result {
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                // Some CI/container environments deny pre_exec operations.
                return Ok(());
            }
            Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
            Ok(pair) => pair,
        };

        let status = child
            .wait()
            .map_err(|e| format!("Failed to wait on child: {e}"))?;

        if let Some(handle) = overlay_handle {
            // Flush upper-layer writes back to real inodes and clean up staging.
            crate::linux_overlayfs::teardown(handle);

            assert!(
                status.success(),
                "atomic write shell command should succeed"
            );

            let content = std::fs::read_to_string(&target).unwrap_or_default();
            let inode_after = std::fs::metadata(&target).map(|m| m.ino()).unwrap_or(0);

            assert_eq!(
                content, new_content,
                "overlayfs flush must write new content to real file"
            );
            assert_eq!(
                inode_before, inode_after,
                "real file inode must not change after overlayfs flush"
            );
        }
        // If overlay_handle is None, overlayfs is unavailable; skip assertions.
        Ok(())
    }

    // ========================================================================
    // Overlay coverage and permission tests
    //
    // These tests verify that:
    //   1. Non-accessible siblings inside an overlay dir get EACCES (mode 0000).
    //   2. The mode 0000 stub in the upper layer never leaks to the real FS.
    //   3. execute_access does not include ReadFile (execute-only enforcement).
    //
    // Tests that control $HOME set it temporarily via HomeGuard, which restores
    // the original value on drop — safe under #[serial] (tests don't run in
    // parallel).
    // ========================================================================

    /// RAII guard that saves and restores the HOME environment variable.
    ///
    /// Used by tests that temporarily redirect HOME to a temp directory so that
    /// `spawn_with_landlock` computes overlay roots relative to a fake home.
    struct HomeGuard(String);

    impl HomeGuard {
        fn set(new_home: &std::path::Path) -> Self {
            let old = std::env::var("HOME").unwrap_or_default();
            // SAFETY: this is a single-threaded test context (enforced by #[serial]).
            #[allow(deprecated)] // set_var is safe in single-threaded serial tests
            std::env::set_var("HOME", new_home);
            Self(old)
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            #[allow(deprecated)]
            std::env::set_var("HOME", &self.0);
        }
    }

    /// Spawn a sandboxed shell command with HOME pointed at `fake_home`.
    ///
    /// `rw_files` are added to `read_write` (file-level entries, which trigger
    /// overlay mounts via the MCA algorithm).  `rw_dirs` are added as directory
    /// entries so their writes are flushed back.  The command's working
    /// directory and data_dir are both `work_dir`.
    #[allow(clippy::too_many_arguments)]
    fn spawn_with_fake_home(
        fake_home: &std::path::Path,
        work_dir: &std::path::Path,
        rw_files: &[&std::path::Path],
        rw_dirs: &[&std::path::Path],
        cmd: &str,
    ) -> Option<(
        std::process::Child,
        Option<crate::linux_overlayfs::OverlayHandle>,
    )> {
        use std::collections::HashMap;

        if check_available().is_err() {
            return None;
        }

        let mut paths = SandboxPaths::default();
        for f in rw_files {
            if let Some(s) = f.to_str() {
                paths.read_write.push(s.to_string());
            }
        }
        for d in rw_dirs {
            if let Some(s) = d.to_str() {
                paths.read_write.push(s.to_string());
            }
        }

        let config = SandboxConfig::new(work_dir.to_path_buf(), paths, work_dir.to_path_buf())
            .with_data_dir(work_dir.to_path_buf())
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();

        // HOME must be set to fake_home before this call so that
        // spawn_with_landlock computes overlay roots relative to it.
        let _guard = HomeGuard::set(fake_home);

        match spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd.to_string()],
            &test_env,
            &path_dirs,
        ) {
            Ok((child, handle, _netns)) => Some((child, handle)),
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                None
            }
            #[allow(clippy::panic)] // unexpected spawn error in test helper — fail loudly
            Err(e) => panic!("spawn_with_landlock failed unexpectedly: {e:?}"),
        }
    }

    /// Non-accessible directories that are siblings of an accessible file inside
    /// the overlay root must be EACCES inside the sandbox.
    ///
    /// Setup: fake_home/.config/allowed.txt (accessible via read_write) and
    ///        fake_home/.config/secret/ (not accessible).
    ///
    /// Overlay root: ~/.config (MCA of accessible paths under home).
    ///
    /// Inside the overlay, `secret/` gets mode 0000 + opaque=y in the upper
    /// layer.  The sandboxed `ls` on that directory must return non-zero.
    #[test]
    #[serial]
    fn test_overlay_non_accessible_sibling_is_eacces() -> TestResult {
        // The default temp dir is under /tmp, which the sandbox can always
        // write. This test needs a directory outside of it.
        let Some(fake_home) = non_tmp_tempdir() else {
            return Ok(());
        };
        let config_dir = fake_home.path().join(".config");
        let allowed_file = config_dir.join("allowed.txt");
        let secret_dir = config_dir.join("secret");
        let work_dir = fake_home.path().join("work");
        let result_file = work_dir.join("ls_exit.txt");

        std::fs::create_dir_all(&config_dir).map_err(|e| format!("mkdir config: {e}"))?;
        std::fs::create_dir_all(&secret_dir).map_err(|e| format!("mkdir secret: {e}"))?;
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;
        std::fs::write(&allowed_file, "allowed").map_err(|e| format!("write: {e}"))?;
        std::fs::write(secret_dir.join("top-secret.txt"), "secret")
            .map_err(|e| format!("write secret: {e}"))?;

        // Command: attempt ls on the non-accessible dir; record exit status in work_dir.
        let cmd = format!(
            "ls '{secret}' > /dev/null 2>&1; echo $? > '{out}'",
            secret = secret_dir.display(),
            out = result_file.display(),
        );

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&allowed_file],
            &[&work_dir],
            &cmd,
        ) else {
            return Ok(()); // overlayfs or user namespaces unavailable
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(()); // overlay not active (no file-type rw entries produced roots)
        };

        let status = child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(status.success(), "outer shell command should exit 0");

        let ls_exit: i32 = std::fs::read_to_string(&result_file)
            .map_err(|e| format!("read result: {e}"))?
            .trim()
            .parse()
            .map_err(|e| format!("parse exit: {e}"))?;

        assert_ne!(
            ls_exit, 0,
            "ls on non-accessible dir must fail inside sandbox \
             (expected EACCES from mode-0000 upper-layer stub)"
        );
        Ok(())
    }

    /// Mode 0000 stubs in the overlay's upper layer must NOT leak to the real
    /// filesystem after teardown.
    ///
    /// The upper layer is a separate staging directory; the real directory is
    /// never chmod'd.  After the sandbox exits and teardown() is called, the
    /// real directory permissions must be identical to what they were before
    /// the sandbox ran.
    #[test]
    #[serial]
    fn test_overlay_real_permissions_not_leaked() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let config_dir = fake_home.path().join(".config");
        let allowed_file = config_dir.join("allowed.txt");
        let private_dir = config_dir.join("private");
        let work_dir = fake_home.path().join("work");

        std::fs::create_dir_all(&config_dir).map_err(|e| format!("mkdir config: {e}"))?;
        std::fs::create_dir_all(&private_dir).map_err(|e| format!("mkdir private: {e}"))?;
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;
        std::fs::write(&allowed_file, "data").map_err(|e| format!("write: {e}"))?;

        // Record original permissions of private_dir before the sandbox touches anything.
        let perms_before = std::fs::metadata(&private_dir)
            .map_err(|e| format!("metadata before: {e}"))?
            .permissions()
            .mode();

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&allowed_file],
            &[&work_dir],
            "true",
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        let perms_after = std::fs::metadata(&private_dir)
            .map_err(|e| format!("metadata after: {e}"))?
            .permissions()
            .mode();

        assert_eq!(
            perms_before, perms_after,
            "mode 0000 in overlay upper layer must not leak to real filesystem: \
             before=0o{perms_before:o} after=0o{perms_after:o}"
        );
        Ok(())
    }

    /// Delete a pre-existing file that lives inside an rw directory.
    /// After teardown the file must be gone from the real filesystem.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_file_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("data");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("to_delete.txt");
        std::fs::write(&target, "will be deleted").map_err(|e| format!("write: {e}"))?;
        assert!(
            target.exists(),
            "pre-condition: file must exist before sandbox"
        );

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")],
            &format!("rm '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        assert!(
            !target.exists(),
            "file deleted inside sandbox must be removed from real FS after teardown"
        );
        Ok(())
    }

    /// Delete a pre-existing file that is listed directly in `read_write`
    /// (write_set entry rather than rw_dir).  After teardown the file must be
    /// gone from the real filesystem.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_direct_write_set_entry() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let target = temp.path().join("config.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;
        assert!(
            target.exists(),
            "pre-condition: file must exist before sandbox"
        );

        let active = run_sandboxed_rw(
            temp.path(),
            &[target.to_str().unwrap_or("")],
            &format!("rm '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        assert!(
            !target.exists(),
            "write_set file deleted inside sandbox must be removed from real FS after teardown"
        );
        Ok(())
    }

    /// Delete a pre-existing file inside an rw_dir that lives under the overlay
    /// root (i.e. under `fake_home`).
    ///
    /// This is the scenario that exposed the char-device whiteout bug: overlayfs
    /// only creates a `user.overlay.whiteout` xattr when USERSPACE creates the
    /// whiteout stub.  When the kernel itself handles `unlink(2)` for a file that
    /// exists in the lower layer, it creates a **char device (major=0, minor=0)**
    /// whiteout instead.  The old `is_overlay_whiteout` only checked for the
    /// xattr, so kernel-created whiteouts were silently skipped and the real file
    /// was never deleted.
    ///
    /// The previous deletion tests (`test_overlay_flush_delete_file_in_rw_dir`)
    /// used a temp dir under `/tmp`, which is outside `home_dir`.  No overlayfs
    /// is mounted for paths outside `home_dir`, so `rm` hit the real FS directly
    /// and no whiteout was ever produced — the bug was invisible.
    ///
    /// This test uses `spawn_with_fake_home` so the rw_dir IS under the overlay
    /// root, triggering the full overlayfs whiteout path.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_under_overlay_root() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        // Place the rw_dir and the target file INSIDE fake_home so that
        // `overlay_roots_for_accessible` computes an overlay root and
        // overlayfs is actually mounted.
        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;
        let target = rw_dir.join("to_delete.txt");
        std::fs::write(&target, "will be deleted").map_err(|e| format!("write: {e}"))?;
        assert!(
            target.exists(),
            "pre-condition: file must exist before sandbox"
        );

        // A file-level read_write entry is needed to trigger the overlay mount
        // on fake_home (the MCA algorithm picks the parent of file entries as
        // the overlay root).
        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file], // file entry → overlay mounted on fake_home/
            &[&rw_dir],   // dir entry → deletions inside rw_dir are flushed
            &format!("rm '{}'", target.display()),
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            !target.exists(),
            "file deleted inside sandbox must be removed from real FS: \
             char-device whiteout (major=0, minor=0) must be detected by \
             is_overlay_whiteout, not just the user.overlay.whiteout xattr"
        );
        Ok(())
    }

    /// An upper-layer-only directory that is deleted inside the sandbox must be
    /// removed from the real filesystem.
    ///
    /// When an upper-layer-only directory is removed with `rmdir`/`rm -rf`,
    /// overlayfs simply removes it from upper with no whiteout — it fires
    /// `IN_DELETE | IN_ISDIR` on the parent.  Previously the `IN_ISDIR` branch
    /// only handled creation events, so directory deletions were silently ignored
    /// and the real directory was left behind.
    #[test]
    #[serial]
    fn test_overlay_delete_session_created_dir() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        // Reproduce the exact sequence from the manual test:
        // mkdir sub, write sub/file, mv sub/file .., rm -rf sub
        let sub = rw_dir.join("sub");
        let kept = rw_dir.join("kept.txt");
        let cmd = format!(
            "mkdir -p '{sub}' && \
             echo hi > '{sub}/tmp.txt' && \
             mv '{sub}/tmp.txt' '{kept}' && \
             rm -rf '{sub}'",
            sub = sub.display(),
            kept = kept.display(),
        );
        let Some((mut child, overlay_handle)) =
            spawn_with_fake_home(fake_home.path(), &work_dir, &[&dot_file], &[&rw_dir], &cmd)
        else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            kept.exists(),
            "file moved out of deleted subdir must exist on real FS"
        );
        assert!(
            !sub.exists(),
            "upper-layer-only directory deleted inside sandbox must be removed \
             from real FS: IN_DELETE|IN_ISDIR must trigger flush_deletion"
        );
        Ok(())
    }

    /// Atomic write pattern (write tmp → rename to target) must not leave the
    /// tmp file on the real filesystem.
    ///
    /// This is the Edit tool pattern: write content to `file.rs.tmp.PID.TS`,
    /// then `rename(tmp, file.rs)`.  In overlayfs, if `tmp` has no lower-layer
    /// copy, the rename produces only `IN_MOVED_FROM` on `tmp` — no whiteout,
    /// no `IN_DELETE`.  Without watching `IN_MOVED_FROM` the tmp file flushed
    /// during `IN_CLOSE_WRITE` would stay on the real FS forever.
    #[test]
    #[serial]
    fn test_overlay_atomic_write_no_tmp_residue() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;
        let target = rw_dir.join("file.rs");
        let tmp = rw_dir.join("file.rs.tmp.99999.1234567890");

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        // Simulate Edit tool: write to tmp, then atomically rename to target.
        let cmd = format!(
            "echo 'content' > '{}' && mv '{}' '{}'",
            tmp.display(),
            tmp.display(),
            target.display(),
        );
        let Some((mut child, overlay_handle)) =
            spawn_with_fake_home(fake_home.path(), &work_dir, &[&dot_file], &[&rw_dir], &cmd)
        else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            target.exists(),
            "target file must exist on real FS after atomic write"
        );
        assert!(
            !tmp.exists(),
            "tmp file must be deleted from real FS after rename: \
             IN_MOVED_FROM must trigger flush_deletion for upper-layer-only files"
        );
        Ok(())
    }

    /// Delete a pre-existing directory (with nested content) inside an rw_dir
    /// that lives under the overlay root.
    ///
    /// `rm -rf dir` triggers an overlayfs opaque-directory whiteout followed by
    /// an `IN_DELETE | IN_ISDIR` inotify event on the parent.  `flush_deletion`
    /// must use `remove_dir_all`, not `remove_file`, to propagate this.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_dir_under_overlay_root() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        let target_dir = rw_dir.join("to_delete");
        let nested_file = target_dir.join("sub").join("file.txt");
        let nested_parent = nested_file.parent().ok_or("nested file has no parent")?;
        std::fs::create_dir_all(nested_parent).map_err(|e| format!("mkdir nested: {e}"))?;
        std::fs::write(&nested_file, "nested").map_err(|e| format!("write nested: {e}"))?;
        assert!(
            target_dir.exists(),
            "pre-condition: dir must exist before sandbox"
        );

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file],
            &[&rw_dir],
            &format!("rm -rf '{}'", target_dir.display()),
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            !target_dir.exists(),
            "directory deleted inside sandbox must be removed from real FS: \
             flush_deletion must handle EISDIR by falling back to remove_dir_all"
        );
        Ok(())
    }

    /// A file written inside the sandbox with non-default permissions must have
    /// those permissions flushed to the real filesystem.
    ///
    /// Regression for the case where `flush_file` preserved content but the
    /// flushed file ended up with default umask permissions instead of the
    /// permissions set inside the sandbox.
    #[test]
    #[serial]
    fn test_overlay_flush_permissions_under_overlay_root() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;
        let target = rw_dir.join("script.sh");
        std::fs::write(&target, "#!/bin/sh\necho hi\n").map_err(|e| format!("write: {e}"))?;

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        // chmod 755 inside the sandbox; teardown must preserve 0o755.
        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file],
            &[&rw_dir],
            &format!("chmod 755 '{}'", target.display()),
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        let mode = std::fs::metadata(&target)
            .map_err(|e| format!("metadata: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "permissions set inside sandbox must be flushed to real FS: got 0o{mode:o}"
        );
        Ok(())
    }

    /// Deleting a non-rw file inside the sandbox must NOT affect the real FS.
    ///
    /// Files and directories that are accessible (readable) but not in any
    /// `rw_dir` or `write_set` entry are session-scoped: the overlayfs whiteout
    /// stays in the upper layer but is never flushed back.  The real file must
    /// survive the sandbox session intact.
    #[test]
    #[serial]
    fn test_overlay_delete_readonly_not_flushed() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        // readonly_dir is accessible but NOT in rw_dirs — deletions must not
        // propagate to real FS.
        let readonly_dir = fake_home.path().join("readonly");
        std::fs::create_dir_all(&readonly_dir).map_err(|e| format!("mkdir readonly: {e}"))?;
        let readonly_file = readonly_dir.join("protected.txt");
        std::fs::write(&readonly_file, "must survive").map_err(|e| format!("write: {e}"))?;

        let readonly_subdir = readonly_dir.join("subdir");
        std::fs::create_dir_all(&readonly_subdir).map_err(|e| format!("mkdir subdir: {e}"))?;
        let readonly_nested = readonly_subdir.join("nested.txt");
        std::fs::write(&readonly_nested, "also survives").map_err(|e| format!("write: {e}"))?;

        // dot_file triggers the overlay mount; rw_dirs is empty so nothing is
        // ever flushed back.
        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        let cmd = format!(
            "rm '{}' && rm -rf '{}'",
            readonly_file.display(),
            readonly_subdir.display(),
        );
        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file],
            &[], // no rw_dirs → nothing flushed
            &cmd,
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            readonly_file.exists(),
            "non-rw file deleted inside sandbox must still exist on real FS"
        );
        assert!(
            readonly_subdir.exists(),
            "non-rw directory deleted inside sandbox must still exist on real FS"
        );
        assert!(
            readonly_nested.exists(),
            "non-rw nested file deleted inside sandbox must still exist on real FS"
        );
        Ok(())
    }

    /// Execute-only access must NOT include `ReadFile`.
    ///
    /// Paths in `paths.execute` should be execute-only: the sandboxed process
    /// can `execve` binaries there but cannot `open(O_RDONLY)` them (which
    /// would let an attacker exfiltrate binary content).
    ///
    /// System library paths (`READ_EXECUTE`) intentionally DO include
    /// `ReadFile` because the dynamic linker uses `open()` to load `.so` files.
    #[test]
    fn test_execute_access_excludes_read_file() {
        assert_eq!(access::EXECUTE_ONLY & access::READ_FILE, 0);
        assert_ne!(access::READ_EXECUTE & access::READ_FILE, 0);
        assert_eq!(access::ALL & access::EXECUTE_ONLY, access::EXECUTE_ONLY);
    }

    // ========================================================================
    // Device set, masks and ordering
    // ========================================================================

    #[test]
    fn test_dev_paths_are_minimal() {
        assert!(!DEV_RW_PATHS.contains(&"/dev"));
        assert!(!DEV_READ_PATHS.contains(&"/dev"));
        for p in ["/dev/shm", "/dev/mqueue"] {
            assert!(
                !DEV_RW_PATHS.contains(&p),
                "{p} must not be writable by default"
            );
            assert!(!DEV_READ_PATHS.contains(&p));
        }
        for p in ["/dev/null", "/dev/tty", "/dev/pts", "/dev/ptmx"] {
            assert!(DEV_RW_PATHS.contains(&p), "{p} must be writable");
        }
        assert!(DEV_READ_PATHS.contains(&"/dev/urandom"));
        let set = compute_accessible_set(&make_test_config(), &[]);
        assert!(!set.contains(Path::new("/dev")));
        assert!(set.contains(Path::new("/dev/null")));
    }

    #[test]
    fn test_system_paths_include_nix_store() {
        assert!(SYSTEM_PATHS.contains(&"/nix/store"));
        assert!(!SYSTEM_PATHS.contains(&"/"));
    }

    #[test]
    fn test_is_explicitly_allowed() {
        let mask = Path::new("/run/user/1000");
        let ancestor_only = vec![PathBuf::from("/"), PathBuf::from("/run")];
        assert!(!is_explicitly_allowed(mask, &ancestor_only));
        let inside = vec![PathBuf::from("/run/user/1000/bus")];
        assert!(is_explicitly_allowed(mask, &inside));
        let exact = vec![PathBuf::from("/run/user/1000")];
        assert!(is_explicitly_allowed(mask, &exact));
        let sibling = vec![PathBuf::from("/run/user/10000")];
        assert!(!is_explicitly_allowed(mask, &sibling));
    }

    #[test]
    fn test_mask_targets_skip_configured_runtime_dir() {
        let mut paths = SandboxPaths::default();
        paths.read_write.push("/run/user/4242/app".to_string());
        let config = SandboxConfig::new(PathBuf::from("/tmp"), paths, PathBuf::from("/tmp"));
        let (dirs, _) = mask_targets(&config, 4242);
        assert!(!dirs.contains(&PathBuf::from("/run/user/4242")));
    }

    #[test]
    fn test_read_write_helpers_handle_pipes() -> TestResult {
        let (r, w) = cloexec_pipe().map_err(|e| format!("pipe: {e}"))?;
        write_all_fd(w.as_raw_fd(), b"abcd")?;
        drop(w);
        let mut buf = [0u8; 4];
        assert!(read_exact_fd(r.as_raw_fd(), &mut buf)?);
        assert_eq!(&buf, b"abcd");
        // EOF before any byte.
        assert!(!read_exact_fd(r.as_raw_fd(), &mut buf)?);
        Ok(())
    }

    /// With no overlays and `LocalhostOnly`, the child must write its UID map
    /// before Landlock applies. A wrong order runs the child as UID 65534.
    #[test]
    #[serial]
    fn test_spawn_keeps_real_uid() -> TestResult {
        use std::collections::HashMap;
        if check_available().is_err() {
            return Ok(());
        }
        let (Some(sh), Some(id_bin)) = (which("sh"), which("id")) else {
            return Ok(()); // skip: no sh or id in PATH
        };
        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir)
        .with_network(NetworkMode::LocalhostOnly);
        let mut path_dirs = test_path_dirs(&sh);
        path_dirs.extend(test_path_dirs(&id_bin));
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let script = format!("[ \"$({} -u)\" = {uid} ]", id_bin.display());
        let (mut child, _overlay, _netns) = spawn_with_landlock(
            &config,
            &sh.to_string_lossy(),
            &["-c".to_string(), script],
            &HashMap::new(),
            &path_dirs,
        )
        .map_err(|e| format!("spawn failed: {e:?}"))?;
        assert!(
            child.wait()?.success(),
            "the child must run with the real UID, not 65534"
        );
        Ok(())
    }

    // ========================================================================
    // Test helpers
    // ========================================================================

    /// A temp dir outside /tmp and /var/tmp (which the sandbox can always
    /// write), in the crate directory. Returns `None` if the crate directory
    /// is itself under a temp path.
    fn non_tmp_tempdir() -> Option<TempDir> {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"));
        if TEMP_PATHS.iter().any(|t| base.starts_with(t)) {
            return None;
        }
        tempfile::tempdir_in(base).ok()
    }

    /// The PATH of the test process as a child environment, and the PATH
    /// directories with their canonical targets (for the Landlock rules).
    fn host_path_env() -> (std::collections::HashMap<String, String>, Vec<PathBuf>) {
        let path = std::env::var("PATH").unwrap_or_default();
        let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
        for d in dirs.clone() {
            if let Ok(real) = std::fs::canonicalize(&d) {
                dirs.push(real);
            }
        }
        dirs.push(PathBuf::from("/bin"));
        dirs.push(PathBuf::from("/usr/bin"));
        let mut env = std::collections::HashMap::new();
        env.insert("PATH".to_string(), path);
        (env, dirs)
    }

    /// Find `name` in PATH (like `which`). Returns `None` if it is absent.
    fn which(name: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join(name))
                .find(|p| p.is_file())
        })
    }

    /// PATH-like directories for a test binary: its directory and the
    /// directory of its canonical target.
    fn test_path_dirs(bin: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = bin.parent().map(Path::to_path_buf).into_iter().collect();
        if let Some(real) = std::fs::canonicalize(bin)
            .ok()
            .and_then(|r| r.parent().map(Path::to_path_buf))
        {
            v.push(real);
        }
        v.push(PathBuf::from("/usr/bin"));
        v.push(PathBuf::from("/bin"));
        v
    }
}
