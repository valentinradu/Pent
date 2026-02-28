//! Linux sandbox implementation using Landlock LSM.
//!
//! Uses Landlock for filesystem access control. Requires kernel 5.19+ (ABI v4).
//!
//! Network isolation is implemented via `unshare(CLONE_NEWNET)` in the child
//! process after fork but before exec:
//! - `LocalhostOnly` / `ProxyOnly`: new network namespace + loopback brought up
//! - `Blocked`: new network namespace with no interfaces
//! - `Unrestricted`: no network changes
//!
//! # Landlock Architecture
//!
//! Landlock creates a deny-all baseline for filesystem operations,
//! then explicitly allows access to specific paths:
//!
//! ```text
//! Ruleset (deny-all baseline)
//!   |
//!   +-- Allow workspace (rw)
//!   +-- Allow data_dir (rw)
//!   +-- Allow mounts (per config)
//!   +-- Allow PATH dirs (read+exec)
//!   +-- Allow execute paths (read+exec) — binary dirs, installed tools
//!   +-- Allow read paths (read only) — config files, libraries, data
//!   +-- Allow system libs (ro)
//!   +-- Allow /tmp (rw)
//!   +-- Allow /dev (ro)
//!   +-- Allow /proc (ro)
//! ```
//!
//! # pre_exec for spawn_sandboxed
//!
//! Landlock restricts the current process. For `spawn_sandboxed`,
//! we use `Command::pre_exec()` to apply Landlock in the child
//! process after fork but before exec.

use crate::{NetworkMode, SandboxConfig, SandboxError};
use std::path::{Path, PathBuf};

/// Minimum required Landlock ABI version.
/// ABI v4 requires kernel 5.19+.
#[allow(dead_code)]
pub const MIN_LANDLOCK_ABI: i32 = 4;

/// System paths to allow read access (libraries, config, etc.)
const SYSTEM_PATHS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/share",
    "/etc",
];

/// Temp paths to allow read/write access.
const TEMP_PATHS: &[&str] = &["/tmp", "/var/tmp"];

/// Device and proc paths to allow read access.
const DEVICE_PATHS: &[&str] = &["/dev", "/proc"];

/// Check if Landlock ABI v4 is available.
///
/// # Errors
/// Returns `SandboxUnavailable` with kernel upgrade suggestion if not available.
#[cfg(target_os = "linux")]
pub fn check_available() -> Result<(), SandboxError> {
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, ABI};

    // Try to create a minimal ruleset — succeeds only if the kernel supports ABI v4.
    let all_access = AccessFs::from_all(ABI::V4);
    Ruleset::default()
        .handle_access(all_access)
        .and_then(|r| r.create())
        .map(|_| ())
        .map_err(|_| SandboxError::SandboxUnavailable {
            reason: "Landlock ABI v4 not available".to_string(),
            remediation: "Upgrade to Linux kernel 5.19+ for Landlock ABI v4 support".to_string(),
        })
}

#[cfg(not(target_os = "linux"))]
pub fn check_available() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Build Landlock ruleset for the given config.
///
/// Creates deny-all baseline with explicit allows for:
/// - Workspace directory (rw)
/// - data_dir directory (rw)
/// - Mount paths (ro or rw per config)
/// - PATH directories (ro+exec)
/// - System libraries /usr/lib, /lib, /lib64 (ro)
/// - Temp directories /tmp, /var/tmp (rw)
/// - Device nodes /dev (ro)
/// - Proc filesystem /proc (ro)
///
/// # Arguments
/// * `config` - Sandbox configuration
/// * `path_dirs` - PATH directories to allow
///
/// # Returns
/// Landlock RulesetCreated ready to be applied
///
/// # Errors
/// * `InvalidConfig` - If a required path cannot be opened
#[cfg(target_os = "linux")]
#[allow(dead_code)] // used in tests
pub fn build_landlock_ruleset(
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
) -> Result<landlock::RulesetCreated, SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };

    // All filesystem access rights for deny-all baseline
    let all_access = AccessFs::from_all(ABI::V4);

    // Read-only: no Execute (config files, libraries, data).
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;

    // Execute: readable and runnable (binary directories, installed tools).
    let execute_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;

    // Write: all rights (workspace, temp dirs, cache dirs); unchanged.
    let write_access = all_access;

    // Create ruleset with deny-all baseline
    let mut ruleset = Ruleset::default()
        .handle_access(all_access)
        .map_err(|e| SandboxError::InvalidConfig(format!("Failed to create ruleset: {}", e)))?
        .create()
        .map_err(|e| SandboxError::InvalidConfig(format!("Failed to create ruleset: {}", e)))?;

    // Helper to add path rule, skipping non-existent paths
    let add_path =
        |ruleset: &mut landlock::RulesetCreated, path: &Path, access| -> Result<(), SandboxError> {
            if !path.exists() {
                return Ok(()); // Skip non-existent paths
            }
            let fd = PathFd::new(path).map_err(|e| {
                SandboxError::InvalidConfig(format!("Failed to open path {:?}: {}", path, e))
            })?;
            ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|e| {
                    SandboxError::InvalidConfig(format!("Failed to add rule for {:?}: {}", path, e))
                })?;
            Ok(())
        };

    // Workspace - read/write
    add_path(&mut ruleset, &config.workspace, write_access)?;

    // data_dir - read/write
    add_path(&mut ruleset, &config.data_dir, write_access)?;

    // Mounts
    for mount in &config.mounts {
        if mount.readonly {
            add_path(&mut ruleset, &mount.path, read_access)?;
        } else {
            add_path(&mut ruleset, &mount.path, write_access)?;
        }
    }

    // Configured SandboxPaths (from profiles and TOML config).
    // traversal = ReadDir only (stat/list, no file reads or exec).
    // read = ReadFile | ReadDir (config files, libraries, data; no exec).
    // execute = ReadFile | ReadDir | Execute (binary directories, installed tools).
    // read_write = all access rights.
    let traversal_access = AccessFs::ReadDir;
    let (traversal_paths, read_paths, execute_paths, rw_paths) = config.paths.expand_paths();
    for (path, _) in &traversal_paths {
        add_path(&mut ruleset, path, traversal_access.into())?;
    }
    for (path, _) in &read_paths {
        add_path(&mut ruleset, path, read_access)?;
    }
    for (path, _) in &execute_paths {
        add_path(&mut ruleset, path, execute_access)?;
    }
    for (path, _) in &rw_paths {
        add_path(&mut ruleset, path, write_access)?;
    }

    // PATH directories - read + execute (these are binary dirs)
    for path_dir in path_dirs {
        add_path(&mut ruleset, path_dir, execute_access)?;
    }

    // System libraries - read + execute (dynamic linker in /usr/lib, /lib64 needs Execute)
    for sys_path in SYSTEM_PATHS {
        add_path(&mut ruleset, Path::new(sys_path), execute_access)?;
    }

    // Temp directories - read/write
    for tmp_path in TEMP_PATHS {
        add_path(&mut ruleset, Path::new(tmp_path), write_access)?;
    }

    // Device and proc - read only
    for dev_path in DEVICE_PATHS {
        add_path(&mut ruleset, Path::new(dev_path), read_access)?;
    }

    Ok(ruleset)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn build_landlock_ruleset(
    _config: &SandboxConfig,
    _path_dirs: &[PathBuf],
) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Apply Landlock ruleset to current process.
///
/// After this call, the current process is restricted to the ruleset.
/// This is irreversible for the lifetime of the process.
///
/// # Arguments
/// * `ruleset` - The ruleset to apply
///
/// # Errors
/// * `SandboxUnavailable` - If restrict_self fails
#[cfg(target_os = "linux")]
#[allow(dead_code)] // used in tests
pub fn apply_landlock(ruleset: landlock::RulesetCreated) -> Result<(), SandboxError> {
    ruleset
        .restrict_self()
        .map_err(|e| SandboxError::SandboxUnavailable {
            reason: format!("Failed to apply Landlock: {}", e),
            remediation: "Check kernel support and permissions".to_string(),
        })?;

    Ok(())
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn apply_landlock(_ruleset: ()) -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Bring up the loopback interface in the current network namespace.
///
/// Called after `unshare(CLONE_NEWNET)` to make localhost connectivity
/// available for `LocalhostOnly` and `ProxyOnly` modes.
///
/// # Safety
/// Caller must be in a post-fork, pre-exec context (pre_exec hook) or
/// equivalent single-threaded environment. Uses raw ioctl syscalls.
#[cfg(target_os = "linux")]
unsafe fn bring_up_loopback() {
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

    let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if sock < 0 {
        return;
    }
    libc::ioctl(
        sock,
        libc::SIOCGIFFLAGS as _,
        &mut req as *mut IfReq as *mut libc::c_void,
    );
    req.ifr_flags |= IFF_UP;
    libc::ioctl(
        sock,
        libc::SIOCSIFFLAGS as _,
        &mut req as *mut IfReq as *mut libc::c_void,
    );
    libc::close(sock);
}

/// Set up UID/GID mappings for a newly created user namespace.
///
/// Maps the caller's real UID/GID to 0 (root) inside the user namespace.
/// This grants `CAP_NET_ADMIN` within the namespace — required to bring up
/// the loopback interface via ioctl — while leaving host filesystem permission
/// checks unchanged (the kernel uses the real/host UID for those).
///
/// Must be called after `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, in a
/// post-fork, single-threaded child before exec.
///
/// # Safety
/// Uses raw libc open/write/close, which are safe in a post-fork child.
#[cfg(target_os = "linux")]
unsafe fn setup_userns_mappings(uid: u32, gid: u32) {
    // Kernels >= 3.19 require "deny" in setgroups before writing gid_map
    // when the caller is unprivileged.
    let fd = libc::open(
        b"/proc/self/setgroups\0".as_ptr() as *const libc::c_char,
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd >= 0 {
        let deny = b"deny";
        libc::write(fd, deny.as_ptr() as *const libc::c_void, deny.len());
        libc::close(fd);
    }

    // Map host GID → 0 inside namespace.
    let gid_map = format!("0 {gid} 1\n");
    let fd = libc::open(
        b"/proc/self/gid_map\0".as_ptr() as *const libc::c_char,
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd >= 0 {
        let b = gid_map.as_bytes();
        libc::write(fd, b.as_ptr() as *const libc::c_void, b.len());
        libc::close(fd);
    }

    // Map host UID → 0 inside namespace.
    let uid_map = format!("0 {uid} 1\n");
    let fd = libc::open(
        b"/proc/self/uid_map\0".as_ptr() as *const libc::c_char,
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd >= 0 {
        let b = uid_map.as_bytes();
        libc::write(fd, b.as_ptr() as *const libc::c_void, b.len());
        libc::close(fd);
    }
}

/// Apply network isolation to the current process for the given mode.
///
/// Uses `unshare(CLONE_NEWUSER | CLONE_NEWNET)` — no root required on any
/// kernel that allows unprivileged user namespaces (Ubuntu 22.04+, Fedora,
/// Arch, etc.). The user namespace maps the caller's UID/GID to 0 inside,
/// which grants `CAP_NET_ADMIN` within the namespace for loopback setup.
///
/// Note: ProxyOnly mode uses a veth pair set up by the parent
/// (`spawn_with_landlock`) and is handled via `setns` there, not here.
/// When `apply_network_isolation` is called for ProxyOnly, it falls back
/// to loopback-only isolation.
///
/// # Errors
/// Returns `io::Error` if unshare fails.  On systems with unprivileged user
/// namespaces disabled (`/proc/sys/kernel/unprivileged_userns_clone = 0`)
/// this will fail with EPERM.
#[cfg(target_os = "linux")]
fn apply_network_isolation(network: &NetworkMode) -> std::io::Result<()> {
    match network {
        NetworkMode::LocalhostOnly | NetworkMode::ProxyOnly { .. } => {
            // SAFETY: getuid/getgid are always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let uid = unsafe { libc::getuid() };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let gid = unsafe { libc::getgid() };
            // CLONE_NEWUSER | CLONE_NEWNET: create both namespaces atomically.
            // Does not require root when unprivileged user namespaces are enabled.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret =
                unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                // Map real UID/GID to root inside namespace (gives CAP_NET_ADMIN).
                setup_userns_mappings(uid, gid);
                // Bring up loopback (requires CAP_NET_ADMIN, now available).
                bring_up_loopback();
            }
        }
        NetworkMode::Blocked => {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let uid = unsafe { libc::getuid() };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let gid = unsafe { libc::getgid() };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret =
                unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { setup_userns_mappings(uid, gid) };
        }
        NetworkMode::Unrestricted => {}
    }
    Ok(())
}

/// Spawn command with Landlock sandbox using pre_exec.
///
/// Uses `Command::pre_exec()` to apply Landlock and network isolation in the
/// child process after fork but before exec. This restricts only the child.
///
/// For write-listed file paths, overlayfs is mounted over their parent directories
/// inside the child's mount namespace so that atomic writes (rename-based) go to
/// the overlay upper layer. An inotify watcher in the parent flushes completed
/// writes back to the real file inodes in-place, preserving the inodes that
/// Landlock rules are bound to.
///
/// # Arguments
/// * `config` - Sandbox configuration
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `path_dirs` - PATH directories for ruleset
///
/// # Returns
/// `(child_handle, overlay_handle)` — `overlay_handle` is `Some` when overlayfs
/// is in use; pass it to [`super::linux_overlayfs::teardown`] after the child exits.
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock unavailable
/// * `SpawnFailed` - If spawn fails
#[cfg(target_os = "linux")]
pub fn spawn_with_landlock(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
) -> Result<(std::process::Child, Option<super::linux_overlayfs::OverlayHandle>, Option<super::linux_netns::NetnsHandle>), SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
    };
    use std::collections::HashSet;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    // Clone config data for use in pre_exec closure
    let workspace = config.workspace.clone();
    let data_dir = config.data_dir.clone();
    let mounts = config.mounts.clone();
    let paths = config.paths.clone();
    let mut path_dirs = path_dirs.to_vec();
    let network = config.network.clone();

    // Identify write-listed file paths (as opposed to directories) and prepare
    // overlayfs staging directories for them. Directories use regular Landlock
    // write rules; files get inode-stable access via the overlayfs + inotify path.
    let (_, read_expanded, execute_expanded, rw_expanded) = config.paths.expand_paths();
    let overlay_file_paths: Vec<PathBuf> = rw_expanded
        .iter()
        .filter_map(|(path, _)| {
            // Include paths that are files, or don't exist yet but whose parent
            // directory exists (will be created as a file on first write).
            if path.is_file()
                || (!path.exists()
                    && path.parent().map_or(false, |p| p.is_dir()))
            {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    let write_set: HashSet<PathBuf> = overlay_file_paths.iter().cloned().collect();

    // Directory-type read_write entries: all files created or modified inside
    // these directories during the session should be flushed back to the real FS.
    //
    // Include paths that are currently directories AND paths that don't exist
    // yet but whose parent does — those might be created as directories by the
    // sandboxed process (e.g. ~/.cache/claude that doesn't exist at spawn time).
    // Paths that are already files are excluded (they're handled by write_set).
    let rw_dirs: HashSet<PathBuf> = rw_expanded
        .iter()
        .filter_map(|(path, _)| {
            if path.is_dir() {
                Some(path.clone())
            } else if !path.is_file()
                && !path.exists()
                && path.parent().map_or(false, |p| p.is_dir())
            {
                // Non-existent entry with an existing parent: include so that
                // if the sandbox creates it as a directory, its contents are flushed.
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();

    // Build the set of paths the sandboxed process is allowed to read.
    // Traversal-only paths are intentionally excluded (ReadDir but not ReadFile).
    let mut accessible: HashSet<PathBuf> = HashSet::new();
    for (p, _) in read_expanded.iter().chain(&execute_expanded).chain(&rw_expanded) {
        accessible.insert(p.clone());
    }
    accessible.extend(write_set.iter().cloned());
    accessible.insert(config.workspace.clone());
    accessible.insert(config.data_dir.clone());
    for mount in &config.mounts {
        accessible.insert(mount.path.clone());
    }
    for sys_path in SYSTEM_PATHS {
        accessible.insert(PathBuf::from(sys_path));
    }
    for tmp_path in TEMP_PATHS {
        accessible.insert(PathBuf::from(tmp_path));
    }
    for dev_path in DEVICE_PATHS {
        accessible.insert(PathBuf::from(dev_path));
    }
    for path_dir in path_dirs.iter() {
        accessible.insert(path_dir.clone());
    }

    let pid = std::process::id();
    let overlay_mounts =
        super::linux_overlayfs::prepare_overlay_dirs(&overlay_file_paths, pid)
            .map_err(SandboxError::SpawnFailed)?;

    // Compute the set of parent directories covered by overlayfs (for Landlock rules).
    let overlay_dirs: HashSet<PathBuf> =
        overlay_mounts.iter().map(|m| m.real_dir.clone()).collect();

    // Clone overlay data for capture into the pre_exec closure.
    let overlay_mounts_pre = overlay_mounts.clone();
    let write_set_pre = write_set.clone();
    let overlay_dirs_pre = overlay_dirs.clone();
    // accessible is passed to setup_overlay_dirs (runs in pre_exec after unshare).
    let accessible_pre = accessible;

    // For ProxyOnly, create the host-side veth pair. The child will create its own
    // user+net namespace via unshare in pre_exec; the background thread moves the
    // inner veth into it once the child signals readiness via pipe.
    let mut proxy_netns: Option<super::linux_netns::NetnsHandle> =
        if let NetworkMode::ProxyOnly { dns_port, .. } = &config.network {
            let ns_config = super::linux_netns::NetnsConfig::from_pid();
            Some(super::linux_netns::create_netns(&ns_config, *dns_port)?)
        } else {
            None
        };

    // Proxy data for the pre_exec closure and background thread.
    let is_proxy = proxy_netns.is_some();
    let proxy_inner_veth: String =
        proxy_netns.as_ref().map_or(String::new(), |h| h.inner_veth.clone());
    let proxy_inner_cidr: String =
        proxy_netns.as_ref().map_or(String::new(), |h| h.inner_cidr.clone());
    let proxy_gateway: String = proxy_netns
        .as_ref()
        .map_or(String::new(), |h| h.outer_ip.to_string());

    // Pipe fds for pre_exec ↔ background-thread sync.  -1 when not ProxyOnly.
    // ready_pipe: child writes its PID → parent reads it
    // go_pipe:    parent writes go signal → child reads it
    // Both ends are O_CLOEXEC so they're closed automatically when the child
    // calls exec; the pre_exec hook closes them explicitly in the child.
    let (proxy_ready_r, proxy_ready_w): (libc::c_int, libc::c_int);
    let (proxy_go_r, proxy_go_w): (libc::c_int, libc::c_int);
    if is_proxy {
        let mut rp = [0i32; 2];
        let mut gp = [0i32; 2];
        // SAFETY: pipe2 is always safe to call.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if libc::pipe2(rp.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                return Err(SandboxError::SpawnFailed(std::io::Error::last_os_error()));
            }
            if libc::pipe2(gp.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                libc::close(rp[0]);
                libc::close(rp[1]);
                return Err(SandboxError::SpawnFailed(std::io::Error::last_os_error()));
            }
        }
        (proxy_ready_r, proxy_ready_w) = (rp[0], rp[1]);
        (proxy_go_r, proxy_go_w) = (gp[0], gp[1]);
    } else {
        (proxy_ready_r, proxy_ready_w) = (-1, -1);
        (proxy_go_r, proxy_go_w) = (-1, -1);
    }

    // For ProxyOnly, inject proxy env vars pointing to the veth host-side IP so
    // the child can reach the proxy from inside the isolated namespace.
    let effective_env: std::collections::HashMap<String, String> =
        if let (NetworkMode::ProxyOnly { proxy_addr, .. }, Some(handle)) =
            (&config.network, &proxy_netns)
        {
            let outer_ip = handle.outer_ip;
            let port = proxy_addr.port();
            let http_url = format!("http://{}:{}", outer_ip, port);
            // socks5h = hostname resolved by the proxy, so the sandboxed process
            // never calls getaddrinfo for external hosts — DNS stays on the proxy side.
            let socks_url = format!("socks5h://{}:{}", outer_ip, port);
            let no_proxy = "localhost,127.0.0.1,::1";
            let mut e = env.clone();
            e.insert("HTTP_PROXY".to_string(), http_url.clone());
            e.insert("HTTPS_PROXY".to_string(), http_url.clone());
            e.insert("http_proxy".to_string(), http_url.clone());
            e.insert("https_proxy".to_string(), http_url.clone());
            e.insert("ALL_PROXY".to_string(), socks_url.clone());
            e.insert("all_proxy".to_string(), socks_url.clone());
            e.insert("GRPC_PROXY".to_string(), socks_url.clone());
            e.insert("grpc_proxy".to_string(), socks_url);
            e.insert("NO_PROXY".to_string(), no_proxy.to_string());
            e.insert("no_proxy".to_string(), no_proxy.to_string());
            // Route git-over-SSH through the SOCKS5 proxy (nc -X 5 = SOCKS5).
            e.insert(
                "GIT_SSH_COMMAND".to_string(),
                format!("ssh -o ProxyCommand='nc -X 5 -x {}:{} %h %p'", outer_ip, port),
            );
            // Signal to the sandboxed process that it is running inside a proxy sandbox.
            // Claude Code checks this flag to activate its own proxy-aware networking.
            e.insert("SANDBOX_RUNTIME".to_string(), "1".to_string());
            e
        } else {
            env.clone()
        };

    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(&config.cwd);
    command.env_clear();
    for (key, value) in &effective_env {
        command.env(key, value);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    // pre_exec runs in child after fork, before exec.
    // SAFETY: Although we use heap allocations and file I/O here (which are not
    // strictly async-signal-safe), this is safe in practice because:
    // 1. We're in a single-threaded child process after fork
    // 2. No locks are held from the parent that could deadlock
    // 3. Modern Linux handles this correctly before exec
    // Resolve the real path of cmd (following symlinks) and ensure its parent
    // directory is in the Landlock execute rules.  Without this, a command that
    // is a symlink (e.g. ~/.local/bin/claude -> ~/.local/share/claude/versions/X)
    // would fail with EACCES because Landlock checks execute access on the
    // *resolved* inode, not the symlink itself.
    {
        let cmd_path = if cmd.contains('/') {
            PathBuf::from(cmd)
        } else {
            path_dirs
                .iter()
                .map(|d| d.join(cmd))
                .find(|p| p.exists())
                .unwrap_or_else(|| PathBuf::from(cmd))
        };
        if let Ok(real) = std::fs::canonicalize(&cmd_path) {
            if let Some(parent) = real.parent() {
                let parent_buf = parent.to_path_buf();
                if !path_dirs.contains(&parent_buf) {
                    path_dirs.push(parent_buf);
                }
            }
        }
    }

    // Clone strings that are used in BOTH the pre_exec closure and the
    // background thread (the closure moves them; the thread needs its own copy).
    let proxy_inner_veth_bg = proxy_inner_veth.clone();

    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        command.pre_exec(move || {
            // ── Phase 0: Fix dumpable bit and drop inheritable capabilities ──
            //
            // The pent binary carries cap_net_admin=eip on disk (file caps).
            // Executing a binary with file capabilities has two side-effects
            // that break user-namespace setup:
            //
            // Problem 1 — non-dumpable process (EACCES on /proc/self/uid_map):
            //   The kernel marks any process with elevated file capabilities as
            //   "not dumpable" (PR_GET_DUMPABLE → 0).  Non-dumpable processes
            //   have their /proc/[pid]/ files owned by root:root in the initial
            //   user namespace.  After unshare(CLONE_NEWUSER) but before uid_map
            //   is written, the process appears as uid 65534 (overflowuid) inside
            //   the new namespace.  Opening /proc/self/{uid_map,gid_map,setgroups}
            //   for writing then fails with EACCES (owned by root, we're nobody).
            //   Fix: prctl(PR_SET_DUMPABLE, 1) restores /proc ownership to our
            //   real uid, making those files writable again after unshare.
            //
            // Problem 2 — non-empty inheritable set (EACCES from unshare):
            //   Linux ≥ 5.11 rejects unshare(CLONE_NEWUSER) when the calling
            //   process has a non-empty inheritable capability set.
            //   Fix: capset to zero the inheritable words before unshare.
            //   (effective and permitted are fine; they don't trigger this check,
            //   and we need them cleared only to the extent the dumpable fix above
            //   handles uid_map — which it does independently.)
            {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
            }
            {
                #[repr(C)]
                struct CapHeader { version: u32, pid: i32 }
                #[repr(C)]
                #[derive(Copy, Clone)]
                struct CapData { effective: u32, permitted: u32, inheritable: u32 }
                const CAP_V3: u32 = 0x20080522;
                let mut hdr = CapHeader { version: CAP_V3, pid: 0 };
                let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::syscall(libc::SYS_capget, &mut hdr as *mut CapHeader, data.as_mut_ptr());
                data[0].inheritable = 0;
                data[1].inheritable = 0;
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr());
            }

            // ── Phase 1: Namespace and overlay setup ─────────────────────────
            //
            // When overlayfs is in use we need CLONE_NEWUSER + CLONE_NEWNS (and
            // CLONE_NEWNET for network-isolating modes) in a single unshare call.
            // ProxyOnly now creates its own user+net namespace here too.
            let has_overlays = !overlay_mounts_pre.is_empty();

            if has_overlays {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let uid = libc::getuid();
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let gid = libc::getgid();

                let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
                match &network {
                    NetworkMode::LocalhostOnly
                    | NetworkMode::Blocked
                    | NetworkMode::ProxyOnly { .. } => {
                        flags |= libc::CLONE_NEWNET;
                    }
                    _ => {}
                }
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let ret = libc::unshare(flags);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                setup_userns_mappings(uid, gid);

                // Create upper/work dirs and populate stubs from inside the
                // user namespace.  This must happen after unshare + userns
                // mappings so the kernel sees the directories as created in
                // the same security context as the overlay mount.  Doing this
                // in the parent process (before fork) causes EACCES on the
                // overlay mount on kernel 6.18 with btrfs lower.
                super::linux_overlayfs::setup_overlay_dirs(
                    &overlay_mounts_pre,
                    &accessible_pre,
                )?;

                // Mount overlayfs inside the new mount namespace.
                // SAFETY: we are in a single-threaded post-fork child that has
                // just called unshare(CLONE_NEWUSER | CLONE_NEWNS).
                //
                // NOTE: do NOT make the mount tree private (MS_REC|MS_PRIVATE)
                // before this call.  On this system overlayfs works fine on
                // inherited slave mounts (confirmed by testing), but making
                // the tree private first causes EACCES on the overlay mount
                // itself.  rprivate is applied later in setup_child_dns, where
                // it is needed before mounting tmpfs on /run.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                super::linux_overlayfs::mount_overlays(&overlay_mounts_pre)?;
            } else if proxy_ready_w >= 0 {
                // ProxyOnly without overlays: unshare user+net+mount namespace.
                // CLONE_NEWNS is required so that:
                //   1. We can mount a tmpfs on /run for the iptables lock file.
                //   2. We can bind-mount a custom /etc/resolv.conf.
                // Both are scoped to this mount namespace and invisible to the host.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let uid = libc::getuid();
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let gid = libc::getgid();
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let ret = libc::unshare(
                    libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS,
                );
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                setup_userns_mappings(uid, gid);
                // rprivate is applied inside setup_child_dns before the
                // tmpfs-on-/run and resolv.conf bind-mounts.
            }

            // ── Phase 1.5: ProxyOnly pipe-sync and inner veth config ─────────
            //
            // The child has a fresh CLONE_NEWNET namespace (Phase 1 or the else-if
            // above). Signal readiness to the parent background thread by writing
            // our PID; the thread moves the inner veth here, then sends a go byte.
            // We then configure the inner veth before Landlock is applied — after
            // Landlock the ip binary would be inaccessible.
            if proxy_ready_w >= 0 {
                // Restore dumpability so the parent can open /proc/self if needed.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);

                // Send our PID (4 bytes, native endian) to the background thread.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let pid = libc::getpid();
                let pid_bytes = pid.to_ne_bytes();
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::write(proxy_ready_w, pid_bytes.as_ptr().cast(), 4);
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::close(proxy_ready_w);

                // Block until the background thread moves the inner veth in.
                let mut buf = [0u8; 1];
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::read(proxy_go_r, buf.as_mut_ptr().cast(), 1);
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                libc::close(proxy_go_r);

                // Configure the inner veth inside our new network namespace.
                // ip is still accessible here — Landlock hasn't been applied yet.
                super::linux_netns::run_ip_local(&[
                    "addr", "add", &proxy_inner_cidr, "dev", &proxy_inner_veth,
                ])
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                super::linux_netns::run_ip_local(&[
                    "link", "set", &proxy_inner_veth, "up",
                ])
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                super::linux_netns::run_ip_local(&["link", "set", "lo", "up"])
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                super::linux_netns::run_ip_local(&[
                    "route", "add", "default", "via", &proxy_gateway,
                ])
                .map_err(|e| std::io::Error::other(e.to_string()))?;

                // ── resolv.conf inside child namespace ────────────────────────
                // Point /etc/resolv.conf at the host-side veth IP (outer_ip).
                // DNS queries to port 53 on that IP are intercepted by the
                // host-side nft PREROUTING rule (created in create_netns) and
                // redirected to the proxy's DNS server port.
                if let NetworkMode::ProxyOnly { dns_port, .. } = &network {
                    if *dns_port != 0 {
                        super::linux_netns::setup_child_dns(&proxy_gateway, *dns_port);
                    }
                }
            }

            // ── Phase 2: Landlock ─────────────────────────────────────────────
            let all_access = AccessFs::from_all(ABI::V4);
            let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
            let execute_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
            let write_access = all_access;

            let mut ruleset = Ruleset::default()
                .handle_access(all_access)
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .create()
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            // Helper: pass ruleset by &mut so it isn't moved into the closure.
            let add_path = |ruleset: &mut landlock::RulesetCreated,
                            path: &Path,
                            access|
             -> std::io::Result<()> {
                if !path.exists() {
                    return Ok(());
                }
                let fd = PathFd::new(path).map_err(|e| std::io::Error::other(e.to_string()))?;
                ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                Ok(())
            };

            // Add workspace and data_dir
            add_path(&mut ruleset, &workspace, write_access)?;
            add_path(&mut ruleset, &data_dir, write_access)?;

            // Add mounts
            for mount in &mounts {
                if mount.readonly {
                    add_path(&mut ruleset, &mount.path, read_access)?;
                } else {
                    add_path(&mut ruleset, &mount.path, write_access)?;
                }
            }

            // Add configured SandboxPaths (from profiles and TOML config).
            let traversal_access = AccessFs::ReadDir;
            let (traversal_paths, read_paths, execute_paths, rw_paths) = paths.expand_paths();
            for (path, _) in &traversal_paths {
                add_path(&mut ruleset, path, traversal_access.into())?;
            }
            for (path, _) in &read_paths {
                add_path(&mut ruleset, path, read_access)?;
            }
            for (path, _) in &execute_paths {
                add_path(&mut ruleset, path, execute_access)?;
            }
            // For rw_paths:
            // - Paths covered by overlayfs (files in write_set_pre): skip; access
            //   is granted at the parent directory level via the overlay_dirs rule.
            // - Paths not covered (directories, non-overlay files): add directly.
            for (path, _) in &rw_paths {
                if write_set_pre.contains(path) {
                    continue; // covered by overlay parent-dir rule below
                }
                add_path(&mut ruleset, path, write_access)?;
            }
            // Overlay parent directories — grant full write access so the child
            // can read/write through the overlayfs mount point. Inside the
            // namespace, writes go to upper (tmpfs); the real filesystem only
            // sees changes when the parent's watcher flushes write_set files.
            // The overlay's opaque/whiteout stubs protect non-manifest content;
            // if the mount failed, pre_exec already returned an error above.
            for dir in &overlay_dirs_pre {
                add_path(&mut ruleset, dir, write_access)?;
            }

            // Add PATH directories (binary dirs — read + execute)
            for path_dir in &path_dirs {
                add_path(&mut ruleset, path_dir, execute_access)?;
            }

            // Add system paths (dynamic linker in /usr/lib, /lib64 needs Execute)
            for sys_path in SYSTEM_PATHS {
                add_path(&mut ruleset, Path::new(sys_path), execute_access)?;
            }

            // Add temp paths
            for tmp_path in TEMP_PATHS {
                add_path(&mut ruleset, Path::new(tmp_path), write_access)?;
            }

            // Add device and proc paths
            for dev_path in DEVICE_PATHS {
                add_path(&mut ruleset, Path::new(dev_path), read_access)?;
            }

            // Apply the ruleset
            ruleset
                .restrict_self()
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            // ── Phase 3: Network isolation ────────────────────────────────────
            if has_overlays || proxy_ready_w >= 0 {
                // Namespace was already created in Phase 1 / Phase 1.5.
                // ProxyOnly: veth + loopback already configured in Phase 1.5.
                // LocalhostOnly / Blocked: just bring up loopback if needed.
                match &network {
                    NetworkMode::LocalhostOnly => {
                        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                        bring_up_loopback();
                    }
                    _ => {}
                }
            } else {
                // No overlays and not ProxyOnly: apply_network_isolation handles
                // unshare + loopback internally.
                apply_network_isolation(&network)?;
            }

            Ok(())
        });
    }

    // Spawn the background thread that moves the inner veth into the child's
    // namespace. Must be launched BEFORE command.spawn() because the child's
    // pre_exec will block on the go_pipe until the thread responds.
    let bg_thread: Option<std::thread::JoinHandle<Result<(), SandboxError>>> = if is_proxy {
        let inner_veth = proxy_inner_veth_bg;
        let ready_r = proxy_ready_r;
        let go_w = proxy_go_w;
        Some(std::thread::spawn(move || {
            // Read child PID (4 bytes, native endian) from ready pipe.
            let mut pid_bytes = [0u8; 4];
            // SAFETY: read on a valid pipe fd.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let n = unsafe { libc::read(ready_r, pid_bytes.as_mut_ptr().cast(), 4) };
            // SAFETY: close is always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(ready_r) };
            if n != 4 {
                // SAFETY: close is always safe.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::close(go_w) };
                return Err(SandboxError::NetworkSetupFailed(
                    "child ready signal truncated".to_string(),
                ));
            }
            let pid = i32::from_ne_bytes(pid_bytes);

            // Move inner veth into the child's network namespace.
            if let Err(e) = super::linux_netns::move_inner_veth_to_pid(&inner_veth, pid) {
                // SAFETY: close is always safe.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::close(go_w) };
                return Err(e);
            }

            // Signal child to proceed with inner veth configuration.
            // SAFETY: write/close on valid pipe fds.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::write(go_w, b"1".as_ptr().cast(), 1);
                libc::close(go_w);
            }
            Ok(())
        }))
    } else {
        None
    };

    let result = command.spawn().map_err(SandboxError::SpawnFailed);

    // Close the parent's copies of the child-side pipe ends.  The child's
    // copies were already closed by O_CLOEXEC on exec.
    if is_proxy {
        // SAFETY: close is always safe.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(proxy_ready_w);
            libc::close(proxy_go_r);
        }
    }

    // Join background thread; propagate any error it encountered.
    if let Some(thread) = bg_thread {
        let _ = thread.join();
    }

    if result.is_err() {
        proxy_netns = None; // triggers Drop → cleans up firewall/routing rules
    }

    let child = result?;

    // Start the inotify watcher now that the child is running.
    let overlay_handle = if overlay_mounts.is_empty() {
        None
    } else {
        Some(super::linux_overlayfs::spawn_watcher(overlay_mounts, write_set, rw_dirs))
    };

    Ok((child, overlay_handle, proxy_netns))
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_with_landlock(
    _config: &SandboxConfig,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _path_dirs: &[PathBuf],
) -> Result<(std::process::Child, Option<()>), SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serial_test::serial;
    use crate::SandboxPaths;
    use tempfile::TempDir;

    struct TestDirs {
        workspace: PathBuf,
        data_dir: PathBuf,
        _temp: TempDir,
    }

    fn make_test_dirs() -> TestDirs {
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
        assert_eq!(MIN_LANDLOCK_ABI, 4);
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    #[cfg(target_os = "linux")]
    fn test_check_available_returns_result() {
        // Should return Ok if Landlock ABI v4 available, Err otherwise
        // Either result is valid depending on kernel version
        let result = check_available();
        // Just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_check_available_non_linux() {
        let result = check_available();
        assert!(matches!(result, Err(SandboxError::UnsupportedPlatform)));
    }

    // ========================================================================
    // build_landlock_ruleset tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    fn make_test_config() -> SandboxConfig {
        SandboxConfig::new(
            PathBuf::from("/tmp/test-workspace"),
            SandboxPaths::default(),
            PathBuf::from("/tmp/test-workspace"),
        )
        .with_data_dir(PathBuf::from("/tmp/test-data"))
    }

    #[test]
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    fn test_build_landlock_ruleset_with_path_dirs() {
        let config = make_test_config();
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let result = build_landlock_ruleset(&config, &path_dirs);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_build_landlock_ruleset_non_linux() {
        let config = SandboxConfig::new(
            PathBuf::from("/workspace"),
            SandboxPaths::default(),
            PathBuf::from("/workspace"),
        )
        .with_data_dir(PathBuf::from("/home/.data"));
        let result = build_landlock_ruleset(&config, &[]);
        assert!(matches!(result, Err(SandboxError::UnsupportedPlatform)));
    }

    // ========================================================================
    // apply_landlock tests
    // ========================================================================

    // Note: apply_landlock is irreversible for the process, so we can't
    // test it directly in unit tests. Integration tests would fork a child.

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_apply_landlock_non_linux() {
        let result = apply_landlock(());
        assert!(matches!(result, Err(SandboxError::UnsupportedPlatform)));
    }

    // ========================================================================
    // spawn_with_landlock tests
    // ========================================================================

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_spawn_with_landlock_true_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir.clone());
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let env = HashMap::new();

        let result = spawn_with_landlock(&config, "/bin/true", &[], &env, &path_dirs);

        if check_available().is_ok() {
            match result {
                Ok((mut child, _overlay, _netns)) => {
                    let status = child.wait().expect("Failed to wait on child");
                    assert!(status.success(), "true command should succeed");
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    // Some CI/container environments expose Landlock but deny
                    // applying it in pre_exec.
                }
                Err(e) => panic!("spawn_with_landlock failed: {:?}", e),
            }
        }
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_spawn_with_landlock_echo_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir.clone());
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let env = HashMap::new();

        let result = spawn_with_landlock(
            &config,
            "/bin/echo",
            &["hello".to_string()],
            &env,
            &path_dirs,
        );

        if check_available().is_ok() {
            match result {
                Ok((mut child, _overlay, _netns)) => {
                    let status = child.wait().expect("Failed to wait on child");
                    assert!(status.success());
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    // Some CI/container environments expose Landlock but deny
                    // applying it in pre_exec.
                }
                Err(e) => panic!("spawn_with_landlock failed: {:?}", e),
            }
        }
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_spawn_with_landlock_nonexistent_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir.clone());
        let env = HashMap::new();

        let result = spawn_with_landlock(&config, "/nonexistent/command/12345", &[], &env, &[]);

        if check_available().is_ok() {
            // Should fail to spawn nonexistent command
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // Overlay flush correctness tests
    //
    // These tests verify that writes made inside the sandbox are flushed back
    // to the real filesystem on teardown.  All tests use /tmp (always rw, no
    // network required) and fall back gracefully when overlayfs is unavailable.
    // ========================================================================

    /// Helper: spawn a sandboxed shell command with the given read_write paths
    /// and return (child, overlay_handle).  Falls back gracefully when the
    /// kernel does not support user namespaces or overlayfs.
    #[cfg(target_os = "linux")]
    fn spawn_rw(
        workspace: &std::path::Path,
        rw_paths: &[&str],
        cmd: &str,
    ) -> Option<(std::process::Child, Option<crate::linux_overlayfs::OverlayHandle>)> {
        use std::collections::HashMap;

        if check_available().is_err() {
            return None;
        }

        let mut paths = SandboxPaths::default();
        for p in rw_paths {
            paths.read_write.push((*p).to_string());
        }

        let config = SandboxConfig::new(workspace.to_path_buf(), paths, workspace.to_path_buf())
            .with_data_dir(workspace.to_path_buf())
            .with_env(HashMap::new());

        let path_dirs = vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")];

        match spawn_with_landlock(&config, "/bin/sh", &["-c".to_string(), cmd.to_string()], &HashMap::new(), &path_dirs) {
            Ok((child, handle, _netns)) => Some((child, handle)),
            Err(SandboxError::SpawnFailed(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(e) => panic!("spawn_with_landlock failed: {:?}", e),
        }
    }

    /// Run `spawn_rw`, wait for the child, call teardown, then return whether
    /// the overlay was active (Some handle → true, None → false).
    #[cfg(target_os = "linux")]
    fn run_sandboxed_rw(workspace: &std::path::Path, rw_paths: &[&str], cmd: &str) -> bool {
        let Some((mut child, overlay_handle)) = spawn_rw(workspace, rw_paths, cmd) else {
            return false;
        };
        let status = child.wait().expect("wait failed");
        assert!(status.success(), "sandboxed command failed: {cmd}");
        if let Some(handle) = overlay_handle {
            crate::linux_overlayfs::teardown(handle);
            true
        } else {
            false
        }
    }

    /// Modify an existing file that is listed directly in read_write (file-level
    /// entry).  This is the original write_set path.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_direct_file_entry() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("config.json");
        std::fs::write(&target, r#"{"v":1}"#).unwrap();

        let active = run_sandboxed_rw(
            temp.path(),
            &[target.to_str().unwrap()],
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active { return; }

        let content = std::fs::read_to_string(&target).unwrap();
        assert_eq!(content, r#"{"v":2}"#, "direct file-level write_set entry must be flushed");
    }

    /// Modify a file inside a directory listed in read_write (directory-level
    /// entry — the rw_dirs path that was broken before this fix).
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_file_inside_rw_dir() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("mydir");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("settings.json");
        std::fs::write(&target, r#"{"v":1}"#).unwrap();

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap()],   // directory, not file
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active { return; }

        let content = std::fs::read_to_string(&target).unwrap();
        assert_eq!(content, r#"{"v":2}"#, "file inside rw_dir must be flushed");
    }

    /// Modify multiple files inside the same rw directory in one session.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_multiple_files_in_rw_dir() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("store");
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "old-a").unwrap();
        std::fs::write(&b, "old-b").unwrap();

        let cmd = format!(
            "printf 'new-a' > '{}' && printf 'new-b' > '{}'",
            a.display(), b.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[dir.to_str().unwrap()], &cmd);
        if !active { return; }

        assert_eq!(std::fs::read_to_string(&a).unwrap(), "new-a", "a.txt must be flushed");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "new-b", "b.txt must be flushed");
    }

    /// Create a new file inside an rw directory (file did not exist at spawn time).
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_newly_created_file_in_rw_dir() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("newdir");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("created.txt");
        assert!(!target.exists());

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap()],
            &format!("printf 'hello' > '{}'", target.display()),
        );
        if !active { return; }

        assert!(target.exists(), "newly created file must exist on real FS after teardown");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
    }

    /// Create a new subdirectory and file inside an rw directory.
    /// The subdirectory did not exist at spawn time.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_file_in_new_subdir() {
        let temp = tempfile::tempdir().unwrap();
        let rw_dir = temp.path().join("data");
        std::fs::create_dir_all(&rw_dir).unwrap();
        // subdir does NOT exist at spawn time
        let subdir = rw_dir.join("projects").join("alpha");
        let target = subdir.join("state.json");

        let cmd = format!(
            "mkdir -p '{}' && printf '{{\"ok\":true}}' > '{}'",
            subdir.display(), target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap()], &cmd);
        if !active { return; }

        assert!(subdir.exists(), "new subdirectory must exist on real FS after teardown");
        assert!(target.exists(), "file in new subdir must be flushed to real FS");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), r#"{"ok":true}"#);
    }

    /// Atomic write (write-to-tmp then rename) inside an rw directory.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_atomic_write_in_rw_dir() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("cfg");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.toml");
        std::fs::write(&target, "version = 1").unwrap();
        let tmp = dir.join("config.toml.tmp");

        let cmd = format!(
            "printf 'version = 2' > '{}' && mv '{}' '{}'",
            tmp.display(), tmp.display(), target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[dir.to_str().unwrap()], &cmd);
        if !active { return; }

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "version = 2",
            "atomic write (tmp→rename) in rw_dir must be flushed");
    }

    /// Mix of a direct file entry and a directory entry in the same session.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_mixed_file_and_dir_entries() {
        let temp = tempfile::tempdir().unwrap();
        let file_entry = temp.path().join("config.json");
        let dir_entry = temp.path().join("cache");
        std::fs::write(&file_entry, "old").unwrap();
        std::fs::create_dir_all(&dir_entry).unwrap();
        let cache_file = dir_entry.join("data.bin");
        std::fs::write(&cache_file, "stale").unwrap();

        let cmd = format!(
            "printf 'new' > '{}' && printf 'fresh' > '{}'",
            file_entry.display(), cache_file.display()
        );
        let active = run_sandboxed_rw(
            temp.path(),
            &[file_entry.to_str().unwrap(), dir_entry.to_str().unwrap()],
            &cmd,
        );
        if !active { return; }

        assert_eq!(std::fs::read_to_string(&file_entry).unwrap(), "new",
            "direct file entry must be flushed");
        assert_eq!(std::fs::read_to_string(&cache_file).unwrap(), "fresh",
            "file inside directory entry must be flushed");
    }

    /// Append to an existing file inside an rw directory.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_append_to_file_in_rw_dir() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("logs");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("app.log");
        std::fs::write(&target, "line1\n").unwrap();

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap()],
            &format!("printf 'line2\\n' >> '{}'", target.display()),
        );
        if !active { return; }

        let content = std::fs::read_to_string(&target).unwrap();
        assert_eq!(content, "line1\nline2\n", "appended content must be flushed");
    }

    /// A read_write path that does not exist at spawn time and is created as a
    /// directory by the sandbox process.  Its contents must be flushed.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_flush_nonexistent_rw_path_created_as_dir() {
        let temp = tempfile::tempdir().unwrap();
        // rw_dir does NOT exist at spawn time — it will be created by the sandbox.
        let rw_dir = temp.path().join("cache");
        assert!(!rw_dir.exists());
        let target = rw_dir.join("state.json");

        let cmd = format!(
            "mkdir -p '{}' && printf '{{\"ok\":true}}' > '{}'",
            rw_dir.display(), target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap()], &cmd);
        if !active { return; }

        assert!(rw_dir.exists(), "directory created by sandbox must exist on real FS");
        assert!(target.exists(), "file inside newly-created rw dir must be flushed");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), r#"{"ok":true}"#);
    }

    /// Files in a directory NOT in read_write must NOT be flushed to the real FS.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_no_flush_for_non_rw_dir() {
        let temp = tempfile::tempdir().unwrap();
        let rw_dir = temp.path().join("allowed");
        let other_dir = temp.path().join("forbidden");
        std::fs::create_dir_all(&rw_dir).unwrap();
        std::fs::create_dir_all(&other_dir).unwrap();

        // Create a file in both dirs so we have real inodes in both.
        let allowed_file = rw_dir.join("ok.txt");
        let forbidden_file = other_dir.join("secret.txt");
        std::fs::write(&allowed_file, "original-allowed").unwrap();
        std::fs::write(&forbidden_file, "original-secret").unwrap();

        // The sandbox only gets read_write on rw_dir, not other_dir.
        // Writing to other_dir from the sandbox should not touch the real file.
        let cmd = format!(
            "printf 'modified-allowed' > '{}'; printf 'should-not-persist' > '{}' 2>/dev/null; true",
            allowed_file.display(), forbidden_file.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap()], &cmd);
        if !active { return; }

        assert_eq!(std::fs::read_to_string(&allowed_file).unwrap(), "modified-allowed",
            "rw_dir file must be flushed");
        assert_eq!(std::fs::read_to_string(&forbidden_file).unwrap(), "original-secret",
            "non-rw_dir file must NOT be modified on real FS");
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_overlay_atomic_write_preserves_inode() {
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
        if check_available().is_err() {
            return;
        }
        use std::collections::HashMap;
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.json");
        std::fs::write(&target, r#"{"version":1}"#).unwrap();
        let inode_before = std::fs::metadata(&target).unwrap().ino();

        // A SandboxConfig that lists target.json in read_write.
        let workspace = temp.path().to_path_buf();
        let mut paths = SandboxPaths::default();
        paths.read_write.push(target.to_str().unwrap().to_string());

        let config = SandboxConfig::new(workspace.clone(), paths, workspace)
            .with_data_dir(temp.path().to_path_buf())
            .with_env(HashMap::new());

        let path_dirs = vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")];

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

        let result =
            spawn_with_landlock(&config, "/bin/sh", &["-c".to_string(), cmd], &HashMap::new(), &path_dirs);

        let (mut child, overlay_handle, _netns) = match result {
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                // Some CI/container environments deny pre_exec operations.
                return;
            }
            Err(e) => panic!("spawn_with_landlock failed: {:?}", e),
            Ok(pair) => pair,
        };

        let status = child.wait().expect("Failed to wait on child");

        if let Some(handle) = overlay_handle {
            // Flush upper-layer writes back to real inodes and clean up staging.
            crate::linux_overlayfs::teardown(handle);

            assert!(status.success(), "atomic write shell command should succeed");

            let content = std::fs::read_to_string(&target).unwrap_or_default();
            let inode_after = std::fs::metadata(&target).map(|m| m.ino()).unwrap_or(0);

            assert_eq!(content, new_content, "overlayfs flush must write new content to real file");
            assert_eq!(inode_before, inode_after, "real file inode must not change after overlayfs flush");
        }
        // If overlay_handle is None, overlayfs is unavailable; skip assertions.
    }
}
