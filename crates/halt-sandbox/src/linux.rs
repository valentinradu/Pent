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
/// When `apply_network_isolation` is called for ProxyOnly (e.g. from
/// `exec_with_landlock`), it falls back to loopback-only isolation.
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

/// Execute command with Landlock sandbox, replacing current process.
///
/// # Arguments
/// * `config` - Sandbox configuration
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `path_dirs` - PATH directories for ruleset
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock unavailable or apply fails
/// * `NetworkSetupFailed` - If network namespace setup fails
/// * `SpawnFailed` - If exec fails
#[cfg(target_os = "linux")]
pub fn exec_with_landlock(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // Build and apply Landlock ruleset
    let ruleset = build_landlock_ruleset(config, path_dirs)?;
    apply_landlock(ruleset)?;

    // Apply network isolation
    apply_network_isolation(&config.network).map_err(SandboxError::SpawnFailed)?;

    // Build command
    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(&config.cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }

    // exec() replaces current process - only returns on error
    let err = command.exec();
    Err(SandboxError::SpawnFailed(err))
}

#[cfg(not(target_os = "linux"))]
pub fn exec_with_landlock(
    _config: &SandboxConfig,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _path_dirs: &[PathBuf],
) -> Result<std::convert::Infallible, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
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
) -> Result<(std::process::Child, Option<super::linux_overlayfs::OverlayHandle>), SandboxError> {
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
    let path_dirs = path_dirs.to_vec();
    let network = config.network.clone();

    // Identify write-listed file paths (as opposed to directories) and prepare
    // overlayfs staging directories for them. Directories use regular Landlock
    // write rules; files get inode-stable access via the overlayfs + inotify path.
    let (_, _, _, rw_expanded) = config.paths.expand_paths();
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

    // For ProxyOnly, create a named network namespace in the parent so the child
    // can join it via setns() in pre_exec. A named namespace survives the child's
    // exec and must be deleted by the caller after child.wait().
    //
    // The tuple holds (namespace_name, open_fd). The fd is O_CLOEXEC so it is
    // automatically closed when the child calls exec(); the parent closes it
    // explicitly after spawn() returns.
    let proxy_netns: Option<(String, libc::c_int, std::net::Ipv4Addr)> =
        if let NetworkMode::ProxyOnly { .. } = &config.network {
            let ns_config = super::linux_netns::NetnsConfig::from_pid();
            super::linux_netns::create_netns(&ns_config)?;

            let netns_path = std::ffi::CString::new(format!("/var/run/netns/{}", ns_config.name))
                .map_err(|e| {
                SandboxError::NetworkSetupFailed(format!("invalid netns name: {}", e))
            })?;
            // SAFETY: netns_path is a valid NUL-terminated CString. O_CLOEXEC
            // ensures the fd is closed on exec in the child; we close it in the
            // parent explicitly after spawn().
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let fd = unsafe { libc::open(netns_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                let _ = super::linux_netns::delete_netns(&ns_config.name);
                return Err(SandboxError::NetworkSetupFailed(format!(
                    "failed to open /var/run/netns/{}: {}",
                    ns_config.name,
                    std::io::Error::last_os_error()
                )));
            }

            Some((ns_config.name, fd, ns_config.outer_ip))
        } else {
            None
        };

    // fd value for the pre_exec closure (-1 when not ProxyOnly)
    let netns_fd: libc::c_int = proxy_netns.as_ref().map_or(-1, |(_, fd, _)| *fd);

    // For ProxyOnly, inject proxy env vars pointing to the veth host-side IP so
    // the child can reach the proxy from inside the isolated namespace.
    let effective_env: std::collections::HashMap<String, String> =
        if let (NetworkMode::ProxyOnly { proxy_addr }, Some((_, _, outer_ip))) =
            (&config.network, &proxy_netns)
        {
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        command.pre_exec(move || {
            // ── Phase 1: Namespace and overlay setup ─────────────────────────
            //
            // When overlayfs is in use we need CLONE_NEWUSER + CLONE_NEWNS (and
            // CLONE_NEWNET for local-network modes) in a single unshare call.
            // For ProxyOnly, CLONE_NEWNET is handled separately via setns below.
            let has_overlays = !overlay_mounts_pre.is_empty();

            if has_overlays {
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let uid = libc::getuid();
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let gid = libc::getgid();

                let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
                // Add CLONE_NEWNET for modes that don't use setns.
                if netns_fd < 0 {
                    match &network {
                        NetworkMode::LocalhostOnly | NetworkMode::Blocked => {
                            flags |= libc::CLONE_NEWNET;
                        }
                        _ => {}
                    }
                }
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let ret = libc::unshare(flags);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                setup_userns_mappings(uid, gid);

                // Mount overlayfs inside the new mount namespace.
                // SAFETY: we are in a single-threaded post-fork child that has
                // just called unshare(CLONE_NEWUSER | CLONE_NEWNS).
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                super::linux_overlayfs::mount_overlays(&overlay_mounts_pre)?;
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
            if netns_fd >= 0 {
                // ProxyOnly: join the named namespace created by the parent.
                // SAFETY: netns_fd is a valid open fd to the named netns file.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let ret = libc::setns(netns_fd, libc::CLONE_NEWNET);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                bring_up_loopback();
            } else if has_overlays {
                // Namespace already created in Phase 1; just bring up loopback
                // if needed. apply_network_isolation would call unshare again.
                match &network {
                    NetworkMode::LocalhostOnly | NetworkMode::ProxyOnly { .. } => {
                        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                        bring_up_loopback();
                    }
                    _ => {}
                }
            } else {
                // No overlays: use the existing path (handles unshare internally).
                apply_network_isolation(&network)?;
            }

            Ok(())
        });
    }

    let result = command.spawn().map_err(SandboxError::SpawnFailed);

    // Close the netns fd in the parent; the child's copy was closed by exec (O_CLOEXEC).
    // On spawn failure, also clean up the named namespace so it doesn't leak.
    if let Some((ns_name, fd, _)) = proxy_netns {
        // SAFETY: fd is a valid open file descriptor obtained from libc::open above.
        // The child's copy was closed by exec (O_CLOEXEC); we close the parent's copy here.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
        if result.is_err() {
            let _ = super::linux_netns::delete_netns(&ns_name);
        }
    }

    let child = result?;

    // Start the inotify watcher now that the child is running.
    let overlay_handle = if overlay_mounts.is_empty() {
        None
    } else {
        Some(super::linux_overlayfs::spawn_watcher(overlay_mounts, write_set))
    };

    Ok((child, overlay_handle))
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
    // exec_with_landlock tests
    // ========================================================================

    // Note: exec_with_landlock replaces the process, can't test directly.
    // Would need integration tests with fork.

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
                Ok((mut child, _overlay)) => {
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
                Ok((mut child, _overlay)) => {
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
}
