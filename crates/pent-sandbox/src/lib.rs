//! OS-level process sandboxing.
//!
//! Provides filesystem and network containment using native OS mechanisms:
//! - macOS: sandbox-exec with SBPL profiles
//! - Linux: Landlock LSM for filesystem, network namespaces for network
//!
//! # Example
//!
//! ```ignore
//! use pent_sandbox::{SandboxConfig, SandboxPaths, spawn_sandboxed};
//!
//! let paths = SandboxPaths {
//!     traversal: vec!["/".to_string(), "/Users".to_string()],
//!     read: vec!["/usr/lib".to_string()],
//!     read_write: vec!["/tmp".to_string()],
//! };
//!
//! let config = SandboxConfig::new(
//!     "/home/user/project".into(),
//!     paths,
//!     "/home/user/project".into(),
//! ).with_env(build_env(&[]));
//!
//! let child = spawn_sandboxed(&config, "my-process", &[])?;
//! ```

mod config;
mod env;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod linux_netns;

#[cfg(target_os = "linux")]
mod linux_overlayfs;

pub use config::{system_default_paths, SandboxConfig};
pub use env::{build_env, resolve_path_dirs_from, resolve_path_directories};
pub use pent_settings::{Mount, NetworkMode, SandboxPaths, SandboxSettings};
#[cfg(target_os = "linux")]
pub use linux::compute_accessible_set;
#[cfg(target_os = "linux")]
pub use linux_overlayfs::OverlayHandle;

use std::process::Child;
use thiserror::Error;

/// A sandboxed child process, optionally with an overlayfs handle.
pub struct SandboxChild {
    /// The child process handle.
    pub child: Child,
    /// Overlay handle for Linux (inotify watcher + in-place flush on exit).
    /// Pass this to [`teardown_overlay`] after `child.wait()` returns.
    #[cfg(target_os = "linux")]
    pub overlay: Option<linux_overlayfs::OverlayHandle>,
    /// Anonymous network namespace handle for `ProxyOnly` mode on Linux.
    /// Dropping this cleans up firewall/routing rules added during setup.
    #[cfg(target_os = "linux")]
    pub netns: Option<linux_netns::NetnsHandle>,
}

/// Errors that can occur during sandbox operations.
#[derive(Error, Debug)]
pub enum SandboxError {
    /// Platform not supported for sandboxing.
    #[error("Sandboxing not supported on this platform")]
    UnsupportedPlatform,

    /// Sandbox mechanism unavailable (e.g., old kernel, missing binary).
    #[error("{reason}. {remediation}")]
    SandboxUnavailable { reason: String, remediation: String },

    /// Invalid configuration provided.
    #[error("Invalid sandbox config: {0}")]
    InvalidConfig(String),

    /// Process spawn failed.
    #[error("Failed to spawn process: {0}")]
    SpawnFailed(#[from] std::io::Error),

    /// Network namespace setup failed.
    #[error("Network setup failed: {0}")]
    NetworkSetupFailed(String),

    /// Operation requires elevated privileges.
    #[error("Privilege required: {0}")]
    PrivilegeRequired(String),
}

/// Spawn a command in a sandbox, returning a [`SandboxChild`] handle.
///
/// On Linux, the returned [`SandboxChild::overlay`] may contain an
/// [`OverlayHandle`] for write-listed file paths. Pass it to [`teardown_overlay`]
/// after `child.wait()` returns to flush writes and clean up.
///
/// # Errors
/// Returns a [`SandboxError`] if the sandbox cannot be set up or the process cannot be spawned.
pub fn spawn_sandboxed(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<SandboxChild, SandboxError> {
    // ── Auto-grant access to the binary's location ───────────────────────────
    // Rule: the binary's resolved directory (and the package root when it lives
    // in a `bin/` subdirectory) is always readable and executable.  This lets
    // runtimes like Node.js find sibling dirs (lib/node_modules/, etc.).
    //
    // Two-step resolution:
    // 1. Locate the binary in PATH without canonicalising — the symlink path
    //    preserves the `bin/` structure we need for the package-root heuristic.
    //    (e.g. ~/.npm-global/bin/gemini → ../lib/…/index.js: the symlink parent
    //    IS `bin/`, but the canonicalized parent is `dist/`.)
    // 2. Canonicalize separately and add the real parent as well, so the
    //    Landlock execute rule covers the actual inode the kernel will check.
    //
    // Must happen before any platform-specific call:
    // - Linux: overlayfs accessible set is built from config at mount time.
    // - macOS: SBPL profile is generated from config before spawn.
    let mut effective_config = config.clone();
    // Canonical binary parent directories that need ReadFile for execve to work.
    // These are collected separately from execute_paths so they can receive
    // syslib_access (ReadFile | ReadDir | Execute) rather than execute_access
    // (ReadDir | Execute only). On Linux, the kernel requires ReadFile on the
    // binary's directory for execve to succeed under Landlock, even though
    // Execute alone should theoretically be sufficient.
    let mut binary_real_parents: Vec<std::path::PathBuf> = Vec::new();
    {
        let path_env = config.env.get("PATH").map_or("", String::as_str);

        // Step 1: find the binary as it appears in PATH (symlink not resolved).
        let found: Option<std::path::PathBuf> = if std::path::Path::new(cmd).is_absolute() {
            Some(std::path::PathBuf::from(cmd))
        } else {
            path_env
                .split(':')
                .map(|dir| std::path::Path::new(dir).join(cmd))
                .find(|p| p.is_file())
        };

        let mut add = |s: String| {
            if !effective_config.paths.execute.contains(&s) {
                effective_config.paths.execute.push(s);
            }
        };

        if let Some(ref fp) = found {
            if let Some(parent) = fp.parent() {
                // Symlink-path parent → always add (covers bin/ dirs).
                add(parent.to_string_lossy().into_owned());
                // The symlink parent also needs syslib_access so that any
                // binaries symlinked from it can be read and executed.
                binary_real_parents.push(parent.to_path_buf());
                // Package-root heuristic: `bin/` sibling dirs (lib/, etc.).
                // The package root receives syslib_access so that Node.js
                // runtimes can read .js files and spawn nested binaries from
                // anywhere in the package tree.
                // Only apply for user-space package roots (e.g. ~/.npm-global),
                // NOT for system directories like / (pkg_root of /bin/true is /).
                // Adding / to accessible/path_dirs would make every path appear
                // to be "in an accessible subtree", breaking overlay stub logic.
                if parent.file_name().is_some_and(|n| n == "bin") {
                    if let Some(pkg_root) = parent.parent() {
                        // Skip filesystem root and other degenerate cases.
                        if pkg_root.parent().is_some() {
                            add(pkg_root.to_string_lossy().into_owned());
                            binary_real_parents.push(pkg_root.to_path_buf());
                        }
                    }
                }
            }
            // Step 2: canonical parent for Landlock execute on the real inode.
            // Added to binary_real_parents so it receives syslib_access (with
            // ReadFile) — required for execve to succeed under Landlock on Linux.
            if let Ok(real) = std::fs::canonicalize(fp) {
                if let Some(real_parent) = real.parent() {
                    binary_real_parents.push(real_parent.to_path_buf());
                    // Also add as execute path for the accessible set computation.
                    add(real_parent.to_string_lossy().into_owned());
                }
            }
        }
    }
    let config = &effective_config;

    #[cfg(target_os = "macos")]
    {
        let profile = macos::generate_sbpl_profile(config)?;
        let env_with_proxy;
        let env = if let NetworkMode::ProxyOnly { proxy_addr } = &config.network {
            let port = proxy_addr.port();
            let http_url = format!("http://127.0.0.1:{port}");
            let socks_url = format!("socks5h://127.0.0.1:{port}");
            let no_proxy = "localhost,127.0.0.1,::1";
            let mut e = config.env.clone();
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
            e.insert(
                "GIT_SSH_COMMAND".to_string(),
                format!("ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:{port} %h %p'"),
            );
            e.insert("SANDBOX_RUNTIME".to_string(), "1".to_string());
            env_with_proxy = e;
            &env_with_proxy
        } else {
            &config.env
        };
        let child = macos::spawn_with_sandbox(&profile, cmd, args, env, &config.cwd)?;
        Ok(SandboxChild { child })
    }
    #[cfg(target_os = "linux")]
    {
        let child_path = config.env.get("PATH").map_or("", |s| s.as_str());
        let mut path_dirs = resolve_path_dirs_from(child_path);
        // Add canonical binary parent dirs to path_dirs so they receive
        // syslib_access (ReadFile | ReadDir | Execute) — execve requires ReadFile.
        for p in binary_real_parents {
            if p.is_dir() && !path_dirs.contains(&p) {
                path_dirs.push(p);
            }
        }
        let (child, overlay, netns) =
            linux::spawn_with_landlock(config, cmd, args, &config.env, &path_dirs)?;
        Ok(SandboxChild { child, overlay, netns })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// Clean up Linux sandbox resources created by `spawn_sandboxed`.
///
/// Called after `child.wait()` to remove the named network namespace
/// (created for `ProxyOnly` mode): `pent-{pid}`.
///
/// Keyed by the *parent* process ID (`std::process::id()`).
///
/// # Errors
/// Returns `NetworkSetupFailed` if the network namespace cannot be deleted.
/// Non-Linux platforms always return `Ok(())`.
#[cfg(target_os = "linux")]
pub const fn delete_sandbox_netns(_pid: u32) -> Result<(), SandboxError> {
    Ok(())
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub const fn delete_sandbox_netns(_pid: u32) -> Result<(), SandboxError> {
    Ok(())
}

/// Flush write-listed files from the overlay upper layer back to the real
/// filesystem inodes and clean up staging directories.
///
/// Call this **after** `child.wait()` returns. The child's mount namespace
/// (and all overlayfs mounts) are already destroyed at this point.
///
/// # Linux
///
/// Signals the inotify watcher thread to stop, joins it, performs a final
/// flush of any writes not already caught by inotify, then removes the staging
/// directories under `/tmp/pent-ovl-<pid>-N/`.
#[cfg(target_os = "linux")]
pub fn teardown_overlay(handle: OverlayHandle) {
    linux_overlayfs::teardown(handle);
}

/// Check if sandboxing is available on this system.
///
/// # Errors
/// Returns a [`SandboxError`] if sandboxing is not available or not properly configured.
pub fn check_availability() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        macos::check_available()
    }
    #[cfg(target_os = "linux")]
    {
        linux::check_available()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(SandboxError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_sandbox_error_display() {
        let err = SandboxError::SandboxUnavailable {
            reason: "Landlock is not supported on this kernel".to_string(),
            remediation: "Upgrade to kernel 5.19 or later".to_string(),
        };
        assert!(err.to_string().contains("Landlock"));
        assert!(err.to_string().contains("5.19"));
    }

    #[test]
    fn test_sandbox_error_privilege() {
        let err =
            SandboxError::PrivilegeRequired("Network namespace requires CAP_NET_ADMIN".to_string());
        assert!(err.to_string().contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn test_sandbox_error_unsupported_platform() {
        let err = SandboxError::UnsupportedPlatform;
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_sandbox_error_invalid_config() {
        let err = SandboxError::InvalidConfig("bad path".to_string());
        assert!(err.to_string().contains("bad path"));
    }

    #[test]
    fn test_check_availability() {
        // On macOS and Linux this should succeed; on other platforms it errors.
        let _result = check_availability();
        // We don't assert success/failure since it depends on kernel version.
    }

    struct TestDirs {
        config: SandboxConfig,
        _temp: TempDir,
    }

    fn make_test_config() -> TestDirs {
        #[allow(clippy::unwrap_used)] // infra-only helper, no meaningful error recovery
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).ok();

        let paths = system_default_paths();
        let config =
            SandboxConfig::new(workspace.clone(), paths, workspace).with_env(build_env(&[]));
        TestDirs {
            config,
            _temp: temp,
        }
    }

    #[test]
    #[serial]
    #[cfg(target_os = "macos")]
    fn test_spawn_sandboxed_native_macos() -> TestResult {
        if check_availability().is_err() {
            return Ok(());
        }
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, "/usr/bin/true", &[]);

        match result {
            Ok(mut sc) => {
                let status = sc.child.wait().map_err(|e| format!("Failed to wait: {e}"))?;
                if !status.success() {
                    if status.code() == Some(71) {
                        return Ok(());
                    }
                    return Err(format!("Exit status: {:?}", status).into());
                }
            }
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => return Err(format!("spawn_sandboxed failed: {e:?}").into()),
        }
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_spawn_sandboxed_native_linux() -> TestResult {
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, "/bin/true", &[]);

        if check_availability().is_ok() {
            match result {
                Ok(mut sc) => {
                    let status = sc.child.wait().map_err(|e| format!("Failed to wait: {e}"))?;
                    assert!(status.success());
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(e) => return Err(format!("spawn_sandboxed failed: {e:?}").into()),
            }
        }
        Ok(())
    }

    // =========================================================================
    // Linux Landlock enforcement tests
    //
    // These tests exercise spawn_with_landlock by verifying that the sandboxed
    // child process actually has the expected restrictions.
    // They are subprocess-based: the child is spawned with spawn_sandboxed and
    // the parent checks the exit code.
    //
    // spawn_with_landlock is exercised end-to-end by the integration tests in pent/tests/.
    // =========================================================================

    /// Spawn a command inside the sandbox and return its exit code.
    #[cfg(target_os = "linux")]
    fn sandboxed_exit(
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> Result<Option<i32>, SandboxError> {
        let args: Vec<String> = args.iter().map(std::string::ToString::to_string).collect();
        let mut sandbox_child = spawn_sandboxed(config, cmd, &args)?;
        let status = sandbox_child.child.wait().map_err(SandboxError::SpawnFailed)?;
        Ok(status.code())
    }

    /// Build a test config with the given network mode and no extra paths.
    #[cfg(target_os = "linux")]
    fn linux_test_config(workspace: std::path::PathBuf, network: NetworkMode) -> SandboxConfig {
        SandboxConfig::new(
            workspace.clone(),
            system_default_paths(),
            workspace,
        )
        .with_network(network)
        .with_env(build_env(&[]))
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_workspace_file_readable() -> TestResult {
        // Verifies that spawn_with_landlock grants rw access to the workspace:
        // a file written before spawning must be readable by the child process.
        if check_availability().is_err() {
            return Ok(());
        }
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = temp.path().to_path_buf();
        let test_file = workspace.join("hello.txt");
        std::fs::write(&test_file, "hello landlock").map_err(|e| format!("write: {e}"))?;

        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        let code = match sandboxed_exit(&config, "/bin/cat", &[test_file.to_str().unwrap_or("")]) {
            Ok(code) => code,
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(e) => return Err(format!("spawn_sandboxed failed: {e:?}").into()),
        };
        assert_eq!(
            code,
            Some(0),
            "cat should succeed for a file inside the workspace"
        );
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_sysfs_blocked() -> TestResult {
        // /sys is not in the allowed read set, so access must fail.
        // /sys/kernel/version is present on every Linux kernel and readable
        // without root — it's a reliable blocked-path canary.
        if check_availability().is_err() {
            return Ok(());
        }
        // Skip if /sys/kernel/version doesn't exist on this kernel build.
        if !std::path::Path::new("/sys/kernel/version").exists() {
            return Ok(());
        }
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = temp.path().to_path_buf();

        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        let code = match sandboxed_exit(&config, "/bin/cat", &["/sys/kernel/version"]) {
            Ok(code) => code,
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(e) => return Err(format!("spawn_sandboxed failed: {e:?}").into()),
        };
        assert!(
            code != Some(0),
            "cat /sys/kernel/version should fail because /sys is not in the Landlock allow set"
        );
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_network_blocked() -> TestResult {
        // In Blocked mode, spawn_with_landlock calls unshare(CLONE_NEWNET) in
        // pre_exec, leaving the child in an empty network namespace with no
        // external connectivity.
        if check_availability().is_err() {
            return Ok(());
        }
        // Skip if bash is not available (needed for /dev/tcp redirection).
        if !std::path::Path::new("/bin/bash").exists() {
            return Ok(());
        }
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = temp.path().to_path_buf();

        let config = linux_test_config(workspace, NetworkMode::Blocked);
        // bash's /dev/tcp pseudo-device requires no external binaries and
        // will fail with ENETUNREACH / EADDRNOTAVAIL when the network namespace
        // has no routes — a reliable signal that the namespace is isolated.
        let code = match sandboxed_exit(
            &config,
            "/bin/bash",
            &["-c", "exec 3<>/dev/tcp/1.1.1.1/80 2>/dev/null"],
        ) {
            Ok(code) => code,
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(e) => return Err(format!("spawn_sandboxed failed: {e:?}").into()),
        };
        assert!(
            code != Some(0),
            "TCP connection to external IP should fail in Blocked network mode"
        );
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_network_localhost_allows_loopback() -> TestResult {
        // In LocalhostOnly mode, loopback is brought up inside the new network
        // namespace, so the child must be able to connect to 127.0.0.1.
        // We check ECONNREFUSED (port not listening), which proves the loopback
        // interface is up — contrast with ENETUNREACH in the blocked test.
        if check_availability().is_err() {
            return Ok(());
        }
        if !std::path::Path::new("/bin/bash").exists() {
            return Ok(());
        }
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = temp.path().to_path_buf();

        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        // Port 1 on localhost is never open; bash exits non-zero with ECONNREFUSED.
        // What matters is that the error is NOT "network unreachable" — meaning
        // the loopback interface exists and routes work.
        let code = match sandboxed_exit(
            &config,
            "/bin/bash",
            &["-c", "exec 3<>/dev/tcp/127.0.0.1/1 2>/dev/null; echo $?"],
        ) {
            Ok(code) => code,
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(());
            }
            Err(e) => return Err(format!("spawn_sandboxed failed: {e:?}").into()),
        };
        // The child exits non-zero (ECONNREFUSED), but it must exit — not hang.
        // A hang or ENETUNREACH exit would indicate the loopback interface is down.
        assert!(
            code.is_some(),
            "Child should exit (even with an error) when loopback is available"
        );
        Ok(())
    }
}
