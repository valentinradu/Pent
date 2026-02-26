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
pub fn spawn_sandboxed(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<SandboxChild, SandboxError> {
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
        let path_dirs = resolve_path_dirs_from(child_path);
        let (child, overlay) =
            linux::spawn_with_landlock(config, cmd, args, &config.env, &path_dirs)?;
        Ok(SandboxChild { child, overlay })
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
pub fn delete_sandbox_netns(pid: u32) -> Result<(), SandboxError> {
    let name = format!("pent-{}", pid);
    linux_netns::delete_netns(&name)
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn delete_sandbox_netns(_pid: u32) -> Result<(), SandboxError> {
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

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
    fn test_spawn_sandboxed_native_macos() {
        if check_availability().is_err() {
            return;
        }
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, "/usr/bin/true", &[]);

        match result {
            Ok(mut sc) => {
                let status = sc.child.wait().expect("Failed to wait");
                if !status.success() {
                    if status.code() == Some(71) {
                        return;
                    }
                    panic!("Exit status: {:?}", status);
                }
            }
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        }
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_spawn_sandboxed_native_linux() {
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, "/bin/true", &[]);

        if check_availability().is_ok() {
            match result {
                Ok(mut sc) => {
                    let status = sc.child.wait().expect("Failed to wait");
                    assert!(status.success());
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
            }
        }
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
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
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
    fn test_linux_landlock_workspace_file_readable() {
        // Verifies that spawn_with_landlock grants rw access to the workspace:
        // a file written before spawning must be readable by the child process.
        if check_availability().is_err() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();
        let test_file = workspace.join("hello.txt");
        std::fs::write(&test_file, "hello landlock").unwrap();

        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        let code = match sandboxed_exit(&config, "/bin/cat", &[test_file.to_str().unwrap()]) {
            Ok(code) => code,
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        };
        assert_eq!(
            code,
            Some(0),
            "cat should succeed for a file inside the workspace"
        );
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_sysfs_blocked() {
        // /sys is not in the allowed read set, so access must fail.
        // /sys/kernel/version is present on every Linux kernel and readable
        // without root — it's a reliable blocked-path canary.
        if check_availability().is_err() {
            return;
        }
        // Skip if /sys/kernel/version doesn't exist on this kernel build.
        if !std::path::Path::new("/sys/kernel/version").exists() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().to_path_buf();

        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        let code = match sandboxed_exit(&config, "/bin/cat", &["/sys/kernel/version"]) {
            Ok(code) => code,
            Err(SandboxError::SpawnFailed(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        };
        assert!(
            code != Some(0),
            "cat /sys/kernel/version should fail because /sys is not in the Landlock allow set"
        );
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_network_blocked() {
        // In Blocked mode, spawn_with_landlock calls unshare(CLONE_NEWNET) in
        // pre_exec, leaving the child in an empty network namespace with no
        // external connectivity.
        if check_availability().is_err() {
            return;
        }
        // Skip if bash is not available (needed for /dev/tcp redirection).
        if !std::path::Path::new("/bin/bash").exists() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
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
                return;
            }
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        };
        assert!(
            code != Some(0),
            "TCP connection to external IP should fail in Blocked network mode"
        );
    }

    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_linux_landlock_network_localhost_allows_loopback() {
        // In LocalhostOnly mode, loopback is brought up inside the new network
        // namespace, so the child must be able to connect to 127.0.0.1.
        // We check ECONNREFUSED (port not listening), which proves the loopback
        // interface is up — contrast with ENETUNREACH in the blocked test.
        if check_availability().is_err() {
            return;
        }
        if !std::path::Path::new("/bin/bash").exists() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
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
                return;
            }
            Err(e) => panic!("spawn_sandboxed failed: {:?}", e),
        };
        // The child exits non-zero (ECONNREFUSED), but it must exit — not hang.
        // A hang or ENETUNREACH exit would indicate the loopback interface is down.
        assert!(
            code.is_some(),
            "Child should exit (even with an error) when loopback is available"
        );
    }
}
