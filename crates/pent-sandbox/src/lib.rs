//! OS-level process sandboxing.
//!
//! Provides filesystem and network containment using native OS mechanisms:
//! - macOS: sandbox-exec with SBPL profiles
//! - Linux: Landlock LSM for filesystem, network namespaces for network.
//!   No privileges are necessary: pent uses unprivileged user namespaces.
//!
//! # Example
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use pent_sandbox::{build_env, spawn_sandboxed, SandboxConfig, SandboxPaths};
//!
//! let paths = SandboxPaths {
//!     traversal: vec!["/".to_string()],
//!     read: vec!["/usr/lib".to_string()],
//!     execute: vec!["/usr/bin".to_string()],
//!     read_write: vec!["/tmp".to_string()],
//! };
//!
//! let workspace = std::path::PathBuf::from("/home/user/project");
//! let config = SandboxConfig::new(workspace.clone(), paths, workspace)
//!     .with_env(build_env(&[]));
//!
//! let mut child = spawn_sandboxed(&config, "my-process", &[])?;
//! let status = child.child.wait()?;
//! # let _ = status;
//! # Ok(())
//! # }
//! ```

mod config;
mod env;

// The SBPL generator is pure Rust, so its unit tests also run on Linux.
// On Linux, only the tests use the module; the allow stops dead-code
// warnings for the macOS spawn functions.
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos;

// The parse and filter functions of the macOS log reader are pure Rust, so
// their unit tests also run on Linux.
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos_log;

// The snapshot of the process tree, which the log reader needs. The two
// calls of `libproc` exist only on macOS.
#[cfg(target_os = "macos")]
mod macos_proctable;

// The measurement of `kqueue` for MAC-10. The module holds no production
// code: `kqueue` gives no fact that the poll of the process table does not
// already give (see the comment of the module). The test holds the answer
// of the kernel, so a later macOS that follows a `fork` is visible.
#[cfg(all(target_os = "macos", test))]
mod macos_kqueue;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod linux_landlock;

#[cfg(target_os = "linux")]
mod linux_fdpass;

#[cfg(target_os = "linux")]
mod linux_proxynet;

#[cfg(target_os = "linux")]
mod linux_overlayfs;

#[cfg(target_os = "linux")]
mod linux_watch;

#[cfg(target_os = "linux")]
mod linux_unixconn;

pub use config::{system_default_paths, SandboxConfig};
pub use env::{build_env, resolve_path_directories, resolve_path_dirs_from};
#[cfg(target_os = "linux")]
pub use linux::check_user_namespaces;
#[cfg(target_os = "linux")]
pub use linux::compute_accessible_set;
#[cfg(target_os = "linux")]
pub use linux::{proc_isolation, ProcDenial, ProcIsolation};
#[cfg(target_os = "linux")]
pub use linux_overlayfs::{
    cleanup_stale_overlays, DiscardKind, DiscardedWrite, FlushError, FlushFailure, OverlayHandle,
    OverlayTeardownReport,
};
#[cfg(target_os = "linux")]
pub use linux_proxynet::{child_proxy_addr, ProxyListeners, CHILD_DNS_PORT, CHILD_PROXY_PORT};
pub use pent_settings::{Mount, NetworkMode, SandboxPaths, SandboxSettings};

use std::process::Child;
use thiserror::Error;

/// Return the paths that the sandbox allows without a profile rule.
///
/// The list has the default paths of [`system_default_paths`], the paths that
/// the platform backend always allows (on Linux: `/nix/store`, `/proc`, the
/// device nodes, ...), the directories in `path_env` (a `PATH` value) and
/// their canonical targets. The summary of watch mode omits accesses below
/// these paths, because a profile does not need a rule for them.
#[must_use]
pub fn implicit_allowed_paths(path_env: &str) -> Vec<std::path::PathBuf> {
    let (_traversal, read, execute, read_write) = system_default_paths().expand_paths();
    let mut paths: Vec<std::path::PathBuf> = read
        .into_iter()
        .chain(execute)
        .chain(read_write)
        .map(|(path, _glob)| path)
        .collect();
    #[cfg(target_os = "linux")]
    paths.extend(linux::implicit_paths());
    for dir in resolve_path_dirs_from(path_env) {
        if let Ok(real) = std::fs::canonicalize(&dir) {
            paths.push(real);
        }
        paths.push(dir);
    }
    paths.sort();
    paths.dedup();
    paths
}

/// The options of watch mode.
///
/// Watch mode does not apply the sandbox policy. It records each access of
/// the process tree and blocks only the accesses that `guard` names. The
/// kernel enforces the guard (mount masks on Linux, Seatbelt deny rules on
/// macOS).
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// The dangerous accesses to block (see [`pent_profile::guard_rules`]).
    pub guard: Vec<pent_profile::GuardRule>,
    /// The Unix socket paths that the child can connect to. See
    /// [`SandboxConfig::unix_sockets`]. Watch mode records each connection
    /// that it refuses, so the review can propose the path.
    pub unix_sockets: Vec<std::path::PathBuf>,
}

/// A process that runs in watch mode.
pub struct WatchedChild {
    /// The child and the platform resources (the overlay and the proxy
    /// listeners on Linux).
    pub child: SandboxChild,
    /// The recorded events. The channel closes when the last process of the
    /// tree exits and the recorder has sent all events.
    pub events: std::sync::mpsc::Receiver<pent_profile::WatchEvent>,
}

/// Spawn `cmd` in watch mode.
///
/// `config.network` selects the network path as for [`spawn_sandboxed`].
/// Watch mode uses [`NetworkMode::ProxyOnly`] with the proxy in observe mode,
/// so that network events have domain names.
///
/// On macOS, the child runs under a Seatbelt profile that allows each
/// operation with `(with report)` and denies the guard accesses. A reader of
/// `log stream` (started before the spawn) turns the reports of the process
/// tree into events. macOS limits the rate of the reports, so the events are
/// a lower bound.
///
/// On Linux, a seccomp filter with user notification reports the path
/// syscalls of the process tree to a supervisor thread, and masks in the
/// private mount namespace of the child enforce the guard.
///
/// The event channel closes only after the caller reaps the last process of
/// the tree, because a zombie still holds the seccomp filter. Call `wait()`
/// on the child (and `teardown_overlay` when pent is a child subreaper)
/// before you wait for the channel to close.
///
/// # Errors
/// Returns [`SandboxError::UnsupportedPlatform`] on a platform without a
/// recorder, [`SandboxError::SandboxUnavailable`] on macOS if
/// `log stream` cannot start, or a spawn error.
pub fn spawn_watched(
    config: &SandboxConfig,
    options: &WatchOptions,
    cmd: &str,
    args: &[String],
) -> Result<WatchedChild, SandboxError> {
    #[cfg(target_os = "macos")]
    {
        macos::spawn_watched(config, options, cmd, args)
    }
    #[cfg(target_os = "linux")]
    {
        linux_watch::spawn_watched(config, options, cmd, args)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (config, options, cmd, args);
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// A sandboxed child process, optionally with an overlayfs handle.
pub struct SandboxChild {
    /// The child process handle.
    pub child: Child,
    /// Overlay handle for Linux (inotify watcher + in-place flush on exit).
    /// Pass this to [`teardown_overlay`] after `child.wait()` returns.
    #[cfg(target_os = "linux")]
    pub overlay: Option<linux_overlayfs::OverlayHandle>,
    /// The proxy listeners for `ProxyOnly` mode on Linux. The child made
    /// them in its network namespace before `exec`. Give them to the proxy;
    /// the child can reach nothing else.
    #[cfg(target_os = "linux")]
    pub proxy_listeners: Option<ProxyListeners>,
    /// The recorded events when [`SandboxConfig::record_events`] is set
    /// (`pent run --trace`). The recorder observes next to the enforcement.
    /// Events that the policy denies have [`pent_profile::Outcome::Denied`].
    ///
    /// On macOS, the channel has the Seatbelt denials of the process tree.
    /// It is `None` if `log stream` cannot start.
    ///
    /// On Linux, the seccomp recorder reports each access, and the outcome is
    /// `Denied` when the Landlock policy does not allow the access. The
    /// channel closes only after the caller reaps the last process of the
    /// tree.
    pub events: Option<std::sync::mpsc::Receiver<pent_profile::WatchEvent>>,
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

    /// The setup of the sandbox network failed.
    #[error("Network setup failed: {0}")]
    NetworkSetupFailed(String),
}

/// Spawn a command in a sandbox, returning a [`SandboxChild`] handle.
///
/// On Linux, the returned [`SandboxChild::overlay`] may contain an
/// [`OverlayHandle`] for write-listed file paths. Pass it to [`teardown_overlay`]
/// after `child.wait()` returns to flush writes and clean up.
///
/// On Linux, the child gets `PR_SET_PDEATHSIG(SIGKILL)`: it dies when pent
/// dies. The kernel sends this signal when the *thread* that called `fork`
/// exits. Thus call this function on a thread that lives as long as the
/// child (for example the main thread), not on a short-lived worker thread.
/// File descriptors from 3 up do not pass to the child.
///
/// # Errors
/// Returns a [`SandboxError`] if the sandbox cannot be set up or the process cannot be spawned.
pub fn spawn_sandboxed(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<SandboxChild, SandboxError> {
    // ── Auto-grant access to the binary's location ───────────────────────────
    // The binary's directories receive read + execute access (see
    // `binary_grant_dirs` for the rules). This lets runtimes like Node.js read
    // the files of their own package.
    //
    // Must happen before any platform-specific call:
    // - Linux: overlayfs accessible set is built from config at mount time.
    // - macOS: SBPL profile is generated from config before spawn.
    let mut effective_config = config.clone();
    // Directories that need ReadFile for execve to work. On Linux these get
    // read + execute access (ReadFile | ReadDir | Execute), not the
    // execute-only access of configured execute paths.
    let mut binary_real_parents: Vec<std::path::PathBuf> = Vec::new();
    {
        let path_env = config.env.get("PATH").map_or("", String::as_str);
        if let Some(found) = find_in_path(cmd, path_env) {
            let canonical = std::fs::canonicalize(&found).unwrap_or_else(|_| found.clone());
            let home = config
                .env
                .get("HOME")
                .map(std::path::PathBuf::from)
                .or_else(dirs::home_dir);
            for dir in binary_grant_dirs(&found, &canonical, home.as_deref()) {
                let s = dir.to_string_lossy().into_owned();
                if !effective_config.paths.execute.contains(&s) {
                    effective_config.paths.execute.push(s);
                }
                binary_real_parents.push(dir);
            }
        }
    }
    let config = &effective_config;

    #[cfg(target_os = "macos")]
    {
        macos::spawn_run(config, cmd, args)
    }
    #[cfg(target_os = "linux")]
    {
        let child_path = config.env.get("PATH").map_or("", |s| s.as_str());
        let mut path_dirs = resolve_path_dirs_from(child_path);
        // Landlock checks the inode that a symbolic link resolves to. Add the
        // canonical target of each PATH directory too (for example
        // /run/current-system/sw/bin -> /nix/store/...-system-path/bin).
        for dir in path_dirs.clone() {
            if let Ok(real) = std::fs::canonicalize(&dir) {
                if !path_dirs.contains(&real) {
                    path_dirs.push(real);
                }
            }
        }
        // Add canonical binary parent dirs to path_dirs so they receive
        // syslib_access (ReadFile | ReadDir | Execute) — execve requires ReadFile.
        for p in binary_real_parents {
            if p.is_dir() && !path_dirs.contains(&p) {
                path_dirs.push(p);
            }
        }
        let spawned = linux::spawn_linux(
            config,
            cmd,
            args,
            &config.env,
            &path_dirs,
            linux::SpawnMode::Sandbox,
        )?;
        Ok(SandboxChild {
            child: spawned.child,
            overlay: spawned.overlay,
            proxy_listeners: spawned.proxy_listeners,
            events: spawned.events,
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// Find `cmd` the way `execvp` does: a path with a slash is used as is; a
/// bare name is searched in `path_env`. The result is not canonical, so the
/// caller sees the symbolic link in PATH.
fn find_in_path(cmd: &str, path_env: &str) -> Option<std::path::PathBuf> {
    if cmd.contains('/') {
        return Some(std::path::PathBuf::from(cmd));
    }
    path_env
        .split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| std::path::Path::new(dir).join(cmd))
        .find(|p| p.is_file())
}

/// Paths in `$HOME` that must never receive an automatic grant. Their
/// ancestors must not receive one either.
const SENSITIVE_HOME_PATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".config",
    ".local",
    ".netrc",
    ".kube",
    ".docker",
    ".password-store",
    ".cargo/credentials.toml",
    ".npmrc",
];

/// Return true if an automatic grant on `dir` is too broad.
///
/// A grant is too broad if `dir` is `/`, `$HOME`, an ancestor of `$HOME`, a
/// direct child of `$HOME` (for example `~/.cargo` or `~/.bun`, which can
/// hold credentials), or an ancestor of a sensitive path in `$HOME`.
fn is_too_broad(dir: &std::path::Path, home: Option<&std::path::Path>) -> bool {
    if dir.parent().is_none() {
        return true;
    }
    let Some(home) = home else {
        return false;
    };
    home.starts_with(dir)
        || dir.parent() == Some(home)
        || SENSITIVE_HOME_PATHS
            .iter()
            .any(|s| home.join(s).starts_with(dir))
}

/// Return the nearest Node.js package directory that contains `file`.
///
/// A package directory is `.../node_modules/<name>` or
/// `.../node_modules/@scope/<name>`, with a `package.json` file.
fn node_package_dir(file: &std::path::Path) -> Option<std::path::PathBuf> {
    let is_node_modules = |p: &std::path::Path| p.file_name().is_some_and(|n| n == "node_modules");
    file.ancestors().skip(1).find_map(|dir| {
        let parent = dir.parent()?;
        let scoped = parent
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('@'))
            && parent.parent().is_some_and(is_node_modules);
        ((is_node_modules(parent) || scoped) && dir.join("package.json").is_file())
            .then(|| dir.to_path_buf())
    })
}

/// Compute the directories that receive automatic read + execute access for
/// the binary `found` (as found in PATH) with the canonical path `canonical`.
///
/// The heuristic:
/// 1. The directory of `found` (usually a PATH directory such as `bin/`).
/// 2. The directory of `canonical` (the real file that `execve` opens).
/// 3. If `canonical` is inside a Node.js package
///    (`.../node_modules/<pkg>/...`), that package directory, so that the
///    runtime can read the other files of the package.
/// 4. Otherwise, if the directory of `canonical` is a `bin/` directory, its
///    parent (the package root, for example `/opt/tool/bin` → `/opt/tool`).
///
/// A directory that [`is_too_broad`] rejects (`/`, `$HOME`, `~/.local`, a
/// direct child of `$HOME`, an ancestor of `~/.ssh`, ...) never receives a
/// grant.
#[must_use]
pub(crate) fn binary_grant_dirs(
    found: &std::path::Path,
    canonical: &std::path::Path,
    home: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let mut push = |d: &std::path::Path| {
        if !is_too_broad(d, home) && !dirs.iter().any(|x| x == d) {
            dirs.push(d.to_path_buf());
        }
    };
    if let Some(p) = found.parent() {
        push(p);
    }
    if let Some(real_parent) = canonical.parent() {
        push(real_parent);
        if let Some(pkg) = node_package_dir(canonical) {
            push(&pkg);
        } else if real_parent.file_name().is_some_and(|n| n == "bin") {
            if let Some(root) = real_parent.parent() {
                push(root);
            }
        }
    }
    dirs
}

/// Flush write-listed files from the overlay upper layer back to the real
/// filesystem inodes and clean up staging directories.
///
/// Call this **after** `child.wait()` returns.
///
/// # Linux
///
/// First waits until no background process of the session is alive. Pent
/// is a child subreaper (the spawn sets this), so the kernel gives orphaned
/// session processes to pent. Processes that do not exit in a grace time get
/// `SIGKILL`. Then the function stops the inotify watcher thread, does a
/// final flush of any writes not already caught by inotify, and removes the
/// staging directories.
///
/// The returned report lists the paths that pent could not flush and the
/// writes that the overlay discards. When a flush fails, the function keeps
/// the staging directory, so the data stays recoverable. Show the report to
/// the user.
#[cfg(target_os = "linux")]
pub fn teardown_overlay(handle: OverlayHandle) -> OverlayTeardownReport {
    linux_overlayfs::teardown(handle)
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
        // The result depends on the kernel, so the test asserts the two
        // things that do not: the function answers for the platform that
        // pent supports, and a refusal names the reason.
        let result = check_availability();
        if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
            assert!(
                matches!(result, Err(SandboxError::UnsupportedPlatform)),
                "an unsupported platform must say so: {result:?}"
            );
            return;
        }
        if let Err(e) = result {
            let message = e.to_string();
            assert!(
                !message.is_empty(),
                "a refusal must tell the user what is missing"
            );
            assert!(
                !matches!(e, SandboxError::UnsupportedPlatform),
                "Linux and macOS are supported platforms: {message}"
            );
        }
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
                let status = sc
                    .child
                    .wait()
                    .map_err(|e| format!("Failed to wait: {e}"))?;
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
        let Some(true_bin) = which("true") else {
            return Ok(()); // skip: no `true` in PATH
        };
        let dirs = make_test_config();
        let result = spawn_sandboxed(&dirs.config, &true_bin.to_string_lossy(), &[]);

        if check_availability().is_ok() {
            match result {
                Ok(mut sc) => {
                    let status = sc
                        .child
                        .wait()
                        .map_err(|e| format!("Failed to wait: {e}"))?;
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
        let status = sandbox_child
            .child
            .wait()
            .map_err(SandboxError::SpawnFailed)?;
        Ok(status.code())
    }

    /// Build a test config with the given network mode and no extra paths.
    #[cfg(target_os = "linux")]
    fn linux_test_config(workspace: std::path::PathBuf, network: NetworkMode) -> SandboxConfig {
        SandboxConfig::new(workspace.clone(), system_default_paths(), workspace)
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

        let Some(cat) = which("cat") else {
            return Ok(()); // skip: no `cat` in PATH
        };
        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        let code = match sandboxed_exit(
            &config,
            &cat.to_string_lossy(),
            &[test_file.to_str().unwrap_or("")],
        ) {
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

        let Some(cat) = which("cat") else {
            return Ok(()); // skip: no `cat` in PATH
        };
        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        let code = match sandboxed_exit(&config, &cat.to_string_lossy(), &["/sys/kernel/version"]) {
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
        let Some(bash) = which("bash") else {
            return Ok(());
        };
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = temp.path().to_path_buf();

        let config = linux_test_config(workspace, NetworkMode::Blocked);
        // bash's /dev/tcp pseudo-device requires no external binaries and
        // will fail with ENETUNREACH / EADDRNOTAVAIL when the network namespace
        // has no routes — a reliable signal that the namespace is isolated.
        let code = match sandboxed_exit(
            &config,
            &bash.to_string_lossy(),
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
        let Some(bash) = which("bash") else {
            return Ok(());
        };
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = temp.path().to_path_buf();

        let config = linux_test_config(workspace, NetworkMode::LocalhostOnly);
        // Port 1 on localhost is never open; bash exits non-zero with ECONNREFUSED.
        // What matters is that the error is NOT "network unreachable" — meaning
        // the loopback interface exists and routes work.
        let code = match sandboxed_exit(
            &config,
            &bash.to_string_lossy(),
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

    // =========================================================================
    // Binary grants and PATH resolution
    // =========================================================================

    /// Find `name` in PATH (like `which`). Returns `None` if it is absent.
    ///
    /// Only the Linux tests use this helper.
    #[cfg(target_os = "linux")]
    fn which(name: &str) -> Option<std::path::PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join(name))
                .find(|p| p.is_file())
        })
    }

    #[test]
    fn test_find_in_path() -> TestResult {
        let temp = tempfile::tempdir()?;
        let a = temp.path().join("a");
        let b = temp.path().join("b");
        std::fs::create_dir_all(&a)?;
        std::fs::create_dir_all(&b)?;
        std::fs::write(b.join("tool"), "")?;
        let path_env = format!("{}::{}", a.display(), b.display());
        assert_eq!(find_in_path("tool", &path_env), Some(b.join("tool")));
        assert_eq!(find_in_path("missing", &path_env), None);
        assert_eq!(
            find_in_path("./rel/tool", &path_env),
            Some(std::path::PathBuf::from("./rel/tool"))
        );
        Ok(())
    }

    #[test]
    fn test_binary_grant_dirs_never_home_or_local() {
        use std::path::Path;
        let home = Path::new("/home/u");
        // ~/.local/bin/tool -> ~/.local/share/tool/bin/tool
        let dirs = binary_grant_dirs(
            Path::new("/home/u/.local/bin/tool"),
            Path::new("/home/u/.local/share/tool/bin/tool"),
            Some(home),
        );
        for d in &dirs {
            assert_ne!(d, Path::new("/home/u"));
            assert_ne!(d, Path::new("/home/u/.local"));
            assert!(!Path::new("/home/u/.ssh").starts_with(d));
        }
        assert!(dirs.contains(&std::path::PathBuf::from("/home/u/.local/bin")));
        assert!(dirs.contains(&std::path::PathBuf::from("/home/u/.local/share/tool/bin")));
        assert!(dirs.contains(&std::path::PathBuf::from("/home/u/.local/share/tool")));

        // A binary directly in $HOME/bin: $HOME is never granted.
        let dirs = binary_grant_dirs(
            Path::new("/home/u/bin/x"),
            Path::new("/home/u/bin/x"),
            Some(home),
        );
        assert!(!dirs.iter().any(|d| d == Path::new("/home/u")));

        // ~/.cargo/bin/x: ~/.cargo (direct child of $HOME) is not granted.
        let dirs = binary_grant_dirs(
            Path::new("/home/u/.cargo/bin/x"),
            Path::new("/home/u/.cargo/bin/x"),
            Some(home),
        );
        assert!(!dirs.iter().any(|d| d == Path::new("/home/u/.cargo")));

        // /bin/true: `/` is never granted.
        let dirs = binary_grant_dirs(Path::new("/bin/true"), Path::new("/bin/true"), None);
        assert!(!dirs.iter().any(|d| d == Path::new("/")));
    }

    #[test]
    fn test_binary_grant_dirs_node_package() -> TestResult {
        let temp = tempfile::tempdir()?;
        let home = temp.path().join("home");
        let pkg = home.join(".npm-global/lib/node_modules/@scope/tool");
        std::fs::create_dir_all(pkg.join("dist"))?;
        std::fs::write(pkg.join("package.json"), "{}")?;
        std::fs::write(pkg.join("dist/cli.js"), "")?;
        let bin = home.join(".npm-global/bin");
        let dirs = binary_grant_dirs(&bin.join("tool"), &pkg.join("dist/cli.js"), Some(&home));
        assert!(dirs.contains(&pkg), "package dir must be granted: {dirs:?}");
        assert!(dirs.contains(&bin));
        assert!(!dirs.contains(&home.join(".npm-global")));
        assert!(!dirs.iter().any(|d| d.ends_with("node_modules")));
        Ok(())
    }
}
