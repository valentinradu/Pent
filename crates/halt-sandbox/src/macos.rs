//! macOS sandbox implementation using sandbox-exec and SBPL profiles.
//!
//! Uses Apple's Seatbelt sandbox via the `sandbox-exec` command.
//! Generates SBPL (Sandbox Profile Language) profiles at runtime.
//!
//! # SBPL Profile Structure
//!
//! Uses `(allow default)` as baseline with selective denies:
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-read* (subpath "/System"))
//! (deny file-read* (subpath "/Users"))
//! (allow file-read* (subpath "/Users/name/.claude"))
//! (deny file-write* (subpath "/System"))
//! ```
//!
//! # Note
//! sandbox-exec is deprecated by Apple but still functional.
//! No lightweight alternative exists for process sandboxing on macOS.

use crate::{NetworkMode, SandboxConfig, SandboxError};
use std::fmt::Write as _;
use std::path::Path;

/// Check if sandbox-exec is available on this system.
///
/// # Errors
/// Returns `SandboxUnavailable` if sandbox-exec is not found.
pub fn check_available() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            Ok(())
        } else {
            Err(SandboxError::SandboxUnavailable {
                reason: "sandbox-exec not found at /usr/bin/sandbox-exec".to_string(),
                remediation: "This should not happen on macOS. Check system integrity.".to_string(),
            })
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(SandboxError::UnsupportedPlatform)
    }
}

/// Validate that a path does not contain SBPL control characters.
///
/// SBPL uses `(`, `)`, `;`, and `*` as structural characters. A path
/// containing any of these would allow an attacker to inject arbitrary
/// rules into the generated sandbox profile.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains a forbidden character.
fn validate_path_for_sbpl(path: &Path) -> Result<(), SandboxError> {
    let s = path.to_string_lossy();
    for ch in ['(', ')', ';', '*'] {
        if s.contains(ch) {
            return Err(SandboxError::InvalidConfig(format!(
                "Path {path:?} contains SBPL control character {ch}; \
                 refusing to include it in the sandbox profile to prevent rule injection"
            )));
        }
    }
    Ok(())
}

/// Generate SBPL profile string for the given config.
///
/// Uses `(allow default)` baseline with selective denies, then allows
/// paths from config.paths (traversal, read, read_write).
///
/// # Arguments
/// * `config` - Sandbox configuration with paths
///
/// # Returns
/// SBPL profile as a String
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if any user-supplied path contains
/// SBPL control characters (`(`, `)`, `;`, `*`) that would allow profile injection.
pub fn generate_sbpl_profile(config: &SandboxConfig) -> Result<String, SandboxError> {
    let mut profile = String::new();

    // Header - use allow default as baseline, then selectively deny.
    //
    // We deny file-read-data (file content) globally and re-allow it only for
    // paths the process is permitted to read.  Crucially, we do NOT deny
    // file-read-metadata (stat/lstat/access) globally: the macOS DNS resolution
    // stack (getaddrinfo → mDNSResponder / Network Extension) calls stat() on
    // paths outside the allowlist (VPN sockets, network config databases, etc.)
    // and needs file-read-metadata to succeed everywhere.  Denying all of
    // file-read* broke DNS for every program that uses getaddrinfo().
    profile.push_str("(version 1)\n");
    profile.push_str("(allow default)\n");
    profile.push_str("(deny file-read-data)\n");
    profile.push_str("(deny file-write*)\n");

    // Expand paths from config
    let (traversal, read, read_write) = config.paths.expand_paths();

    // =========================================================================
    // TRAVERSAL PATHS - allow reading the directory entry itself
    // =========================================================================
    for (path, is_glob) in &traversal {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data");
        } else {
            validate_path_for_sbpl(path)?;
            let escaped = escape_sbpl_path(path);
            write!(profile, "(allow file-read-data (literal \"{escaped}\"))\n").unwrap();
        }
    }

    // Add workspace parent directories for realpath traversal
    let mut parent = config.workspace.parent();
    while let Some(p) = parent {
        let canonical = canonicalize_for_sbpl(p);
        write!(profile, "(allow file-read-data (literal \"{canonical}\"))\n").unwrap();
        parent = p.parent();
    }

    // =========================================================================
    // READ PATHS - subpath content access
    // =========================================================================
    for (path, is_glob) in &read {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data");
        } else {
            validate_path_for_sbpl(path)?;
            add_sbpl_path_rule(&mut profile, path, "file-read-data");
        }
    }

    // =========================================================================
    // READ-WRITE PATHS - subpath content and write access
    // =========================================================================
    for (path, is_glob) in &read_write {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data file-write*");
        } else {
            validate_path_for_sbpl(path)?;
            add_sbpl_path_rule(&mut profile, path, "file-read-data file-write*");
        }
    }

    // Workspace - always read/write (validated as user-supplied input)
    validate_path_for_sbpl(&config.workspace)?;
    add_sbpl_path_rule(
        &mut profile,
        &config.workspace,
        "file-read-data file-write*",
    );

    // TMPDIR if set
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let tmpdir_path = Path::new(&tmpdir).to_path_buf();
        validate_path_for_sbpl(&tmpdir_path)?;
        add_sbpl_path_rule(&mut profile, &tmpdir_path, "file-read-data file-write*");
    }

    // =========================================================================
    // NETWORK RULES
    // =========================================================================
    let network_rules = generate_network_rules(&config.network);
    if !network_rules.is_empty() {
        profile.push_str(&network_rules);
        profile.push('\n');
    }

    Ok(profile)
}

/// Generate SBPL network rules based on NetworkMode.
///
/// # Network Rules
/// - Unrestricted: No network rules (allow default permits it)
/// - LocalhostOnly: Deny network, then allow all loopback outbound
/// - ProxyOnly: No network rules — proxy enforcement is not supported on macOS.
///   On macOS there is no per-process network namespace (unlike Linux), so traffic
///   cannot be transparently redirected through a proxy regardless of DYLD injection
///   limitations. ProxyOnly is therefore treated as Unrestricted at the Seatbelt
///   level; the caller (halt CLI) is responsible for warning the user.
/// - Blocked: `(deny network*)`
fn generate_network_rules(mode: &NetworkMode) -> String {
    match mode {
        NetworkMode::Unrestricted | NetworkMode::ProxyOnly { .. } => {
            // Allow default already permits network.
            // ProxyOnly is treated as Unrestricted on macOS — see doc comment above.
            String::new()
        }
        NetworkMode::LocalhostOnly => {
            // Deny all network, then allow only loopback.
            // network-outbound to remote localhost: allows TCP/UDP connects to 127.x
            // network-bind to local localhost: allows binding loopback server sockets
            // (local ip "localhost:*") is intentionally omitted — on recent macOS it
            // matches unbound outbound sockets (local addr 0.0.0.0) and would leak.
            r#"(deny network*)
(allow network-outbound (remote ip "localhost:*"))
(allow network-bind (local ip "localhost:*"))"#
                .to_string()
        }
        NetworkMode::Blocked => {
            // Explicit deny since we use allow default
            "(deny network*)".to_string()
        }
    }
}

/// Escape a path for use in SBPL profile.
///
/// SBPL requires escaping of:
/// - Double quotes -> \"
/// - Backslashes -> \\
fn escape_sbpl_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
}

/// Canonicalize a path for SBPL, resolving symlinks.
///
/// SBPL uses literal paths, so symlinks like /var -> /private/var must be resolved.
/// Falls back to original path if canonicalization fails.
fn canonicalize_for_sbpl(path: &Path) -> String {
    path.canonicalize()
        .map(|p| escape_sbpl_path(&p))
        .unwrap_or_else(|_| escape_sbpl_path(path))
}

/// Add SBPL rules for a glob path (prefix match) using SBPL regex.
///
/// A glob path `~/.claude.json*` (with trailing `*` stripped before calling here)
/// generates a regex rule that matches the path and anything starting with it.
/// The regex is anchored at the start (`^`) and the path chars are regex-escaped.
fn add_sbpl_glob_rule(profile: &mut String, path: &Path, access: &str) {
    let s = path.to_string_lossy();
    // Regex-escape the path (only `.` is special in practice for file paths).
    let escaped_regex = s.replace('.', "\\.");
    let canonical = path
        .canonicalize()
        .map(|p| p.to_string_lossy().replace('.', "\\."))
        .unwrap_or_else(|_| escaped_regex.clone());

    write!(profile, "(allow {access} (regex \"^{canonical}\"))\n").unwrap();
    if escaped_regex != canonical {
        write!(profile, "(allow {access} (regex \"^{escaped_regex}\"))\n").unwrap();
    }
}

/// Add SBPL rules for a path, including both original and canonical if they differ.
///
/// macOS has symlinks like /var -> /private/var. File operations may use either path,
/// so we need to allow both in the SBPL profile.
fn add_sbpl_path_rule(profile: &mut String, path: &Path, access: &str) {
    let original = escape_sbpl_path(path);
    let canonical = canonicalize_for_sbpl(path);

    // Use literal for files, subpath for directories
    let is_file = path.is_file();
    let modifier = if is_file { "literal" } else { "subpath" };

    // Always add the canonical path
    write!(profile, "(allow {access} ({modifier} \"{canonical}\"))\n").unwrap();

    // If original differs from canonical (symlink), add it too
    if original != canonical {
        write!(profile, "(allow {access} ({modifier} \"{original}\"))\n").unwrap();
    }

    // For executable files, also allow process-exec
    if is_file && is_executable(path) {
        write!(profile, "(allow process-exec (literal \"{canonical}\"))\n").unwrap();
        if original != canonical {
            write!(profile, "(allow process-exec (literal \"{original}\"))\n").unwrap();
        }
    }
}

/// Check if a file is executable
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Execute a command under sandbox-exec, replacing current process.
///
/// # Arguments
/// * `profile` - SBPL profile string
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `cwd` - Working directory
///
/// # Errors
/// Returns `SpawnFailed` if exec fails (only returns on error).
#[cfg(target_os = "macos")]
pub fn exec_with_sandbox(
    profile: &str,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &Path,
) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p");
    command.arg(profile);
    command.arg(cmd);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }

    // exec() replaces current process - only returns on error
    let err = command.exec();
    Err(SandboxError::SpawnFailed(err))
}

#[cfg(not(target_os = "macos"))]
pub fn exec_with_sandbox(
    _profile: &str,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _cwd: &Path,
) -> Result<std::convert::Infallible, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

/// Spawn a command under sandbox-exec, returning Child handle.
///
/// # Arguments
/// * `profile` - SBPL profile string
/// * `cmd` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `cwd` - Working directory
///
/// # Returns
/// Child process handle
///
/// # Errors
/// Returns `SpawnFailed` if spawn fails.
#[cfg(target_os = "macos")]
pub fn spawn_with_sandbox(
    profile: &str,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    use std::process::{Command, Stdio};

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p");
    command.arg(profile);
    command.arg(cmd);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    command.spawn().map_err(SandboxError::SpawnFailed)
}

#[cfg(not(target_os = "macos"))]
pub fn spawn_with_sandbox(
    _profile: &str,
    _cmd: &str,
    _args: &[String],
    _env: &std::collections::HashMap<String, String>,
    _cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    Err(SandboxError::UnsupportedPlatform)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::SandboxPaths;
    use std::net::SocketAddr;

    // ========================================================================
    // escape_sbpl_path tests
    // ========================================================================

    #[test]
    fn test_escape_sbpl_path_simple() {
        let path = Path::new("/usr/bin");
        let escaped = escape_sbpl_path(path);
        assert_eq!(escaped, "/usr/bin");
    }

    #[test]
    fn test_escape_sbpl_path_with_spaces() {
        let path = Path::new("/Users/name/My Documents");
        let escaped = escape_sbpl_path(path);
        // Spaces don't need escaping in SBPL subpath strings
        assert_eq!(escaped, "/Users/name/My Documents");
    }

    #[test]
    fn test_escape_sbpl_path_with_quotes() {
        let path = Path::new("/path/with\"quotes");
        let escaped = escape_sbpl_path(path);
        assert_eq!(escaped, r#"/path/with\"quotes"#);
    }

    #[test]
    fn test_escape_sbpl_path_with_backslash() {
        let path = Path::new(r"/path/with\backslash");
        let escaped = escape_sbpl_path(path);
        assert_eq!(escaped, r"/path/with\\backslash");
    }

    // ========================================================================
    // canonicalize_for_sbpl tests
    // ========================================================================

    #[test]
    fn test_canonicalize_for_sbpl_resolves_symlink() {
        // On macOS, /var is a symlink to /private/var
        #[cfg(target_os = "macos")]
        {
            let path = Path::new("/var");
            let canonical = canonicalize_for_sbpl(path);
            assert!(
                canonical.starts_with("/private/var"),
                "Expected /private/var, got {}",
                canonical
            );
        }
    }

    #[test]
    fn test_canonicalize_for_sbpl_nonexistent_fallback() {
        // Non-existent paths should fall back to escaped original
        let path = Path::new("/nonexistent/path/12345");
        let canonical = canonicalize_for_sbpl(path);
        assert_eq!(canonical, "/nonexistent/path/12345");
    }

    // ========================================================================
    // generate_network_rules tests
    // ========================================================================

    #[test]
    fn test_network_rules_unrestricted() {
        let rules = generate_network_rules(&NetworkMode::Unrestricted);
        // Unrestricted = empty (allow default permits network)
        assert!(rules.is_empty());
    }

    #[test]
    fn test_network_rules_localhost_only() {
        let rules = generate_network_rules(&NetworkMode::LocalhostOnly);
        // Should deny all, then allow localhost
        assert!(rules.contains("(deny network*)"));
        assert!(rules.contains("localhost"));
    }

    #[test]
    fn test_network_rules_proxy_only() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let rules = generate_network_rules(&NetworkMode::ProxyOnly { proxy_addr: addr });
        // On macOS, ProxyOnly produces no Seatbelt network rules — enforcement is
        // impossible without per-process network namespaces (Linux-only).
        assert!(
            rules.is_empty(),
            "ProxyOnly should generate no network rules on macOS, got: {rules}"
        );
    }

    #[test]
    fn test_network_rules_blocked() {
        let rules = generate_network_rules(&NetworkMode::Blocked);
        // Blocked = explicit deny
        assert!(rules.contains("(deny network*)"));
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    fn test_check_available_on_macos() {
        // On macOS, sandbox-exec should exist
        let result = check_available();
        #[cfg(target_os = "macos")]
        assert!(result.is_ok());
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_err());
    }

    // ========================================================================
    // generate_sbpl_profile tests
    // ========================================================================

    fn make_test_paths() -> SandboxPaths {
        SandboxPaths {
            traversal: vec!["/".to_string(), "/Users".to_string()],
            read: vec!["/usr/lib".to_string()],
            read_write: vec!["/tmp".to_string()],
        }
    }

    #[test]
    fn test_sbpl_profile_has_version() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(version 1)"));
    }

    #[test]
    fn test_sbpl_profile_has_allow_default() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(allow default)"));
    }

    #[test]
    fn test_sbpl_profile_allows_workspace() {
        let config = SandboxConfig::new(
            "/my/workspace".into(),
            make_test_paths(),
            "/my/workspace".into(),
        );
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("/my/workspace"));
    }

    #[test]
    fn test_sbpl_profile_includes_traversal() {
        let paths = SandboxPaths {
            traversal: vec!["/".to_string(), "/custom/traversal".to_string()],
            read: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(literal \"/custom/traversal\")"));
    }

    #[test]
    fn test_sbpl_profile_includes_network_rules_when_blocked() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into())
                .with_network(NetworkMode::Blocked);
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn test_sbpl_profile_rejects_path_with_parenthesis() {
        let paths = SandboxPaths {
            traversal: vec!["/bad) (deny network*) (allow file-read* (subpath \"/".to_string()],
            read: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let result = generate_sbpl_profile(&config);
        assert!(
            result.is_err(),
            "Path with SBPL control characters should be rejected"
        );
    }

    #[test]
    fn test_sbpl_profile_rejects_path_with_glob() {
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/path/with/*/wildcard".to_string()],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let result = generate_sbpl_profile(&config);
        assert!(result.is_err(), "Path with * should be rejected");
    }

    #[test]
    fn test_sbpl_profile_rejects_workspace_with_semicolon() {
        let config = SandboxConfig::new(
            "/bad;workspace".into(),
            make_test_paths(),
            "/bad;workspace".into(),
        );
        let result = generate_sbpl_profile(&config);
        assert!(result.is_err(), "Workspace path with ; should be rejected");
    }
}
