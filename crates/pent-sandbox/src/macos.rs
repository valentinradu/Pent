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
//! (deny file-write* (subpath "/Users/name/project/.pent"))
//! ```
//!
//! When more than one rule matches an operation, the last rule wins.
//!
//! Each path goes into the profile as a quoted SBPL string. The generator
//! escapes backslashes and double quotes, so a path cannot add rules.
//!
//! # Note
//! sandbox-exec is deprecated by Apple but still functional.
//! No lightweight alternative exists for process sandboxing on macOS.

use crate::{NetworkMode, SandboxConfig, SandboxError};
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

/// Make sure that a path string can go into an SBPL string literal.
///
/// The profile generator quotes and escapes each string (see
/// [`sbpl_string`]), so the SBPL structural characters `(`, `)`, `;`, `"`
/// and `\` are safe in a path. A workspace with the name `proj (copy)` is
/// valid. Only NUL and newline are rejected: the sandbox library reads the
/// profile as a C string, which ends at NUL, and a newline in a path is
/// almost always an error.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the text contains NUL or a newline.
fn validate_sbpl_text(text: &str) -> Result<(), SandboxError> {
    if let Some(ch) = text.chars().find(|c| matches!(c, '\0' | '\n')) {
        return Err(SandboxError::InvalidConfig(format!(
            "Path {text:?} contains the character {ch:?}; \
             pent cannot put this path in the sandbox profile"
        )));
    }
    Ok(())
}

/// Quote `text` as an SBPL string literal, with the double quotes.
///
/// SBPL strings use the Scheme escape rules: a backslash starts an escape
/// sequence and a double quote ends the string. This function escapes both
/// characters, so the sandbox library reads back exactly `text`.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the text contains NUL or a newline.
fn sbpl_string(text: &str) -> Result<String, SandboxError> {
    validate_sbpl_text(text)?;
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            other => out.push(other),
        }
    }
    out.push('"');
    Ok(out)
}

/// Translate a glob prefix into an anchored SBPL regex.
///
/// The config loader removes the trailing `*` of a glob entry, so the
/// result matches the pattern and all paths that start with it (there is
/// no `$` anchor). In the remaining text, `**` matches any characters and
/// `*` matches any characters except `/`. All other regex metacharacters
/// are escaped, so they match only themselves.
///
/// The result is a regex, not an SBPL string. Give it to [`sbpl_string`]
/// to escape the backslashes for the SBPL reader.
fn glob_prefix_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len().saturating_add(1));
    out.push('^');
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    out.push_str(".*");
                } else {
                    out.push_str("[^/]*");
                }
            }
            '\\' | '.' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// The action of one SBPL rule.
#[derive(Clone, Copy)]
enum RuleAction {
    Allow,
    Deny,
}

impl RuleAction {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Add one rule `(<action> <access> (<filter> "<value>"))` to `profile`.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if `value` contains NUL or a newline.
fn push_rule(
    profile: &mut String,
    action: RuleAction,
    access: &str,
    filter: &str,
    value: &str,
) -> Result<(), SandboxError> {
    let quoted = sbpl_string(value)?;
    profile.push_str(&format!(
        "({} {access} ({filter} {quoted}))\n",
        action.keyword()
    ));
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
/// Returns `SandboxError::InvalidConfig` if a path contains NUL or a newline.
/// All other characters are quoted and escaped, so they cannot change the
/// structure of the profile.
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
    //
    // Rule order is important. When more than one rule matches an operation,
    // the last rule in the profile wins. The global denies come first, the
    // allows come after them, and the project-config deny comes last.
    profile.push_str("(version 1)\n");
    profile.push_str("(allow default)\n");
    profile.push_str("(deny file-read-data)\n");
    profile.push_str("(deny file-write*)\n");

    // Expand paths from config
    let (traversal, read, execute, read_write) = config.paths.expand_paths();

    // =========================================================================
    // TRAVERSAL PATHS - allow reading the directory entry itself
    // =========================================================================
    for (path, is_glob) in &traversal {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data")?;
        } else {
            push_rule(
                &mut profile,
                RuleAction::Allow,
                "file-read-data",
                "literal",
                &path.to_string_lossy(),
            )?;
        }
    }

    // Add workspace parent directories for realpath traversal
    let mut parent = config.workspace.parent();
    while let Some(p) = parent {
        push_rule(
            &mut profile,
            RuleAction::Allow,
            "file-read-data",
            "literal",
            &canonical_or_original(p),
        )?;
        parent = p.parent();
    }

    // =========================================================================
    // READ PATHS - subpath content access
    // =========================================================================
    for (path, is_glob) in &read {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data")?;
        } else {
            add_sbpl_path_rule(&mut profile, path, "file-read-data")?;
        }
    }

    // =========================================================================
    // EXECUTE PATHS - file content read + process execution
    // =========================================================================
    for (path, is_glob) in &execute {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data")?;
            add_sbpl_glob_rule(&mut profile, path, "process-exec")?;
        } else {
            add_sbpl_path_rule(&mut profile, path, "file-read-data")?;
            // Unconditionally grant process-exec for execute paths (unlike read paths
            // which only add process-exec for individual executable files found on disk).
            let canonical = canonical_or_original(path);
            let original = path.to_string_lossy();
            let modifier = if path.is_file() { "literal" } else { "subpath" };
            push_rule(
                &mut profile,
                RuleAction::Allow,
                "process-exec",
                modifier,
                &canonical,
            )?;
            if original != canonical {
                push_rule(
                    &mut profile,
                    RuleAction::Allow,
                    "process-exec",
                    modifier,
                    &original,
                )?;
            }
        }
    }

    // =========================================================================
    // READ-WRITE PATHS - subpath content and write access
    // =========================================================================
    for (path, is_glob) in &read_write {
        if *is_glob {
            add_sbpl_glob_rule(&mut profile, path, "file-read-data file-write*")?;
        } else {
            add_sbpl_path_rule(&mut profile, path, "file-read-data file-write*")?;
        }
    }

    // Workspace - always read/write
    add_sbpl_path_rule(
        &mut profile,
        &config.workspace,
        "file-read-data file-write*",
    )?;

    // TMPDIR if set
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        add_sbpl_path_rule(
            &mut profile,
            Path::new(&tmpdir),
            "file-read-data file-write*",
        )?;
    }

    // =========================================================================
    // PROJECT CONFIG - deny writes to <workspace>/.pent
    // =========================================================================
    // The project config (.pent/pent.toml) controls the sandbox of the next
    // run. The sandboxed process must not change it. These rules come after
    // all allow rules (the workspace, TMPDIR and read_write paths), because
    // the last matching rule wins. Thus they also apply when the workspace
    // is in TMPDIR or a read_write path contains the workspace.
    add_project_config_deny(&mut profile, &config.workspace)?;

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

/// Add rules that deny writes to `<workspace>/.pent`.
///
/// The rules use the canonical workspace path and also the original path
/// if it is different (for example `/var` and `/private/var`).
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains NUL or a newline.
fn add_project_config_deny(profile: &mut String, workspace: &Path) -> Result<(), SandboxError> {
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let canonical = canonical_ws.join(".pent");
    let original = workspace.join(".pent");
    push_rule(
        profile,
        RuleAction::Deny,
        "file-write*",
        "subpath",
        &canonical.to_string_lossy(),
    )?;
    if original != canonical {
        push_rule(
            profile,
            RuleAction::Deny,
            "file-write*",
            "subpath",
            &original.to_string_lossy(),
        )?;
    }
    Ok(())
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
///   level. The pent CLI shows a warning and gives `Unrestricted` to the sandbox
///   when the effective mode is proxy on macOS.
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

/// Return the canonical form of `path` as a string, with symlinks resolved.
///
/// SBPL compares the real path, so symlinks like /var -> /private/var must be
/// resolved. Falls back to the original path if canonicalization fails. The
/// result is not escaped; [`push_rule`] quotes it.
fn canonical_or_original(path: &Path) -> String {
    path.canonicalize().map_or_else(
        |_| path.to_string_lossy().into_owned(),
        |p| p.to_string_lossy().into_owned(),
    )
}

/// Add SBPL rules for a glob path (prefix match) using SBPL regex.
///
/// A glob path `~/.claude.json*` (with trailing `*` stripped before calling here)
/// generates a regex rule that matches the path and anything starting with it.
/// See [`glob_prefix_to_regex`] for the translation.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains NUL or a newline.
fn add_sbpl_glob_rule(profile: &mut String, path: &Path, access: &str) -> Result<(), SandboxError> {
    let original = glob_prefix_to_regex(&path.to_string_lossy());
    let canonical = path.canonicalize().map_or_else(
        |_| original.clone(),
        |p| glob_prefix_to_regex(&p.to_string_lossy()),
    );

    push_rule(profile, RuleAction::Allow, access, "regex", &canonical)?;
    if original != canonical {
        push_rule(profile, RuleAction::Allow, access, "regex", &original)?;
    }
    Ok(())
}

/// Add SBPL rules for a path, including both original and canonical if they differ.
///
/// macOS has symlinks like /var -> /private/var. File operations may use either path,
/// so we need to allow both in the SBPL profile.
///
/// # Errors
/// Returns `SandboxError::InvalidConfig` if the path contains NUL or a newline.
fn add_sbpl_path_rule(profile: &mut String, path: &Path, access: &str) -> Result<(), SandboxError> {
    let original = path.to_string_lossy();
    let canonical = canonical_or_original(path);

    // Use literal for files, subpath for directories
    let is_file = path.is_file();
    let modifier = if is_file { "literal" } else { "subpath" };

    // Always add the canonical path
    push_rule(profile, RuleAction::Allow, access, modifier, &canonical)?;

    // If original differs from canonical (symlink), add it too
    if original != canonical {
        push_rule(profile, RuleAction::Allow, access, modifier, &original)?;
    }

    // For executable files, also allow process-exec
    if is_file && is_executable(path) {
        push_rule(
            profile,
            RuleAction::Allow,
            "process-exec",
            "literal",
            &canonical,
        )?;
        if original != canonical {
            push_rule(
                profile,
                RuleAction::Allow,
                "process-exec",
                "literal",
                &original,
            )?;
        }
    }
    Ok(())
}

/// Check if a file is executable
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
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
    // sbpl_string tests
    // ========================================================================

    fn quoted(text: &str) -> String {
        sbpl_string(text).unwrap()
    }

    #[test]
    fn test_sbpl_string_simple() {
        assert_eq!(quoted("/usr/bin"), r#""/usr/bin""#);
    }

    #[test]
    fn test_sbpl_string_with_spaces() {
        // Spaces don't need escaping in SBPL strings
        assert_eq!(
            quoted("/Users/name/My Documents"),
            r#""/Users/name/My Documents""#
        );
    }

    #[test]
    fn test_sbpl_string_with_quotes() {
        assert_eq!(quoted("/path/with\"quotes"), r#""/path/with\"quotes""#);
    }

    #[test]
    fn test_sbpl_string_with_backslash() {
        assert_eq!(
            quoted(r"/path/with\backslash"),
            r#""/path/with\\backslash""#
        );
    }

    #[test]
    fn test_sbpl_string_backslash_before_quote() {
        // A trailing backslash must not escape the closing quote.
        assert_eq!(quoted(r#"/a\"#), r#""/a\\""#);
        assert_eq!(quoted(r#"/a\""#), r#""/a\\\"""#);
    }

    #[test]
    fn test_sbpl_string_keeps_parens_and_semicolons() {
        assert_eq!(quoted("/w/proj (copy);x"), r#""/w/proj (copy);x""#);
    }

    #[test]
    fn test_sbpl_string_rejects_nul_and_newline() {
        assert!(sbpl_string("/a\0b").is_err());
        assert!(sbpl_string("/a\nb").is_err());
    }

    // ========================================================================
    // glob_prefix_to_regex tests
    // ========================================================================

    #[test]
    fn test_glob_regex_escapes_dot() {
        assert_eq!(
            glob_prefix_to_regex("/h/.claude.json"),
            r"^/h/\.claude\.json"
        );
    }

    #[test]
    fn test_glob_regex_escapes_all_metachars() {
        assert_eq!(
            glob_prefix_to_regex(r"/a+b?c(d)e[f]g{h}i^j$k|l\m"),
            r"^/a\+b\?c\(d\)e\[f\]g\{h\}i\^j\$k\|l\\m"
        );
    }

    #[test]
    fn test_glob_regex_translates_stars() {
        assert_eq!(glob_prefix_to_regex("/a/*/b"), "^/a/[^/]*/b");
        assert_eq!(glob_prefix_to_regex("/a/**/b"), "^/a/.*/b");
    }

    #[test]
    fn test_glob_regex_in_sbpl_string_doubles_backslashes() {
        // The SBPL reader turns "\\." back into "\.", which the regex
        // engine reads as a literal dot.
        let regex = glob_prefix_to_regex("/h/.x");
        assert_eq!(quoted(&regex), r#""^/h/\\.x""#);
    }

    // ========================================================================
    // canonical_or_original tests
    // ========================================================================

    #[test]
    fn test_canonical_or_original_resolves_symlink() {
        // On macOS, /var is a symlink to /private/var
        #[cfg(target_os = "macos")]
        {
            let canonical = canonical_or_original(Path::new("/var"));
            assert!(
                canonical.starts_with("/private/var"),
                "Expected /private/var, got {canonical}"
            );
        }
    }

    #[test]
    fn test_canonical_or_original_nonexistent_fallback() {
        // Non-existent paths fall back to the original path
        let canonical = canonical_or_original(Path::new("/nonexistent/path/12345"));
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
        let rules = generate_network_rules(&NetworkMode::ProxyOnly {
            proxy_addr: addr,
            dns_port: 0,
        });
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
            execute: vec![],
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
            execute: vec![],
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
    fn test_sbpl_profile_quotes_path_with_parenthesis() {
        // An injection attempt stays inside one quoted string.
        let evil = "/bad\") (allow file-write* (subpath \"/";
        let paths = SandboxPaths {
            traversal: vec![evil.to_string()],
            read: vec![],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(
            profile.contains(
                r#"(allow file-read-data (literal "/bad\") (allow file-write* (subpath \"/"))"#
            ),
            "injected path must stay quoted: {profile}"
        );
        assert!(!profile.contains("(allow file-write* (subpath \"/\"))"));
    }

    #[test]
    fn test_sbpl_profile_accepts_workspace_with_parens() {
        let ws = "/w/proj (copy)";
        let config = SandboxConfig::new(ws.into(), make_test_paths(), ws.into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(
            profile.contains(r#"(subpath "/w/proj (copy)")"#),
            "{profile}"
        );
    }

    #[test]
    fn test_sbpl_profile_accepts_workspace_with_semicolon() {
        let config = SandboxConfig::new(
            "/bad;workspace".into(),
            make_test_paths(),
            "/bad;workspace".into(),
        );
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains(r#"(subpath "/bad;workspace")"#));
    }

    #[test]
    fn test_sbpl_profile_rejects_newline_in_path() {
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/a\nb".to_string()],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        assert!(generate_sbpl_profile(&config).is_err());
    }

    #[test]
    fn test_sbpl_profile_interior_star_is_literal() {
        // Only a trailing '*' makes a glob. An interior '*' is part of the
        // literal path; it does not widen the rule.
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/path/with/*/wildcard".to_string()],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(profile.contains(r#"(subpath "/path/with/*/wildcard")"#));
    }

    #[test]
    fn test_sbpl_profile_glob_is_escaped() {
        let paths = SandboxPaths {
            traversal: vec![],
            read: vec!["/n/a\"b(c).d*".to_string()],
            execute: vec![],
            read_write: vec![],
        };
        let config = SandboxConfig::new("/workspace".into(), paths, "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        assert!(
            profile.contains(r#"(allow file-read-data (regex "^/n/a\"b\\(c\\)\\.d"))"#),
            "{profile}"
        );
    }

    #[test]
    fn test_sbpl_profile_denies_project_config_writes_last() {
        let config =
            SandboxConfig::new("/workspace".into(), make_test_paths(), "/workspace".into());
        let profile = generate_sbpl_profile(&config).unwrap();
        let deny = r#"(deny file-write* (subpath "/workspace/.pent"))"#;
        let deny_at = profile.find(deny);
        let allow_at = profile.find(r#"(allow file-read-data file-write* (subpath "/workspace"))"#);
        assert!(deny_at.is_some(), "missing .pent deny: {profile}");
        assert!(allow_at.is_some(), "missing workspace allow: {profile}");
        // The last matching rule wins, so the deny must come after every
        // file-write allow.
        let last_allow = profile.rfind("(allow file-read-data file-write*");
        assert!(
            deny_at > last_allow,
            "the .pent deny must come last: {profile}"
        );
    }
}
