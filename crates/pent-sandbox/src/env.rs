//! Environment variable filtering for sandboxed processes.
//!
//! Provides safe environment filtering to prevent secrets from leaking
//! into sandboxed processes while preserving necessary system variables.

use std::collections::HashMap;
use std::path::PathBuf;

/// Environment variables that are always safe to pass through.
///
/// These are standard system variables needed for process execution.
const SAFE_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "LANG",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "TMPDIR",
    "TZ",
    "COLORTERM",
    "TERM_PROGRAM",
];

/// Environment variable prefixes that are safe to pass through.
const SAFE_ENV_PREFIXES: &[&str] = &[
    "LC_",  // Locale settings
    "XDG_", // XDG base directories
];

/// Build filtered environment from current env + allowlist.
///
/// Includes:
/// - SAFE_ENV_VARS (PATH, HOME, USER, SHELL, TERM, etc.)
/// - Variables matching SAFE_ENV_PREFIXES (LC_*, XDG_*)
/// - Variables explicitly in the allowlist
///
/// # Arguments
/// * `env_allowlist` - Additional variable names to include
///
/// # Returns
/// HashMap of filtered environment variables
pub fn build_env(env_allowlist: &[String]) -> HashMap<String, String> {
    std::env::vars()
        .filter(|(key, _)| {
            // Include if in SAFE_ENV_VARS
            if SAFE_ENV_VARS.contains(&key.as_str()) {
                return true;
            }
            // Include if starts with SAFE_ENV_PREFIXES
            for prefix in SAFE_ENV_PREFIXES {
                if key.starts_with(prefix) {
                    return true;
                }
            }
            // Include if in allowlist
            env_allowlist.contains(key)
        })
        .collect()
}

/// Resolve PATH directories from a PATH string.
///
/// Parses the given PATH string and returns only directories that actually
/// exist. Used for sandbox path allowlists so that the child's PATH (which
/// may differ from the parent's, e.g. when running under sudo) drives the
/// Landlock ruleset.
///
/// # Arguments
/// * `path_str` - A colon-separated (Unix) or semicolon-separated (Windows) PATH string
///
/// # Returns
/// Vec of existing PATH directories as PathBuf
pub fn resolve_path_dirs_from(path_str: &str) -> Vec<PathBuf> {
    if path_str.is_empty() {
        return Vec::new();
    }

    #[cfg(unix)]
    const PATH_SEP: char = ':';
    #[cfg(windows)]
    const PATH_SEP: char = ';';

    path_str
        .split(PATH_SEP)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.exists() && p.is_dir())
        .collect()
}

/// Resolve PATH directories from the current process's PATH environment variable.
///
/// Convenience wrapper around [`resolve_path_dirs_from`].
pub fn resolve_path_directories() -> Vec<PathBuf> {
    resolve_path_dirs_from(&std::env::var("PATH").unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // ========================================================================
    // SAFE_ENV_VARS / SAFE_ENV_PREFIXES constants
    // ========================================================================

    #[test]
    fn test_safe_env_vars_includes_path() {
        assert!(SAFE_ENV_VARS.contains(&"PATH"));
    }

    #[test]
    fn test_safe_env_vars_includes_home() {
        assert!(SAFE_ENV_VARS.contains(&"HOME"));
    }

    #[test]
    fn test_safe_env_prefixes_includes_lc() {
        assert!(SAFE_ENV_PREFIXES.contains(&"LC_"));
    }

    #[test]
    fn test_safe_env_prefixes_includes_xdg() {
        assert!(SAFE_ENV_PREFIXES.contains(&"XDG_"));
    }

    // ========================================================================
    // build_env tests
    // ========================================================================

    #[test]
    #[serial]
    fn test_build_env_includes_safe_vars() {
        // Set a known safe var
        std::env::set_var("PATH", "/usr/bin");
        let env = build_env(&[]);
        assert!(env.contains_key("PATH"));
    }

    #[test]
    #[serial]
    fn test_build_env_includes_lc_prefix() {
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        let env = build_env(&[]);
        assert!(env.contains_key("LC_ALL"));
    }

    #[test]
    #[serial]
    fn test_build_env_includes_xdg_prefix() {
        std::env::set_var("XDG_CONFIG_HOME", "/home/user/.config");
        let env = build_env(&[]);
        assert!(env.contains_key("XDG_CONFIG_HOME"));
    }

    #[test]
    #[serial]
    fn test_build_env_includes_allowlist() {
        std::env::set_var("ANTHROPIC_API_KEY", "secret123");
        let env = build_env(&["ANTHROPIC_API_KEY".to_string()]);
        assert!(env.contains_key("ANTHROPIC_API_KEY"));
    }

    #[test]
    #[serial]
    fn test_build_env_excludes_non_allowlisted() {
        std::env::set_var("SECRET_TOKEN", "shouldnotpass");
        let env = build_env(&[]);
        assert!(!env.contains_key("SECRET_TOKEN"));
    }

    #[test]
    #[serial]
    fn test_build_env_empty_allowlist() {
        let env = build_env(&[]);
        // Should still have safe vars if they exist
        // PATH typically exists
        if std::env::var("PATH").is_ok() {
            assert!(env.contains_key("PATH"));
        }
    }

    #[test]
    #[serial]
    fn test_build_env_allowlist_nonexistent_var() {
        // Allowlist a var that doesn't exist
        std::env::remove_var("NONEXISTENT_VAR_12345");
        let env = build_env(&["NONEXISTENT_VAR_12345".to_string()]);
        assert!(!env.contains_key("NONEXISTENT_VAR_12345"));
    }

    // ========================================================================
    // resolve_path_directories tests
    // ========================================================================

    #[test]
    fn test_resolve_path_directories_returns_existing() {
        // PATH should contain at least one existing directory
        let dirs = resolve_path_directories();
        // All returned dirs should exist
        for dir in &dirs {
            assert!(dir.exists(), "{:?} should exist", dir);
        }
    }

    #[test]
    #[serial]
    fn test_resolve_path_directories_filters_nonexistent() {
        // Set PATH with a mix of existing and non-existing
        let original = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", "/usr/bin:/nonexistent/path/12345:/bin");

        let dirs = resolve_path_directories();

        // Restore
        std::env::set_var("PATH", original);

        // Should not contain nonexistent path
        assert!(!dirs
            .iter()
            .any(|p| p.to_string_lossy().contains("nonexistent")));
    }

    #[test]
    #[serial]
    fn test_resolve_path_directories_empty_path() {
        let original = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", "");

        let dirs = resolve_path_directories();

        std::env::set_var("PATH", original);

        assert!(dirs.is_empty());
    }
}
