//! Sandbox configuration types.

use crate::{Mount, NetworkMode, SandboxPaths, SandboxSettings};
use std::collections::HashMap;
use std::path::PathBuf;

/// Platform-appropriate system-wide sandbox path defaults.
///
/// Provides sensible baseline access (system binaries, libraries, temp dirs)
/// that most processes need. Lives here rather than in `halt-settings` because
/// the content is platform-specific knowledge, not config-format knowledge.
pub fn system_default_paths() -> SandboxPaths {
    SandboxPaths {
        traversal: vec!["/".to_string()],
        read: vec![
            "/bin".to_string(),
            "/sbin".to_string(),
            "/usr/bin".to_string(),
            "/usr/sbin".to_string(),
            "/usr/lib".to_string(),
            "/usr/share".to_string(),
            "/etc".to_string(),
            // macOS system libraries and frameworks
            "/Library".to_string(),
            "/System/Library".to_string(),
            "/System/Volumes/Preboot/Cryptexes".to_string(),
            // macOS system databases (Security framework, Keychain, timezone, dyld cache)
            "/private/var/db".to_string(),
            // Homebrew: ARM Macs → /opt/homebrew, Intel → /usr/local (covered by /usr/*)
            "/opt/homebrew".to_string(),
        ],
        read_write: vec![
            "/tmp".to_string(),
            // Device files — processes need /dev/null, /dev/urandom, etc.
            "/dev".to_string(),
            // macOS per-user volatile cache dirs (Keychain/MDS/Security framework)
            "/private/var/folders".to_string(),
        ],
    }
}

/// Configuration for sandboxed process execution.
///
/// Specifies filesystem access, network mode, environment, and working directory.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Workspace directory — always granted read-write access.
    pub workspace: PathBuf,

    /// Sandbox filesystem paths (traversal, read, read_write).
    /// Used by the macOS SBPL profile generator.
    pub paths: SandboxPaths,

    /// Application data directory (e.g. `~/.myapp`) — read-write inside sandbox.
    /// Used by the Linux Landlock ruleset.
    pub data_dir: PathBuf,

    /// Additional mount points exposed inside the sandbox.
    /// Used by the Linux Landlock ruleset.
    pub mounts: Vec<Mount>,

    /// Filtered environment variables to pass to the process.
    pub env: HashMap<String, String>,

    /// Network isolation mode.
    pub network: NetworkMode,

    /// Working directory for the process.
    pub cwd: PathBuf,

}

impl SandboxConfig {
    /// Create a new sandbox config with default network mode (`LocalhostOnly`).
    ///
    /// # Arguments
    /// * `workspace` - Workspace directory (read-write)
    /// * `paths` - Sandbox filesystem paths (macOS SBPL)
    /// * `cwd` - Working directory
    pub fn new(workspace: PathBuf, paths: SandboxPaths, cwd: PathBuf) -> Self {
        Self {
            data_dir: workspace.clone(),
            workspace,
            paths,
            mounts: Vec::new(),
            env: HashMap::new(),
            network: NetworkMode::default(),
            cwd,
        }
    }

    /// Set the environment variables.
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Set the network mode.
    pub fn with_network(mut self, network: NetworkMode) -> Self {
        self.network = network;
        self
    }

    /// Set the application data directory (used by Linux Landlock).
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }

    /// Add an additional mount point (used by Linux Landlock).
    pub fn with_mount(mut self, mount: Mount) -> Self {
        self.mounts.push(mount);
        self
    }

    /// Build a `SandboxConfig` from a `SandboxSettings` fragment, merging
    /// the settings' paths on top of [`system_default_paths()`].
    ///
    /// This is the canonical way to construct a `SandboxConfig` from loaded
    /// config files; it avoids the manual path-extension boilerplate in callers.
    pub fn from_sandbox_settings(
        settings: SandboxSettings,
        workspace: PathBuf,
        cwd: PathBuf,
    ) -> Self {
        let paths = system_default_paths().merge(settings.paths);
        let mut cfg = Self::new(workspace, paths, cwd);
        for mount in settings.mounts {
            cfg.mounts.push(mount);
        }
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_new() {
        let config = SandboxConfig::new(
            PathBuf::from("/workspace"),
            SandboxPaths::default(),
            PathBuf::from("/workspace"),
        );

        assert_eq!(config.workspace, PathBuf::from("/workspace"));
        assert_eq!(config.network, NetworkMode::LocalhostOnly);
    }

    #[test]
    fn test_sandbox_config_builder() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        let paths = SandboxPaths {
            traversal: vec!["/".to_string()],
            read: vec!["/usr/lib".to_string()],
            read_write: vec!["/tmp".to_string()],
        };

        let config = SandboxConfig::new(
            PathBuf::from("/workspace"),
            paths,
            PathBuf::from("/workspace"),
        )
        .with_network(NetworkMode::LocalhostOnly)
        .with_env(env);

        assert_eq!(config.network, NetworkMode::LocalhostOnly);
        assert!(config.env.contains_key("PATH"));
        assert_eq!(config.paths.traversal, vec!["/"]);
    }

    #[test]
    fn test_sandbox_config_with_data_dir() {
        let config = SandboxConfig::new(
            PathBuf::from("/workspace"),
            SandboxPaths::default(),
            PathBuf::from("/workspace"),
        )
        .with_data_dir(PathBuf::from("/home/user/.myapp"));

        assert_eq!(config.data_dir, PathBuf::from("/home/user/.myapp"));
    }

    #[test]
    fn test_sandbox_config_with_mount() {
        let config = SandboxConfig::new(
            PathBuf::from("/workspace"),
            SandboxPaths::default(),
            PathBuf::from("/workspace"),
        )
        .with_mount(Mount {
            path: PathBuf::from("/opt/tools"),
            readonly: true,
        });

        assert_eq!(config.mounts.len(), 1);
        assert_eq!(config.mounts[0].path, PathBuf::from("/opt/tools"));
        assert!(config.mounts[0].readonly);
    }
}
