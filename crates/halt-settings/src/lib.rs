//! Layered TOML configuration for the halt sandbox.
//!
//! Provides structured configuration types for all halt components,
//! loading from:
//! - Global config: `~/.config/halt/halt.toml`
//! - Project config: `<workspace>/.halt/halt.toml`
//!
//! Project values take precedence for scalar fields; list fields are merged.
//!
//! # Example
//!
//! ```no_run
//! use halt_settings::ConfigLoader;
//!
//! let config = ConfigLoader::load(std::path::Path::new(".")).unwrap();
//! println!("{:?}", config.sandbox.network);
//! ```

mod loader;
mod profiles;

pub use loader::ConfigLoader;
pub use profiles::{
    build_profiles_config, is_profile_likely_active, profile_deps_transitive, profile_requires,
    Profile,
};

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors from settings operations.
#[derive(Error, Debug)]
pub enum SettingsError {
    /// TOML deserialization failed.
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    /// TOML serialization failed.
    #[error("Failed to serialize config: {0}")]
    SerializeError(#[from] toml::ser::Error),

    /// I/O error reading or writing a config file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Network isolation mode for sandboxed processes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkMode {
    /// Unrestricted network access.
    Unrestricted,
    /// Only loopback (127.0.0.1 / ::1) is reachable.
    #[default]
    LocalhostOnly,
    /// Route all traffic through a local proxy at the given address.
    ///
    /// `proxy_addr` is assigned at runtime when the proxy server starts;
    /// it is not read from or written to config files.
    ProxyOnly {
        #[serde(skip, default = "default_proxy_addr")]
        proxy_addr: std::net::SocketAddr,
    },
    /// No network access at all.
    Blocked,
}

fn default_proxy_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 0))
}

type ExpandedPath = (PathBuf, bool);
type ExpandedPathLists = (Vec<ExpandedPath>, Vec<ExpandedPath>, Vec<ExpandedPath>, Vec<ExpandedPath>);

/// Filesystem paths made available to the sandboxed process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPaths {
    /// Paths that may be traversed (stat / readdir) but not read or written.
    #[serde(default)]
    pub traversal: Vec<String>,
    /// Paths accessible for reading.
    #[serde(default)]
    pub read: Vec<String>,
    /// Paths accessible for reading and execution (binary directories, installed tools).
    #[serde(default)]
    pub execute: Vec<String>,
    /// Paths accessible for reading and writing.
    #[serde(default)]
    pub read_write: Vec<String>,
}

impl SandboxPaths {
    /// Merge `other` paths on top of `self`, deduplicating all four lists.
    #[must_use]
    pub fn merge(mut self, other: SandboxPaths) -> SandboxPaths {
        self.traversal.extend(other.traversal);
        dedup_preserve_order(&mut self.traversal);
        self.read.extend(other.read);
        dedup_preserve_order(&mut self.read);
        self.execute.extend(other.execute);
        dedup_preserve_order(&mut self.execute);
        self.read_write.extend(other.read_write);
        dedup_preserve_order(&mut self.read_write);
        self
    }

    /// Expand each list into `PathBuf` values.
    ///
    /// Expand paths, resolving `~/` to the user's home directory.
    ///
    /// Returns `(traversal, read, execute, read_write)` where each list contains
    /// `(path, is_glob)` pairs.  A path is a glob when the config entry ends
    /// with `*`; the `*` is stripped from the returned `PathBuf` and callers
    /// should treat the path as a prefix (matching the path and everything
    /// under / starting with it).
    pub fn expand_paths(&self) -> ExpandedPathLists {
        let home = dirs::home_dir();
        let expand = |s: &str| -> ExpandedPath {
            let (s, is_glob) = if let Some(stripped) = s.strip_suffix('*') {
                (stripped, true)
            } else {
                (s, false)
            };
            let path = if let Some(rest) = s.strip_prefix("~/") {
                if let Some(ref h) = home {
                    h.join(rest)
                } else {
                    PathBuf::from(s)
                }
            } else if s == "~" {
                if let Some(ref h) = home {
                    h.clone()
                } else {
                    PathBuf::from(s)
                }
            } else {
                PathBuf::from(s)
            };
            (path, is_glob)
        };
        let to_paths = |v: &Vec<String>| v.iter().map(|s| expand(s)).collect::<Vec<_>>();
        (
            to_paths(&self.traversal),
            to_paths(&self.read),
            to_paths(&self.execute),
            to_paths(&self.read_write),
        )
    }

}

/// An additional mount point exposed inside the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    /// Path to expose.
    pub path: PathBuf,
    /// Whether the path is read-only inside the sandbox.
    #[serde(default)]
    pub readonly: bool,
}

/// TOML `[sandbox]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxSettings {
    /// Network isolation mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMode>,

    /// Filesystem paths made available to the sandbox.
    #[serde(default)]
    pub paths: SandboxPaths,

    /// Additional mount points.
    #[serde(default)]
    pub mounts: Vec<Mount>,
}

/// TOML `[proxy]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxySettings {
    /// Domains allowed through the proxy.
    /// Supports exact matches (`example.com`) and wildcards (`*.github.com`).
    #[serde(default)]
    pub domain_allowlist: Vec<String>,

    /// Upstream DNS servers (e.g. `["8.8.8.8:53"]`).
    /// If absent, system resolvers from `/etc/resolv.conf` are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_dns: Option<Vec<String>>,

    /// DNS response TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ttl_seconds: Option<u32>,

    /// TCP connection timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_connect_timeout_secs: Option<u64>,

    /// TCP idle timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_idle_timeout_secs: Option<u64>,
}

/// Top-level halt configuration, corresponding to `halt.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaltConfig {
    /// Sandbox configuration.
    #[serde(default)]
    pub sandbox: SandboxSettings,

    /// Proxy configuration.
    #[serde(default)]
    pub proxy: ProxySettings,
}

impl HaltConfig {
    /// Parse a `HaltConfig` from a TOML string.
    ///
    /// # Errors
    /// Returns `SettingsError::ParseError` if the TOML is malformed or
    /// contains unrecognised keys for this schema.
    pub fn parse(toml: &str) -> Result<Self, SettingsError> {
        toml::from_str(toml).map_err(SettingsError::ParseError)
    }

    /// Load a `HaltConfig` from a file on disk.
    ///
    /// # Errors
    /// Returns `SettingsError::Io` on read failure, or
    /// `SettingsError::ParseError` if the file content is not valid TOML.
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        let contents = std::fs::read_to_string(path)?;
        Self::parse(&contents)
    }

    /// Serialize this config to a TOML string.
    ///
    /// # Errors
    /// Returns `SettingsError::SerializeError` if serialization fails.
    pub fn to_toml(&self) -> Result<String, SettingsError> {
        toml::to_string_pretty(self).map_err(SettingsError::SerializeError)
    }

    /// Save this config to a file, creating parent directories as needed.
    ///
    /// # Errors
    /// Returns `SettingsError::Io` on write failure, or
    /// `SettingsError::SerializeError` if serialization fails.
    pub fn save(&self, path: &Path) -> Result<(), SettingsError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = self.to_toml()?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Merge `other` (project-level) on top of `self` (global-level).
    ///
    /// - Scalar fields: `other` wins when explicitly set (`Some`).
    /// - List fields (`domain_allowlist`, `paths.*`, `mounts`): extended with
    ///   `other`'s values so both global and project entries contribute.
    #[must_use]
    pub fn merge(mut self, other: HaltConfig) -> HaltConfig {
        // sandbox scalars: project wins if set
        if other.sandbox.network.is_some() {
            self.sandbox.network = other.sandbox.network;
        }
        // sandbox lists: global + project (deduplicated)
        self.sandbox.paths = self.sandbox.paths.merge(other.sandbox.paths);
        self.sandbox.mounts.extend(other.sandbox.mounts);

        // proxy lists: global + project (deduplicated)
        self.proxy
            .domain_allowlist
            .extend(other.proxy.domain_allowlist);
        dedup_preserve_order(&mut self.proxy.domain_allowlist);
        // proxy scalars: project wins if set
        if other.proxy.upstream_dns.is_some() {
            self.proxy.upstream_dns = other.proxy.upstream_dns;
        }
        if other.proxy.dns_ttl_seconds.is_some() {
            self.proxy.dns_ttl_seconds = other.proxy.dns_ttl_seconds;
        }
        if other.proxy.tcp_connect_timeout_secs.is_some() {
            self.proxy.tcp_connect_timeout_secs = other.proxy.tcp_connect_timeout_secs;
        }
        if other.proxy.tcp_idle_timeout_secs.is_some() {
            self.proxy.tcp_idle_timeout_secs = other.proxy.tcp_idle_timeout_secs;
        }
        self
    }
}

/// Remove duplicates from a `Vec<String>` while preserving insertion order.
fn dedup_preserve_order(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let config = HaltConfig::parse("").unwrap();
        assert!(config.sandbox.network.is_none());
        assert!(config.proxy.domain_allowlist.is_empty());
    }

    #[test]
    fn test_parse_proxy_allowlist() {
        let toml = "[proxy]\ndomain_allowlist = [\"example.com\", \"*.github.com\"]";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.proxy.domain_allowlist.len(), 2);
        assert!(config
            .proxy
            .domain_allowlist
            .contains(&"example.com".to_string()));
    }

    #[test]
    fn test_parse_network_localhost_only() {
        let toml = "[sandbox.network]\nmode = \"localhost_only\"";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.sandbox.network, Some(NetworkMode::LocalhostOnly));
    }

    #[test]
    fn test_parse_network_proxy_only() {
        // proxy_addr is a runtime detail — not read from config files.
        let toml = "[sandbox.network]\nmode = \"proxy_only\"";
        let config = HaltConfig::parse(toml).unwrap();
        assert!(
            matches!(config.sandbox.network, Some(NetworkMode::ProxyOnly { .. })),
            "Expected ProxyOnly variant"
        );
    }

    #[test]
    fn test_parse_sandbox_paths() {
        let toml =
            "[sandbox.paths]\ntraversal = [\"/\"]\nread = [\"/usr/lib\"]\nexecute = [\"/usr/bin\"]\nread_write = [\"/tmp\"]";
        let config = HaltConfig::parse(toml).unwrap();
        assert_eq!(config.sandbox.paths.traversal, vec!["/"]);
        assert_eq!(config.sandbox.paths.read, vec!["/usr/lib"]);
        assert_eq!(config.sandbox.paths.execute, vec!["/usr/bin"]);
        assert_eq!(config.sandbox.paths.read_write, vec!["/tmp"]);
    }

    #[test]
    fn test_merge_scalar_project_wins() {
        let global =
            HaltConfig::parse("[sandbox]\nnetwork = { mode = \"localhost_only\" }").unwrap();
        let project = HaltConfig::parse("[sandbox]\nnetwork = { mode = \"blocked\" }").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.sandbox.network, Some(NetworkMode::Blocked));
    }

    #[test]
    fn test_merge_scalar_global_wins_when_project_absent() {
        let global =
            HaltConfig::parse("[sandbox]\nnetwork = { mode = \"localhost_only\" }").unwrap();
        let project = HaltConfig::parse("").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.sandbox.network, Some(NetworkMode::LocalhostOnly));
    }

    #[test]
    fn test_merge_lists_extend() {
        let global = HaltConfig::parse("[proxy]\ndomain_allowlist = [\"example.com\"]").unwrap();
        let project = HaltConfig::parse("[proxy]\ndomain_allowlist = [\"*.github.com\"]").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.proxy.domain_allowlist.len(), 2);
        assert!(merged
            .proxy
            .domain_allowlist
            .contains(&"example.com".to_string()));
        assert!(merged
            .proxy
            .domain_allowlist
            .contains(&"*.github.com".to_string()));
    }

    #[test]
    fn test_roundtrip_toml() {
        let toml = "[proxy]\ndomain_allowlist = [\"example.com\"]\n";
        let config = HaltConfig::parse(toml).unwrap();
        let serialized = config.to_toml().unwrap();
        let reparsed = HaltConfig::parse(&serialized).unwrap();
        assert_eq!(
            reparsed.proxy.domain_allowlist,
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("halt.toml");

        let mut config = HaltConfig::default();
        config.proxy.domain_allowlist = vec!["test.local".to_string()];

        config.save(&path).unwrap();

        let loaded = HaltConfig::load(&path).unwrap();
        assert_eq!(
            loaded.proxy.domain_allowlist,
            vec!["test.local".to_string()]
        );
    }

    #[test]
    fn test_sandbox_paths_merge() {
        let base = SandboxPaths {
            traversal: vec!["/".to_string()],
            read: vec!["/usr/lib".to_string()],
            execute: vec!["/usr/bin".to_string()],
            read_write: vec!["/tmp".to_string()],
        };
        let extra = SandboxPaths {
            traversal: vec![],
            read: vec!["/opt/foo".to_string()],
            execute: vec!["/usr/bin".to_string(), "/usr/local/bin".to_string()],
            read_write: vec!["/tmp".to_string(), "/var".to_string()],
        };
        let merged = base.merge(extra);
        assert_eq!(merged.traversal, vec!["/"]);
        assert_eq!(merged.read, vec!["/usr/lib", "/opt/foo"]);
        // /usr/bin deduplicated
        assert_eq!(merged.execute, vec!["/usr/bin", "/usr/local/bin"]);
        // /tmp deduplicated
        assert_eq!(merged.read_write, vec!["/tmp", "/var"]);
    }

    #[test]
    fn test_sandbox_paths_expand_paths() {
        let paths = SandboxPaths {
            traversal: vec!["/".to_string()],
            read: vec!["/usr/lib".to_string()],
            execute: vec!["/usr/bin".to_string()],
            read_write: vec!["/tmp".to_string()],
        };
        let (traversal, read, execute, read_write) = paths.expand_paths();
        assert_eq!(traversal, vec![(PathBuf::from("/"), false)]);
        assert_eq!(read, vec![(PathBuf::from("/usr/lib"), false)]);
        assert_eq!(execute, vec![(PathBuf::from("/usr/bin"), false)]);
        assert_eq!(read_write, vec![(PathBuf::from("/tmp"), false)]);
    }

    #[test]
    fn test_settings_error_display() {
        let err = HaltConfig::parse("invalid toml :::").unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
