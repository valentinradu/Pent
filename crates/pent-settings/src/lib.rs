//! Layered TOML configuration for the pent sandbox.
//!
//! Provides structured configuration types for all pent components,
//! loading from:
//! - Global config: `~/.config/pent/pent.toml`
//! - Project config: `<workspace>/.pent/pent.toml`
//!
//! The global config always applies. The project config applies only when
//! the user trusts it (see [`TrustStore`]). Project values take precedence for
//! scalar fields; list fields are merged.
//!
//! # Example
//!
//! ```no_run
//! use pent_settings::ConfigLoader;
//!
//! let config = ConfigLoader::load(std::path::Path::new(".")).unwrap();
//! println!("{:?}", config.sandbox.network);
//! ```

mod loader;
mod profiles;
mod trust;

pub use loader::{ConfigLoader, LoadedConfig, ProjectConfigStatus};
pub use profiles::{
    build_profiles_config, is_profile_likely_active, profile_deps_transitive, profile_requires,
    Profile, ProfileParseError,
};
pub use trust::{TrustError, TrustStatus, TrustStore};

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors from settings operations.
#[derive(Error, Debug)]
pub enum SettingsError {
    /// TOML deserialization failed.
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    /// TOML deserialization of a specific config file failed.
    #[error("Failed to parse config file {}: {source}", path.display())]
    ParseFile {
        /// The config file that failed to parse.
        path: PathBuf,
        /// The parse error.
        source: Box<toml::de::Error>,
    },

    /// A config file does not contain valid UTF-8.
    #[error("Config file {} is not valid UTF-8", path.display())]
    NotUtf8 {
        /// The config file with the invalid content.
        path: PathBuf,
    },

    /// TOML serialization failed.
    #[error("Failed to serialize config: {0}")]
    SerializeError(#[from] toml::ser::Error),

    /// I/O error reading or writing a config file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A trust store operation failed.
    #[error(transparent)]
    Trust(#[from] TrustError),
}

/// A `read_write` entry uses a glob, which the Linux backend does not support.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error(
    "read_write path {entry:?} uses a glob ('*') which is not supported \
     on Linux (overlayfs requires exact paths); \
     remove the trailing '*' or use the exact filename"
)]
pub struct RwGlobError {
    /// The `read_write` entry that ends with `*`.
    pub entry: String,
}

/// Network isolation mode for sandboxed processes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
// Deserialization goes through `NetworkModeRepr`: serde ignores unknown keys
// of a unit variant in an internally tagged enum, also with
// `deny_unknown_fields`.
#[serde(tag = "mode", rename_all = "snake_case", from = "NetworkModeRepr")]
pub enum NetworkMode {
    /// Unrestricted network access.
    Unrestricted,
    /// Only loopback (127.0.0.1 / `::1`) is reachable.
    LocalhostOnly,
    /// Route all traffic through a local proxy at the given address.
    ///
    /// `proxy_addr` and `dns_port` are assigned at runtime when the proxy
    /// server starts; they are not read from or written to config files.
    ProxyOnly {
        #[serde(skip, default = "default_proxy_addr")]
        proxy_addr: std::net::SocketAddr,
        /// Port the proxy's DNS server listens on (bound to 0.0.0.0).
        /// Used to set up a PREROUTING REDIRECT rule that transparently
        /// intercepts DNS queries from the child namespace.
        #[serde(skip)]
        dns_port: u16,
    },
    /// No network access at all.
    #[default]
    Blocked,
}

fn default_proxy_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 0))
}

/// The TOML form of [`NetworkMode`]: a table with only the `mode` key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkModeRepr {
    mode: NetworkModeKind,
}

/// The values of the `mode` key.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NetworkModeKind {
    Unrestricted,
    LocalhostOnly,
    ProxyOnly,
    Blocked,
}

impl From<NetworkModeRepr> for NetworkMode {
    fn from(repr: NetworkModeRepr) -> Self {
        match repr.mode {
            NetworkModeKind::Unrestricted => Self::Unrestricted,
            NetworkModeKind::LocalhostOnly => Self::LocalhostOnly,
            NetworkModeKind::ProxyOnly => Self::ProxyOnly {
                proxy_addr: default_proxy_addr(),
                dns_port: 0,
            },
            NetworkModeKind::Blocked => Self::Blocked,
        }
    }
}

type ExpandedPath = (PathBuf, bool);
type ExpandedPathLists = (
    Vec<ExpandedPath>,
    Vec<ExpandedPath>,
    Vec<ExpandedPath>,
    Vec<ExpandedPath>,
);

/// Filesystem paths made available to the sandboxed process.
///
/// Each entry is a string. Pent expands a leading `~` or `~/` to the home
/// directory. Pent does not expand environment variables such as `$HOME`.
/// The loader resolves a relative entry against the workspace (see
/// [`PentConfig::resolve_relative_paths`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub fn merge(mut self, other: Self) -> Self {
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

    /// Validate that no `read_write` entry ends with `*`.
    ///
    /// On Linux, `read_write` paths that name specific files are protected by
    /// overlayfs so that atomic writes (create-temp → rename) preserve the real
    /// file inode that Landlock is bound to. Glob patterns (`~/.claude.json*`)
    /// are not supported for `read_write` because overlayfs requires exact paths.
    ///
    /// # Errors
    ///
    /// Returns [`RwGlobError`] for the first `read_write` entry that ends
    /// with `*`.
    pub fn validate_no_rw_globs(&self) -> Result<(), RwGlobError> {
        match self.read_write.iter().find(|entry| entry.ends_with('*')) {
            Some(entry) => Err(RwGlobError {
                entry: entry.clone(),
            }),
            None => Ok(()),
        }
    }

    /// Resolve each relative entry against `base`.
    ///
    /// An entry that starts with `/` or `~` does not change. Pent does not
    /// normalize `..`, thus an entry such as `../other` names a directory
    /// outside `base`.
    pub fn resolve_relative(&mut self, base: &Path) {
        for list in [
            &mut self.traversal,
            &mut self.read,
            &mut self.execute,
            &mut self.read_write,
        ] {
            for entry in list.iter_mut() {
                if let Some(resolved) = resolve_entry(entry, base) {
                    *entry = resolved;
                }
            }
        }
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
    #[must_use]
    pub fn expand_paths(&self) -> ExpandedPathLists {
        let home = dirs::home_dir();
        let expand = |s: &str| -> ExpandedPath {
            let (s, is_glob) = s
                .strip_suffix('*')
                .map_or((s, false), |stripped| (stripped, true));
            (expand_tilde(Path::new(s), home.as_deref()), is_glob)
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

/// Expand a leading `~` component in `path` to `home`.
///
/// The path does not change when `home` is `None` or when the first component
/// is not `~`.
fn expand_tilde(path: &Path, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return path.to_path_buf();
    };
    match path.strip_prefix("~") {
        Ok(rest) if rest.as_os_str().is_empty() => home.to_path_buf(),
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

/// Resolve one relative config entry against `base`.
///
/// Returns `None` when the entry is empty, absolute, or starts with `~`, or
/// when the result is not valid UTF-8. In these cases the entry stays as it is.
fn resolve_entry(entry: &str, base: &Path) -> Option<String> {
    if entry.is_empty() || entry.starts_with('~') || Path::new(entry).is_absolute() {
        return None;
    }
    base.join(entry).into_os_string().into_string().ok()
}

/// An additional mount point exposed inside the sandbox.
///
/// Only the Linux backend uses mounts. The macOS backend ignores them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    /// Path to expose. Pent expands a leading `~`. The loader resolves a
    /// relative path against the workspace.
    pub path: PathBuf,
    /// Whether the path is read-only inside the sandbox.
    ///
    /// The default is `true`. Set `readonly = false` to give write access.
    #[serde(default = "default_mount_readonly")]
    pub readonly: bool,
}

/// Default value of [`Mount::readonly`]: a mount is read-only unless the
/// config says otherwise.
const fn default_mount_readonly() -> bool {
    true
}

/// TOML `[sandbox]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Top-level pent configuration, corresponding to `pent.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PentConfig {
    /// Profiles that `pent config add` wrote into this file.
    ///
    /// `pent config rm` uses this list to find the entries that other
    /// profiles still need. `pent config rm` never removes an entry that no
    /// listed profile gives, because the user added that entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<Profile>,

    /// Sandbox configuration.
    #[serde(default)]
    pub sandbox: SandboxSettings,

    /// Proxy configuration.
    #[serde(default)]
    pub proxy: ProxySettings,
}

impl PentConfig {
    /// Parse a `PentConfig` from a TOML string.
    ///
    /// # Errors
    /// Returns `SettingsError::ParseError` if the TOML is malformed or
    /// contains unrecognised keys for this schema.
    pub fn parse(toml: &str) -> Result<Self, SettingsError> {
        toml::from_str(toml).map_err(SettingsError::ParseError)
    }

    /// Parse a `PentConfig` from the bytes of the file at `path`.
    ///
    /// This function does not read `path`. It uses `path` only in the error
    /// message.
    ///
    /// # Errors
    /// Returns `SettingsError::NotUtf8` if the bytes are not UTF-8, or
    /// `SettingsError::ParseFile` if the TOML is malformed or contains
    /// unrecognised keys.
    pub fn parse_file_contents(path: &Path, contents: &[u8]) -> Result<Self, SettingsError> {
        let text = std::str::from_utf8(contents).map_err(|_| SettingsError::NotUtf8 {
            path: path.to_path_buf(),
        })?;
        toml::from_str(text).map_err(|source| SettingsError::ParseFile {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Load a `PentConfig` from a file on disk.
    ///
    /// # Errors
    /// Returns `SettingsError::Io` on read failure, `SettingsError::NotUtf8`
    /// if the file is not UTF-8, or `SettingsError::ParseFile` if the file
    /// content is not valid TOML or contains unrecognised keys.
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        let contents = std::fs::read(path)?;
        Self::parse_file_contents(path, &contents)
    }

    /// Resolve relative paths against `base`, and expand `~` in mount paths.
    ///
    /// The loader calls this function with the workspace as `base`. Thus a
    /// relative entry in a config file names a path in the workspace, not a
    /// path in the current directory of the process. Pent does not normalize
    /// `..`, thus an entry such as `../other` names a directory outside the
    /// workspace.
    pub fn resolve_relative_paths(&mut self, base: &Path) {
        self.sandbox.paths.resolve_relative(base);
        let home = dirs::home_dir();
        for mount in &mut self.sandbox.mounts {
            let expanded = expand_tilde(&mount.path, home.as_deref());
            mount.path = if expanded.is_relative() {
                base.join(expanded)
            } else {
                expanded
            };
        }
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
    pub fn merge(mut self, other: Self) -> Self {
        // recorded profiles: union, without duplicates
        for p in other.profiles {
            if !self.profiles.contains(&p) {
                self.profiles.push(p);
            }
        }
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
        let config = PentConfig::parse("").unwrap();
        assert!(config.sandbox.network.is_none());
        assert!(config.proxy.domain_allowlist.is_empty());
    }

    #[test]
    fn test_parse_proxy_allowlist() {
        let toml = "[proxy]\ndomain_allowlist = [\"example.com\", \"*.github.com\"]";
        let config = PentConfig::parse(toml).unwrap();
        assert_eq!(config.proxy.domain_allowlist.len(), 2);
        assert!(config
            .proxy
            .domain_allowlist
            .contains(&"example.com".to_string()));
    }

    #[test]
    fn test_parse_network_localhost_only() {
        let toml = "[sandbox.network]\nmode = \"localhost_only\"";
        let config = PentConfig::parse(toml).unwrap();
        assert_eq!(config.sandbox.network, Some(NetworkMode::LocalhostOnly));
    }

    #[test]
    fn test_parse_network_proxy_only() {
        // proxy_addr is a runtime detail — not read from config files.
        let toml = "[sandbox.network]\nmode = \"proxy_only\"";
        let config = PentConfig::parse(toml).unwrap();
        assert!(
            matches!(config.sandbox.network, Some(NetworkMode::ProxyOnly { .. })),
            "Expected ProxyOnly variant"
        );
    }

    #[test]
    fn test_parse_sandbox_paths() {
        let toml =
            "[sandbox.paths]\ntraversal = [\"/\"]\nread = [\"/usr/lib\"]\nexecute = [\"/usr/bin\"]\nread_write = [\"/tmp\"]";
        let config = PentConfig::parse(toml).unwrap();
        assert_eq!(config.sandbox.paths.traversal, vec!["/"]);
        assert_eq!(config.sandbox.paths.read, vec!["/usr/lib"]);
        assert_eq!(config.sandbox.paths.execute, vec!["/usr/bin"]);
        assert_eq!(config.sandbox.paths.read_write, vec!["/tmp"]);
    }

    #[test]
    fn test_merge_scalar_project_wins() {
        let global =
            PentConfig::parse("[sandbox]\nnetwork = { mode = \"localhost_only\" }").unwrap();
        let project = PentConfig::parse("[sandbox]\nnetwork = { mode = \"blocked\" }").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.sandbox.network, Some(NetworkMode::Blocked));
    }

    #[test]
    fn test_merge_scalar_global_wins_when_project_absent() {
        let global =
            PentConfig::parse("[sandbox]\nnetwork = { mode = \"localhost_only\" }").unwrap();
        let project = PentConfig::parse("").unwrap();
        let merged = global.merge(project);
        assert_eq!(merged.sandbox.network, Some(NetworkMode::LocalhostOnly));
    }

    #[test]
    fn test_merge_lists_extend() {
        let global = PentConfig::parse("[proxy]\ndomain_allowlist = [\"example.com\"]").unwrap();
        let project = PentConfig::parse("[proxy]\ndomain_allowlist = [\"*.github.com\"]").unwrap();
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
        let config = PentConfig::parse(toml).unwrap();
        let serialized = config.to_toml().unwrap();
        let reparsed = PentConfig::parse(&serialized).unwrap();
        assert_eq!(
            reparsed.proxy.domain_allowlist,
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pent.toml");

        let mut config = PentConfig::default();
        config.proxy.domain_allowlist = vec!["test.local".to_string()];

        config.save(&path).unwrap();

        let loaded = PentConfig::load(&path).unwrap();
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
    fn test_unknown_keys_rejected() {
        for (toml, key) in [
            ("typo = 1\n", "typo"),
            ("[sandbox]\nnetwrk = 1\n", "netwrk"),
            ("[sandbox.paths]\nreadwrite = []\n", "readwrite"),
            ("[proxy]\ndomain_alowlist = []\n", "domain_alowlist"),
            (
                "[[sandbox.mounts]]\npath = \"/x\"\nread_only = true\n",
                "read_only",
            ),
            (
                "[sandbox.network]\nmode = \"blocked\"\nproxy = 1\n",
                "proxy",
            ),
            (
                "[sandbox.network]\nmode = \"proxy_only\"\ndns_port = 53\n",
                "dns_port",
            ),
        ] {
            let result = PentConfig::parse(toml);
            assert!(result.is_err(), "{toml:?} must be rejected");
            if let Err(err) = result {
                assert!(err.to_string().contains(key), "{toml:?}: {err}");
            }
        }
    }

    #[test]
    fn test_parse_file_contents_names_the_file() {
        let err = PentConfig::parse_file_contents(Path::new("/x/pent.toml"), b"[proxy]\nfoo = 1\n")
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/x/pent.toml"), "{msg}");
        assert!(msg.contains("foo"), "{msg}");
    }

    #[test]
    fn test_mount_readonly_default_true() {
        let config =
            PentConfig::parse("[[sandbox.mounts]]\npath = \"/a\"\n[[sandbox.mounts]]\npath = \"/b\"\nreadonly = false\n")
                .unwrap();
        assert!(config.sandbox.mounts[0].readonly);
        assert!(!config.sandbox.mounts[1].readonly);
    }

    #[test]
    fn test_validate_no_rw_globs() {
        let ok = SandboxPaths {
            read_write: vec!["~/.claude.json".to_string()],
            ..Default::default()
        };
        assert!(ok.validate_no_rw_globs().is_ok());
        let bad = SandboxPaths {
            read_write: vec!["~/.claude.json*".to_string()],
            ..Default::default()
        };
        let err = bad.validate_no_rw_globs().unwrap_err();
        assert_eq!(err.entry, "~/.claude.json*");
        assert!(err.to_string().contains("glob"));
    }

    #[test]
    fn test_expand_tilde() {
        let home = Path::new("/home/u");
        assert_eq!(expand_tilde(Path::new("~"), Some(home)), home);
        assert_eq!(
            expand_tilde(Path::new("~/a/b"), Some(home)),
            PathBuf::from("/home/u/a/b")
        );
        assert_eq!(
            expand_tilde(Path::new("~other/a"), Some(home)),
            PathBuf::from("~other/a")
        );
        assert_eq!(
            expand_tilde(Path::new("/a"), Some(home)),
            PathBuf::from("/a")
        );
        assert_eq!(expand_tilde(Path::new("~/a"), None), PathBuf::from("~/a"));
    }

    #[test]
    fn test_resolve_relative_paths() {
        let mut config = PentConfig::parse(
            "[sandbox.paths]\nread_write = [\"out\", \"../up\", \"/abs\", \"~/h\", \"g*\"]\n",
        )
        .unwrap();
        config.resolve_relative_paths(Path::new("/ws"));
        assert_eq!(
            config.sandbox.paths.read_write,
            vec!["/ws/out", "/ws/../up", "/abs", "~/h", "/ws/g*"]
        );
    }

    #[test]
    fn test_settings_error_display() {
        let err = PentConfig::parse("invalid toml :::").unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
