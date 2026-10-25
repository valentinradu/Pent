//! TOML configuration and the profile store of pent.
//!
//! This crate provides:
//! - The global settings `pent.toml` ([`PentConfig`]): the `[proxy]` tunables
//!   and the `[[sandbox.mounts]]`. The file has no paths and no domains.
//! - The profile store ([`ProfileStore`]): the recorded profiles, the drafts,
//!   the raw watch logs, the logs of denied accesses and the trust of each
//!   profile.
//! - The shared sandbox types ([`SandboxPaths`], [`NetworkMode`], [`Mount`]).
//!
//! Pent finds its files with the XDG rules (see [`PentDirs`]):
//! `$XDG_CONFIG_HOME/pent` (default `~/.config/pent`) and
//! `$XDG_STATE_HOME/pent` (default `~/.local/state/pent`).
//!
//! # Example
//!
//! ```no_run
//! use pent_settings::ConfigLoader;
//!
//! let config = ConfigLoader::load(std::path::Path::new(".")).unwrap();
//! println!("{:?}", config.proxy.upstream_dns);
//! ```

mod loader;
mod store;
mod trust;

pub use loader::ConfigLoader;
pub use store::{
    open_log_nofollow, EventLog, LoadedProfile, LogOpen, PentDirs, ProfileEntry, ProfileStatus,
    ProfileStore, StoreError, WatchRunMode,
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

    /// The config file has a key that pent does not use now. The message
    /// tells the user where the setting went.
    #[error("{}: {message}", path.display())]
    MovedKey {
        /// The config file with the old key.
        path: PathBuf,
        /// What changed and what to do.
        message: &'static str,
    },
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
    ///
    /// On Linux, the sandbox ignores both values: the child makes the proxy
    /// listeners on fixed loopback ports in its own network namespace
    /// (`pent_sandbox::child_proxy_addr`).
    ProxyOnly {
        /// The address of the proxy as the child sees it.
        #[serde(skip, default = "default_proxy_addr")]
        proxy_addr: std::net::SocketAddr,
        /// The port of the DNS server of the proxy as the child sees it.
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
/// [`SandboxPaths::resolve_relative`] resolves a relative entry against the
/// workspace.
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
///
/// The section has only the mounts. The paths are in the profiles.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSettings {
    /// Additional mount points.
    #[serde(default)]
    pub mounts: Vec<Mount>,
}

/// The proxy policy for destination addresses that are not public.
///
/// These addresses are loopback, private (RFC 1918), CGNAT, link-local,
/// unique local and multicast addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateDestinations {
    /// The proxy rejects these addresses, also for an allowed domain.
    #[default]
    Deny,
    /// The proxy connects to these addresses for an allowed domain.
    Allow,
}

/// TOML `[proxy]` section: the tunables of the proxy.
///
/// The section has no domains. The domains are in the profiles.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySettings {
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

    /// The policy for destinations that are not public. The default is
    /// `"deny"`. Set `"allow"` when an allowed domain resolves to an
    /// internal address (for example a company registry on `10.x`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_destinations: Option<PrivateDestinations>,
}

/// The keys that older versions of pent used, and where each setting went.
///
/// Each entry is `(table, key, message)`. An empty table is the top level.
const MOVED_KEYS: &[(&str, &str, &str)] = &[
    (
        "",
        "profiles",
        "`profiles` was removed: the @profiles do not exist now; record a profile with `pent watch`",
    ),
    (
        "sandbox",
        "paths",
        "`sandbox.paths` moved to profiles; record one with `pent watch`",
    ),
    (
        "proxy",
        "domain_allowlist",
        "`domain_allowlist` moved to profiles; record one with `pent watch`",
    ),
    (
        "sandbox",
        "network",
        "`sandbox.network` was removed; the profile sets the network mode, \
         and `pent run --network` changes it",
    ),
];

/// Find the first old key in the TOML text.
///
/// Returns `None` when the text has no old key, or when the text is not valid
/// TOML. The typed parse then reports the syntax error.
fn find_moved_key(text: &str) -> Option<&'static str> {
    let table: toml::Table = text.parse().ok()?;
    MOVED_KEYS.iter().find_map(|&(section, key, message)| {
        let scope = if section.is_empty() {
            Some(&table)
        } else {
            table.get(section).and_then(toml::Value::as_table)
        };
        scope
            .is_some_and(|t| t.contains_key(key))
            .then_some(message)
    })
}

/// Top-level pent configuration, corresponding to the global `pent.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PentConfig {
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
    /// Returns `SettingsError::MovedKey` if the TOML has a key of an older
    /// version of pent, and `SettingsError::ParseError` if the TOML is
    /// malformed or contains unrecognised keys for this schema.
    pub fn parse(toml: &str) -> Result<Self, SettingsError> {
        if let Some(message) = find_moved_key(toml) {
            return Err(SettingsError::MovedKey {
                path: PathBuf::from("pent.toml"),
                message,
            });
        }
        toml::from_str(toml).map_err(SettingsError::ParseError)
    }

    /// Parse a `PentConfig` from the bytes of the file at `path`.
    ///
    /// This function does not read `path`. It uses `path` only in the error
    /// message.
    ///
    /// # Errors
    /// Returns `SettingsError::NotUtf8` if the bytes are not UTF-8,
    /// `SettingsError::MovedKey` if the file has a key of an older version of
    /// pent, or `SettingsError::ParseFile` if the TOML is malformed or
    /// contains unrecognised keys.
    pub fn parse_file_contents(path: &Path, contents: &[u8]) -> Result<Self, SettingsError> {
        let text = std::str::from_utf8(contents).map_err(|_| SettingsError::NotUtf8 {
            path: path.to_path_buf(),
        })?;
        if let Some(message) = find_moved_key(text) {
            return Err(SettingsError::MovedKey {
                path: path.to_path_buf(),
                message,
            });
        }
        toml::from_str(text).map_err(|source| SettingsError::ParseFile {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Load a `PentConfig` from a file on disk.
    ///
    /// # Errors
    /// Returns `SettingsError::Io` on read failure, and the errors of
    /// [`PentConfig::parse_file_contents`].
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        let contents = std::fs::read(path)?;
        Self::parse_file_contents(path, &contents)
    }

    /// Expand `~` in mount paths, and resolve relative mount paths against
    /// `base`.
    ///
    /// The loader calls this function with the workspace as `base`. Pent does
    /// not normalize `..`.
    pub fn resolve_relative_paths(&mut self, base: &Path) {
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
        assert!(config.sandbox.mounts.is_empty());
        assert!(config.proxy.upstream_dns.is_none());
    }

    #[test]
    fn test_parse_proxy_tunables() {
        let config = PentConfig::parse(
            "[proxy]\nupstream_dns = [\"1.1.1.1:53\"]\ndns_ttl_seconds = 60\n\
             tcp_connect_timeout_secs = 5\ntcp_idle_timeout_secs = 9\n",
        )
        .unwrap();
        assert_eq!(
            config.proxy.upstream_dns,
            Some(vec!["1.1.1.1:53".to_string()])
        );
        assert_eq!(config.proxy.dns_ttl_seconds, Some(60));
        assert_eq!(config.proxy.tcp_connect_timeout_secs, Some(5));
        assert_eq!(config.proxy.tcp_idle_timeout_secs, Some(9));
    }

    #[test]
    fn test_private_destinations_parse() {
        let global = PentConfig::parse("[proxy]\nprivate_destinations = \"allow\"\n");
        assert!(global.is_ok(), "{global:?}");
        let Ok(global) = global else { return };
        assert_eq!(
            global.proxy.private_destinations,
            Some(PrivateDestinations::Allow)
        );
        assert!(PentConfig::parse("[proxy]\nprivate_destinations = \"maybe\"\n").is_err());
    }

    #[test]
    fn test_old_keys_name_the_new_flow() {
        for (toml, key) in [
            (
                "[proxy]\ndomain_allowlist = [\"a.com\"]\n",
                "`domain_allowlist`",
            ),
            ("[sandbox.paths]\nread = [\"/x\"]\n", "`sandbox.paths`"),
            ("profiles = [\"@npm\"]\n", "`profiles`"),
            (
                "[sandbox.network]\nmode = \"blocked\"\n",
                "`sandbox.network`",
            ),
        ] {
            let err = PentConfig::parse(toml).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(key), "{toml:?}: {msg}");
            assert!(msg.starts_with("pent.toml: "), "{toml:?}: {msg}");
            if key != "`sandbox.network`" {
                assert!(msg.contains("pent watch"), "{toml:?}: {msg}");
            }
        }
    }

    #[test]
    fn test_old_key_error_names_the_file() {
        let err = PentConfig::parse_file_contents(
            Path::new("/x/pent.toml"),
            b"[proxy]\ndomain_allowlist = []\n",
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "/x/pent.toml: `domain_allowlist` moved to profiles; record one with `pent watch`"
        );
    }

    #[test]
    fn test_roundtrip_toml() {
        let toml = "[proxy]\nupstream_dns = [\"8.8.8.8:53\"]\n[[sandbox.mounts]]\npath = \"/m\"\n";
        let config = PentConfig::parse(toml).unwrap();
        let serialized = config.to_toml().unwrap();
        let reparsed = PentConfig::parse(&serialized).unwrap();
        assert_eq!(reparsed.proxy.upstream_dns, config.proxy.upstream_dns);
        assert_eq!(reparsed.sandbox.mounts.len(), 1);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pent.toml");

        let mut config = PentConfig::default();
        config.proxy.dns_ttl_seconds = Some(42);

        config.save(&path).unwrap();

        let loaded = PentConfig::load(&path).unwrap();
        assert_eq!(loaded.proxy.dns_ttl_seconds, Some(42));
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
            ("[proxy]\ndomain_alowlist = []\n", "domain_alowlist"),
            (
                "[[sandbox.mounts]]\npath = \"/x\"\nread_only = true\n",
                "read_only",
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
    fn test_network_mode_repr_rejects_unknown_keys() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[allow(dead_code)] // the test checks only the parse result
            network: NetworkMode,
        }
        for toml in [
            "[network]\nmode = \"blocked\"\nproxy = 1\n",
            "[network]\nmode = \"proxy_only\"\ndns_port = 53\n",
        ] {
            assert!(toml::from_str::<Wrapper>(toml).is_err(), "{toml:?}");
        }
        assert!(toml::from_str::<Wrapper>("[network]\nmode = \"proxy_only\"\n").is_ok());
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
    fn test_resolve_relative() {
        let mut paths = SandboxPaths {
            read_write: ["out", "../up", "/abs", "~/h", "g*"]
                .iter()
                .map(ToString::to_string)
                .collect(),
            ..Default::default()
        };
        paths.resolve_relative(Path::new("/ws"));
        assert_eq!(
            paths.read_write,
            vec!["/ws/out", "/ws/../up", "/abs", "~/h", "/ws/g*"]
        );
    }

    #[test]
    fn test_resolve_relative_mount_paths() {
        let mut config = PentConfig::parse("[[sandbox.mounts]]\npath = \"mnt\"\n").unwrap();
        config.resolve_relative_paths(Path::new("/ws"));
        assert_eq!(config.sandbox.mounts[0].path, PathBuf::from("/ws/mnt"));
    }

    #[test]
    fn test_settings_error_display() {
        let err = PentConfig::parse("invalid toml :::").unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
