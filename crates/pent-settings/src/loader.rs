//! Layered configuration loading.
//!
//! Loads and merges configuration from two locations:
//! 1. Global: `~/.config/pent/pent.toml`. Pent always loads it, also when the
//!    workspace has no project config.
//! 2. Project: `<workspace>/.pent/pent.toml`. Pent loads it only when the user
//!    trusts its exact content (see [`TrustStore`]).
//!
//! Project values take precedence for scalar fields; list fields are extended
//! so that both global and project entries contribute. Relative paths in both
//! files resolve against the workspace.

use crate::{PentConfig, SettingsError, TrustStatus, TrustStore};
use std::path::{Path, PathBuf};

/// Loads and merges `PentConfig` from global and project-level files.
pub struct ConfigLoader;

/// The state of the project config after a load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectConfigStatus {
    /// The workspace has no project config.
    Absent,
    /// The user trusts the project config. Pent applies it.
    Trusted,
    /// The user did not trust the project config. Pent does not apply it.
    Untrusted,
    /// The project config changed after the user trusted it. Pent does not
    /// apply it.
    Changed,
}

impl ProjectConfigStatus {
    /// Returns `true` when pent applies the project config.
    #[must_use]
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Trusted)
    }

    /// Returns `true` when a project config exists but pent does not apply it.
    #[must_use]
    pub const fn is_ignored(self) -> bool {
        matches!(self, Self::Untrusted | Self::Changed)
    }
}

impl From<TrustStatus> for ProjectConfigStatus {
    fn from(status: TrustStatus) -> Self {
        match status {
            TrustStatus::Trusted => Self::Trusted,
            TrustStatus::Untrusted => Self::Untrusted,
            TrustStatus::Changed => Self::Changed,
        }
    }
}

/// The result of [`ConfigLoader::load_with_status`].
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The merged configuration that pent applies.
    pub config: PentConfig,
    /// The path of the project config file (it may not exist).
    pub project_path: PathBuf,
    /// The state of the project config.
    pub project_status: ProjectConfigStatus,
}

impl ConfigLoader {
    /// Load the merged configuration for the given workspace.
    ///
    /// Reads the global config (`~/.config/pent/pent.toml`) and, when the user
    /// trusts it, the project config (`<workspace>/.pent/pent.toml`), and
    /// merges them. The global config applies also when the workspace has no
    /// project config. Missing files are silently skipped. An untrusted or
    /// changed project config is skipped; use [`ConfigLoader::load_with_status`]
    /// to find out about it and warn the user.
    ///
    /// # Errors
    /// Returns an error if the global config or a trusted project config
    /// exists but cannot be parsed.
    pub fn load(workspace: &Path) -> Result<PentConfig, SettingsError> {
        Ok(Self::load_with_status(workspace)?.config)
    }

    /// Load the merged configuration and the state of the project config.
    ///
    /// The trust store is `<config dir>/pent/trusted.toml`. When pent cannot
    /// read the trust store, no project config is trusted.
    ///
    /// # Errors
    /// Returns an error if the global config or a trusted project config
    /// exists but cannot be parsed.
    pub fn load_with_status(workspace: &Path) -> Result<LoadedConfig, SettingsError> {
        // A trust store that pent cannot read trusts nothing. Pent then
        // ignores the project config and warns; it does not fail, so that
        // embedders keep working.
        let store = TrustStore::open_default().ok();
        Self::load_from(
            workspace,
            Self::global_config_path().as_deref(),
            store.as_ref(),
        )
    }

    /// Load with an explicit global config path and trust store.
    pub(crate) fn load_from(
        workspace: &Path,
        global_path: Option<&Path>,
        store: Option<&TrustStore>,
    ) -> Result<LoadedConfig, SettingsError> {
        let global = match global_path {
            Some(path) => match read_optional(path)? {
                Some(bytes) => PentConfig::parse_file_contents(path, &bytes)?,
                None => PentConfig::default(),
            },
            None => PentConfig::default(),
        };

        let project_path = Self::project_config_path(workspace);
        // Read the bytes once: pent checks the trust of these bytes and parses
        // the same bytes, thus a change between the two steps has no effect.
        let (project, project_status) = match read_optional(&project_path)? {
            None => (PentConfig::default(), ProjectConfigStatus::Absent),
            Some(bytes) => {
                let status = store.map_or(ProjectConfigStatus::Untrusted, |s| {
                    s.status(&project_path, &bytes).into()
                });
                if status.is_applied() {
                    (
                        PentConfig::parse_file_contents(&project_path, &bytes)?,
                        status,
                    )
                } else {
                    (PentConfig::default(), status)
                }
            }
        };

        let mut config = global.merge(project);
        config.resolve_relative_paths(workspace);
        Ok(LoadedConfig {
            config,
            project_path,
            project_status,
        })
    }

    /// Absolute path to the global config file.
    ///
    /// Returns `None` if the user's config directory cannot be determined
    /// (e.g., `$HOME` is unset). Callers should treat `None` as "no global
    /// config" rather than falling back to a relative path.
    #[must_use]
    pub fn global_config_path() -> Option<PathBuf> {
        Self::global_config_dir().map(|d| d.join("pent.toml"))
    }

    /// Absolute path to the project config file for the given workspace.
    #[must_use]
    pub fn project_config_path(workspace: &Path) -> PathBuf {
        Self::project_config_dir(workspace).join("pent.toml")
    }

    /// Load one config file, returning `None` if it is absent or inaccessible.
    ///
    /// The relative paths in the file do not change.
    ///
    /// # Errors
    /// Returns an error if the file is readable but not a valid config.
    pub fn load_file(path: &Path) -> Result<Option<PentConfig>, SettingsError> {
        read_optional(path)?
            .map(|bytes| PentConfig::parse_file_contents(path, &bytes))
            .transpose()
    }

    fn global_config_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("pent"))
    }

    fn project_config_dir(workspace: &Path) -> PathBuf {
        workspace.join(".pent")
    }
}

/// Read a config file, returning `None` if it is absent or inaccessible.
///
/// IO errors (not-found, permission-denied, EPERM from a sandbox, etc.) are
/// treated as "no config" so that optional config files — in particular the
/// global one — never prevent the tool from running in restricted environments.
///
/// # Errors
/// Returns an error for other I/O errors.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, SettingsError> {
    match std::fs::read(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(None)
        }
        // EPERM (raw os error 1) is not always mapped to PermissionDenied by
        // std on macOS; handle it explicitly so sandboxed environments work.
        Err(ref e) if e.raw_os_error() == Some(1) => Ok(None),
        Err(e) => Err(SettingsError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A workspace, a global config path and a trust store, all in temp dirs.
    struct Fixture {
        workspace: tempfile::TempDir,
        config_dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Result<Self, std::io::Error> {
            Ok(Self {
                workspace: tempfile::tempdir()?,
                config_dir: tempfile::tempdir()?,
            })
        }

        fn global_path(&self) -> PathBuf {
            self.config_dir.path().join("pent.toml")
        }

        fn store_path(&self) -> PathBuf {
            self.config_dir.path().join("trusted.toml")
        }

        fn write_project(&self, contents: &str) -> Result<PathBuf, std::io::Error> {
            let pent_dir = self.workspace.path().join(".pent");
            fs::create_dir_all(&pent_dir)?;
            let path = pent_dir.join("pent.toml");
            fs::write(&path, contents)?;
            Ok(path)
        }

        fn trust_project(&self) -> TestResult {
            let path = ConfigLoader::project_config_path(self.workspace.path());
            let bytes = fs::read(&path)?;
            let mut store = TrustStore::open(self.store_path())?;
            store.trust(&path, &bytes);
            store.save()?;
            Ok(())
        }

        fn load(&self) -> Result<LoadedConfig, Box<dyn std::error::Error>> {
            let store = TrustStore::open(self.store_path())?;
            Ok(ConfigLoader::load_from(
                self.workspace.path(),
                Some(&self.global_path()),
                Some(&store),
            )?)
        }
    }

    #[test]
    fn test_load_nothing_returns_default() -> TestResult {
        let f = Fixture::new()?;
        let loaded = f.load()?;
        assert!(loaded.config.sandbox.network.is_none());
        assert!(loaded.config.proxy.domain_allowlist.is_empty());
        assert_eq!(loaded.project_status, ProjectConfigStatus::Absent);
        Ok(())
    }

    #[test]
    fn test_global_config_loaded_without_project_config() -> TestResult {
        let f = Fixture::new()?;
        fs::write(
            f.global_path(),
            "[proxy]\ndomain_allowlist = [\"global.com\"]\n",
        )?;
        let loaded = f.load()?;
        assert_eq!(loaded.config.proxy.domain_allowlist, vec!["global.com"]);
        assert_eq!(loaded.project_status, ProjectConfigStatus::Absent);
        Ok(())
    }

    #[test]
    fn test_untrusted_project_config_not_applied() -> TestResult {
        let f = Fixture::new()?;
        fs::write(
            f.global_path(),
            "[proxy]\ndomain_allowlist = [\"global.com\"]\n",
        )?;
        f.write_project("[proxy]\ndomain_allowlist = [\"project.com\"]\n")?;
        let loaded = f.load()?;
        assert_eq!(loaded.project_status, ProjectConfigStatus::Untrusted);
        assert_eq!(loaded.config.proxy.domain_allowlist, vec!["global.com"]);
        Ok(())
    }

    #[test]
    fn test_untrusted_malformed_project_config_is_not_parsed() -> TestResult {
        let f = Fixture::new()?;
        f.write_project("not valid toml :::")?;
        let loaded = f.load()?;
        assert_eq!(loaded.project_status, ProjectConfigStatus::Untrusted);
        Ok(())
    }

    #[test]
    fn test_trusted_project_config_applied_and_merged() -> TestResult {
        let f = Fixture::new()?;
        fs::write(
            f.global_path(),
            "[proxy]\ndomain_allowlist = [\"global.com\"]\n",
        )?;
        f.write_project("[proxy]\ndomain_allowlist = [\"project.com\"]\n")?;
        f.trust_project()?;
        let loaded = f.load()?;
        assert_eq!(loaded.project_status, ProjectConfigStatus::Trusted);
        assert_eq!(
            loaded.config.proxy.domain_allowlist,
            vec!["global.com", "project.com"]
        );
        Ok(())
    }

    #[test]
    fn test_edit_invalidates_trust() -> TestResult {
        let f = Fixture::new()?;
        f.write_project("[proxy]\ndomain_allowlist = [\"project.com\"]\n")?;
        f.trust_project()?;
        f.write_project("[proxy]\ndomain_allowlist = [\"evil.com\"]\n")?;
        let loaded = f.load()?;
        assert_eq!(loaded.project_status, ProjectConfigStatus::Changed);
        assert!(loaded.config.proxy.domain_allowlist.is_empty());
        Ok(())
    }

    #[test]
    fn test_no_store_means_untrusted() -> TestResult {
        let f = Fixture::new()?;
        f.write_project("[proxy]\ndomain_allowlist = [\"project.com\"]\n")?;
        let loaded = ConfigLoader::load_from(f.workspace.path(), None, None)?;
        assert_eq!(loaded.project_status, ProjectConfigStatus::Untrusted);
        assert!(loaded.config.proxy.domain_allowlist.is_empty());
        Ok(())
    }

    #[test]
    fn test_relative_project_paths_resolve_against_workspace() -> TestResult {
        let f = Fixture::new()?;
        f.write_project(
            "[sandbox.paths]\nread = [\"data\", \"/abs\", \"~/x\"]\n\
             [[sandbox.mounts]]\npath = \"mnt\"\n",
        )?;
        f.trust_project()?;
        let loaded = f.load()?;
        let ws = f.workspace.path();
        assert_eq!(
            loaded.config.sandbox.paths.read,
            vec![
                ws.join("data").to_string_lossy().into_owned(),
                "/abs".to_string(),
                "~/x".to_string(),
            ]
        );
        let mount = loaded.config.sandbox.mounts.first().ok_or("no mount")?;
        assert_eq!(mount.path, ws.join("mnt"));
        assert!(mount.readonly, "a mount without the key must be read-only");
        Ok(())
    }

    #[test]
    fn test_project_config_path() {
        let path = ConfigLoader::project_config_path(Path::new("/workspace"));
        assert_eq!(path, PathBuf::from("/workspace/.pent/pent.toml"));
    }

    #[test]
    fn test_global_config_path_ends_with_pent_toml() {
        // global_config_path() may be None in environments without $HOME.
        if let Some(path) = ConfigLoader::global_config_path() {
            assert!(path.ends_with("pent.toml"));
            assert!(path.to_string_lossy().contains("pent"));
        }
    }

    #[test]
    fn test_load_trusted_malformed_config_returns_error() -> TestResult {
        let f = Fixture::new()?;
        f.write_project("not valid toml :::")?;
        f.trust_project()?;
        let result = f.load();
        assert!(result.is_err(), "malformed config should return an error");
        Ok(())
    }

    #[test]
    fn test_load_malformed_global_config_returns_error() -> TestResult {
        let f = Fixture::new()?;
        fs::write(f.global_path(), "[proxy]\ndomain_alowlist = []\n")?;
        let err = f.load().err().ok_or("expected an error")?;
        let msg = err.to_string();
        assert!(msg.contains("domain_alowlist"), "{msg}");
        assert!(msg.contains("pent.toml"), "{msg}");
        Ok(())
    }
}
