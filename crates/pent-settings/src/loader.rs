//! Layered configuration loading.
//!
//! Loads and merges configuration from two locations:
//! 1. Global: `~/.config/pent/pent.toml`
//! 2. Project: `<workspace>/.pent/pent.toml`
//!
//! Project values take precedence for scalar fields; list fields are extended
//! so that both global and project entries contribute.

use crate::{PentConfig, SettingsError};
use std::path::{Path, PathBuf};

/// Loads and merges `PentConfig` from global and project-level files.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load the merged configuration for the given workspace.
    ///
    /// Reads the global config (`~/.config/pent/pent.toml`), then the project
    /// config (`<workspace>/.pent/pent.toml`), and merges them. Missing files
    /// are silently skipped. Parse errors are returned as errors.
    ///
    /// # Errors
    /// Returns an error if a config file exists but cannot be parsed.
    pub fn load(workspace: &Path) -> Result<PentConfig, SettingsError> {
        let global = if let Some(path) = Self::global_config_path() {
            Self::load_file(&path)?.unwrap_or_default()
        } else {
            PentConfig::default()
        };
        let project = Self::load_file(&Self::project_config_path(workspace))?.unwrap_or_default();
        Ok(global.merge(project))
    }

    /// Absolute path to the global config file.
    ///
    /// Returns `None` if the user's config directory cannot be determined
    /// (e.g., `$HOME` is unset). Callers should treat `None` as "no global
    /// config" rather than falling back to a relative path.
    pub fn global_config_path() -> Option<PathBuf> {
        Self::global_config_dir().map(|d| d.join("pent.toml"))
    }

    /// Absolute path to the project config file for the given workspace.
    pub fn project_config_path(workspace: &Path) -> PathBuf {
        Self::project_config_dir(workspace).join("pent.toml")
    }

    fn global_config_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("pent"))
    }

    fn project_config_dir(workspace: &Path) -> PathBuf {
        workspace.join(".pent")
    }

    /// Load a config file, returning `None` if it is absent or inaccessible.
    ///
    /// IO errors (not-found, permission-denied, EPERM from a sandbox, etc.) are
    /// treated as "no config" so that optional config files — in particular the
    /// global one — never prevent the tool from running in restricted environments.
    ///
    /// # Errors
    /// Returns an error only if the file is readable but contains invalid TOML.
    fn load_file(path: &Path) -> Result<Option<PentConfig>, SettingsError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => PentConfig::parse(&contents).map(Some),
            Err(e) if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) => Ok(None),
            // EPERM (raw os error 1) is not always mapped to PermissionDenied by
            // std on macOS; handle it explicitly so sandboxed environments work.
            Err(ref e) if e.raw_os_error() == Some(1) => Ok(None),
            Err(e) => Err(SettingsError::Io(e)),
        }
    }
}

#[cfg(test)]
impl ConfigLoader {
    /// Load only the project-level config, skipping the global file.
    ///
    /// Used in unit tests to avoid pollution from the developer's real global
    /// pent.toml (`~/Library/Application Support/pent/pent.toml`).
    fn load_project_only(workspace: &Path) -> Result<PentConfig, SettingsError> {
        Ok(Self::load_file(&Self::project_config_path(workspace))?.unwrap_or_default())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_missing_workspace_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        // Use load_project_only to avoid pollution from the real global config.
        let config = ConfigLoader::load_project_only(dir.path()).unwrap();
        assert!(config.sandbox.network.is_none());
        assert!(config.proxy.domain_allowlist.is_empty());
    }

    #[test]
    fn test_load_project_config_only() {
        let dir = tempfile::tempdir().unwrap();
        let pent_dir = dir.path().join(".pent");
        fs::create_dir_all(&pent_dir).unwrap();
        fs::write(
            pent_dir.join("pent.toml"),
            "[proxy]\ndomain_allowlist = [\"example.com\"]\n",
        )
        .unwrap();

        // Use load_project_only to avoid pollution from the real global config.
        let config = ConfigLoader::load_project_only(dir.path()).unwrap();
        assert_eq!(
            config.proxy.domain_allowlist,
            vec!["example.com".to_string()]
        );
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
    fn test_load_malformed_config_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let pent_dir = dir.path().join(".pent");
        fs::create_dir_all(&pent_dir).unwrap();
        fs::write(pent_dir.join("pent.toml"), "not valid toml :::").unwrap();

        let result = ConfigLoader::load(dir.path());
        assert!(result.is_err(), "malformed config should return an error");
    }

    #[test]
    fn test_load_merges_global_and_project() {
        let global_dir = tempfile::tempdir().unwrap();
        let global_config_path = global_dir.path().join("pent.toml");
        std::fs::write(
            &global_config_path,
            "[proxy]\ndomain_allowlist = [\"global.com\"]\n",
        )
        .unwrap();

        let project_dir = tempfile::tempdir().unwrap();
        let pent_dir = project_dir.path().join(".pent");
        fs::create_dir_all(&pent_dir).unwrap();
        fs::write(
            pent_dir.join("pent.toml"),
            "[proxy]\ndomain_allowlist = [\"project.com\"]\n",
        )
        .unwrap();

        // Load global manually then merge with project to test merge logic
        let global = PentConfig::load(&global_config_path).unwrap();
        let project = PentConfig::load(&pent_dir.join("pent.toml")).unwrap();
        let merged = global.merge(project);

        assert!(merged
            .proxy
            .domain_allowlist
            .contains(&"global.com".to_string()));
        assert!(merged
            .proxy
            .domain_allowlist
            .contains(&"project.com".to_string()));
    }
}
