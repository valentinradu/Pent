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
        let project_path = Self::project_config_path(workspace);
        let project = Self::load_file(&project_path)?.unwrap_or_default();

        // Global config is only loaded when a project config file exists.
        // Without a project context the behaviour must match --no-config
        // (defaults only), so that running `pent run -- <cmd>` in an
        // unconfigured directory never silently activates ProxyOnly or other
        // modes the user didn't ask for in that context.
        let global = if project_path.exists() {
            if let Some(path) = Self::global_config_path() {
                Self::load_file(&path)?.unwrap_or_default()
            } else {
                PentConfig::default()
            }
        } else {
            PentConfig::default()
        };

        Ok(global.merge(project))
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
mod tests {
    use super::*;
    use std::fs;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_load_no_project_config_returns_default() -> TestResult {
        let dir = tempfile::tempdir()?;
        // No .pent/pent.toml → load() must return defaults regardless of any
        // global config the developer may have installed on this machine.
        let config = ConfigLoader::load(dir.path())?;
        assert!(config.sandbox.network.is_none());
        assert!(config.proxy.domain_allowlist.is_empty());
        Ok(())
    }

    #[test]
    fn test_load_project_config_only() -> TestResult {
        let dir = tempfile::tempdir()?;
        let pent_dir = dir.path().join(".pent");
        fs::create_dir_all(&pent_dir)?;
        fs::write(
            pent_dir.join("pent.toml"),
            "[proxy]\ndomain_allowlist = [\"example.com\"]\n",
        )?;

        let config = ConfigLoader::load(dir.path())?;
        assert!(
            config.proxy.domain_allowlist.contains(&"example.com".to_string()),
            "project domain_allowlist should be present"
        );
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
    fn test_load_malformed_config_returns_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        let pent_dir = dir.path().join(".pent");
        fs::create_dir_all(&pent_dir)?;
        fs::write(pent_dir.join("pent.toml"), "not valid toml :::")?;

        let result = ConfigLoader::load(dir.path());
        assert!(result.is_err(), "malformed config should return an error");
        Ok(())
    }

    #[test]
    fn test_load_merges_global_and_project() -> TestResult {
        let global_dir = tempfile::tempdir()?;
        let global_config_path = global_dir.path().join("pent.toml");
        std::fs::write(
            &global_config_path,
            "[proxy]\ndomain_allowlist = [\"global.com\"]\n",
        )?;

        let project_dir = tempfile::tempdir()?;
        let pent_dir = project_dir.path().join(".pent");
        fs::create_dir_all(&pent_dir)?;
        fs::write(
            pent_dir.join("pent.toml"),
            "[proxy]\ndomain_allowlist = [\"project.com\"]\n",
        )?;

        // Load global manually then merge with project to test merge logic
        let global = PentConfig::load(&global_config_path)?;
        let project = PentConfig::load(&pent_dir.join("pent.toml"))?;
        let merged = global.merge(project);

        assert!(merged
            .proxy
            .domain_allowlist
            .contains(&"global.com".to_string()));
        assert!(merged
            .proxy
            .domain_allowlist
            .contains(&"project.com".to_string()));
        Ok(())
    }
}
