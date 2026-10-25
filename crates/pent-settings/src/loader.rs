//! Configuration loading.
//!
//! Pent has one settings file: the global `pent.toml` in the pent config
//! directory (`$XDG_CONFIG_HOME/pent/pent.toml`, default
//! `~/.config/pent/pent.toml`). Pent has no project or local settings file.
//! The paths and the domains are in the profiles (see
//! [`crate::ProfileStore`]).

use crate::{PentConfig, PentDirs, SettingsError};
use std::path::{Path, PathBuf};

/// Loads the global `PentConfig`.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load the global configuration.
    ///
    /// A missing file gives the default configuration. Relative mount paths
    /// resolve against `workspace`.
    ///
    /// # Errors
    /// Returns an error if the global config exists but cannot be parsed.
    pub fn load(workspace: &Path, dirs: Option<&PentDirs>) -> Result<PentConfig, SettingsError> {
        Self::load_from(workspace, Self::global_config_path(dirs).as_deref())
    }

    /// Load with an explicit global config path.
    pub(crate) fn load_from(
        workspace: &Path,
        global_path: Option<&Path>,
    ) -> Result<PentConfig, SettingsError> {
        let mut config = match global_path {
            Some(path) => Self::load_file(path)?.unwrap_or_default(),
            None => PentConfig::default(),
        };
        config.resolve_relative_paths(workspace);
        Ok(config)
    }

    /// Absolute path to the global config file.
    ///
    /// Returns `None` if the pent config directory cannot be determined
    /// (e.g., `$HOME` is unset). Callers should treat `None` as "no global
    /// config" rather than falling back to a relative path.
    /// The caller passes the directories, so that one call to
    /// [`PentDirs::from_env`] serves the whole program and a test can give
    /// its own directories.
    #[must_use]
    pub fn global_config_path(dirs: Option<&PentDirs>) -> Option<PathBuf> {
        dirs.map(PentDirs::global_config)
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
}

/// Read a config file, returning `None` if it is absent or inaccessible.
///
/// IO errors (not-found, permission-denied, EPERM from a sandbox, etc.) are
/// treated as "no config" so that the optional global config never prevents
/// the tool from running in restricted environments.
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
#[allow(clippy::panic)] // a test that cannot set itself up must stop loudly
mod tests {
    use super::*;
    use std::fs;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_load_nothing_returns_default() -> TestResult {
        let dir = tempfile::tempdir()?;
        let config = ConfigLoader::load_from(dir.path(), Some(&dir.path().join("pent.toml")))?;
        assert!(config.sandbox.mounts.is_empty());
        assert!(config.proxy.upstream_dns.is_none());
        Ok(())
    }

    #[test]
    fn test_no_global_path_returns_default() -> TestResult {
        let dir = tempfile::tempdir()?;
        let config = ConfigLoader::load_from(dir.path(), None)?;
        assert!(config.sandbox.mounts.is_empty());
        Ok(())
    }

    #[test]
    fn test_global_config_loaded_and_mounts_resolved() -> TestResult {
        let dir = tempfile::tempdir()?;
        let global = dir.path().join("pent.toml");
        fs::write(
            &global,
            "[proxy]\ndns_ttl_seconds = 7\n[[sandbox.mounts]]\npath = \"mnt\"\n",
        )?;
        let ws = dir.path().join("ws");
        let config = ConfigLoader::load_from(&ws, Some(&global))?;
        assert_eq!(config.proxy.dns_ttl_seconds, Some(7));
        let mount = config.sandbox.mounts.first().ok_or("no mount")?;
        assert_eq!(mount.path, ws.join("mnt"));
        assert!(mount.readonly, "a mount without the key must be read-only");
        Ok(())
    }

    /// [`ConfigLoader::load`] reads the global config file and resolves the
    /// relative mount paths against the workspace.
    ///
    /// With the seam the body reads:
    ///
    /// ```text
    /// let dirs = PentDirs::from_vars(Some(config_home.into()), None, Some(home));
    /// fs::write(dirs.global_config(), "[proxy]\ndns_ttl_seconds = 7\n")?;
    /// let config = ConfigLoader::load(&workspace, dirs.as_ref())?;
    /// assert_eq!(config.proxy.dns_ttl_seconds, Some(7));
    /// ```
    ///
    /// Today `load` finds the file through `PentDirs::from_env`, which
    /// reads the environment of the process. A test cannot change the
    /// environment without a race with the other tests.
    #[test]
    fn test_load_reads_the_global_config_of_the_given_directories() {
        let tmp = match tempfile::tempdir() {
            Ok(t) => t,
            Err(e) => panic!("the test needs a temporary directory: {e}"),
        };
        let config_home = tmp.path().join("config");
        let dirs = PentDirs::from_vars(
            Some(config_home.clone().into()),
            None,
            Some(tmp.path().to_path_buf()),
        );
        let Some(dirs) = dirs else {
            panic!("from_vars must answer for an absolute config directory");
        };
        let global = dirs.global_config();
        if let Some(parent) = global.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                panic!("the test needs the config directory: {e}");
            }
        }
        if let Err(e) = std::fs::write(&global, "[proxy]\ndns_ttl_seconds = 7\n") {
            panic!("the test needs the config file: {e}");
        }
        match ConfigLoader::load(tmp.path(), Some(&dirs)) {
            Ok(config) => assert_eq!(config.proxy.dns_ttl_seconds, Some(7)),
            Err(e) => panic!("the config must load: {e}"),
        }
        // With no directories there is no global config, and the load
        // gives the defaults instead of an error.
        match ConfigLoader::load(tmp.path(), None) {
            Ok(config) => assert_eq!(config.proxy.dns_ttl_seconds, None),
            Err(e) => panic!("a load with no directories must give the defaults: {e}"),
        }
    }

    /// [`ConfigLoader::global_config_path`] names `pent.toml` in the config
    /// directory of the given directories.
    ///
    /// With the seam the body reads:
    ///
    /// ```text
    /// let dirs = PentDirs::from_vars(Some("/c".into()), None, None);
    /// assert_eq!(ConfigLoader::global_config_path(dirs.as_ref()),
    ///            Some(PathBuf::from("/c/pent/pent.toml")));
    /// assert_eq!(ConfigLoader::global_config_path(None), None);
    /// ```
    #[test]
    fn test_global_config_path_names_pent_toml_in_the_config_directory() {
        // Both variables are absolute, so the function needs no home
        // directory.
        let dirs = PentDirs::from_vars(Some("/c".into()), Some("/s".into()), None);
        let Some(dirs) = dirs else {
            panic!("from_vars must answer for an absolute config directory");
        };
        assert_eq!(
            ConfigLoader::global_config_path(Some(&dirs)),
            Some(PathBuf::from("/c/pent/pent.toml"))
        );
        assert_eq!(ConfigLoader::global_config_path(None), None);
    }

    #[test]
    fn test_global_config_path_ends_with_pent_toml() {
        // global_config_path() may be None in environments without $HOME.
        let dirs = PentDirs::from_env();
        if let Some(path) = ConfigLoader::global_config_path(dirs.as_ref()) {
            assert!(path.ends_with("pent/pent.toml"));
        }
    }

    #[test]
    fn test_load_malformed_global_config_returns_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        let global = dir.path().join("pent.toml");
        fs::write(&global, "[proxy]\ndomain_alowlist = []\n")?;
        let err = ConfigLoader::load_from(dir.path(), Some(&global))
            .err()
            .ok_or("expected an error")?;
        let msg = err.to_string();
        assert!(msg.contains("domain_alowlist"), "{msg}");
        assert!(msg.contains("pent.toml"), "{msg}");
        Ok(())
    }

    /// An I/O error that is not "not found" and not "permission denied"
    /// stops the load. A directory in the place of the file gives such an
    /// error.
    #[test]
    fn test_a_config_path_that_is_a_directory_is_an_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pent.toml");
        fs::create_dir(&path)?;
        let result = ConfigLoader::load_file(&path);
        assert!(
            matches!(result, Err(SettingsError::Io(_))),
            "a directory must not read as no config: {result:?}"
        );
        Ok(())
    }

    /// A file that the user cannot read counts as no config, so pent runs
    /// in a restricted environment.
    #[cfg(unix)]
    #[test]
    fn test_a_config_file_that_the_user_cannot_read_gives_no_config() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pent.toml");
        fs::write(&path, "[proxy]\ndns_ttl_seconds = 7\n")?;
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
        if fs::read(&path).is_ok() {
            // The root user reads each file, so the test has no meaning.
            return Ok(());
        }
        let result = ConfigLoader::load_file(&path);
        assert!(matches!(result, Ok(None)), "{result:?}");
        Ok(())
    }

    #[test]
    fn test_load_old_global_config_names_the_new_flow() -> TestResult {
        let dir = tempfile::tempdir()?;
        let global = dir.path().join("pent.toml");
        fs::write(&global, "[proxy]\ndomain_allowlist = [\"a.com\"]\n")?;
        let err = ConfigLoader::load_from(dir.path(), Some(&global))
            .err()
            .ok_or("expected an error")?;
        assert!(err.to_string().contains("pent watch"), "{err}");
        Ok(())
    }
}
