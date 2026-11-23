//! The runtime directory of pent: the socket and the lock of pentd.
//!
//! The directory is `$XDG_RUNTIME_DIR/pent` when the variable names a
//! directory below one of the [`HIDDEN_ROOTS`], else `/tmp/pent-<uid>`. The
//! sandbox covers each hidden root with a private tmpfs, so the program
//! never reaches the socket of pentd. A `XDG_RUNTIME_DIR` in another place
//! (for example `~/.run`) would be visible in the sandbox, and the check of
//! `SO_PEERCRED` does not stop the program: it has the same user ID.
//!
//! The fallback has a fixed name, not `$TMPDIR`: each pent process of the
//! user must find the same pentd.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// The directories that the sandbox covers with a private tmpfs. They are
/// the paths of `PRIVATE_DIRS` in `pent-sandbox`, and a test there checks
/// that the two lists agree.
pub const HIDDEN_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run"];

/// The file name of the socket of pentd.
const PENTD_SOCKET: &str = "pentd.sock";
/// The file name of the lock of pentd.
const PENTD_LOCK: &str = "pentd.lock";

/// An error of the runtime directory.
#[derive(Error, Debug)]
pub enum RuntimeDirError {
    /// Pent cannot create or read the directory.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// The directory.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The directory is a link, belongs to another user, or gives access to
    /// another user.
    #[error(
        "{} is not a private directory of this user (it must be a directory \
         with the mode 0700 that this user owns); if it is yours, run: \
         chmod 700 {}",
        path.display(),
        path.display()
    )]
    NotPrivate {
        /// The directory.
        path: PathBuf,
    },
}

/// The runtime directory of pent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDir {
    path: PathBuf,
}

impl RuntimeDir {
    /// Find the directory from the environment. Pent resolves the links of
    /// `XDG_RUNTIME_DIR` first, so a link below a hidden root that leads to
    /// another place does not count as hidden.
    #[must_use]
    pub fn from_env() -> Self {
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|dir| Path::new(dir).is_absolute())
            .and_then(|dir| std::fs::canonicalize(dir).ok())
            .filter(|dir| dir.is_dir())
            .map(PathBuf::into_os_string);
        Self::from_var(xdg, current_uid())
    }

    /// Find the directory from the given values. A test calls this function
    /// instead of [`RuntimeDir::from_env`].
    ///
    /// Pent uses `xdg_runtime_dir` only when it is absolute, has no `..`
    /// component, and is below one of the [`HIDDEN_ROOTS`].
    #[must_use]
    pub fn from_var(xdg_runtime_dir: Option<OsString>, uid: u32) -> Self {
        let path = match xdg_runtime_dir.map(PathBuf::from) {
            Some(dir) if is_hidden(&dir) => dir.join("pent"),
            _ => PathBuf::from(format!("/tmp/pent-{uid}")),
        };
        Self { path }
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The socket of pentd: `<dir>/pentd.sock`.
    #[must_use]
    pub fn pentd_socket(&self) -> PathBuf {
        self.path.join(PENTD_SOCKET)
    }

    /// The lock of pentd: `<dir>/pentd.lock`.
    #[must_use]
    pub fn pentd_lock(&self) -> PathBuf {
        self.path.join(PENTD_LOCK)
    }

    /// Create the directory with the mode `0700` when it is missing, and
    /// check that it is private.
    ///
    /// # Errors
    /// Returns `RuntimeDirError::Io` when pent cannot create or read the
    /// directory, and `RuntimeDirError::NotPrivate` when the path is a
    /// link, belongs to another user, or gives access to another user.
    pub fn ensure(&self) -> Result<&Path, RuntimeDirError> {
        use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
        let io = |source| RuntimeDirError::Io {
            path: self.path.clone(),
            source,
        };
        match std::fs::DirBuilder::new().mode(0o700).create(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(e)),
        }
        let meta = std::fs::symlink_metadata(&self.path).map_err(io)?;
        if !meta.is_dir() || meta.uid() != current_uid() || meta.mode() & 0o077 != 0 {
            return Err(RuntimeDirError::NotPrivate {
                path: self.path.clone(),
            });
        }
        Ok(&self.path)
    }
}

/// Return true if `dir` is absolute, has no `..` component, and is a
/// hidden root or below one.
fn is_hidden(dir: &Path) -> bool {
    dir.is_absolute()
        && !dir.components().any(|c| c == Component::ParentDir)
        && HIDDEN_ROOTS.iter().any(|root| dir.starts_with(root))
}

/// The user ID of this process.
#[must_use]
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn the_directory_follows_xdg_runtime_dir_or_has_a_fixed_fallback() {
        let d = RuntimeDir::from_var(Some("/run/user/1000".into()), 1000);
        assert_eq!(d.path(), Path::new("/run/user/1000/pent"));
        assert_eq!(
            d.pentd_socket(),
            PathBuf::from("/run/user/1000/pent/pentd.sock")
        );
        assert_eq!(
            d.pentd_lock(),
            PathBuf::from("/run/user/1000/pent/pentd.lock")
        );
        for var in [None, Some("rel".into()), Some(OsString::new())] {
            let d = RuntimeDir::from_var(var, 1000);
            assert_eq!(d.path(), Path::new("/tmp/pent-1000"));
        }
    }

    #[test]
    fn a_runtime_dir_that_the_sandbox_does_not_hide_is_not_used() {
        for visible in ["/home/u/.run", "/run/../home/u", "/runx/user", "/", "/var"] {
            let d = RuntimeDir::from_var(Some(visible.into()), 1000);
            assert_eq!(d.path(), Path::new("/tmp/pent-1000"), "{visible}");
        }
        for hidden in [
            "/run/user/1000",
            "/tmp/rt",
            "/var/tmp/rt",
            "/var/run/user/1",
        ] {
            let d = RuntimeDir::from_var(Some(hidden.into()), 1000);
            assert_eq!(d.path(), Path::new(hidden).join("pent"), "{hidden}");
        }
    }

    #[test]
    fn ensure_makes_a_private_directory_and_refuses_an_open_one() {
        let tmp = tempfile::tempdir_in("/tmp").unwrap();
        let d = RuntimeDir::from_var(Some(tmp.path().into()), current_uid());
        let path = d.ensure().unwrap().to_path_buf();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // A second call accepts the directory.
        assert!(d.ensure().is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = d.ensure().map(Path::to_path_buf);
        assert!(matches!(err, Err(RuntimeDirError::NotPrivate { .. })));
        // The message tells the user how to repair the directory.
        let text = err.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            text.ends_with(&format!("chmod 700 {}", path.display())),
            "{text}"
        );

        // A link at the path is refused, also to a private directory.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let other = tempfile::tempdir_in("/tmp").unwrap();
        let real = other.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, other.path().join("pent")).unwrap();
        let linked = RuntimeDir::from_var(Some(other.path().into()), current_uid());
        assert!(matches!(
            linked.ensure(),
            Err(RuntimeDirError::NotPrivate { .. })
        ));
    }
}
