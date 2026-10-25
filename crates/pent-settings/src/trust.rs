//! Trust store for project config files.
//!
//! A project config (`<workspace>/.pent/pent.toml`) comes with the repository.
//! Thus a person other than the user can write it. Pent applies a project
//! config only when the user approved its exact content, as `direnv allow`
//! does.
//!
//! The trust store is the file `<config dir>/pent/trusted.toml`. Each entry
//! holds the canonical absolute path of an approved project config and the
//! SHA-256 digest of its bytes. A change to the file changes the digest, and
//! then pent does not apply the file until the user trusts it again.
//!
//! Pent writes the trust store atomically (a temporary file and a rename) with
//! the mode `0600`.

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// File name of the trust store in the pent config directory.
const TRUST_FILE_NAME: &str = "trusted.toml";

/// Errors from trust store operations.
#[derive(Error, Debug)]
pub enum TrustError {
    /// The trust store location is not known (for example, `$HOME` is unset).
    #[error("Cannot find the trust store: the user config directory is not available")]
    NoConfigDir,

    /// The trust store file is not valid.
    #[error("Failed to parse the trust store {}: {source}", path.display())]
    Parse {
        /// The trust store file.
        path: PathBuf,
        /// The parse error.
        source: Box<toml::de::Error>,
    },

    /// Serialization of the trust store failed.
    #[error("Failed to serialize the trust store: {0}")]
    Serialize(#[from] toml::ser::Error),

    /// An I/O operation on the trust store or on a config file failed.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// The file that pent tried to read or write.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
}

/// The trust state of a project config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// The user approved this exact content.
    Trusted,
    /// The user did not approve this file.
    Untrusted,
    /// The user approved this file, but its content changed after that.
    Changed,
}

/// SHA-256 digest of a config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigDigest([u8; 32]);

impl ConfigDigest {
    fn of(contents: &[u8]) -> Self {
        Self(Sha256::digest(contents).into())
    }

    fn from_hex(s: &str) -> Option<Self> {
        let (pairs, rest) = s.as_bytes().as_chunks::<2>();
        if pairs.len() != 32 || !rest.is_empty() {
            return None;
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(pairs) {
            let pair = std::str::from_utf8(pair).ok()?;
            *slot = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for ConfigDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ConfigDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ConfigDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s)
            .ok_or_else(|| serde::de::Error::custom("sha256 must be 64 hexadecimal characters"))
    }
}

/// One approved project config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustEntry {
    /// Canonical absolute path of the project config file.
    path: PathBuf,
    /// SHA-256 digest of the approved file content.
    sha256: ConfigDigest,
}

/// On-disk format of the trust store.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    #[serde(default)]
    trusted: Vec<TrustEntry>,
}

/// The set of project config files that the user approved.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    file: TrustFile,
}

impl TrustStore {
    /// Default location of the trust store: `<config dir>/pent/trusted.toml`.
    ///
    /// Returns `None` when the user config directory is not known.
    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("pent").join(TRUST_FILE_NAME))
    }

    /// Open the trust store at the default location.
    ///
    /// # Errors
    /// Returns `TrustError::NoConfigDir` when the location is not known, and
    /// the errors of [`TrustStore::open`].
    pub fn open_default() -> Result<Self, TrustError> {
        Self::open(Self::default_path().ok_or(TrustError::NoConfigDir)?)
    }

    /// Open the trust store at `path`. A missing file gives an empty store.
    ///
    /// # Errors
    /// Returns `TrustError::Io` when the file exists but pent cannot read it,
    /// and `TrustError::Parse` when its content is not valid.
    pub fn open(path: PathBuf) -> Result<Self, TrustError> {
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|source| TrustError::Parse {
                path: path.clone(),
                source: Box::new(source),
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TrustFile::default(),
            Err(source) => return Err(TrustError::Io { path, source }),
        };
        Ok(Self { path, file })
    }

    /// An empty trust store that saves to `path`.
    #[must_use]
    pub fn empty(path: PathBuf) -> Self {
        Self {
            path,
            file: TrustFile::default(),
        }
    }

    /// The file that holds this trust store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The trust state of the config file at `config_path` with `contents`.
    ///
    /// The caller gives the bytes that it read, so that the bytes that pent
    /// checks are the bytes that pent applies.
    #[must_use]
    pub fn status(&self, config_path: &Path, contents: &[u8]) -> TrustStatus {
        let key = canonical_key(config_path);
        match self.file.trusted.iter().find(|e| e.path == key) {
            Some(entry) if entry.sha256 == ConfigDigest::of(contents) => TrustStatus::Trusted,
            Some(_) => TrustStatus::Changed,
            None => TrustStatus::Untrusted,
        }
    }

    /// Record that the user approves `contents` for the file at `config_path`.
    ///
    /// This function changes only the store in memory. Call
    /// [`TrustStore::save`] to write it.
    pub fn trust(&mut self, config_path: &Path, contents: &[u8]) {
        let key = canonical_key(config_path);
        let sha256 = ConfigDigest::of(contents);
        match self.file.trusted.iter_mut().find(|e| e.path == key) {
            Some(entry) => entry.sha256 = sha256,
            None => self.file.trusted.push(TrustEntry { path: key, sha256 }),
        }
    }

    /// Remove the approval for the file at `config_path`.
    ///
    /// Returns `true` when the store had an entry for the file. This function
    /// changes only the store in memory. Call [`TrustStore::save`] to write it.
    pub fn untrust(&mut self, config_path: &Path) -> bool {
        let key = canonical_key(config_path);
        let before = self.file.trusted.len();
        self.file.trusted.retain(|e| e.path != key);
        self.file.trusted.len() != before
    }

    /// Write the trust store atomically, with the mode `0600`.
    ///
    /// # Errors
    /// Returns `TrustError::Serialize` when serialization fails, and
    /// `TrustError::Io` when pent cannot write the file.
    pub fn save(&self) -> Result<(), TrustError> {
        let text = toml::to_string_pretty(&self.file)?;
        write_atomic_private(&self.path, text.as_bytes())
    }
}

/// The key of a config file in the trust store: its canonical absolute path.
///
/// When the file does not exist (for example, after the user deleted it), the
/// key is the path as given. Then `untrust` can still remove the entry when
/// the caller gives the same path.
fn canonical_key(config_path: &Path) -> PathBuf {
    std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf())
}

/// Write `contents` to `path` through a temporary file and a rename.
///
/// The temporary file is in the same directory, thus the rename is atomic. On
/// Unix the file gets the mode `0600` when pent creates it.
fn write_atomic_private(path: &Path, contents: &[u8]) -> Result<(), TrustError> {
    let io_err = |source| TrustError::Io {
        path: path.to_path_buf(),
        source,
    };
    let dir = path.parent().ok_or_else(|| {
        io_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the trust store path has no parent directory",
        ))
    })?;
    std::fs::create_dir_all(dir).map_err(io_err)?;

    let file_name = path
        .file_name()
        .map_or_else(|| TRUST_FILE_NAME.into(), |n| n.to_string_lossy());
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        // The mode in `open` applies only to a new file. Set it again in case
        // an old temporary file with a wider mode exists.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        // The write failed. Remove the temporary file; a failure here is not
        // important, because the original error is the one to report.
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(io_err)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_untrusted_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(dir.path().join("trusted.toml")).unwrap();
        let cfg = dir.path().join("pent.toml");
        std::fs::write(&cfg, "a").unwrap();
        assert_eq!(store.status(&cfg, b"a"), TrustStatus::Untrusted);
    }

    #[test]
    fn test_trust_save_reopen_and_change() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("cfg").join("trusted.toml");
        let cfg = dir.path().join("pent.toml");
        std::fs::write(&cfg, "a").unwrap();

        let mut store = TrustStore::open(store_path.clone()).unwrap();
        store.trust(&cfg, b"a");
        store.save().unwrap();

        let store = TrustStore::open(store_path).unwrap();
        assert_eq!(store.status(&cfg, b"a"), TrustStatus::Trusted);
        assert_eq!(store.status(&cfg, b"b"), TrustStatus::Changed);
    }

    #[test]
    fn test_trust_uses_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let cfg = dir.path().join("pent.toml");
        std::fs::write(&cfg, "a").unwrap();

        let mut store = TrustStore::empty(dir.path().join("trusted.toml"));
        store.trust(&sub.join("..").join("pent.toml"), b"a");
        assert_eq!(store.status(&cfg, b"a"), TrustStatus::Trusted);
    }

    #[test]
    fn test_untrust() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("pent.toml");
        std::fs::write(&cfg, "a").unwrap();
        let mut store = TrustStore::empty(dir.path().join("trusted.toml"));
        store.trust(&cfg, b"a");
        assert!(store.untrust(&cfg));
        assert!(!store.untrust(&cfg));
        assert_eq!(store.status(&cfg, b"a"), TrustStatus::Untrusted);
    }

    #[test]
    fn test_trust_replaces_digest() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("pent.toml");
        std::fs::write(&cfg, "a").unwrap();
        let mut store = TrustStore::empty(dir.path().join("trusted.toml"));
        store.trust(&cfg, b"a");
        store.trust(&cfg, b"b");
        assert_eq!(store.file.trusted.len(), 1);
        assert_eq!(store.status(&cfg, b"b"), TrustStatus::Trusted);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("trusted.toml");
        TrustStore::empty(store_path.clone()).save().unwrap();
        let mode = std::fs::metadata(&store_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_corrupt_store_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("trusted.toml");
        std::fs::write(&store_path, "[[trusted]]\npath = \"/x\"\nsha256 = \"zz\"\n").unwrap();
        assert!(matches!(
            TrustStore::open(store_path),
            Err(TrustError::Parse { .. })
        ));
    }

    #[test]
    fn test_digest_hex_roundtrip() {
        let d = ConfigDigest::of(b"hello");
        let hex = d.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(ConfigDigest::from_hex(&hex), Some(d));
        assert_eq!(ConfigDigest::from_hex("00"), None);
    }
}
