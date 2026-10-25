//! Trust store for profiles.
//!
//! A profile gives a program access to files and domains. Pent applies a
//! profile only when the user approved its exact content, as `direnv allow`
//! does. `pent trust NAME` records the approval.
//!
//! The trust store is the file `<pent config dir>/trusted.toml`. Each entry
//! holds the canonical absolute path of an approved profile and the SHA-256
//! digest of its bytes. A change to the file changes the digest, and then
//! pent does not apply the file until the user trusts it again.
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
    #[error("Cannot find the trust store: the home directory is not available")]
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

    /// An I/O operation on the trust store failed.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// The file that pent tried to read or write.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
}

/// The trust state of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// The user approved this exact content.
    Trusted,
    /// The user did not approve this file.
    Untrusted,
    /// The user approved this file, but its content changed after that.
    Changed,
}

/// SHA-256 digest of a trusted file.
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

/// One approved file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustEntry {
    /// Canonical absolute path of the file.
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

/// The set of files (profiles) that the user approved.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    file: TrustFile,
}

impl TrustStore {
    /// Default location of the trust store: `<pent config dir>/trusted.toml`
    /// (see [`crate::PentDirs`]).
    ///
    /// Returns `None` when the pent config directory is not known.
    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        crate::PentDirs::from_env().map(|d| d.config.join(TRUST_FILE_NAME))
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
        write_atomic_private(&self.path, text.as_bytes()).map_err(|source| TrustError::Io {
            path: self.path.clone(),
            source,
        })
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

/// The number of tries for a new temporary file name.
const TMP_TRIES: u32 = 32;

/// Create `dir` and its missing parents with the mode `0700`.
///
/// # Errors
/// Returns the I/O error of `mkdir(2)`.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Write `contents` to `path` through a temporary file and a rename.
///
/// The temporary file is in the same directory, thus the rename is atomic.
/// On Unix the file gets the mode `0600`, and a missing parent directory
/// gets the mode `0700`.
///
/// The temporary file has a name that no other process can guess, and pent
/// opens it with `O_EXCL` and `O_NOFOLLOW`. Thus pent never writes through
/// a symbolic link that another process put at that name.
///
/// # Errors
/// Returns the I/O error of the first step that fails.
pub(crate) fn write_atomic_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the path has no parent directory",
        )
    })?;
    create_private_dir(dir)?;

    let file_name = path
        .file_name()
        .map_or_else(|| TRUST_FILE_NAME.into(), |n| n.to_string_lossy());
    let (tmp, mut file) = create_new_private(dir, &file_name)?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        // The write failed. Remove the temporary file; a failure here is not
        // important, because the original error is the one to report.
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create a new file in `dir` with the mode `0600` and a name that no other
/// process can guess, and return its path and the open file.
///
/// `create_new` gives `O_EXCL`, so the call fails when the name exists.
/// With `O_NOFOLLOW` it also fails when the name is a symbolic link. Pent
/// tries [`TMP_TRIES`] names.
///
/// # Errors
/// Returns the I/O error of `open(2)`.
fn create_new_private(dir: &Path, file_name: &str) -> std::io::Result<(PathBuf, std::fs::File)> {
    create_new_private_from(dir, temp_names(file_name))
}

/// The names that [`create_new_private`] tries, in order.
///
/// The name holds the identifier of the process and a nonce, thus another
/// process cannot guess it.
fn temp_names(file_name: &str) -> impl Iterator<Item = String> + '_ {
    let pid = std::process::id();
    (0..TMP_TRIES).map(move |attempt| format!(".{file_name}.{pid}.{:016x}.tmp", nonce(attempt)))
}

/// Create a new file in `dir` with the mode `0600` and the first free name
/// of `names`, and return its path and the open file.
///
/// The caller gives the source of the names, thus a test can give names that
/// it knows. [`create_new_private`] gives the names of [`temp_names`].
///
/// # Errors
/// Returns the I/O error of `open(2)`. When every name exists, or when
/// `names` is empty, it returns the error `AlreadyExists`.
fn create_new_private_from<I>(dir: &Path, names: I) -> std::io::Result<(PathBuf, std::fs::File)>
where
    I: IntoIterator<Item = String>,
{
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut last = None;
    for name in names {
        let tmp = dir.join(name);
        match options.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            // The name exists, or it is a symbolic link. Try the next name.
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    || e.raw_os_error() == Some(libc::ELOOP) =>
            {
                last = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "no free name for the temporary file",
        )
    }))
}

/// A number for the name of a temporary file. The clock and the number of
/// the try make it different for each call.
fn nonce(attempt: u32) -> u64 {
    nonce_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
        attempt,
    )
}

/// The nonce for the clock value `since_epoch` and the try `attempt`.
///
/// The caller gives the clock value, thus a test can give a series of values
/// and look at the result.
fn nonce_from(since_epoch: std::time::Duration, attempt: u32) -> u64 {
    let seed = u64::from(since_epoch.subsec_nanos()) ^ since_epoch.as_secs().rotate_left(32);
    // A multiplication with an odd constant spreads the bits of the clock.
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(u64::from(attempt))
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

    /// The key of an entry is the path of the file. The approval of one
    /// file must never apply to another file, also when the two files have
    /// the same content.
    #[test]
    fn the_approval_of_one_file_does_not_apply_to_another_file() {
        let dir = tempfile::tempdir().unwrap();
        let approved = dir.path().join("approved.toml");
        let other = dir.path().join("other.toml");
        std::fs::write(&approved, "a").unwrap();
        std::fs::write(&other, "a").unwrap();
        let mut store = TrustStore::empty(dir.path().join("trusted.toml"));
        store.trust(&approved, b"a");
        assert_eq!(store.status(&approved, b"a"), TrustStatus::Trusted);
        assert_eq!(store.status(&other, b"a"), TrustStatus::Untrusted);
        assert!(!store.untrust(&other));
        assert!(store.untrust(&approved));
    }

    /// Only a missing file gives an empty store. Another I/O error is an
    /// error, so a trust store that pent cannot read never looks empty.
    #[test]
    fn a_trust_store_that_pent_cannot_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the path of the store: `read_to_string` gives
        // `IsADirectory`, which is not `NotFound`.
        let store_path = dir.path().join("trusted.toml");
        std::fs::create_dir(&store_path).unwrap();
        assert!(matches!(
            TrustStore::open(store_path),
            Err(TrustError::Io { .. })
        ));
        // A missing file still gives an empty store.
        let missing = dir.path().join("missing.toml");
        let store = TrustStore::open(missing);
        assert!(store.is_ok(), "{store:?}");
    }

    /// The default trust store is `trusted.toml` in the pent config
    /// directory. A wrong path reads the approvals of another file, or
    /// none.
    #[test]
    fn the_default_trust_store_is_in_the_config_directory() {
        let expected = crate::PentDirs::from_env().map(|d| d.config.join("trusted.toml"));
        assert_eq!(TrustStore::default_path(), expected);
        if let Some(path) = expected {
            assert!(path.ends_with("pent/trusted.toml"), "{}", path.display());
        }
    }

    /// The name of the temporary file must not be the same each time: a
    /// name that another process can guess lets that process put a symbolic
    /// link there before pent opens it.
    #[test]
    fn the_name_of_the_temporary_file_changes() {
        let seen: std::collections::HashSet<u64> = (0..1000).map(|_| nonce(0)).collect();
        assert!(
            seen.len() > 1,
            "the nonce of the temporary file is always the same: {seen:?}"
        );
        assert_ne!(nonce(0), nonce(1), "each try must give another name");
    }

    /// The nonce must not repeat, and its low bits must vary. A test cannot
    /// count entropy, but it can check these two properties on a long series
    /// of clock values.
    #[test]
    fn ten_thousand_nonces_hold_no_duplicate_and_the_low_bits_vary() {
        use std::collections::HashSet;
        use std::time::Duration;

        const COUNT: u32 = 10_000;
        const SECS: u64 = 1_700_000_000;
        let values: Vec<u64> = (0..COUNT)
            .map(|nanos| nonce_from(Duration::new(SECS, nanos), 0))
            .collect();

        let unique: HashSet<u64> = values.iter().copied().collect();
        assert_eq!(
            unique.len(),
            values.len(),
            "two clock values give the same nonce"
        );

        let low_bytes: HashSet<u8> = values
            .iter()
            .map(|value| u8::try_from(value & 0xff).unwrap())
            .collect();
        assert_eq!(
            low_bytes.len(),
            256,
            "the low bits of the nonce do not vary: {} values",
            low_bytes.len()
        );

        // The number of the try also changes the nonce.
        let clock = Duration::new(SECS, 7);
        assert_ne!(nonce_from(clock, 0), nonce_from(clock, 1));
    }

    /// The names of the temporary files hold the identifier of the process
    /// and a nonce, and no name repeats.
    #[test]
    fn the_temporary_names_hold_the_process_and_a_nonce() {
        use std::collections::HashSet;

        let names: Vec<String> = temp_names("trusted.toml").collect();
        assert_eq!(names.len(), TMP_TRIES as usize);
        let prefix = format!(".trusted.toml.{}.", std::process::id());
        assert!(
            names
                .iter()
                .all(|n| n.starts_with(&prefix) && n.ends_with(".tmp")),
            "{names:?}"
        );
        let unique: HashSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "{names:?}");
    }

    /// Another process can put a file at the name that pent tries. Pent then
    /// takes the next name, and it does not touch the file of the other
    /// process.
    #[test]
    fn the_next_name_wins_when_the_first_name_exists() {
        let dir = tempfile::tempdir().unwrap();
        let taken = dir.path().join("first.tmp");
        std::fs::write(&taken, "other process").unwrap();

        let names = vec!["first.tmp".to_string(), "second.tmp".to_string()];
        let result = create_new_private_from(dir.path(), names);
        let taken_name = result.as_ref().ok().map(|(path, _)| path.clone());
        assert_eq!(
            taken_name,
            Some(dir.path().join("second.tmp")),
            "{result:?}"
        );
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "other process");
    }

    /// A symbolic link at the name gives `ELOOP`, because pent opens the
    /// file with `O_NOFOLLOW`. Pent takes the next name, and it never writes
    /// through the link. This is the race that the retry stops.
    #[cfg(unix)]
    #[test]
    fn the_next_name_wins_when_the_first_name_is_a_symbolic_link() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("first.tmp")).unwrap();

        let names = vec!["first.tmp".to_string(), "second.tmp".to_string()];
        let result = create_new_private_from(dir.path(), names);
        let taken_name = result.as_ref().ok().map(|(path, _)| path.clone());
        assert_eq!(
            taken_name,
            Some(dir.path().join("second.tmp")),
            "{result:?}"
        );
        if let Ok((_, mut file)) = result {
            assert!(file.write_all(b"new").is_ok());
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    /// With no free name pent reports an error and writes nothing.
    #[test]
    fn no_free_name_gives_an_error() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["first.tmp", "second.tmp"] {
            std::fs::write(dir.path().join(name), "taken").unwrap();
        }
        let names = vec!["first.tmp".to_string(), "second.tmp".to_string()];
        let result = create_new_private_from(dir.path(), names);
        assert_eq!(
            error_kind(&result),
            Some(std::io::ErrorKind::AlreadyExists),
            "{result:?}"
        );
        // An empty source of names gives the same error.
        let result = create_new_private_from(dir.path(), Vec::new());
        assert_eq!(
            error_kind(&result),
            Some(std::io::ErrorKind::AlreadyExists),
            "{result:?}"
        );
    }

    /// An error that is not a name conflict stops the retry: pent reports
    /// the error of the first try and takes no other name.
    ///
    /// The test counts the names, because the kind of the error is the
    /// same after one try and after 32 tries.
    #[test]
    fn an_error_that_is_not_a_name_conflict_stops_the_retry() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");

        let mut tried = 0_u32;
        let names = ["first.tmp", "second.tmp", "third.tmp"]
            .into_iter()
            .map(|name| {
                tried += 1;
                name.to_string()
            });
        let result = create_new_private_from(&missing, names);
        assert_eq!(
            error_kind(&result),
            Some(std::io::ErrorKind::NotFound),
            "{result:?}"
        );
        assert_eq!(tried, 1, "pent must stop after the first name");
    }

    /// A name conflict makes pent take the next name, and only the next
    /// name. The test counts the names that pent takes from the source.
    #[test]
    fn a_name_conflict_takes_one_more_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("first.tmp"), "taken").unwrap();

        let mut tried = 0_u32;
        let names = ["first.tmp", "second.tmp", "third.tmp"]
            .into_iter()
            .map(|name| {
                tried += 1;
                name.to_string()
            });
        let result = create_new_private_from(dir.path(), names);
        let taken_name = result.as_ref().ok().map(|(path, _)| path.clone());
        assert_eq!(
            taken_name,
            Some(dir.path().join("second.tmp")),
            "{result:?}"
        );
        assert_eq!(tried, 2, "pent must stop at the first free name");
    }

    /// The kind of the error of a result, or `None` when it is `Ok`.
    fn error_kind<T>(result: &std::io::Result<T>) -> Option<std::io::ErrorKind> {
        result.as_ref().err().map(std::io::Error::kind)
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
