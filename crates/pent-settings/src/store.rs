//! The profile store.
//!
//! The store keeps these files (see `docs/design/watch.md`):
//!
//! | Path | Content |
//! |---|---|
//! | `<config>/profiles/<name>.toml` | A trusted profile. |
//! | `<config>/trusted.toml` | The trust store (path and SHA-256 of each trusted profile). |
//! | `<state>/drafts/<name>.toml` | The draft that `pent watch` writes. |
//! | `<state>/watch/<name>/<run>.jsonl` | The raw events of one watch run. |
//! | `<state>/denied/<name>.jsonl` | The accesses that `pent run` denied. |
//! | `<state>/rules/<key>.toml` | The rules of one program (see `docs/design/pent.md`). |
//!
//! `<config>` is `$XDG_CONFIG_HOME/pent` (default `~/.config/pent`) and
//! `<state>` is `$XDG_STATE_HOME/pent` (default `~/.local/state/pent`).
//!
//! Pent writes profiles, drafts, rules and the trust store atomically, with
//! the mode `0600`. The directories get the mode `0700` when pent creates them.

use std::ffi::OsString;
use std::fmt;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};

use pent_profile::{
    DocError, ProfileDoc, ProfileName, RuleFileError, RuleKey, RuleSet, Target, WatchEvent,
};
use thiserror::Error;

use crate::trust::write_atomic_private;
use crate::{TrustError, TrustStatus, TrustStore};

/// File name of the trust store in the pent config directory.
const TRUST_FILE: &str = "trusted.toml";
/// File extension of the event logs.
const LOG_EXTENSION: &str = "jsonl";
/// File extension of the rule files.
const RULES_EXTENSION: &str = "toml";
/// The largest rule file that pent reads: about 25,000 rules.
const MAX_RULES_LEN: u64 = 4 * 1024 * 1024;

/// Errors from profile store operations.
#[derive(Error, Debug)]
pub enum StoreError {
    /// The location of the store is not known (`$HOME` is not set).
    #[error("Cannot find the pent directories: the home directory is not available")]
    NoHome,

    /// An I/O operation on a file of the store failed.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },

    /// A trust store operation failed.
    #[error(transparent)]
    Trust(#[from] TrustError),

    /// A profile or a draft is not valid.
    #[error("{}: {source}", path.display())]
    Doc {
        /// The profile or draft file.
        path: PathBuf,
        /// The parse error.
        source: DocError,
    },

    /// A file of the store is not valid UTF-8.
    #[error("{} is not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },

    /// A rule file is not valid, or pent cannot encode the rules.
    #[error("{}: {source}", path.display())]
    Rules {
        /// The rule file.
        path: PathBuf,
        /// The problem. It is in a box because a TOML error is large.
        source: Box<RuleFileError>,
    },

    /// A rule file is a symbolic link, a directory or a special file. Pent
    /// does not follow a link: the rules decide what a program can do, so
    /// they must be the file in the store. A FIFO would block the read.
    #[error("{} is not a regular file; pent reads only a regular file here", path.display())]
    NotRegular {
        /// The file.
        path: PathBuf,
    },

    /// A rule file is larger than the limit.
    #[error("{} has more than {max_len} bytes", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
        /// The limit in bytes.
        max_len: u64,
    },

    /// Pent cannot encode an event as JSON.
    #[error("Cannot encode an event: {0}")]
    Encode(#[from] serde_json::Error),

    /// The profile has no draft and no profile file, so there is nothing to
    /// trust.
    #[error("no draft and no profile for \"{0}\"")]
    NothingToTrust(ProfileName),

    /// Another `pent watch` of the same profile runs now. Two runs would
    /// delete and read each other's logs and write the same draft.
    #[error(
        "another pent watch of \"{name}\" runs now{}; wait until it ends, \
         or record under another name with --profile",
        pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
    )]
    WatchBusy {
        /// The profile.
        name: ProfileName,
        /// The process that holds the lock, when the lock file names it.
        pid: Option<u32>,
    },
}

/// The lock on the watch runs of one profile. See
/// [`ProfileStore::lock_watch`].
///
/// The lock ends when the value drops, and the kernel ends it when the
/// process ends, also after a crash.
#[derive(Debug)]
pub struct WatchLock {
    _file: std::fs::File,
}

/// The pent directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PentDirs {
    /// The config directory: `$XDG_CONFIG_HOME/pent`, default
    /// `~/.config/pent`.
    pub config: PathBuf,
    /// The state directory: `$XDG_STATE_HOME/pent`, default
    /// `~/.local/state/pent`.
    pub state: PathBuf,
}

impl PentDirs {
    /// Find the pent directories from the environment.
    ///
    /// Returns `None` when an XDG variable is not set and the home directory
    /// is not known.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_vars(
            std::env::var_os("XDG_CONFIG_HOME"),
            std::env::var_os("XDG_STATE_HOME"),
            dirs::home_dir(),
        )
    }

    /// Find the pent directories from the given values.
    ///
    /// A test calls this function instead of [`PentDirs::from_env`]: the
    /// environment belongs to the whole process, so a test that changes it
    /// races the other tests.
    ///
    /// The XDG Base Directory specification tells programs to ignore a value
    /// that is empty or not absolute. Pent does the same.
    pub fn from_vars(
        xdg_config: Option<OsString>,
        xdg_state: Option<OsString>,
        home: Option<PathBuf>,
    ) -> Option<Self> {
        let pick = |var: Option<OsString>, default: &str| -> Option<PathBuf> {
            match var.map(PathBuf::from) {
                Some(path) if path.is_absolute() => Some(path),
                _ => home.as_ref().map(|h| h.join(default)),
            }
        };
        Some(Self {
            config: pick(xdg_config, ".config")?.join("pent"),
            state: pick(xdg_state, ".local/state")?.join("pent"),
        })
    }

    /// The global settings file: `<config>/pent.toml`.
    #[must_use]
    pub fn global_config(&self) -> PathBuf {
        self.config.join("pent.toml")
    }

    /// The trust store: `<config>/trusted.toml`.
    #[must_use]
    pub fn trust_store(&self) -> PathBuf {
        self.config.join(TRUST_FILE)
    }

    /// The directory of the rule files: `<state>/rules`.
    #[must_use]
    pub fn rules_dir(&self) -> PathBuf {
        self.state.join("rules")
    }
}

/// The trust state of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileStatus {
    /// The user trusts the profile. Pent applies it.
    Trusted,
    /// The profile file exists, but the user did not trust it.
    NotTrusted,
    /// The profile changed after the user trusted it. Pent does not apply it.
    Changed,
    /// Only a draft exists. Pent does not apply a draft.
    DraftOnly,
    /// No profile and no draft exist.
    Missing,
}

impl fmt::Display for ProfileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Trusted => "trusted",
            Self::NotTrusted => "not trusted",
            Self::Changed => "changed after trust",
            Self::DraftOnly => "draft only",
            Self::Missing => "missing",
        })
    }
}

/// The result of [`ProfileStore::load`].
#[derive(Debug, Clone)]
pub struct LoadedProfile {
    /// The trust state.
    pub status: ProfileStatus,
    /// The profile file (it may not exist).
    pub path: PathBuf,
    /// The profile. Pent parses the profile only when the user trusts it,
    /// thus this is `Some` only for [`ProfileStatus::Trusted`].
    pub doc: Option<ProfileDoc>,
    /// True when a draft exists.
    pub has_draft: bool,
}

/// One line of [`ProfileStore::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEntry {
    /// The profile name.
    pub name: ProfileName,
    /// The trust state of the profile file.
    pub status: ProfileStatus,
    /// True when a draft exists.
    pub has_draft: bool,
}

/// What [`ProfileStore::start_watch_run`] does with the logs of earlier runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchRunMode {
    /// Keep the logs of earlier runs (`pent watch --append`).
    Append,
    /// Delete the logs of earlier runs. The new run starts a new draft.
    Replace,
}

/// An event log file that pent appends JSON lines to.
#[derive(Debug)]
pub struct EventLog {
    path: PathBuf,
    file: std::fs::File,
}

impl EventLog {
    /// Open `path` for append. Create the file (mode `0600`) and its parent
    /// directories (mode `0700`) when they do not exist.
    ///
    /// The open uses `O_NOFOLLOW`, so a symbolic link at the path of the log
    /// makes the call fail. Pent never appends to the target of such a link.
    fn open_append(path: PathBuf) -> Result<Self, StoreError> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        match open_log_nofollow(&path, LogOpen::Append) {
            Ok(file) => Ok(Self { path, file }),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    /// The path of the log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event as one JSON line.
    ///
    /// Each line goes to the file in one write call, so lines from two pent
    /// processes do not mix.
    ///
    /// # Errors
    /// Returns `StoreError::Encode` if the event cannot be encoded, and
    /// `StoreError::Io` if the write fails.
    pub fn append(&mut self, event: &WatchEvent) -> Result<(), StoreError> {
        let mut line = event.to_json_line()?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|source| StoreError::Io {
                path: self.path.clone(),
                source,
            })
    }
}

/// The profiles, the drafts, the event logs and their trust.
#[derive(Debug, Clone)]
pub struct ProfileStore {
    dirs: PentDirs,
}

impl ProfileStore {
    /// Open the store at the default location (see [`PentDirs::from_env`]).
    ///
    /// # Errors
    /// Returns `StoreError::NoHome` when the location is not known.
    pub fn open_default() -> Result<Self, StoreError> {
        PentDirs::from_env()
            .map(Self::new)
            .ok_or(StoreError::NoHome)
    }

    /// Open the store in the given directories.
    #[must_use]
    pub const fn new(dirs: PentDirs) -> Self {
        Self { dirs }
    }

    /// The directories of the store.
    #[must_use]
    pub const fn dirs(&self) -> &PentDirs {
        &self.dirs
    }

    /// The path of the trusted profile `name`.
    #[must_use]
    pub fn profile_path(&self, name: &ProfileName) -> PathBuf {
        self.dirs.config.join("profiles").join(name.file_name())
    }

    /// The path of the draft of `name`.
    #[must_use]
    pub fn draft_path(&self, name: &ProfileName) -> PathBuf {
        self.dirs.state.join("drafts").join(name.file_name())
    }

    /// The directory of the raw watch logs of `name`.
    #[must_use]
    pub fn watch_dir(&self, name: &ProfileName) -> PathBuf {
        self.dirs.state.join("watch").join(name.as_str())
    }

    /// The lock file of the watch runs of `name`, next to the directory of
    /// the logs. `pent profile rm` deletes that directory, so the lock file
    /// is outside it.
    #[must_use]
    pub fn watch_lock_path(&self, name: &ProfileName) -> PathBuf {
        self.dirs
            .state
            .join("watch")
            .join(format!("{}.lock", name.as_str()))
    }

    /// Take the lock on the watch runs of `name`. Hold it for the whole run,
    /// until the draft is written.
    ///
    /// A run without `--append` deletes the logs of the earlier runs, and
    /// each run reads all logs and writes the draft at its end. Two runs of
    /// one profile at the same time would thus delete and read each other's
    /// logs. The lock does not wait: a second run stops at once.
    ///
    /// The lock file holds the PID of the run that holds the lock, for the
    /// message of a second run. The open uses `O_NOFOLLOW`.
    ///
    /// # Errors
    /// Returns [`StoreError::WatchBusy`] when another run holds the lock,
    /// and `StoreError::Io` when the lock file cannot be opened or written.
    pub fn lock_watch(&self, name: &ProfileName) -> Result<WatchLock, StoreError> {
        use std::io::{Read as _, Seek as _};
        let path = self.watch_lock_path(name);
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let io = |source| StoreError::Io {
            path: path.clone(),
            source,
        };
        let mut options = std::fs::OpenOptions::new();
        // No truncation before the lock: the file names the holder.
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path).map_err(io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut text = String::new();
                // The PID is only for the message; an unreadable file gives
                // the message without it.
                let pid = file
                    .read_to_string(&mut text)
                    .ok()
                    .and_then(|_| text.trim().parse().ok());
                return Err(StoreError::WatchBusy {
                    name: name.clone(),
                    pid,
                });
            }
            Err(std::fs::TryLockError::Error(source)) => return Err(io(source)),
        }
        file.set_len(0).map_err(io)?;
        file.rewind().map_err(io)?;
        file.write_all(std::process::id().to_string().as_bytes())
            .map_err(io)?;
        Ok(WatchLock { _file: file })
    }

    /// The log of the accesses that `pent run` denied for `name`.
    #[must_use]
    pub fn denied_path(&self, name: &ProfileName) -> PathBuf {
        self.dirs
            .state
            .join("denied")
            .join(format!("{name}.{LOG_EXTENSION}"))
    }

    /// The trace log of `name` (`pent run --trace`):
    /// `$XDG_STATE_HOME/pent/trace/<name>.log`.
    ///
    /// The log is not in the workspace, because the sandboxed process can
    /// write the workspace and could put a symbolic link there.
    #[must_use]
    pub fn trace_log_path(&self, name: &ProfileName) -> PathBuf {
        self.dirs.state.join("trace").join(format!("{name}.log"))
    }

    /// Create an empty trace log for `name` and return its path.
    ///
    /// The directory gets the mode `0700` and the file the mode `0600`. Pent
    /// does not follow a symbolic link at the path of the log.
    ///
    /// # Errors
    /// Returns an error if the directory or the file cannot be created, or
    /// if the path of the log is a symbolic link.
    pub fn create_trace_log(&self, name: &ProfileName) -> Result<PathBuf, StoreError> {
        let path = self.trace_log_path(name);
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        open_log_nofollow(&path, LogOpen::Truncate).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    fn open_trust(&self) -> Result<TrustStore, StoreError> {
        Ok(TrustStore::open(self.dirs.trust_store())?)
    }

    /// Load the profile `name` and its trust state.
    ///
    /// Pent reads the profile file one time. It checks the trust of these
    /// bytes and parses the same bytes, thus a change between the two steps
    /// has no effect.
    ///
    /// # Errors
    /// Returns an error if a file cannot be read, if the trust store is not
    /// valid, or if a trusted profile is not valid.
    pub fn load(&self, name: &ProfileName) -> Result<LoadedProfile, StoreError> {
        let path = self.profile_path(name);
        let has_draft = exists(&self.draft_path(name))?;
        let Some(bytes) = read_optional(&path, ReadFrom::AnyPath)? else {
            let status = if has_draft {
                ProfileStatus::DraftOnly
            } else {
                ProfileStatus::Missing
            };
            return Ok(LoadedProfile {
                status,
                path,
                doc: None,
                has_draft,
            });
        };
        let (status, doc) = match self.open_trust()?.status(&path, &bytes) {
            TrustStatus::Trusted => (ProfileStatus::Trusted, Some(parse_doc(&path, &bytes)?)),
            TrustStatus::Untrusted => (ProfileStatus::NotTrusted, None),
            TrustStatus::Changed => (ProfileStatus::Changed, None),
        };
        Ok(LoadedProfile {
            status,
            path,
            doc,
            has_draft,
        })
    }

    /// Read the text of the profile file of `name`, if it exists.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read.
    pub fn read_profile_text(&self, name: &ProfileName) -> Result<Option<String>, StoreError> {
        read_text(&self.profile_path(name), ReadFrom::AnyPath)
    }

    /// Read the text of the draft of `name`, if it exists.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read.
    pub fn read_draft_text(&self, name: &ProfileName) -> Result<Option<String>, StoreError> {
        read_text(&self.draft_path(name), ReadFrom::AnyPath)
    }

    /// Read and parse the draft of `name`, if it exists.
    ///
    /// # Errors
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn read_draft(&self, name: &ProfileName) -> Result<Option<ProfileDoc>, StoreError> {
        let path = self.draft_path(name);
        read_optional(&path, ReadFrom::AnyPath)?
            .map(|bytes| parse_doc(&path, &bytes))
            .transpose()
    }

    /// Write the draft of `name` atomically and return its path.
    ///
    /// # Errors
    /// Returns `StoreError::Doc` if `text` is not a valid profile (pent does
    /// not write a draft that it cannot apply), and `StoreError::Io` if the
    /// write fails.
    pub fn write_draft(&self, name: &ProfileName, text: &str) -> Result<PathBuf, StoreError> {
        let path = self.draft_path(name);
        parse_doc(&path, text.as_bytes())?;
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        write_atomic_private(&path, text.as_bytes()).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    /// Trust the profile `name` and return the path of the profile file.
    ///
    /// When a draft exists, pent moves the draft to the profile file and
    /// trusts it. Otherwise pent trusts the profile file as it is (for
    /// example after `pent untrust`, or after the user edited the file).
    /// Pent reads the bytes one time, checks that they are a valid profile,
    /// and records the hash of these bytes.
    ///
    /// # Errors
    /// Returns `StoreError::NothingToTrust` when no draft and no profile
    /// exist, `StoreError::Doc` when the file is not a valid profile, and I/O
    /// or trust store errors.
    pub fn trust(&self, name: &ProfileName) -> Result<PathBuf, StoreError> {
        let profile = self.profile_path(name);
        let draft = self.draft_path(name);
        let mut trust = self.open_trust()?;
        if let Some(bytes) = read_optional(&draft, ReadFrom::AnyPath)? {
            parse_doc(&draft, &bytes)?;
            if let Some(dir) = profile.parent() {
                create_private_dir(dir)?;
            }
            write_atomic_private(&profile, &bytes).map_err(|source| StoreError::Io {
                path: profile.clone(),
                source,
            })?;
            trust.trust(&profile, &bytes);
            trust.save()?;
            remove_optional(&draft)?;
            return Ok(profile);
        }
        let bytes = read_optional(&profile, ReadFrom::AnyPath)?
            .ok_or_else(|| StoreError::NothingToTrust(name.clone()))?;
        parse_doc(&profile, &bytes)?;
        trust.trust(&profile, &bytes);
        trust.save()?;
        Ok(profile)
    }

    /// Trust exactly the bytes `shown` for the profile `name`, and return
    /// the path of the profile file.
    ///
    /// Use this function after the user saw `shown` and said yes.
    /// [`ProfileStore::trust`] reads the file again, so a change between
    /// the question and the answer goes into the profile without the user
    /// seeing it. This function writes `shown`, records the hash of
    /// `shown`, and deletes the draft. Thus the profile holds the bytes
    /// that the user saw, also when another process changed the draft in
    /// the meantime.
    ///
    /// # Errors
    /// Returns `StoreError::Doc` when `shown` is not a valid profile, and
    /// I/O or trust store errors.
    pub fn trust_exact(&self, name: &ProfileName, shown: &[u8]) -> Result<PathBuf, StoreError> {
        let profile = self.profile_path(name);
        parse_doc(&profile, shown)?;
        let mut trust = self.open_trust()?;
        if let Some(dir) = profile.parent() {
            create_private_dir(dir)?;
        }
        write_atomic_private(&profile, shown).map_err(|source| StoreError::Io {
            path: profile.clone(),
            source,
        })?;
        trust.trust(&profile, shown);
        trust.save()?;
        remove_optional(&self.draft_path(name))?;
        Ok(profile)
    }

    /// Remove the trust of the profile `name`.
    ///
    /// Returns `true` when the profile was trusted (or changed after the
    /// trust) before the call.
    ///
    /// # Errors
    /// Returns trust store errors.
    pub fn untrust(&self, name: &ProfileName) -> Result<bool, StoreError> {
        let mut trust = self.open_trust()?;
        let removed = trust.untrust(&self.profile_path(name));
        if removed {
            trust.save()?;
        }
        Ok(removed)
    }

    /// List the profiles and the drafts, sorted by name.
    ///
    /// Files with a name that is not a valid profile name are not in the
    /// list.
    ///
    /// # Errors
    /// Returns an error if a directory or a profile cannot be read, or if
    /// the trust store is not valid.
    pub fn list(&self) -> Result<Vec<ProfileEntry>, StoreError> {
        let profiles = names_in(&self.dirs.config.join("profiles"), "toml")?;
        let drafts = names_in(&self.dirs.state.join("drafts"), "toml")?;
        let mut names: Vec<ProfileName> = profiles.iter().chain(&drafts).cloned().collect();
        names.sort();
        names.dedup();
        let trust = self.open_trust()?;
        names
            .into_iter()
            .map(|name| {
                let has_draft = drafts.contains(&name);
                let path = self.profile_path(&name);
                let status = match read_optional(&path, ReadFrom::AnyPath)? {
                    Some(bytes) => match trust.status(&path, &bytes) {
                        TrustStatus::Trusted => ProfileStatus::Trusted,
                        TrustStatus::Untrusted => ProfileStatus::NotTrusted,
                        TrustStatus::Changed => ProfileStatus::Changed,
                    },
                    None => ProfileStatus::DraftOnly,
                };
                Ok(ProfileEntry {
                    name,
                    status,
                    has_draft,
                })
            })
            .collect()
    }

    /// Remove the profile `name`: the profile file, the draft, the trust
    /// entry, the watch logs and the log of denied accesses.
    ///
    /// Returns `true` when the profile file or the draft existed.
    ///
    /// # Errors
    /// Returns I/O or trust store errors.
    pub fn remove(&self, name: &ProfileName) -> Result<bool, StoreError> {
        let profile = remove_optional(&self.profile_path(name))?;
        let draft = remove_optional(&self.draft_path(name))?;
        self.untrust(name)?;
        let watch = self.watch_dir(name);
        match std::fs::remove_dir_all(&watch) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(StoreError::Io {
                    path: watch,
                    source,
                })
            }
        }
        remove_optional(&self.denied_path(name))?;
        Ok(profile || draft)
    }

    /// Start the raw log of a new watch run of `name`.
    ///
    /// With [`WatchRunMode::Replace`], pent first deletes the logs of earlier
    /// runs.
    ///
    /// # Errors
    /// Returns I/O errors.
    pub fn start_watch_run(
        &self,
        name: &ProfileName,
        mode: WatchRunMode,
    ) -> Result<EventLog, StoreError> {
        let dir = self.watch_dir(name);
        if mode == WatchRunMode::Replace {
            for path in self.watch_runs(name)? {
                remove_optional(&path)?;
            }
        }
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let run = format!("{secs:020}-{}.{LOG_EXTENSION}", std::process::id());
        EventLog::open_append(dir.join(run))
    }

    /// The log files of the watch runs of `name`, oldest first.
    ///
    /// # Errors
    /// Returns an error if the directory exists but cannot be read.
    pub fn watch_runs(&self, name: &ProfileName) -> Result<Vec<PathBuf>, StoreError> {
        let dir = self.watch_dir(name);
        let mut runs: Vec<PathBuf> = read_dir_optional(&dir)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == LOG_EXTENSION))
            .collect();
        runs.sort();
        Ok(runs)
    }

    /// Read the events of all watch runs of `name`, oldest run first.
    ///
    /// # Errors
    /// Returns an error if a log cannot be read.
    pub fn read_watch_events(&self, name: &ProfileName) -> Result<Vec<WatchEvent>, StoreError> {
        let mut events = Vec::new();
        for run in self.watch_runs(name)? {
            events.extend(read_events(&run)?);
        }
        Ok(events)
    }

    /// Open the log of denied accesses of `name` for append.
    ///
    /// # Errors
    /// Returns I/O errors.
    pub fn denied_log(&self, name: &ProfileName) -> Result<EventLog, StoreError> {
        EventLog::open_append(self.denied_path(name))
    }

    /// Read the denied accesses of `name`.
    ///
    /// # Errors
    /// Returns an error if the log exists but cannot be read.
    pub fn read_denied(&self, name: &ProfileName) -> Result<Vec<WatchEvent>, StoreError> {
        read_events(&self.denied_path(name))
    }

    /// Delete the denied accesses of `name`.
    ///
    /// # Errors
    /// Returns I/O errors.
    pub fn clear_denied(&self, name: &ProfileName) -> Result<(), StoreError> {
        remove_optional(&self.denied_path(name)).map(|_| ())
    }
}

/// The rule files: one TOML file for each key in `<state>/rules/`.
///
/// pentd is the only writer. A user can read and edit a file. Pent reads it
/// again at each load, and a change keeps the comments of the user (see
/// [`RuleSet::update_toml`]).
#[derive(Debug, Clone)]
pub struct RuleStore {
    dir: PathBuf,
}

/// The lock on the rule file of one key. See [`RuleStore::update`].
///
/// The lock ends when the value drops, and the kernel ends it when the
/// process ends, also after a crash.
#[derive(Debug)]
struct RulesLock {
    _file: std::fs::File,
}

impl RuleStore {
    /// Open the store at the default location (see [`PentDirs::from_env`]).
    ///
    /// # Errors
    /// Returns `StoreError::NoHome` when the location is not known.
    pub fn open_default() -> Result<Self, StoreError> {
        PentDirs::from_env()
            .map(|dirs| Self::new(&dirs))
            .ok_or(StoreError::NoHome)
    }

    /// Open the store in the given directories.
    #[must_use]
    pub fn new(dirs: &PentDirs) -> Self {
        Self {
            dir: dirs.rules_dir(),
        }
    }

    /// The path of the rule file of `key`. A key is always a safe file
    /// name, so the path stays in the directory.
    #[must_use]
    pub fn path(&self, key: &RuleKey) -> PathBuf {
        self.dir.join(format!("{key}.{RULES_EXTENSION}"))
    }

    /// The path of the lock file of `key`. Its name starts with `.`, so it
    /// is never a key.
    fn lock_path(&self, key: &RuleKey) -> PathBuf {
        self.dir.join(format!(".{key}.lock"))
    }

    /// Read the rules of `key`. A missing file gives no rules.
    ///
    /// # Errors
    /// Returns `StoreError::NotRegular` when the path is a symbolic link, a
    /// directory or a special file, `StoreError::TooLarge` when the file is
    /// larger than the limit, `StoreError::Rules` when the file is not
    /// valid, and `StoreError::Io` when the read fails.
    pub fn load(&self, key: &RuleKey) -> Result<RuleSet, StoreError> {
        Ok(self.read(key)?.0)
    }

    /// Read the rules of `key` and the text of the file.
    fn read(&self, key: &RuleKey) -> Result<(RuleSet, Option<String>), StoreError> {
        let path = self.path(key);
        let Some(text) = read_text(&path, ReadFrom::rules())? else {
            return Ok((RuleSet::new(key.clone()), None));
        };
        let rules = RuleSet::from_toml(key.clone(), &text).map_err(|source| StoreError::Rules {
            path,
            source: Box::new(source),
        })?;
        Ok((rules, Some(text)))
    }

    /// Change the rules of `key` with `change`, and write the file again.
    /// Returns the value of `change`.
    ///
    /// The call holds a lock on the key from the read to the write, so two
    /// pent processes cannot lose each other's change. It reads the file
    /// again, so it also sees an edit of the user that came before the
    /// call. The write is atomic, with the mode `0600`, and it keeps the
    /// comments of the user. The rename never follows a symbolic link: a
    /// link that appears at the path after the read is replaced, and its
    /// target does not change.
    ///
    /// # Errors
    /// Returns the errors of [`RuleStore::load`]: pent does not write over a
    /// file that it cannot read. Also returns `StoreError::Rules` when pent
    /// cannot encode the rules, and `StoreError::Io` when the lock or the
    /// write fails.
    pub fn update<R>(
        &self,
        key: &RuleKey,
        change: impl FnOnce(&mut RuleSet) -> R,
    ) -> Result<R, StoreError> {
        let _lock = self.lock(key)?;
        let path = self.path(key);
        let (mut rules, old) = self.read(key)?;
        let result = change(&mut rules);
        // The change cannot move the rules to the file of another key.
        rules.key = key.clone();
        let text = match &old {
            Some(old) => rules.update_toml(old),
            None => rules.to_toml(),
        }
        .map_err(|source| StoreError::Rules {
            path: path.clone(),
            source: Box::new(source),
        })?;
        if old.as_deref() != Some(text.as_str()) {
            write_atomic_private(&path, text.as_bytes())
                .map_err(|source| StoreError::Io { path, source })?;
        }
        Ok(result)
    }

    /// Write `rules` in place of the rules of `rules.key`, with
    /// [`RuleStore::update`]. Returns the path of the file.
    ///
    /// # Errors
    /// Returns the errors of [`RuleStore::update`].
    pub fn save(&self, rules: &RuleSet) -> Result<PathBuf, StoreError> {
        self.update(&rules.key, |set| set.rules.clone_from(&rules.rules))?;
        Ok(self.path(&rules.key))
    }

    /// The keys that have a rule file, in order. Pent skips a file whose
    /// name is not a valid key, and an entry that is not a regular file.
    ///
    /// # Errors
    /// Returns `StoreError::Io` when pent cannot read the directory.
    pub fn keys(&self) -> Result<Vec<RuleKey>, StoreError> {
        let mut keys: Vec<RuleKey> = read_dir_optional(&self.dir)?
            .iter()
            .filter(|p| p.extension().is_some_and(|e| e == RULES_EXTENSION))
            .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file()))
            .filter_map(|p| p.file_stem()?.to_str()?.parse().ok())
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// Remove each rule of `key` with the target `target`, or each rule of
    /// `key` for `None`, under the lock of the key. Returns how many rules
    /// went. When no rule is left, the rule file goes too, so no key stays
    /// with an empty file. A key with no file stays with no file. The lock
    /// file stays: a removal of a lock file that another process holds
    /// would break the lock.
    ///
    /// # Errors
    /// Returns the errors of [`RuleStore::update`].
    pub fn forget(&self, key: &RuleKey, target: Option<&Target>) -> Result<usize, StoreError> {
        let _lock = self.lock(key)?;
        let path = self.path(key);
        let (mut rules, old) = self.read(key)?;
        let Some(old) = old else {
            return Ok(0);
        };
        let before = rules.rules.len();
        match target {
            Some(target) => rules.rules.retain(|r| r.target != *target),
            None => rules.rules.clear(),
        }
        let count = before.saturating_sub(rules.rules.len());
        if count == 0 {
            return Ok(0);
        }
        if rules.rules.is_empty() {
            remove_optional(&path)?;
            return Ok(count);
        }
        let text = rules
            .update_toml(&old)
            .map_err(|source| StoreError::Rules {
                path: path.clone(),
                source: Box::new(source),
            })?;
        write_atomic_private(&path, text.as_bytes())
            .map_err(|source| StoreError::Io { path, source })?;
        Ok(count)
    }

    /// Remove the rule file of `key`. Returns `true` when the file existed.
    ///
    /// # Errors
    /// Returns `StoreError::Io` when the lock or the removal fails.
    pub fn remove(&self, key: &RuleKey) -> Result<bool, StoreError> {
        let _lock = self.lock(key)?;
        remove_optional(&self.path(key))
    }

    /// Take the lock of `key`. The call waits while another process holds
    /// it.
    fn lock(&self, key: &RuleKey) -> Result<RulesLock, StoreError> {
        use std::os::unix::fs::OpenOptionsExt as _;
        create_private_dir(&self.dir)?;
        let path = self.lock_path(key);
        let io = |source| StoreError::Io {
            path: path.clone(),
            source,
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(io)?;
        file.lock().map_err(io)?;
        Ok(RulesLock { _file: file })
    }
}

/// Parse the bytes of a profile or a draft.
fn parse_doc(path: &Path, bytes: &[u8]) -> Result<ProfileDoc, StoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| StoreError::NotUtf8 {
        path: path.to_path_buf(),
    })?;
    ProfileDoc::parse(text).map_err(|source| StoreError::Doc {
        path: path.to_path_buf(),
        source,
    })
}

/// Read the events of one log file. A missing file has no events.
///
/// Pent skips a line that is not a valid event. Such a line occurs when a
/// pent process stopped in the middle of a write.
fn read_events(path: &Path) -> Result<Vec<WatchEvent>, StoreError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(StoreError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let mut events = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if let Ok(event) = WatchEvent::from_json_line(&line) {
            events.push(event);
        }
    }
    Ok(events)
}

/// How [`read_optional`] opens a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadFrom {
    /// Follow a symbolic link. A profile can be a link, for example from a
    /// manager of dotfiles.
    AnyPath,
    /// Read only a regular file with at most `max_len` bytes. A symbolic
    /// link, a directory and a special file are errors. A FIFO does not
    /// block the open.
    RegularFile {
        /// The limit in bytes.
        max_len: u64,
    },
}

impl ReadFrom {
    /// The mode for a rule file.
    const fn rules() -> Self {
        Self::RegularFile {
            max_len: MAX_RULES_LEN,
        }
    }
}

/// Read a file. A missing file gives `None`.
fn read_optional(path: &Path, from: ReadFrom) -> Result<Option<Vec<u8>>, StoreError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let io_err = |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    };
    let not_regular = || StoreError::NotRegular {
        path: path.to_path_buf(),
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    if from != ReadFrom::AnyPath {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if from != ReadFrom::AnyPath && e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(not_regular())
        }
        Err(e) => return Err(io_err(e)),
    };
    let mut bytes = Vec::new();
    match from {
        ReadFrom::AnyPath => {
            let mut file = file;
            file.read_to_end(&mut bytes).map_err(io_err)?;
        }
        ReadFrom::RegularFile { max_len } => {
            if !file.metadata().map_err(io_err)?.is_file() {
                return Err(not_regular());
            }
            file.take(max_len.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(io_err)?;
            if u64::try_from(bytes.len()).map_or(true, |len| len > max_len) {
                return Err(StoreError::TooLarge {
                    path: path.to_path_buf(),
                    max_len,
                });
            }
        }
    }
    Ok(Some(bytes))
}

/// Read a text file. A missing file gives `None`.
fn read_text(path: &Path, from: ReadFrom) -> Result<Option<String>, StoreError> {
    read_optional(path, from)?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| StoreError::NotUtf8 {
                path: path.to_path_buf(),
            })
        })
        .transpose()
}

/// Return true if `path` exists.
fn exists(path: &Path) -> Result<bool, StoreError> {
    path.try_exists().map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Remove a file. Returns `true` when the file existed.
fn remove_optional(path: &Path) -> Result<bool, StoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The entries of a directory. A missing directory has no entries.
fn read_dir_optional(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let io_err = |source| StoreError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(e)),
    };
    entries
        .map(|entry| entry.map(|e| e.path()).map_err(io_err))
        .collect()
}

/// The profile names of the `<name>.<extension>` files in `dir`.
fn names_in(dir: &Path, extension: &str) -> Result<Vec<ProfileName>, StoreError> {
    Ok(read_dir_optional(dir)?
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == extension))
        .filter_map(|p| p.file_stem()?.to_str()?.parse().ok())
        .collect())
}

/// How [`open_log_nofollow`] opens a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOpen {
    /// Create the file, or empty it.
    Truncate,
    /// Create the file, or append to it.
    Append,
}

/// Open a log file for writing with the mode `0600`. The call fails if the
/// last component of `path` is a symbolic link.
///
/// # Errors
/// Returns the error of `open(2)` (`ELOOP` for a symbolic link).
pub fn open_log_nofollow(path: &Path, how: LogOpen) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true);
    match how {
        LogOpen::Truncate => options.write(true).truncate(true),
        LogOpen::Append => options.append(true),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Create `dir` and its missing parents with the mode `0700`.
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    crate::trust::create_private_dir(dir).map_err(|source| StoreError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    #[cfg(unix)]
    #[test]
    fn trace_log_is_private_and_does_not_follow_links() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(PentDirs {
            config: tmp.path().join("config"),
            state: tmp.path().join("state"),
        });
        let name: ProfileName = "tool".parse().unwrap();
        let path = store.create_trace_log(&name).unwrap();
        assert!(!path.starts_with(tmp.path().join("config")));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        // A symbolic link at the log path makes the open fail, and the
        // target does not change.
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(store.create_trace_log(&name).is_err());
        assert!(open_log_nofollow(&path, LogOpen::Append).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
    use super::*;
    use pent_profile::{FsOp, Outcome, ProcessInfo};

    /// A store in temp directories. The test never touches the real home.
    struct Fixture {
        _root: tempfile::TempDir,
        store: ProfileStore,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(PentDirs {
            config: root.path().join("config/pent"),
            state: root.path().join("state/pent"),
        });
        Fixture { _root: root, store }
    }

    fn name(s: &str) -> ProfileName {
        s.parse().unwrap()
    }

    const DRAFT: &str = "# reason comments\n[filesystem]\nread = [\"~/.gitconfig\"] # git\n\
                         [network]\ndomains = [\"a.com\"]\n";

    fn fs_event(path: &str, outcome: Outcome) -> WatchEvent {
        WatchEvent::Fs {
            op: FsOp::Read,
            path: PathBuf::from(path),
            process: ProcessInfo {
                pid: 1,
                name: "p".to_string(),
            },
            outcome,
        }
    }

    /// One watch run of a profile at a time. A second lock fails at once
    /// and names the holder; the lock of another profile works; the lock
    /// is free again when the first one drops.
    #[test]
    fn a_second_watch_of_a_profile_is_refused() {
        let f = fixture();
        let first = f.store.lock_watch(&name("claude"));
        assert!(first.is_ok(), "{first:?}");
        let second = f.store.lock_watch(&name("claude"));
        assert!(
            matches!(
                &second,
                Err(StoreError::WatchBusy { name: n, pid })
                    if *n == name("claude") && *pid == Some(std::process::id())
            ),
            "the second lock must fail and name this process: {second:?}"
        );
        let message = StoreError::WatchBusy {
            name: name("claude"),
            pid: Some(42),
        }
        .to_string();
        assert!(
            message.contains("(pid 42)") && message.contains("--profile"),
            "{message}"
        );
        assert!(f.store.lock_watch(&name("other")).is_ok());
        drop(first);
        assert!(f.store.lock_watch(&name("claude")).is_ok());
        // `pent profile rm` deletes the log directory; the lock file is not
        // in it.
        assert!(!f
            .store
            .watch_lock_path(&name("claude"))
            .starts_with(f.store.watch_dir(&name("claude"))));
    }

    /// The lock file is private, and a symbolic link at its path makes the
    /// lock fail: pent never writes through such a link.
    #[cfg(unix)]
    #[test]
    fn the_watch_lock_file_is_private_and_does_not_follow_links() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = fixture();
        let lock = f.store.lock_watch(&name("claude"));
        assert!(lock.is_ok(), "{lock:?}");
        let path = f.store.watch_lock_path(&name("claude"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let target = f._root.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = f.store.watch_lock_path(&name("linked"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            f.store.lock_watch(&name("linked")),
            Err(StoreError::Io { .. })
        ));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn dirs_use_xdg_variables_and_defaults() {
        let home = Some(PathBuf::from("/home/u"));
        let d = PentDirs::from_vars(None, None, home.clone()).unwrap();
        assert_eq!(d.config, PathBuf::from("/home/u/.config/pent"));
        assert_eq!(d.state, PathBuf::from("/home/u/.local/state/pent"));
        assert_eq!(
            d.global_config(),
            PathBuf::from("/home/u/.config/pent/pent.toml")
        );
        assert_eq!(
            d.trust_store(),
            PathBuf::from("/home/u/.config/pent/trusted.toml")
        );

        let d = PentDirs::from_vars(Some("/c".into()), Some("/s".into()), home.clone()).unwrap();
        assert_eq!(d.config, PathBuf::from("/c/pent"));
        assert_eq!(d.state, PathBuf::from("/s/pent"));

        // A relative or empty value is ignored.
        let d = PentDirs::from_vars(Some("rel".into()), Some("".into()), home).unwrap();
        assert_eq!(d.config, PathBuf::from("/home/u/.config/pent"));
        assert_eq!(d.state, PathBuf::from("/home/u/.local/state/pent"));

        assert!(PentDirs::from_vars(None, Some("/s".into()), None).is_none());
        assert!(PentDirs::from_vars(Some("/c".into()), Some("/s".into()), None).is_some());
    }

    #[test]
    fn missing_then_draft_then_trusted() {
        let f = fixture();
        let n = name("claude");
        assert_eq!(f.store.load(&n).unwrap().status, ProfileStatus::Missing);

        let draft = f.store.write_draft(&n, DRAFT).unwrap();
        assert_eq!(draft, f.store.draft_path(&n));
        let loaded = f.store.load(&n).unwrap();
        assert_eq!(loaded.status, ProfileStatus::DraftOnly);
        assert!(loaded.has_draft);
        assert!(loaded.doc.is_none());

        let profile = f.store.trust(&n).unwrap();
        assert_eq!(profile, f.store.profile_path(&n));
        assert!(!draft.exists(), "trust moves the draft");
        let loaded = f.store.load(&n).unwrap();
        assert_eq!(loaded.status, ProfileStatus::Trusted);
        assert!(!loaded.has_draft);
        let doc = loaded.doc.unwrap();
        assert_eq!(doc.filesystem.read, vec!["~/.gitconfig"]);
        assert_eq!(doc.network.domains, vec!["a.com"]);
        // The comments stay in the profile file.
        let text = f.store.read_profile_text(&n).unwrap().unwrap();
        assert!(text.contains("# git"), "{text}");
    }

    #[test]
    fn edit_after_trust_is_changed_and_untrust_is_not_trusted() {
        let f = fixture();
        let n = name("claude");
        f.store.write_draft(&n, DRAFT).unwrap();
        f.store.trust(&n).unwrap();
        std::fs::write(
            f.store.profile_path(&n),
            "[network]\ndomains = [\"evil.com\"]\n",
        )
        .unwrap();
        let loaded = f.store.load(&n).unwrap();
        assert_eq!(loaded.status, ProfileStatus::Changed);
        assert!(loaded.doc.is_none());

        // Trust without a draft trusts the profile file as it is.
        f.store.trust(&n).unwrap();
        assert_eq!(f.store.load(&n).unwrap().status, ProfileStatus::Trusted);

        assert!(f.store.untrust(&n).unwrap());
        assert!(!f.store.untrust(&n).unwrap());
        assert_eq!(f.store.load(&n).unwrap().status, ProfileStatus::NotTrusted);
    }

    #[test]
    fn untrusted_invalid_profile_is_not_parsed() {
        let f = fixture();
        let n = name("x");
        let path = f.store.profile_path(&n);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not toml :::").unwrap();
        assert_eq!(f.store.load(&n).unwrap().status, ProfileStatus::NotTrusted);
        assert!(matches!(f.store.trust(&n), Err(StoreError::Doc { .. })));
    }

    #[test]
    fn invalid_draft_is_rejected() {
        let f = fixture();
        let n = name("x");
        assert!(matches!(
            f.store.write_draft(&n, "[filesystem]\nwrite = []\n"),
            Err(StoreError::Doc { .. })
        ));
        assert!(!f.store.draft_path(&n).exists());
    }

    #[test]
    fn trust_without_files_fails() {
        let f = fixture();
        assert!(matches!(
            f.store.trust(&name("none")),
            Err(StoreError::NothingToTrust(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = fixture();
        let n = name("claude");
        let draft = f.store.write_draft(&n, DRAFT).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&draft), 0o600);
        assert_eq!(mode(draft.parent().unwrap()), 0o700);
        let profile = f.store.trust(&n).unwrap();
        assert_eq!(mode(&profile), 0o600);
        let log = f.store.denied_log(&n).unwrap();
        assert_eq!(mode(log.path()), 0o600);
    }

    #[test]
    fn list_shows_profiles_and_drafts() {
        let f = fixture();
        f.store.write_draft(&name("b"), DRAFT).unwrap();
        f.store.write_draft(&name("a"), DRAFT).unwrap();
        f.store.trust(&name("a")).unwrap();
        f.store.write_draft(&name("a"), DRAFT).unwrap();
        // A file with a name that is not a valid profile name is skipped.
        std::fs::write(f.store.dirs().state.join("drafts/.hidden.toml"), DRAFT).unwrap();
        let list = f.store.list().unwrap();
        assert_eq!(
            list,
            vec![
                ProfileEntry {
                    name: name("a"),
                    status: ProfileStatus::Trusted,
                    has_draft: true
                },
                ProfileEntry {
                    name: name("b"),
                    status: ProfileStatus::DraftOnly,
                    has_draft: true
                },
            ]
        );
    }

    #[test]
    fn remove_deletes_everything() {
        let f = fixture();
        let n = name("claude");
        f.store.write_draft(&n, DRAFT).unwrap();
        f.store.trust(&n).unwrap();
        f.store.write_draft(&n, DRAFT).unwrap();
        let mut log = f.store.start_watch_run(&n, WatchRunMode::Append).unwrap();
        log.append(&fs_event("/a", Outcome::Allowed)).unwrap();
        let mut denied = f.store.denied_log(&n).unwrap();
        denied.append(&fs_event("/b", Outcome::Denied)).unwrap();

        assert!(f.store.remove(&n).unwrap());
        assert_eq!(f.store.load(&n).unwrap().status, ProfileStatus::Missing);
        assert!(f.store.read_watch_events(&n).unwrap().is_empty());
        assert!(f.store.read_denied(&n).unwrap().is_empty());
        assert!(!f.store.remove(&n).unwrap());
        // The trust entry is gone: a new profile file is not trusted.
        let path = f.store.profile_path(&n);
        std::fs::write(&path, DRAFT).unwrap();
        assert_eq!(f.store.load(&n).unwrap().status, ProfileStatus::NotTrusted);
    }

    /// Only a missing watch directory is not an error. When the directory
    /// exists and pent cannot delete it, `remove` reports the error. A
    /// silent return would tell the user that the raw logs of the watch
    /// runs are gone while they stay on the disk.
    #[cfg(unix)]
    #[test]
    fn remove_reports_the_error_when_it_cannot_delete_the_watch_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let f = fixture();
        let n = name("claude");
        f.store.write_draft(&n, DRAFT).unwrap();
        let mut log = f.store.start_watch_run(&n, WatchRunMode::Append).unwrap();
        log.append(&fs_event("/a", Outcome::Allowed)).unwrap();
        drop(log);

        let watch = f.store.watch_dir(&n);
        let parent = watch.parent().unwrap().to_path_buf();
        let read_only = std::fs::Permissions::from_mode(0o500);
        let writable = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&parent, read_only).unwrap();
        if ignores_the_mode(&parent) {
            // The user of the test has `CAP_DAC_OVERRIDE` (for example
            // root). The mode then stops nothing.
            std::fs::set_permissions(&parent, writable).unwrap();
            println!("SKIP: the user of this test can write a directory with the mode 0500");
            return;
        }

        let result = f.store.remove(&n);
        // Give the write permission back, so that the temporary directory
        // goes away at the end of the test.
        std::fs::set_permissions(&parent, writable).unwrap();

        // The comparison is on the text, because the test must not panic
        // on an unexpected value.
        let reported = match &result {
            Err(StoreError::Io { path, source }) => {
                format!("{} {:?}", path.display(), source.kind())
            }
            other => format!("not an I/O error: {other:?}"),
        };
        assert_eq!(
            reported,
            format!(
                "{} {:?}",
                watch.display(),
                std::io::ErrorKind::PermissionDenied
            )
        );
        // The logs are still there, as the error says.
        assert!(watch.exists());
    }

    /// True when the process can create a file in `dir`, although the mode
    /// of `dir` gives no write permission.
    #[cfg(unix)]
    fn ignores_the_mode(dir: &Path) -> bool {
        let probe = dir.join("probe");
        match std::fs::write(&probe, b"x") {
            Ok(()) => {
                std::fs::remove_file(&probe).unwrap();
                true
            }
            Err(_) => false,
        }
    }

    /// A draft comes back with its text and with its rules.
    #[test]
    fn a_draft_comes_back_with_its_text_and_its_rules() {
        let f = fixture();
        let n = name("claude");
        assert_eq!(f.store.read_draft_text(&n).unwrap(), None);
        assert_eq!(f.store.read_draft(&n).unwrap(), None);
        f.store.write_draft(&n, DRAFT).unwrap();
        assert_eq!(
            f.store.read_draft_text(&n).unwrap(),
            Some(DRAFT.to_string())
        );
        let doc = f.store.read_draft(&n).unwrap();
        assert_eq!(
            doc.as_ref().map(|d| d.filesystem.read.clone()),
            Some(vec!["~/.gitconfig".to_string()])
        );
        assert_eq!(
            doc.as_ref().map(|d| d.network.domains.clone()),
            Some(vec!["a.com".to_string()])
        );
    }

    /// `remove` reports true when it deleted a draft, also when there is no
    /// profile file.
    #[test]
    fn remove_reports_a_draft_without_a_profile() {
        let f = fixture();
        let n = name("claude");
        f.store.write_draft(&n, DRAFT).unwrap();
        assert!(f.store.remove(&n).unwrap());
        assert!(!f.store.remove(&n).unwrap());
        // The other direction: a profile file with no draft.
        std::fs::create_dir_all(f.store.profile_path(&n).parent().unwrap()).unwrap();
        std::fs::write(f.store.profile_path(&n), DRAFT).unwrap();
        assert!(f.store.remove(&n).unwrap());
    }

    /// Only a missing file gives `None`. Another I/O error is an error, so
    /// a profile that pent cannot read never looks absent.
    #[test]
    fn a_file_that_pent_cannot_read_is_an_error_and_not_an_absence() {
        let f = fixture();
        let n = name("claude");
        // A directory at the path of each file: the read gives
        // `IsADirectory`, which is not `NotFound`.
        std::fs::create_dir_all(f.store.profile_path(&n)).unwrap();
        std::fs::create_dir_all(f.store.draft_path(&n)).unwrap();
        std::fs::create_dir_all(f.store.denied_path(&n)).unwrap();
        assert!(f.store.read_profile_text(&n).is_err());
        assert!(f.store.read_draft(&n).is_err());
        assert!(f.store.read_denied(&n).is_err());
        assert!(f.store.remove(&n).is_err());
        // A file at the path of the watch directory: `read_dir` gives
        // `NotADirectory`, which is not `NotFound`.
        let watch = f.store.watch_dir(&n);
        std::fs::create_dir_all(watch.parent().unwrap()).unwrap();
        std::fs::write(&watch, "x").unwrap();
        assert!(f.store.watch_runs(&n).is_err());

        // A log file whose parent directory is a file: `open` gives
        // `NotADirectory`. A directory is not enough here, because `open`
        // on a directory works and the error comes later, from the read.
        let g = fixture();
        let denied_dir = g.store.denied_path(&n).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(denied_dir.parent().unwrap()).unwrap();
        std::fs::write(&denied_dir, "x").unwrap();
        assert!(g.store.read_denied(&n).is_err());
    }

    /// Each profile state has its own text. The `pent profile` list shows
    /// it, so two states must not read the same.
    #[test]
    fn each_profile_status_has_its_own_text() {
        let texts: Vec<String> = [
            ProfileStatus::Trusted,
            ProfileStatus::NotTrusted,
            ProfileStatus::Changed,
            ProfileStatus::DraftOnly,
            ProfileStatus::Missing,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            texts,
            vec![
                "trusted",
                "not trusted",
                "changed after trust",
                "draft only",
                "missing"
            ]
        );
    }

    /// `from_env` reads the XDG variables of the process and falls back to
    /// the home directory.
    #[test]
    fn from_env_uses_the_variables_of_the_process() {
        let expected = PentDirs::from_vars(
            std::env::var_os("XDG_CONFIG_HOME"),
            std::env::var_os("XDG_STATE_HOME"),
            dirs::home_dir(),
        );
        assert_eq!(PentDirs::from_env(), expected);
    }

    #[test]
    fn watch_runs_append_and_replace() {
        let f = fixture();
        let n = name("claude");
        let mut first = f.store.start_watch_run(&n, WatchRunMode::Replace).unwrap();
        first.append(&fs_event("/one", Outcome::Allowed)).unwrap();
        // Two runs in the same second get different names from the PID only
        // across processes; give this run a different name by hand.
        let second_path = f.store.watch_dir(&n).join("99999999999999999999-1.jsonl");
        let mut second = EventLog::open_append(second_path).unwrap();
        second.append(&fs_event("/two", Outcome::Allowed)).unwrap();
        // A partial line from a crash is skipped.
        std::fs::OpenOptions::new()
            .append(true)
            .open(second.path())
            .unwrap()
            .write_all(b"{\"type\":\"fs\"")
            .unwrap();

        let events = f.store.read_watch_events(&n).unwrap();
        assert_eq!(
            events,
            vec![
                fs_event("/one", Outcome::Allowed),
                fs_event("/two", Outcome::Allowed)
            ]
        );
        assert_eq!(f.store.watch_runs(&n).unwrap().len(), 2);

        let _third = f.store.start_watch_run(&n, WatchRunMode::Replace).unwrap();
        assert_eq!(f.store.watch_runs(&n).unwrap().len(), 1);
        assert!(f.store.read_watch_events(&n).unwrap().is_empty());
    }

    #[test]
    fn denied_log_append_read_clear() {
        let f = fixture();
        let n = name("claude");
        assert!(f.store.read_denied(&n).unwrap().is_empty());
        f.store
            .denied_log(&n)
            .unwrap()
            .append(&fs_event("/x", Outcome::Denied))
            .unwrap();
        f.store
            .denied_log(&n)
            .unwrap()
            .append(&fs_event("/y", Outcome::Denied))
            .unwrap();
        assert_eq!(f.store.read_denied(&n).unwrap().len(), 2);
        f.store.clear_denied(&n).unwrap();
        assert!(f.store.read_denied(&n).unwrap().is_empty());
        f.store.clear_denied(&n).unwrap();
    }

    mod rules {
        use super::*;
        use pent_profile::{Decision, PathWidth, Rule, RulePath, Source, Target};
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::{Duration, SystemTime};

        fn rules_fixture() -> (tempfile::TempDir, RuleStore) {
            let root = tempfile::tempdir().unwrap();
            let store = RuleStore::new(&PentDirs {
                config: root.path().join("config/pent"),
                state: root.path().join("state/pent"),
            });
            (root, store)
        }

        fn key(s: &str) -> RuleKey {
            s.parse().unwrap()
        }

        #[test]
        fn forget_keeps_the_other_rules_and_removes_an_empty_file() {
            let (_root, store) = rules_fixture();
            let set = sample("cargo");
            assert!(set.rules.len() >= 2);
            store.save(&set).unwrap();
            let first = set.rules[0].target.clone();
            assert_eq!(store.forget(&key("cargo"), Some(&first)).unwrap(), 1);
            let left = store.load(&key("cargo")).unwrap();
            assert_eq!(left.rules.len(), set.rules.len() - 1);
            assert!(left.rules.iter().all(|r| r.target != first));
            // The same target again: nothing goes, and the file stays.
            assert_eq!(store.forget(&key("cargo"), Some(&first)).unwrap(), 0);
            assert!(store.path(&key("cargo")).exists());
            // Each rule: the file goes too.
            assert_eq!(
                store.forget(&key("cargo"), None).unwrap(),
                set.rules.len() - 1
            );
            assert!(!store.path(&key("cargo")).exists());
            assert!(store.keys().unwrap().is_empty());
            // A key with no file gets no file.
            assert_eq!(store.forget(&key("node"), None).unwrap(), 0);
            assert!(!store.path(&key("node")).exists());
        }

        fn sample(k: &str) -> RuleSet {
            let mut set = RuleSet::new(key(k));
            set.rules.push(Rule {
                target: Target::File {
                    kind: pent_profile::FileKind::Read,
                    width: PathWidth::Subtree(RulePath::new("/home/u/.cargo").unwrap()),
                },
                decision: Decision::Allow,
                source: Source::Human,
                created: SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_348_800),
            });
            set.rules.push(Rule {
                target: Target::Domain("*.npmjs.org".parse().unwrap()),
                decision: Decision::Deny,
                source: Source::Model,
                created: SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_348_801),
            });
            set
        }

        #[test]
        fn the_rules_survive_a_round_trip_in_a_private_file() {
            let (_root, store) = rules_fixture();
            let set = sample("claude");
            let path = store.save(&set).unwrap();
            assert!(path.ends_with("state/pent/rules/claude.toml"), "{path:?}");
            assert_eq!(store.load(&key("claude")).unwrap(), set);

            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);

            // A second save replaces the file and leaves no temporary file.
            // The lock files stay, with the mode 0600.
            store.save(&sample("claude")).unwrap();
            store.save(&sample("cargo")).unwrap();
            let mut names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            assert_eq!(
                names,
                [".cargo.lock", ".claude.lock", "cargo.toml", "claude.toml"]
            );
            assert_eq!(mode(&path.with_file_name(".claude.lock")), 0o600);
            assert_eq!(store.keys().unwrap(), vec![key("cargo"), key("claude")]);
        }

        #[test]
        fn a_missing_file_gives_no_rules_and_remove_reports_it() {
            let (_root, store) = rules_fixture();
            assert_eq!(
                store.load(&key("claude")).unwrap(),
                RuleSet::new(key("claude"))
            );
            assert!(store.keys().unwrap().is_empty());
            assert!(!store.remove(&key("claude")).unwrap());
            store.save(&sample("claude")).unwrap();
            assert!(store.remove(&key("claude")).unwrap());
            assert!(store.keys().unwrap().is_empty());
        }

        #[test]
        fn a_hand_edit_is_read_at_the_next_load() {
            let (_root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            let edited = text.replace("decision = \"deny\"", "decision = \"allow\"")
                + "\n# a note of the user\n[[rule]]\nkind = \"localhost\"\nport = 5432\n\
                   decision = \"allow\"\nsource = \"human\"\ncreated = 2026-11-22T13:00:00+01:00\n";
            std::fs::write(&path, edited).unwrap();
            let set = store.load(&key("claude")).unwrap();
            assert_eq!(set.rules.len(), 3);
            assert!(set.rules.iter().all(|r| r.decision == Decision::Allow));
        }

        #[test]
        fn a_bad_file_is_an_error_that_names_the_file_and_the_field() {
            let (_root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(
                &path,
                text.replace("source = \"human\"", "colour = \"red\""),
            )
            .unwrap();
            let err = store.load(&key("claude")).unwrap_err();
            assert!(matches!(err, StoreError::Rules { .. }), "{err:?}");
            let message = err.to_string();
            assert!(message.contains("claude.toml"), "{message}");
            assert!(message.contains("colour"), "{message}");

            std::fs::write(&path, [0xff, 0xfe]).unwrap();
            assert!(matches!(
                store.load(&key("claude")),
                Err(StoreError::NotUtf8 { .. })
            ));
        }

        #[test]
        fn a_symbolic_link_at_the_path_is_not_followed() {
            let (root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let target = root.path().join("elsewhere.toml");
            std::fs::write(&target, sample("claude").to_toml().unwrap()).unwrap();
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();

            // The load and the update refuse the link, also when the target
            // is valid, and the target does not change.
            let before = std::fs::read(&target).unwrap();
            assert!(matches!(
                store.load(&key("claude")),
                Err(StoreError::NotRegular { .. })
            ));
            assert!(matches!(
                store.save(&RuleSet::new(key("claude"))),
                Err(StoreError::NotRegular { .. })
            ));
            assert_eq!(std::fs::read(&target).unwrap(), before);
        }

        #[test]
        fn a_link_that_appears_during_an_update_is_replaced() {
            let (root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let target = root.path().join("elsewhere.toml");
            std::fs::write(&target, "keep").unwrap();

            // The change runs between the read and the write. It puts a link
            // at the path, as a race would.
            store
                .update(&key("claude"), |set| {
                    set.rules.pop();
                    std::fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink(&target, &path).unwrap();
                })
                .unwrap();
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
            assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
            assert_eq!(store.load(&key("claude")).unwrap().rules.len(), 1);
        }

        #[test]
        fn a_directory_or_a_fifo_at_the_path_is_refused_at_once() {
            let (_root, store) = rules_fixture();
            let path = store.path(&key("claude"));
            std::fs::create_dir_all(&path).unwrap();
            assert!(matches!(
                store.load(&key("claude")),
                Err(StoreError::NotRegular { .. })
            ));

            // A blocking open of a FIFO waits for a writer forever. The load
            // must return at once.
            let fifo = store.path(&key("fifo"));
            let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: `c_path` is a valid C string that lives for the call.
            let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
            assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
            assert!(matches!(
                store.load(&key("fifo")),
                Err(StoreError::NotRegular { .. })
            ));
            assert_eq!(store.keys().unwrap(), vec![]);
        }

        #[test]
        fn a_file_above_the_limit_is_refused() {
            let (_root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let mut text = std::fs::read_to_string(&path).unwrap();
            let len = usize::try_from(MAX_RULES_LEN).unwrap();
            text.push_str(&"#".repeat(len));
            std::fs::write(&path, text).unwrap();
            assert!(matches!(
                store.load(&key("claude")),
                Err(StoreError::TooLarge { .. })
            ));
        }

        #[test]
        fn a_save_keeps_the_comments_of_the_user() {
            let (_root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            let edited =
                text.replacen("[[rule]]", "# why I allow cargo\n[[rule]]", 1) + "# the end\n";
            std::fs::write(&path, &edited).unwrap();

            // Forget the domain rule.
            store
                .update(&key("claude"), |set| {
                    set.rules.retain(|r| !matches!(r.target, Target::Domain(_)));
                })
                .unwrap();
            let after = std::fs::read_to_string(&path).unwrap();
            assert!(after.contains("# why I allow cargo"), "{after}");
            assert!(after.contains("# the end"), "{after}");
            assert!(!after.contains("npmjs"), "{after}");
            assert!(after.starts_with("# The rules of pent"), "{after}");
        }

        #[test]
        fn an_update_sees_an_edit_that_came_after_a_load() {
            let (_root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let loaded = store.load(&key("claude")).unwrap();
            assert_eq!(loaded.rules.len(), 2);

            // The user adds a rule after the load.
            let mut text = std::fs::read_to_string(&path).unwrap();
            text.push_str(
                "\n[[rule]]\nkind = \"localhost\"\nport = 5432\ndecision = \"allow\"\n\
                 source = \"human\"\ncreated = 2026-11-22T13:00:00Z\n",
            );
            std::fs::write(&path, text).unwrap();

            let count = store
                .update(&key("claude"), |set| {
                    set.rules.push(sample("x").rules.remove(0));
                    set.rules.len()
                })
                .unwrap();
            assert_eq!(count, 4);
            assert_eq!(store.load(&key("claude")).unwrap().rules.len(), 4);
        }

        #[test]
        fn parallel_updates_lose_no_rule() {
            let (_root, store) = rules_fixture();
            let threads: Vec<_> = (1..=16_u16)
                .map(|port| {
                    let store = store.clone();
                    std::thread::spawn(move || {
                        store
                            .update(&key("claude"), |set| {
                                set.rules.push(Rule {
                                    target: Target::Localhost(
                                        std::num::NonZeroU16::new(port).unwrap(),
                                    ),
                                    decision: Decision::Allow,
                                    source: Source::Human,
                                    created: SystemTime::UNIX_EPOCH,
                                });
                            })
                            .unwrap();
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }
            assert_eq!(store.load(&key("claude")).unwrap().rules.len(), 16);
        }

        #[test]
        fn a_file_with_a_name_that_is_not_a_key_or_not_a_file_is_skipped() {
            let (root, store) = rules_fixture();
            let path = store.save(&sample("claude")).unwrap();
            let dir = path.parent().unwrap();
            std::fs::write(dir.join(".hidden.toml"), "").unwrap();
            std::fs::write(dir.join("notes.txt"), "").unwrap();
            std::fs::create_dir(dir.join("adir.toml")).unwrap();
            let target = root.path().join("t.toml");
            std::fs::write(&target, sample("linked").to_toml().unwrap()).unwrap();
            std::os::unix::fs::symlink(&target, dir.join("linked.toml")).unwrap();
            assert_eq!(store.keys().unwrap(), vec![key("claude")]);
        }
    }
}
