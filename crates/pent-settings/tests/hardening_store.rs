//! Hardening tests for the profile store and the trust store.
//!
//! Each test uses a new temporary directory for the config and the state
//! directories, thus no test reads or changes the files of the user. The
//! tests use only the public API of `pent-settings`.
//!
//! A test with `#[ignore = "OPEN H-<n>: ..."]` shows a property that does not
//! hold now. Its assertion fails. See `docs/security/watch-and-profiles.md`.

use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{symlink, PermissionsExt as _};
use std::path::{Path, PathBuf};

use pent_profile::{
    classify, guard_rules, guard_rules_with, FsOp, GuardAccess, GuardClass, NetProtocol, Outcome,
    ProcessInfo, ProfileName, WatchEvent,
};
use pent_settings::{PentDirs, ProfileStatus, ProfileStore, TrustStatus, TrustStore, WatchRunMode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DRAFT: &str = "# draft\n[filesystem]\nread = [\"~/.gitconfig\"] # read by git\n\n\
                     [network]\ndomains = [\"api.example.com\"]\n";

struct Fixture {
    root: tempfile::TempDir,
    store: ProfileStore,
}

impl Fixture {
    fn new() -> std::io::Result<Self> {
        let root = tempfile::tempdir()?;
        let store = ProfileStore::new(PentDirs {
            config: root.path().join("config/pent"),
            state: root.path().join("state/pent"),
        });
        Ok(Self { root, store })
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }
}

fn name(s: &str) -> Result<ProfileName, pent_profile::ProfileNameError> {
    s.parse()
}

fn mode(path: &Path) -> std::io::Result<u32> {
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o777)
}

fn fs_event(path: PathBuf, process: &str) -> WatchEvent {
    WatchEvent::Fs {
        op: FsOp::Read,
        path,
        process: ProcessInfo {
            pid: 1,
            name: process.to_string(),
        },
        outcome: Outcome::Allowed,
    }
}

// ── Modes ────────────────────────────────────────────────────────────────────

#[test]
fn p5_store_files_are_0600_and_new_dirs_are_0700() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let draft = f.store.write_draft(&n, DRAFT)?;
    assert_eq!(mode(&draft)?, 0o600, "draft");
    let profile = f.store.trust(&n)?;
    assert_eq!(mode(&profile)?, 0o600, "profile");
    assert_eq!(mode(&f.store.dirs().trust_store())?, 0o600, "trust store");

    let mut log = f.store.start_watch_run(&n, WatchRunMode::Replace)?;
    log.append(&fs_event(PathBuf::from("/a"), "p"))?;
    assert_eq!(mode(log.path())?, 0o600, "watch log");
    let mut denied = f.store.denied_log(&n)?;
    denied.append(&fs_event(PathBuf::from("/a"), "p"))?;
    assert_eq!(mode(denied.path())?, 0o600, "denied log");

    for dir in [
        "config/pent",
        "config/pent/profiles",
        "state/pent",
        "state/pent/drafts",
        "state/pent/watch",
        "state/pent/watch/tool",
        "state/pent/denied",
    ] {
        assert_eq!(mode(&f.path(dir))?, 0o700, "{dir}");
    }
    Ok(())
}

/// `TrustStore::save` is public. When it makes the parent directory, the
/// directory must get the mode 0700, as the profile store does.
#[test]
fn p5_trust_store_save_makes_a_private_dir() -> TestResult {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("new");
    let store = TrustStore::empty(dir.join("trusted.toml"));
    store.save()?;
    assert_eq!(mode(&dir)?, 0o700);
    Ok(())
}

// ── Symbolic links ───────────────────────────────────────────────────────────

/// Make a victim file and return its path and content.
fn victim(f: &Fixture) -> std::io::Result<(PathBuf, &'static str)> {
    let path = f.path("victim.txt");
    let text = "do not change\n";
    fs::write(&path, text)?;
    Ok((path, text))
}

#[test]
fn p5_symlink_at_draft_path_is_replaced_not_followed() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let (victim, text) = victim(&f)?;
    let draft = f.store.draft_path(&n);
    fs::create_dir_all(draft.parent().ok_or("no parent")?)?;
    symlink(&victim, &draft)?;
    f.store.write_draft(&n, DRAFT)?;
    assert_eq!(fs::read_to_string(&victim)?, text);
    assert!(fs::symlink_metadata(&draft)?.file_type().is_file());
    Ok(())
}

#[test]
fn p5_symlink_at_profile_path_is_replaced_not_followed() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let (victim, text) = victim(&f)?;
    let profile = f.store.profile_path(&n);
    fs::create_dir_all(profile.parent().ok_or("no parent")?)?;
    symlink(&victim, &profile)?;
    f.store.write_draft(&n, DRAFT)?;
    f.store.trust(&n)?;
    assert_eq!(fs::read_to_string(&victim)?, text);
    assert!(fs::symlink_metadata(&profile)?.file_type().is_file());
    assert_eq!(fs::read_to_string(&profile)?, DRAFT);
    Ok(())
}

#[test]
fn p5_symlink_at_trust_store_path_is_replaced_not_followed() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let (victim, _) = victim(&f)?;
    let trust = f.store.dirs().trust_store();
    fs::create_dir_all(trust.parent().ok_or("no parent")?)?;
    // The victim must parse as a trust store, else `open` fails first.
    fs::write(&victim, "")?;
    symlink(&victim, &trust)?;
    f.store.write_draft(&n, DRAFT)?;
    f.store.trust(&n)?;
    assert_eq!(fs::read_to_string(&victim)?, "");
    assert!(fs::symlink_metadata(&trust)?.file_type().is_file());
    Ok(())
}

/// The atomic write uses the temporary file `.<name>.<pid>.tmp` in the same
/// directory. It opens it without `O_EXCL` and without `O_NOFOLLOW`, so a
/// symbolic link at that name sends the write (and the `chmod 0600`) to the
/// target of the link.
#[test]
fn p5_symlink_at_temporary_file_is_not_followed() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let (victim, text) = victim(&f)?;
    let draft = f.store.draft_path(&n);
    let dir = draft.parent().ok_or("no parent")?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".tool.toml.{}.tmp", std::process::id()));
    symlink(&victim, &tmp)?;
    let result = f.store.write_draft(&n, DRAFT);
    assert_eq!(
        fs::read_to_string(&victim)?,
        text,
        "the write went through the link (result {result:?})"
    );
    Ok(())
}

/// The event logs are opened with `O_APPEND | O_CREAT` and no
/// `O_NOFOLLOW`. A symbolic link at the log path makes pent append JSON to
/// the target.
#[test]
fn p5_symlink_at_event_log_is_not_followed() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let (victim, text) = victim(&f)?;
    let denied = f.store.denied_path(&n);
    fs::create_dir_all(denied.parent().ok_or("no parent")?)?;
    symlink(&victim, &denied)?;
    if let Ok(mut log) = f.store.denied_log(&n) {
        // An error is the safe result; only a success can change the victim.
        let _ = log.append(&fs_event(PathBuf::from("/x"), "p"));
    }
    assert_eq!(fs::read_to_string(&victim)?, text);
    Ok(())
}

// ── Trust ────────────────────────────────────────────────────────────────────

#[test]
fn p5_trust_records_the_hash_of_the_moved_bytes() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    // Bytes that a text editor can change without a visible change.
    let draft_text = format!("{DRAFT}# trailing spaces   \r\n");
    let draft_text = draft_text.replace("\r\n", "\n");
    f.store.write_draft(&n, &draft_text)?;
    let profile = f.store.trust(&n)?;
    let bytes = fs::read(&profile)?;
    assert_eq!(bytes, draft_text.as_bytes(), "trust moves the draft bytes");
    let trust = TrustStore::open(f.store.dirs().trust_store())?;
    assert_eq!(trust.status(&profile, &bytes), TrustStatus::Trusted);
    assert!(
        !f.store.draft_path(&n).exists(),
        "the draft goes away after trust"
    );
    let loaded = f.store.load(&n)?;
    assert_eq!(loaded.status, ProfileStatus::Trusted);
    assert!(loaded.doc.is_some());
    Ok(())
}

#[test]
fn p5_profile_that_changed_after_trust_is_not_applied() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    f.store.write_draft(&n, DRAFT)?;
    let profile = f.store.trust(&n)?;
    let original = fs::read(&profile)?;
    let changes: Vec<Vec<u8>> = vec![
        [original.as_slice(), b" "].concat(),
        [original.as_slice(), b"\n"].concat(),
        [original.as_slice(), b"# comment\n"].concat(),
        original
            .get(..original.len().saturating_sub(1))
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
        String::from_utf8_lossy(&original)
            .replace("api.example.com", "*.example.com")
            .into_bytes(),
    ];
    for changed in changes {
        fs::write(&profile, &changed)?;
        let loaded = f.store.load(&n)?;
        assert_eq!(loaded.status, ProfileStatus::Changed, "{changed:?}");
        assert!(loaded.doc.is_none(), "pent parses a changed profile");
    }
    // The same bytes again: trusted again.
    fs::write(&profile, &original)?;
    assert_eq!(f.store.load(&n)?.status, ProfileStatus::Trusted);
    Ok(())
}

/// A profile that is replaced by a symbolic link to another file with other
/// bytes is not trusted.
#[test]
fn p5_profile_replaced_by_a_symlink_is_not_applied() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    f.store.write_draft(&n, DRAFT)?;
    let profile = f.store.trust(&n)?;
    let other = f.path("other.toml");
    fs::write(&other, "[network]\ndomains = [\"*.evil.example\"]\n")?;
    fs::remove_file(&profile)?;
    symlink(&other, &profile)?;
    let loaded = f.store.load(&n)?;
    assert_ne!(loaded.status, ProfileStatus::Trusted);
    assert!(loaded.doc.is_none());
    Ok(())
}

/// `pent trust NAME` shows the draft text, asks, then trusts it.
/// `ProfileStore::trust` reads the draft again, so a change between the two
/// reads goes into the profile without the user seeing it.
/// `ProfileStore::trust_exact` trusts only the bytes that the caller shows.
#[test]
fn p5_trust_moves_the_bytes_that_the_user_saw() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    f.store.write_draft(&n, DRAFT)?;
    let shown = f.store.read_draft_text(&n)?.ok_or("no draft")?;
    // Another process changes the draft while the user reads it.
    fs::write(
        f.store.draft_path(&n),
        "[network]\ndomains = [\"*.evil.example\"]\n",
    )?;
    let profile = f.store.trust_exact(&n, shown.as_bytes())?;
    assert_eq!(fs::read_to_string(&profile)?, shown);
    // The profile is trusted, and the draft is gone.
    assert_eq!(f.store.load(&n)?.status, ProfileStatus::Trusted);
    assert!(!f.store.draft_path(&n).exists());
    Ok(())
}

// ── The guard and the XDG directories ────────────────────────────────────────

/// The guard protects the files of pent at `~/.config/pent` and
/// `~/.local/state/pent`. Pent uses `$XDG_CONFIG_HOME` and `$XDG_STATE_HOME`
/// when they are set. Then the profiles, the trust store and the drafts are
/// in other directories, and the guard does not block writes to them.
#[test]
fn p5_guard_protects_pent_files_in_xdg_dirs() -> TestResult {
    let home = Path::new("/home/u");
    let dirs = PentDirs {
        config: PathBuf::from("/home/u/dotfiles/config/pent"),
        state: PathBuf::from("/home/u/dotfiles/state/pent"),
    };
    let store = ProfileStore::new(dirs.clone());
    let n = name("tool")?;
    // `pent watch` gives the real pent directories to the guard.
    let rules = guard_rules_with(home, &[dirs.config.clone(), dirs.state.clone()]);
    // The default rules alone do not cover these paths.
    assert_eq!(
        classify(&guard_rules(home), &dirs.trust_store(), GuardAccess::Write),
        None
    );
    for path in [
        dirs.trust_store(),
        store.profile_path(&n),
        store.draft_path(&n),
        store.denied_path(&n),
    ] {
        assert_eq!(
            classify(&rules, &path, GuardAccess::Write),
            Some(GuardClass::PentFiles),
            "{}",
            path.display()
        );
    }
    Ok(())
}

// ── Event logs ───────────────────────────────────────────────────────────────

#[test]
fn p5_event_logs_keep_one_event_per_line() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let events = vec![
        fs_event(PathBuf::from("/home/u/a\nb"), "p\nq"),
        fs_event(PathBuf::from("/home/u/\r\n{\"type\":\"fs\"}\n"), "\u{2028}"),
        WatchEvent::UnixConnect {
            target: "@x\n{\"type\":\"dns\",\"name\":\"evil.example\"}".to_string(),
            process: ProcessInfo {
                pid: 2,
                name: "\u{1b}[2J".to_string(),
            },
            outcome: Outcome::Allowed,
        },
        WatchEvent::Dns {
            name: "a\nb.example".to_string(),
            qtype: "A\n".to_string(),
            outcome: Outcome::Denied,
        },
        WatchEvent::Connect {
            host: "h\n".to_string(),
            port: 443,
            protocol: NetProtocol::Socks5,
            outcome: Outcome::Blocked(GuardClass::Credential),
        },
    ];
    let mut log = f.store.start_watch_run(&n, WatchRunMode::Replace)?;
    for e in &events {
        log.append(e)?;
    }
    let text = fs::read_to_string(log.path())?;
    assert_eq!(text.lines().count(), events.len(), "{text}");
    assert_eq!(f.store.read_watch_events(&n)?, events);

    let mut denied = f.store.denied_log(&n)?;
    for e in &events {
        denied.append(e)?;
    }
    assert_eq!(f.store.read_denied(&n)?, events);
    Ok(())
}

/// The Linux recorder reads raw path bytes, so a path can be non-UTF-8.
/// `serde_json` cannot encode such a `PathBuf`, so `EventLog::append` fails.
/// `pent watch` then stops to write events for the rest of the run (it sets
/// `write_failed`), so one crafted `open()` hides all later accesses,
/// blocked attempts too, from the review.
#[test]
fn p5_event_log_accepts_non_utf8_paths() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let mut log = f.store.start_watch_run(&n, WatchRunMode::Replace)?;
    let bad = PathBuf::from(std::ffi::OsString::from_vec(b"/home/u/\xff\xfe".to_vec()));
    let result = log.append(&fs_event(bad, "p"));
    assert!(result.is_ok(), "{result:?}");
    Ok(())
}

/// A partial line (a pent process that stopped in a write) does not hide
/// the other events.
#[test]
fn p5_event_log_skips_a_broken_line() -> TestResult {
    let f = Fixture::new()?;
    let n = name("tool")?;
    let mut log = f.store.start_watch_run(&n, WatchRunMode::Replace)?;
    let good = fs_event(PathBuf::from("/a"), "p");
    log.append(&good)?;
    let path = log.path().to_path_buf();
    drop(log);
    let mut text = fs::read_to_string(&path)?;
    text.push_str("{\"type\":\"fs\",\"op\":\n");
    text.push_str(&good.to_json_line()?);
    text.push('\n');
    fs::write(&path, text)?;
    assert_eq!(f.store.read_watch_events(&n)?, vec![good.clone(), good]);
    Ok(())
}

// ── Names ────────────────────────────────────────────────────────────────────

/// The store builds each path from a `ProfileName`, so a path stays in its
/// directory.
#[test]
fn p5_store_paths_stay_in_their_directories() -> TestResult {
    let f = Fixture::new()?;
    for raw in ["a", "a.b", "a-b_c", "x.toml"] {
        let n = name(raw)?;
        for (path, dir) in [
            (f.store.profile_path(&n), "config/pent/profiles"),
            (f.store.draft_path(&n), "state/pent/drafts"),
            (f.store.watch_dir(&n), "state/pent/watch"),
            (f.store.denied_path(&n), "state/pent/denied"),
        ] {
            assert_eq!(path.parent(), Some(f.path(dir).as_path()), "{raw}");
        }
    }
    for bad in ["..", "../x", "a/b", ".x", "a\nb", "a\u{1b}"] {
        assert!(bad.parse::<ProfileName>().is_err(), "{bad:?}");
    }
    Ok(())
}

/// A file in the store with a name that is not a valid profile name does
/// not show in the list.
#[test]
fn p5_list_skips_files_with_invalid_names() -> TestResult {
    let f = Fixture::new()?;
    let profiles = f.path("config/pent/profiles");
    fs::create_dir_all(&profiles)?;
    for file in [".hidden.toml", "a b.toml", "x\u{1b}[2J.toml", "ok.toml"] {
        fs::write(profiles.join(file), "")?;
    }
    let names: Vec<String> = f
        .store
        .list()?
        .into_iter()
        .map(|e| e.name.as_str().to_string())
        .collect();
    assert_eq!(names, vec!["ok"]);
    Ok(())
}
