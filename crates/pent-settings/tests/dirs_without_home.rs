//! The pent directories when the environment gives no location.
//!
//! [`PentDirs::from_env`] and [`TrustStore::default_path`] read the
//! environment of the process. A test must not change the environment of
//! the test process, because that races the other tests. Each test here
//! runs the helper program `pent-dirs-probe` in a child process with the
//! environment that the test wants.
//!
//! The helper prints one line for each location: `config=`, `state=` and
//! `trust=`, with a path or the word `none`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// The helper program, from Cargo.
const PROBE: &str = env!("CARGO_BIN_EXE_pent-dirs-probe");

/// A user identifier that the user database of a test machine does not
/// have. The test maps the user of the process to it in a new user
/// namespace, so that the C library finds no home directory.
#[cfg(target_os = "linux")]
const UNKNOWN_UID: u32 = 61_234;

/// The variables that give a location to pent.
#[cfg(target_os = "linux")]
const LOCATION_VARS: [&str; 3] = ["HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"];

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Run the helper and give the three lines as a map.
fn run(command: &mut Command) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let out = command.output()?;
    if !out.status.success() {
        return Err(format!(
            "the helper failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let text = String::from_utf8(out.stdout)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect())
}

/// The home directory gives every location.
#[test]
fn the_locations_follow_the_home_directory() -> TestResult {
    let home = tempfile::tempdir()?;
    let fields = run(Command::new(PROBE).env_clear().env("HOME", home.path()))?;
    assert_eq!(
        fields.get("config").map(Path::new),
        Some(home.path().join(".config/pent").as_path())
    );
    assert_eq!(
        fields.get("state").map(Path::new),
        Some(home.path().join(".local/state/pent").as_path())
    );
    assert_eq!(
        fields.get("trust").map(Path::new),
        Some(home.path().join(".config/pent/trusted.toml").as_path())
    );
    Ok(())
}

/// An absolute XDG variable wins over the home directory.
#[test]
fn an_absolute_xdg_variable_wins_over_the_home_directory() -> TestResult {
    let root = tempfile::tempdir()?;
    let fields = run(Command::new(PROBE)
        .env_clear()
        .env("HOME", root.path().join("home"))
        .env("XDG_CONFIG_HOME", root.path().join("cfg"))
        .env("XDG_STATE_HOME", root.path().join("state")))?;
    assert_eq!(
        fields.get("config").map(Path::new),
        Some(root.path().join("cfg/pent").as_path())
    );
    assert_eq!(
        fields.get("state").map(Path::new),
        Some(root.path().join("state/pent").as_path())
    );
    assert_eq!(
        fields.get("trust").map(Path::new),
        Some(root.path().join("cfg/pent/trusted.toml").as_path())
    );
    Ok(())
}

/// With no home directory and no XDG variable, every location is `none`.
///
/// The C library answers with the home directory of the user database when
/// `HOME` is not set, thus the test also needs a user that the database does
/// not have. The test makes a user namespace and maps the user of the
/// process to [`UNKNOWN_UID`].
///
/// The test runs only on Linux, and only when the machine has `unshare` and
/// permits a user namespace. It prints a line and ends when it cannot make
/// the namespace: the result would then say nothing.
#[cfg(target_os = "linux")]
#[test]
fn no_home_and_no_xdg_variable_give_none() -> TestResult {
    let mut command = Command::new("unshare");
    command
        .arg("--user")
        .arg(format!("--map-user={UNKNOWN_UID}"))
        .arg("--")
        .arg(PROBE);
    for var in LOCATION_VARS {
        command.env_remove(var);
    }
    let fields = match run(&mut command) {
        Ok(fields) => fields,
        Err(e) => {
            println!("SKIP: this machine cannot make a user namespace: {e}");
            return Ok(());
        }
    };
    if fields.get("config").map(String::as_str) != Some("none") {
        println!("SKIP: the user database has an entry for the user {UNKNOWN_UID}: {fields:?}");
        return Ok(());
    }
    assert_eq!(fields.get("state").map(String::as_str), Some("none"));
    assert_eq!(fields.get("trust").map(String::as_str), Some("none"));
    Ok(())
}
