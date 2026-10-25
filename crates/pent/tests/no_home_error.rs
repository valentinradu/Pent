//! Pent with no home directory and no XDG variable.
//!
//! Pent keeps its profiles and its trust store in the config directory. When
//! the environment gives no location, [`pent_settings::PentDirs::from_env`]
//! answers `None`, and pent must print a clear error and end with the status
//! 1. It must not panic.
//!
//! The C library answers with the home directory of the user database when
//! `HOME` is not set, thus the test also needs a user that the database does
//! not have. The test makes a user namespace and maps the user of the
//! process to [`UNKNOWN_UID`]. This works only on Linux.

#![cfg(target_os = "linux")]

use std::process::Command;

/// The pent binary, from Cargo.
const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// A user identifier that the user database of a test machine does not have.
const UNKNOWN_UID: u32 = 61_234;

/// The variables that give a location to pent.
const LOCATION_VARS: [&str; 3] = ["HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"];

/// Run `pent <args>` with no location in the environment and with a user
/// that the user database does not have.
fn pent_without_a_home(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut command = Command::new("unshare");
    command
        .arg("--user")
        .arg(format!("--map-user={UNKNOWN_UID}"))
        .arg("--")
        .arg(PENT)
        .args(args);
    for var in LOCATION_VARS {
        command.env_remove(var);
    }
    command.output()
}

/// Each command that needs the store says what is wrong and ends with the
/// status 1.
#[test]
fn pent_reports_a_clear_error_and_does_not_panic() {
    let Ok(probe) = pent_without_a_home(&["profile", "list"]) else {
        println!("SKIP: this machine has no `unshare` program");
        return;
    };
    let stderr = String::from_utf8_lossy(&probe.stderr).to_string();
    if stderr.contains("unshare failed") || stderr.contains("Operation not permitted") {
        println!("SKIP: this machine does not permit a user namespace: {stderr}");
        return;
    }
    if probe.status.success() {
        println!("SKIP: the user database has an entry for the user {UNKNOWN_UID}");
        return;
    }

    for args in [
        vec!["profile", "list"],
        vec!["profile", "show", "tool"],
        vec!["untrust", "tool"],
    ] {
        let out = pent_without_a_home(&args);
        assert!(out.is_ok(), "cannot run pent {args:?}: {out:?}");
        let Ok(out) = out else { return };
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("panicked"),
            "pent {args:?} panicked: {stderr}"
        );
        assert_eq!(out.status.code(), Some(1), "pent {args:?}: {stderr}");
        assert!(
            stderr.contains("home directory is not available"),
            "pent {args:?} does not say why: {stderr}"
        );
    }
}
