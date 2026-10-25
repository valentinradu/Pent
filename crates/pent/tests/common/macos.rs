//! Helpers for the macOS end-to-end tests.
//!
//! The helpers drive the two macOS tools that the sandbox uses: the Seatbelt
//! front end `/usr/bin/sandbox-exec` and the unified log `/usr/bin/log`.
//!
//! Nobody has run the macOS backend of pent yet. A failure must therefore be
//! easy to read: each helper returns the full output, and the tests print the
//! profile and the log lines in the message of the assertion.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use super::e2e::{skip, BoxError};

/// Return true if every path of `files` is an executable file. Else print
/// the skip reason for `test` and return false.
///
/// The macOS tools have fixed paths, so the tests name them directly
/// instead of looking in `PATH`.
pub fn have_files(test: &str, files: &[&str]) -> bool {
    let missing: Vec<&str> = files
        .iter()
        .copied()
        .filter(|f| {
            !std::fs::metadata(f).is_ok_and(|m| {
                m.is_file()
                    && std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o111 != 0
            })
        })
        .collect();
    if missing.is_empty() {
        return true;
    }
    skip(
        test,
        &format!("not an executable file: {}", missing.join(", ")),
    )
}

/// The Seatbelt front end.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The unified log tool.
pub const LOG: &str = "/usr/bin/log";

/// The tool that writes a line into the unified log.
pub const LOGGER: &str = "/usr/bin/logger";

/// Write `profile` to a new file below `dir` and return its path.
///
/// `sandbox-exec -p` takes the profile on the command line. A long profile
/// is over the argument limit, so the tests use `-f` with a file.
///
/// # Errors
/// Returns an error if the file cannot be written.
pub fn write_profile(dir: &Path, name: &str, profile: &str) -> std::io::Result<PathBuf> {
    let path = dir.join(format!("{name}.sb"));
    let mut file = std::fs::File::create(&path)?;
    file.write_all(profile.as_bytes())?;
    file.sync_all()?;
    Ok(path)
}

/// Run `argv` under `profile` with `sandbox-exec -f` and return the output.
///
/// # Errors
/// Returns an error if the profile cannot be written or `sandbox-exec`
/// cannot start.
pub fn sandbox_exec(dir: &Path, profile: &str, argv: &[&str]) -> Result<Output, BoxError> {
    let path = write_profile(dir, "profile", profile)?;
    let out = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .args(argv)
        .stdin(Stdio::null())
        .output()?;
    Ok(out)
}

/// Start `argv` under `profile` with `sandbox-exec -f` and return the child.
///
/// The caller must kill and reap the child.
///
/// # Errors
/// Returns an error if the profile cannot be written or `sandbox-exec`
/// cannot start.
pub fn sandbox_exec_spawn(dir: &Path, profile: &str, argv: &[&str]) -> Result<Child, BoxError> {
    let path = write_profile(dir, "noise", profile)?;
    let child = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child)
}

/// Write `message` into the unified log with `/usr/bin/logger`.
///
/// # Errors
/// Returns an error if `logger` cannot start or exits with an error.
pub fn log_write(message: &str) -> Result<(), BoxError> {
    let out = Command::new(LOGGER)
        .arg("--")
        .arg(message)
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "logger failed ({:?}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

/// The lines of the unified log of the last `window` that contain `marker`.
///
/// `window` has the form that `log show --last` takes, for example `2m`.
/// Returns an empty string when the log has no such line.
///
/// # Errors
/// Returns an error if `log show` cannot start.
pub fn log_lines(window: &str, marker: &str) -> Result<String, BoxError> {
    let predicate = format!("eventMessage CONTAINS \"{marker}\"");
    let out = Command::new(LOG)
        .args(["show", "--last", window, "--style", "syslog", "--predicate"])
        .arg(&predicate)
        .stdin(Stdio::null())
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Wait until the unified log holds a line with `marker`, or until
/// `timeout` passes. Return the lines (empty when none arrived).
///
/// The unified log delivers a line with a delay, so a test must wait.
///
/// # Errors
/// Returns an error if `log show` cannot start.
pub fn wait_for_log_line(
    window: &str,
    marker: &str,
    timeout: Duration,
) -> Result<String, BoxError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let lines = log_lines(window, marker)?;
        if !lines.trim().is_empty() {
            return Ok(lines);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(String::new());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A profile that denies each read below `dir` and logs the denial.
///
/// A second, unrelated process runs under this profile. Its denials go to
/// the same unified log as the denials of pent, so the tests use it to prove
/// that the reader of pent keeps only the processes of its own run.
#[must_use]
pub fn deny_reads_profile(dir: &Path) -> String {
    format!(
        "(version 1)\n(allow default)\n(deny file-read-data (subpath \"{}\"))\n",
        dir.display()
    )
}
