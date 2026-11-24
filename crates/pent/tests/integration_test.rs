//! CLI integration tests for `pent`.
//!
//! These tests invoke the compiled `pent` binary as a subprocess and verify
//! its behavior end-to-end. Each test operates in an isolated temp directory.
//!
//! # Running
//!
//! ```bash
//! cargo test --test integration_test
//! ```
//!
//! The tests of the Linux sandbox (filesystem containment, network
//! isolation) are in `e2e_linux.rs`.

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

use common::{Xdg, PENT, TEST_PROFILE};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ============================================================================
// Infrastructure
// ============================================================================

/// Invoke `pent` with the given arguments in `cwd` and return the full Output.
///
/// `XDG_CONFIG_HOME` and `XDG_STATE_HOME` point into `cwd/.test-home`, thus
/// the test does not read or change the real user config.
#[allow(clippy::panic)] // infrastructure helper: spawn failure is a hard test setup error
fn run_pent(cwd: &Path, args: &[&str]) -> Output {
    let home = cwd.join(".test-home");
    let runtime =
        common::runtime_dir().unwrap_or_else(|e| panic!("cannot make a runtime directory: {e}"));
    common::use_runtime(&mut Command::new(PENT), &runtime)
        .args(args)
        .current_dir(cwd)
        .env_remove("PENT_LOG") // keep test output clean
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn pent binary: {e}"))
}

/// Assert exit-success and return stdout as a String.
#[track_caller]
fn expect_success(out: &Output) -> String {
    assert!(
        out.status.success(),
        "pent exited {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Assert that the command exited with a non-zero status.
#[track_caller]
fn expect_failure(out: &Output) {
    assert!(
        !out.status.success(),
        "Expected pent to fail but it succeeded\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Invoke `pent run --key pent-test [extra_args] -- [cmd_args]` in
/// `workspace`.
///
/// The key has no rule file, in temporary XDG directories. `HOME` stays the
/// real home directory, so that the tests can place files outside the
/// sandbox defaults.
#[allow(clippy::panic)] // infrastructure helper: setup failure is a hard test setup error
fn sandboxed_run(workspace: &Path, extra_args: &[String], cmd_args: &[&str]) -> Output {
    let xdg = Xdg::new().unwrap_or_else(|e| panic!("cannot make the XDG directories: {e}"));
    let mut args: Vec<String> = vec![
        "run".into(),
        "-w".into(),
        "--key".into(),
        TEST_PROFILE.into(),
    ];
    args.extend_from_slice(extra_args);
    args.push("--".into());
    for a in cmd_args {
        args.push((*a).to_string());
    }
    xdg.apply(&mut Command::new(PENT))
        .args(&args)
        .current_dir(workspace)
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn pent: {e}"))
}

// ============================================================================
// A. Config command tests — no sandbox execution needed
// ============================================================================

#[test]
fn test_config_init_creates_global_config() -> TestResult {
    let dir = TempDir::new()?;
    let out = run_pent(dir.path(), &["config", "init"]);
    expect_success(&out);

    let config_path = dir.path().join(".test-home/.config/pent/pent.toml");
    assert!(config_path.exists(), "pent.toml was not created");
    assert!(
        !dir.path().join(".pent").exists(),
        "pent has no project config now"
    );
    let contents = fs::read_to_string(&config_path)?;
    assert!(
        toml::from_str::<toml::Value>(&contents).is_ok(),
        "Generated config is not valid TOML:\n{contents}"
    );
    Ok(())
}

#[test]
fn test_config_init_fails_if_already_exists() -> TestResult {
    let dir = TempDir::new()?;
    // First init should succeed
    expect_success(&run_pent(dir.path(), &["config", "init"]));
    // Second init should fail with a clear error
    let out = run_pent(dir.path(), &["config", "init"]);
    expect_failure(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("Config file"),
        "Expected 'already exists' in stderr, got: {stderr}"
    );
    Ok(())
}

#[test]
fn test_config_show_toml_is_valid() -> TestResult {
    let dir = TempDir::new()?;
    expect_success(&run_pent(dir.path(), &["config", "init"]));

    let out = run_pent(dir.path(), &["config", "show", "--format", "toml"]);
    let stdout = expect_success(&out);
    assert!(
        toml::from_str::<toml::Value>(&stdout).is_ok(),
        "config show --format toml is not valid TOML:\n{stdout}"
    );
    Ok(())
}

#[test]
fn test_config_show_json_is_valid() -> TestResult {
    let dir = TempDir::new()?;
    expect_success(&run_pent(dir.path(), &["config", "init"]));

    let out = run_pent(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "config show --format json is not valid JSON:\n{stdout}"
    );
    Ok(())
}

#[test]
fn test_config_show_json_has_sandbox_and_proxy_keys() -> TestResult {
    let dir = TempDir::new()?;
    expect_success(&run_pent(dir.path(), &["config", "init"]));

    let out = run_pent(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout)?;

    assert!(json.get("sandbox").is_some(), "Missing 'sandbox' key");
    assert!(json.get("proxy").is_some(), "Missing 'proxy' key");
    Ok(())
}

#[test]
fn test_config_show_without_config_file_uses_defaults() -> TestResult {
    // No config init — should still produce valid output using defaults
    let dir = TempDir::new()?;
    let out = run_pent(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert!(json.get("sandbox").is_some());
    assert!(json.get("proxy").is_some());
    Ok(())
}

// ============================================================================
// B. Check command
// ============================================================================

#[test]
fn test_check_reports_platform() -> TestResult {
    // `pent check` should always print platform info even when sandboxing
    // is unavailable. The exit status may be non-zero in restricted envs.
    let dir = TempDir::new()?;
    let out = run_pent(dir.path(), &["check"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("platform"),
        "Expected 'platform' in check stderr, got: {stderr}"
    );
    Ok(())
}

// ============================================================================
// K. Run — --execute flag
// ============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_execute_flag_allows_binary() -> TestResult {
    // Only runs when Landlock is enforcing; otherwise meaningless.
    // We skip silently if unavailable.
    //
    // execute_access is ReadDir | Execute (no ReadFile), so the binary must
    // also be listed under --read for execve to succeed. The test finds
    // `true` in PATH: some systems (NixOS) do not have /usr/bin/true.
    let Some(bin) = common::e2e::which("true") else {
        common::e2e::skip("test_execute_flag_allows_binary", "true is not in PATH");
        return Ok(());
    };
    // Run the path in PATH: on NixOS it is a link to a multi-call binary,
    // which needs its name. Allow the directory of the link and of the
    // target.
    let real = bin.canonicalize()?;
    let dir = bin.parent().ok_or("the binary has no directory")?;
    let real_dir = real.parent().ok_or("the binary has no directory")?;
    let bin = bin.to_str().ok_or("the path is not UTF-8")?;
    let dir = dir.to_str().ok_or("the path is not UTF-8")?;
    let real_dir = real_dir.to_str().ok_or("the path is not UTF-8")?;
    let ws = TempDir::new()?;
    let out = sandboxed_run(
        ws.path(),
        &[
            "--network",
            "unrestricted",
            "--execute",
            dir,
            "--read",
            dir,
            "--execute",
            real_dir,
            "--read",
            real_dir,
            "--read",
            "/usr/lib",
            "--read",
            "/usr/lib64",
            "--read",
            "/lib",
            "--read",
            "/lib64",
        ]
        .map(String::from),
        &[bin],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Skip if the sandbox itself cannot be set up (overlay requires privileges).
    if !out.status.success()
        && (stderr.contains("Operation not permitted")
            || stderr.contains("overlayfs")
            || stderr.contains("user namespace"))
    {
        common::e2e::skip(
            "test_execute_flag_allows_binary",
            &format!("the overlay sandbox is not available: {stderr}"),
        );
        return Ok(());
    }
    assert!(
        out.status.success(),
        "pent --execute DIR --read DIR -- {bin} should succeed\nstderr: {stderr}",
    );
    Ok(())
}

// ============================================================================
// L. Run — no-hang smoke tests (Linux only, no root required)
//
// Each test spawns `pent run -- <binary>` and asserts the process exits within
// a short deadline.  A hung process fails the test with "timeout expired".
// The tests cover two cases the user reported:
//   • System binaries (e.g. /usr/bin/true, /usr/bin/curl) — known to work.
//   • User-local binaries (e.g. ~/.local/bin/claude) — known to hang.
// ============================================================================

#[cfg(target_os = "linux")]
mod no_hang {
    use super::*;
    use std::io::Read as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    /// Spawn `pent` with `args` in `dir`; kill it if it has not exited after
    /// `timeout_secs`.  Returns `(finished_before_deadline, stderr_text)`.
    ///
    /// `home` must be a temp dir from [`rules_home`] — it is set as `$HOME`
    /// so the real `~/.config/pent` is invisible to pent.
    /// `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `XDG_DATA_HOME` are also
    /// cleared so they cannot override the isolated home.
    /// stdout is discarded (`Stdio::null`) — we only capture stderr for
    /// diagnostics.  stderr is drained in a background thread so the child
    /// can never block on a full pipe.
    #[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // infrastructure helper: spawn/pipe failures are hard test setup errors
    fn pent_timeout(dir: &Path, home: &Path, args: &[&str], timeout_secs: u64) -> (bool, String) {
        let runtime = common::runtime_dir().unwrap();
        let mut child = common::use_runtime(&mut Command::new(PENT), &runtime)
            .args(args)
            .current_dir(dir)
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_DATA_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn pent: {e}"));

        let mut stderr_pipe = child.stderr.take().unwrap();
        let (err_tx, err_rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut buf = String::new();
            stderr_pipe.read_to_string(&mut buf).ok();
            let _ = err_tx.send(buf);
        });

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let exited = loop {
            match child.try_wait().expect("try_wait failed") {
                Some(_) => break true,
                None if Instant::now() >= deadline => {
                    child.kill().ok();
                    child.wait().ok();
                    break false;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };

        let stderr = err_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_default();
        (exited, stderr)
    }

    /// Make a temp `$HOME` with the rule file of `key`. The rule file has
    /// the allow rules `targets` (see [`common::rule_file_text`]). With no
    /// target, the home has no rule file.
    #[allow(clippy::panic)] // infrastructure helper: setup failures are hard test setup errors
    fn rules_home(key: &str, targets: &[&str]) -> TempDir {
        let home = TempDir::new().unwrap_or_else(|e| panic!("cannot make the home: {e}"));
        if !targets.is_empty() {
            let text = common::rule_file_text(targets)
                .unwrap_or_else(|e| panic!("the targets are not valid: {e}"));
            common::write_rule_file(&home.path().join(".local/state"), key, &text)
                .unwrap_or_else(|e| panic!("cannot write the rule file of {key}: {e}"));
        }
        home
    }

    /// Find `name` via `which`; fall back to `~/.local/bin/<name>`.
    fn detect_binary(name: &str) -> Option<std::path::PathBuf> {
        if let Ok(out) = Command::new("which").arg(name).output() {
            if out.status.success() {
                let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !p.is_empty() {
                    return Some(std::path::PathBuf::from(p));
                }
            }
        }
        let home = std::env::var("HOME").ok()?;
        let candidate = std::path::PathBuf::from(home).join(".local/bin").join(name);
        candidate.exists().then_some(candidate)
    }

    // ── baseline: system binaries ─────────────────────────────────────────────

    /// `true` from PATH: the simplest possible exit.  Should always finish in <2s.
    #[test]
    fn system_true_exits_quickly() -> TestResult {
        let dir = TempDir::new()?;
        let home = rules_home(TEST_PROFILE, &[]);
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &["run", "-w", "--key", TEST_PROFILE, "--", "true"],
            2,
        );
        assert!(ok, "pent run -- true timed out (2s)\nstderr:\n{stderr}");
        Ok(())
    }

    /// Same as above but with explicit --network blocked (the default).
    #[test]
    fn system_true_blocked_network_exits_quickly() -> TestResult {
        let dir = TempDir::new()?;
        let home = rules_home(TEST_PROFILE, &[]);
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &[
                "run",
                "-w",
                "--key",
                TEST_PROFILE,
                "--network",
                "blocked",
                "--",
                "true",
            ],
            2,
        );
        assert!(
            ok,
            "pent run --network blocked -- true timed out (2s)\nstderr:\n{stderr}"
        );
        Ok(())
    }

    /// `curl --version`: a real binary with shared libraries.
    #[test]
    fn system_curl_version_exits_quickly() -> TestResult {
        if common::e2e::which("curl").is_none() {
            crate::common::e2e::skip("system_curl_version_exits_quickly", "curl is not in PATH");
            return Ok(());
        }
        let dir = TempDir::new()?;
        let home = rules_home(TEST_PROFILE, &[]);
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &[
                "run",
                "-w",
                "--key",
                TEST_PROFILE,
                "--",
                "curl",
                "--version",
            ],
            2,
        );
        assert!(
            ok,
            "pent run -- curl --version timed out (2s)\nstderr:\n{stderr}"
        );
        Ok(())
    }

    // ── local binaries: --version flag ────────────────────────────────────────
    //
    // detect_binary uses the REAL $HOME (the test process's env) to locate the
    // binary.  pent itself gets a fresh empty home so it finds no global config.
    //
    // Only `claude` has a test here. The tests for `codex` and `gemini` are
    // gone: no machine that we use installs those two programs, so the six
    // tests skipped on each machine and proved nothing. A developer with one
    // of them runs the `claude` tests with the other name by hand. Install a
    // program in `e2e/Dockerfile` before you add a test for it.

    #[allow(clippy::unwrap_used)] // infrastructure helper: to_str() only fails on non-UTF-8 paths
    fn assert_version_exits_quickly(name: &str) {
        let Some(bin) = detect_binary(name) else {
            crate::common::e2e::skip_optional(name, "not in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();
        let dir = TempDir::new().unwrap();
        let home = rules_home(TEST_PROFILE, &[]);
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &["run", "-w", "--key", TEST_PROFILE, "--", bin_s, "--version"],
            5,
        );
        assert!(
            ok,
            "pent run -- {name} --version timed out (5s)\nstderr:\n{stderr}"
        );
    }

    #[test]
    fn claude_version_exits_quickly() {
        assert_version_exits_quickly("claude");
    }

    // ── with rules: a domain rule → ProxyOnly ─────────────────────────────────
    //
    // The rule file lives only in the isolated `home`.

    #[allow(clippy::unwrap_used)] // infrastructure helper: to_str()/TempDir failures are hard errors
    fn assert_proxy_mode_exits_quickly(name: &str) {
        let Some(bin) = detect_binary(name) else {
            crate::common::e2e::skip_optional(name, "not in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();

        let dir = TempDir::new().unwrap();
        let home = rules_home(TEST_PROFILE, &["domain api.anthropic.com"]);

        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &["run", "-w", "--key", TEST_PROFILE, "--", bin_s, "--version"],
            5, // the proxy setup takes much less than 1s; allow 5s total
        );
        assert!(
            ok,
            "pent run (proxy mode) -- {name} --version timed out (5s)\n\
             hint: pent may be hanging in the proxy setup or the child is \
             not routing through the proxy\nstderr:\n{stderr}",
        );
    }

    #[test]
    fn claude_proxy_mode_exits_quickly() {
        assert_proxy_mode_exits_quickly("claude");
    }

    // ── PTY-simulated interactive sessions ────────────────────────────────────
    //
    // Isolation model:
    //   HOME            = real test-process HOME  (so ~/.npm-global, ~/.local/share/claude
    //                     etc. are reachable by the sandboxed binary)
    //   XDG_STATE_HOME  = unset: the rule file of {agent} is in the temp HOME
    //   cwd             = fresh empty TempDir
    //
    // Each test writes the rules of {agent} (the paths and the domains of
    // common::agent_profile) in a temp HOME before it spawns pent, so the
    // agent's paths and network rules are active.
    //
    // Test flow:
    //   1. Wait up to 8s for PTY output that looks like a started TUI:
    //      ≥ 2 non-empty lines after stripping ANSI, no known crash markers.
    //   2. Kill pent — this test is only about verifying the TUI starts.
    //
    // Overlay teardown is tested separately by the _version_exits_quickly tests,
    // where the agent exits cleanly and pent runs full cleanup.
    //
    // A hang or error in step 1 → sandbox blocked a resource the binary needs.

    /// Spawn `pent` with a PTY.  `agent_home` is the temp HOME that contains the
    /// agent's config (written by `setup_agent_config`).  The real HOME is still
    /// inherited so binaries can find their modules (e.g. ~/.npm-global, ~/.local).
    #[allow(clippy::expect_used)] // infrastructure helper: PTY/dup failures are hard test setup errors
    fn spawn_with_pty(
        dir: &Path,
        agent_home: &Path,
        args: &[&str],
    ) -> (libc::c_int, std::process::Child, TempDir) {
        use std::os::unix::io::FromRawFd;
        use std::process::Stdio;

        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        let rc = unsafe {
            libc::openpty(
                std::ptr::addr_of_mut!(master),
                std::ptr::addr_of_mut!(slave),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());

        let slave_out = unsafe { libc::dup(slave) };
        let slave_err = unsafe { libc::dup(slave) };
        assert!(slave_out >= 0 && slave_err >= 0, "dup(slave) failed");

        let runtime = common::runtime_dir().expect("cannot make a runtime directory");
        let child = common::use_runtime(&mut Command::new(PENT), &runtime)
            .args(args)
            .current_dir(dir)
            // Use the agent_home so the rule file of {agent} is visible.
            .env("HOME", agent_home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("PENT_LOG")
            .stdin(unsafe { Stdio::from_raw_fd(slave) })
            .stdout(unsafe { Stdio::from_raw_fd(slave_out) })
            .stderr(unsafe { Stdio::from_raw_fd(slave_err) })
            .spawn()
            .expect("failed to spawn pent with PTY");

        (master, child, runtime)
    }

    /// The paths of `common::agent_profile` that name one file. Each other
    /// path is a directory.
    const AGENT_FILES: &[&str] = &[
        "~/.bashrc",
        "~/.bash_profile",
        "~/.profile",
        "~/.npmrc",
        "~/.ssh/known_hosts",
        "~/.ssh/config",
        "~/.ssh/config.d",
        "~/.gitconfig",
        "~/.claude.json",
        "~/.claude.lock",
    ];

    /// The directories of `common::agent_profile` that hold a location of
    /// the guard list. A subtree rule cannot give them (pent holds such a
    /// rule back), thus they go to the run as flags.
    const AGENT_FLAG_DIRS: &[&str] = &["~/.local/bin", "~/.config/git"];

    /// The string list `key` in the table `table` of `toml_text`.
    fn string_list(toml_text: &str, table: &str, key: &str) -> Result<Vec<String>, String> {
        let doc: toml::Value = toml::from_str(toml_text).map_err(|e| e.to_string())?;
        let Some(list) = doc.get(table).and_then(|t| t.get(key)) else {
            return Ok(Vec::new());
        };
        list.as_array()
            .ok_or_else(|| format!("{table}.{key} is not a list"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{table}.{key} has a non-string value"))
            })
            .collect()
    }

    /// Write the rules of `agent` into a fresh temp HOME: the paths and the
    /// domains of `common::agent_profile`, with `~` replaced by the home. A
    /// file gets an exact rule, a directory a subtree rule, and a directory
    /// of `AGENT_FLAG_DIRS` a flag.
    ///
    /// Returns the TempDir (keep alive) — its path is used as HOME — and
    /// the flags for the run.
    #[allow(clippy::panic)] // infrastructure helper: setup failures are hard test setup errors
    fn setup_agent_config(agent: &str) -> (TempDir, Vec<String>) {
        let home = TempDir::new().unwrap_or_else(|e| panic!("cannot make the home: {e}"));
        let profile = common::agent_profile(agent);
        let list = |table: &str, key: &str| {
            string_list(&profile, table, key).unwrap_or_else(|e| panic!("agent_profile: {e}"))
        };
        let mut targets = Vec::new();
        let mut flags = Vec::new();
        for (key, kind, flag) in [
            ("read", "read", "--read"),
            ("read_write", "write", "--write"),
            ("execute", "exec", "--execute"),
        ] {
            for value in list("filesystem", key) {
                let rel = value
                    .strip_prefix("~/")
                    .unwrap_or_else(|| panic!("the path {value:?} is not in the home"));
                let path = home.path().join(rel).display().to_string();
                if AGENT_FILES.contains(&value.as_str()) {
                    targets.push(format!("{kind} {path}"));
                } else if AGENT_FLAG_DIRS.contains(&value.as_str()) {
                    flags.extend([flag.to_string(), path]);
                } else {
                    targets.push(format!("{kind} {path}/**"));
                }
            }
        }
        for domain in list("network", "domains") {
            targets.push(format!("domain {domain}"));
        }
        let targets: Vec<&str> = targets.iter().map(String::as_str).collect();
        let text = common::rule_file_text(&targets)
            .unwrap_or_else(|e| panic!("the targets are not valid: {e}"));
        common::write_rule_file(&home.path().join(".local/state"), agent, &text)
            .unwrap_or_else(|e| panic!("cannot write the rule file of {agent}: {e}"));
        (home, flags)
    }

    /// Poll `master_fd` (non-blocking) for up to `timeout`.  Returns what arrived.
    fn drain_pty(master_fd: libc::c_int, timeout: Duration) -> Vec<u8> {
        unsafe { libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK) };
        let deadline = Instant::now() + timeout;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(master_fd, tmp.as_mut_ptr().cast(), tmp.len()) };
            #[allow(clippy::cast_sign_loss)]
            if n > 0 {
                buf.extend_from_slice(&tmp[..n as usize]);
            }
            if Instant::now() >= deadline {
                break;
            }
            if n <= 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        unsafe { libc::fcntl(master_fd, libc::F_SETFL, 0) };
        buf
    }

    /// Strip ANSI/VT escape sequences from `input`.
    ///
    /// Handles CSI (`ESC [` … letter) and OSC (`ESC ]` … BEL or `ESC \`)
    /// sequences.  Other single-char escape sequences consume one extra byte.
    fn strip_ansi(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] != 0x1b {
                out.push(input[i]);
                i += 1;
                continue;
            }
            i += 1; // consume ESC
            if i >= input.len() {
                break;
            }
            match input[i] {
                b'[' => {
                    // CSI: skip until ASCII letter (inclusive)
                    i += 1;
                    while i < input.len() && !input[i].is_ascii_alphabetic() {
                        i += 1;
                    }
                    if i < input.len() {
                        i += 1;
                    }
                }
                b']' => {
                    // OSC: skip until BEL (0x07) or ST (ESC \)
                    i += 1;
                    while i < input.len() {
                        if input[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if input[i] == 0x1b {
                            break;
                        }
                        i += 1;
                    }
                    // consume ST if present
                    if i + 1 < input.len() && input[i] == 0x1b && input[i + 1] == b'\\' {
                        i += 2;
                    }
                }
                _ => {
                    i += 1;
                } // other: skip the byte after ESC
            }
        }
        out
    }

    /// Return `true` if `output` looks like a running TUI rather than a crash.
    ///
    /// Positive signal: ≥ 2 non-empty lines after stripping ANSI (pent itself
    /// prints 1 status line; if the agent TUI rendered there will be more).
    /// Negative signal: known crash/error markers must be absent.
    fn looks_like_prompt(output: &[u8]) -> bool {
        if output.is_empty() {
            return false;
        }
        let raw = String::from_utf8_lossy(output);
        let error_markers = [
            "ERR_MODULE_NOT_FOUND",
            "Cannot find module",
            "Cannot find package",
            "ENOENT",
            "EACCES",
            "Permission denied",
            "Privilege required",
        ];
        if error_markers.iter().any(|m| raw.contains(m)) {
            return false;
        }
        let stripped = strip_ansi(output);
        let text = String::from_utf8_lossy(&stripped);
        text.lines().filter(|l| !l.trim().is_empty()).count() >= 2
    }

    /// Core PTY TUI-start test: write the rules of `{agent}` into a temp HOME,
    /// spawn `pent run --network unrestricted -- <binary>` with a PTY, and
    /// confirm the TUI renders (≥ 2 non-empty lines after ANSI strip, no crash
    /// markers).  Then kill pent.  This test is purely about sandbox access —
    /// teardown is covered by the _version_exits_quickly tests.
    #[allow(clippy::panic, clippy::unwrap_used)] // infrastructure helper: PTY test failure should panic with a clear message
    fn assert_pty_interactive(agent: &str) {
        let Some(bin) = detect_binary(agent) else {
            crate::common::e2e::skip_optional(agent, "not in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();

        let dir = TempDir::new().unwrap();
        // Write the rules; keep TempDir alive so the rule file persists.
        let (agent_home, flags) = setup_agent_config(agent);
        let mut args = vec!["run", "-w", "--key", agent, "--network", "unrestricted"];
        args.extend(flags.iter().map(String::as_str));
        args.extend(["--", bin_s]);

        let (master, mut child, _runtime) = spawn_with_pty(dir.path(), agent_home.path(), &args);

        // Step 1: wait for the TUI to render.
        //
        // The budget is generous: the test starts a real agent under a real
        // sandbox, and a loaded machine needs much longer than a quiet one.
        // A budget that flakes under load tells nothing about pent, and it
        // trains the reader to ignore a red suite. The test still fails in
        // a sensible time when the TUI never comes.
        let output = drain_pty(master, Duration::from_secs(60));
        let printable = String::from_utf8_lossy(&output);

        if !looks_like_prompt(&output) {
            child.kill().ok();
            child.wait().ok();
            unsafe { libc::close(master) };
            panic!(
                "pent run -- {agent}: the TUI gave no prompt within 60s\n\
                 output: {printable:?}\n\
                 hint: sandbox may be blocking a resource the binary needs"
            );
        }

        // TUI rendered — that's the assertion.  Kill pent and close the master.
        child.kill().ok();
        child.wait().ok();
        unsafe { libc::close(master) };
    }

    #[test]
    fn pty_claude_interactive_exits_quickly() {
        assert_pty_interactive("claude");
    }
}
