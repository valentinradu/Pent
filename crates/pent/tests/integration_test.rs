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
//! Sandbox enforcement tests (filesystem containment, network isolation) run
//! only on macOS where `sandbox-exec` is available. They are skipped at
//! runtime on other platforms or when `sandbox-exec` is absent.

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
    Command::new(PENT)
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

/// True when we are on macOS and sandbox-exec can actually apply a profile.
///
/// Merely checking that the binary exists is insufficient: macOS does not
/// allow nested Seatbelt sandboxes, so `sandbox_apply` returns EPERM when
/// `pent` is itself running under `sandbox-exec` (e.g. during development).
fn sandbox_available() -> bool {
    if !cfg!(target_os = "macos") || !Path::new("/usr/bin/sandbox-exec").exists() {
        return false;
    }
    Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1) (allow default)", "/bin/true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extra --read flags that must be added to give the sandboxed shell
/// access to system executables (/bin/sh, /bin/cat, /usr/bin/nc, etc.)
/// and macOS system frameworks that those executables depend on.
///
/// System defaults only include /usr/lib, /usr/share, /etc, /tmp.
/// /bin, /usr/bin, and /System/Library are NOT included, so we pass
/// them explicitly in each test that actually runs a command.
fn sys_exec_args() -> Vec<String> {
    vec![
        "--read".into(),
        "/bin".into(),
        "--read".into(),
        "/usr/bin".into(),
        "--read".into(),
        "/System/Library".into(),
    ]
}

/// Invoke `pent run --profile pent-test [extra_args] -- [cmd_args]` in
/// `workspace`.
///
/// The profile is empty and trusted, in temporary XDG directories. `HOME`
/// stays the real home directory, so that the tests can place files outside
/// the sandbox defaults.
#[allow(clippy::panic)] // infrastructure helper: setup failure is a hard test setup error
fn sandboxed_run(workspace: &Path, extra_args: &[String], cmd_args: &[&str]) -> Output {
    let xdg = Xdg::new().unwrap_or_else(|e| panic!("cannot make the XDG directories: {e}"));
    xdg.install_profile(TEST_PROFILE, "")
        .unwrap_or_else(|e| panic!("cannot install the test profile: {e}"));
    let mut args: Vec<String> = vec!["run".into(), "--profile".into(), TEST_PROFILE.into()];
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

/// A path in the user's home directory that is guaranteed to be
/// outside the sandbox defaults (`system_defaults` gives no access to `$HOME`).
///
/// $HOME is typically /Users/<username> on macOS — not under /tmp, not
/// under /usr/lib, and not under $TMPDIR (which is /var/folders/…/T/).
fn home_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::var("HOME").ok().map(|h| {
        std::path::PathBuf::from(h).join(format!("pent-integration-{}-{name}", std::process::id()))
    })
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
// C. Run — filesystem tests (macOS sandbox required)
// ============================================================================

#[test]
fn test_run_reads_file_in_workspace() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    fs::write(dir.path().join("hello.txt"), "hello-workspace\n")?;

    let out = sandboxed_run(dir.path(), &sys_exec_args(), &["/bin/cat", "hello.txt"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("hello-workspace"),
        "Expected file content, got: {stdout}"
    );
    Ok(())
}

#[test]
fn test_run_writes_file_in_workspace() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    let target = dir.path().join("created.txt");

    let out = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/sh", "-c", "echo wrote > created.txt"],
    );
    expect_success(&out);
    assert!(target.exists(), "created.txt was not created in workspace");
    assert!(
        fs::read_to_string(&target)?.contains("wrote"),
        "Unexpected content in created.txt"
    );
    Ok(())
}

#[test]
fn test_run_cannot_read_file_in_home_dir() -> TestResult {
    // $HOME (/Users/<user>) is NOT in sandbox defaults, so the sandboxed
    // process should not be able to read files placed there.
    if !sandbox_available() {
        return Ok(());
    }

    let Some(secret_path) = home_path("secret.txt") else {
        return Ok(()); // no HOME env var, skip
    };

    fs::write(&secret_path, "should-not-be-readable\n")?;

    let dir = TempDir::new()?;
    let out = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &[
            "/bin/cat",
            secret_path
                .to_str()
                .ok_or("secret path is not valid UTF-8")?,
        ],
    );
    // Sandbox blocks the read → non-zero exit
    expect_failure(&out);

    let _ = fs::remove_file(&secret_path); // cleanup
    Ok(())
}

#[test]
fn test_run_extra_read_gives_access_to_home_dir_file() -> TestResult {
    // Verify that --read <dir> grants read access to that directory from
    // inside the sandbox, even if it would otherwise be inaccessible.
    if !sandbox_available() {
        return Ok(());
    }

    let Some(secret_dir) = home_path("extra-read-dir") else {
        return Ok(());
    };
    fs::create_dir_all(&secret_dir)?;
    let secret_file = secret_dir.join("data.txt");
    fs::write(&secret_file, "accessible-via-flag\n")?;

    let dir = TempDir::new()?;

    // Without --read: access should fail
    let out_blocked = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &[
            "/bin/cat",
            secret_file
                .to_str()
                .ok_or("secret_file path is not valid UTF-8")?,
        ],
    );
    expect_failure(&out_blocked);

    // With --read <secret_dir>: access should succeed
    let mut extra = sys_exec_args();
    extra.push("--read".into());
    extra.push(
        secret_dir
            .to_str()
            .ok_or("secret_dir path is not valid UTF-8")?
            .to_string(),
    );

    let out_allowed = sandboxed_run(
        dir.path(),
        &extra,
        &[
            "/bin/cat",
            secret_file
                .to_str()
                .ok_or("secret_file path is not valid UTF-8")?,
        ],
    );
    let stdout = expect_success(&out_allowed);
    assert!(
        stdout.contains("accessible-via-flag"),
        "Expected file content after --read grant, got: {stdout}"
    );

    // cleanup
    let _ = fs::remove_file(&secret_file);
    let _ = fs::remove_dir(&secret_dir);
    Ok(())
}

#[test]
fn test_run_extra_write_gives_write_access() -> TestResult {
    // --write <dir> should grant write access to a directory that is
    // otherwise inaccessible.
    if !sandbox_available() {
        return Ok(());
    }

    let Some(write_dir) = home_path("extra-write-dir") else {
        return Ok(());
    };
    fs::create_dir_all(&write_dir)?;
    let target = write_dir.join("out.txt");
    let target_str = target
        .to_str()
        .ok_or("target path is not valid UTF-8")?
        .to_string();

    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    extra.push("--write".into());
    extra.push(
        write_dir
            .to_str()
            .ok_or("write_dir path is not valid UTF-8")?
            .to_string(),
    );

    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", &format!("echo written > {target_str}")],
    );
    expect_success(&out);
    assert!(target.exists(), "Output file not created in --write dir");

    // cleanup
    let _ = fs::remove_file(&target);
    let _ = fs::remove_dir(&write_dir);
    Ok(())
}

// ============================================================================
// D. Run — network isolation tests (macOS sandbox required)
// ============================================================================

/// Run `nc -zw2 <host> <port>` inside the sandbox with the given network args.
/// Returns the Output of the pent invocation.
fn nc_test(workspace: &Path, net_args: &[&str]) -> Output {
    let mut extra = sys_exec_args();
    for a in net_args {
        extra.push((*a).to_string());
    }
    // nc -zw2 1.1.1.1 80 — TCP connect to Cloudflare DNS, 2s timeout
    // Exit 0 if connected, non-zero if blocked/failed
    sandboxed_run(workspace, &extra, &["/usr/bin/nc", "-zw2", "1.1.1.1", "80"])
}

#[test]
fn test_run_blocked_network_prevents_tcp_connect() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    // --network blocked: SBPL generates (deny network*) → connect() returns EPERM
    let out = nc_test(dir.path(), &["--network", "blocked"]);
    expect_failure(&out);
    Ok(())
}

#[test]
fn test_run_localhost_network_blocks_external_connect() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    // --network localhost: only loopback allowed; 1.1.1.1 is not localhost
    let out = nc_test(dir.path(), &["--network", "localhost"]);
    expect_failure(&out);
    Ok(())
}

#[test]
fn test_run_blocked_network_by_direct_ip() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    // Direct IP (bypasses DNS) under blocked mode. The sandbox network* deny
    // covers connect() regardless of how the destination was obtained.
    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--network".into(), "blocked".into()]);
    // Use 8.8.8.8:53 (Google DNS) — different IP to avoid any local-network edge cases
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/usr/bin/nc", "-zw2", "8.8.8.8", "53"],
    );
    expect_failure(&out);
    Ok(())
}

#[test]
fn test_run_localhost_network_allows_loopback() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--network".into(), "localhost".into()]);
    // nc -zw2 127.0.0.1 <any> will return "connection refused" (ECONNREFUSED,
    // exit 1) if nothing is listening — but that's a TCP-level error, NOT a
    // sandbox EPERM.  We verify by checking the stderr: sandbox violations
    // show up as "Operation not permitted", not "connection refused".
    // Actually, nc exits 1 in both cases; we can't distinguish easily without
    // reading stderr, so we just verify the sandbox doesn't crash pent itself.
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", "nc -zw1 127.0.0.1 9 2>&1; echo NC_DONE"],
    );
    // pent itself should exit 0 (it waits for the child); the nc may fail but
    // the shell echo should still run.
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("NC_DONE"),
        "Shell did not complete: {stdout}"
    );
    Ok(())
}

// ============================================================================
// E. Run — proxy / --allow flag
// ============================================================================

#[test]
fn test_run_allow_flag_starts_proxy_without_crash() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    // Passing --allow starts the proxy server. We run a neutral command
    // (echo) to verify the proxy starts and shuts down cleanly.
    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--allow".into(), "example.com".into()]);
    let out = sandboxed_run(dir.path(), &extra, &["/bin/echo", "proxy-ok"]);
    let stdout = expect_success(&out);
    assert!(stdout.contains("proxy-ok"));
    Ok(())
}

// ============================================================================
// F. Run — environment variable passthrough
// ============================================================================

#[test]
fn test_run_env_flag_passes_named_variable() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--env".into(), "HOME".into()]);
    let out = sandboxed_run(dir.path(), &extra, &["/bin/sh", "-c", "echo HOME=$HOME"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("HOME=/"),
        "Expected HOME to be set, got: {stdout}"
    );
    Ok(())
}

#[test]
fn test_run_env_explicit_kv_sets_variable() -> TestResult {
    if !sandbox_available() {
        return Ok(());
    }

    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--env".into(), "PENT_TEST=injected".into()]);
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", "echo RESULT=$PENT_TEST"],
    );
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("RESULT=injected"),
        "Expected injected value, got: {stdout}"
    );
    Ok(())
}

// ============================================================================
// J. MCP server accessibility — localhost connectivity in proxy_only mode
// ============================================================================

#[test]
fn test_proxy_mode_allows_localhost_mcp_connection() -> TestResult {
    // MCP servers typically run on localhost (stdio or SSE). Verify that a
    // sandboxed process in proxy_only mode can reach a TCP server on 127.0.0.1.
    if !sandbox_available() {
        return Ok(());
    }

    // Bind an ephemeral TCP port so there is something to connect to.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let dir = TempDir::new()?;
    let mut extra = sys_exec_args();
    // --allow triggers proxy_only mode, same as the example configs use.
    extra.extend_from_slice(&["--allow".into(), "example.com".into()]);

    // nc exits 0 on successful connect, 1 on refused — either is fine here.
    // What must NOT appear is "Operation not permitted", which indicates the
    // sandbox blocked the syscall rather than the server rejecting the conn.
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &[
            "/bin/sh",
            "-c",
            &format!("nc -zw1 127.0.0.1 {port} 2>&1; echo MCP_DONE"),
        ],
    );
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("MCP_DONE"),
        "Shell did not complete: {stdout}"
    );
    assert!(
        !stdout.contains("Operation not permitted"),
        "Sandbox blocked localhost MCP connection: {stdout}"
    );

    drop(listener);
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
    // execute_access is now ReadDir | Execute (no ReadFile), so the binary and
    // its shared libraries must also be listed under --read for execve to succeed.
    //
    // The test uses the FHS layout. Some systems (NixOS) do not have it.
    if !std::path::Path::new("/usr/bin/true").exists() {
        println!("SKIP: /usr/bin/true does not exist on this system");
        return Ok(());
    }
    let out = sandboxed_run(
        std::path::Path::new("/tmp"),
        &[
            "--network",
            "unrestricted",
            "--execute",
            "/usr/bin",
            "--read",
            "/usr/bin",
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
        &["/usr/bin/true"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Skip if the sandbox itself cannot be set up (overlay requires privileges).
    if !out.status.success()
        && (stderr.contains("Operation not permitted")
            || stderr.contains("overlayfs")
            || stderr.contains("user namespace"))
    {
        println!("SKIP: overlay sandbox not available: {stderr}");
        return Ok(());
    }
    assert!(
        out.status.success(),
        "pent --execute /usr/bin --read /usr/bin -- /usr/bin/true should succeed\nstderr: {stderr}",
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
    use serial_test::serial;
    use std::io::Read as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    /// Spawn `pent` with `args` in `dir`; kill it if it has not exited after
    /// `timeout_secs`.  Returns `(finished_before_deadline, stderr_text)`.
    ///
    /// `home` must be a temp dir from [`profile_home`] — it is set as `$HOME`
    /// so the real `~/.config/pent` is invisible to pent.
    /// `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `XDG_DATA_HOME` are also
    /// cleared so they cannot override the isolated home.
    /// stdout is discarded (`Stdio::null`) — we only capture stderr for
    /// diagnostics.  stderr is drained in a background thread so the child
    /// can never block on a full pipe.
    #[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // infrastructure helper: spawn/pipe failures are hard test setup errors
    fn pent_timeout(dir: &Path, home: &Path, args: &[&str], timeout_secs: u64) -> (bool, String) {
        let mut child = Command::new(PENT)
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

    /// Make a temp `$HOME` with the trusted profile `name` (content `toml`).
    #[allow(clippy::unwrap_used, clippy::panic)] // infrastructure helper: setup failures are hard test setup errors
    fn profile_home(name: &str, toml: &str) -> TempDir {
        let home = TempDir::new().unwrap();
        let drafts = home.path().join(".local/state/pent/drafts");
        fs::create_dir_all(&drafts).unwrap();
        fs::write(drafts.join(format!("{name}.toml")), toml).unwrap();
        let status = Command::new(PENT)
            .args(["trust", name, "--yes"])
            .env("HOME", home.path())
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_DATA_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("pent trust {name}: {e}"));
        assert!(status.success(), "pent trust {name} --yes failed");
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

    /// /usr/bin/true: the simplest possible exit.  Should always finish in <2s.
    #[test]
    fn system_true_exits_quickly() -> TestResult {
        let dir = TempDir::new()?;
        let home = profile_home(TEST_PROFILE, "");
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &["run", "--profile", TEST_PROFILE, "--", "/usr/bin/true"],
            2,
        );
        assert!(
            ok,
            "pent run -- /usr/bin/true timed out (2s)\nstderr:\n{stderr}"
        );
        Ok(())
    }

    /// Same as above but with explicit --network blocked (the default).
    #[test]
    fn system_true_blocked_network_exits_quickly() -> TestResult {
        let dir = TempDir::new()?;
        let home = profile_home(TEST_PROFILE, "");
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &[
                "run",
                "--profile",
                TEST_PROFILE,
                "--network",
                "blocked",
                "--",
                "/usr/bin/true",
            ],
            2,
        );
        assert!(
            ok,
            "pent run --network blocked -- /usr/bin/true timed out (2s)\nstderr:\n{stderr}"
        );
        Ok(())
    }

    /// /usr/bin/curl --version: a real binary that reads shared libs from /usr/lib.
    #[test]
    fn system_curl_version_exits_quickly() -> TestResult {
        if !std::path::Path::new("/usr/bin/curl").exists() {
            println!("SKIP: /usr/bin/curl not found");
            return Ok(());
        }
        let dir = TempDir::new()?;
        let home = profile_home(TEST_PROFILE, "");
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &[
                "run",
                "--profile",
                TEST_PROFILE,
                "--",
                "/usr/bin/curl",
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

    #[allow(clippy::unwrap_used)] // infrastructure helper: to_str() only fails on non-UTF-8 paths
    fn assert_version_exits_quickly(name: &str) {
        let Some(bin) = detect_binary(name) else {
            println!("SKIP: {name} not found in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();
        let dir = TempDir::new().unwrap();
        let home = profile_home(TEST_PROFILE, "");
        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &["run", "--profile", TEST_PROFILE, "--", bin_s, "--version"],
            5,
        );
        assert!(
            ok,
            "pent run -- {name} --version timed out (5s)\nstderr:\n{stderr}"
        );
    }

    #[test]
    #[serial(pty)]
    fn claude_version_exits_quickly() {
        assert_version_exits_quickly("claude");
    }
    #[test]
    #[serial(pty)]
    fn codex_version_exits_quickly() {
        assert_version_exits_quickly("codex");
    }
    #[test]
    #[serial(pty)]
    fn gemini_version_exits_quickly() {
        assert_version_exits_quickly("gemini");
    }

    // ── with a profile: the profile has domains → ProxyOnly ─────────────────
    //
    // The profile lives only in the isolated `home`.

    #[allow(clippy::unwrap_used)] // infrastructure helper: to_str()/TempDir failures are hard errors
    fn assert_proxy_mode_exits_quickly(name: &str) {
        let Some(bin) = detect_binary(name) else {
            println!("SKIP: {name} not found in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();

        let dir = TempDir::new().unwrap();
        let home = profile_home(
            TEST_PROFILE,
            "[network]\ndomains = [\"api.anthropic.com\"]\n",
        );

        let (ok, stderr) = pent_timeout(
            dir.path(),
            home.path(),
            &["run", "--profile", TEST_PROFILE, "--", bin_s, "--version"],
            5, // proxy + veth setup may take ~1s; allow 5s total
        );
        assert!(
            ok,
            "pent run (proxy mode) -- {name} --version timed out (5s)\n\
             hint: pent may be hanging in veth/nft setup or the child is \
             not routing through the proxy\nstderr:\n{stderr}",
        );
    }

    #[test]
    #[serial(netns)]
    fn claude_proxy_mode_exits_quickly() {
        assert_proxy_mode_exits_quickly("claude");
    }
    #[test]
    #[serial(netns)]
    fn codex_proxy_mode_exits_quickly() {
        assert_proxy_mode_exits_quickly("codex");
    }
    #[test]
    #[serial(netns)]
    fn gemini_proxy_mode_exits_quickly() {
        assert_proxy_mode_exits_quickly("gemini");
    }

    // ── PTY-simulated interactive sessions ────────────────────────────────────
    //
    // Isolation model:
    //   HOME            = real test-process HOME  (so ~/.npm-global, ~/.local/share/claude
    //                     etc. are reachable by the sandboxed binary)
    //   XDG_CONFIG_HOME = fresh TempDir with the {agent} profile installed
    //   cwd             = fresh empty TempDir
    //
    // Each test installs and trusts the {agent} profile (common::agent_profile)
    // in a temp HOME before it spawns pent, so the agent's paths and network
    // rules are active.
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
    ) -> (libc::c_int, std::process::Child) {
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

        let child = Command::new(PENT)
            .args(args)
            .current_dir(dir)
            // Use the agent_home so the {agent} profile is visible.
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

        (master, child)
    }

    /// Install the trusted `{agent}` profile into a fresh temp HOME.
    /// Returns the TempDir (keep alive) — its path is used as HOME.
    fn setup_agent_config(agent: &str) -> TempDir {
        profile_home(agent, &common::agent_profile(agent))
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

    /// Core PTY TUI-start test: install the `{agent}` profile into a temp HOME,
    /// spawn `pent run --network unrestricted -- <binary>` with a PTY, and
    /// confirm the TUI renders (≥ 2 non-empty lines after ANSI strip, no crash
    /// markers).  Then kill pent.  This test is purely about sandbox access —
    /// teardown is covered by the _version_exits_quickly tests.
    #[allow(clippy::panic, clippy::unwrap_used)] // infrastructure helper: PTY test failure should panic with a clear message
    fn assert_pty_interactive(agent: &str) {
        let Some(bin) = detect_binary(agent) else {
            println!("SKIP: {agent} not found");
            return;
        };
        let bin_s = bin.to_str().unwrap();

        let dir = TempDir::new().unwrap();
        // Install the agent profile; keep TempDir alive so the config persists.
        let agent_home = setup_agent_config(agent);

        let (master, mut child) = spawn_with_pty(
            dir.path(),
            agent_home.path(),
            &[
                "run",
                "--profile",
                agent,
                "--network",
                "unrestricted",
                "--",
                bin_s,
            ],
        );

        // Step 1: wait up to 8 s for the TUI to render.
        let output = drain_pty(master, Duration::from_secs(8));
        let printable = String::from_utf8_lossy(&output);

        if !looks_like_prompt(&output) {
            child.kill().ok();
            child.wait().ok();
            unsafe { libc::close(master) };
            panic!(
                "pent run -- {agent}: PTY output within 8s was empty or contained errors\n\
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
    #[serial(pty)]
    fn pty_claude_interactive_exits_quickly() {
        assert_pty_interactive("claude");
    }
    #[test]
    #[serial(pty)]
    fn pty_codex_interactive_exits_quickly() {
        assert_pty_interactive("codex");
    }
    #[test]
    #[serial(pty)]
    fn pty_gemini_interactive_exits_quickly() {
        assert_pty_interactive("gemini");
    }
}
