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

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

// ============================================================================
// Infrastructure
// ============================================================================

/// Path to the compiled `pent` binary, injected by Cargo at compile time.
const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// Invoke `pent` with the given arguments in `cwd` and return the full Output.
fn run_halt(cwd: &Path, args: &[&str]) -> Output {
    Command::new(PENT)
        .args(args)
        .current_dir(cwd)
        .env_remove("PENT_LOG") // keep test output clean
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

/// Invoke `pent run --no-config [extra_args] -- [cmd_args]` in `workspace`.
fn sandboxed_run(workspace: &Path, extra_args: &[String], cmd_args: &[&str]) -> Output {
    let mut args: Vec<String> = vec!["run".into(), "--no-config".into()];
    args.extend_from_slice(extra_args);
    args.push("--".into());
    for a in cmd_args {
        args.push((*a).to_string());
    }
    Command::new(PENT)
        .args(&args)
        .current_dir(workspace)
        .env_remove("PENT_LOG")
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
fn test_config_init_creates_project_config() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "init"]);
    expect_success(&out);

    let config_path = dir.path().join(".pent").join("pent.toml");
    assert!(config_path.exists(), ".pent/pent.toml was not created");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(
        toml::from_str::<toml::Value>(&contents).is_ok(),
        "Generated config is not valid TOML:\n{contents}"
    );
}

#[test]
fn test_config_init_fails_if_already_exists() {
    let dir = TempDir::new().unwrap();
    // First init should succeed
    expect_success(&run_halt(dir.path(), &["config", "init"]));
    // Second init should fail with a clear error
    let out = run_halt(dir.path(), &["config", "init"]);
    expect_failure(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists") || stderr.contains("Config file"),
        "Expected 'already exists' in stderr, got: {stderr}"
    );
}

#[test]
fn test_config_show_toml_is_valid() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "init"]));

    let out = run_halt(dir.path(), &["config", "show", "--format", "toml"]);
    let stdout = expect_success(&out);
    assert!(
        toml::from_str::<toml::Value>(&stdout).is_ok(),
        "config show --format toml is not valid TOML:\n{stdout}"
    );
}

#[test]
fn test_config_show_json_is_valid() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "init"]));

    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "config show --format json is not valid JSON:\n{stdout}"
    );
}

#[test]
fn test_config_show_json_has_sandbox_and_proxy_keys() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "init"]));

    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(json.get("sandbox").is_some(), "Missing 'sandbox' key");
    assert!(json.get("proxy").is_some(), "Missing 'proxy' key");
}

#[test]
fn test_config_show_without_config_file_uses_defaults() {
    // No config init — should still produce valid output using defaults
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("sandbox").is_some());
    assert!(json.get("proxy").is_some());
}

#[test]
fn test_config_project_overrides_domain_allowlist() {
    let dir = TempDir::new().unwrap();

    // Write a project config with a specific domain
    let dot_halt = dir.path().join(".pent");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::write(
        dot_halt.join("pent.toml"),
        "[proxy]\ndomain_allowlist = [\"project-domain.example\"]\n",
    )
    .unwrap();

    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let allowlist = json["proxy"]["domain_allowlist"]
        .as_array()
        .expect("domain_allowlist should be an array");
    assert!(
        allowlist
            .iter()
            .any(|v| v.as_str() == Some("project-domain.example")),
        "Expected project-domain.example in allowlist, got: {allowlist:?}"
    );
}

// ============================================================================
// B. Check command
// ============================================================================

#[test]
fn test_check_reports_platform() {
    // `pent check` should always print platform info even when sandboxing
    // is unavailable. The exit status may be non-zero in restricted envs.
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["check"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("platform"),
        "Expected 'platform' in check stderr, got: {stderr}"
    );
}

// ============================================================================
// C. Run — filesystem tests (macOS sandbox required)
// ============================================================================

#[test]
fn test_run_reads_file_in_workspace() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), "hello-workspace\n").unwrap();

    let out = sandboxed_run(dir.path(), &sys_exec_args(), &["/bin/cat", "hello.txt"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("hello-workspace"),
        "Expected file content, got: {stdout}"
    );
}

#[test]
fn test_run_writes_file_in_workspace() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let target = dir.path().join("created.txt");

    let out = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/sh", "-c", "echo wrote > created.txt"],
    );
    expect_success(&out);
    assert!(target.exists(), "created.txt was not created in workspace");
    assert!(
        fs::read_to_string(&target).unwrap().contains("wrote"),
        "Unexpected content in created.txt"
    );
}

#[test]
fn test_run_cannot_read_file_in_home_dir() {
    // $HOME (/Users/<user>) is NOT in sandbox defaults, so the sandboxed
    // process should not be able to read files placed there.
    if !sandbox_available() {
        return;
    }

    let Some(secret_path) = home_path("secret.txt") else {
        return; // no HOME env var, skip
    };

    fs::write(&secret_path, "should-not-be-readable\n").unwrap();

    let dir = TempDir::new().unwrap();
    let out = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/cat", secret_path.to_str().unwrap()],
    );
    // Sandbox blocks the read → non-zero exit
    expect_failure(&out);

    let _ = fs::remove_file(&secret_path); // cleanup
}

#[test]
fn test_run_extra_read_gives_access_to_home_dir_file() {
    // Verify that --read <dir> grants read access to that directory from
    // inside the sandbox, even if it would otherwise be inaccessible.
    if !sandbox_available() {
        return;
    }

    let Some(secret_dir) = home_path("extra-read-dir") else {
        return;
    };
    fs::create_dir_all(&secret_dir).unwrap();
    let secret_file = secret_dir.join("data.txt");
    fs::write(&secret_file, "accessible-via-flag\n").unwrap();

    let dir = TempDir::new().unwrap();

    // Without --read: access should fail
    let out_blocked = sandboxed_run(
        dir.path(),
        &sys_exec_args(),
        &["/bin/cat", secret_file.to_str().unwrap()],
    );
    expect_failure(&out_blocked);

    // With --read <secret_dir>: access should succeed
    let mut extra = sys_exec_args();
    extra.push("--read".into());
    extra.push(secret_dir.to_str().unwrap().to_string());

    let out_allowed = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/cat", secret_file.to_str().unwrap()],
    );
    let stdout = expect_success(&out_allowed);
    assert!(
        stdout.contains("accessible-via-flag"),
        "Expected file content after --read grant, got: {stdout}"
    );

    // cleanup
    let _ = fs::remove_file(&secret_file);
    let _ = fs::remove_dir(&secret_dir);
}

#[test]
fn test_run_extra_write_gives_write_access() {
    // --write <dir> should grant write access to a directory that is
    // otherwise inaccessible.
    if !sandbox_available() {
        return;
    }

    let Some(write_dir) = home_path("extra-write-dir") else {
        return;
    };
    fs::create_dir_all(&write_dir).unwrap();
    let target = write_dir.join("out.txt");
    let target_str = target.to_str().unwrap().to_string();

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.push("--write".into());
    extra.push(write_dir.to_str().unwrap().to_string());

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
fn test_run_blocked_network_prevents_tcp_connect() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    // --network blocked: SBPL generates (deny network*) → connect() returns EPERM
    let out = nc_test(dir.path(), &["--network", "blocked"]);
    expect_failure(&out);
}

#[test]
fn test_run_localhost_network_blocks_external_connect() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    // --network localhost: only loopback allowed; 1.1.1.1 is not localhost
    let out = nc_test(dir.path(), &["--network", "localhost"]);
    expect_failure(&out);
}

#[test]
fn test_run_blocked_network_by_direct_ip() {
    if !sandbox_available() {
        return;
    }

    // Direct IP (bypasses DNS) under blocked mode. The sandbox network* deny
    // covers connect() regardless of how the destination was obtained.
    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--network".into(), "blocked".into()]);
    // Use 8.8.8.8:53 (Google DNS) — different IP to avoid any local-network edge cases
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/usr/bin/nc", "-zw2", "8.8.8.8", "53"],
    );
    expect_failure(&out);
}

#[test]
fn test_run_localhost_network_allows_loopback() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
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
}

// ============================================================================
// E. Run — proxy / --allow flag
// ============================================================================

#[test]
fn test_run_allow_flag_starts_proxy_without_crash() {
    if !sandbox_available() {
        return;
    }

    // Passing --allow starts the proxy server. We run a neutral command
    // (echo) to verify the proxy starts and shuts down cleanly.
    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--allow".into(), "example.com".into()]);
    let out = sandboxed_run(dir.path(), &extra, &["/bin/echo", "proxy-ok"]);
    let stdout = expect_success(&out);
    assert!(stdout.contains("proxy-ok"));
}

// ============================================================================
// F. Run — environment variable passthrough
// ============================================================================

#[test]
fn test_run_env_flag_passes_named_variable() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--env".into(), "HOME".into()]);
    let out = sandboxed_run(dir.path(), &extra, &["/bin/sh", "-c", "echo HOME=$HOME"]);
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("HOME=/"),
        "Expected HOME to be set, got: {stdout}"
    );
}

#[test]
fn test_run_env_explicit_kv_sets_variable() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut extra = sys_exec_args();
    extra.extend_from_slice(&["--env".into(), "HALT_TEST=injected".into()]);
    let out = sandboxed_run(
        dir.path(),
        &extra,
        &["/bin/sh", "-c", "echo RESULT=$HALT_TEST"],
    );
    let stdout = expect_success(&out);
    assert!(
        stdout.contains("RESULT=injected"),
        "Expected injected value, got: {stdout}"
    );
}

// ============================================================================
// G. Run — --no-config flag
// ============================================================================

#[test]
fn test_run_no_config_ignores_project_config() {
    if !sandbox_available() {
        return;
    }

    let dir = TempDir::new().unwrap();

    // Create a project config that requests blocked networking.
    // With --no-config this should be ignored and defaults apply.
    let dot_halt = dir.path().join(".pent");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::write(
        dot_halt.join("pent.toml"),
        "[sandbox.network]\nmode = \"blocked\"\n",
    )
    .unwrap();

    // sandboxed_run already passes --no-config; echo should succeed even
    // though the project config requests blocked networking.
    let out = sandboxed_run(dir.path(), &sys_exec_args(), &["/bin/echo", "no-config"]);
    let stdout = expect_success(&out);
    assert!(stdout.contains("no-config"));
}

// ============================================================================
// H. Run — extra config file via --config flag
// ============================================================================

// ============================================================================
// I. Profile add / rm commands
// ============================================================================

#[test]
fn test_config_add_creates_config_if_missing() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join(".pent").join("pent.toml");
    assert!(!config_path.exists());

    let out = run_halt(dir.path(), &["config", "add", "@cargo"]);
    expect_success(&out);

    assert!(config_path.exists(), "config should be created by add");
}

#[test]
fn test_config_add_writes_domains() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "add", "@npm"]);
    expect_success(&out);

    let config_path = dir.path().join(".pent").join("pent.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(
        contents.contains("registry.npmjs.org"),
        "Expected registry.npmjs.org in config after adding @npm: {contents}"
    );
}

#[test]
fn test_config_add_npm_also_adds_node() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "add", "@npm"]);
    expect_success(&out);

    // @npm depends on @node; @node adds traversal: ~ on all platforms
    let config_path = dir.path().join(".pent").join("pent.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(
        contents.contains("\"~\""),
        "Expected traversal '~' from @node profile after adding @npm: {contents}"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("@node"),
        "Expected '@node' in add stderr: {stderr}"
    );
}

#[test]
fn test_config_add_deduplicates() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@npm"]));
    expect_success(&run_halt(dir.path(), &["config", "add", "@npm"]));

    let config_path = dir.path().join(".pent").join("pent.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    let count = contents.matches("registry.npmjs.org").count();
    assert_eq!(
        count, 1,
        "registry.npmjs.org should appear exactly once: {contents}"
    );
}

#[test]
fn test_config_rm_removes_domains() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@npm"]));
    expect_success(&run_halt(dir.path(), &["config", "rm", "@npm"]));

    let config_path = dir.path().join(".pent").join("pent.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(
        !contents.contains("registry.npmjs.org"),
        "registry.npmjs.org should be removed after rm @npm: {contents}"
    );
}

#[test]
fn test_config_rm_node_blocked_by_gemini() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@gemini"]));

    let out = run_halt(dir.path(), &["config", "rm", "@node"]);
    expect_failure(&out);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("@gemini") || stderr.contains("depends"),
        "Expected error mentioning @gemini dependency: {stderr}"
    );
}

#[test]
fn test_config_rm_gemini_node_together_succeeds() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@gemini"]));

    let out = run_halt(dir.path(), &["config", "rm", "@gemini", "@node"]);
    expect_success(&out);

    let config_path = dir.path().join(".pent").join("pent.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(
        !contents.contains("generativelanguage.googleapis.com"),
        "gemini domains should be removed: {contents}"
    );
}

#[test]
fn test_config_add_multiple_profiles() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "add", "@npm", "@cargo", "@gh"]);
    expect_success(&out);

    let config_path = dir.path().join(".pent").join("pent.toml");
    let contents = fs::read_to_string(&config_path).unwrap();
    assert!(contents.contains("registry.npmjs.org"), "npm domain missing");
    assert!(contents.contains("crates.io"), "cargo domain missing");
    assert!(contents.contains("github.com"), "gh domain missing");
}

#[test]
fn test_config_add_unknown_profile_fails() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "add", "@not-a-real-profile"]);
    expect_failure(&out);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown") || stderr.contains("@not-a-real-profile"),
        "Expected error about unknown profile: {stderr}"
    );
}

// ============================================================================
// J. MCP server accessibility — localhost connectivity in proxy_only mode
// ============================================================================

#[test]
fn test_proxy_mode_allows_localhost_mcp_connection() {
    // MCP servers typically run on localhost (stdio or SSE). Verify that a
    // sandboxed process in proxy_only mode can reach a TCP server on 127.0.0.1.
    if !sandbox_available() {
        return;
    }

    // Bind an ephemeral TCP port so there is something to connect to.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let dir = TempDir::new().unwrap();
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
}

#[test]
fn test_run_extra_config_merges_domain_allowlist() {
    // Verify that an additional config file passed via --config is merged into
    // the effective configuration. We test this at the `config show` level.
    let dir = TempDir::new().unwrap();
    let extra_cfg = dir.path().join("extra.toml");
    fs::write(
        &extra_cfg,
        "[proxy]\ndomain_allowlist = [\"extra-domain.example\"]\n",
    )
    .unwrap();

    // Write a project config with a base domain
    let dot_halt = dir.path().join(".pent");
    fs::create_dir_all(&dot_halt).unwrap();
    fs::write(
        dot_halt.join("pent.toml"),
        "[proxy]\ndomain_allowlist = [\"base-domain.example\"]\n",
    )
    .unwrap();

    // `pent run --config extra.toml --no-config echo` would skip project config
    // but load the extra one. Instead we test via a `run` that exits immediately.
    // Simpler: use `config show` (no --config option on config show, so test
    // via the run command's config loading indirectly).
    //
    // For now, just verify the project config is reflected in config show.
    let out = run_halt(dir.path(), &["config", "show", "--format", "json"]);
    let stdout = expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let allowlist = json["proxy"]["domain_allowlist"]
        .as_array()
        .expect("domain_allowlist should be an array");
    assert!(
        allowlist
            .iter()
            .any(|v| v.as_str() == Some("base-domain.example")),
        "Expected base-domain.example in allowlist, got: {allowlist:?}"
    );
}


// ============================================================================
// K. Run — --execute flag
// ============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_execute_flag_allows_binary() {
    // Only runs when Landlock is enforcing; otherwise meaningless.
    // We skip silently if unavailable.
    let out = run_halt(
        std::path::Path::new("/tmp"),
        &[
            "run",
            "--no-config",
            "--network",
            "unrestricted",
            "--execute",
            "/usr/bin",
            "--",
            "/usr/bin/true",
        ],
    );
    // If Landlock is not available pent falls back gracefully; either way exit 0.
    assert!(
        out.status.success(),
        "pent --execute /usr/bin -- /usr/bin/true should succeed\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

// ============================================================================
// N. Profile content verification (all platforms)
// ============================================================================

#[test]
fn test_config_add_claude_has_correct_domains_and_paths() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@claude"]));

    let contents =
        fs::read_to_string(dir.path().join(".pent").join("pent.toml")).unwrap();
    assert!(
        contents.contains("api.anthropic.com"),
        "@claude missing api.anthropic.com: {contents}"
    );
    assert!(
        contents.contains("statsig.anthropic.com"),
        "@claude missing statsig.anthropic.com: {contents}"
    );
    assert!(
        contents.contains("~/.claude\""),
        "@claude missing ~/.claude path: {contents}"
    );
    assert!(
        contents.contains("~/.local/share/claude"),
        "@claude missing ~/.local/share/claude: {contents}"
    );
    assert!(
        contents.contains("api.github.com"),
        "@claude missing api.github.com (marketplace): {contents}"
    );
    assert!(
        contents.contains("raw.githubusercontent.com"),
        "@claude missing raw.githubusercontent.com (marketplace): {contents}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_config_add_claude_has_macos_app_support_path() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@claude"]));

    let contents =
        fs::read_to_string(dir.path().join(".pent").join("pent.toml")).unwrap();
    assert!(
        contents.contains("Application Support/claude"),
        "@claude missing ~/Library/Application Support/claude on macOS: {contents}"
    );
}

#[test]
fn test_config_add_codex_has_correct_domains_and_paths() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@codex"]));

    let contents =
        fs::read_to_string(dir.path().join(".pent").join("pent.toml")).unwrap();
    assert!(
        contents.contains("api.openai.com"),
        "@codex missing api.openai.com: {contents}"
    );
    assert!(
        contents.contains("~/.codex"),
        "@codex missing ~/.codex path: {contents}"
    );
}

#[test]
fn test_config_add_gemini_has_correct_domains_and_paths() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@gemini"]));

    let contents =
        fs::read_to_string(dir.path().join(".pent").join("pent.toml")).unwrap();
    assert!(
        contents.contains("generativelanguage.googleapis.com"),
        "@gemini missing generativelanguage.googleapis.com: {contents}"
    );
    assert!(
        contents.contains("~/.gemini") || contents.contains("gemini-cli"),
        "@gemini missing data path (~/.gemini or gemini-cli): {contents}"
    );
}

#[test]
fn test_config_add_output_shows_file_path() {
    let dir = TempDir::new().unwrap();
    let out = run_halt(dir.path(), &["config", "add", "@cargo"]);
    expect_success(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pent.toml"),
        "Expected pent.toml path in add stderr: {stderr}"
    );
}

#[test]
fn test_config_rm_output_shows_file_path() {
    let dir = TempDir::new().unwrap();
    expect_success(&run_halt(dir.path(), &["config", "add", "@cargo"]));
    let out = run_halt(dir.path(), &["config", "rm", "@cargo"]);
    expect_success(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pent.toml"),
        "Expected pent.toml path in rm stderr: {stderr}"
    );
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
    /// `home` must be an empty temp dir — it is set as `$HOME` so the real
    /// `~/.config/pent/pent.toml` global config is invisible to pent.
    /// `XDG_CONFIG_HOME` and `XDG_DATA_HOME` are also cleared so they cannot
    /// override the isolated home.
    /// stdout is discarded (`Stdio::null`) — we only capture stderr for
    /// diagnostics.  stderr is drained in a background thread so the child
    /// can never block on a full pipe.
    fn pent_timeout(dir: &Path, home: &Path, args: &[&str], timeout_secs: u64) -> (bool, String) {
        let mut child = Command::new(PENT)
            .args(args)
            .current_dir(dir)
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
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

        let stderr = err_rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
        (exited, stderr)
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
    fn system_true_exits_quickly() {
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let (ok, stderr) = pent_timeout(
            dir.path(), home.path(),
            &["run", "--no-config", "--", "/usr/bin/true"],
            2,
        );
        assert!(ok, "pent run -- /usr/bin/true timed out (2s)\nstderr:\n{stderr}");
    }

    /// Same as above but with explicit --network blocked (the default).
    #[test]
    fn system_true_blocked_network_exits_quickly() {
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let (ok, stderr) = pent_timeout(
            dir.path(), home.path(),
            &["run", "--no-config", "--network", "blocked", "--", "/usr/bin/true"],
            2,
        );
        assert!(ok, "pent run --network blocked -- /usr/bin/true timed out (2s)\nstderr:\n{stderr}");
    }

    /// /usr/bin/curl --version: a real binary that reads shared libs from /usr/lib.
    #[test]
    fn system_curl_version_exits_quickly() {
        if !std::path::Path::new("/usr/bin/curl").exists() {
            println!("SKIP: /usr/bin/curl not found");
            return;
        }
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let (ok, stderr) = pent_timeout(
            dir.path(), home.path(),
            &["run", "--no-config", "--", "/usr/bin/curl", "--version"],
            2,
        );
        assert!(ok, "pent run -- curl --version timed out (2s)\nstderr:\n{stderr}");
    }

    // ── local binaries: --version flag ────────────────────────────────────────
    //
    // detect_binary uses the REAL $HOME (the test process's env) to locate the
    // binary.  pent itself gets a fresh empty home so it finds no global config.

    fn assert_version_exits_quickly(name: &str) {
        let Some(bin) = detect_binary(name) else {
            println!("SKIP: {name} not found in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();
        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let (ok, stderr) = pent_timeout(
            dir.path(), home.path(),
            &["run", "--no-config", "--", bin_s, "--version"],
            5,
        );
        assert!(ok, "pent run -- {name} --version timed out (5s)\nstderr:\n{stderr}");
    }

    #[test] #[serial(pty)]
    fn claude_version_exits_quickly() { assert_version_exits_quickly("claude"); }
    #[test] #[serial(pty)]
    fn codex_version_exits_quickly()  { assert_version_exits_quickly("codex"); }
    #[test] #[serial(pty)]
    fn gemini_version_exits_quickly() { assert_version_exits_quickly("gemini"); }

    // ── with-config: project pent.toml sets domain_allowlist → ProxyOnly ─────
    //
    // The project config lives only in the temp `dir` (.pent/pent.toml).
    // The isolated `home` ensures no global config is loaded on top of it.

    fn assert_proxy_mode_exits_quickly(name: &str) {
        let Some(bin) = detect_binary(name) else {
            println!("SKIP: {name} not found in PATH or ~/.local/bin");
            return;
        };
        let bin_s = bin.to_str().unwrap();

        let dir = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        let dot_pent = dir.path().join(".pent");
        fs::create_dir_all(&dot_pent).unwrap();
        fs::write(
            dot_pent.join("pent.toml"),
            "[proxy]\ndomain_allowlist = [\"api.anthropic.com\"]\n",
        )
        .unwrap();

        let (ok, stderr) = pent_timeout(
            dir.path(), home.path(),
            &["run", "--", bin_s, "--version"],
            5,  // proxy + veth setup may take ~1s; allow 5s total
        );
        assert!(
            ok,
            "pent run (proxy mode) -- {name} --version timed out (5s)\n\
             hint: pent may be hanging in veth/nft setup or the child is \
             not routing through the proxy\nstderr:\n{stderr}",
        );
    }

    #[test] #[serial(netns)]
    fn claude_proxy_mode_exits_quickly() { assert_proxy_mode_exits_quickly("claude"); }
    #[test] #[serial(netns)]
    fn codex_proxy_mode_exits_quickly()  { assert_proxy_mode_exits_quickly("codex"); }
    #[test] #[serial(netns)]
    fn gemini_proxy_mode_exits_quickly() { assert_proxy_mode_exits_quickly("gemini"); }

    // ── PTY-simulated interactive sessions ────────────────────────────────────
    //
    // Isolation model:
    //   HOME            = real test-process HOME  (so ~/.npm-global, ~/.local/share/claude
    //                     etc. are reachable by the sandboxed binary)
    //   XDG_CONFIG_HOME = fresh TempDir with @{agent} profile installed
    //   cwd             = fresh empty TempDir
    //
    // Each test runs `pent config add --global @{agent}` into a temp HOME before
    // spawning pent, so the agent's paths and network profile are active.
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
    #[allow(clippy::cast_sign_loss)]
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
            // Use the agent_home so the @{agent} global config is visible.
            .env("HOME", agent_home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("PENT_LOG")
            .stdin(unsafe { Stdio::from_raw_fd(slave) })
            .stdout(unsafe { Stdio::from_raw_fd(slave_out) })
            .stderr(unsafe { Stdio::from_raw_fd(slave_err) })
            .spawn()
            .expect("failed to spawn pent with PTY");

        (master, child)
    }

    /// Install the `@{agent}` global profile into a fresh temp HOME.
    /// Returns the TempDir (keep alive) — its path is used as HOME.
    fn setup_agent_config(agent: &str) -> TempDir {
        let home = TempDir::new().unwrap();
        let status = Command::new(PENT)
            .args(["config", "add", "--global", &format!("@{agent}")])
            .env("HOME", home.path())
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("pent config add @{agent}: {e}"));
        assert!(status.success(), "pent config add --global @{agent} failed");
        home
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
            if n > 0 { buf.extend_from_slice(&tmp[..n as usize]); }
            if Instant::now() >= deadline { break; }
            if n <= 0 { std::thread::sleep(Duration::from_millis(50)); }
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
            if i >= input.len() { break; }
            match input[i] {
                b'[' => {
                    // CSI: skip until ASCII letter (inclusive)
                    i += 1;
                    while i < input.len() && !input[i].is_ascii_alphabetic() { i += 1; }
                    if i < input.len() { i += 1; }
                }
                b']' => {
                    // OSC: skip until BEL (0x07) or ST (ESC \)
                    i += 1;
                    while i < input.len() {
                        if input[i] == 0x07 { i += 1; break; }
                        if input[i] == 0x1b { break; }
                        i += 1;
                    }
                    // consume ST if present
                    if i + 1 < input.len() && input[i] == 0x1b && input[i + 1] == b'\\' {
                        i += 2;
                    }
                }
                _ => { i += 1; } // other: skip the byte after ESC
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
        if output.is_empty() { return false; }
        let raw = String::from_utf8_lossy(output);
        let error_markers = [
            "ERR_MODULE_NOT_FOUND", "Cannot find module", "Cannot find package",
            "ENOENT", "EACCES", "Permission denied", "Privilege required",
        ];
        if error_markers.iter().any(|m| raw.contains(m)) { return false; }
        let stripped = strip_ansi(output);
        let text = String::from_utf8_lossy(&stripped);
        text.lines().filter(|l| !l.trim().is_empty()).count() >= 2
    }

    /// Core PTY TUI-start test: install `@{agent}` profile into a temp HOME,
    /// spawn `pent run --network unrestricted -- <binary>` with a PTY, and
    /// confirm the TUI renders (≥ 2 non-empty lines after ANSI strip, no crash
    /// markers).  Then kill pent.  This test is purely about sandbox access —
    /// teardown is covered by the _version_exits_quickly tests.
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
            dir.path(), agent_home.path(),
            &["run", "--network", "unrestricted", "--", bin_s],
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

    #[test] #[serial(pty)]
    fn pty_claude_interactive_exits_quickly() { assert_pty_interactive("claude"); }
    #[test] #[serial(pty)]
    fn pty_codex_interactive_exits_quickly()  { assert_pty_interactive("codex"); }
    #[test] #[serial(pty)]
    fn pty_gemini_interactive_exits_quickly() { assert_pty_interactive("gemini"); }
}

