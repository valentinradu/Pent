//! Integration tests for the recorded profiles: `pent run` without a trusted
//! profile, `pent trust`, `pent untrust`, `pent profile`, `pent watch` and
//! the global settings.
//!
//! Each test sets `XDG_CONFIG_HOME` and `XDG_STATE_HOME` to temporary
//! directories, thus no test reads or changes the real files of the user.
//! A test that must run without a terminal starts pent in a new session
//! (`setsid`), so that `/dev/tty` is not available.

mod common;

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Output, Stdio};

use common::{Xdg, PENT};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Run pent with `args` in the XDG directories of `xdg`, without a terminal.
fn pent(xdg: &Xdg, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(PENT);
    xdg.apply(&mut cmd).args(args).stdin(Stdio::null());
    // SAFETY: setsid() is async-signal-safe and has no memory-safety
    // preconditions. The child gets a new session without a controlling
    // terminal, so pent cannot open /dev/tty and never waits for an answer.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.output()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[track_caller]
fn expect_success(out: &Output) {
    assert!(
        out.status.success(),
        "pent exited {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        stdout(out),
        stderr(out),
    );
}

#[track_caller]
fn expect_failure(out: &Output) {
    assert!(
        !out.status.success(),
        "pent must fail\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out),
    );
}

const DRAFT: &str =
    "# Profile for \"claude\".\n[filesystem]\nread = [\"~/.gitconfig\"] # read by git\n\
                     \n[network]\ndomains = []\n";

// ============================================================================
// A. pent run without a trusted profile
// ============================================================================

#[test]
fn test_run_without_profile_names_pent_watch() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(&xdg, &["run", "--", "claude", "--resume"])?;
    expect_failure(&out);
    let err = stderr(&out);
    assert!(
        err.contains(
            "✗ no trusted profile for \"claude\"\n  record one: pent watch -- claude --resume"
        ),
        "{err}"
    );
    Ok(())
}

#[test]
fn test_run_with_profile_flag_names_it_in_the_hint() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(
        &xdg,
        &["run", "--profile", "train", "--", "python3", "train.py"],
    )?;
    expect_failure(&out);
    let err = stderr(&out);
    assert!(err.contains("no trusted profile for \"train\""), "{err}");
    assert!(
        err.contains("record one: pent watch --profile train -- python3 train.py"),
        "{err}"
    );
    assert!(
        !err.contains("generic"),
        "--profile suppresses the warning: {err}"
    );
    Ok(())
}

#[test]
fn test_run_generic_command_warns() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(&xdg, &["run", "--", "bash", "-c", "true"])?;
    expect_failure(&out);
    let err = stderr(&out);
    assert!(
        err.contains("\"bash\" comes from a generic command"),
        "{err}"
    );
    assert!(err.contains("--profile NAME"), "{err}");
    Ok(())
}

#[test]
fn test_run_invalid_profile_name_fails() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(&xdg, &["run", "--profile", "../x", "--", "true"])?;
    expect_failure(&out);
    assert!(stderr(&out).contains("profile name"), "{}", stderr(&out));
    Ok(())
}

#[test]
fn test_run_with_draft_only_names_pent_trust() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.write_draft("claude", DRAFT)?;
    let out = pent(&xdg, &["run", "--", "claude"])?;
    expect_failure(&out);
    let err = stderr(&out);
    assert!(err.contains("the draft is not trusted"), "{err}");
    assert!(
        err.contains("review and trust it: pent trust claude"),
        "{err}"
    );
    assert!(!err.contains("pent watch"), "{err}");
    Ok(())
}

#[test]
fn test_run_after_edit_says_changed() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.install_profile("claude", DRAFT)?;
    fs::write(
        xdg.profile_path("claude"),
        "[network]\ndomains = [\"evil.example\"]\n",
    )?;
    let out = pent(&xdg, &["run", "--", "claude"])?;
    expect_failure(&out);
    let err = stderr(&out);
    assert!(
        err.contains("the profile \"claude\" changed after you trusted it"),
        "{err}"
    );
    assert!(err.contains("pent trust claude"), "{err}");
    Ok(())
}

#[test]
fn test_run_after_untrust_says_not_trusted() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.install_profile("claude", DRAFT)?;
    expect_success(&pent(&xdg, &["untrust", "claude"])?);
    let out = pent(&xdg, &["run", "--", "claude"])?;
    expect_failure(&out);
    assert!(
        stderr(&out).contains("the profile \"claude\" is not trusted"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

// ============================================================================
// B. pent trust
// ============================================================================

#[test]
fn test_trust_moves_the_draft_to_the_profile() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.write_draft("claude", DRAFT)?;
    let out = pent(&xdg, &["trust", "claude", "--yes"])?;
    expect_success(&out);
    let err = stderr(&out);
    assert!(err.contains("read by git"), "the draft is shown: {err}");
    assert!(err.contains("✓ trusted \"claude\""), "{err}");
    assert!(!xdg.draft_path("claude").exists());
    let profile = fs::read_to_string(xdg.profile_path("claude"))?;
    assert_eq!(profile, DRAFT, "the comments stay");

    // Trust again: nothing to do.
    let out = pent(&xdg, &["trust", "claude", "--yes"])?;
    expect_success(&out);
    assert!(stderr(&out).contains("already trusted"), "{}", stderr(&out));
    Ok(())
}

#[test]
fn test_trust_without_yes_needs_a_terminal() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.write_draft("claude", DRAFT)?;
    let out = pent(&xdg, &["trust", "claude"])?;
    expect_failure(&out);
    assert!(
        stderr(&out).contains("pent trust claude --yes"),
        "{}",
        stderr(&out)
    );
    assert!(xdg.draft_path("claude").exists(), "nothing changes");
    assert!(!xdg.profile_path("claude").exists());
    Ok(())
}

#[test]
fn test_trust_without_draft_or_profile_fails() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(&xdg, &["trust", "nothing", "--yes"])?;
    expect_failure(&out);
    assert!(
        stderr(&out).contains("record one: pent watch -- nothing"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn test_trust_rejects_an_invalid_draft() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.write_draft("claude", "[filesystem]\nwrite = [\"/\"]\n")?;
    let out = pent(&xdg, &["trust", "claude", "--yes"])?;
    expect_failure(&out);
    assert!(!xdg.profile_path("claude").exists());
    Ok(())
}

#[test]
fn test_trust_store_mode_0600() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let xdg = Xdg::new()?;
    xdg.install_profile("claude", DRAFT)?;
    let store = xdg.config.join("pent/trusted.toml");
    assert_eq!(fs::metadata(&store)?.permissions().mode() & 0o777, 0o600);
    let profile = xdg.profile_path("claude");
    assert_eq!(fs::metadata(&profile)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}

#[test]
fn test_trust_review_without_denials() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.install_profile("claude", DRAFT)?;
    let out = pent(&xdg, &["trust", "claude", "--review"])?;
    expect_success(&out);
    assert!(
        stderr(&out).contains("no denied accesses for \"claude\""),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn test_trust_review_needs_a_trusted_profile() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.write_draft("claude", DRAFT)?;
    let out = pent(&xdg, &["trust", "claude", "--review"])?;
    expect_failure(&out);
    assert!(
        stderr(&out).contains("pent trust claude"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

/// INTEGRATOR: `pent_profile::summary::summarize` is a stub that returns no
/// items. When the summary lands, also check that the draft has the denied
/// domain.
#[test]
fn test_trust_review_consumes_the_denied_log() -> TestResult {
    let xdg = Xdg::new()?;
    xdg.install_profile("claude", DRAFT)?;
    let denied = xdg.state.join("pent/denied/claude.jsonl");
    fs::create_dir_all(denied.parent().ok_or("no parent")?)?;
    fs::write(
        &denied,
        "{\"type\":\"connect\",\"host\":\"evil.example\",\"port\":443,\
         \"protocol\":\"http_connect\",\"outcome\":{\"kind\":\"denied\"}}\n",
    )?;
    let out = pent(&xdg, &["trust", "claude", "--review", "--yes"])?;
    expect_success(&out);
    assert!(!denied.exists(), "the review deletes the denied log");
    Ok(())
}

// ============================================================================
// C. pent profile
// ============================================================================

#[test]
fn test_profile_list_show_rm() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(&xdg, &["profile", "list"])?;
    expect_success(&out);
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("none"), "{}", stderr(&out));

    xdg.install_profile("claude", DRAFT)?;
    xdg.write_draft("codex", DRAFT)?;
    xdg.install_profile("gemini", DRAFT)?;
    fs::write(
        xdg.profile_path("gemini"),
        "[network]\ndomains = [\"x.example\"]\n",
    )?;

    let out = pent(&xdg, &["profile", "list"])?;
    expect_success(&out);
    let lines: Vec<String> = stdout(&out)
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(
        lines,
        vec![
            "claude trusted",
            "codex draft only",
            "gemini changed after trust"
        ]
    );

    let out = pent(&xdg, &["profile", "show", "claude"])?;
    expect_success(&out);
    assert_eq!(stdout(&out), DRAFT);
    assert!(stderr(&out).contains("(trusted)"), "{}", stderr(&out));

    let out = pent(&xdg, &["profile", "show", "codex"])?;
    expect_success(&out);
    assert_eq!(stdout(&out), DRAFT);
    assert!(stderr(&out).contains("not trusted"), "{}", stderr(&out));

    expect_failure(&pent(&xdg, &["profile", "show", "missing"])?);

    let out = pent(&xdg, &["profile", "rm", "claude"])?;
    expect_success(&out);
    assert!(!xdg.profile_path("claude").exists());
    let out = pent(&xdg, &["run", "--", "claude"])?;
    assert!(
        stderr(&out).contains("no trusted profile for \"claude\""),
        "{}",
        stderr(&out)
    );
    // The trust entry is gone too: the same content is not trusted.
    fs::write(xdg.profile_path("claude"), DRAFT)?;
    let out = pent(&xdg, &["run", "--", "claude"])?;
    assert!(stderr(&out).contains("is not trusted"), "{}", stderr(&out));
    Ok(())
}

// ============================================================================
// D. pent watch
// ============================================================================

#[test]
fn test_watch_without_yes_needs_a_terminal() -> TestResult {
    let xdg = Xdg::new()?;
    let out = pent(&xdg, &["watch", "--", "true"])?;
    expect_failure(&out);
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    Ok(())
}

/// INTEGRATOR: update this test when the recorders land. Today
/// `spawn_watched` returns `UnsupportedPlatform`, and on Linux without
/// `CAP_NET_ADMIN` the proxy cannot start. The test checks that pent shows
/// the banner, fails with a clear message, and writes no draft.
#[test]
fn test_watch_yes_reports_the_missing_recorder() -> TestResult {
    let xdg = Xdg::new()?;
    let ws = tempfile::TempDir::new()?;
    let mut cmd = Command::new(PENT);
    let out = xdg
        .apply(&mut cmd)
        .args(["watch", "--yes", "--", "true"])
        .current_dir(ws.path())
        .stdin(Stdio::null())
        .output()?;
    expect_failure(&out);
    let err = stderr(&out);
    assert!(
        err.starts_with("pent watch: true\n  Watch mode does not sandbox"),
        "{err}"
    );
    assert!(
        err.contains("✗ pent watch is not available on this platform yet")
            || err.contains("CAP_NET_ADMIN"),
        "{err}"
    );
    assert!(!err.contains("panicked"), "{err}");
    assert!(!xdg.draft_path("true").exists());
    Ok(())
}

// ============================================================================
// E. Global settings
// ============================================================================

#[test]
fn test_config_init_show_and_old_keys() -> TestResult {
    let xdg = Xdg::new()?;
    // Without a file, `config show` prints the defaults.
    let out = pent(&xdg, &["config", "show", "--format", "json"])?;
    expect_success(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout(&out))?;
    assert!(
        json.get("proxy").is_some() && json.get("sandbox").is_some(),
        "{json}"
    );

    expect_success(&pent(&xdg, &["config", "init"])?);
    let global = xdg.config.join("pent/pent.toml");
    assert!(global.exists());
    let out = pent(&xdg, &["config", "init"])?;
    expect_failure(&out);
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    let out = pent(&xdg, &["config", "show"])?;
    expect_success(&out);
    toml::from_str::<toml::Value>(&stdout(&out))?;

    for (old, key) in [
        (
            "[proxy]\ndomain_allowlist = [\"a.example\"]\n",
            "`domain_allowlist` moved to profiles",
        ),
        (
            "[sandbox.paths]\nread = [\"/x\"]\n",
            "`sandbox.paths` moved to profiles",
        ),
        ("profiles = [\"@npm\"]\n", "`profiles` was removed"),
    ] {
        fs::write(&global, old)?;
        let out = pent(&xdg, &["config", "show"])?;
        expect_failure(&out);
        let err = stderr(&out);
        assert!(err.contains(key), "{old:?}: {err}");
        assert!(err.contains("pent watch"), "{old:?}: {err}");
    }

    // `pent run` reads the global settings too.
    xdg.install_profile("claude", DRAFT)?;
    let out = pent(&xdg, &["run", "--", "claude"])?;
    expect_failure(&out);
    assert!(
        stderr(&out).contains("`profiles` was removed"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn test_removed_commands_fail() -> TestResult {
    let xdg = Xdg::new()?;
    for args in [
        &["config", "add", "@npm"][..],
        &["config", "rm", "@npm"][..],
        &["config", "trust", "--yes"][..],
        &["config", "untrust"][..],
        &["run", "--no-config", "--", "true"][..],
    ] {
        let out = pent(&xdg, args)?;
        expect_failure(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: clap usage error");
    }
    Ok(())
}
