//! CLI integration tests for the config trust flow, the global config, the
//! `config rm` algorithm and the config schema.
//!
//! Each test uses a temp workspace and a temp home. `HOME` and
//! `XDG_CONFIG_HOME` point into the temp home, thus the tests do not read or
//! change the real user config.
//!
//! # Running
//!
//! ```bash
//! cargo test --test config_trust_test
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Path to the compiled `pent` binary, injected by Cargo at compile time.
const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// A temp workspace and a temp home for one test.
struct TestEnv {
    workspace: TempDir,
    home: TempDir,
}

impl TestEnv {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            workspace: TempDir::new()?,
            home: TempDir::new()?,
        })
    }

    /// The workspace as pent sees it (`getcwd` gives the canonical path).
    fn workspace_canonical(&self) -> Result<PathBuf, std::io::Error> {
        fs::canonicalize(self.workspace.path())
    }

    /// Invoke `pent` in the workspace with the temp home. stdin is not a
    /// terminal.
    #[allow(clippy::panic)] // infrastructure helper: spawn failure is a hard test setup error
    fn pent(&self, args: &[&str]) -> Output {
        Command::new(PENT)
            .args(args)
            .current_dir(self.workspace.path())
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env_remove("PENT_LOG")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("Failed to spawn pent binary: {e}"))
    }

    /// The pent config directory in the temp home (as `dirs::config_dir`).
    fn config_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home
                .path()
                .join("Library")
                .join("Application Support")
                .join("pent")
        } else {
            self.home.path().join(".config").join("pent")
        }
    }

    fn write_global(&self, contents: &str) -> Result<(), std::io::Error> {
        fs::create_dir_all(self.config_dir())?;
        fs::write(self.config_dir().join("pent.toml"), contents)
    }

    fn project_path(&self) -> PathBuf {
        self.workspace.path().join(".pent").join("pent.toml")
    }

    fn write_project(&self, contents: &str) -> Result<(), std::io::Error> {
        fs::create_dir_all(self.workspace.path().join(".pent"))?;
        fs::write(self.project_path(), contents)
    }

    /// `pent config show --format json`, parsed. Also returns stderr.
    fn show(&self) -> Result<(serde_json::Value, String), Box<dyn std::error::Error>> {
        let out = self.pent(&["config", "show", "--format", "json"]);
        let stdout = expect_success(&out);
        Ok((serde_json::from_str(&stdout)?, stderr(&out)))
    }
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

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The string items of a JSON array at `json[a][b]`.
fn str_list(json: &serde_json::Value, a: &str, b: &str) -> Vec<String> {
    json[a][b]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|x| x.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn domains(json: &serde_json::Value) -> Vec<String> {
    str_list(json, "proxy", "domain_allowlist")
}

fn has(list: &[String], item: &str) -> bool {
    list.iter().any(|x| x == item)
}

// ============================================================================
// A. Trust flow
// ============================================================================

#[test]
fn test_untrusted_project_config_not_applied() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;

    let (json, err) = env.show()?;
    assert!(!has(&domains(&json), "project.example"), "{json}");
    assert!(err.contains("not trusted, not applied"), "{err}");
    assert!(err.contains("pent config trust"), "{err}");
    Ok(())
}

#[test]
fn test_run_warns_about_untrusted_project_config() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;

    // The warning comes before the sandbox starts, thus the result of the
    // command itself does not matter here.
    let out = env.pent(&["run", "--network", "unrestricted", "--", "true"]);
    let err = stderr(&out);
    assert!(err.contains("is not trusted"), "{err}");
    assert!(err.contains("pent config trust"), "{err}");
    Ok(())
}

#[test]
fn test_trust_then_applied() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;

    let out = env.pent(&["config", "trust", "--yes"]);
    expect_success(&out);
    let err = stderr(&out);
    assert!(
        err.contains("+ proxy.domain_allowlist += \"project.example\""),
        "trust must print what the project config adds: {err}"
    );

    let (json, err) = env.show()?;
    assert!(has(&domains(&json), "project.example"), "{json}");
    assert!(err.contains("trusted, applied"), "{err}");
    Ok(())
}

#[test]
fn test_trust_diff_omits_global_entries() -> TestResult {
    let env = TestEnv::new()?;
    env.write_global("[proxy]\ndomain_allowlist = [\"both.example\"]\n")?;
    env.write_project("[proxy]\ndomain_allowlist = [\"both.example\", \"new.example\"]\n")?;

    let out = env.pent(&["config", "trust", "--yes"]);
    expect_success(&out);
    let err = stderr(&out);
    assert!(err.contains("\"new.example\""), "{err}");
    assert!(!err.contains("\"both.example\""), "{err}");
    Ok(())
}

#[test]
fn test_edit_invalidates_trust() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;
    expect_success(&env.pent(&["config", "trust", "--yes"]));

    env.write_project("[proxy]\ndomain_allowlist = [\"evil.example\"]\n")?;
    let (json, err) = env.show()?;
    let list = domains(&json);
    assert!(!has(&list, "evil.example"), "{json}");
    assert!(!has(&list, "project.example"), "{json}");
    assert!(err.contains("changed after"), "{err}");
    Ok(())
}

#[test]
fn test_untrust() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;
    expect_success(&env.pent(&["config", "trust", "--yes"]));
    expect_success(&env.pent(&["config", "untrust"]));

    let (json, err) = env.show()?;
    assert!(!has(&domains(&json), "project.example"), "{json}");
    assert!(err.contains("not trusted"), "{err}");
    Ok(())
}

#[test]
fn test_trust_without_yes_needs_a_terminal() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;

    let out = env.pent(&["config", "trust"]);
    expect_failure(&out);
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));

    let (json, _) = env.show()?;
    assert!(!has(&domains(&json), "project.example"), "{json}");
    Ok(())
}

#[test]
fn test_trust_without_project_config_fails() -> TestResult {
    let env = TestEnv::new()?;
    let out = env.pent(&["config", "trust", "--yes"]);
    expect_failure(&out);
    assert!(
        stderr(&out).contains("No project config"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_trust_store_mode_0600() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let env = TestEnv::new()?;
    env.write_project("")?;
    expect_success(&env.pent(&["config", "trust", "--yes"]));
    let mode = fs::metadata(env.config_dir().join("trusted.toml"))?
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    Ok(())
}

#[test]
fn test_config_add_trusts_the_file_it_writes() -> TestResult {
    let env = TestEnv::new()?;
    expect_success(&env.pent(&["config", "add", "@cargo"]));

    let (json, err) = env.show()?;
    assert!(has(&domains(&json), "crates.io"), "{json}");
    assert!(err.contains("trusted, applied"), "{err}");

    // A second add on the trusted file keeps it trusted.
    expect_success(&env.pent(&["config", "add", "@pip"]));
    let (json, err) = env.show()?;
    assert!(has(&domains(&json), "pypi.org"), "{json}");
    assert!(err.contains("trusted, applied"), "{err}");
    Ok(())
}

#[test]
fn test_config_add_does_not_trust_an_untrusted_file() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[proxy]\ndomain_allowlist = [\"cloned.example\"]\n")?;

    let out = env.pent(&["config", "add", "@cargo"]);
    expect_success(&out);
    assert!(
        stderr(&out).contains("pent config trust"),
        "{}",
        stderr(&out)
    );

    let (json, err) = env.show()?;
    assert!(!has(&domains(&json), "cloned.example"), "{json}");
    assert!(err.contains("not trusted"), "{err}");
    Ok(())
}

// ============================================================================
// B. Global config
// ============================================================================

#[test]
fn test_global_config_loaded_without_project_config() -> TestResult {
    let env = TestEnv::new()?;
    env.write_global("[proxy]\ndomain_allowlist = [\"global.example\"]\n")?;

    let (json, err) = env.show()?;
    assert!(has(&domains(&json), "global.example"), "{json}");
    assert!(err.contains("not found"), "{err}");
    Ok(())
}

#[test]
fn test_global_config_applies_with_untrusted_project_config() -> TestResult {
    let env = TestEnv::new()?;
    env.write_global("[proxy]\ndomain_allowlist = [\"global.example\"]\n")?;
    env.write_project("[proxy]\ndomain_allowlist = [\"project.example\"]\n")?;

    let (json, _) = env.show()?;
    let list = domains(&json);
    assert!(has(&list, "global.example"), "{json}");
    assert!(!has(&list, "project.example"), "{json}");
    Ok(())
}

// ============================================================================
// C. config rm
// ============================================================================

fn project_toml(env: &TestEnv) -> Result<toml::Value, Box<dyn std::error::Error>> {
    Ok(toml::from_str(&fs::read_to_string(env.project_path())?)?)
}

fn toml_list(value: &toml::Value, path: &[&str]) -> Vec<String> {
    let mut v = Some(value);
    for key in path {
        v = v.and_then(|x| x.get(*key));
    }
    v.and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn test_config_add_records_profiles() -> TestResult {
    let env = TestEnv::new()?;
    expect_success(&env.pent(&["config", "add", "@npm"]));
    let cfg = project_toml(&env)?;
    let profiles = toml_list(&cfg, &["profiles"]);
    assert_eq!(profiles, vec!["@node", "@base", "@npm"]);
    Ok(())
}

#[test]
fn test_config_rm_keeps_entries_shared_with_other_profiles() -> TestResult {
    let env = TestEnv::new()?;
    // @gh and @claude both give github.com; only @gh gives *.github.com.
    expect_success(&env.pent(&["config", "add", "@gh", "@claude"]));
    expect_success(&env.pent(&["config", "rm", "@gh"]));

    let cfg = project_toml(&env)?;
    let list = toml_list(&cfg, &["proxy", "domain_allowlist"]);
    assert!(
        has(&list, "github.com"),
        "@claude still needs github.com: {list:?}"
    );
    assert!(has(&list, "api.anthropic.com"), "{list:?}");
    assert!(
        !has(&list, "*.github.com"),
        "only @gh gives *.github.com: {list:?}"
    );
    let rw = toml_list(&cfg, &["sandbox", "paths", "read_write"]);
    assert!(!has(&rw, "~/.config/gh"), "{rw:?}");
    let profiles = toml_list(&cfg, &["profiles"]);
    assert!(!has(&profiles, "@gh"), "{profiles:?}");
    assert!(has(&profiles, "@claude"), "{profiles:?}");
    Ok(())
}

#[test]
fn test_config_rm_keeps_manual_entries() -> TestResult {
    let env = TestEnv::new()?;
    expect_success(&env.pent(&["config", "add", "@npm"]));

    // Add entries by hand.
    let text = fs::read_to_string(env.project_path())?;
    let mut cfg: toml::Table = toml::from_str(&text)?;
    let proxy = cfg
        .entry("proxy")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(list) = proxy
        .get_mut("domain_allowlist")
        .and_then(toml::Value::as_array_mut)
    {
        list.push(toml::Value::String("manual.example".into()));
    }
    fs::write(env.project_path(), toml::to_string(&cfg)?)?;

    expect_success(&env.pent(&["config", "rm", "@npm"]));
    let cfg = project_toml(&env)?;
    let list = toml_list(&cfg, &["proxy", "domain_allowlist"]);
    assert!(has(&list, "manual.example"), "{list:?}");
    assert!(!has(&list, "registry.npmjs.org"), "{list:?}");
    Ok(())
}

#[test]
fn test_config_rm_profile_not_recorded_removes_nothing() -> TestResult {
    let env = TestEnv::new()?;
    expect_success(&env.pent(&["config", "add", "@claude"]));
    // @gh is not recorded. Its domains overlap with @claude.
    let out = env.pent(&["config", "rm", "@gh"]);
    expect_success(&out);
    assert!(
        stderr(&out).contains("not in the `profiles` list"),
        "{}",
        stderr(&out)
    );
    let cfg = project_toml(&env)?;
    let list = toml_list(&cfg, &["proxy", "domain_allowlist"]);
    assert!(has(&list, "github.com"), "{list:?}");
    Ok(())
}

#[test]
fn test_config_rm_legacy_config_without_profiles_key() -> TestResult {
    let env = TestEnv::new()?;
    // An older pent wrote this file: no `profiles` key.
    env.write_project(
        "[proxy]\ndomain_allowlist = [\"github.com\", \"*.github.com\", \"api.anthropic.com\"]\n",
    )?;
    let out = env.pent(&["config", "rm", "@gh"]);
    expect_success(&out);
    assert!(
        stderr(&out).contains("no `profiles` list"),
        "{}",
        stderr(&out)
    );

    let cfg = project_toml(&env)?;
    let list = toml_list(&cfg, &["proxy", "domain_allowlist"]);
    assert!(has(&list, "github.com"), "@claude looks present: {list:?}");
    assert!(!has(&list, "*.github.com"), "{list:?}");
    Ok(())
}

#[test]
fn test_config_rm_dependency_of_remaining_profile_fails() -> TestResult {
    let env = TestEnv::new()?;
    expect_success(&env.pent(&["config", "add", "@claude"]));
    let out = env.pent(&["config", "rm", "@node"]);
    expect_failure(&out);
    let err = stderr(&out);
    assert!(err.contains("depends on it"), "{err}");
    Ok(())
}

// ============================================================================
// D. Config schema
// ============================================================================

#[test]
fn test_unknown_key_in_global_config_fails() -> TestResult {
    let env = TestEnv::new()?;
    env.write_global("[proxy]\ndomain_alowlist = [\"x.example\"]\n")?;
    let out = env.pent(&["config", "show"]);
    expect_failure(&out);
    let err = stderr(&out);
    assert!(err.contains("domain_alowlist"), "{err}");
    assert!(err.contains("pent.toml"), "{err}");
    Ok(())
}

#[test]
fn test_unknown_key_in_project_config_cannot_be_trusted() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[sandbox.paths]\nreadwrite = [\"~/x\"]\n")?;
    let out = env.pent(&["config", "trust", "--yes"]);
    expect_failure(&out);
    assert!(stderr(&out).contains("readwrite"), "{}", stderr(&out));
    Ok(())
}

#[test]
fn test_mounts_default_readonly() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project(
        "[[sandbox.mounts]]\npath = \"/opt/a\"\n\
         [[sandbox.mounts]]\npath = \"/opt/b\"\nreadonly = false\n",
    )?;
    expect_success(&env.pent(&["config", "trust", "--yes"]));
    let (json, _) = env.show()?;
    let mounts = json["sandbox"]["mounts"]
        .as_array()
        .ok_or("mounts must be an array")?;
    assert_eq!(mounts.len(), 2, "{json}");
    assert_eq!(
        mounts[0]["readonly"],
        serde_json::Value::Bool(true),
        "{json}"
    );
    assert_eq!(
        mounts[1]["readonly"],
        serde_json::Value::Bool(false),
        "{json}"
    );
    Ok(())
}

#[test]
fn test_relative_project_path_resolves_against_workspace() -> TestResult {
    let env = TestEnv::new()?;
    env.write_project("[sandbox.paths]\nread = [\"data\"]\n")?;
    expect_success(&env.pent(&["config", "trust", "--yes"]));
    let (json, _) = env.show()?;
    let read = str_list(&json["sandbox"], "paths", "read");
    let expected = Path::new(&env.workspace_canonical()?).join("data");
    assert!(
        has(&read, &expected.to_string_lossy()),
        "expected {expected:?} in {read:?}"
    );
    Ok(())
}
