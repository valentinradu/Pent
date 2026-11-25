//! Shared helpers for the integration tests.
//!
//! Each test binary uses only some of the helpers.
#![allow(dead_code)] // each test binary uses a different subset of the helpers

#[cfg(unix)]
pub mod e2e;

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Path to the compiled `pent` binary, injected by Cargo at compile time.
pub const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// The profile name that the tests use for a run without an agent.
pub const TEST_PROFILE: &str = "pent-test";

/// A private runtime directory for one test, for `XDG_RUNTIME_DIR`.
///
/// `pent run` starts pentd in the runtime directory. A test that does not
/// set its own directory would hold, or start, the pentd of the user. The
/// directory is short and in `/tmp`, because the path of a Unix socket has
/// at most 107 bytes, and pent uses `XDG_RUNTIME_DIR` only below a
/// directory that the sandbox hides.
///
/// # Errors
/// Returns an error if the directory cannot be made.
pub fn runtime_dir() -> std::io::Result<TempDir> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new().prefix("pt").tempdir_in("/tmp")?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Keep pentd from starting in the runtime directory `runtime`: a regular
/// file at the path of its socket makes each start fail (PD-5). A run then
/// has no pentd, and each access that needs a question gets the refusal of
/// the base at once (RN-8 in `docs/security/run.md`). A test of a static
/// refusal uses it, so the refusal does not wait for the deadline of a
/// question.
///
/// # Errors
/// Returns an error if the directory or the file cannot be made.
pub fn block_pentd(runtime: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = runtime.join("pent");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(dir.join("pentd.sock"), "not a socket")
}

/// Give `cmd` the runtime directory `dir`, and a short linger, so the
/// pentd that `pent run` starts stops soon after the test.
pub fn use_runtime<'a>(cmd: &'a mut Command, dir: &TempDir) -> &'a mut Command {
    cmd.env("XDG_RUNTIME_DIR", dir.path())
        .env("PENTD_LINGER_MS", "200")
}

/// The text of a rule file with one allow rule for each target of
/// `targets`. A target has the text form of `pent rules show`:
/// `read /a/**` (a subtree), `write /a/b` (an exact path), `exec /a/**`,
/// `list /a`, `domain *.example.com`, `unix-socket /run/x.sock` or
/// `localhost 5432`. A target that starts with `deny ` gives a deny rule.
///
/// # Errors
/// Returns an error for a target that has no kind or no value.
pub fn rule_file_text(
    targets: &[&str],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use std::fmt::Write as _;
    let mut text = String::from("version = 1\n");
    for target in targets {
        let (decision, target) = match target.strip_prefix("deny ") {
            Some(rest) => ("deny", rest),
            None => ("allow", *target),
        };
        let (kind, value) = target
            .split_once(' ')
            .ok_or_else(|| format!("the target {target:?} has no value"))?;
        text.push_str("\n[[rule]]\n");
        writeln!(text, "kind = \"{kind}\"")?;
        match kind {
            "list" | "read" | "write" | "exec" => match value.strip_suffix("/**") {
                Some(base) => {
                    let base = if base.is_empty() { "/" } else { base };
                    writeln!(text, "width = \"subtree\"\npath = {base:?}")?;
                }
                None => writeln!(text, "width = \"exact\"\npath = {value:?}")?,
            },
            "domain" => writeln!(text, "domain = {value:?}")?,
            "unix-socket" => writeln!(text, "path = {value:?}")?,
            "localhost" => writeln!(text, "port = {value}")?,
            other => return Err(format!("unknown kind {other:?}").into()),
        }
        writeln!(
            text,
            "decision = \"{decision}\"\nsource = \"human\"\ncreated = 2026-11-22T12:00:00Z"
        )?;
    }
    Ok(text)
}

/// Write `text` as the rule file of `key` in the state directory `state`
/// (the value of `XDG_STATE_HOME`), with the mode `0600`.
///
/// # Errors
/// Returns an error if a directory or the file cannot be written.
pub fn write_rule_file(state: &std::path::Path, key: &str, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let dir = state.join("pent/rules");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join(format!("{key}.toml")))?;
    file.write_all(text.as_bytes())
}

/// Temporary XDG directories for one test.
///
/// Pent finds its config (profiles, trust store, `pent.toml`) and its state
/// (drafts, logs) through `XDG_CONFIG_HOME` and `XDG_STATE_HOME`. A test
/// that sets them never reads or changes the real files of the user.
pub struct Xdg {
    _dir: TempDir,
    runtime: TempDir,
    /// The value of `XDG_CONFIG_HOME`.
    pub config: PathBuf,
    /// The value of `XDG_STATE_HOME`.
    pub state: PathBuf,
}

impl Xdg {
    /// Make new empty XDG directories.
    ///
    /// # Errors
    /// Returns an error if the temporary directory cannot be made.
    pub fn new() -> std::io::Result<Self> {
        let dir = TempDir::new()?;
        Ok(Self {
            config: dir.path().join("config"),
            state: dir.path().join("state"),
            _dir: dir,
            runtime: runtime_dir()?,
        })
    }

    /// Set the XDG variables on `cmd`, also the runtime directory.
    pub fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        use_runtime(cmd, &self.runtime)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env_remove("PENT_LOG")
            // A refused file asks since step 5.4; see `e2e::TestEnv`.
            .env("PENT_FILE_DEADLINE_MS", "300")
    }

    /// The draft file of `name`.
    pub fn draft_path(&self, name: &str) -> PathBuf {
        self.state.join("pent/drafts").join(format!("{name}.toml"))
    }

    /// The profile file of `name`.
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.config
            .join("pent/profiles")
            .join(format!("{name}.toml"))
    }

    /// Write `toml` as the draft of `name`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn write_draft(&self, name: &str, toml: &str) -> std::io::Result<()> {
        let path = self.draft_path(name);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, toml)
    }

    /// Write the allow rules `targets` as the rule file of `key`. See
    /// [`rule_file_text`] for the form of a target.
    ///
    /// # Errors
    /// Returns an error if a target is not valid or the file cannot be
    /// written.
    pub fn install_rules(
        &self,
        key: &str,
        targets: &[&str],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        write_rule_file(&self.state, key, &rule_file_text(targets)?)?;
        Ok(())
    }

    /// Write `toml` as the draft of `name` and trust it with
    /// `pent trust NAME --yes`.
    ///
    /// # Errors
    /// Returns an error if a step fails.
    pub fn install_profile(
        &self,
        name: &str,
        toml: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.write_draft(name, toml)?;
        let out = self
            .apply(&mut Command::new(PENT))
            .args(["trust", name, "--yes"])
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(format!(
                "pent trust {name} --yes failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(())
    }
}

/// A profile for one of the coding agents, for the e2e tests.
///
/// The content comes from the old built-in profiles (`@claude`, `@codex`,
/// `@gemini` and their dependencies). Pent does not ship profiles now; the
/// user records them with `pent watch`.
pub fn agent_profile(agent: &str) -> String {
    let mut read = vec!["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.npmrc"];
    let mut read_write = vec!["~/.npm"];
    let execute = vec!["~/.local/bin"];
    let mut domains = vec!["registry.npmjs.org", "*.npmjs.org"];
    match agent {
        "claude" => {
            read.extend([
                "~/.ssh/known_hosts",
                "~/.ssh/config",
                "~/.ssh/config.d",
                "~/.gitconfig",
                "~/.config/git",
            ]);
            read_write.extend([
                "~/.claude",
                "~/.claude.json",
                "~/.claude.lock",
                "~/.local/share/claude",
                "~/.cache/claude",
            ]);
            domains.extend([
                "api.anthropic.com",
                "statsig.anthropic.com",
                "sentry.io",
                "github.com",
                "api.github.com",
                "raw.githubusercontent.com",
                "objects.githubusercontent.com",
                "codeload.github.com",
            ]);
        }
        "codex" => {
            read.push("~/.agents/skills");
            read_write.push("~/.codex");
            domains.extend(["api.openai.com", "*.openai.com"]);
        }
        "gemini" => {
            read_write.push("~/.gemini");
            domains.extend([
                "generativelanguage.googleapis.com",
                "aiplatform.googleapis.com",
                "cloudresourcemanager.googleapis.com",
                "oauth2.googleapis.com",
                "accounts.google.com",
                "cloudcode-pa.googleapis.com",
                "play.googleapis.com",
                "www.googleapis.com",
            ]);
        }
        _ => {}
    }
    let list = |v: &[&str]| -> String {
        v.iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "[filesystem]\nread = [{}]\nread_write = [{}]\nexecute = [{}]\n\n[network]\ndomains = [{}]\n",
        list(&read),
        list(&read_write),
        list(&execute),
        list(&domains)
    )
}
