//! Shared helpers for the integration tests.
//!
//! Each test binary uses only some of the helpers.
#![allow(dead_code)] // each test binary uses a different subset of the helpers

#[cfg(unix)]
pub mod e2e;

#[cfg(target_os = "macos")]
pub mod macos;

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Path to the compiled `pent` binary, injected by Cargo at compile time.
pub const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// The profile name that the tests use for a run without an agent.
pub const TEST_PROFILE: &str = "pent-test";

/// Temporary XDG directories for one test.
///
/// Pent finds its config (profiles, trust store, `pent.toml`) and its state
/// (drafts, logs) through `XDG_CONFIG_HOME` and `XDG_STATE_HOME`. A test
/// that sets them never reads or changes the real files of the user.
pub struct Xdg {
    _dir: TempDir,
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
        })
    }

    /// Set the XDG variables on `cmd`.
    pub fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env_remove("PENT_LOG")
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
    let macos = cfg!(target_os = "macos");
    let mut read = vec!["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.npmrc"];
    let mut read_write = vec!["~/.npm"];
    let mut execute = vec!["~/.local/bin"];
    let mut domains = vec!["registry.npmjs.org", "*.npmjs.org"];
    if macos {
        read.extend([
            "~/.zshenv",
            "~/.zprofile",
            "~/.zshrc",
            "~/.CFUserTextEncoding",
            "~/Library/Preferences",
            "~/Library/Application Support/com.apple.TCC",
        ]);
        execute.push("/usr/libexec/path_helper");
    }
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
            if macos {
                read_write.push("~/Library/Application Support/claude");
            }
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
            if macos {
                read_write.push("~/Library/Application Support/gemini-cli");
            }
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
