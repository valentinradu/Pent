//! End-to-end tests for macOS agents.
//!
//! Ports `e2e/test-macos-agents.sh` to native Rust so the tests always run
//! against the freshly-built binary without a separate bash step.
//!
//! No root required.
//!
//! Run with:
//!
//! ```
//! cargo test --test e2e_macos -- --nocapture
//! ```

mod common;

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PENT_BIN: &str = env!("CARGO_BIN_EXE_pent");

    // ── config setup ─────────────────────────────────────────────────────────

    /// Create a temp $HOME with the trusted `{agent}` profile
    /// (`common::agent_profile`), and return the home directory.
    ///
    /// Pent uses the XDG paths on macOS too, so the profile lands at
    /// `$HOME/.config/pent/profiles/{agent}.toml`.
    fn agent_config(
        agent: &str,
        configs_root: &Path,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let home = configs_root.join(format!("{agent}_home"));
        let drafts = home.join(".local/state/pent/drafts");
        fs::create_dir_all(&drafts)?;
        fs::write(
            drafts.join(format!("{agent}.toml")),
            super::common::agent_profile(agent),
        )?;
        let status = Command::new(PENT_BIN)
            .args(["trust", agent, "--yes"])
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(format!("pent trust {agent} --yes failed").into());
        }
        Ok(home)
    }

    // ── run_pent helper ──────────────────────────────────────────────────────

    /// Run `pent run --profile {agent}` with the profile in `home`. The
    /// sandboxed command still sees the real `$HOME` of the test process
    /// only through the paths of the profile.
    fn run_pent(
        home: &Path,
        agent: &str,
        cwd: &Path,
        cmd: &[&str],
    ) -> Result<(ExitStatus, String), Box<dyn std::error::Error>> {
        let out = Command::new(PENT_BIN)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .args(["run", "--profile", agent, "--"])
            .args(cmd)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        Ok((out.status, stderr))
    }

    fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
        path.to_str()
            .ok_or_else(|| format!("path is not UTF-8: {}", path.display()).into())
    }

    // ── filesystem test ──────────────────────────────────────────────────────

    fn test_filesystem(agent: &str) -> TestResult {
        let configs = TempDir::new()?;
        let ws = TempDir::new()?;
        let home = agent_config(agent, configs.path())?;
        let sentinel = ws.path().join(format!("sentinel-{agent}.txt"));
        let sentinel_s = path_str(&sentinel)?;

        // 1. Workspace write must succeed.
        let (status, stderr) = run_pent(
            &home,
            agent,
            ws.path(),
            &["/bin/sh", "-c", &format!("echo ok > '{sentinel_s}'")],
        )?;
        assert!(
            status.success() && sentinel.exists(),
            "{agent}: workspace write failed (exit {:?})\nstderr: {stderr}",
            status.code()
        );

        // 2. Workspace read must succeed.
        let (status, stderr) = run_pent(&home, agent, ws.path(), &["/bin/cat", sentinel_s])?;
        assert!(
            status.success(),
            "{agent}: workspace read failed\nstderr: {stderr}"
        );

        // 3. Write to $HOME (outside workspace) must be blocked by Seatbelt.
        //    Use the real $HOME of the test process — not the fake agent_home —
        //    so we target a path the SBPL sandbox does not allow.
        //    PID suffix mirrors bash's $$ to avoid collisions between parallel runs.
        let real_home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let blocked = PathBuf::from(&real_home).join(format!(
            "pent-test-blocked-{agent}-{}.tmp",
            std::process::id()
        ));
        let blocked_s = path_str(&blocked)?;
        // The file usually does not exist; NotFound is the expected result.
        let _ = fs::remove_file(&blocked);

        // The exit status is not important: the check is the file below.
        let _ = run_pent(
            &home,
            agent,
            ws.path(),
            &[
                "/bin/sh",
                "-c",
                &format!("echo x > '{blocked_s}' 2>/dev/null; exit 0"),
            ],
        )?;
        assert!(
            !blocked.exists(),
            "{agent}: write to $HOME was NOT blocked — Seatbelt not enforcing"
        );
        // Cleanup only; the file must not exist.
        let _ = fs::remove_file(&blocked);

        // 4. Write to <workspace>/.pent must be blocked: pent writes its
        //    trace log there.
        let pent_dir = ws.path().join(".pent");
        fs::create_dir_all(&pent_dir)?;
        let pent_file = pent_dir.join("pent.toml");
        let pent_file_s = path_str(&pent_file)?;
        // The exit status is not important: the check is the file below.
        let _ = run_pent(
            &home,
            agent,
            ws.path(),
            &[
                "/bin/sh",
                "-c",
                &format!("echo x > '{pent_file_s}' 2>/dev/null; exit 0"),
            ],
        )?;
        assert!(
            !pent_file.exists(),
            "{agent}: write to .pent/pent.toml was NOT blocked"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires agent binary installed"]
    fn filesystem_claude() -> TestResult {
        test_filesystem("claude")
    }
    #[test]
    #[ignore = "requires agent binary installed"]
    fn filesystem_codex() -> TestResult {
        test_filesystem("codex")
    }
    #[test]
    #[ignore = "requires agent binary installed"]
    fn filesystem_gemini() -> TestResult {
        test_filesystem("gemini")
    }
}
