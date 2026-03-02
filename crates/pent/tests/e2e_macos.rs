//! End-to-end tests for macOS agents.
//!
//! Ports `e2e/test-macos-agents.sh` to native Rust so the tests always run
//! against the freshly-built binary without a separate bash step.
//!
//! Network containment is not tested on macOS — see README for details.
//! No root required.
//!
//! Run with:
//!
//! ```
//! cargo test --test e2e_macos -- --nocapture
//! ```

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use tempfile::TempDir;

    const PENT_BIN: &str = env!("CARGO_BIN_EXE_pent");

    // ── config setup ─────────────────────────────────────────────────────────

    /// Create a temp $HOME, run `pent config add --global @{agent}`, and return
    /// the TempDir (keep alive) and the resulting config file path.
    ///
    /// On macOS `dirs::config_dir()` = `~/Library/Application Support`, so
    /// the config lands at:
    ///   `$HOME/Library/Application Support/pent/pent.toml`
    fn agent_config(agent: &str, configs_root: &Path) -> PathBuf {
        let home = configs_root.join(format!("{agent}_home"));
        fs::create_dir_all(&home).unwrap();
        let status = Command::new(PENT_BIN)
            .args(["config", "add", "--global", &format!("@{agent}")])
            .env("HOME", &home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("pent config add @{agent}: {e}"));
        assert!(status.success(), "pent config add --global @{agent} failed");
        home.join("Library")
            .join("Application Support")
            .join("pent")
            .join("pent.toml")
    }

    // ── run_pent helper ──────────────────────────────────────────────────────

    fn run_pent(config: &Path, cmd: &[&str]) -> (ExitStatus, String) {
        let out = Command::new(PENT_BIN)
            .arg("run")
            .arg("--no-config")
            .arg("--config")
            .arg(config)
            .arg("--")
            .args(cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap_or_else(|e| panic!("pent spawn: {e}"));
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (out.status, stderr)
    }

    // ── filesystem test ──────────────────────────────────────────────────────

    fn test_filesystem(agent: &str) {
        let configs = TempDir::new().unwrap();
        let ws = TempDir::new().unwrap();
        let config = agent_config(agent, configs.path());
        let sentinel = ws.path().join(format!("sentinel-{agent}.txt"));
        let sentinel_s = sentinel.to_str().unwrap();

        // 1. Workspace write must succeed.
        let (status, stderr) = run_pent(
            &config,
            &["/bin/sh", "-c", &format!("echo ok > '{sentinel_s}'")],
        );
        assert!(
            status.success() && sentinel.exists(),
            "{agent}: workspace write failed (exit {:?})\nstderr: {stderr}",
            status.code()
        );

        // 2. Workspace read must succeed.
        let (status, stderr) = run_pent(&config, &["/bin/cat", sentinel_s]);
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
        let blocked_s = blocked.to_str().unwrap();
        let _ = fs::remove_file(&blocked);

        let _ = run_pent(
            &config,
            &[
                "/bin/sh",
                "-c",
                &format!("echo x > '{blocked_s}' 2>/dev/null; exit 0"),
            ],
        );
        assert!(
            !blocked.exists(),
            "{agent}: write to $HOME was NOT blocked — Seatbelt not enforcing"
        );
        let _ = fs::remove_file(&blocked);
    }

    #[test]
    fn filesystem_claude() {
        test_filesystem("claude");
    }
    #[test]
    fn filesystem_codex() {
        test_filesystem("codex");
    }
    #[test]
    fn filesystem_gemini() {
        test_filesystem("gemini");
    }
}
