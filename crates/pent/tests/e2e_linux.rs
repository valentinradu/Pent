//! End-to-end tests for Linux agents.
//!
//! Ports `e2e/test-linux-agents.sh` to native Rust so the tests always run
//! against the freshly-built binary without a separate bash step.
//!
//! # Requirements
//!
//! The tests need the agent binaries, Landlock and unprivileged user
//! namespaces. They need no root and no capability. Run with:
//!
//! ```
//! cargo test --test e2e_linux -- --ignored --nocapture
//! ```

mod common;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::OnceLock;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PENT_BIN: &str = env!("CARGO_BIN_EXE_pent");

    // ── sandbox availability probe ───────────────────────────────────────────

    fn landlock_available() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            // Phase 1: kernel supports Landlock? (ABI >= 1 means kernel >= 5.13)
            let abi: u64 = fs::read_to_string("/proc/sys/kernel/landlock_abi")
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0);
            if abi == 0 {
                println!("NOTE: Landlock not supported (kernel too old or not compiled in) — skipping filesystem tests");
                return false;
            }

            // Phase 2: pent check reports ready?
            let api_ok = Command::new(PENT_BIN)
                .arg("check")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !api_ok {
                println!("NOTE: pent check reports sandbox unavailable — skipping filesystem tests");
                return false;
            }

            // Phase 3: actually enforcing? (behavioral probe)
            let probe = "/etc/pent-landlock-probe";
            let _ = fs::remove_file(probe);
            let Ok(xdg) = super::common::Xdg::new() else {
                return false;
            };
            if xdg.install_profile(super::common::TEST_PROFILE, "").is_err() {
                return false;
            }
            let _ = xdg
                .apply(&mut Command::new(PENT_BIN))
                .args([
                    "run", "--profile", super::common::TEST_PROFILE,
                    "--network", "unrestricted",
                    "--",
                    "bash", "-c",
                    "echo probe > /etc/pent-landlock-probe 2>/dev/null; exit 0",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if Path::new(probe).exists() {
                let _ = fs::remove_file(probe);
                println!("NOTE: Landlock API available but not enforcing (kernel limitation) — skipping filesystem tests");
                false
            } else {
                true
            }
        })
    }

    // ── config setup ─────────────────────────────────────────────────────────

    /// Create a temp $HOME with the trusted `{agent}` profile
    /// (`common::agent_profile`), and return the home directory.
    ///
    /// The profile lands at `$HOME/.config/pent/profiles/{agent}.toml`.
    #[allow(clippy::unwrap_used, clippy::panic)] // infrastructure helper: TempDir/spawn failures are test setup failures
    fn agent_config(agent: &str, configs_root: &Path) -> PathBuf {
        let home = configs_root.join(format!("{agent}_home"));
        let drafts = home.join(".local/state/pent/drafts");
        fs::create_dir_all(&drafts).unwrap();
        fs::write(
            drafts.join(format!("{agent}.toml")),
            super::common::agent_profile(agent),
        )
        .unwrap();
        let status = Command::new(PENT_BIN)
            .args(["trust", agent, "--yes"])
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("pent trust {agent}: {e}"));
        assert!(status.success(), "pent trust {agent} --yes failed");
        home
    }

    // ── run_pent helper ──────────────────────────────────────────────────────

    #[allow(clippy::panic)] // infrastructure helper: spawn failure is a hard test setup error
    fn run_pent(home: &Path, agent: &str, extra: &[&str], cmd: &[&str]) -> (ExitStatus, String) {
        let out = Command::new(PENT_BIN)
            .env("HOME", home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .args(["run", "--profile", agent])
            .args(extra)
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

    // ── filesystem tests ─────────────────────────────────────────────────────

    fn test_filesystem(agent: &str) -> TestResult {
        if !landlock_available() {
            println!("\nSKIP {agent}: sandbox not enforcing");
            return Ok(());
        }

        let configs = TempDir::new()?;
        let ws = TempDir::new()?;
        let home = agent_config(agent, configs.path());
        let sentinel = ws.path().join(format!("sentinel-{agent}.txt"));
        let sentinel_s = sentinel
            .to_str()
            .ok_or("sentinel path is not valid UTF-8")?;

        // 1. Workspace write must succeed.
        let (status, stderr) = run_pent(
            &home,
            agent,
            &["--network", "unrestricted"],
            &["bash", "-c", &format!("echo ok > '{sentinel_s}'")],
        );
        assert!(
            status.success() && sentinel.exists(),
            "{agent}: workspace write failed (exit {:?})\nstderr: {stderr}",
            status.code()
        );

        // 2. Workspace read must succeed.
        let (status, stderr) = run_pent(
            &home,
            agent,
            &["--network", "unrestricted"],
            &["bash", "-c", &format!("cat '{sentinel_s}'")],
        );
        assert!(
            status.success(),
            "{agent}: workspace read failed\nstderr: {stderr}"
        );

        // 3. Write outside workspace must be blocked.
        let blocked = format!("/etc/pent-test-{agent}");
        let _ = fs::remove_file(&blocked);
        let _ = run_pent(
            &home,
            agent,
            &["--network", "unrestricted"],
            &[
                "bash",
                "-c",
                &format!("echo x > '{blocked}' 2>/dev/null; exit 0"),
            ],
        );
        assert!(
            !Path::new(&blocked).exists(),
            "{agent}: write to /etc was NOT blocked by sandbox"
        );
        let _ = fs::remove_file(&blocked);

        Ok(())
    }

    #[test]
    #[ignore = "requires agent binary"]
    fn filesystem_claude() -> TestResult {
        test_filesystem("claude")
    }
    #[test]
    #[ignore = "requires agent binary"]
    fn filesystem_codex() -> TestResult {
        test_filesystem("codex")
    }
    #[test]
    #[ignore = "requires agent binary"]
    fn filesystem_gemini() -> TestResult {
        test_filesystem("gemini")
    }

    // ── network tests ────────────────────────────────────────────────────────

    fn test_network(agent: &str, allowed_domain: &str) -> TestResult {
        let configs = TempDir::new()?;
        let home = agent_config(agent, configs.path());

        // 4. Allowed domain reachable through proxy.
        //    curl exit 0=success  7=connect refused (DNS worked)  22=HTTP error (tunnel worked)
        //    curl exit 6=DNS fail  28=timeout — both are failures
        // stdout is already null via run_pent — no -o /dev/null needed (would
        // trigger curl exit 23 because the sandbox may block opening /dev/null for write).
        let (status, stderr) = run_pent(
            &home,
            agent,
            &[],
            &[
                "curl",
                "-sS",
                "--max-time",
                "15",
                &format!("https://{allowed_domain}"),
            ],
        );
        let code = status.code().unwrap_or(-1);
        assert!(
            matches!(code, 0 | 7 | 22),
            "{agent}: allowed domain '{allowed_domain}' NOT reachable \
             (curl exit {code}, expected 0/7/22)\nstderr: {stderr}"
        );

        // 5. Blocked domain must be denied.
        //    curl exit 6=NXDOMAIN  56=proxy rejected CONNECT
        let (status, stderr) = run_pent(
            &home,
            agent,
            &[],
            &[
                "curl",
                "-sS",
                "--max-time",
                "5",
                "https://blocked-domain.invalid",
            ],
        );
        let code = status.code().unwrap_or(-1);
        assert!(
            matches!(code, 6 | 56),
            "{agent}: blocked domain NOT denied \
             (curl exit {code}, expected 6 or 56)\nstderr: {stderr}"
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires agent binary"]
    fn network_claude() -> TestResult {
        test_network("claude", "api.anthropic.com")
    }
    #[test]
    #[ignore = "requires agent binary"]
    fn network_codex() -> TestResult {
        test_network("codex", "api.openai.com")
    }
    #[test]
    #[ignore = "requires agent binary"]
    fn network_gemini() -> TestResult {
        test_network("gemini", "generativelanguage.googleapis.com")
    }
}
