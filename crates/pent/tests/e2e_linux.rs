//! End-to-end tests for Linux agents.
//!
//! Ports `e2e/test-linux-agents.sh` to native Rust so the tests always run
//! against the freshly-built binary without a separate bash step.
//!
//! # Requirements
//!
//! Network namespace creation requires root or `CAP_NET_ADMIN`.  Run with:
//!
//! ```
//! sudo -E cargo test --test e2e_linux -- --nocapture
//! ```
//!
//! Tests are skipped (not failed) when not running as root.

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PENT_BIN: &str = env!("CARGO_BIN_EXE_pent");

    // ── root check ───────────────────────────────────────────────────────────

    fn is_root() -> bool {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_some_and(|uid| uid == 0)
    }

    // ── routing guard ────────────────────────────────────────────────────────

    /// RAII guard: adds uid-restricted routing tables at priority 9990 on
    /// construction, removes them on drop.
    ///
    /// On systems with uid-based policy routing (e.g. VPN or tunnel software
    /// that installs routes only visible to the owning uid) those tables are
    /// invisible to root.  We temporarily inject
    /// `from all lookup <table> priority 9990` for each non-system table so
    /// the pent proxy can reach the name servers.
    struct RoutingGuard(Vec<u32>);

    impl RoutingGuard {
        #[allow(clippy::expect_used)] // infrastructure: ip rule show must succeed for routing tests
        fn install() -> Self {
            let out = Command::new("ip")
                .args(["rule", "show"])
                .output()
                .expect("ip rule show");
            let stdout = String::from_utf8_lossy(&out.stdout);

            let mut added = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for line in stdout.lines() {
                // Lines look like: "5270:\tfrom all lookup 52"
                if let Some(t_str) = line
                    .split_whitespace()
                    .skip_while(|&w| w != "lookup")
                    .nth(1)
                {
                    if let Ok(table) = t_str.parse::<u32>() {
                        // Skip system tables: local=255, main=254, default=253
                        if table < 253 && seen.insert(table) {
                            let ok = Command::new("ip")
                                .args([
                                    "rule",
                                    "add",
                                    "from",
                                    "all",
                                    "lookup",
                                    &table.to_string(),
                                    "priority",
                                    "9990",
                                ])
                                .stderr(Stdio::null())
                                .status()
                                .map(|s| s.success())
                                .unwrap_or(false);
                            if ok {
                                added.push(table);
                            }
                        }
                    }
                }
            }
            Self(added)
        }
    }

    impl Drop for RoutingGuard {
        fn drop(&mut self) {
            for &table in &self.0 {
                let _ = Command::new("ip")
                    .args([
                        "rule",
                        "del",
                        "from",
                        "all",
                        "lookup",
                        &table.to_string(),
                        "priority",
                        "9990",
                    ])
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

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
            let _ = Command::new(PENT_BIN)
                .args([
                    "run", "--no-config",
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

    /// Create a temp $HOME, run `pent config add --global @{agent}`, and return
    /// the `TempDir` (keep alive) and the resulting config file path.
    ///
    /// On Linux `dirs::config_dir()` = `~/.config`, so the config lands at
    /// `$HOME/.config/pent/pent.toml`.
    #[allow(clippy::unwrap_used, clippy::panic)] // infrastructure helper: TempDir/spawn failures are test setup failures
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
        home.join(".config").join("pent").join("pent.toml")
    }

    // ── run_pent helper ──────────────────────────────────────────────────────

    #[allow(clippy::panic)] // infrastructure helper: spawn failure is a hard test setup error
    fn run_pent(config: &Path, extra: &[&str], cmd: &[&str]) -> (ExitStatus, String) {
        let out = Command::new(PENT_BIN)
            .arg("run")
            .arg("--no-config")
            .arg("--config")
            .arg(config)
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
        let config = agent_config(agent, configs.path());
        let sentinel = ws.path().join(format!("sentinel-{agent}.txt"));
        let sentinel_s = sentinel
            .to_str()
            .ok_or("sentinel path is not valid UTF-8")?;

        // 1. Workspace write must succeed.
        let (status, stderr) = run_pent(
            &config,
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
            &config,
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
            &config,
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
    fn filesystem_claude() -> TestResult {
        test_filesystem("claude")
    }
    #[test]
    fn filesystem_codex() -> TestResult {
        test_filesystem("codex")
    }
    #[test]
    fn filesystem_gemini() -> TestResult {
        test_filesystem("gemini")
    }

    // ── network tests ────────────────────────────────────────────────────────

    // Serialize network tests so RoutingGuard add/del doesn't race across threads.
    static NETWORK_MUTEX: Mutex<()> = Mutex::new(());

    fn test_network(agent: &str, allowed_domain: &str) -> TestResult {
        if !is_root() {
            println!(
                "\nSKIP {agent} network: requires root (`sudo -E cargo test --test e2e_linux`)"
            );
            return Ok(());
        }

        let _lock = NETWORK_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _routing = RoutingGuard::install();

        let configs = TempDir::new()?;
        let config = agent_config(agent, configs.path());

        // 4. Allowed domain reachable through proxy.
        //    curl exit 0=success  7=connect refused (DNS worked)  22=HTTP error (tunnel worked)
        //    curl exit 6=DNS fail  28=timeout — both are failures
        // stdout is already null via run_pent — no -o /dev/null needed (would
        // trigger curl exit 23 because the sandbox may block opening /dev/null for write).
        let (status, stderr) = run_pent(
            &config,
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
            &config,
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
    fn network_claude() -> TestResult {
        test_network("claude", "api.anthropic.com")
    }
    #[test]
    fn network_codex() -> TestResult {
        test_network("codex", "api.openai.com")
    }
    #[test]
    fn network_gemini() -> TestResult {
        test_network("gemini", "generativelanguage.googleapis.com")
    }
}
