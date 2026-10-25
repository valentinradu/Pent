//! End-to-end tests on Linux: the real `pent` binary, the real sandbox.
//!
//! Each test has its own directories below `CARGO_TARGET_TMPDIR` (see
//! `common::e2e::TestEnv`): its own `HOME`, `XDG_CONFIG_HOME`,
//! `XDG_STATE_HOME` and workspace. The tests share no state and run in
//! parallel.
//!
//! # Requirements
//!
//! Landlock (ABI v3 or later) and unprivileged user namespaces. Pent needs
//! no root and no capability. The tests find `sh`, `curl`, `getent`, `sleep`
//! and `sudo` in `PATH`. A test skips (it prints `SKIP` and passes) when the
//! sandbox is not available or a tool is missing. The network tests need
//! the internet; they skip when `curl https://example.com` fails without
//! pent.
//!
//! No test has an `#[ignore]` mark: a test that the continuous integration
//! must run never carries one. Set `PENT_REQUIRE_ALL_TESTS=1` to make each
//! skip a failure.
//!
//! ```text
//! cargo test -p pent --test e2e_linux -- --nocapture
//! ```

mod common;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Stdio;
    use std::time::Duration;

    use super::common::agent_profile;
    use super::common::e2e::{
        have_tools, internet, sandbox_ready, staging_dirs, stderr, stdout, wait_timeout, BoxError,
        TestEnv, TestResult,
    };

    /// The time limit for one pent command.
    const TIMEOUT: Duration = Duration::from_secs(60);

    /// The time limit for one answer on the terminal.
    const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Return true if the test can run: the sandbox works and the tools are
    /// in `PATH`.
    fn ready(test: &str, tools: &[&str]) -> bool {
        have_tools(test, tools) && sandbox_ready(test)
    }

    /// The string list `key` in the table `table` of a profile.
    fn rules(toml_text: &str, table: &str, key: &str) -> Result<BTreeSet<String>, BoxError> {
        let doc: toml::Value = toml::from_str(toml_text)?;
        let Some(list) = doc.get(table).and_then(|t| t.get(key)) else {
            return Ok(BTreeSet::new());
        };
        let list = list
            .as_array()
            .ok_or_else(|| format!("{table}.{key} is not a list"))?;
        list.iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| BoxError::from(format!("{table}.{key} has a non-string value")))
            })
            .collect()
    }

    /// A set of strings, for the comparisons.
    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// The lines of `pent profile list`, with single spaces.
    fn profile_list(env: &TestEnv) -> Result<Vec<String>, BoxError> {
        let out = env.pent_ok(&["profile", "list"])?;
        Ok(stdout(&out)
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect())
    }

    // ── the agent profiles ───────────────────────────────────────────────────

    /// The profile of an agent keeps the workspace read-write and denies a
    /// write outside the workspace.
    fn agent_filesystem(agent: &str) -> TestResult {
        if !ready(agent, &["sh"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile(agent, &agent_profile(agent))?;
        let run = |script: &str| {
            env.pent(&[
                "run",
                "--profile",
                agent,
                "--network",
                "unrestricted",
                "--",
                "sh",
                "-c",
                script,
            ])
        };

        let out = run("echo ok > sentinel.txt")?;
        assert!(out.status.success(), "{agent}: {}", stderr(&out));
        assert_eq!(fs::read_to_string(env.ws.join("sentinel.txt"))?, "ok\n");

        let out = run("cat sentinel.txt")?;
        assert!(out.status.success(), "{agent}: {}", stderr(&out));
        assert_eq!(stdout(&out), "ok\n");

        let outside = env.root.join(format!("outside-{agent}"));
        let out = run(&format!("echo x > '{}'", outside.display()))?;
        assert!(!out.status.success(), "{agent}: the write must fail");
        assert!(
            !outside.exists(),
            "{agent}: the write outside the workspace was not denied"
        );
        Ok(())
    }

    #[test]
    fn filesystem_claude() -> TestResult {
        agent_filesystem("claude")
    }

    #[test]
    fn filesystem_codex() -> TestResult {
        agent_filesystem("codex")
    }

    #[test]
    fn filesystem_gemini() -> TestResult {
        agent_filesystem("gemini")
    }

    /// The profile of an agent allows its API domain and denies other
    /// domains.
    fn agent_network(agent: &str, allowed: &str) -> TestResult {
        if !ready(agent, &["curl"]) || !internet(agent) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile(agent, &agent_profile(agent))?;
        let curl = |url: &str| {
            env.pent(&[
                "run",
                "--profile",
                agent,
                "--",
                "curl",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "20",
                url,
            ])
        };

        // Any HTTP answer (also 404) proves that the proxy forwarded the
        // connection.
        let out = curl(&format!("https://{allowed}"))?;
        let code = stdout(&out);
        assert!(
            code.len() == 3 && code != "000",
            "{agent}: {allowed} is not reachable (http code {code:?})\nstderr: {}",
            stderr(&out)
        );

        let out = curl("https://blocked-domain.invalid")?;
        assert!(!out.status.success(), "{agent}: the domain was not denied");
        assert_eq!(stdout(&out), "000", "{agent}: {}", stderr(&out));
        Ok(())
    }

    #[test]
    fn network_claude() -> TestResult {
        agent_network("claude", "api.anthropic.com")
    }

    #[test]
    fn network_codex() -> TestResult {
        agent_network("codex", "api.openai.com")
    }

    #[test]
    fn network_gemini() -> TestResult {
        agent_network("gemini", "generativelanguage.googleapis.com")
    }

    // ── pent run without a trusted profile ───────────────────────────────────

    /// `pent run` does not start the program without a trusted profile. The
    /// message tells the next step: record, trust, or trust again.
    #[test]
    fn run_needs_a_trusted_profile() -> TestResult {
        if !ready("run_needs_a_trusted_profile", &["sh"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let marker = env.ws.join("ran");
        let script = "touch ran";
        let run = || env.pent(&["run", "--profile", "m", "--", "sh", "-c", script]);

        let out = run()?;
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(
            err.contains("✗ no trusted profile for \"m\"\n  record one: pent watch --profile m -- sh -c 'touch ran'"),
            "{err}"
        );
        assert!(!marker.exists(), "the program must not start");

        env.pent_ok(&["watch", "--yes", "--profile", "m", "--", "sh", "-c", "true"])?;
        let out = run()?;
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(err.contains("the draft is not trusted"), "{err}");
        assert!(err.contains("review and trust it: pent trust m"), "{err}");
        assert!(!marker.exists(), "the program must not start");

        env.pent_ok(&["trust", "m", "--yes"])?;
        let out = run()?;
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(marker.exists());
        fs::remove_file(&marker)?;

        let profile = env.profile_path("m");
        let mut text = fs::read_to_string(&profile)?;
        text.push_str("\n[network]\ndomains = [\"evil.example\"]\n");
        fs::write(&profile, text)?;
        let out = run()?;
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(
            err.contains("the profile \"m\" changed after you trusted it"),
            "{err}"
        );
        assert!(err.contains("pent trust m"), "{err}");
        assert!(!marker.exists(), "the program must not start");
        Ok(())
    }

    // ── watch → trust → run ──────────────────────────────────────────────────

    /// The watched program reads a file, edits one config file, edits two
    /// files in one directory and makes files in its cache. The draft has
    /// one rule for each, and the trusted profile allows exactly these
    /// accesses: other paths in the home directory stay hidden, and writes
    /// to them never reach the real home directory.
    #[test]
    fn watch_trust_run_gives_exactly_the_recorded_accesses() -> TestResult {
        if !ready("watch_trust_run", &["sh"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".foorc", "foo\n")?;
        env.write_home(".config/app/settings.toml", "a = 1\n")?;
        env.write_home(".config/app/other.toml", "other\n")?;
        env.write_home(".local/share/data/x", "x\n")?;
        env.write_home(".local/share/data/y", "y\n")?;
        env.write_home(".local/share/other/file", "other\n")?;
        env.write_home(".secret", "secret\n")?;
        fs::create_dir_all(env.home_path(".cache"))?;

        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "t",
            "--",
            "sh",
            "-c",
            "cat ~/.foorc; echo 'b = 2' >> ~/.config/app/settings.toml; \
             echo x2 > ~/.local/share/data/x; echo y2 > ~/.local/share/data/y; \
             mkdir -p ~/.cache/tool/sub; echo c > ~/.cache/tool/sub/c1",
        ])?;
        assert_eq!(stdout(&out), "foo\n");
        let draft = fs::read_to_string(env.draft_path("t"))?;
        assert_eq!(
            rules(&draft, "filesystem", "read_write")?,
            set(&[
                "~/.cache/tool",
                "~/.config/app/settings.toml",
                "~/.local/share/data"
            ]),
            "{draft}"
        );
        assert_eq!(
            rules(&draft, "filesystem", "read")?,
            set(&["~/.foorc"]),
            "{draft}"
        );
        assert!(draft.contains("# cache"), "{draft}");
        assert!(draft.contains("# config file"), "{draft}");

        env.pent_ok(&["trust", "t", "--yes"])?;
        assert!(env.profile_path("t").exists());

        let out = env.pent(&[
            "run",
            "--profile",
            "t",
            "--",
            "sh",
            "-c",
            "cat ~/.foorc; \
             echo 'c = 3' >> ~/.config/app/settings.toml && echo SETTINGS_OK; \
             echo x3 > ~/.local/share/data/x && echo DATA_OK; \
             echo n > ~/.local/share/data/new && echo DATA_NEW_OK; \
             echo c2 > ~/.cache/tool/c2 && echo CACHE_OK; \
             cat ~/.config/app/other.toml 2>/dev/null || echo SIBLING_HIDDEN; \
             cat ~/.local/share/other/file 2>/dev/null || echo OTHER_DIR_HIDDEN; \
             cat ~/.secret 2>/dev/null || echo SECRET_DENIED; \
             echo w 2>/dev/null > ~/.foorc; \
             echo leak 2>/dev/null > ~/.config/app/leak.toml; \
             echo leak 2>/dev/null > ~/.leak; \
             echo leak 2>/dev/null > ~/.local/share/leak; \
             echo DONE",
        ])?;
        let text = stdout(&out);
        let expected = [
            "foo",
            "SETTINGS_OK",
            "DATA_OK",
            "DATA_NEW_OK",
            "CACHE_OK",
            "SIBLING_HIDDEN",
            "OTHER_DIR_HIDDEN",
            "SECRET_DENIED",
            "DONE",
        ];
        assert_eq!(
            text.lines().collect::<Vec<_>>(),
            expected,
            "stderr: {}",
            stderr(&out)
        );

        // The allowed writes reach the real home directory.
        assert_eq!(
            fs::read_to_string(env.home_path(".config/app/settings.toml"))?,
            "a = 1\nb = 2\nc = 3\n"
        );
        assert_eq!(
            fs::read_to_string(env.home_path(".local/share/data/x"))?,
            "x3\n"
        );
        assert!(env.home_path(".local/share/data/new").exists());
        assert!(env.home_path(".cache/tool/c2").exists());
        // The other paths do not change. A write to them can work in the
        // overlay of the home directory, but pent discards it.
        assert_eq!(fs::read_to_string(env.home_path(".foorc"))?, "foo\n");
        assert_eq!(
            fs::read_to_string(env.home_path(".config/app/other.toml"))?,
            "other\n"
        );
        for leak in [".config/app/leak.toml", ".leak", ".local/share/leak"] {
            assert!(
                !env.home_path(leak).exists(),
                "~/{leak} reached the real home directory"
            );
        }
        Ok(())
    }

    // ── the watch guard ──────────────────────────────────────────────────────

    /// The guard of `pent watch` blocks a credential read, writes to the
    /// shell rc files and to the files of pent, and privilege escalation.
    /// The summary lists the attempts in the Blocked section, and the draft
    /// does not have them.
    #[test]
    fn watch_guard_blocks_dangerous_accesses() -> TestResult {
        if !ready("watch_guard", &["sh", "cat", "grep", "touch"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".ssh/id_x", "SECRET-KEY\n")?;
        env.write_home(".zshrc", "z\n")?;
        fs::create_dir_all(env.config_dir().join("pent"))?;
        let sudo = super::common::e2e::which("sudo").is_some();
        let sudo_part = if sudo {
            "sudo -n id -u 2>/dev/null; echo \"sudo=$?\""
        } else {
            eprintln!("NOTE watch_guard: sudo is not in PATH; only NO_NEW_PRIVS is checked");
            "true"
        };
        let script = format!(
            "echo \"ssh=[$(cat ~/.ssh/id_x)]\"; \
             echo pwn 2>/dev/null >> ~/.bashrc; echo \"bashrc=$?\"; \
             echo pwn 2>/dev/null >> ~/.zshrc; echo \"zshrc=$?\"; \
             touch ~/.config/pent/x 2>/dev/null; echo \"pent=$?\"; \
             grep NoNewPrivs /proc/self/status; {sudo_part}"
        );
        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "g",
            "--",
            "sh",
            "-c",
            &script,
        ])?;
        let text = stdout(&out);
        let err = stderr(&out);
        assert!(text.contains("ssh=[]\n"), "the key was readable: {text}");
        // Each write fails. The status of a failed redirection depends on
        // the shell (1 in bash, 2 in dash).
        for name in ["bashrc", "zshrc", "pent"] {
            let status = text
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{name}=")))
                .ok_or_else(|| format!("no status for {name}: {text}"))?;
            assert_ne!(status, "0", "the write to {name} worked: {text}");
        }
        assert!(text.contains("NoNewPrivs:\t1\n"), "{text}");
        if sudo {
            assert!(!text.lines().any(|l| l == "0"), "sudo became root: {text}");
            assert!(!text.contains("sudo=0"), "{text}");
        }
        assert!(!env.home_path(".bashrc").exists(), "~/.bashrc was made");
        assert_eq!(fs::read_to_string(env.home_path(".zshrc"))?, "z\n");
        assert!(!env.config_dir().join("pent/x").exists());

        let blocked = err
            .split("Blocked by the guard")
            .nth(1)
            .ok_or_else(|| format!("no Blocked section:\n{err}"))?;
        for item in [
            "read ~/.ssh/id_x",
            "write ~/.bashrc",
            "write ~/.zshrc",
            "write ~/.config/pent/x",
        ] {
            assert!(blocked.contains(item), "{item} is not blocked:\n{err}");
        }
        if sudo {
            assert!(blocked.contains("runs sudo"), "{err}");
        }
        let draft = fs::read_to_string(env.draft_path("g"))?;
        for path in ["id_x", "bashrc", "zshrc", "pent/x"] {
            assert!(!draft.contains(path), "the draft has {path}:\n{draft}");
        }
        // The draft does not let the program run sudo. (sudo can read its
        // libraries before it fails, thus the draft can have read rules for
        // them.)
        assert_eq!(rules(&draft, "filesystem", "execute")?, set(&[]), "{draft}");
        Ok(())
    }

    // ── the interactive review ───────────────────────────────────────────────

    /// Prepare the files of the review tests and return the watched script.
    /// The summary has two read-write rules, two read rules and two blocked
    /// items.
    fn review_setup(env: &TestEnv) -> Result<&'static str, BoxError> {
        env.write_home(".foorc", "foo\n")?;
        env.write_home(".barrc", "bar\n")?;
        env.write_home(".config/app/settings.toml", "a = 1\n")?;
        env.write_home(".ssh/id_x", "KEY\n")?;
        fs::create_dir_all(env.home_path(".cache"))?;
        Ok("cat ~/.foorc ~/.barrc >/dev/null; \
            echo 'b = 2' >> ~/.config/app/settings.toml; \
            mkdir -p ~/.cache/tool; echo c > ~/.cache/tool/c; \
            cat ~/.ssh/id_x; echo x 2>/dev/null >> ~/.bashrc; true")
    }

    /// The number of the item that has `needle`, in the section that starts
    /// at `title` in `text`.
    fn item_number(text: &str, title: &str, needle: &str) -> Result<String, BoxError> {
        let section = text
            .rsplit(title)
            .next()
            .ok_or_else(|| format!("no section {title:?}:\n{text}"))?;
        section
            .lines()
            .find(|l| l.contains(needle))
            .and_then(|l| l.split_whitespace().next())
            .map(str::to_string)
            .ok_or_else(|| format!("no item {needle:?} in {title:?}:\n{text}").into())
    }

    /// The review on a terminal: Enter accepts a section, `n` rejects one,
    /// an invalid answer asks again, a number picks one blocked item, and
    /// `y` trusts the profile.
    #[test]
    fn review_on_a_terminal_follows_the_answers() -> TestResult {
        if !ready("review_on_a_terminal", &["sh", "cat", "mkdir"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let script = review_setup(&env)?;
        let mut pty = env.spawn_pty(&["watch", "--profile", "r", "--", "sh", "-c", script])?;
        pty.expect("Continue? [y/N]", PROMPT_TIMEOUT)?;
        pty.send_line("y")?;

        pty.expect("Read-write (2)", PROMPT_TIMEOUT)?;
        pty.expect("[a] ", PROMPT_TIMEOUT)?;
        pty.send_line("")?;

        pty.expect("Read (2)", PROMPT_TIMEOUT)?;
        pty.expect("[a] ", PROMPT_TIMEOUT)?;
        pty.send_line("7")?;
        pty.expect("Enter a, n, or numbers from 1 to 2", PROMPT_TIMEOUT)?;
        pty.expect("[a] ", PROMPT_TIMEOUT)?;
        pty.send_line("n")?;

        pty.expect("Blocked by the guard (2)", PROMPT_TIMEOUT)?;
        pty.expect("[n] ", PROMPT_TIMEOUT)?;
        let key = item_number(&pty.text(), "Blocked by the guard (2)", "~/.ssh/id_x")?;
        pty.send_line(&key)?;

        pty.expect("3 of 6 rules selected", PROMPT_TIMEOUT)?;
        pty.expect("Trust this profile now? [y/N]", PROMPT_TIMEOUT)?;
        pty.send_line("y")?;
        let (status, text) = pty.wait(TIMEOUT)?;
        assert!(status.success(), "{text}");
        assert!(text.contains("trusted \"r\""), "{text}");

        let profile = fs::read_to_string(env.profile_path("r"))?;
        assert_eq!(
            rules(&profile, "filesystem", "read_write")?,
            set(&["~/.cache/tool", "~/.config/app/settings.toml"]),
            "{profile}"
        );
        assert_eq!(
            rules(&profile, "filesystem", "read")?,
            set(&["~/.ssh/id_x"]),
            "{profile}"
        );
        assert!(!profile.contains("bashrc"), "{profile}");

        // The trusted profile works at once.
        let out = env.pent(&["run", "--profile", "r", "--", "cat", "/dev/null"])?;
        assert!(out.status.success(), "{}", stderr(&out));
        Ok(())
    }

    /// The review on a terminal with `a` and `n` and without the trust: the
    /// draft has the choice, and `pent trust` asks on the terminal.
    #[test]
    fn review_on_a_terminal_without_trust() -> TestResult {
        if !ready("review_without_trust", &["sh", "cat", "mkdir"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let script = review_setup(&env)?;
        let mut pty = env.spawn_pty(&["watch", "--profile", "r", "--", "sh", "-c", script])?;
        pty.expect("Continue? [y/N]", PROMPT_TIMEOUT)?;
        pty.send_line("y")?;
        pty.expect("Read-write (2)", PROMPT_TIMEOUT)?;
        pty.expect("[a] ", PROMPT_TIMEOUT)?;
        pty.send_line("n")?;
        pty.expect("Read (2)", PROMPT_TIMEOUT)?;
        pty.expect("[a] ", PROMPT_TIMEOUT)?;
        pty.send_line("a")?;
        // Enter keeps the default of the blocked section: none.
        pty.expect("Blocked by the guard (2)", PROMPT_TIMEOUT)?;
        pty.expect("[n] ", PROMPT_TIMEOUT)?;
        pty.send_line("")?;
        pty.expect("Trust this profile now? [y/N]", PROMPT_TIMEOUT)?;
        pty.send_line("")?;
        let (status, text) = pty.wait(TIMEOUT)?;
        assert!(status.success(), "{text}");
        assert!(text.contains("review and trust it: pent trust r"), "{text}");
        assert!(!env.profile_path("r").exists(), "the profile is trusted");

        let draft = fs::read_to_string(env.draft_path("r"))?;
        assert_eq!(rules(&draft, "filesystem", "read_write")?, set(&[]));
        assert_eq!(
            rules(&draft, "filesystem", "read")?,
            set(&["~/.barrc", "~/.foorc"]),
            "{draft}"
        );

        // `pent trust` shows the draft and asks. "n" keeps it a draft.
        let mut pty = env.spawn_pty(&["trust", "r"])?;
        pty.expect("Trust this profile? [y/N]", PROMPT_TIMEOUT)?;
        pty.send_line("n")?;
        let (_, text) = pty.wait(TIMEOUT)?;
        assert!(!env.profile_path("r").exists(), "{text}");

        let mut pty = env.spawn_pty(&["trust", "r"])?;
        pty.expect("~/.foorc", PROMPT_TIMEOUT)?;
        pty.expect("Trust this profile? [y/N]", PROMPT_TIMEOUT)?;
        pty.send_line("y")?;
        let (status, text) = pty.wait(TIMEOUT)?;
        assert!(status.success(), "{text}");
        assert!(env.profile_path("r").exists(), "{text}");
        Ok(())
    }

    // ── network ──────────────────────────────────────────────────────────────

    /// Watch records the domain. The trusted profile allows it and denies
    /// other domains, also at the DNS level. A direct connection past the
    /// proxy fails. `pent trust --review` adds a denied domain.
    #[test]
    fn network_watch_trust_run_review() -> TestResult {
        if !ready("network_flow", &["curl", "sh"]) || !internet("network_flow") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let curl = ["curl", "-sS", "-o", "/dev/null", "--max-time", "20"];
        let with = |extra: &[&str]| -> Vec<String> {
            curl.iter().chain(extra).map(|s| (*s).to_string()).collect()
        };
        let run = |args: &[String]| {
            let mut all = vec!["run", "--profile", "net", "--"];
            all.extend(args.iter().map(String::as_str));
            env.pent(&all)
        };

        let mut watch = vec!["watch", "--yes", "--profile", "net", "--"];
        let args = with(&["https://example.com"]);
        watch.extend(args.iter().map(String::as_str));
        env.pent_ok(&watch)?;
        let draft = fs::read_to_string(env.draft_path("net"))?;
        assert_eq!(
            rules(&draft, "network", "domains")?,
            set(&["example.com"]),
            "{draft}"
        );
        env.pent_ok(&["trust", "net", "--yes"])?;

        let out = run(&with(&["https://example.com"]))?;
        assert!(out.status.success(), "allowed: {}", stderr(&out));

        let out = run(&with(&["https://example.org"]))?;
        assert!(!out.status.success(), "example.org must be denied");
        assert!(
            stderr(&out).contains("1 access denied; review it: pent trust net --review"),
            "{}",
            stderr(&out)
        );

        let out = run(&with(&["--noproxy", "*", "https://example.com"]))?;
        assert!(
            !out.status.success(),
            "a direct connection must fail: {}",
            stderr(&out)
        );

        if have_tools("network_flow (getent)", &["getent"]) {
            let out = run(&[
                "sh".to_string(),
                "-c".to_string(),
                "getent hosts example.com >/dev/null && echo ALLOWED_RESOLVES; \
                 getent hosts example.org >/dev/null || echo DENIED_FAILS"
                    .to_string(),
            ])?;
            assert_eq!(
                stdout(&out),
                "ALLOWED_RESOLVES\nDENIED_FAILS\n",
                "{}",
                stderr(&out)
            );
        }

        let denied = fs::read_to_string(env.denied_log("net"))?;
        assert!(denied.contains("\"example.org\""), "{denied}");

        let out = env.pent_ok(&["trust", "net", "--review", "--yes"])?;
        assert!(stderr(&out).contains("example.org"), "{}", stderr(&out));
        let profile = fs::read_to_string(env.profile_path("net"))?;
        assert_eq!(
            rules(&profile, "network", "domains")?,
            set(&["example.com", "example.org"]),
            "{profile}"
        );
        assert!(
            !env.denied_log("net").exists(),
            "the review must consume the denied log"
        );

        let out = run(&with(&["https://example.org"]))?;
        assert!(out.status.success(), "after review: {}", stderr(&out));
        Ok(())
    }

    // ── --trace ──────────────────────────────────────────────────────────────

    /// `--trace` writes a denied filesystem access and a denied domain to
    /// `$XDG_STATE_HOME/pent/trace/<profile>.log`, each with a fix hint. The proxy denies the domain
    /// before any connection, so this test needs no internet.
    #[test]
    fn trace_logs_filesystem_and_network_denials() -> TestResult {
        if !ready("trace", &["sh", "cat", "curl"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("tr", "[network]\ndomains = [\"allowed.example\"]\n")?;
        let outside = env.root.join("outside.txt");
        fs::write(&outside, "secret\n")?;
        let script = format!(
            "cat '{}'; curl -sS -o /dev/null --max-time 10 https://denied.example; true",
            outside.display()
        );
        let out = env.pent(&[
            "run",
            "--profile",
            "tr",
            "--trace",
            "--",
            "sh",
            "-c",
            &script,
        ])?;
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(!stdout(&out).contains("secret"), "the read was not denied");

        let log = fs::read_to_string(env.trace_log("tr"))?;
        assert!(
            !env.ws.join(".pent/trace.log").exists(),
            "the trace log must not be in the workspace"
        );
        assert!(
            log.contains("pent: [denied] filesystem: \"cat\" (pid "),
            "{log}"
        );
        assert!(
            log.contains(&format!("was denied read on \"{}\"", outside.display())),
            "{log}"
        );
        assert!(
            log.contains(&format!("--read \"{}\"", outside.display())),
            "{log}"
        );
        assert!(
            log.contains("pent: [denied] network:") && log.contains("\"denied.example\""),
            "{log}"
        );
        assert!(log.contains("--allow denied.example"), "{log}");

        // The denials are in the list for `pent trust --review` too.
        let denied = fs::read_to_string(env.denied_log("tr"))?;
        assert!(denied.contains("outside.txt"), "{denied}");
        assert!(denied.contains("denied.example"), "{denied}");
        Ok(())
    }

    // ── signals ──────────────────────────────────────────────────────────────

    /// SIGTERM to pent ends the child. Pent removes its overlay staging
    /// directories and exits like the child: killed by SIGTERM (status 143
    /// in a shell).
    #[test]
    fn sigterm_ends_the_child_and_cleans_up() -> TestResult {
        if !ready("sigterm", &["sh", "sleep"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".config/app/settings.toml", "a = 1\n")?;
        env.install_profile(
            "sig",
            "[filesystem]\nread_write = [\"~/.config/app/settings.toml\"]\n",
        )?;
        // A unique argument: the test finds the sleep process by it.
        let nap = format!("300.{}", std::process::id());
        let script = format!("touch started; exec sleep {nap}");
        let mut child = env
            .command(&["run", "--profile", "sig", "--", "sh", "-c", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        let started = env.ws.join("started");
        let deadline = std::time::Instant::now() + TIMEOUT;
        while !started.exists() {
            if let Some(status) = child.try_wait()? {
                return Err(format!("pent exited before the child started: {status:?}").into());
            }
            if std::time::Instant::now() >= deadline {
                // The kill can fail when pent exits now; the wait reaps it.
                let _ = child.kill();
                child.wait()?;
                return Err("the child did not start".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !staging_dirs(pid).is_empty(),
            "the run has no overlay staging directory"
        );
        let sleepers = || sleep_processes(&nap);
        let deadline = std::time::Instant::now() + TIMEOUT;
        while sleepers().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!sleepers().is_empty(), "the child does not run");

        let pid_i32 = i32::try_from(pid)?;
        // SAFETY: kill() has no memory-safety preconditions. The pid is the
        // pent process of this test, and the test did not reap it yet.
        let rc = unsafe { libc::kill(pid_i32, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill: {}", std::io::Error::last_os_error());
        let status = wait_timeout(&mut child, TIMEOUT)?;
        assert!(
            status.code() == Some(143) || status.signal() == Some(libc::SIGTERM),
            "pent must exit like the child (SIGTERM): {status:?}"
        );
        assert!(sleepers().is_empty(), "the child still runs");
        assert_eq!(staging_dirs(pid), Vec::<std::path::PathBuf>::new());
        Ok(())
    }

    /// The process IDs of the `sleep` processes with the argument `arg`.
    fn sleep_processes(arg: &str) -> Vec<u32> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                fs::read(format!("/proc/{pid}/cmdline"))
                    .is_ok_and(|c| c.split(|b| *b == 0).any(|part| part == arg.as_bytes()))
            })
            .collect()
    }

    // ── profile management ───────────────────────────────────────────────────

    /// `pent profile list/show/rm` and `pent untrust` through the full
    /// flow.
    #[test]
    fn profile_list_show_untrust_rm() -> TestResult {
        if !ready("profile_management", &["sh", "cat"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".foorc", "foo\n")?;
        let out = env.pent_ok(&["profile", "list"])?;
        assert!(stdout(&out).is_empty(), "{}", stdout(&out));

        env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "pm",
            "--",
            "sh",
            "-c",
            "cat ~/.foorc",
        ])?;
        assert_eq!(profile_list(&env)?, vec!["pm draft only"]);

        env.pent_ok(&["trust", "pm", "--yes"])?;
        assert_eq!(profile_list(&env)?, vec!["pm trusted"]);
        let out = env.pent_ok(&["profile", "show", "pm"])?;
        assert!(stdout(&out).contains("\"~/.foorc\""), "{}", stdout(&out));
        assert!(stderr(&out).contains("(trusted)"), "{}", stderr(&out));
        let foorc = env.home_path(".foorc");
        let foorc = foorc.to_str().ok_or("the path is not UTF-8")?;
        let out = env.pent_ok(&["run", "--profile", "pm", "--", "cat", foorc])?;
        assert_eq!(stdout(&out), "foo\n");

        env.pent_ok(&["untrust", "pm"])?;
        assert_eq!(profile_list(&env)?, vec!["pm not trusted"]);
        let out = env.pent(&["run", "--profile", "pm", "--", "cat", foorc])?;
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("the profile \"pm\" is not trusted"),
            "{}",
            stderr(&out)
        );

        env.pent_ok(&["profile", "rm", "pm"])?;
        assert_eq!(profile_list(&env)?, Vec::<String>::new());
        assert!(!env.profile_path("pm").exists());
        assert!(!env.draft_path("pm").exists());
        assert!(!env.state_dir().join("pent/watch/pm").exists());
        let out = env.pent(&["run", "--profile", "pm", "--", "cat", foorc])?;
        assert!(
            stderr(&out).contains("no trusted profile for \"pm\""),
            "{}",
            stderr(&out)
        );
        Ok(())
    }
}
