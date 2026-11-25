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
    use std::path::Path;
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

    // ── the rules of the agents ──────────────────────────────────────────────

    /// The paths of `agent_profile` that name one file. Each other path is
    /// a directory.
    const AGENT_FILES: &[&str] = &[
        "~/.bashrc",
        "~/.bash_profile",
        "~/.profile",
        "~/.npmrc",
        "~/.ssh/known_hosts",
        "~/.ssh/config",
        "~/.ssh/config.d",
        "~/.gitconfig",
        "~/.claude.json",
        "~/.claude.lock",
    ];

    /// The directories of `agent_profile` that hold a location of the
    /// guard list. A subtree rule cannot give them (pent holds such a rule
    /// back), thus they go to the run as flags.
    const AGENT_FLAG_DIRS: &[&str] = &["~/.local/bin", "~/.config/git"];

    /// The access of an agent: the rules for its rule file, and the flags
    /// for each run.
    struct AgentAccess {
        targets: Vec<String>,
        flags: Vec<String>,
    }

    /// The access of the agent `agent`: the paths and the domains of
    /// `agent_profile`, with `~` replaced by `home`. A file gets an exact
    /// rule, a directory gets a subtree rule, and a directory of
    /// `AGENT_FLAG_DIRS` gets a flag.
    fn agent_access(home: &Path, agent: &str) -> Result<AgentAccess, BoxError> {
        let profile = agent_profile(agent);
        let mut access = AgentAccess {
            targets: Vec::new(),
            flags: Vec::new(),
        };
        for (table, list, kind, flag) in [
            ("filesystem", "read", "read", "--read"),
            ("filesystem", "read_write", "write", "--write"),
            ("filesystem", "execute", "exec", "--execute"),
        ] {
            for value in rules(&profile, table, list)? {
                let rel = value
                    .strip_prefix("~/")
                    .ok_or_else(|| format!("the path {value:?} is not in the home directory"))?;
                let path = home.join(rel);
                let path = path.to_str().ok_or("the path is not UTF-8")?;
                if AGENT_FILES.contains(&value.as_str()) {
                    access.targets.push(format!("{kind} {path}"));
                } else if AGENT_FLAG_DIRS.contains(&value.as_str()) {
                    access.flags.extend([flag.to_string(), path.to_string()]);
                } else {
                    access.targets.push(format!("{kind} {path}/**"));
                }
            }
        }
        for domain in rules(&profile, "network", "domains")? {
            access.targets.push(format!("domain {domain}"));
        }
        Ok(access)
    }

    /// Write the rules of the agent `agent` as the rule file of the key
    /// `agent`, and return the flags for each run.
    fn install_agent_rules(env: &TestEnv, agent: &str) -> Result<Vec<String>, BoxError> {
        let access = agent_access(&env.home, agent)?;
        let mut targets: Vec<&str> = access.targets.iter().map(String::as_str).collect();
        // A name with no rule asks a question (step 3.2). The network tests
        // refuse this name with a rule, so they do not wait for the
        // deadline.
        targets.push("deny domain blocked-domain.invalid");
        env.install_rules(agent, &targets)?;
        Ok(access.flags)
    }

    /// Assert that the run applied each rule of its key.
    #[track_caller]
    fn assert_all_rules_apply(what: &str, err: &str) {
        assert!(
            !err.contains("this run does not apply the rule"),
            "{what}: a rule does not apply:\n{err}"
        );
    }

    /// The rules of an agent keep the workspace read-write and deny a
    /// write outside the workspace.
    fn agent_filesystem(agent: &str) -> TestResult {
        if !ready(agent, &["sh"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let flags = install_agent_rules(&env, agent)?;
        let run = |script: &str| {
            let mut args = vec!["run", "-w", "--key", agent, "--network", "unrestricted"];
            args.extend(flags.iter().map(String::as_str));
            args.extend(["--", "sh", "-c", script]);
            env.pent(&args)
        };

        let out = run("echo ok > sentinel.txt")?;
        assert!(out.status.success(), "{agent}: {}", stderr(&out));
        assert_all_rules_apply(agent, &stderr(&out));
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

    /// The rules of an agent allow its API domain and deny other domains.
    fn agent_network(agent: &str, allowed: &str) -> TestResult {
        if !ready(agent, &["curl"]) || !internet(agent) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let flags = install_agent_rules(&env, agent)?;
        let curl = |url: &str| {
            let mut args = vec!["run", "-w", "--key", agent];
            args.extend(flags.iter().map(String::as_str));
            args.extend([
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
            ]);
            env.pent(&args)
        };

        // Any HTTP answer (also 404) proves that the proxy forwarded the
        // connection.
        let out = curl(&format!("https://{allowed}"))?;
        assert_all_rules_apply(agent, &stderr(&out));
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

    // ── pent run and its rule file ───────────────────────────────────────────

    /// Without a rule file, `pent run` runs the program with only the base:
    /// the workspace is read-write, and the home directory stays hidden.
    /// An allow rule in the rule file gives its path. A rule file that is
    /// not valid stops the run before the program starts, and the message
    /// names the file.
    #[test]
    fn run_without_rules_has_only_the_base() -> TestResult {
        if !ready("run_without_rules_has_only_the_base", &["sh", "cat"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let foorc = env.write_home(".foorc", "foo\n")?;
        let foorc = foorc.to_str().ok_or("the path is not UTF-8")?;
        let marker = env.ws.join("ran");
        let script = format!("touch ran; cat '{foorc}' 2>/dev/null || echo HIDDEN");
        let run = || env.pent(&["run", "-w", "--key", "m", "--", "sh", "-c", &script]);

        let out = run()?;
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "HIDDEN\n", "{}", stderr(&out));
        assert!(marker.exists(), "the workspace is not writable");
        fs::remove_file(&marker)?;

        env.install_rules("m", &[&format!("read {foorc}")])?;
        let out = run()?;
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "foo\n", "{}", stderr(&out));
        assert_all_rules_apply("m", &stderr(&out));
        fs::remove_file(&marker)?;

        let rules_path = env.rules_path("m");
        fs::write(&rules_path, "version = 1\n[[rule]]\nkind = \"nothing\"\n")?;
        let out = run()?;
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(err.contains(&rules_path.display().to_string()), "{err}");
        assert!(!marker.exists(), "the program must not start");
        Ok(())
    }

    // ── watch, and the rules of a run ────────────────────────────────────────

    /// The watched program reads a file, edits one config file, edits two
    /// files in one directory and makes files in its cache. The draft has
    /// one rule for each.
    #[test]
    fn watch_records_one_rule_for_each_access() -> TestResult {
        if !ready("watch_records_one_rule_for_each_access", &["sh"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".foorc", "foo\n")?;
        env.write_home(".config/app/settings.toml", "a = 1\n")?;
        env.write_home(".local/share/data/x", "x\n")?;
        env.write_home(".local/share/data/y", "y\n")?;
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
        Ok(())
    }

    /// The rules of a key allow exactly their accesses: other paths in the
    /// home directory stay hidden, and writes to them never reach the real
    /// home directory.
    #[test]
    fn run_rules_give_exactly_their_accesses() -> TestResult {
        if !ready("run_rules_give_exactly_their_accesses", &["sh"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let foorc = env.write_home(".foorc", "foo\n")?;
        let settings = env.write_home(".config/app/settings.toml", "a = 1\n")?;
        env.write_home(".config/app/other.toml", "other\n")?;
        env.write_home(".local/share/data/x", "x\n")?;
        env.write_home(".local/share/data/y", "y\n")?;
        env.write_home(".local/share/other/file", "other\n")?;
        env.write_home(".secret", "secret\n")?;
        env.write_home(".cache/tool/sub/c1", "c\n")?;
        let utf8 = |p: &Path| -> Result<String, BoxError> {
            Ok(p.to_str().ok_or("the path is not UTF-8")?.to_string())
        };
        env.install_rules(
            "t",
            &[
                &format!("read {}", utf8(&foorc)?),
                &format!("write {}", utf8(&settings)?),
                &format!("write {}/**", utf8(&env.home_path(".local/share/data"))?),
                &format!("write {}/**", utf8(&env.home_path(".cache/tool"))?),
            ],
        )?;

        let out = env.pent(&[
            "run",
            "-w",
            "--key",
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
        assert_all_rules_apply("t", &stderr(&out));

        // The allowed writes reach the real home directory.
        assert_eq!(fs::read_to_string(&settings)?, "a = 1\nc = 3\n");
        assert_eq!(
            fs::read_to_string(env.home_path(".local/share/data/x"))?,
            "x3\n"
        );
        assert!(env.home_path(".local/share/data/new").exists());
        assert!(env.home_path(".cache/tool/c2").exists());
        // The other paths do not change. A write to them can work in the
        // overlay of the home directory, but pent discards it.
        assert_eq!(fs::read_to_string(&foorc)?, "foo\n");
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

    /// The curl command that fetches `url`, with no output.
    fn curl_args(extra: &[&str]) -> Vec<String> {
        ["curl", "-sS", "-o", "/dev/null", "--max-time", "20"]
            .iter()
            .chain(extra)
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Watch records the domain in the draft.
    #[test]
    fn network_watch_records_the_domain() -> TestResult {
        if !ready("network_watch", &["curl"]) || !internet("network_watch") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let mut watch = vec!["watch", "--yes", "--profile", "net", "--"];
        let args = curl_args(&["https://example.com"]);
        watch.extend(args.iter().map(String::as_str));
        env.pent_ok(&watch)?;
        let draft = fs::read_to_string(env.draft_path("net"))?;
        assert_eq!(
            rules(&draft, "network", "domains")?,
            set(&["example.com"]),
            "{draft}"
        );
        Ok(())
    }

    /// A domain rule allows its domain and the run denies other domains,
    /// also at the DNS level. A direct connection past the proxy fails.
    #[test]
    fn network_rules_allow_the_domain_and_deny_others() -> TestResult {
        if !ready("network_rules", &["curl", "sh"]) || !internet("network_rules") {
            return Ok(());
        }
        let env = TestEnv::new()?;
        // A name with no rule asks a question (step 3.2); the deny rule
        // refuses example.org at once.
        env.install_rules("net", &["domain example.com", "deny domain example.org"])?;
        let run = |args: &[String]| {
            let mut all = vec!["run", "-w", "--key", "net", "--"];
            all.extend(args.iter().map(String::as_str));
            env.pent(&all)
        };

        let out = run(&curl_args(&["https://example.com"]))?;
        assert!(out.status.success(), "allowed: {}", stderr(&out));

        let out = run(&curl_args(&["https://example.org"]))?;
        assert!(!out.status.success(), "example.org must be denied");
        assert!(
            stderr(&out).contains("1 access denied; see it: pent denials"),
            "{}",
            stderr(&out)
        );

        let out = run(&curl_args(&["--noproxy", "*", "https://example.com"]))?;
        assert!(
            !out.status.success(),
            "a direct connection must fail: {}",
            stderr(&out)
        );

        if have_tools("network_rules (getent)", &["getent"]) {
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
        Ok(())
    }

    // ── --trace ──────────────────────────────────────────────────────────────

    /// `--trace` writes a denied filesystem access and a denied domain to
    /// `$XDG_STATE_HOME/pent/trace/<key>.log`, each with a fix hint. The proxy denies the domain
    /// before any connection, so this test needs no internet.
    #[test]
    fn trace_logs_filesystem_and_network_denials() -> TestResult {
        if !ready("trace", &["sh", "cat", "curl"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        // A name with no rule asks a question (step 3.2); a deny rule
        // refuses it at once.
        env.install_rules(
            "tr",
            &["domain allowed.example", "deny domain denied.example"],
        )?;
        let outside = env.root.join("outside.txt");
        fs::write(&outside, "secret\n")?;
        let script = format!(
            "cat '{}'; curl -sS -o /dev/null --max-time 10 https://denied.example; true",
            outside.display()
        );
        let out = env.pent(&[
            "run", "-w", "--key", "tr", "--trace", "--", "sh", "-c", &script,
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
        // A deny rule refused the name: the hint names the cause, not
        // `--allow`, so it does not push the user to undo the rule.
        assert!(
            log.contains("see the cause of the refusal: pent denials"),
            "{log}"
        );
        assert!(!log.contains("--allow denied.example"), "{log}");
        assert!(!log.contains("pent trust"), "{log}");
        Ok(())
    }

    // ── signals ──────────────────────────────────────────────────────────────

    /// SIGTERM to pent ends the child, no staging directory stays, and pent
    /// exits like the child: killed by SIGTERM (status 143 in a shell).
    #[test]
    fn sigterm_ends_the_child_and_cleans_up() -> TestResult {
        if !ready("sigterm", &["sh", "sleep"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let settings = env.write_home(".config/app/settings.toml", "a = 1\n")?;
        let settings = settings.to_str().ok_or("the path is not UTF-8")?;
        env.install_rules("sig", &[&format!("write {settings}")])?;
        // A unique argument: the test finds the sleep process by it.
        let nap = format!("300.{}", std::process::id());
        let script = format!("touch started; exec sleep {nap}");
        let mut child = env
            .command(&["run", "-w", "--key", "sig", "--", "sh", "-c", &script])
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
        // FUSE covers the home directory (step 5.3), so the write-listed
        // file needs no overlay, and the run makes no staging directory.
        assert_eq!(staging_dirs(&env, pid), Vec::<std::path::PathBuf>::new());
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
        assert_eq!(staging_dirs(&env, pid), Vec::<std::path::PathBuf>::new());
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

        env.pent_ok(&["untrust", "pm"])?;
        assert_eq!(profile_list(&env)?, vec!["pm not trusted"]);

        env.pent_ok(&["profile", "rm", "pm"])?;
        assert_eq!(profile_list(&env)?, Vec::<String>::new());
        assert!(!env.profile_path("pm").exists());
        assert!(!env.draft_path("pm").exists());
        assert!(!env.state_dir().join("pent/watch/pm").exists());
        Ok(())
    }
}
