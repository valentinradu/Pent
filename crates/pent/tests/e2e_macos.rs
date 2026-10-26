//! End-to-end tests on macOS: the real `pent` binary, the real Seatbelt
//! sandbox.
//!
//! Each test has its own directories below `CARGO_TARGET_TMPDIR` (see
//! `common::e2e::TestEnv`): its own `HOME`, `XDG_CONFIG_HOME`,
//! `XDG_STATE_HOME` and workspace. The tests share no state and run in
//! parallel.
//!
//! # What these tests prove
//!
//! The macOS backend of pent never ran before this suite. It ran on a Mac
//! for the first time on 2026-10-25. Each test holds one claim that the
//! README or `docs/design/watch.md` makes about macOS. A test that passes
//! keeps the claim honest. A test that fails tells us that the claim is
//! wrong. `docs/security/macos.md` lists the claims, the test of each one,
//! and the results of the first run.
//!
//! # Requirements
//!
//! `/usr/bin/sandbox-exec`, `/usr/bin/log` and `/usr/bin/logger`, which
//! every macOS has. The network tests need the internet. A test skips (it
//! prints `SKIP` and passes) when the sandbox or a tool is absent. Set
//! `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! ```text
//! cargo test -p pent --test e2e_macos -- --nocapture
//! ```

mod common;

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::common::e2e::{
        have_tools, rules, sandbox_ready, set, skip, stderr, stdout, wait_timeout, BoxError,
        TestEnv, TestResult,
    };
    use super::common::macos::{
        deny_exec_profile, deny_reads_profile, have_files, log_write, sandbox_exec,
        sandbox_exec_spawn, wait_for_log_line, LOGGER, SANDBOX_EXEC,
    };

    /// The time limit for one pent command.
    const TIMEOUT: Duration = Duration::from_secs(120);

    /// The time to wait for a line of the unified log.
    const LOG_TIMEOUT: Duration = Duration::from_secs(30);

    /// The time to wait for a job of `launchd` to make its file.
    const LAUNCHD_WAIT: Duration = Duration::from_secs(10);

    /// The shell of each test. The sandbox allows `/bin` by default.
    const SH: &str = "/bin/sh";

    /// Return true if the test can run: the sandbox works and each tool is
    /// an executable file at its fixed path.
    fn ready(test: &str, tools: &[&str]) -> bool {
        have_files(test, tools) && sandbox_ready(test)
    }

    /// Return true if the test can run and each name of `in_path` is in
    /// `PATH`.
    fn ready_with_path(test: &str, tools: &[&str], in_path: &[&str]) -> bool {
        ready(test, tools) && have_tools(test, in_path)
    }

    /// The draft of `name`, with the raw events in the message of an error.
    ///
    /// The macOS recorder reads the Seatbelt reports from the unified log.
    /// When the draft is empty, the raw events tell whether the reader saw
    /// the access at all. That difference is the first thing to look at.
    fn draft_with_events(env: &TestEnv, name: &str) -> Result<String, BoxError> {
        let path = env.draft_path(name);
        let draft = fs::read_to_string(&path).map_err(|e| {
            format!(
                "no draft at {}: {e}\n--- raw watch events ---\n{}",
                path.display(),
                env.watch_events(name)
            )
        })?;
        Ok(draft)
    }

    /// The text that a failed assertion of a watch test prints.
    ///
    /// The report holds three things, and each one tells a different
    /// cause apart: the draft, the raw events of the run, and the
    /// listing of the directory of the runs. An empty raw log with no
    /// file means that pent never started a run; an empty raw log with a
    /// file of zero bytes means that the reader got no report; a raw log
    /// with events and no rule means that the summary dropped them.
    fn watch_report(env: &TestEnv, name: &str, draft: &str) -> String {
        let dir = env.watch_dir(name);
        let listing = match fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|e| {
                    let size = e.metadata().map_or(0, |m| m.len());
                    format!("  {} ({size} bytes)\n", e.path().display())
                })
                .collect::<String>(),
            Err(e) => format!("  cannot read {}: {e}\n", dir.display()),
        };
        format!(
            "--- draft {} ---\n{draft}\n--- the runs of {name} ---\n{listing}\
             --- raw watch events ---\n{}",
            env.draft_path(name).display(),
            env.watch_events(name)
        )
    }

    // ── B. the filesystem sandbox of `pent run` ──────────────────────────────

    /// A path in the profile is readable. A sibling that the profile does
    /// not name is not. (README: the profile denies file content reads and
    /// allows only the configured paths.)
    #[test]
    fn profile_path_is_readable_and_a_sibling_is_not() -> TestResult {
        if !ready("profile_path_readable", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home("data/named.txt", "NAMED\n")?;
        env.write_home("data/sibling.txt", "SIBLING\n")?;
        env.install_profile("p", "[filesystem]\nread = [\"~/data/named.txt\"]\n")?;

        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--",
            SH,
            "-c",
            "cat ~/data/named.txt 2>/dev/null || echo NAMED_DENIED; \
             cat ~/data/sibling.txt 2>/dev/null || echo SIBLING_DENIED",
        ])?;
        assert_eq!(
            stdout(&out).lines().collect::<Vec<_>>(),
            vec!["NAMED", "SIBLING_DENIED"],
            "the profile path must be readable and the sibling must not\nstderr: {}",
            stderr(&out)
        );
        Ok(())
    }

    /// A write to a path with only a read rule fails. A write to a
    /// `read_write` path reaches the real file.
    #[test]
    fn read_rule_denies_a_write_and_read_write_reaches_the_file() -> TestResult {
        if !ready("read_vs_read_write", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home("data/ro.txt", "RO\n")?;
        env.write_home("data/rw.txt", "RW\n")?;
        env.install_profile(
            "p",
            "[filesystem]\nread = [\"~/data/ro.txt\"]\nread_write = [\"~/data/rw.txt\"]\n",
        )?;

        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--",
            SH,
            "-c",
            "echo CHANGED > ~/data/ro.txt 2>/dev/null || echo RO_WRITE_DENIED; \
             echo CHANGED > ~/data/rw.txt 2>/dev/null && echo RW_WRITE_OK",
        ])?;
        assert_eq!(
            stdout(&out).lines().collect::<Vec<_>>(),
            vec!["RO_WRITE_DENIED", "RW_WRITE_OK"],
            "stderr: {}",
            stderr(&out)
        );
        assert_eq!(
            fs::read_to_string(env.home_path("data/ro.txt"))?,
            "RO\n",
            "the read-only file changed"
        );
        assert_eq!(
            fs::read_to_string(env.home_path("data/rw.txt"))?,
            "CHANGED\n",
            "the write did not reach the real file"
        );
        Ok(())
    }

    /// `--execute` lets the child run a program of the named directory.
    /// Without the flag, the same program does not run (MAC-4).
    ///
    /// The program under test is one that the **child** runs, not the
    /// command of the run. `spawn_sandboxed` always gives exec access to
    /// the directory of the command, because the user names that command
    /// (`binary_grant_dirs` in `crates/pent-sandbox/src/lib.rs`). The
    /// command of this test is therefore the shell, and the shell runs the
    /// tool.
    ///
    /// The run profile denies `process-exec` and allows the `execute`
    /// paths and the system program directories. Before that deny, the
    /// `execute` list of a profile meant nothing on macOS: `(allow
    /// default)` let the child run every program on the machine.
    #[test]
    fn execute_flag_lets_the_child_run_a_tool() -> TestResult {
        if !ready("execute_flag", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let tools = env.root.join("tools");
        fs::create_dir_all(&tools)?;
        let script = tools.join("hello");
        fs::write(&script, "#!/bin/sh\necho HELLO_FROM_TOOL\n")?;
        let mut perms = fs::metadata(&script)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&script, perms)?;
        let script = script.to_str().ok_or("the path is not UTF-8")?;
        let tools = tools.to_str().ok_or("the path is not UTF-8")?;
        env.install_profile("p", "")?;
        let run_tool = format!("'{script}' || echo TOOL_DENIED");

        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--execute",
            tools,
            "--",
            SH,
            "-c",
            &run_tool,
        ])?;
        assert!(
            stdout(&out).contains("HELLO_FROM_TOOL"),
            "--execute must let the child run the tool\nstdout: {}\nstderr: {}",
            stdout(&out),
            stderr(&out)
        );

        // `-v` makes pent log the profile that it gives to the kernel, so
        // a failure shows the rule that lets the program run.
        let out = env.pent(&["-v", "run", "--profile", "p", "--", SH, "-c", &run_tool])?;
        // When the tool runs, the next question is whether the kernel
        // denies this path at all. The probe is a profile of the same
        // shape as the one that pent writes: `(allow default)`, then
        // `(deny process-exec)`, then the allow rules of the system
        // directories.
        let probe = deny_exec_profile();
        let probe_out = sandbox_exec(&env.root, &probe, &[SH, "-c", &run_tool])?;
        assert!(
            !stdout(&out).contains("HELLO_FROM_TOOL"),
            "without --execute the child must not run the tool\n\
             pent exited {:?}\nstdout: {}\nstderr: {}\n\
             --- the kernel answer to the same shape of profile ---\n\
             exit {:?}\nstdout: {}\nstderr: {}\n--- the probe profile ---\n{probe}",
            out.status.code(),
            stdout(&out),
            stderr(&out),
            probe_out.status.code(),
            stdout(&probe_out),
            stderr(&probe_out)
        );
        Ok(())
    }

    /// The command that the user names always runs, also when no
    /// `execute` rule names its directory.
    ///
    /// `spawn_sandboxed` adds the directory of the command to the
    /// `execute` paths (`binary_grant_dirs`). The user names the command,
    /// so pent lets it run; `--execute` is for the programs that the child
    /// runs itself. Both platforms work this way.
    #[test]
    fn the_named_command_runs_without_an_execute_rule() -> TestResult {
        if !ready("named_command_runs", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let tools = env.root.join("tools");
        fs::create_dir_all(&tools)?;
        let script = tools.join("hello");
        fs::write(&script, "#!/bin/sh\necho HELLO_FROM_TOOL\n")?;
        let mut perms = fs::metadata(&script)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&script, perms)?;
        let script = script.to_str().ok_or("the path is not UTF-8")?;
        env.install_profile("p", "")?;

        let out = env.pent(&["run", "--profile", "p", "--", script])?;
        assert!(
            stdout(&out).contains("HELLO_FROM_TOOL"),
            "the command of the run must start\nstdout: {}\nstderr: {}",
            stdout(&out),
            stderr(&out)
        );
        Ok(())
    }

    /// The README says that the profile limits the file content reads, not
    /// the metadata reads. This test keeps that claim honest: `stat` works
    /// on a path that the profile does not name, and `cat` does not.
    #[test]
    fn metadata_read_is_not_limited_but_content_read_is() -> TestResult {
        if !ready("metadata_read", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let secret = env.root.join("outside.txt");
        fs::write(&secret, "SECRET\n")?;
        let secret = secret.to_str().ok_or("the path is not UTF-8")?;
        env.install_profile("p", "")?;

        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--",
            SH,
            "-c",
            &format!(
                "test -f '{secret}' && echo STAT_OK; \
                 cat '{secret}' 2>/dev/null || echo READ_DENIED"
            ),
        ])?;
        assert_eq!(
            stdout(&out).lines().collect::<Vec<_>>(),
            vec!["STAT_OK", "READ_DENIED"],
            "the README claims that only the content read is limited\nstderr: {}",
            stderr(&out)
        );
        Ok(())
    }

    /// The full flow: `pent watch` writes a draft, `pent trust` makes it a
    /// profile, and `pent run` then does the recorded accesses and nothing
    /// more.
    ///
    /// The shell reads and writes the files itself, with the `read`
    /// builtin and a redirect. A `cat` in the script would run in a child
    /// process, and the macOS recorder misses a child that lives less than
    /// one poll of the process table (OPEN MAC-10 in
    /// `docs/security/macos.md`;
    /// `watch_records_a_read_of_a_short_lived_child` holds that case).
    #[test]
    fn watch_trust_run_gives_the_recorded_accesses() -> TestResult {
        if !ready("watch_trust_run", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".foorc", "foo\n")?;
        env.write_home(".config/app/settings.toml", "a = 1\n")?;
        env.write_home(".config/app/other.toml", "other\n")?;
        env.write_home(".secret", "secret\n")?;

        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "t",
            "--",
            SH,
            "-c",
            "read -r l < ~/.foorc; echo \"$l\"; \
             echo 'b = 2' >> ~/.config/app/settings.toml",
        ])?;
        assert_eq!(stdout(&out), "foo\n", "stderr: {}", stderr(&out));

        let draft = draft_with_events(&env, "t")?;
        let read = rules(&draft, "filesystem", "read")?;
        let read_write = rules(&draft, "filesystem", "read_write")?;
        let report = watch_report(&env, "t", &draft);
        assert!(
            read.contains("~/.foorc") || read_write.contains("~/.foorc"),
            "the draft has no rule for the file that the program read\n{report}"
        );
        assert!(
            read_write.contains("~/.config/app/settings.toml"),
            "the draft has no read-write rule for the file that the program changed\n{report}"
        );
        assert!(
            !draft.contains(".secret"),
            "the draft names a file that the program never used\n{report}"
        );

        env.pent_ok(&["trust", "t", "--yes"])?;
        assert!(env.profile_path("t").exists());

        let out = env.pent(&[
            "run",
            "--profile",
            "t",
            "--",
            SH,
            "-c",
            "read -r l < ~/.foorc; echo \"$l\"; \
             echo 'c = 3' >> ~/.config/app/settings.toml && echo SETTINGS_OK; \
             (read -r o < ~/.config/app/other.toml) 2>/dev/null \
             || echo SIBLING_DENIED; \
             (read -r s < ~/.secret) 2>/dev/null || echo SECRET_DENIED",
        ])?;
        assert_eq!(
            stdout(&out).lines().collect::<Vec<_>>(),
            vec!["foo", "SETTINGS_OK", "SIBLING_DENIED", "SECRET_DENIED"],
            "the trusted profile must give exactly the recorded accesses\nstderr: {}\n{report}",
            stderr(&out)
        );
        assert_eq!(
            fs::read_to_string(env.home_path(".config/app/settings.toml"))?,
            "a = 1\nb = 2\nc = 3\n"
        );
        Ok(())
    }

    // ── D. the watch recorder ────────────────────────────────────────────────

    /// A watch run produces events at all.
    ///
    /// This was the single most important unknown of the macOS backend.
    /// The watch profile allows each operation with `(with report)` and
    /// the reader takes the reports from `log stream`. The first run on a
    /// Mac proved that the reports do arrive and that `parse_line` reads
    /// them; the reader dropped them because it knew no name for the
    /// process (MAC-8). If this test fails, every other watch test on
    /// macOS fails with it.
    #[test]
    fn watch_records_a_read_of_a_known_file() -> TestResult {
        if !ready("watch_records_a_read", &["/bin/cat"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let known = env.write_home("known.txt", "KNOWN\n")?;
        let known = known.to_str().ok_or("the path is not UTF-8")?;

        let out = env.pent_ok(&["watch", "--yes", "--profile", "w", "--", "/bin/cat", known])?;
        assert_eq!(stdout(&out), "KNOWN\n", "stderr: {}", stderr(&out));

        let draft = draft_with_events(&env, "w")?;
        let read = rules(&draft, "filesystem", "read")?;
        let read_write = rules(&draft, "filesystem", "read_write")?;
        assert!(
            read.contains("~/known.txt") || read_write.contains("~/known.txt"),
            "the recorder produced no rule for the file that the program read. \
             Either the `(with report)` allow reports do not reach the unified \
             log, or the reader does not match them.\n{}",
            watch_report(&env, "w", &draft)
        );
        Ok(())
    }

    /// A read of a child process that lives a very short time.
    ///
    /// OPEN MAC-10. The reader keeps a report only when the process is a
    /// member of the tree of the run and the name of the report fits the
    /// program that the process runs. Both facts come from a poll of the
    /// process tree, and the child of the fork lives about six
    /// milliseconds, so a poll misses it part of the time.
    ///
    /// The script runs `cat` and then a second command, so the shell
    /// forks for `cat` instead of running it in place. The run of
    /// 2026-10-25 showed that `sh -c 'cat FILE'` alone makes **no**
    /// child: the shell runs `cat` with the process ID of the root, and
    /// the recorder keeps each access of it. The fork is the gap, not the
    /// exec.
    ///
    /// One run is thus not a property: the test keeps its mark.
    /// `watch_keeps_the_read_of_a_short_lived_child_most_of_the_time`
    /// measures the rate over many runs, and that rate is the number of
    /// MAC-10 in `docs/security/macos.md`.
    ///
    /// Read the summary in the message of the failure. "27 accesses by 3
    /// processes" is MAC-10: the root is there and the child is not.
    /// "0 accesses" is MAC-12: the stream of the log delivered no report
    /// at all, so the warm-up of the reader did not work.
    #[test]
    #[ignore = "OPEN MAC-10: the poll of the process tree sees the child of a fork about three times out of four, so one run is not a property; watch_keeps_the_read_of_a_short_lived_child_most_of_the_time holds the rate"]
    fn watch_records_a_read_of_a_short_lived_child() -> TestResult {
        if !ready("watch_records_a_child_read", &[SH, "/bin/cat"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".foorc", "foo\n")?;

        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "c",
            "--",
            SH,
            "-c",
            "cat ~/.foorc; echo END",
        ])?;
        assert_eq!(stdout(&out), "foo\nEND\n", "stderr: {}", stderr(&out));

        let draft = draft_with_events(&env, "c")?;
        let read = rules(&draft, "filesystem", "read")?;
        let read_write = rules(&draft, "filesystem", "read_write")?;
        assert!(
            read.contains("~/.foorc") || read_write.contains("~/.foorc"),
            "the recorder lost the read of the child process\n\
             --- the summary of the run ---\n{}\n{}",
            stderr(&out),
            watch_report(&env, "c", &draft)
        );
        Ok(())
    }

    /// The number of runs that the residual measurement of MAC-10 makes.
    ///
    /// The runner of 2026-10-26 keeps the read of the child in about three
    /// runs out of four. With twelve runs, a recorder that lost each one
    /// would be a chance of about one in seventy million, so the floor of
    /// the assertion below cannot fail by chance.
    const CHILD_RUNS: usize = 12;

    /// The residual window of MAC-10, as a rate.
    ///
    /// The recorder knows a child only when a poll of the process tree
    /// sees it. The child of `sh -c 'cat FILE; echo END'` lives about six
    /// milliseconds (the run 40246732816 measured it), and the poll of
    /// pent asks for one millisecond, which a runner turns into about
    /// five. The recorder thus keeps the accesses of the child most of the
    /// time and not every time.
    ///
    /// The test runs the same watch command [`CHILD_RUNS`] times, counts
    /// the runs whose draft holds the read, and **prints the rate**. The
    /// number in MAC-10 of `docs/security/macos.md` comes from this test.
    ///
    /// The assertion is a floor, not the rate: a rate is not a property of
    /// the machine, and a test of a security property must not fail by
    /// chance. Before the fix the rate was zero, so the floor holds the
    /// whole value of the fix.
    #[test]
    fn watch_keeps_the_read_of_a_short_lived_child_most_of_the_time() -> TestResult {
        if !ready("watch_child_read_rate", &[SH, "/bin/cat"]) {
            return Ok(());
        }
        let mut kept = 0usize;
        let mut reports = String::new();
        for _run in 0..CHILD_RUNS {
            let env = TestEnv::new()?;
            env.write_home(".foorc", "foo\n")?;
            let out = env.pent_ok(&[
                "watch",
                "--yes",
                "--profile",
                "r",
                "--",
                SH,
                "-c",
                "cat ~/.foorc; echo END",
            ])?;
            assert_eq!(stdout(&out), "foo\nEND\n", "stderr: {}", stderr(&out));
            let draft = fs::read_to_string(env.draft_path("r")).unwrap_or_default();
            let read = rules(&draft, "filesystem", "read").unwrap_or_default();
            let read_write = rules(&draft, "filesystem", "read_write").unwrap_or_default();
            if read.contains("~/.foorc") || read_write.contains("~/.foorc") {
                kept = kept.saturating_add(1);
            } else if reports.is_empty() {
                // The first run that lost the read, for the message below.
                reports = watch_report(&env, "r", &draft);
            }
        }
        println!(
            "MAC-10: the recorder kept the read of the short-lived child in \
             {kept} of {CHILD_RUNS} runs"
        );
        assert!(
            kept > 0,
            "the recorder lost the read of the child in every one of \
             {CHILD_RUNS} runs. Before the fix of 2026-10-26 the rate was \
             zero, so this is a regression of MAC-10 in \
             docs/security/macos.md.\n{reports}"
        );
        Ok(())
    }

    /// MAC-12. The first watch run of a machine must record an access.
    ///
    /// `log stream` prints its header before it connects to the log, so
    /// the header proves nothing. On a machine whose log system is cold,
    /// the **first** stream delivered no report at all, and the first
    /// watch run of that machine wrote an empty draft. A user who tried
    /// pent for the first time saw nothing and concluded that pent does
    /// not work.
    ///
    /// `LogReader::start` now makes a Seatbelt report of its own and waits
    /// for it before pent starts the child
    /// (`crates/pent-sandbox/src/macos_log.rs`). The command of this test
    /// is as short as a command can be, so it ends long before a cold
    /// stream would deliver anything.
    ///
    /// A test cannot put the log system of a machine back into its cold
    /// state, so no single test can name the moment. Two things hold the
    /// finding instead: each job of the pipeline runs on a new machine, so
    /// the first watch run of the job is the cold case; and the unit test
    /// `the_warm_up_sees_a_report_of_its_own_probe` of `macos_log.rs`
    /// holds the mechanism on each stream that pent starts.
    #[test]
    fn the_first_watch_run_of_a_machine_records_an_access() -> TestResult {
        if !ready("first_watch_run", &["/bin/cat"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let known = env.write_home("first.txt", "FIRST\n")?;
        let known = known.to_str().ok_or("the path is not UTF-8")?;
        let out = env.pent_ok(&["watch", "--yes", "--profile", "m", "--", "/bin/cat", known])?;
        assert_eq!(stdout(&out), "FIRST\n", "stderr: {}", stderr(&out));

        let draft = draft_with_events(&env, "m")?;
        let read = rules(&draft, "filesystem", "read")?;
        let read_write = rules(&draft, "filesystem", "read_write")?;
        assert!(
            read.contains("~/first.txt") || read_write.contains("~/first.txt"),
            "the run recorded no access. If this is the first watch run of \
             this machine, the warm-up of the log reader did not work and \
             MAC-12 is open again.\n{}",
            watch_report(&env, "m", &draft)
        );
        Ok(())
    }

    /// The reader keeps only the processes of the run.
    ///
    /// A second, unrelated sandboxed process writes its own Seatbelt
    /// denials into the same unified log while pent records. Those denials
    /// must not reach the draft, the raw events or the trace log.
    #[test]
    fn watch_keeps_only_the_processes_of_the_run() -> TestResult {
        if !ready("watch_only_own_processes", &[SH, SANDBOX_EXEC]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let noise_dir = env.root.join("noise");
        fs::create_dir_all(&noise_dir)?;
        // The marker is unique, so the test never reads the noise of
        // another test that runs at the same time.
        let marker = format!("pent-noise-{}", std::process::id());
        let bait = noise_dir.join(&marker);
        fs::write(&bait, "NOISE\n")?;
        let profile = deny_reads_profile(&noise_dir);
        let script = format!(
            "i=0; while [ $i -lt 120 ]; do cat '{}' >/dev/null 2>&1; sleep 0.1; i=$((i+1)); done",
            bait.display()
        );
        let mut noise = sandbox_exec_spawn(&noise_dir, &profile, &[SH, "-c", &script])?;

        let known = env.write_home("known.txt", "KNOWN\n")?;
        let known = known.to_str().ok_or("the path is not UTF-8")?;
        // Record, trust and run, all while the unrelated process writes
        // its denials into the same unified log.
        let watched = env.pent(&["watch", "--yes", "--profile", "w", "--", "/bin/cat", known]);
        let trusted = env.pent(&["trust", "w", "--yes"]);
        let traced = env.pent(&["run", "--profile", "w", "--trace", "--", "/bin/cat", known]);
        // The noise process must stop in every case, also after an error.
        let kill = noise.kill();
        let reap = noise.wait();
        let watched = watched?;
        let trusted = trusted?;
        let traced = traced?;
        kill?;
        reap?;
        assert!(watched.status.success(), "watch: {}", stderr(&watched));
        assert!(trusted.status.success(), "trust: {}", stderr(&trusted));
        assert!(traced.status.success(), "run: {}", stderr(&traced));

        let events = env.watch_events("w");
        assert!(
            !events.contains(&marker),
            "the recorder took the denial of an unrelated process:\n{events}"
        );
        let draft = fs::read_to_string(env.draft_path("w")).unwrap_or_default();
        assert!(
            !draft.contains(&marker),
            "the draft has the denial of an unrelated process:\n{draft}"
        );
        let trace = fs::read_to_string(env.trace_log("w")).unwrap_or_default();
        assert!(
            !trace.contains(&marker),
            "the trace log has the denial of an unrelated process:\n{trace}"
        );
        Ok(())
    }

    /// The guard of `pent watch` blocks a credential read and a write to a
    /// shell start file, and lets the public key through. Each blocked
    /// attempt is in the Blocked section of the summary.
    #[test]
    fn watch_guard_blocks_dangerous_accesses() -> TestResult {
        if !ready("watch_guard", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".ssh/id_x", "SECRET-KEY\n")?;
        env.write_home(".ssh/id_x.pub", "PUBLIC-KEY\n")?;
        env.write_home(".zshrc", "z\n")?;

        // The shell opens each file itself. A `cat` would run in a child
        // process, and the macOS recorder misses a child that lives less
        // than one poll of the process table (OPEN MAC-10).
        let script = "k=''; read -r k < ~/.ssh/id_x 2>/dev/null; \
                      echo \"key=[$k]\"; \
                      p=''; read -r p < ~/.ssh/id_x.pub 2>/dev/null; \
                      echo \"pub=[$p]\"; \
                      echo pwn 2>/dev/null >> ~/.zshrc; echo \"zshrc=$?\"; \
                      true";
        let out = env.pent_ok(&["watch", "--yes", "--profile", "g", "--", SH, "-c", script])?;
        let text = stdout(&out);
        let err = stderr(&out);
        assert!(
            text.contains("key=[]\n"),
            "the guard did not hide the private key:\n{text}"
        );
        assert!(
            text.contains("pub=[PUBLIC-KEY]\n"),
            "the public key beside the private key must stay readable:\n{text}"
        );
        let status = text
            .lines()
            .find_map(|l| l.strip_prefix("zshrc="))
            .ok_or_else(|| format!("no status for the write to ~/.zshrc:\n{text}"))?;
        assert_ne!(status, "0", "the write to ~/.zshrc worked:\n{text}");
        assert_eq!(
            fs::read_to_string(env.home_path(".zshrc"))?,
            "z\n",
            "the guard let the write through"
        );

        let blocked = err
            .split("Blocked by the guard")
            .nth(1)
            .ok_or_else(|| format!("no Blocked section:\n{err}"))?;
        for item in ["read ~/.ssh/id_x", "write ~/.zshrc"] {
            assert!(blocked.contains(item), "{item} is not blocked:\n{err}");
        }
        let draft = fs::read_to_string(env.draft_path("g")).unwrap_or_default();
        assert!(
            !draft.contains("id_x\"") && !draft.contains("zshrc"),
            "the draft has a guarded path:\n{draft}"
        );
        Ok(())
    }

    /// `pent run --trace` writes the trace log to
    /// `$XDG_STATE_HOME/pent/trace/<profile>.log`, with one entry for a
    /// denied file access and one for a denied domain.
    #[test]
    fn trace_logs_filesystem_and_network_denials() -> TestResult {
        if !ready_with_path("trace", &[SH], &["curl"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("tr", "[network]\ndomains = [\"allowed.example\"]\n")?;
        let outside = env.root.join("outside.txt");
        fs::write(&outside, "secret\n")?;
        // The shell opens the file itself, so the denial comes from the
        // root process of the run. A `cat` would run in a child process,
        // and the macOS recorder misses a child that lives less than one
        // poll of the process table (OPEN MAC-10).
        let script = format!(
            "s=''; read -r s < '{}' 2>/dev/null; echo \"$s\"; \
             curl -sS -o /dev/null --max-time 20 https://denied.example; true",
            outside.display()
        );
        let out = env.pent(&["run", "--profile", "tr", "--trace", "--", SH, "-c", &script])?;
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(
            !stdout(&out).contains("secret"),
            "the read was not denied:\n{}",
            stdout(&out)
        );

        let path = env.trace_log("tr");
        let log = fs::read_to_string(&path)
            .map_err(|e| format!("no trace log at {}: {e}", path.display()))?;
        assert!(
            log.contains("[denied] network:") && log.contains("denied.example"),
            "the trace log has no denied domain:\n{log}"
        );
        assert!(
            log.contains("[denied] filesystem:") && log.contains(&outside.display().to_string()),
            "the trace log has no denied file access. On macOS these lines \
             come from the Seatbelt reports in the unified log.\n{log}"
        );
        let denied = fs::read_to_string(env.denied_log("tr")).unwrap_or_default();
        assert!(
            denied.contains("denied.example"),
            "the denied log has no domain:\n{denied}"
        );
        Ok(())
    }

    // ── E. the event log cannot be forged ────────────────────────────────────

    /// A Seatbelt report that another process writes does not become an
    /// event of the pent run.
    ///
    /// The reader parses lines of the unified log, and any process can
    /// write to that log. The reader keeps only the PIDs of its own process
    /// tree, so a line of another process must not reach the draft or the
    /// trace log.
    #[test]
    fn a_forged_log_line_of_another_process_is_not_an_event() -> TestResult {
        if !ready("forged_log_line", &["/bin/cat", LOGGER]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let marker = format!("/pent-forged-{}/secret", std::process::id());
        // The PID of this test process is not in the process tree of the
        // pent run, so the reader must drop the line.
        let line = format!(
            "Sandbox: forger({}) allow(1) file-read-data {marker}",
            std::process::id()
        );
        log_write(&line)?;
        let seen = wait_for_log_line("2m", &marker, LOG_TIMEOUT)?;
        if seen.trim().is_empty() {
            skip(
                "forged_log_line",
                "the unified log did not keep the line of /usr/bin/logger, \
                 so the test cannot prove anything",
            );
            return Ok(());
        }

        // `log stream` delivers only the lines that arrive after its start,
        // so the forger must write while pent records.
        let stop = Arc::new(AtomicBool::new(false));
        let forger = {
            let stop = Arc::clone(&stop);
            let line = line.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // A failure of `logger` only means fewer forged lines.
                    let _ = log_write(&line);
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
        };

        let known = env.write_home("known.txt", "KNOWN\n")?;
        let known = known.to_str().ok_or("the path is not UTF-8")?;
        let out = env.pent(&["watch", "--yes", "--profile", "f", "--", "/bin/cat", known]);
        stop.store(true, Ordering::Relaxed);
        let joined = forger.join();
        let out = out?;
        assert!(joined.is_ok(), "the forger thread panicked");
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "KNOWN\n", "stderr: {}", stderr(&out));

        let events = env.watch_events("f");
        let draft = fs::read_to_string(env.draft_path("f")).unwrap_or_default();
        assert!(
            !events.contains(&marker),
            "a forged log line became a raw event:\n{events}"
        );
        assert!(
            !draft.contains(&marker),
            "a forged log line became a rule of the draft:\n{draft}"
        );
        Ok(())
    }

    // ── the findings of the review ───────────────────────────────────────────
    //
    // Each test below states the secure behaviour. See
    // `docs/security/macos.md`. MAC-1, MAC-2, MAC-3 and MAC-4 have a fix,
    // so these tests run in the normal suite. MAC-10 has none, so its test
    // keeps the `ignore` mark; `--include-ignored` shows the failure.

    /// MAC-1. The watched program writes its own Seatbelt reports into the
    /// unified log with `/usr/bin/logger`. The reader takes only the
    /// messages of the kernel, so these lines are not events.
    #[test]
    fn a_program_cannot_forge_its_own_events() -> TestResult {
        if !ready("forged_by_the_program", &[SH, LOGGER]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let marker = format!("/pent-selfforged-{}/secret", std::process::id());
        let script =
            format!("{LOGGER} -- \"Sandbox: evil($$) allow(1) file-read-data {marker}\"; sleep 2");
        env.pent_ok(&["watch", "--yes", "--profile", "s", "--", SH, "-c", &script])?;
        let draft = fs::read_to_string(env.draft_path("s")).unwrap_or_default();
        let events = env.watch_events("s");
        assert!(
            !events.contains(&marker) && !draft.contains(&marker),
            "the program put a path of its choice into its own draft:\n{draft}\n{events}"
        );
        Ok(())
    }

    /// MAC-2. The guard rule for an SSH key uses a file name pattern. A
    /// pattern with a leading `*` is a name suffix (`*_rsa` matches
    /// `github_rsa`). `add_guard_rules` translates it into the regex
    /// `^<dir>/[^/]*_rsa$`, so the guard hides such a key too.
    #[test]
    fn watch_guard_blocks_a_key_with_a_suffix_name() -> TestResult {
        if !ready("guard_suffix_key", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".ssh/github_rsa", "SUFFIX-KEY\n")?;
        env.write_home(".ssh/github_rsa.pub", "PUBLIC-KEY\n")?;
        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "k",
            "--",
            SH,
            "-c",
            "echo \"key=[$(cat ~/.ssh/github_rsa 2>/dev/null)]\"; \
             echo \"pub=[$(cat ~/.ssh/github_rsa.pub 2>/dev/null)]\"",
        ])?;
        assert!(
            stdout(&out).contains("key=[]\n"),
            "the guard must hide a key whose name ends with _rsa:\n{}",
            stdout(&out)
        );
        assert!(
            stdout(&out).contains("pub=[PUBLIC-KEY]\n"),
            "the public key must stay readable:\n{}",
            stdout(&out)
        );
        let draft = fs::read_to_string(env.draft_path("k")).unwrap_or_default();
        assert!(
            !draft.contains("github_rsa\""),
            "the key went into the draft:\n{draft}"
        );
        Ok(())
    }

    /// MAC-3. The macOS guard rule for a directory of keys has two forms:
    /// `^<dir>/<name>$` for a direct child and `^<dir>/.*/<name>$` for a
    /// file deeper in the tree. A key in a subdirectory is thus hidden too.
    #[test]
    fn watch_guard_blocks_a_key_in_a_subdirectory() -> TestResult {
        if !ready("guard_subdirectory_key", &[SH]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".ssh/work/id_x", "NESTED-KEY\n")?;
        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "n",
            "--",
            SH,
            "-c",
            "echo \"key=[$(cat ~/.ssh/work/id_x 2>/dev/null)]\"",
        ])?;
        assert!(
            stdout(&out).contains("key=[]\n"),
            "the guard must hide a key in a subdirectory of ~/.ssh:\n{}",
            stdout(&out)
        );
        let draft = fs::read_to_string(env.draft_path("n")).unwrap_or_default();
        assert!(
            !draft.contains("id_x\""),
            "the key went into the draft:\n{draft}"
        );
        Ok(())
    }

    /// Ask `launchd` to run a job that makes `target`, and return true
    /// when the file appears. The caller is outside the sandbox.
    ///
    /// This is the control of the test below. A runner on which
    /// `launchctl submit` never runs a job passes the assertion of that
    /// test for the wrong reason.
    fn launchd_runs_a_job(target: &std::path::Path, label: &str) -> Result<bool, BoxError> {
        let script = format!("touch '{}'", target.display());
        let submit = std::process::Command::new("/bin/launchctl")
            .args(["submit", "-l", label, "--", SH, "-c", &script])
            .output()?;
        let deadline = std::time::Instant::now() + LAUNCHD_WAIT;
        while !target.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let ran = target.exists();
        // The job must go, also when it never ran.
        let removed = std::process::Command::new("/bin/launchctl")
            .args(["remove", label])
            .output()?;
        if !ran {
            eprintln!(
                "launchctl submit made no job: submit={:?} stderr={} remove={:?}",
                submit.status,
                String::from_utf8_lossy(&submit.stderr).trim(),
                removed.status
            );
        }
        Ok(ran)
    }

    /// MAC-4. The child must not make `launchd` run a program for it: such
    /// a program is a child of `launchd` and runs with no profile.
    ///
    /// The profile of `pent run` denies `job-creation` and `mach-lookup`,
    /// which are the two routes to another process that runs a file.
    ///
    /// The run of 2026-10-25 on `macos-latest` (run 40236253209) measured
    /// that macOS itself refuses a job of a sandboxed process, also under
    /// `(allow default)` with no deny at all. The denies of pent are the
    /// second layer. The control below keeps the test honest: it holds
    /// that `launchctl submit` does run a job on this machine.
    #[test]
    fn the_child_cannot_start_a_program_through_launchd() -> TestResult {
        let test = "launchd_escape";
        if !ready(test, &[SH, "/bin/launchctl"]) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("p", "")?;
        let control = env.root.join("control");
        let control_label = format!("pent-control-{}", std::process::id());
        if !launchd_runs_a_job(&control, &control_label)? {
            skip(
                test,
                "launchctl submit runs no job on this machine, so the test \
                 cannot show the escape",
            );
            return Ok(());
        }
        let escaped = env.root.join("escaped");
        let label = format!("pent-test-{}", std::process::id());
        let script = format!(
            "/bin/launchctl submit -l {label} -- /bin/sh -c \"touch '{}'\" 2>/dev/null; \
             sleep 3; /bin/launchctl remove {label} 2>/dev/null; true",
            escaped.display()
        );
        let mut child = env
            .command(&["run", "--profile", "p", "--", SH, "-c", &script])
            .spawn()?;
        wait_timeout(&mut child, TIMEOUT)?;
        assert!(
            !escaped.exists(),
            "launchd ran a program for the sandboxed child, and that program \
             wrote {} outside the profile",
            escaped.display()
        );
        Ok(())
    }

    // ── a guard against a silent change of the test set ──────────────────────

    /// The set helper and the rule parser work on the draft format that the
    /// other tests read. A change of the format must not make the other
    /// assertions pass without a reason.
    #[test]
    fn the_rule_parser_reads_a_draft() -> TestResult {
        let draft = "[filesystem]\nread = [\"~/a\"]\nread_write = []\n";
        assert_eq!(rules(draft, "filesystem", "read")?, set(&["~/a"]));
        assert_eq!(rules(draft, "filesystem", "read_write")?, set(&[]));
        assert_eq!(rules(draft, "network", "domains")?, set(&[]));
        Ok(())
    }
}
