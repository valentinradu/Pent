//! Parity of watch mode between Linux and macOS.
//!
//! `docs/design/watch.md` says: "The commands and the results are the same
//! on Linux and on macOS." This test holds that claim. The same command
//! under the same profile must give the same set of rules in the draft,
//! except for the paths that only one platform has.
//!
//! The test runs on both platforms, so a difference shows up as a failure
//! on the platform that changed. On macOS the recorder reads the Seatbelt
//! reports from the unified log, and those reports are a lower bound (the
//! system limits their rate). A missing rule on macOS is therefore the
//! failure that this test is most likely to show first.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox or a tool is
//! absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! ```text
//! cargo test -p pent --test parity_watch -- --nocapture
//! ```

mod common;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod parity {
    use std::collections::BTreeSet;
    use std::fs;

    use super::common::e2e::{
        have_tools, rules, sandbox_ready, stderr, stdout, TestEnv, TestResult,
    };

    /// The command that both platforms record. It reads one file and
    /// changes one file.
    const SCRIPT: &str = "cat ~/.foorc; echo 'b = 2' >> ~/.config/app/settings.toml";

    /// The read rules that the draft must have on every platform.
    const EXPECTED_READ: &[&str] = &["~/.foorc"];

    /// The read-write rules that the draft must have on every platform.
    const EXPECTED_READ_WRITE: &[&str] = &["~/.config/app/settings.toml"];

    /// The prefixes of the rules that only one platform makes.
    ///
    /// A shell reads its own start files, and macOS adds the caches and the
    /// preferences of the system frameworks. A rule below one of these
    /// prefixes is not a difference in the pipeline, so the comparison
    /// ignores it. Keep this list short: each entry hides a difference.
    const PLATFORM_SPECIFIC: &[&str] = &[
        "~/Library",
        "~/.CFUserTextEncoding",
        "~/.cache",
        "~/.bash",
        "~/.zsh",
        "~/.profile",
        "~/.local/share",
        "~/.config/fish",
        "~/.terminfo",
    ];

    /// Return true if `rule` names a path that only one platform has.
    fn is_platform_specific(rule: &str) -> bool {
        PLATFORM_SPECIFIC.iter().any(|p| rule.starts_with(p))
    }

    /// The same command under the same profile gives the same set of rules
    /// on Linux and on macOS.
    #[test]
    fn the_same_command_gives_the_same_rules_on_both_platforms() -> TestResult {
        let test = "watch_parity";
        if !have_tools(test, &["sh", "cat"]) || !sandbox_ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.write_home(".foorc", "foo\n")?;
        env.write_home(".config/app/settings.toml", "a = 1\n")?;

        let out = env.pent_ok(&["watch", "--yes", "--profile", "p", "--", "sh", "-c", SCRIPT])?;
        assert_eq!(stdout(&out), "foo\n", "stderr: {}", stderr(&out));

        let path = env.draft_path("p");
        let draft = fs::read_to_string(&path)
            .map_err(|e| format!("no draft at {}: {e}", path.display()))?;
        let report = format!(
            "--- draft ---\n{draft}\n--- raw watch events ---\n{}",
            env.watch_events("p")
        );

        let read = rules(&draft, "filesystem", "read")?;
        let read_write = rules(&draft, "filesystem", "read_write")?;
        let execute = rules(&draft, "filesystem", "execute")?;
        let domains = rules(&draft, "network", "domains")?;

        // A read-write rule includes read, so a required read rule may be
        // in either list.
        for rule in EXPECTED_READ {
            assert!(
                read.contains(*rule) || read_write.contains(*rule),
                "{} has no rule for {rule}\n{report}",
                std::env::consts::OS
            );
        }
        for rule in EXPECTED_READ_WRITE {
            assert!(
                read_write.contains(*rule),
                "{} has no read-write rule for {rule}\n{report}",
                std::env::consts::OS
            );
        }

        let expected: BTreeSet<&str> = EXPECTED_READ
            .iter()
            .chain(EXPECTED_READ_WRITE)
            .copied()
            .collect();
        let extra: Vec<&String> = read
            .iter()
            .chain(&read_write)
            .chain(&execute)
            .filter(|rule| !expected.contains(rule.as_str()))
            .filter(|rule| !is_platform_specific(rule))
            .collect();
        assert!(
            extra.is_empty(),
            "{} made rules that the other platform does not make: {extra:?}\n{report}",
            std::env::consts::OS
        );
        assert!(
            domains.is_empty(),
            "the command used no network, so the draft must have no domain: \
             {domains:?}\n{report}"
        );
        Ok(())
    }
}
