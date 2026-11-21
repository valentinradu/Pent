//! The rules of a watch draft for a known command.
//!
//! A command with a known set of accesses must give exactly that set of
//! rules in the draft, except for the start files of the shell. A missing
//! rule or an extra rule is a change in the pipeline of watch mode.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox or a tool is
//! absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! ```text
//! cargo test -p pent --test watch_draft_rules -- --nocapture
//! ```

mod common;

#[cfg(target_os = "linux")]
mod draft_rules {
    use std::collections::BTreeSet;
    use std::fs;

    use super::common::e2e::{
        have_tools, rules, sandbox_ready, stderr, stdout, TestEnv, TestResult,
    };

    /// The recorded command. It reads one file and changes one file.
    /// The shell reads and writes the files itself, with no child program.
    const SCRIPT: &str =
        "read -r l < ~/.foorc; echo \"$l\"; echo 'b = 2' >> ~/.config/app/settings.toml";

    /// The read rules that the draft must have.
    const EXPECTED_READ: &[&str] = &["~/.foorc"];

    /// The read-write rules that the draft must have.
    const EXPECTED_READ_WRITE: &[&str] = &["~/.config/app/settings.toml"];

    /// The prefixes of the rules that depend on the shell of the host.
    ///
    /// A shell reads its own start files. A rule below one of these
    /// prefixes is not a change in the pipeline, so the comparison ignores
    /// it. Keep this list short: each entry hides a difference.
    const HOST_SPECIFIC: &[&str] = &[
        "~/.cache",
        "~/.bash",
        "~/.zsh",
        "~/.profile",
        "~/.local/share",
        "~/.config/fish",
        "~/.terminfo",
    ];

    /// Return true if `rule` names a path that depends on the shell of the
    /// host.
    fn is_host_specific(rule: &str) -> bool {
        HOST_SPECIFIC.iter().any(|p| rule.starts_with(p))
    }

    /// A known command gives exactly the expected rules in the draft.
    #[test]
    fn a_known_command_gives_the_expected_rules() -> TestResult {
        let test = "watch_draft_rules";
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
                "the draft has no rule for {rule}\n{report}"
            );
        }
        for rule in EXPECTED_READ_WRITE {
            assert!(
                read_write.contains(*rule),
                "the draft has no read-write rule for {rule}\n{report}"
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
            .filter(|rule| !is_host_specific(rule))
            .collect();
        assert!(
            extra.is_empty(),
            "the draft has rules that the command does not need: {extra:?}\n{report}"
        );
        assert!(
            domains.is_empty(),
            "the command used no network, so the draft must have no domain: \
             {domains:?}\n{report}"
        );
        Ok(())
    }
}
