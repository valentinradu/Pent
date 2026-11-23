//! B. The summary against the kernel.
//!
//! This file runs `pent watch` for each row of
//! [`differential::WATCH_CASES`] and compares the draft with what the
//! program really did.
//!
//! Two assertions hold the two descriptions together:
//!
//! 1. The draft has each rule that the program really needs.
//! 2. The draft has no rule that the program never needed. Such a rule
//!    makes the profile wider than necessary.
//!
//! `pent run` no longer applies a profile: it applies the rule file of a
//! key. Thus the third step of the old round trip (a run with the draft
//! as the profile makes no denial) has no claim now, and this file does
//! not test it.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox or a tool
//! is absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! ```text
//! cargo test -p pent --test differential_watch_round_trip -- --include-ignored --nocapture
//! ```

mod common;

#[path = "common/differential.rs"]
mod differential;

#[cfg(target_os = "linux")]
mod round_trip {
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt as _;

    use super::common::e2e::{
        have_tools, rules, sandbox_ready, stderr, stdout, BoxError, TestEnv, TestResult,
    };
    use super::differential::{watch_closed, WatchCase};

    /// Make the files and the links of `case`.
    fn prepare(case: &WatchCase, env: &TestEnv) -> TestResult {
        for (rel, body) in case.setup {
            let path = env.home.join(rel);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, body)?;
        }
        for rel in case.executables {
            let path = env.home.join(rel);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
        for (link, target) in case.links {
            let target = env.home.join(target);
            let link = env.home.join(link);
            if link.symlink_metadata().is_ok() {
                std::fs::remove_file(&link)?;
            }
            std::os::unix::fs::symlink(&target, &link)?;
        }
        Ok(())
    }

    /// Every rule of the draft, from each list.
    fn draft_rules(draft: &str) -> Result<BTreeSet<String>, BoxError> {
        let mut all = BTreeSet::new();
        for key in ["read", "read_write", "execute", "unix_sockets"] {
            all.extend(rules(draft, "filesystem", key)?);
        }
        all.extend(rules(draft, "network", "domains")?);
        Ok(all)
    }

    /// Run `pent watch` for `case` and return the test environment and the
    /// text of the draft (empty when pent wrote no draft).
    fn watch(case: &WatchCase) -> Result<(TestEnv, String), BoxError> {
        let env = TestEnv::new()?;
        prepare(case, &env)?;
        let home = env.home.to_string_lossy().into_owned();
        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "p",
            "--",
            "sh",
            "-c",
            case.script,
            "pent-probe",
            &home,
        ])?;
        let report = format!("stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
        let draft = std::fs::read_to_string(env.draft_path("p")).unwrap_or_default();
        assert!(
            !draft.is_empty() || case.needs.is_empty(),
            "{}: pent wrote no draft, but the program needs {:?}\n{report}",
            case.id,
            case.needs
        );
        Ok((env, draft))
    }

    /// Return true when the host can run every row.
    fn ready(test: &str) -> bool {
        have_tools(test, &["sh", "cat", "ln", "mv", "rm"]) && sandbox_ready(test)
    }

    /// Assertion 1: the draft has each rule that the program needs.
    #[test]
    fn the_draft_has_each_rule_that_the_program_needs() -> TestResult {
        let test = "watch_draft_is_complete";
        if !ready(test) {
            return Ok(());
        }
        let mut missing = Vec::new();
        for case in watch_closed() {
            let (env, draft) = watch(case)?;
            let have = draft_rules(&draft)?;
            for rule in case.needs {
                if !have.contains(*rule) {
                    missing.push(format!(
                        "  {}: the draft has no rule for {rule:?}\n--- draft ---\n{draft}\
                         \n--- raw events ---\n{}",
                        case.id,
                        env.watch_events("p")
                    ));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "{test}: the recorder missed a rule:\n{}",
            missing.join("\n")
        );
        Ok(())
    }

    /// Assertion 2: the draft has no rule that the program never needed.
    #[test]
    fn the_draft_has_no_rule_that_the_program_never_needed() -> TestResult {
        let test = "watch_draft_is_narrow";
        if !ready(test) {
            return Ok(());
        }
        let mut extra = Vec::new();
        for case in watch_closed() {
            let (_env, draft) = watch(case)?;
            let have = draft_rules(&draft)?;
            let needed: BTreeSet<&str> = case.needs.iter().copied().collect();
            for rule in &have {
                if needed.contains(rule.as_str()) {
                    continue;
                }
                if case.allowed_extra.iter().any(|p| rule.starts_with(p)) {
                    continue;
                }
                extra.push(format!(
                    "  {}: the draft has {rule:?}, which the program never needed\
                     \n--- draft ---\n{draft}",
                    case.id
                ));
            }
        }
        assert!(
            extra.is_empty(),
            "{test}: the profile is wider than necessary:\n{}",
            extra.join("\n")
        );
        Ok(())
    }
}
