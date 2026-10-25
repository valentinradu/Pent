//! B. The summary against the kernel.
//!
//! This file runs the round trip of the whole flow for each row of
//! [`differential::WATCH_CASES`]: **watch, trust, run, and no denial**.
//!
//! Three assertions hold the two descriptions together:
//!
//! 1. The draft has each rule that the program really needs. A rule that
//!    the recorder missed shows up in step 3 as a denial.
//! 2. The draft has no rule that the program never needed. Such a rule
//!    makes the profile wider than necessary.
//! 3. A run with the draft as the profile makes no denial. A denial after
//!    a clean watch run is a defect of the recorder.
//!
//! The test `a_run_outside_the_draft_is_recorded` is the positive control
//! of assertion 3: it proves that a denial does reach the log, so a silent
//! log in the other tests means "no denial", not "no recorder".
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
    use super::differential::{watch_closed, WatchCase, RAN};

    /// The messages that a shell prints when the sandbox denies an access.
    const DENIAL_MESSAGES: &[&str] = &["Permission denied", "Operation not permitted"];

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

    /// Run the program again with the draft as the profile and return the
    /// output and the log of the denied accesses.
    fn run_with_the_draft(
        case: &WatchCase,
        env: &TestEnv,
        draft: &str,
    ) -> Result<(String, String), BoxError> {
        if draft.is_empty() {
            env.install_profile("p", "")?;
        } else {
            env.pent_ok(&["trust", "p", "--yes"])?;
        }
        let home = env.home.to_string_lossy().into_owned();
        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--trace",
            "--",
            "sh",
            "-c",
            &format!("printf '{RAN}\\n'\n{}", case.script),
            "pent-probe",
            &home,
        ])?;
        let text = format!("{}{}", stdout(&out), stderr(&out));
        let log = std::fs::read_to_string(env.denied_log("p")).unwrap_or_default();
        Ok((text, log))
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

    /// Assertion 3: watch, trust, run, and no denial.
    #[test]
    fn a_run_with_the_draft_makes_no_denial() -> TestResult {
        let test = "watch_round_trip";
        if !ready(test) {
            return Ok(());
        }
        let mut bad = Vec::new();
        for case in watch_closed() {
            let (env, draft) = watch(case)?;
            let (text, log) = run_with_the_draft(case, &env, &draft)?;
            assert!(
                text.contains(RAN),
                "{}: the child did not run, so the row proves nothing:\n{text}",
                case.id
            );
            let message = DENIAL_MESSAGES.iter().find(|m| text.contains(**m));
            if message.is_some() || !log.trim().is_empty() {
                bad.push(format!(
                    "  {}: the run after a clean watch run got a denial\
                     \n--- output ---\n{text}\n--- denied ---\n{log}\
                     \n--- draft ---\n{draft}",
                    case.id
                ));
            }
        }
        assert!(
            bad.is_empty(),
            "{test}: the recorder missed what the enforcement blocks:\n{}",
            bad.join("\n")
        );
        Ok(())
    }

    /// The positive control of assertion 3: a run that leaves the draft
    /// does get a denial, and pent records it.
    #[test]
    fn a_run_outside_the_draft_is_recorded() -> TestResult {
        let test = "watch_round_trip_control";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        std::fs::write(env.home.join(".apprc"), "cfg\n")?;
        let outside = env.root.join("outside.txt");
        std::fs::write(&outside, "SECRET\n")?;
        let home = env.home.to_string_lossy().into_owned();
        env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "p",
            "--",
            "sh",
            "-c",
            r#"cat "$1/.apprc" > /dev/null"#,
            "pent-probe",
            &home,
        ])?;
        env.pent_ok(&["trust", "p", "--yes"])?;
        let outside = outside.to_string_lossy().into_owned();
        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--trace",
            "--",
            "sh",
            "-c",
            &format!("printf '{RAN}\\n'; cat \"$1\" 2>&1"),
            "pent-probe",
            &outside,
        ])?;
        let text = format!("{}{}", stdout(&out), stderr(&out));
        assert!(text.contains(RAN), "the child did not run:\n{text}");
        let log = std::fs::read_to_string(env.denied_log("p")).unwrap_or_default();
        assert!(
            log.contains("outside.txt"),
            "pent must record an access that the draft does not name, else \
             an empty log proves nothing:\n{text}\nlog: {log}"
        );
        Ok(())
    }
}
