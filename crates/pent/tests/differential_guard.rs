//! C. The guard against the summary.
//!
//! `pent_profile::classify` tells the user that an access is blocked. The
//! kernel of a watch run either blocks it or does not. The two verdicts
//! must agree. When the summary says "blocked" and the kernel allows the
//! access, the user trusts a protection that is not there; that is the
//! most dangerous of the three kinds of disagreement.
//!
//! The table [`differential::GUARD_CASES`] holds the paths: a key with
//! each name shape, keys at several depths, a key through a symbolic
//! link, a key with a character of a regular expression in its name, the
//! persistence writes, and the positive controls that the guard must not
//! block.
//!
//! The same table runs on Linux and on macOS. A row carries one
//! disagreement identifier for each platform, because the two kernel
//! backends enforce the guard in different ways. The macOS half runs only
//! in the pipeline; nobody has run it on a Mac yet.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox or a tool
//! is absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! ```text
//! cargo test -p pent --test differential_guard -- --include-ignored --nocapture
//! ```

mod common;

#[path = "common/differential.rs"]
mod differential;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod guard_table {
    use std::path::Path;

    use pent_profile::{classify, guard_rules, GuardAccess, GuardClass};

    use super::common::e2e::{
        have_tools, sandbox_ready, stderr, stdout, BoxError, TestEnv, TestResult,
    };
    use super::differential::{
        guard_closed, guard_open, guard_open_ids, GuardCase, GuardKind, Verdict, MARKER, RAN, WROTE,
    };

    /// The probe that reads the path in `$1`.
    const READ_PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'; cat "$1" 2>&1"#;

    /// The probe that makes the path in `$1` and then reads it.
    const MAKE_AND_READ_PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'
printf 'PENT-SECRET-CONTENT\n' > "$1" 2>&1
cat "$1" 2>&1
"#;

    /// The probe that appends to the path in `$1`.
    const WRITE_PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'
printf 'PENT-WROTE\n' >> "$1" 2>&1
printf 'rc=%s\n' "$?"
"#;

    /// The name that the table uses for a guard class.
    fn class_name(class: GuardClass) -> &'static str {
        match class {
            GuardClass::Credential => "credential",
            GuardClass::Persistence => "persistence",
            GuardClass::PentFiles => "pent-files",
            GuardClass::PrivilegeEscalation => "privilege-escalation",
        }
    }

    /// The verdict of `classify` for `case`: `Deny` when a guard rule
    /// matches, `Allow` when none matches.
    fn summary_verdict(case: &GuardCase, home: &Path) -> Result<Verdict, BoxError> {
        let rules = guard_rules(home);
        let access = match case.kind {
            GuardKind::Read => GuardAccess::Read,
            GuardKind::Write => GuardAccess::Write,
        };
        let got = classify(&rules, &home.join(case.path), access);
        let got_name = got.map_or("", class_name);
        if got_name != case.class {
            return Err(format!(
                "{}: classify says {got_name:?} for {} {:?}, the table says {:?}. \
                 The table and the guard list must agree before the kernel \
                 can be compared with either one.",
                case.id,
                case.kind_word(),
                case.path,
                case.class
            )
            .into());
        }
        Ok(if case.class.is_empty() {
            Verdict::Allow
        } else {
            Verdict::Deny
        })
    }

    /// Make the files and the link that `case` needs.
    fn prepare(case: &GuardCase, env: &TestEnv) -> TestResult {
        if let Some((link, target)) = case.link_dir {
            let target = env.home.join(target);
            std::fs::create_dir_all(&target)?;
            let link = env.home.join(link);
            if let Some(dir) = link.parent() {
                std::fs::create_dir_all(dir)?;
            }
            if link.symlink_metadata().is_ok() {
                std::fs::remove_file(&link)?;
            }
            std::os::unix::fs::symlink(&target, &link)?;
        }
        if case.make_in_run {
            // Only the parent exists; the program makes the file.
            if let Some(dir) = env.home.join(case.path).parent() {
                std::fs::create_dir_all(dir)?;
            }
            return Ok(());
        }
        let path = env.home.join(case.path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, format!("{MARKER}\n"))?;
        Ok(())
    }

    /// Run `case` under `pent watch` and return the verdict of the kernel.
    fn kernel_verdict(case: &GuardCase) -> Result<(Verdict, String), BoxError> {
        let env = TestEnv::new()?;
        prepare(case, &env)?;
        let path = env.home.join(case.path);
        let text = path.to_string_lossy().into_owned();
        let probe = match (case.kind, case.make_in_run) {
            (GuardKind::Read, false) => READ_PROBE,
            (GuardKind::Read, true) => MAKE_AND_READ_PROBE,
            (GuardKind::Write, _) => WRITE_PROBE,
        };
        let out = env.pent(&[
            "watch",
            "--yes",
            "--profile",
            "p",
            "--",
            "sh",
            "-c",
            probe,
            "pent-probe",
            &text,
        ])?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            combined.contains(RAN),
            "{}: the child did not run, so the row proves nothing:\n{combined}",
            case.id
        );
        let allowed = match case.kind {
            GuardKind::Read => combined.contains(MARKER),
            GuardKind::Write => std::fs::read_to_string(&path)
                .unwrap_or_default()
                .contains(WROTE),
        };
        let verdict = if allowed {
            Verdict::Allow
        } else {
            Verdict::Deny
        };
        Ok((verdict, combined))
    }

    /// Run `cases` and fail with the full list of the rows that disagree.
    fn run_rows(test: &str, cases: &[&GuardCase]) -> TestResult {
        assert!(!cases.is_empty(), "{test}: the row list is empty");
        let mut wrong = Vec::new();
        for case in cases {
            let env_home = TestEnv::new()?;
            let want = summary_verdict(case, &env_home.home)?;
            drop(env_home);
            let (got, output) = kernel_verdict(case)?;
            if got != want {
                wrong.push(format!(
                    "  {}: {} {:?}: classify says {}, the kernel says {}\n{output}",
                    case.id,
                    case.kind_word(),
                    case.path,
                    want.word(),
                    got.word()
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{test}: `classify` and the kernel disagree on {} of {} rows:\n{}",
            wrong.len(),
            cases.len(),
            wrong.join("\n")
        );
        Ok(())
    }

    /// Return true when the host can run every row.
    fn ready(test: &str) -> bool {
        have_tools(test, &["sh", "cat"]) && sandbox_ready(test)
    }

    /// Every row of the table without an open disagreement: the verdict
    /// of `classify` is the verdict of the kernel in a real watch run.
    #[test]
    fn classify_and_the_kernel_agree() -> TestResult {
        let test = "guard_classify_vs_kernel";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &guard_closed())
    }

    /// The guard must hide a private key that a symbolic link below
    /// `~/.ssh` points to. The summary says "blocked"; the program reads
    /// the key.
    #[test]
    #[ignore = "OPEN DIFF-5: the guard misses a key behind a symbolic link, but the summary says blocked"]
    fn diff_5_a_key_behind_a_symbolic_link() -> TestResult {
        let test = "guard_diff_5_symlink";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &guard_open("DIFF-5"))
    }

    /// The guard must hide a private key that the program makes during
    /// the run. The summary says "blocked"; the program reads the key.
    ///
    /// Seatbelt decides at the time of the access, so the row has no
    /// disagreement on macOS and the test runs on Linux only.
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "OPEN DIFF-6: the guard misses a key made during the run, but the summary says blocked"]
    fn diff_6_a_key_made_during_the_run() -> TestResult {
        let test = "guard_diff_6_new_key";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &guard_open("DIFF-6"))
    }

    /// On macOS the guard must also hide a key whose name matches a
    /// suffix pattern. The backend builds a regular expression from the
    /// prefix form only.
    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "OPEN DIFF-9: on macOS the guard misses a key name that matches a suffix pattern"]
    fn diff_9_a_suffix_pattern_on_macos() -> TestResult {
        let test = "guard_diff_9_suffix_pattern";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &guard_open("DIFF-9"))
    }

    /// Each disagreement of the table has an ignored test in this file.
    #[test]
    fn every_open_row_has_a_test() {
        let expected: Vec<&str> = if cfg!(target_os = "macos") {
            vec!["DIFF-5", "DIFF-9"]
        } else {
            vec!["DIFF-5", "DIFF-6"]
        };
        assert_eq!(
            guard_open_ids(),
            expected,
            "a row of GUARD_CASES names a disagreement without an ignored \
             test in this file"
        );
    }
}

/// DIFF-7: the summary proposes a rule on a path that the guard calls a
/// credential.
///
/// The recorder sees two events for the same path: the create (which
/// becomes a read-write rule) and the read (which the guard blocks). The
/// review selects the normal section by default and the blocked section
/// not at all, so a user who presses Enter writes a draft that gives
/// read-write access to a private key.
#[cfg(target_os = "linux")]
mod draft_against_the_guard {
    use super::common::e2e::{
        have_tools, rules, sandbox_ready, stderr, stdout, TestEnv, TestResult,
    };

    #[test]
    fn diff_7_the_draft_grants_a_blocked_credential() -> TestResult {
        let test = "guard_diff_7_draft_grants_a_credential";
        if !have_tools(test, &["sh", "cat"]) || !sandbox_ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        std::fs::create_dir_all(env.home.join(".ssh"))?;
        let home = env.home.to_string_lossy().into_owned();
        let out = env.pent_ok(&[
            "watch",
            "--yes",
            "--profile",
            "p",
            "--",
            "sh",
            "-c",
            r#"printf 'KEY\n' > "$1/.ssh/id_new"; cat "$1/.ssh/id_new" > /dev/null"#,
            "pent-probe",
            &home,
        ])?;
        let report = format!("stdout: {}\nstderr: {}", stdout(&out), stderr(&out));
        let draft = std::fs::read_to_string(env.draft_path("p")).unwrap_or_default();
        assert!(
            report.contains("Blocked by the guard"),
            "the positive control failed: the summary must show the blocked \
             read, else this test proves nothing\n{report}"
        );
        let mut granted = rules(&draft, "filesystem", "read_write")?;
        granted.extend(rules(&draft, "filesystem", "read")?);
        assert!(
            !granted.contains("~/.ssh/id_new"),
            "the summary shows \"read ~/.ssh/id_new\" as a blocked \
             credential and at the same time proposes a rule on the same \
             path. The review selects that rule by default, so the draft \
             gives read-write access to a private key.\n--- draft ---\n\
             {draft}\n{report}"
        );
        Ok(())
    }
}
