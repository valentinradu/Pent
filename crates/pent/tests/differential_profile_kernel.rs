//! A. The profile against the kernel.
//!
//! The profile is one description of the policy; the kernel is another.
//! This file runs the real `pent` binary for each row of
//! [`differential::FS_CASES`] and asserts that the result of the run is
//! the result that the profile states.
//!
//! The test writes nothing by hand: the table holds the profile, the path,
//! the access and the verdict. To add a case, add one line to the table.
//!
//! Each row that asserts a denial has a row that asserts the access in the
//! same table, so a run that fails for another reason cannot pass the
//! table. Each probe also prints `PENT_CHILD_RAN` first: a child that never
//! started proves nothing.
//!
//! A test skips (it prints `SKIP` and passes) when the sandbox or a tool is
//! absent. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! ```text
//! cargo test -p pent --test differential_profile_kernel -- --include-ignored --nocapture
//! ```

mod common;

#[path = "common/differential.rs"]
mod differential;

#[cfg(target_os = "linux")]
mod fs_table {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::common::e2e::{
        have_tools, sandbox_ready, stderr, stdout, BoxError, TestEnv, TestResult,
    };
    use super::differential::{
        fs_closed, fs_open, resolve, Access, FsCase, Verdict, EXECUTED, GREETING, MARKER, RAN,
        WROTE,
    };

    /// The content of every file that the table makes. The file is a shell
    /// script with the marker in a comment, so one file serves a read, a
    /// write and an execution.
    fn file_body() -> String {
        format!("#!/bin/sh\n# {MARKER}\necho {EXECUTED}\n")
    }

    /// The probe that reads the path in `$1`.
    const READ_PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'; cat "$1" 2>&1"#;

    /// The probe that appends to the path in `$1`.
    const WRITE_PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'
d=$(dirname "$1")
mkdir -p "$d" 2>&1
printf 'PENT-WROTE\n' >> "$1" 2>&1
printf 'rc=%s\n' "$?"
"#;

    /// The probe that runs the path in `$1`.
    const EXEC_PROBE: &str = r#"printf 'PENT_CHILD_RAN\n'; "$1" 2>&1"#;

    /// The probe that connects to the Unix socket in `sys.argv[1]`.
    const SOCKET_PROBE: &str = "import socket, sys\n\
         print('PENT_CHILD_RAN', flush=True)\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         s.settimeout(5)\n\
         try:\n\
         \x20   s.connect(sys.argv[1])\n\
         \x20   print(s.recv(64).decode(), flush=True)\n\
         except OSError as e:\n\
         \x20   print('ERROR', e, flush=True)\n";

    /// A Unix socket server that answers every connection with
    /// [`GREETING`].
    ///
    /// The thread runs until the test ends. It holds the listener, so the
    /// socket stays in the directory for the whole run.
    struct Server {
        stop: Arc<AtomicBool>,
        path: PathBuf,
    }

    impl Server {
        /// Bind a server at `path`.
        ///
        /// # Errors
        /// Returns an error if the socket cannot be bound.
        fn start(path: &Path) -> std::io::Result<Self> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let listener = UnixListener::bind(path)?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(mut s) = stream {
                        // The client can close first; the test reads the
                        // result, so a failed write needs no report.
                        let _ = s.write_all(format!("{GREETING}\n").as_bytes());
                    }
                }
            });
            Ok(Self {
                stop,
                path: path.to_path_buf(),
            })
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // Wake the thread one time, so it sees the flag and ends.
            let _ = std::os::unix::net::UnixStream::connect(&self.path);
        }
    }

    /// Make the file, the link or the socket that `case` needs.
    ///
    /// Returns the server when the case uses a Unix socket.
    fn prepare(case: &FsCase, env: &TestEnv) -> Result<Option<Server>, BoxError> {
        if let Some((link, target)) = case.symlink {
            let target = env.home.join(target);
            if let Some(dir) = target.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&target, file_body())?;
            let link = env.home.join(link);
            if link.symlink_metadata().is_ok() {
                std::fs::remove_file(&link)?;
            }
            std::os::unix::fs::symlink(&target, &link)?;
        }
        let path = resolve(&env.home, &env.ws, case.target);
        if case.access == Access::UnixSocket {
            return Ok(Some(Server::start(&path)?));
        }
        if case.make_in_run || case.symlink.is_some() {
            return Ok(None);
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, file_body())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(None)
    }

    /// Run one row and return the verdict of the kernel.
    fn kernel_verdict(case: &FsCase) -> Result<Verdict, BoxError> {
        let env = TestEnv::new()?;
        // A path with `..` leaves the home directory; the parent must
        // exist before the run.
        std::fs::create_dir_all(&env.root)?;
        env.install_profile("p", case.profile)?;
        let server = prepare(case, &env)?;
        let path = resolve(&env.home, &env.ws, case.target);
        let text = path.to_string_lossy().into_owned();

        let args: Vec<&str> = match case.access {
            Access::Read => vec![
                "run",
                "--profile",
                "p",
                "--",
                "sh",
                "-c",
                READ_PROBE,
                "p",
                &text,
            ],
            Access::Write => vec![
                "run",
                "--profile",
                "p",
                "--",
                "sh",
                "-c",
                WRITE_PROBE,
                "p",
                &text,
            ],
            Access::Execute => vec![
                "run",
                "--profile",
                "p",
                "--",
                "sh",
                "-c",
                EXEC_PROBE,
                "p",
                &text,
            ],
            Access::UnixSocket => vec![
                "run",
                "--profile",
                "p",
                "--",
                "python3",
                "-c",
                SOCKET_PROBE,
                &text,
            ],
        };
        let out = env.pent(&args)?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            combined.contains(RAN),
            "{}: the child did not run, so the row proves nothing:\n{combined}",
            case.id
        );
        drop(server);

        let verdict = match case.access {
            Access::Read => yes_no(combined.contains(MARKER)),
            Access::Execute => yes_no(combined.contains(EXECUTED)),
            Access::UnixSocket => yes_no(combined.contains(GREETING)),
            // A write that the overlay discards is not a write. The host
            // file is the only honest answer.
            Access::Write => {
                let host = std::fs::read_to_string(&path).unwrap_or_default();
                yes_no(host.contains(WROTE))
            }
        };
        Ok(verdict)
    }

    /// `Allow` for true, `Deny` for false.
    fn yes_no(allowed: bool) -> Verdict {
        if allowed {
            Verdict::Allow
        } else {
            Verdict::Deny
        }
    }

    /// Run `cases` and fail with the full list of the rows that disagree.
    fn run_rows(test: &str, cases: &[&FsCase]) -> TestResult {
        let mut wrong = Vec::new();
        for case in cases {
            let got = kernel_verdict(case)?;
            if got != case.verdict {
                wrong.push(format!(
                    "  {}: the profile says {}, the kernel says {}",
                    case.id,
                    case.verdict.word(),
                    got.word()
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{test}: the profile and the kernel disagree on {} of {} rows:\n{}",
            wrong.len(),
            cases.len(),
            wrong.join("\n")
        );
        Ok(())
    }

    /// Return true when the host can run every row.
    fn ready(test: &str) -> bool {
        have_tools(test, &["sh", "cat", "dirname", "python3"]) && sandbox_ready(test)
    }

    /// Every row of the table without an open disagreement: the result of
    /// a real `pent run` is the result that the profile states.
    #[test]
    fn the_profile_and_the_kernel_agree() -> TestResult {
        let test = "fs_profile_vs_kernel";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &fs_closed())
    }

    /// A profile entry that names a symbolic link must give access to the
    /// file. Today it gives access to neither the link nor its target.
    #[test]
    #[ignore = "OPEN DIFF-2: a profile entry that names a symbolic link gives access to nothing"]
    fn diff_2_a_profile_entry_that_names_a_symbolic_link() -> TestResult {
        let test = "fs_diff_2_symlink";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &fs_open("DIFF-2"))
    }

    /// A profile has three lists, and `read` is not `execute`. A rule that
    /// gives read access must not let the program run the file.
    #[test]
    #[ignore = "OPEN DIFF-4: a read rule also gives execute"]
    fn diff_4_a_read_rule_also_gives_execute() -> TestResult {
        let test = "fs_diff_4_read_gives_execute";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &fs_open("DIFF-4"))
    }

    /// A rule that gives read access must not let the program change what
    /// the other processes of the sandbox read.
    ///
    /// The overlay discards the write at the end of the run, so the file
    /// of the host does not change (the table holds that row). Inside the
    /// run the write succeeds and every later read gives the new content.
    #[test]
    #[ignore = "OPEN DIFF-3: a write to a read-only rule succeeds inside the run"]
    fn diff_3_a_write_to_a_read_only_rule_succeeds_in_the_run() -> TestResult {
        let test = "fs_diff_3_write_in_the_run";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("p", "[filesystem]\nread = [\"~/ro\"]\n")?;
        let file = env.home.join("ro/f.txt");
        std::fs::create_dir_all(env.home.join("ro"))?;
        std::fs::write(&file, format!("{MARKER}\n"))?;
        let script = format!(
            "printf '{RAN}\\n'\nprintf 'changed\\n' > \"$1\" 2>&1\nprintf 'rc=%s\\n' \"$?\"\ncat \"$1\" 2>&1\n"
        );
        let text = file.to_string_lossy().into_owned();
        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--",
            "sh",
            "-c",
            &script,
            "p",
            &text,
        ])?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(combined.contains(RAN), "the child did not run:\n{combined}");
        assert!(
            combined.contains("rc=1") || !combined.contains("changed"),
            "a read rule let the program change the file inside the run; \
             the next read of any process of the sandbox gives the new \
             content:\n{combined}"
        );
        Ok(())
    }

    /// The kernel must tell pent about every access that it blocks.
    ///
    /// `pent run --trace` records a Landlock denial. It records nothing
    /// when the overlay hides the path: the program gets `ENOENT`, and the
    /// review never sees the access.
    #[test]
    #[ignore = "OPEN DIFF-1: a read that the overlay hides is not recorded as a denial"]
    fn diff_1_a_hidden_path_is_not_a_recorded_denial() -> TestResult {
        let test = "fs_diff_1_hidden_denial";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        env.install_profile("p", "[filesystem]\nread = [\"~/open.txt\"]\n")?;
        std::fs::write(env.home.join("open.txt"), format!("{MARKER}\n"))?;
        std::fs::write(env.home.join("secret.txt"), "SECRET\n")?;
        let hidden = env.home.join("secret.txt").to_string_lossy().into_owned();
        let out = env.pent(&[
            "run",
            "--profile",
            "p",
            "--trace",
            "--",
            "sh",
            "-c",
            READ_PROBE,
            "p",
            &hidden,
        ])?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(combined.contains(RAN), "the child did not run:\n{combined}");
        // The positive control: a path outside the home directory gives a
        // Landlock denial, and pent records it.
        let outside = env.root.join("outside.txt");
        std::fs::write(&outside, "SECRET\n")?;
        let outside = outside.to_string_lossy().into_owned();
        let control = env.pent(&[
            "run",
            "--profile",
            "p",
            "--trace",
            "--",
            "sh",
            "-c",
            READ_PROBE,
            "p",
            &outside,
        ])?;
        let control_text = format!("{}{}", stdout(&control), stderr(&control));
        let log = std::fs::read_to_string(env.denied_log("p")).unwrap_or_default();
        assert!(
            log.contains("outside.txt"),
            "the positive control failed: pent did not record the Landlock \
             denial, so this test proves nothing\n{control_text}\nlog: {log}"
        );
        assert!(
            log.contains("secret.txt"),
            "the overlay hid \"secret.txt\" and the program got ENOENT, but \
             pent recorded no denial, so `pent trust p --review` never shows \
             the access:\n{combined}\nlog: {log}"
        );
        Ok(())
    }

    /// The table must stay a table: a row with an open disagreement needs
    /// its own ignored test, else the disagreement is silent.
    #[test]
    fn every_open_row_has_a_test() {
        let mut ids: Vec<&str> = super::differential::FS_CASES
            .iter()
            .filter_map(|c| c.open)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids,
            vec!["DIFF-2", "DIFF-4"],
            "a row of FS_CASES names a disagreement without an ignored test \
             in this file"
        );
    }
}
