//! A. The rules against the kernel.
//!
//! The rule file of a key is one description of the policy; the kernel is
//! another. This file runs the real `pent` binary for each row of
//! [`differential::FS_CASES`] and asserts that the result of the run is
//! the result that the rules state.
//!
//! The table holds a profile for each row. The test translates the
//! profile into the rule file of the key, with the map of `Grants::of`
//! (`crates/pent/src/commands/decide.rs`):
//!
//! - `read`, `read_write` and `execute` become the rule kinds `read`,
//!   `write` and `exec`;
//! - an entry that names the target of a row of the same profile is a
//!   file and gets the exact width; each other entry is a directory and
//!   gets the subtree width (`/**`);
//! - `~` is the home directory, and a relative entry is below the
//!   workspace, because a rule path is always absolute;
//! - `unix_sockets` becomes `unix-socket`, and `domains` becomes `domain`.
//!
//! The test writes nothing by hand: the table holds the profile, the path,
//! the access and the verdict. To add a case, add one line to the table.
//! [`HELD_BACK_ROWS`] holds the rows where the rule form gives another
//! verdict than the profile, each with its reason.
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
    use std::process::{Child, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::common::e2e::{
        have_tools, sandbox_ready, stderr, stdout, BoxError, TestEnv, TestResult,
    };
    use super::differential::{
        fs_closed, fs_rows, resolve, Access, FsCase, Verdict, EXECUTED, FS_CASES, GREETING, MARKER,
        RAN, WROTE,
    };

    /// The key of each run of this file.
    const KEY: &str = "p";

    /// The start of the warning of `pent run` for a rule that it does not
    /// apply.
    const HELD_BACK: &str = "this run does not apply the rule";

    /// The rows where `pent run` does not apply a rule of the profile, with
    /// the verdict of the rules then.
    ///
    /// A static layer cannot give a subtree that covers a location of the
    /// guard list: a credential, a file that runs code later, or a file of
    /// pent. `pent run` then does not apply the rule, and it warns. A
    /// profile gave such a subtree. The rows of this list now prove that
    /// the kernel gives nothing for the rule:
    ///
    /// - `~` covers the files of pent and the credentials.
    ///
    /// The check looks at the kind of the rule: the guard stops only a
    /// write in `~/bin`, so a read or an exec rule on `~/bin` applies.
    const HELD_BACK_ROWS: &[(&str, Verdict)] = &[
        ("tilde-a-file-of-the-home-directory", Verdict::Deny),
        ("tilde-does-not-reach-the-root", Verdict::Deny),
    ];

    /// The verdict of the rules for `case`.
    fn rule_verdict(case: &FsCase) -> Verdict {
        HELD_BACK_ROWS
            .iter()
            .find(|(id, _)| *id == case.id)
            .map_or(case.verdict, |(_, verdict)| *verdict)
    }

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

    /// The arguments of `pent run` with the key of this file. `extra`
    /// comes before `--`, and `command` after it.
    fn run_args<'a>(extra: &[&'a str], command: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec!["run", "--key", KEY];
        args.extend_from_slice(extra);
        args.push("--");
        args.extend_from_slice(command);
        args
    }

    /// The absolute path of a profile entry: `~` is the home directory,
    /// and a relative entry is below the workspace.
    fn entry_path(entry: &str, env: &TestEnv) -> PathBuf {
        if entry == "~" {
            env.home.clone()
        } else if let Some(rest) = entry.strip_prefix("~/") {
            env.home.join(rest)
        } else {
            env.ws.join(entry)
        }
    }

    /// The text of `path` for a rule target.
    fn path_text(path: &Path) -> Result<&str, BoxError> {
        path.to_str()
            .ok_or_else(|| format!("the path {} is not UTF-8", path.display()).into())
    }

    /// The entries of the list `key` in the table `section`.
    ///
    /// # Errors
    /// Returns an error when the list holds a value that is not a string.
    fn entries<'a>(section: Option<&'a toml::Table>, key: &str) -> Result<Vec<&'a str>, BoxError> {
        let Some(list) = section.and_then(|s| s.get(key)) else {
            return Ok(Vec::new());
        };
        let list = list
            .as_array()
            .ok_or_else(|| format!("the profile key {key:?} is not a list"))?;
        list.iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| format!("an entry of {key:?} is not a string").into())
            })
            .collect()
    }

    /// The rule targets of the profile of `case`, in the text form of
    /// `pent rules show`. See the head of this file for the map.
    ///
    /// # Errors
    /// Returns an error for a profile key that has no rule form, so a new
    /// profile shape in the table cannot pass in silence.
    fn rule_targets(case: &FsCase, env: &TestEnv) -> Result<Vec<String>, BoxError> {
        let table: toml::Table = case.profile.parse()?;
        for (name, value) in &table {
            let known: &[&str] = match name.as_str() {
                "filesystem" => &["read", "read_write", "execute", "unix_sockets"],
                "network" => &["domains"],
                other => return Err(format!("{}: no rule form for [{other}]", case.id).into()),
            };
            let section = value
                .as_table()
                .ok_or_else(|| format!("{}: [{name}] is not a table", case.id))?;
            if let Some(key) = section.keys().find(|k| !known.contains(&k.as_str())) {
                return Err(format!("{}: no rule form for {name}.{key}", case.id).into());
            }
        }
        let files: Vec<PathBuf> = FS_CASES
            .iter()
            .filter(|c| c.profile == case.profile)
            .map(|c| resolve(&env.home, &env.ws, c.target))
            .collect();
        let fs = table.get("filesystem").and_then(toml::Value::as_table);
        let mut targets = Vec::new();
        for (list, kind) in [
            ("read", "read"),
            ("read_write", "write"),
            ("execute", "exec"),
        ] {
            for entry in entries(fs, list)? {
                let path = entry_path(entry, env);
                let text = path_text(&path)?;
                if files.contains(&path) {
                    targets.push(format!("{kind} {text}"));
                } else {
                    targets.push(format!("{kind} {text}/**"));
                }
            }
        }
        for entry in entries(fs, "unix_sockets")? {
            let path = entry_path(entry, env);
            targets.push(format!("unix-socket {}", path_text(&path)?));
        }
        let net = table.get("network").and_then(toml::Value::as_table);
        for domain in entries(net, "domains")? {
            targets.push(format!("domain {domain}"));
        }
        Ok(targets)
    }

    /// Write the rule file of [`KEY`] with `targets`.
    fn install(env: &TestEnv, targets: &[String]) -> TestResult {
        let targets: Vec<&str> = targets.iter().map(String::as_str).collect();
        env.install_rules(KEY, &targets)
    }

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

    /// A pentd in the foreground for one test. It keeps the refusals of a
    /// run after the run ends, so `pent denials` can show them.
    struct Pentd(Child);

    impl Pentd {
        /// Start pentd with the runtime directory of `env`, and wait until
        /// it listens.
        ///
        /// # Errors
        /// Returns an error if pentd cannot start or never listens.
        fn start(env: &TestEnv) -> Result<Self, BoxError> {
            let child = env
                .command(&["daemon"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let pentd = Self(child);
            let socket = env.runtime.join("pent/pentd.sock");
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
                    return Ok(pentd);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(format!("pentd never listened on {}", socket.display()).into())
        }
    }

    impl Drop for Pentd {
        fn drop(&mut self) {
            // The child can be gone already; the error does not matter here.
            let _ = self.0.kill();
            let _ = self.0.wait();
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

    /// What one run of a row gives: the verdict of the kernel, true when
    /// pent warned that it does not apply a rule, and the output.
    struct Run {
        verdict: Verdict,
        held_back: bool,
        output: String,
    }

    /// Run one row and return what the kernel did.
    fn kernel_verdict(case: &FsCase) -> Result<Run, BoxError> {
        let env = TestEnv::new()?;
        // A socket with no rule would ask a question; without pentd it
        // gets the refusal at once (RN-8).
        env.block_pentd()?;
        // A path with `..` leaves the home directory; the parent must
        // exist before the run.
        std::fs::create_dir_all(&env.root)?;
        let targets = rule_targets(case, &env)?;
        let server = prepare(case, &env)?;
        let path = resolve(&env.home, &env.ws, case.target);
        let run = probe(&env, &targets, case.access, &path);
        drop(server);
        let run = run?;
        assert!(
            run.output.contains(RAN),
            "{}: the child did not run, so the row proves nothing:\n{}",
            case.id,
            run.output
        );
        Ok(run)
    }

    /// Write the rules `targets`, run the probe of `access` on `path`, and
    /// return what the kernel did.
    fn probe(
        env: &TestEnv,
        targets: &[String],
        access: Access,
        path: &Path,
    ) -> Result<Run, BoxError> {
        install(env, targets)?;
        let text = path.to_string_lossy().into_owned();
        let command: Vec<&str> = match access {
            Access::Read => vec!["sh", "-c", READ_PROBE, "p", &text],
            Access::Write => vec!["sh", "-c", WRITE_PROBE, "p", &text],
            Access::Execute => vec!["sh", "-c", EXEC_PROBE, "p", &text],
            Access::UnixSocket => vec!["python3", "-c", SOCKET_PROBE, &text],
        };
        let out = env.pent(&run_args(&[], &command))?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        let verdict = match access {
            Access::Read => yes_no(combined.contains(MARKER)),
            Access::Execute => yes_no(combined.contains(EXECUTED)),
            Access::UnixSocket => yes_no(combined.contains(GREETING)),
            // A write that the overlay discards is not a write. The host
            // file is the only honest answer.
            Access::Write => {
                let host = std::fs::read_to_string(path).unwrap_or_default();
                yes_no(host.contains(WROTE))
            }
        };
        Ok(Run {
            verdict,
            held_back: stderr(&out).contains(HELD_BACK),
            output: format!("rules {targets:?}\n{combined}"),
        })
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
            let want = rule_verdict(case);
            let run = kernel_verdict(case)?;
            if run.verdict != want {
                wrong.push(format!(
                    "  {}: the rules say {}, the kernel says {}\n{}",
                    case.id,
                    want.word(),
                    run.verdict.word(),
                    run.output
                ));
            }
            // A rule that pent does not apply makes a denial for the wrong
            // reason. Only a row of HELD_BACK_ROWS may have one, and each
            // row of it must have one.
            let want_held_back = HELD_BACK_ROWS.iter().any(|(id, _)| *id == case.id);
            if run.held_back != want_held_back {
                wrong.push(format!(
                    "  {}: pent {} that it does not apply a rule, and \
                     HELD_BACK_ROWS {} the row\n{}",
                    case.id,
                    if run.held_back { "said" } else { "did not say" },
                    if want_held_back {
                        "holds"
                    } else {
                        "does not hold"
                    },
                    run.output
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{test}: the rules and the kernel disagree on {} of {} rows:\n{}",
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
    /// a real `pent run` is the result that the rules state.
    #[test]
    fn the_rules_and_the_kernel_agree() -> TestResult {
        let test = "fs_rules_vs_kernel";
        if !ready(test) {
            return Ok(());
        }
        run_rows(test, &fs_closed())
    }

    /// Each row of [`HELD_BACK_ROWS`] names a row of the table.
    #[test]
    fn each_held_back_row_names_a_row() {
        for (id, _) in HELD_BACK_ROWS {
            assert!(
                FS_CASES.iter().any(|c| c.id == *id),
                "HELD_BACK_ROWS names {id:?}, and FS_CASES has no such row"
            );
        }
    }

    /// DIFF-2. A rule on a path that is a symbolic link must give access
    /// to the file. Before the fix it gave access to neither the link nor
    /// its target.
    #[test]
    fn diff_2_a_rule_that_names_a_symbolic_link() -> TestResult {
        let test = "fs_diff_2_symlink";
        if !ready(test) {
            return Ok(());
        }
        run_rows(
            test,
            &fs_rows(&[
                "symlink-the-named-link",
                "symlink-the-target-by-its-own-name",
            ]),
        )
    }

    /// DIFF-4. The kinds `read` and `exec` are different. A rule that
    /// gives read access must not let the program run the file.
    ///
    /// The rows of the table with this claim use `~/bin`, a location of
    /// the guard list, and `pent run` does not apply a subtree rule on it
    /// (see [`HELD_BACK_ROWS`]). This test uses the same rules on
    /// `~/tools`, which is not in the guard list. The rows of an `exec`
    /// rule and of a `write` rule are the positive controls.
    #[test]
    fn diff_4_a_read_rule_also_gives_execute() -> TestResult {
        let test = "fs_diff_4_read_gives_execute";
        if !ready(test) {
            return Ok(());
        }
        // The kind of the rule, the access, and the verdict of the rules.
        let cases = [
            ("read", Access::Execute, Verdict::Deny),
            ("read", Access::Read, Verdict::Allow),
            ("exec", Access::Execute, Verdict::Allow),
            ("exec", Access::Read, Verdict::Allow),
            ("exec", Access::Write, Verdict::Deny),
            ("write", Access::Execute, Verdict::Allow),
        ];
        let mut wrong = Vec::new();
        for (kind, access, want) in cases {
            let env = TestEnv::new()?;
            // A socket with no rule would ask a question; without pentd it
            // gets the refusal at once (RN-8).
            env.block_pentd()?;
            let dir = env.home.join("tools");
            let tool = dir.join("tool");
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&tool, file_body())?;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))?;
            let rule = format!("{kind} {}/**", path_text(&dir)?);
            let run = probe(&env, std::slice::from_ref(&rule), access, &tool)?;
            assert!(
                run.output.contains(RAN),
                "{rule}, {access:?}: the child did not run:\n{}",
                run.output
            );
            if run.verdict != want || run.held_back {
                wrong.push(format!(
                    "  {rule}, {access:?}: the rules say {}, the kernel says {}\n{}",
                    want.word(),
                    run.verdict.word(),
                    run.output
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{test}: the rules and the kernel disagree:\n{}",
            wrong.join("\n")
        );
        Ok(())
    }

    /// DIFF-3. A rule that gives read access must not let the program
    /// change what the other processes of the sandbox read.
    ///
    /// The overlay discards the write at the end of the run, so the file
    /// of the host does not change (the table holds that row). Before the
    /// fix the write succeeded inside the run, and every later read gave
    /// the new content.
    #[test]
    fn diff_3_a_write_to_a_read_only_rule_succeeds_in_the_run() -> TestResult {
        let test = "fs_diff_3_write_in_the_run";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        // A socket with no rule would ask a question; without pentd it
        // gets the refusal at once (RN-8).
        env.block_pentd()?;
        let dir = env.home.join("ro");
        install(&env, &[format!("read {}/**", path_text(&dir)?)])?;
        let file = dir.join("f.txt");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&file, format!("{MARKER}\n"))?;
        let script = format!(
            "printf '{RAN}\\n'\nprintf 'changed\\n' > \"$1\" 2>&1\nprintf 'rc=%s\\n' \"$?\"\ncat \"$1\" 2>&1\n"
        );
        let text = file.to_string_lossy().into_owned();
        let out = env.pent(&run_args(&[], &["sh", "-c", &script, "p", &text]))?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(combined.contains(RAN), "the child did not run:\n{combined}");
        // The positive control: the rule gives the read.
        assert!(
            combined.contains(MARKER) || combined.contains("changed"),
            "the read rule did not give the read, so this test proves \
             nothing:\n{combined}"
        );
        assert!(
            combined.contains("rc=1") || !combined.contains("changed"),
            "a read rule let the program change the file inside the run; \
             the next read of any process of the sandbox gives the new \
             content:\n{combined}"
        );
        Ok(())
    }

    /// The trace log of the last run of [`KEY`]. Each run with `--trace`
    /// makes a new log.
    fn trace_log(env: &TestEnv) -> String {
        std::fs::read_to_string(env.trace_log(KEY)).unwrap_or_default()
    }

    /// The list of `pent denials`: the refusals of each run since pentd
    /// started.
    fn denials(env: &TestEnv) -> Result<String, BoxError> {
        let out = env.pent(&["denials"])?;
        assert!(
            out.status.success(),
            "pent denials failed:\n{}{}",
            stdout(&out),
            stderr(&out)
        );
        Ok(stdout(&out))
    }

    /// Assert that the trace log `log` of one run and the list of
    /// `pent denials` both name `name`. `what` says what failed.
    fn assert_recorded(env: &TestEnv, log: &str, name: &str, what: &str) -> TestResult {
        let denials = denials(env)?;
        assert!(
            log.contains(name) && denials.contains(name),
            "{what}\n--- trace log ---\n{log}\n--- pent denials ---\n{denials}"
        );
        Ok(())
    }

    /// DIFF-1, second form. A program can test a path before it opens it
    /// and stop there: uutils `cat`, the `cat` of Ubuntu 26.04, calls
    /// `statx` and never `open` for a file that is not there. The test of
    /// the shell (`[ -e ]`) does the same with no `open`, so this test does
    /// not depend on the `cat` of the machine.
    #[test]
    fn diff_1_a_test_of_a_hidden_path_is_a_recorded_denial() -> TestResult {
        let test = "fs_diff_1_hidden_test";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let _pentd = Pentd::start(&env)?;
        let open = env.home.join("open.txt");
        install(&env, &[format!("read {}", path_text(&open)?)])?;
        std::fs::write(&open, format!("{MARKER}\n"))?;
        std::fs::write(env.home.join("secret.txt"), "SECRET\n")?;
        let hidden = env.home.join("secret.txt").to_string_lossy().into_owned();
        let out = env.pent(&run_args(
            &["--trace"],
            &[
                "sh",
                "-c",
                r#"printf 'PENT_CHILD_RAN\n'; [ -e "$1" ] && echo PRESENT || echo MISSING"#,
                "p",
                &hidden,
            ],
        ))?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(combined.contains(RAN), "the child did not run:\n{combined}");
        assert!(
            combined.contains("MISSING"),
            "the overlay did not hide the path, so this test proves nothing:\n{combined}"
        );
        assert_recorded(
            &env,
            &trace_log(&env),
            "secret.txt",
            &format!(
                "the program tested a hidden path and got ENOENT, but pent \
                 recorded no denial:\n{combined}"
            ),
        )
    }

    /// DIFF-1. The kernel must tell pent about every access that it
    /// blocks.
    ///
    /// `pent run --trace` records a Landlock denial in the trace log, and
    /// `pent denials` shows it. Before the fix pent recorded nothing when
    /// the overlay hid the path: the program got `ENOENT`, and the user
    /// never saw the access.
    #[test]
    fn diff_1_a_hidden_path_is_not_a_recorded_denial() -> TestResult {
        let test = "fs_diff_1_hidden_denial";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        let _pentd = Pentd::start(&env)?;
        let open = env.home.join("open.txt");
        install(&env, &[format!("read {}", path_text(&open)?)])?;
        std::fs::write(&open, format!("{MARKER}\n"))?;
        std::fs::write(env.home.join("secret.txt"), "SECRET\n")?;
        let hidden = env.home.join("secret.txt").to_string_lossy().into_owned();
        let out = env.pent(&run_args(
            &["--trace"],
            &["sh", "-c", READ_PROBE, "p", &hidden],
        ))?;
        let combined = format!("{}{}", stdout(&out), stderr(&out));
        assert!(combined.contains(RAN), "the child did not run:\n{combined}");
        let hidden_log = trace_log(&env);
        // The positive control: a path outside the home directory gives a
        // Landlock denial, and pent records it.
        let outside = env.root.join("outside.txt");
        std::fs::write(&outside, "SECRET\n")?;
        let outside = outside.to_string_lossy().into_owned();
        let control = env.pent(&run_args(
            &["--trace"],
            &["sh", "-c", READ_PROBE, "p", &outside],
        ))?;
        let control_text = format!("{}{}", stdout(&control), stderr(&control));
        assert_recorded(
            &env,
            &trace_log(&env),
            "outside.txt",
            &format!(
                "the positive control failed: pent did not record the \
                 Landlock denial, so this test proves nothing\n{control_text}"
            ),
        )?;
        assert_recorded(
            &env,
            &hidden_log,
            "secret.txt",
            &format!(
                "the overlay hid \"secret.txt\" and the program got ENOENT, \
                 but pent recorded no denial, so `pent denials` never shows \
                 the access:\n{combined}"
            ),
        )
    }

    /// Run the read probe on `path` with the rules `targets`. Return the
    /// verdict of the kernel and the output.
    fn read_with(
        env: &TestEnv,
        targets: &[String],
        path: &Path,
    ) -> Result<(Verdict, String), BoxError> {
        let run = probe(env, targets, Access::Read, path)?;
        assert!(
            run.output.contains(RAN),
            "the child did not run:\n{}",
            run.output
        );
        Ok((run.verdict, run.output))
    }

    /// A rule on the whole home directory covers the files of pent and
    /// the credentials, so `pent run` does not apply it and says so. The
    /// profile `read = ["~"]` gave the whole home directory; the rule
    /// gives nothing, and the kernel agrees.
    #[test]
    fn a_rule_on_the_whole_home_directory_is_not_applied() -> TestResult {
        let test = "fs_rule_on_the_home_directory";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        // A socket with no rule would ask a question; without pentd it
        // gets the refusal at once (RN-8).
        env.block_pentd()?;
        let file = env.home.join("data/one.txt");
        std::fs::create_dir_all(env.home.join("data"))?;
        std::fs::write(&file, format!("{MARKER}\n"))?;
        // The positive control: a rule on a directory of the home
        // directory gives the file.
        let data = format!("read {}/**", path_text(&env.home.join("data"))?);
        let (got, output) = read_with(&env, &[data], &file)?;
        assert_eq!(
            got,
            Verdict::Allow,
            "the positive control failed:\n{output}"
        );
        let home = format!("read {}/**", path_text(&env.home)?);
        let (got, output) = read_with(&env, &[home], &file)?;
        assert!(
            output.contains(HELD_BACK),
            "pent did not say that it does not apply the rule:\n{output}"
        );
        assert_eq!(
            got,
            Verdict::Deny,
            "pent said that it does not apply the rule, but the kernel gave \
             the file:\n{output}"
        );
        Ok(())
    }

    /// An exact rule on a path that is a directory gives nothing: Landlock
    /// would give the whole tree, and the rule names one path. The kernel
    /// must not give a child of the directory.
    #[test]
    fn an_exact_rule_on_a_directory_gives_no_child() -> TestResult {
        let test = "fs_exact_rule_on_a_directory";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        // A socket with no rule would ask a question; without pentd it
        // gets the refusal at once (RN-8).
        env.block_pentd()?;
        let dir = env.home.join("data");
        let file = dir.join("one.txt");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&file, format!("{MARKER}\n"))?;
        // The positive control: the subtree rule on the same directory
        // gives the child.
        let subtree = format!("read {}/**", path_text(&dir)?);
        let (got, output) = read_with(&env, &[subtree], &file)?;
        assert_eq!(
            got,
            Verdict::Allow,
            "the positive control failed:\n{output}"
        );
        let exact = format!("read {}", path_text(&dir)?);
        let (got, output) = read_with(&env, &[exact], &file)?;
        assert!(
            output.contains(HELD_BACK),
            "pent did not say that it does not apply the rule:\n{output}"
        );
        assert_eq!(
            got,
            Verdict::Deny,
            "an exact rule on a directory gave a child of the directory:\n{output}"
        );
        Ok(())
    }

    /// A deny rule inside the width of an allow rule wins: the kernel
    /// cannot make a hole in a grant, so pent does not apply the allow
    /// rule, and the denied path stays closed.
    #[test]
    fn a_deny_rule_inside_an_allow_rule_wins() -> TestResult {
        let test = "fs_deny_inside_an_allow";
        if !ready(test) {
            return Ok(());
        }
        let env = TestEnv::new()?;
        // A socket with no rule would ask a question; without pentd it
        // gets the refusal at once (RN-8).
        env.block_pentd()?;
        let dir = env.home.join("src");
        let secret = dir.join("secret/key.txt");
        std::fs::create_dir_all(dir.join("secret"))?;
        std::fs::write(&secret, format!("{MARKER}\n"))?;
        let allow = format!("read {}/**", path_text(&dir)?);
        let deny = format!("deny read {}/**", path_text(&dir.join("secret"))?);
        // The positive control: without the deny rule, the allow rule
        // gives the file.
        let (got, output) = read_with(&env, std::slice::from_ref(&allow), &secret)?;
        assert_eq!(
            got,
            Verdict::Allow,
            "the positive control failed:\n{output}"
        );
        let (got, output) = read_with(&env, &[allow, deny], &secret)?;
        assert!(
            output.contains(HELD_BACK),
            "pent did not say that it does not apply the allow rule:\n{output}"
        );
        assert_eq!(
            got,
            Verdict::Deny,
            "the rules deny the file, but the kernel gave it:\n{output}"
        );
        Ok(())
    }

    /// The table must stay a table: a row with an open disagreement needs
    /// its own ignored test, else the disagreement is silent.
    #[test]
    fn every_open_row_has_a_test() {
        let mut ids: Vec<&str> = FS_CASES.iter().filter_map(|c| c.open).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids,
            Vec::<&str>::new(),
            "a row of FS_CASES names a disagreement without an ignored test \
             in this file"
        );
    }
}
