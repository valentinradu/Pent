//! Helpers for the end-to-end tests that run the real `pent` binary.
//!
//! Each test makes its own [`TestEnv`]: a new directory below the
//! temporary directory of Cargo (`CARGO_TARGET_TMPDIR`), with a home
//! directory, the XDG directories in it, and a workspace. Pent always gives
//! access to `/tmp`, so the tests do not put their files there: a test of a
//! denial must use a path that the sandbox does not allow. The tests share
//! no global state, thus they can run in parallel.
//!
//! The tests find the tools (`sh`, `curl`, `getent`, ...) in `PATH`. When a
//! tool is missing, the test prints `SKIP` with the reason and passes.
//!
//! # `PENT_REQUIRE_ALL_TESTS`
//!
//! A test that skips proves nothing. Set `PENT_REQUIRE_ALL_TESTS=1` to make
//! each skip a failure. The continuous integration sets the variable, so a
//! test that stops working makes the build red. See [`skip`].

use std::io::{Read as _, Write as _};
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::PENT;

/// The error type of the helpers.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The result of a test.
pub type TestResult = Result<(), BoxError>;

/// The environment variables that the tests remove. A proxy setting of the
/// host must not change what the tests see.
const REMOVED_VARS: &[&str] = &[
    "PENT_LOG",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// Make a new session for the child, without a controlling terminal.
///
/// Pent asks its questions on `/dev/tty`. Without a terminal, pent does not
/// ask and never waits for an answer, also when `cargo test` runs in a
/// terminal.
fn detach_from_terminal(cmd: &mut Command) {
    // SAFETY: setsid() is async-signal-safe and has no memory-safety
    // preconditions. It runs in the child between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Remove the variables of [`REMOVED_VARS`] from `cmd`.
fn clean_env(cmd: &mut Command) -> &mut Command {
    for var in REMOVED_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// The name of the variable that makes each skip a failure.
pub const REQUIRE_ALL_TESTS: &str = "PENT_REQUIRE_ALL_TESTS";

/// Return true if the caller asks for all tests.
///
/// The value `0` and the empty value mean "no".
pub fn require_all_tests() -> bool {
    std::env::var_os(REQUIRE_ALL_TESTS).is_some_and(|v| !v.is_empty() && v != "0")
}

/// Print `SKIP <test>: <reason>` and return false.
///
/// With `PENT_REQUIRE_ALL_TESTS=1` the function fails the test instead. Use
/// it for each environment limit that the continuous integration must not
/// have: a missing sandbox, a missing tool, or a missing internet
/// connection.
///
/// # Panics
/// Fails the test when `PENT_REQUIRE_ALL_TESTS` is set.
#[track_caller]
pub fn skip(test: &str, reason: &str) -> bool {
    assert!(
        !require_all_tests(),
        "{REQUIRE_ALL_TESTS}=1 but {test} skips: {reason}. \
         The test must run here. Fix the environment, or remove the test."
    );
    eprintln!("SKIP {test}: {reason}");
    false
}

/// Print `SKIP (optional) <test>: <reason>` and return false.
///
/// Use it only for a program of another project (`claude`, `codex`,
/// `gemini`). A continuous integration runner cannot install them, so
/// `PENT_REQUIRE_ALL_TESTS` does not make this skip a failure. Never use it
/// for the sandbox, for a system tool, or for the network.
pub fn skip_optional(test: &str, reason: &str) -> bool {
    eprintln!("SKIP (optional) {test}: {reason}");
    false
}

/// Return true when pent can give the command its own PID namespace with
/// its own `/proc`. Else print the skip reason for `test` and return false.
///
/// A container runtime hides a part of `/proc` with its own mounts, and the
/// kernel then refuses a new `proc` mount (finding LS-3 in
/// `docs/security/linux-sandbox.md`). Pent runs the command there without
/// the PID namespace, and it says so. The protection is thus genuinely
/// absent in a container, and a test of it cannot hold.
///
/// `PENT_REQUIRE_ALL_TESTS` does not make this skip a failure: the
/// continuous integration runs the same tests in a container and outside
/// one, and the test must prove the protection outside one. Use this
/// function only for a test of the PID namespace or of the private `/proc`.
#[cfg(target_os = "linux")]
pub fn private_proc_ready(test: &str) -> bool {
    let isolation = pent_sandbox::proc_isolation();
    if isolation.is_private() {
        return true;
    }
    eprintln!(
        "SKIP (container) {test}: this host gives the command no private /proc, \
         so the protection is absent here: {}",
        isolation.warning_lines().join("; ")
    );
    false
}

/// The directories of one test.
pub struct TestEnv {
    _dir: TempDir,
    /// The root of the test. It contains `home` and `ws`. The sandbox does
    /// not give access to other paths in it.
    pub root: PathBuf,
    /// The value of `HOME`.
    pub home: PathBuf,
    /// The workspace: the current directory of pent.
    pub ws: PathBuf,
}

impl TestEnv {
    /// Make new empty directories for one test.
    ///
    /// # Errors
    /// Returns an error if a directory cannot be made.
    pub fn new() -> std::io::Result<Self> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("e2e");
        std::fs::create_dir_all(&base)?;
        let dir = tempfile::Builder::new().prefix("t-").tempdir_in(&base)?;
        // The sandbox resolves symbolic links, thus the tests use the
        // canonical paths.
        let root = dir.path().canonicalize()?;
        let home = root.join("home");
        let ws = root.join("ws");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&ws)?;
        Ok(Self {
            _dir: dir,
            root,
            home,
            ws,
        })
    }

    /// The value of `XDG_CONFIG_HOME`.
    pub fn config_dir(&self) -> PathBuf {
        self.home.join(".config")
    }

    /// The value of `XDG_STATE_HOME`.
    pub fn state_dir(&self) -> PathBuf {
        self.home.join(".local/state")
    }

    /// The draft file of `name`.
    pub fn draft_path(&self, name: &str) -> PathBuf {
        self.state_dir()
            .join("pent/drafts")
            .join(format!("{name}.toml"))
    }

    /// The profile file of `name`.
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.config_dir()
            .join("pent/profiles")
            .join(format!("{name}.toml"))
    }

    /// The list of the accesses that `pent run` denied for `name`.
    pub fn denied_log(&self, name: &str) -> PathBuf {
        self.state_dir()
            .join("pent/denied")
            .join(format!("{name}.jsonl"))
    }

    /// The trace log of `name` (`pent run --trace`).
    pub fn trace_log(&self, name: &str) -> PathBuf {
        self.state_dir()
            .join("pent/trace")
            .join(format!("{name}.log"))
    }

    /// The directory with the raw events of each watch run of `name`.
    pub fn watch_dir(&self, name: &str) -> PathBuf {
        self.state_dir().join("pent/watch").join(name)
    }

    /// The raw events of every watch run of `name`, as one text.
    ///
    /// Returns an empty string when the directory does not exist. Use it in
    /// the message of a failed assertion: it tells whether the recorder saw
    /// the access at all.
    pub fn watch_events(&self, name: &str) -> String {
        let Ok(entries) = std::fs::read_dir(self.watch_dir(name)) else {
            return String::new();
        };
        let mut files: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        files.sort();
        files
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect()
    }

    /// The path of `rel` in the home directory.
    pub fn home_path(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    /// Write `content` to `rel` in the home directory. Make the parent
    /// directories.
    ///
    /// # Errors
    /// Returns an error if the write fails.
    pub fn write_home(&self, rel: &str, content: &str) -> std::io::Result<PathBuf> {
        let path = self.home_path(rel);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, content)?;
        Ok(path)
    }

    /// A `pent` command with the environment of the test, without a
    /// terminal. The current directory is the workspace and stdin is empty.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut cmd = self.raw_command(args);
        cmd.stdin(Stdio::null());
        detach_from_terminal(&mut cmd);
        cmd
    }

    /// A `pent` command with the environment of the test. The caller sets
    /// the standard streams and the session.
    fn raw_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(PENT);
        clean_env(&mut cmd)
            .args(args)
            .current_dir(&self.ws)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.config_dir())
            .env("XDG_STATE_HOME", self.state_dir());
        cmd
    }

    /// Run `pent` with `args` and return its output.
    ///
    /// # Errors
    /// Returns an error if pent cannot start.
    pub fn pent(&self, args: &[&str]) -> std::io::Result<Output> {
        self.command(args).output()
    }

    /// Run `pent` with `args` and return its output. Fail when pent fails.
    ///
    /// # Errors
    /// Returns an error if pent cannot start or exits with an error.
    pub fn pent_ok(&self, args: &[&str]) -> Result<Output, BoxError> {
        let out = self.pent(args)?;
        if !out.status.success() {
            return Err(format!(
                "pent {} failed ({:?})\nstdout: {}\nstderr: {}",
                args.join(" "),
                out.status,
                stdout(&out),
                stderr(&out)
            )
            .into());
        }
        Ok(out)
    }

    /// Write `toml` as the draft of `name` and trust it with
    /// `pent trust NAME --yes`.
    ///
    /// # Errors
    /// Returns an error if a step fails.
    pub fn install_profile(&self, name: &str, toml: &str) -> TestResult {
        let path = self.draft_path(name);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, toml)?;
        self.pent_ok(&["trust", name, "--yes"])?;
        Ok(())
    }

    /// Start `pent` with `args` on a new pseudo-terminal.
    ///
    /// # Errors
    /// Returns an error if the terminal or the process cannot start.
    pub fn spawn_pty(&self, args: &[&str]) -> Result<Pty, BoxError> {
        Pty::spawn(self.raw_command(args))
    }
}

/// The string list `key` in the table `table` of a profile or a draft.
///
/// Returns an empty set when the table or the key is absent.
///
/// # Errors
/// Returns an error if the text is not valid TOML, or if the key is not a
/// list of strings.
pub fn rules(
    toml_text: &str,
    table: &str,
    key: &str,
) -> Result<std::collections::BTreeSet<String>, BoxError> {
    let doc: toml::Value = toml::from_str(toml_text)?;
    let Some(list) = doc.get(table).and_then(|t| t.get(key)) else {
        return Ok(std::collections::BTreeSet::new());
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
pub fn set(items: &[&str]) -> std::collections::BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

/// The text of stdout.
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The text of stderr.
pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Find the executable `name` in `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// Return true if all `tools` are in `PATH`. Else print the skip reason for
/// `test` and return false.
pub fn have_tools(test: &str, tools: &[&str]) -> bool {
    let missing: Vec<&str> = tools
        .iter()
        .copied()
        .filter(|t| which(t).is_none())
        .collect();
    if missing.is_empty() {
        return true;
    }
    skip(test, &format!("not in PATH: {}", missing.join(", ")))
}

/// The messages that a shell prints when the sandbox denies a write.
///
/// Landlock gives `EACCES` ("Permission denied"); Seatbelt gives `EPERM`
/// ("Operation not permitted").
const DENIAL_MESSAGES: &[&str] = &["Permission denied", "Operation not permitted"];

/// Return true if pent can make its sandbox on this host. Else print the
/// skip reason for `test` and return false.
///
/// The check runs one time for each test binary: `pent check`, then a run
/// that writes outside the workspace. When the file exists after the run,
/// the sandbox does not enforce its rules.
pub fn sandbox_ready(test: &str) -> bool {
    static READY: OnceLock<Result<(), String>> = OnceLock::new();
    let ready = READY.get_or_init(|| {
        let probe = || -> Result<Result<(), String>, BoxError> {
            if which("sh").is_none() {
                return Ok(Err("sh is not in PATH".to_string()));
            }
            let env = TestEnv::new()?;
            let out = env.pent(&["check"])?;
            if !out.status.success() {
                return Ok(Err(format!(
                    "pent check reports that the sandbox is not available:\n{}{}",
                    stdout(&out),
                    stderr(&out)
                )));
            }
            env.install_profile("probe", "")?;
            let outside = env.root.join("outside");
            let script = format!("echo probe > '{}'", outside.display());
            let out = env.pent(&["run", "--profile", "probe", "--", "sh", "-c", &script])?;
            if outside.exists() {
                return Ok(Err("the sandbox does not enforce its rules".to_string()));
            }
            let err = stderr(&out);
            if DENIAL_MESSAGES.iter().any(|m| err.contains(m)) {
                Ok(Ok(()))
            } else {
                Ok(Err(format!("the probe run did not get a denial:\n{err}")))
            }
        };
        probe().unwrap_or_else(|e| Err(format!("the probe failed: {e}")))
    });
    match ready {
        Ok(()) => true,
        Err(why) => skip(test, why),
    }
}

/// Return true if the host can reach `https://example.com` without pent.
/// Else print the skip reason for `test` and return false.
pub fn internet(test: &str) -> bool {
    static ONLINE: OnceLock<bool> = OnceLock::new();
    if !have_tools(test, &["curl"]) {
        return false;
    }
    let online = *ONLINE.get_or_init(|| {
        let mut cmd = Command::new("curl");
        clean_env(&mut cmd)
            .args([
                "-sS",
                "-o",
                "/dev/null",
                "--max-time",
                "10",
                "https://example.com",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });
    if !online {
        return skip(
            test,
            "curl https://example.com fails without pent (no internet)",
        );
    }
    true
}

/// Wait until `child` exits.
///
/// # Errors
/// Returns an error after `timeout`. The child is then killed.
pub fn wait_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus, BoxError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            // The kill can fail when the child exits now; the wait reaps it.
            let _ = child.kill();
            child.wait()?;
            return Err(format!("the process did not exit after {timeout:?}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Remove the terminal escape sequences and the carriage returns.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    // A CSI sequence ends with a letter or `~`.
                    for n in chars.by_ref() {
                        if n.is_ascii_alphabetic() || n == '~' {
                            break;
                        }
                    }
                } else {
                    chars.next();
                }
            }
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// A process on a pseudo-terminal, with a simple "expect" interface.
///
/// The terminal is the controlling terminal of the process, thus pent can
/// open `/dev/tty`. A thread copies the output of the terminal to a buffer.
pub struct Pty {
    master: std::fs::File,
    child: Child,
    output: Arc<Mutex<Vec<u8>>>,
    /// The end of the text that [`Pty::expect`] already matched.
    cursor: usize,
}

impl Pty {
    fn spawn(mut cmd: Command) -> Result<Self, BoxError> {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // SAFETY: the pointers point to valid c_int values. The name, the
        // termios and the window size are optional (null).
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(format!("openpty: {}", std::io::Error::last_os_error()).into());
        }
        // SAFETY: openpty returned two new file descriptors that nothing
        // else owns.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        cmd.stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?));
        // SAFETY: setsid() and ioctl(TIOCSCTTY) are async-signal-safe. They
        // run in the child between fork and exec. Stdin is the terminal at
        // that point, thus TIOCSCTTY makes it the controlling terminal.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        // Close the copy of the parent. The reader then gets EIO when the
        // last process on the terminal closes it.
        drop(slave);
        let master = std::fs::File::from(master);
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut reader = master.try_clone()?;
        let sink = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
                    break;
                };
                if let Ok(mut out) = sink.lock() {
                    out.extend_from_slice(chunk);
                }
            }
        });
        Ok(Self {
            master,
            child,
            output,
            cursor: 0,
        })
    }

    /// All output until now, without escape sequences.
    pub fn text(&self) -> String {
        let bytes = self.output.lock().map(|o| o.clone()).unwrap_or_default();
        strip_ansi(&String::from_utf8_lossy(&bytes))
    }

    /// Wait until the output after the last match has `needle`.
    ///
    /// # Errors
    /// Returns an error with the full output after `timeout`.
    pub fn expect(&mut self, needle: &str, timeout: Duration) -> TestResult {
        let deadline = Instant::now() + timeout;
        loop {
            let text = self.text();
            if let Some(found) = text.get(self.cursor..).and_then(|rest| rest.find(needle)) {
                self.cursor = self
                    .cursor
                    .saturating_add(found)
                    .saturating_add(needle.len());
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the terminal did not show {needle:?} after {timeout:?}\n--- output ---\n{text}"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Type `line` and Enter.
    ///
    /// # Errors
    /// Returns an error if the write fails.
    pub fn send_line(&mut self, line: &str) -> TestResult {
        self.master.write_all(format!("{line}\n").as_bytes())?;
        self.master.flush()?;
        Ok(())
    }

    /// Wait until the process exits. Return its status and the full output.
    ///
    /// # Errors
    /// Returns an error after `timeout`.
    pub fn wait(mut self, timeout: Duration) -> Result<(ExitStatus, String), BoxError> {
        let status = wait_timeout(&mut self.child, timeout)?;
        // The reader thread can be late: give it a short time.
        std::thread::sleep(Duration::from_millis(100));
        Ok((status, self.text()))
    }
}

/// The overlay staging directories of the pent process `pid`.
///
/// Pent puts them in `/tmp/pent-<uid>` or in `$XDG_RUNTIME_DIR/pent`, with
/// the name `ovl-<pid>-...`.
pub fn staging_dirs(pid: u32) -> Vec<PathBuf> {
    // SAFETY: getuid() has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut roots = vec![PathBuf::from(format!("/tmp/pent-{uid}"))];
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        roots.push(PathBuf::from(runtime).join("pent"));
    }
    let prefix = format!("ovl-{pid}-");
    roots
        .iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .map(|e| e.path())
        .collect()
}
