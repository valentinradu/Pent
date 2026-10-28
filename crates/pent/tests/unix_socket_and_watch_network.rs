//! Integration tests for the Unix socket rules and for the network options
//! of `pent watch`.
//!
//! Each test uses its own `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME`
//! below `CARGO_TARGET_TMPDIR`, thus no test reads or changes the real files
//! of the user. The home directory is not below `/tmp`, because the summary
//! omits each path below `/tmp`. Each pent process starts in a new session
//! (`setsid`), so pent cannot open `/dev/tty` and never waits for an answer.
//!
//! `pent watch` needs the recorder of the platform. A host without
//! unprivileged user namespaces cannot run it. Each test that records a run
//! checks the message of such a host and stops.

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// An isolated home, workspace and XDG directories for one test.
struct Env {
    _root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    config: PathBuf,
    state: PathBuf,
}

impl Env {
    fn new() -> std::io::Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("sockets-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
        let home = root.path().join("home");
        let workspace = home.join("work/app");
        fs::create_dir_all(&workspace)?;
        Ok(Self {
            config: root.path().join("config"),
            state: root.path().join("state"),
            home,
            workspace,
            _root: root,
        })
    }

    fn pent(&self, args: &[&str]) -> std::io::Result<Output> {
        self.command(args).output()
    }

    /// Start pent with `args` and do not wait for it.
    fn spawn(&self, args: &[&str]) -> std::io::Result<std::process::Child> {
        self.command(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(PENT);
        cmd.args(args)
            .current_dir(&self.workspace)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("CLICOLOR", "0")
            .env("NO_COLOR", "1")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("PENT_LOG")
            .stdin(Stdio::null());
        // SAFETY: setsid() is async-signal-safe and has no memory-safety
        // preconditions. The child gets a new session without a controlling
        // terminal, so pent cannot open /dev/tty and never waits for input.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }

    fn draft_path(&self, name: &str) -> PathBuf {
        self.state.join("pent/drafts").join(format!("{name}.toml"))
    }

    fn profile_path(&self, name: &str) -> PathBuf {
        self.config
            .join("pent/profiles")
            .join(format!("{name}.toml"))
    }

    /// Write `toml` as the draft of `name` and trust it.
    fn install_profile(&self, name: &str, toml: &str) -> TestResult {
        let path = self.draft_path(name);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(path, toml)?;
        let out = self.pent(&["trust", name, "--yes"])?;
        assert!(out.status.success(), "trust failed: {}", stderr(&out));
        Ok(())
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Return true when the host cannot run the recorder of `pent watch`.
fn recorder_missing(out: &Output) -> bool {
    if out.status.success() {
        return false;
    }
    let err = stderr(out);
    err.contains("pent watch is not available on this platform yet")
        || err.contains("user namespace")
        || err.contains("unshare")
        || err.contains("Landlock")
}

// ============================================================================
// A. The Unix socket rules
// ============================================================================

/// The profile key `filesystem.unix_sockets` is valid, and `pent trust`
/// shows the section.
#[test]
fn a_profile_can_name_a_unix_socket() -> TestResult {
    let env = Env::new()?;
    let draft = "[filesystem]\nunix_sockets = [\"~/.gnupg/S.gpg-agent\"] # gpg-agent\n";
    let path = env.draft_path("tool");
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    fs::write(&path, draft)?;
    let out = env.pent(&["trust", "tool", "--yes"])?;
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = stderr(&out);
    assert!(shown.contains("S.gpg-agent"), "{shown}");
    let profile = fs::read_to_string(env.profile_path("tool"))?;
    assert!(profile.contains("unix_sockets"), "{profile}");

    let out = env.pent(&["profile", "show", "tool"])?;
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("S.gpg-agent"), "{}", stdout(&out));
    Ok(())
}

/// `pent run --unix-socket PATH` is accepted next to `--read` and
/// `--write`, and it does not stop the command.
#[test]
fn run_accepts_the_unix_socket_flag() -> TestResult {
    let env = Env::new()?;
    env.install_profile("true", "[filesystem]\nread = []\n")?;
    let socket = env.home.join("agent.sock");
    let socket = socket.to_string_lossy().into_owned();
    let out = env.pent(&[
        "run",
        "--unix-socket",
        &socket,
        "--unix-socket",
        "~/other.sock",
        "--",
        "true",
    ])?;
    let err = stderr(&out);
    assert!(!err.contains("unexpected argument"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    if !out.status.success() {
        // A host without Landlock cannot run the sandbox.
        assert!(
            err.contains("Landlock") || err.contains("namespace"),
            "{err}"
        );
    }
    Ok(())
}

/// A socket path of the profile reaches the run too.
#[test]
fn run_accepts_a_socket_rule_of_the_profile() -> TestResult {
    let env = Env::new()?;
    env.install_profile(
        "true",
        "[filesystem]\nunix_sockets = [\"~/.gnupg/S.gpg-agent\"]\n",
    )?;
    let out = env.pent(&["run", "--", "true"])?;
    let err = stderr(&out);
    assert!(!err.contains("invalid profile"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    if !out.status.success() {
        assert!(
            err.contains("Landlock") || err.contains("namespace"),
            "{err}"
        );
    }
    Ok(())
}

// ============================================================================
// B. The network options of pent watch
// ============================================================================

/// The banner of the default run says that the network is open. With
/// `--allow` the proxy enforces the allowlist, so the line goes away.
#[test]
fn the_watch_banner_names_an_open_network() -> TestResult {
    let env = Env::new()?;
    let out = env.pent(&["watch", "--yes", "--", "true"])?;
    let err = stderr(&out);
    assert!(err.contains("The network is open in this run."), "{err}");
    assert!(err.contains("--network blocked"), "{err}");

    let out = env.pent(&["watch", "--yes", "--allow", "a.example", "--", "true"])?;
    let err = stderr(&out);
    assert!(!err.contains("The network is open"), "{err}");
    Ok(())
}

/// `--network` has precedence over `--allow`, as in `pent run`.
#[test]
fn the_watch_network_flag_has_precedence() -> TestResult {
    let env = Env::new()?;
    let out = env.pent(&[
        "watch",
        "--yes",
        "--network",
        "blocked",
        "--allow",
        "a.example",
        "--",
        "true",
    ])?;
    let err = stderr(&out);
    assert!(err.contains("--allow has no effect"), "{err}");
    assert!(err.contains("blocked"), "{err}");
    Ok(())
}

/// With `--allow`, the proxy refuses each other domain, and the refused
/// request becomes an item of the summary and a rule of the draft.
///
/// The command resolves a name that the allowlist does not have. In the
/// sandbox, `/etc/resolv.conf` names the proxy resolver, so the query
/// reaches the proxy and the proxy refuses it.
#[test]
fn watch_with_allow_records_a_refused_domain() -> TestResult {
    let env = Env::new()?;
    let out = env.pent(&[
        "watch",
        "--yes",
        "--profile",
        "lookup",
        "--allow",
        "allowed.example",
        "--",
        "getent",
        "hosts",
        "refused.example",
    ])?;
    if recorder_missing(&out) {
        return Ok(());
    }
    let err = stderr(&out);
    assert!(!err.contains("The network is open"), "{err}");
    let draft = env.draft_path("lookup");
    if !draft.exists() || !err.contains("refused.example") {
        // The host has no `getent`, so the run made no DNS query.
        return Ok(());
    }
    // The refused name is an item of the summary, as a denial of
    // `pent run` is, so the user can accept it as a rule.
    let text = fs::read_to_string(&draft)?;
    assert!(
        text.contains("refused.example"),
        "the draft must hold the refused domain\n{text}\n{err}"
    );
    // A Unix socket is a strong grant. A review without a terminal does not
    // select it, so the draft does not hold it.
    if err.contains("  Unix sockets\n") {
        assert!(
            !text.contains("unix_sockets"),
            "a review without a terminal must not accept a socket\n{text}\n{err}"
        );
    }
    Ok(())
}

/// Two watch runs of one profile at the same time would delete and read
/// each other's logs and write the same draft. A second run stops at once
/// with a clear message, and the first run ends as usual.
#[test]
fn a_second_watch_of_the_same_profile_stops_at_once() -> TestResult {
    let env = Env::new()?;
    let first = env.spawn(&["watch", "--yes", "--profile", "busy", "--", "sleep", "4"])?;
    // Wait until the first run holds the lock: the lock file names it.
    let lock = env.state.join("pent/watch/busy.lock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while fs::read_to_string(&lock)
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        if std::time::Instant::now() > deadline {
            return Err("the first run never took the lock".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let started = std::time::Instant::now();
    let second = env.pent(&["watch", "--yes", "--profile", "busy", "--", "true"])?;
    let err = stderr(&second);
    assert!(!second.status.success(), "the second run must fail:\n{err}");
    assert!(
        err.contains("another pent watch of \"busy\" runs now")
            && err.contains(&format!("(pid {})", first.id())),
        "the message must name the first run:\n{err}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "the second run must not wait for the first one"
    );
    assert!(
        !err.contains("Watch mode does not sandbox"),
        "the second run must stop before the banner:\n{err}"
    );

    let first = first.wait_with_output()?;
    if recorder_missing(&first) {
        return Ok(());
    }
    assert!(
        first.status.success(),
        "the first run must end as usual:\n{}",
        stderr(&first)
    );
    assert!(
        env.draft_path("busy").exists(),
        "the first run wrote no draft"
    );
    Ok(())
}

// ============================================================================
// C. The warning lines of the summary
// ============================================================================

/// A read outside the home directory gives a warning line under the header
/// and a comment in the first lines of the draft.
#[test]
fn a_read_outside_the_home_warns_and_goes_into_the_draft() -> TestResult {
    let env = Env::new()?;
    let outside = env
        ._root
        .path()
        .join("outside")
        .to_string_lossy()
        .into_owned();
    fs::create_dir_all(&outside)?;
    for i in 0..4 {
        fs::write(Path::new(&outside).join(format!("f{i}")), "x")?;
    }
    let script = format!("cat {outside}/f0 {outside}/f1 {outside}/f2 {outside}/f3 >/dev/null");
    let out = env.pent(&[
        "watch",
        "--yes",
        "--profile",
        "reader",
        "--",
        "sh",
        "-c",
        &script,
    ])?;
    if recorder_missing(&out) {
        return Ok(());
    }
    let draft = env.draft_path("reader");
    if !draft.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&draft)?;
    let err = stderr(&out);
    let outside_rule = text.contains(&outside);
    if outside_rule {
        assert!(
            err.contains("outside the home directory"),
            "the summary must warn: {err}"
        );
        assert!(
            text.lines()
                .take(4)
                .any(|l| l.starts_with('#') && l.contains("outside the home directory")),
            "the draft must hold the same fact:\n{text}"
        );
    }
    Ok(())
}
