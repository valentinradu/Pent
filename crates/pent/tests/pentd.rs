//! pentd: the three ways to start it, the lock, the holds and the socket.
//!
//! Each test has its own runtime directory, a short path in `/tmp`: the
//! path of a Unix socket has at most 107 bytes, and `CARGO_TARGET_TMPDIR`
//! can be longer. `PENTD_LINGER_MS` makes pentd stop soon after the last
//! hold.
//!
//! ```text
//! cargo test -p pent --test pentd
//! ```

mod common;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::e2e::{have_tools, internet, sandbox_ready, stderr, stdout, TestEnv, TestResult};
use common::PENT;

/// The linger time of each pentd in these tests.
const LINGER_MS: &str = "200";

/// The time limit for each wait.
const WAIT: Duration = Duration::from_secs(10);

/// One line of a hold.
const HOLD_LINE: &[u8] = b"{\"v\":1,\"msg\":{\"hold\":\"daemon\"}}\n";

/// A private runtime directory for one test, as `XDG_RUNTIME_DIR`.
struct Runtime {
    dir: tempfile::TempDir,
}

impl Runtime {
    fn new() -> std::io::Result<Self> {
        let dir = tempfile::Builder::new().prefix("pd").tempdir_in("/tmp")?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { dir })
    }

    fn xdg(&self) -> &Path {
        self.dir.path()
    }

    fn pent_dir(&self) -> PathBuf {
        self.dir.path().join("pent")
    }

    fn socket(&self) -> PathBuf {
        self.pent_dir().join("pentd.sock")
    }

    /// A `pent` command with this runtime directory.
    fn pent(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(PENT);
        cmd.args(args);
        self.apply(&mut cmd);
        cmd
    }

    /// Give `cmd` this runtime directory, the linger, and no stdio.
    fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("XDG_RUNTIME_DIR", self.xdg())
            .env("PENTD_LINGER_MS", LINGER_MS)
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
    }

    /// Return true when a connection to the socket works before the limit.
    fn wait_for_socket(&self) -> bool {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if UnixStream::connect(self.socket()).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Connect and send a hold.
    fn hold(&self) -> std::io::Result<UnixStream> {
        let mut stream = UnixStream::connect(self.socket())?;
        stream.write_all(HOLD_LINE)?;
        Ok(stream)
    }
}

/// Wait for the end of `child` until `limit`. Returns `None` when the child
/// still runs.
fn wait_exit(child: &mut Child, limit: Duration) -> std::io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send `signal` to `child`.
fn signal(child: &Child, signal: i32) -> std::io::Result<()> {
    let pid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    // SAFETY: `kill` takes two integers and has no memory effects.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Stop `child` at the end of a test, also when the test fails.
struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        // The child can be gone already; the error does not matter here.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_foreground_pentd_has_a_private_socket_and_stops_on_a_signal() -> TestResult {
    let rt = Runtime::new()?;
    let mut pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket(), "pentd never listened");

    let mode = |p: &Path| -> std::io::Result<u32> {
        Ok(std::fs::metadata(p)?.permissions().mode() & 0o777)
    };
    assert_eq!(mode(&rt.pent_dir())?, 0o700);
    assert_eq!(mode(&rt.socket())?, 0o600);
    assert_eq!(mode(&rt.pent_dir().join("pentd.lock"))?, 0o600);

    // A foreground pentd holds itself: it does not stop after the linger.
    std::thread::sleep(Duration::from_millis(600));
    assert!(pentd.0.try_wait()?.is_none(), "a foreground pentd stopped");

    signal(&pentd.0, libc::SIGTERM)?;
    let status = wait_exit(&mut pentd.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert!(!rt.socket().exists(), "pentd left its socket");
    Ok(())
}

#[test]
fn two_starts_at_the_same_time_give_one_pentd() -> TestResult {
    let rt = Runtime::new()?;
    let mut a = rt.pent(&["daemon"]);
    let mut b = rt.pent(&["daemon"]);
    a.stderr(Stdio::piped());
    b.stderr(Stdio::piped());
    let mut a = Reap(a.spawn()?);
    let mut b = Reap(b.spawn()?);
    assert!(rt.wait_for_socket(), "no pentd listened");

    // One of the two stops at once with an error; the other serves.
    let deadline = Instant::now() + WAIT;
    let (loser, winner) = loop {
        if a.0.try_wait()?.is_some() {
            break (&mut a, &mut b);
        }
        if b.0.try_wait()?.is_some() {
            break (&mut b, &mut a);
        }
        assert!(Instant::now() < deadline, "both pentd processes still run");
        std::thread::sleep(Duration::from_millis(20));
    };
    let status = loser.0.wait()?;
    assert!(!status.success(), "the second pentd must fail");
    let mut err = String::new();
    if let Some(mut stderr) = loser.0.stderr.take() {
        stderr.read_to_string(&mut err)?;
    }
    assert!(err.contains("pentd runs already (pid "), "{err}");
    assert!(winner.0.try_wait()?.is_none(), "the first pentd stopped");
    assert!(rt.hold().is_ok());
    Ok(())
}

#[test]
fn a_spawned_pentd_stops_after_the_last_hold() -> TestResult {
    let rt = Runtime::new()?;

    // With no hold at all, a spawned pentd stops after the linger.
    let mut alone = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let status = wait_exit(&mut alone.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");

    let mut pentd = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let first = loop {
        if let Ok(stream) = rt.hold() {
            break stream;
        }
        assert!(pentd.0.try_wait()?.is_none(), "pentd stopped before a hold");
        std::thread::sleep(Duration::from_millis(10));
    };
    let second = rt.hold()?;
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        pentd.0.try_wait()?.is_none(),
        "pentd stopped with two holds"
    );

    drop(first);
    std::thread::sleep(Duration::from_millis(600));
    assert!(pentd.0.try_wait()?.is_none(), "pentd stopped with one hold");

    drop(second);
    let status = wait_exit(&mut pentd.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert!(!rt.socket().exists(), "pentd left its socket");
    Ok(())
}

#[test]
fn a_crash_of_a_holder_ends_its_hold() -> TestResult {
    let rt = Runtime::new()?;
    let mut pentd = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let stream = loop {
        if let Ok(stream) = rt.hold() {
            break stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // The connection goes to a child process, as its stdin, and the test
    // drops its own copy. Thus only the child holds pentd.
    let mut holder = Reap(
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(stream)))
            .spawn()?,
    );
    std::thread::sleep(Duration::from_millis(600));
    assert!(pentd.0.try_wait()?.is_none(), "pentd stopped with a hold");

    signal(&holder.0, libc::SIGKILL)?;
    holder.0.wait()?;
    let status = wait_exit(&mut pentd.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    Ok(())
}

#[test]
fn two_spawned_starts_give_one_server_and_the_second_stops_in_silence() -> TestResult {
    let rt = Runtime::new()?;
    let mut a = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let _hold = loop {
        if let Ok(stream) = rt.hold() {
            break stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut b = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    // The second waits for the lock, then stops with success.
    let status = wait_exit(&mut b.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert!(a.0.try_wait()?.is_none(), "the first pentd stopped");
    assert!(rt.hold().is_ok(), "the first pentd does not serve");
    Ok(())
}

#[test]
fn a_stale_socket_of_a_killed_pentd_is_replaced() -> TestResult {
    let rt = Runtime::new()?;
    let mut first = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    signal(&first.0, libc::SIGKILL)?;
    first.0.wait()?;
    let meta = std::fs::symlink_metadata(rt.socket())?;
    assert!(meta.file_type().is_socket(), "the stale socket must stay");
    assert!(UnixStream::connect(rt.socket()).is_err());

    let _second = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket(), "the second pentd never listened");
    Ok(())
}

#[test]
fn a_file_at_the_socket_path_stops_pentd_and_stays() -> TestResult {
    let rt = Runtime::new()?;
    std::fs::create_dir(rt.pent_dir())?;
    std::fs::set_permissions(rt.pent_dir(), std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(rt.socket(), "keep")?;
    let out = rt.pent(&["daemon"]).stderr(Stdio::piped()).output()?;
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("is not a socket"), "{err}");
    assert_eq!(std::fs::read_to_string(rt.socket())?, "keep");
    Ok(())
}

#[test]
fn a_long_line_or_a_bad_line_closes_the_connection() -> TestResult {
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    for payload in [vec![b'a'; 70 * 1024], b"not json\n".to_vec()] {
        let mut stream = UnixStream::connect(rt.socket())?;
        stream.set_read_timeout(Some(WAIT))?;
        // pentd can close the connection before the whole payload arrives;
        // the read below is the check.
        let _ = stream.write_all(&payload);
        let mut buf = [0_u8; 16];
        let n = stream.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "pentd must close the connection");
    }
    // A good hold still works.
    let mut stream = rt.hold()?;
    stream.set_read_timeout(Some(Duration::from_millis(300)))?;
    let mut buf = [0_u8; 16];
    let read = stream.read(&mut buf);
    assert!(read.is_err(), "pentd closed a valid hold: {read:?}");
    Ok(())
}

#[test]
fn a_socket_from_systemd_is_served_and_kept() -> TestResult {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let rt = Runtime::new()?;
    std::fs::create_dir(rt.pent_dir())?;
    std::fs::set_permissions(rt.pent_dir(), std::fs::Permissions::from_mode(0o700))?;
    let listener = std::os::unix::net::UnixListener::bind(rt.socket())?;
    let fd = listener.as_raw_fd();

    // systemd sets LISTEN_PID to the PID of the service. `exec` in `sh`
    // keeps the PID, so `$$` is the PID of pentd.
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" daemon", PENT]);
    rt.apply(&mut cmd);
    // SAFETY: the hook runs in the child after the fork and calls only
    // `dup2` and `fcntl`, which are async-signal-safe. `fd` stays open in
    // the parent until the spawn returns.
    unsafe {
        cmd.pre_exec(move || {
            // When the listener is fd 3 already, `dup2` does nothing, and
            // the flag `FD_CLOEXEC` must go so the fd survives the exec.
            let rc = if fd == 3 {
                libc::fcntl(3, libc::F_SETFD, 0)
            } else {
                libc::dup2(fd, 3)
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut pentd = Reap(cmd.spawn()?);
    drop(listener);

    // The unit holds itself: no stop after the linger.
    std::thread::sleep(Duration::from_millis(600));
    assert!(pentd.0.try_wait()?.is_none(), "an activated pentd stopped");

    // pentd serves the socket: it closes the connection of a bad line.
    let mut stream = UnixStream::connect(rt.socket())?;
    stream.set_read_timeout(Some(WAIT))?;
    stream.write_all(b"not json\n")?;
    let mut buf = [0_u8; 16];
    assert_eq!(stream.read(&mut buf).unwrap_or(0), 0);

    signal(&pentd.0, libc::SIGTERM)?;
    let status = wait_exit(&mut pentd.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert!(rt.socket().exists(), "pentd removed the socket of systemd");
    Ok(())
}

#[test]
fn pent_run_starts_pentd_and_holds_it_for_the_run() -> TestResult {
    let test = "pent_run_starts_pentd_and_holds_it_for_the_run";
    if !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let env = TestEnv::new()?;
    let mut run = env.command(&["run", "--", "sh", "-c", "sleep 2"]);
    run.env("XDG_RUNTIME_DIR", rt.xdg())
        .env("PENTD_LINGER_MS", LINGER_MS)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut run = Reap(run.spawn()?);
    assert!(rt.wait_for_socket(), "pent run did not start pentd");
    // The run holds the same pentd longer than the linger. The client
    // starts a new pentd when it loses one, so the check uses the PID in
    // the lock file, not only the socket.
    let lock = rt.pent_dir().join("pentd.lock");
    let first = std::fs::read_to_string(&lock)?;
    std::thread::sleep(Duration::from_millis(800));
    assert!(
        UnixStream::connect(rt.socket()).is_ok(),
        "pentd stopped during the run"
    );
    assert_eq!(
        std::fs::read_to_string(&lock)?,
        first,
        "the first pentd stopped during the run"
    );
    let status = wait_exit(&mut run.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");

    // After the run, pentd stops and removes its socket.
    let deadline = Instant::now() + WAIT;
    while rt.socket().exists() {
        assert!(
            Instant::now() < deadline,
            "pentd did not stop after the run"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
fn the_program_cannot_see_the_socket_of_pentd() -> TestResult {
    let test = "the_program_cannot_see_the_socket_of_pentd";
    if !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let script = format!(
        "if [ -e '{sock}' ] || [ -e '{dir}' ]; then echo SEEN; else echo HIDDEN; fi",
        sock = rt.socket().display(),
        dir = rt.pent_dir().display()
    );
    let out = env
        .command(&["run", "--", "sh", "-c", &script])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .env("PENTD_LINGER_MS", LINGER_MS)
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // The positive control: the script ran in the sandbox.
    assert!(text.contains("HIDDEN"), "{text}");
    // The socket is there for the host, so the check means something.
    assert!(rt.socket().exists());
    Ok(())
}

/// A real `pent run` sends an event for each decision, and `pent denials`
/// shows each refusal with its cause: a rule, or the base when no rule
/// covers the access.
#[test]
fn pent_denials_shows_the_refusals_of_a_real_run() -> TestResult {
    let test = "pent_denials_shows_the_refusals_of_a_real_run";
    if !have_tools(test, &["sh", "cat", "getent"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    // A pentd in the foreground keeps the refusals after the run ends.
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    env.install_rules("sh", &["deny domain bad.example"])?;
    let outside = env.root.join("outside.txt");
    std::fs::write(&outside, "secret\n")?;
    let outside = outside.to_str().ok_or("the path is not UTF-8")?;
    // `--allow` starts the proxy. The rule refuses the name, so no query
    // goes upstream, and the test needs no network. `--trace` records the
    // refusal of Landlock, which no rule and no question decides: the
    // base. (A name with no rule asks a question since step 3.3.)
    let script = format!("cat '{outside}'; getent hosts bad.example; true");
    let out = env
        .command(&[
            "run",
            "--trace",
            "--allow",
            "good.example",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .output()?;
    assert!(out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("see them: pent denials"),
        "{}",
        stderr(&out)
    );
    let out = rt.pent(&["denials"]).stdout(Stdio::piped()).output()?;
    let text = stdout(&out);
    assert!(out.status.success(), "{out:?}");
    let line = |needle: &str| {
        text.lines()
            .find(|l| l.contains(needle))
            .map(str::to_string)
    };
    let read = line(&format!("read {outside}"))
        .ok_or_else(|| format!("no refusal of the read: {text}"))?;
    assert!(
        read.contains("by cat") && read.ends_with("(the base)"),
        "{read}"
    );
    let bad =
        line("domain bad.example").ok_or_else(|| format!("no refusal of bad.example: {text}"))?;
    assert!(bad.contains("by sh") && bad.ends_with("(a rule)"), "{bad}");
    assert!(line("domain good.example").is_none(), "{text}");
    Ok(())
}

/// A run with the proxy and no rule for a name: the program waits, `pent
/// questions` shows the question, and the answer decides the connection.
/// Returns the output of the run and the code of the question.
fn answer_a_proxy_question(
    rt: &Runtime,
    env: &TestEnv,
    url: &str,
    verb: &str,
) -> Result<(std::process::Output, String), common::e2e::BoxError> {
    let host = url
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let run = env
        .command(&[
            "run",
            "--key",
            "fetch",
            "--",
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "CODE=%{http_code}\n",
            url,
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let code = match question_code(rt, &host) {
        Ok(code) => code,
        Err(e) => {
            let mut run = run;
            // The test fails anyway; the kill only cleans up.
            let _ = run.kill();
            let _ = run.wait();
            return Err(e);
        }
    };
    let answer = rt.pent(&[verb, &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    // The run ends at the deadline of the proxy at the latest.
    Ok((run.wait_with_output()?, code))
}

/// The code of the open question for the domain `host`, as soon as pentd
/// has it.
fn question_code(rt: &Runtime, host: &str) -> Result<String, common::e2e::BoxError> {
    question_for(rt, &format!("domain {host}"))
}

/// The code of the open question whose request has the text `request`
/// (as `localhost 5432`), as soon as pentd has it.
fn question_for(rt: &Runtime, request: &str) -> Result<String, common::e2e::BoxError> {
    let deadline = Instant::now() + WAIT;
    loop {
        let out = rt
            .pent(&["questions", "--json"])
            .stdout(Stdio::piped())
            .output()?;
        let found = stdout(&out).lines().find_map(|line| {
            let question: pent_profile::Question = serde_json::from_str(line).ok()?;
            (question.ask.request.to_string() == request).then(|| question.id.to_string())
        });
        if let Some(code) = found {
            return Ok(code);
        }
        if Instant::now() >= deadline {
            return Err(format!("no question for {request}").into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A real question through the proxy: a "deny" refuses the connection at
/// once, long before the deadline of 20 s, and `pent denials` names the
/// answer. The test needs no network: the refused name never resolves.
#[test]
fn a_proxy_question_waits_for_a_deny() -> TestResult {
    let test = "a_proxy_question_waits_for_a_deny";
    if !have_tools(test, &["curl"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let begin = Instant::now();
    let (out, code) = answer_a_proxy_question(&rt, &env, "https://asked.example/", "deny")?;
    let took = begin.elapsed();
    assert!(
        took < pent_profile::PROXY_DEADLINE,
        "the run waited for the deadline: {took:?}"
    );
    assert!(stdout(&out).contains("CODE=000"), "{out:?}");
    let denials = rt.pent(&["denials"]).stdout(Stdio::piped()).output()?;
    let text = stdout(&denials);
    assert!(
        text.lines().any(|l| l.contains("domain asked.example")
            && l.ends_with(&format!("(the answer to question {code})"))),
        "{text}"
    );
    Ok(())
}

/// A real question through the proxy: an "allow" lets the connection go
/// through, and the program gets its page.
#[test]
fn a_proxy_question_waits_for_an_allow() -> TestResult {
    let test = "a_proxy_question_waits_for_an_allow";
    if !have_tools(test, &["curl"]) || !sandbox_ready(test) || !internet(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let (out, _code) = answer_a_proxy_question(&rt, &env, "https://example.com/", "allow")?;
    assert!(stdout(&out).contains("CODE=200"), "{out:?}");
    // An answer with the scope "run" writes no rule.
    assert!(!env.rules_path("fetch").exists());
    Ok(())
}

/// Start a run of `script` with no rule for the key `dns`, and give it the
/// runtime directory of `rt`.
fn spawn_dns_run(rt: &Runtime, env: &TestEnv, script: &str) -> std::io::Result<Child> {
    env.command(&["run", "--key", "dns", "--", "sh", "-c", script])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// A DNS query with no rule waits for the question. A "deny" gives
/// `REFUSED` at once, so the program learns that the name is refused, not
/// that it does not exist, and `pent denials` names the answer. The test
/// needs no network: the refused name never goes upstream.
#[test]
fn a_dns_question_waits_for_a_deny() -> TestResult {
    let test = "a_dns_question_waits_for_a_deny";
    if !have_tools(test, &["sh", "getent"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let begin = Instant::now();
    let run = spawn_dns_run(&rt, &env, "getent hosts asked.example; echo RC=$?")?;
    let code = question_code(&rt, "asked.example")?;
    let answer = rt.pent(&["deny", &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    let out = run.wait_with_output()?;
    let took = begin.elapsed();
    // getent exits with 2 when the name has no address.
    assert!(stdout(&out).contains("RC=2"), "{out:?}");
    // A deny ends the wait; the deadline of DNS is 4 s for each try.
    assert!(took < Duration::from_secs(4), "the run took {took:?}");
    let denials = rt.pent(&["denials"]).stdout(Stdio::piped()).output()?;
    let text = stdout(&denials);
    assert!(
        text.lines().any(|l| l.contains("domain asked.example")
            && l.ends_with(&format!("(the answer to question {code})"))),
        "{text}"
    );
    Ok(())
}

/// The human answers after the deadline of DNS. The program got SERVFAIL
/// and tries again, and the next try gets the answer with no new question:
/// the question that stayed open got the answer.
#[test]
fn a_late_dns_answer_applies_to_the_next_try() -> TestResult {
    let test = "a_late_dns_answer_applies_to_the_next_try";
    if !have_tools(test, &["sh", "getent"]) || !sandbox_ready(test) || !internet(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let script = "i=0; while [ $i -lt 30 ]; do \
                  if getent hosts example.com > /dev/null; then echo RESOLVED=$i; exit 0; fi; \
                  i=$((i+1)); sleep 1; done; echo NEVER";
    let run = spawn_dns_run(&rt, &env, script)?;
    let code = question_code(&rt, "example.com")?;
    // Wait past the deadline of DNS, so the first try ends with SERVFAIL.
    std::thread::sleep(pent_profile::DNS_DEADLINE + Duration::from_secs(1));
    let answer = rt.pent(&["allow", &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    let out = run.wait_with_output()?;
    assert!(stdout(&out).contains("RESOLVED="), "{out:?}");
    // A try before the answer got SERVFAIL at the deadline: the refusal
    // names the deadline of the same question. (glibc tries again after
    // SERVFAIL, so the answer can reach the first call of getent.)
    let denials = rt.pent(&["denials"]).stdout(Stdio::piped()).output()?;
    let text = stdout(&denials);
    assert!(
        text.lines().any(|l| l.contains("domain example.com")
            && l.ends_with(&format!("(the deadline of question {code})"))),
        "{text}"
    );
    let left = rt
        .pent(&["questions", "--json"])
        .stdout(Stdio::piped())
        .output()?;
    assert_eq!(stdout(&left), "", "a new question stayed open");
    Ok(())
}

/// A server on the host that sends `HELLO` to each client, on a Unix
/// socket at `path` or on a TCP port of the loopback.
enum HostServer {
    Unix(std::os::unix::net::UnixListener),
    Tcp(std::net::TcpListener),
}

impl HostServer {
    /// Serve each client in a thread, until the test ends.
    fn serve(self) {
        std::thread::spawn(move || loop {
            let sent = match &self {
                Self::Unix(l) => l.accept().and_then(|(mut c, _)| c.write_all(b"HELLO")),
                Self::Tcp(l) => l.accept().and_then(|(mut c, _)| c.write_all(b"HELLO")),
            };
            if sent.is_err() {
                return;
            }
        });
    }
}

/// The program of the socket tests: it connects to `$1` (a path, or a port
/// of 127.0.0.1) and prints what it gets, or the name of its error.
const SOCKET_PROBE: &str = r#"
import socket, sys
target = sys.argv[1]
try:
    if target.isdigit():
        s = socket.create_connection(("127.0.0.1", int(target)), timeout=200)
    else:
        s = socket.socket(socket.AF_UNIX)
        s.connect(target)
    print("GOT", s.recv(5).decode())
except OSError as e:
    print("ERR", type(e).__name__)
"#;

/// Run the probe for `target` with no rule, answer its question
/// `request` with `verb`, and return the output and the code of the
/// question.
fn answer_a_socket_question(
    rt: &Runtime,
    env: &TestEnv,
    target: &str,
    request: &str,
    verb: &str,
) -> Result<(std::process::Output, String), common::e2e::BoxError> {
    let run = env
        .command(&[
            "run",
            "--key",
            "probe",
            "--",
            "python3",
            "-c",
            SOCKET_PROBE,
            target,
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let code = match question_for(rt, request) {
        Ok(code) => code,
        Err(e) => {
            let mut run = run;
            // The test fails anyway; the kill only cleans up.
            let _ = run.kill();
            let _ = run.wait();
            return Err(e);
        }
    };
    let answer = rt.pent(&[verb, &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    Ok((run.wait_with_output()?, code))
}

/// A Unix socket off the list asks. An "allow" gives the connection that
/// the supervisor makes on the host; a "deny" gives `EACCES`, and `pent
/// denials` names the answer and the program.
#[test]
fn a_unix_socket_question_decides_the_connection() -> TestResult {
    let test = "a_unix_socket_question_decides_the_connection";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let path = env.root.join("service.sock");
    HostServer::Unix(std::os::unix::net::UnixListener::bind(&path)?).serve();
    let target = path.to_str().ok_or("the path is not UTF-8")?;
    let request = format!("unix-socket {target}");

    let (out, _) = answer_a_socket_question(&rt, &env, target, &request, "allow")?;
    assert!(stdout(&out).contains("GOT HELLO"), "{out:?}");

    let (out, code) = answer_a_socket_question(&rt, &env, target, &request, "deny")?;
    assert!(stdout(&out).contains("ERR PermissionError"), "{out:?}");
    let denials = rt.pent(&["denials"]).stdout(Stdio::piped()).output()?;
    let text = stdout(&denials);
    assert!(
        text.lines().any(|l| l.contains(&request)
            && l.contains("by python3")
            && l.ends_with(&format!("(the answer to question {code})"))),
        "{text}"
    );
    Ok(())
}

/// A port of the host off the list asks. An "allow" connects on the
/// host; a "deny" gives `ECONNREFUSED`.
#[test]
fn a_port_question_decides_the_connection() -> TestResult {
    let test = "a_port_question_decides_the_connection";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port().to_string();
    HostServer::Tcp(listener).serve();
    let request = format!("localhost {port}");

    let (out, _) = answer_a_socket_question(&rt, &env, &port, &request, "allow")?;
    assert!(stdout(&out).contains("GOT HELLO"), "{out:?}");

    let (out, _) = answer_a_socket_question(&rt, &env, &port, &request, "deny")?;
    assert!(
        stdout(&out).contains("ERR ConnectionRefusedError"),
        "{out:?}"
    );
    Ok(())
}

/// A port that nothing serves on the host asks no question: the program
/// gets `ECONNREFUSED` at once, as without pent.
#[test]
fn a_port_that_the_host_does_not_serve_asks_no_question() -> TestResult {
    let test = "a_port_that_the_host_does_not_serve_asks_no_question";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let free = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let begin = Instant::now();
    let out = env
        .command(&[
            "run",
            "--key",
            "probe",
            "--",
            "python3",
            "-c",
            SOCKET_PROBE,
            &free.to_string(),
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .output()?;
    assert!(
        stdout(&out).contains("ERR ConnectionRefusedError"),
        "{out:?}"
    );
    assert!(begin.elapsed() < Duration::from_secs(10), "the run waited");
    let open = rt
        .pent(&["questions", "--json"])
        .stdout(Stdio::piped())
        .output()?;
    assert_eq!(stdout(&open), "", "a question opened");
    Ok(())
}

/// A rule decides a socket with no question, also for the path as the
/// program writes it: a deny rule on a link refuses at once, and the event
/// names the form that the rule names. After an "allow", a second
/// connection of the same run asks no new question.
#[test]
fn a_known_decision_of_a_socket_asks_no_question() -> TestResult {
    let test = "a_known_decision_of_a_socket_asks_no_question";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let path = env.root.join("service.sock");
    HostServer::Unix(std::os::unix::net::UnixListener::bind(&path)?).serve();
    let link = env.root.join("link.sock");
    std::os::unix::fs::symlink(&path, &link)?;
    let target = path.to_str().ok_or("the path is not UTF-8")?;
    let link = link.to_str().ok_or("the path is not UTF-8")?;
    env.install_rules("probe", &[&format!("deny unix-socket {link}")])?;
    let begin = Instant::now();
    let out = env
        .command(&[
            "run",
            "--key",
            "probe",
            "--",
            "python3",
            "-c",
            SOCKET_PROBE,
            link,
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .output()?;
    assert!(stdout(&out).contains("ERR PermissionError"), "{out:?}");
    assert!(begin.elapsed() < Duration::from_secs(10), "the run waited");
    let denials = rt.pent(&["denials"]).stdout(Stdio::piped()).output()?;
    let text = stdout(&denials);
    assert!(
        text.lines()
            .any(|l| l.contains(&format!("unix-socket {link}")) && l.ends_with("(a rule)")),
        "{text}"
    );

    // Two connections in one run: one question, one answer.
    std::fs::remove_file(env.rules_path("probe"))?;
    let twice = format!(
        "import socket\nfor _ in range(2):\n    s = socket.socket(socket.AF_UNIX)\n    \
         s.connect({target:?})\n    print('GOT', s.recv(5).decode())\n"
    );
    let run = env
        .command(&["run", "--key", "probe", "--", "python3", "-c", &twice])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let code = question_for(&rt, &format!("unix-socket {target}"))?;
    let answer = rt.pent(&["allow", &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    let out = run.wait_with_output()?;
    assert_eq!(stdout(&out).matches("GOT HELLO").count(), 2, "{out:?}");
    let open = rt
        .pent(&["questions", "--json"])
        .stdout(Stdio::piped())
        .output()?;
    assert_eq!(stdout(&open), "", "the second connection asked again");
    Ok(())
}

/// An allow rule for the path that the program wrote does not open the
/// socket that the path reaches: the program controls the link. The
/// connection asks for the canonical target, and a "deny" refuses it.
#[test]
fn an_allow_of_a_link_does_not_open_its_target() -> TestResult {
    let test = "an_allow_of_a_link_does_not_open_its_target";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let path = env.root.join("service.sock");
    HostServer::Unix(std::os::unix::net::UnixListener::bind(&path)?).serve();
    let target = path.to_str().ok_or("the path is not UTF-8")?;
    // The rule names a path in the workspace that does not exist at the
    // start. The program makes it a link to the socket of the host.
    let link = env.ws.join("app.sock");
    let link = link.to_str().ok_or("the path is not UTF-8")?;
    env.install_rules("probe", &[&format!("unix-socket {link}")])?;
    let script = format!(
        "import os, socket\nos.symlink({target:?}, {link:?})\ntry:\n    \
         s = socket.socket(socket.AF_UNIX)\n    s.connect({link:?})\n    \
         print('GOT', s.recv(5).decode())\nexcept OSError as e:\n    \
         print('ERR', type(e).__name__)\n"
    );
    let run = env
        .command(&["run", "--key", "probe", "--", "python3", "-c", &script])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let code = match question_for(&rt, &format!("unix-socket {target}")) {
        Ok(code) => code,
        Err(e) => {
            let out = run.wait_with_output()?;
            return Err(format!("{e}; the run gave {out:?}").into());
        }
    };
    let answer = rt.pent(&["deny", &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    let out = run.wait_with_output()?;
    assert!(stdout(&out).contains("ERR PermissionError"), "{out:?}");
    Ok(())
}

/// `--network blocked` refuses a Unix socket, a port and a name off the
/// lists with no question.
#[test]
fn network_blocked_asks_no_question_for_a_socket() -> TestResult {
    let test = "network_blocked_asks_no_question_for_a_socket";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let path = env.root.join("service.sock");
    HostServer::Unix(std::os::unix::net::UnixListener::bind(&path)?).serve();
    let target = path.to_str().ok_or("the path is not UTF-8")?;
    let begin = Instant::now();
    let out = env
        .command(&[
            "run",
            "--network",
            "blocked",
            "--key",
            "probe",
            "--",
            "python3",
            "-c",
            SOCKET_PROBE,
            target,
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .output()?;
    assert!(stdout(&out).contains("ERR PermissionError"), "{out:?}");
    // `blocked` starts no proxy and no DNS server: a name gets no
    // question either.
    let out = env
        .command(&[
            "run",
            "--network",
            "blocked",
            "--key",
            "probe",
            "--",
            "sh",
            "-c",
            "getent hosts asked.example; echo RC=$?",
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .output()?;
    assert!(stdout(&out).contains("RC=2"), "{out:?}");
    assert!(begin.elapsed() < Duration::from_secs(10), "the run waited");
    let open = rt
        .pent(&["questions", "--json"])
        .stdout(Stdio::piped())
        .output()?;
    assert_eq!(stdout(&open), "", "a question opened");
    Ok(())
}

/// A question does not stop the other calls: while one thread of the
/// program waits for the question of a socket, another thread connects to
/// a socket that a rule allows and finishes.
#[test]
fn a_question_does_not_stop_the_other_connections() -> TestResult {
    let test = "a_question_does_not_stop_the_other_connections";
    if !have_tools(test, &["python3"]) || !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    let _pentd = Reap(rt.pent(&["daemon"]).spawn()?);
    assert!(rt.wait_for_socket());
    let env = TestEnv::new()?;
    let asked = env.root.join("asked.sock");
    let listed = env.root.join("listed.sock");
    HostServer::Unix(std::os::unix::net::UnixListener::bind(&asked)?).serve();
    HostServer::Unix(std::os::unix::net::UnixListener::bind(&listed)?).serve();
    let asked = asked.to_str().ok_or("the path is not UTF-8")?;
    let listed = listed.to_str().ok_or("the path is not UTF-8")?;
    env.install_rules("probe", &[&format!("unix-socket {listed}")])?;
    let marker = env.ws.join("second-done");
    let script = r#"
import socket, sys, threading, time
def first():
    try:
        s = socket.socket(socket.AF_UNIX)
        s.connect(sys.argv[1])
    except OSError:
        pass
t = threading.Thread(target=first)
t.start()
time.sleep(0.5)
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[2])
if s.recv(5) == b"HELLO":
    open("second-done", "w").close()
t.join()
"#;
    let run = env
        .command(&[
            "run", "--key", "probe", "--", "python3", "-c", script, asked, listed,
        ])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut run = Reap(run);
    let code = question_for(&rt, &format!("unix-socket {asked}"))?;
    // The second connection finishes while the question is open.
    let deadline = Instant::now() + WAIT;
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "the second connection waited for the question"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let open = rt.pent(&["questions"]).stdout(Stdio::piped()).output()?;
    assert!(
        stdout(&open).contains(&code),
        "the question is not open any more"
    );
    let answer = rt.pent(&["deny", &code]).output()?;
    assert!(answer.status.success(), "{answer:?}");
    let status = wait_exit(&mut run.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    Ok(())
}

#[test]
fn pentd_does_not_remove_a_socket_that_another_process_put_at_its_path() -> TestResult {
    let rt = Runtime::new()?;
    let mut pentd = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let hold = loop {
        if let Ok(stream) = rt.hold() {
            break stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Another process (for example systemd) takes the path.
    std::fs::remove_file(rt.socket())?;
    let other = std::os::unix::net::UnixListener::bind(rt.socket())?;
    drop(hold);
    let status = wait_exit(&mut pentd.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert!(
        rt.socket().exists(),
        "pentd removed the socket of another process"
    );
    assert!(UnixStream::connect(rt.socket()).is_ok());
    drop(other);
    Ok(())
}

/// A socket where another process listens, as systemd does with
/// `pentd.socket` before its pentd starts.
fn foreign_listener(rt: &Runtime) -> std::io::Result<std::os::unix::net::UnixListener> {
    std::fs::create_dir_all(rt.pent_dir())?;
    std::fs::set_permissions(rt.pent_dir(), std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::net::UnixListener::bind(rt.socket())
}

#[test]
fn pentd_does_not_take_a_socket_where_another_process_listens() -> TestResult {
    let rt = Runtime::new()?;
    let listener = foreign_listener(&rt)?;
    listener.set_nonblocking(true)?;

    let mut foreground = Reap(rt.pent(&["daemon"]).stderr(Stdio::piped()).spawn()?);
    let status = wait_exit(&mut foreground.0, WAIT)?;
    assert!(
        status.is_some_and(|s| !s.success()),
        "pent daemon must fail at once, not serve: {status:?}"
    );
    let mut err = String::new();
    if let Some(mut stderr) = foreground.0.stderr.take() {
        stderr.read_to_string(&mut err)?;
    }
    assert!(err.contains("another process listens on"), "{err}");

    // A spawned pentd stops in silence: the other process serves.
    let mut spawned = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let status = wait_exit(&mut spawned.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");

    // The socket is still the one of the other process.
    let _client = UnixStream::connect(rt.socket())?;
    std::thread::sleep(Duration::from_millis(50));
    let mut got = false;
    while listener.accept().is_ok() {
        got = true;
    }
    assert!(got, "the socket of the other process does not work");
    Ok(())
}

#[test]
fn an_activated_pentd_waits_for_the_lock_of_a_pentd_that_stops() -> TestResult {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let rt = Runtime::new()?;
    let mut spawned = Reap(rt.pent(&["daemon", "--spawned"]).spawn()?);
    let hold = loop {
        if let Ok(stream) = rt.hold() {
            break stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // systemd takes the path while the spawned pentd serves.
    std::fs::remove_file(rt.socket())?;
    let listener = std::os::unix::net::UnixListener::bind(rt.socket())?;
    let fd = listener.as_raw_fd();
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" daemon", PENT]);
    rt.apply(&mut cmd);
    // SAFETY: the hook runs in the child after the fork and calls only
    // `dup2` and `fcntl`, which are async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let rc = if fd == 3 {
                libc::fcntl(3, libc::F_SETFD, 0)
            } else {
                libc::dup2(fd, 3)
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut activated = Reap(cmd.spawn()?);
    drop(listener);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        activated.0.try_wait()?.is_none(),
        "the activated pentd must wait for the lock"
    );

    // The spawned pentd stops, and the activated pentd takes the lock.
    drop(hold);
    let status = wait_exit(&mut spawned.0, WAIT)?;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        activated.0.try_wait()?.is_none(),
        "the activated pentd stopped"
    );
    let mut stream = UnixStream::connect(rt.socket())?;
    stream.set_read_timeout(Some(WAIT))?;
    stream.write_all(b"not json\n")?;
    let mut buf = [0_u8; 16];
    assert_eq!(
        stream.read(&mut buf).unwrap_or(0),
        0,
        "the activated pentd does not serve"
    );
    Ok(())
}

#[test]
fn pent_run_does_not_wait_for_a_pentd_that_cannot_start() -> TestResult {
    let test = "pent_run_does_not_wait_for_a_pentd_that_cannot_start";
    if !sandbox_ready(test) {
        return Ok(());
    }
    let rt = Runtime::new()?;
    std::fs::create_dir(rt.pent_dir())?;
    std::fs::set_permissions(rt.pent_dir(), std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(rt.socket(), "not a socket")?;
    let env = TestEnv::new()?;
    let begin = Instant::now();
    let out = env
        .command(&["run", "--", "sh", "-c", "exit 0"])
        .env("XDG_RUNTIME_DIR", rt.xdg())
        .output()?;
    let took = begin.elapsed();
    assert!(out.status.success(), "{out:?}");
    // The client gives up when the pentd that it started stops. The limit
    // of the wait is 3 s, so a run below 2 s did not wait for it.
    assert!(took < Duration::from_secs(2), "the run took {took:?}");
    Ok(())
}

#[test]
fn pentd_does_not_spin_at_the_limit_of_file_descriptors() -> TestResult {
    let rt = Runtime::new()?;
    // A small limit of file descriptors: the runtime and the listener use
    // a few, and the connections below use the rest.
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "ulimit -n 24 && exec \"$0\" daemon", PENT]);
    rt.apply(&mut cmd);
    let pentd = Reap(cmd.spawn()?);
    assert!(rt.wait_for_socket(), "pentd never listened");
    let clients: Vec<UnixStream> = (0..40)
        .filter_map(|_| UnixStream::connect(rt.socket()).ok())
        .collect();
    assert!(
        clients.len() > 24,
        "the test needs more connections than fds"
    );

    // The CPU time of pentd in one second. A loop that spins on the error
    // of `accept(2)` uses nearly all of it.
    let ticks = |pid: u32| -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let after = stat.rsplit_once(')').ok_or("bad stat")?.1;
        let fields: Vec<&str> = after.split_whitespace().collect();
        let utime: u64 = fields.get(11).ok_or("no utime")?.parse()?;
        let stime: u64 = fields.get(12).ok_or("no stime")?.parse()?;
        Ok(utime + stime)
    };
    std::thread::sleep(Duration::from_millis(200));
    let before = ticks(pentd.0.id())?;
    std::thread::sleep(Duration::from_secs(1));
    let used = ticks(pentd.0.id())? - before;
    // SAFETY: sysconf has no preconditions.
    let per_second = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })?;
    assert!(
        used < per_second / 4,
        "pentd used {used} of {per_second} ticks in one second"
    );
    drop(clients);
    Ok(())
}

// ── The queue ───────────────────────────────────────────────────────────────

mod queue {
    use std::io::{BufRead as _, BufReader};
    use std::num::NonZeroU16;
    use std::os::unix::net::UnixStream;

    use pent_profile::{
        Answer, Ask, Class, Deadline, Decision, FileKind, Hold, MenuIndex, Message, PathWidth,
        QuestionId, RejectReason, Rejected, Request, RulePath, Scope, SessionId, Source, Target,
        Timestamp, FILE_DEADLINE,
    };

    use super::*;

    /// A client of pentd that speaks lines.
    pub(super) struct Client {
        write: UnixStream,
        read: BufReader<UnixStream>,
    }

    impl Client {
        pub(super) fn connect(rt: &Runtime) -> std::io::Result<Self> {
            let write = UnixStream::connect(rt.socket())?;
            write.set_read_timeout(Some(WAIT))?;
            let read = BufReader::new(write.try_clone()?);
            Ok(Self { write, read })
        }

        pub(super) fn send(&mut self, message: Message) -> TestResult {
            self.write.write_all(message.encode_line()?.as_bytes())?;
            Ok(())
        }

        /// The next message, without the messages of the event stream of
        /// a watcher (`Session`, `Event`, `EventsDropped`): these tests
        /// check the questions and the verdicts, and the tests of the hub
        /// check the stream.
        pub(super) fn recv(&mut self) -> Result<Message, common::e2e::BoxError> {
            loop {
                let message = self.recv_any()?;
                if !matches!(
                    message,
                    Message::Session(_) | Message::Event(_) | Message::EventsDropped(_)
                ) {
                    return Ok(message);
                }
            }
        }

        /// The next message.
        pub(super) fn recv_any(&mut self) -> Result<Message, common::e2e::BoxError> {
            let mut line = String::new();
            if self.read.read_line(&mut line)? == 0 {
                return Err("pentd closed the connection".into());
            }
            Ok(Message::decode_line(&line)?)
        }

        /// A session of `pent run` with the key `key`.
        pub(super) fn session(rt: &Runtime, key: &str) -> Result<Self, common::e2e::BoxError> {
            let mut client = Self::connect(rt)?;
            client.send(Message::Hold(Hold::Run {
                key: key.parse()?,
                command: vec![key.to_string()],
            }))?;
            Ok(client)
        }

        /// Ask `ask` and return the number that pentd gives it.
        pub(super) fn ask(&mut self, ask: Ask) -> Result<QuestionId, common::e2e::BoxError> {
            self.send(Message::Ask(ask))?;
            match self.recv()? {
                Message::Question(q) => Ok(q.id),
                other => Err(format!("pentd sent {other:?} in place of a number").into()),
            }
        }
    }

    pub(super) fn port_ask(port: u16) -> Result<Ask, common::e2e::BoxError> {
        let port = NonZeroU16::new(port).ok_or("port 0")?;
        Ok(Ask {
            // pentd replaces these two values.
            session: SessionId(77),
            key: "ignored".parse()?,
            program: "psql".into(),
            request: Request::Localhost(port),
            class: Class::Normal,
            menu: vec![Target::Localhost(port)],
            asked: Timestamp(0),
            deadline: Deadline::new(FILE_DEADLINE)?,
        })
    }

    pub(super) fn read_ask(path: &str, parent: &str) -> Result<Ask, common::e2e::BoxError> {
        let rp = RulePath::new(path)?;
        Ok(Ask {
            request: Request::File {
                kind: FileKind::Read,
                path: rp.clone(),
            },
            menu: vec![
                Target::File {
                    kind: FileKind::Read,
                    width: PathWidth::Exact(rp),
                },
                Target::File {
                    kind: FileKind::Read,
                    width: PathWidth::Subtree(RulePath::new(parent)?),
                },
            ],
            ..port_ask(1)?
        })
    }

    fn answer(id: QuestionId, width: u16, scope: Scope) -> Answer {
        Answer {
            id,
            decision: Decision::Allow,
            width: MenuIndex(width),
            scope,
            source: Source::Human,
        }
    }

    /// A pentd in the foreground with its own state directory.
    pub(super) fn pentd(rt: &Runtime, state: &Path, args: &[&str]) -> std::io::Result<Reap> {
        let mut cmd = rt.pent(args);
        cmd.env("XDG_STATE_HOME", state).env("HOME", state);
        Ok(Reap(cmd.spawn()?))
    }

    #[test]
    fn an_answer_reaches_the_session_the_watcher_and_the_rule_file() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());

        let mut session = Client::session(&rt, "cargo")?;
        session.send(Message::Ask(port_ask(5432)?))?;
        let question = match session.recv()? {
            Message::Question(q) => q,
            other => return Err(format!("{other:?}").into()),
        };
        // pentd gives the key of the session, not the key of the ask.
        assert_eq!(question.ask.key.as_str(), "cargo");

        let mut watcher = Client::connect(&rt)?;
        watcher.send(Message::Watch)?;
        assert!(matches!(watcher.recv()?, Message::Question(q) if q.id == question.id));

        let mut answerer = Client::connect(&rt)?;
        answerer.send(Message::Answer(answer(question.id, 0, Scope::Remember)))?;
        for client in [&mut answerer, &mut session, &mut watcher] {
            match client.recv()? {
                Message::Verdict(v) => {
                    assert_eq!(v.id, question.id);
                    assert_eq!(v.decision, Decision::Allow);
                    assert_eq!(v.target, question.ask.menu[0]);
                }
                other => return Err(format!("{other:?}").into()),
            }
        }

        // pentd wrote the rule.
        let file = state.path().join("pent/rules/cargo.toml");
        let deadline = Instant::now() + WAIT;
        while !file.exists() {
            assert!(Instant::now() < deadline, "pentd wrote no rule");
            std::thread::sleep(Duration::from_millis(20));
        }
        let text = std::fs::read_to_string(&file)?;
        assert!(text.contains("kind = \"localhost\""), "{text}");
        assert!(text.contains("port = 5432"), "{text}");
        assert!(text.contains("decision = \"allow\""), "{text}");
        Ok(())
    }

    #[test]
    fn pentd_refuses_a_bad_answer_and_a_message_of_the_wrong_role() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut session = Client::session(&rt, "cargo")?;
        let id = session.ask(port_ask(5432)?)?;

        let rejected =
            |client: &mut Client, message: Message| -> Result<Rejected, common::e2e::BoxError> {
                client.send(message)?;
                match client.recv()? {
                    Message::Rejected(r) => Ok(r),
                    other => Err(format!("pentd sent {other:?}").into()),
                }
            };
        // A session cannot answer, also its own question.
        let r = rejected(&mut session, Message::Answer(answer(id, 0, Scope::Run)))?;
        assert_eq!(r.reason, RejectReason::NotPermitted);

        // A session cannot watch the questions of other runs.
        let r = rejected(&mut session, Message::Watch)?;
        assert_eq!(r.reason, RejectReason::NotPermitted);

        // A hold is only the first message: a watcher never becomes a
        // session, so it cannot ask, and it gets no verdict of its own.
        let mut watcher = Client::connect(&rt)?;
        watcher.send(Message::Watch)?;
        assert!(matches!(watcher.recv()?, Message::Question(q) if q.id == id));
        let hold = Message::Hold(Hold::Run {
            key: "cargo".parse()?,
            command: vec![],
        });
        let r = rejected(&mut watcher, hold)?;
        assert_eq!(r.reason, RejectReason::NotPermitted);
        let r = rejected(&mut watcher, Message::Ask(port_ask(81)?))?;
        assert_eq!(r.reason, RejectReason::NotPermitted);

        let mut client = Client::connect(&rt)?;
        let r = rejected(&mut client, Message::Ask(port_ask(80)?))?;
        assert_eq!(r.reason, RejectReason::NotPermitted);
        let r = rejected(
            &mut client,
            Message::Answer(answer(QuestionId(999), 0, Scope::Run)),
        )?;
        assert_eq!(r.reason, RejectReason::UnknownQuestion);
        let r = rejected(&mut client, Message::Answer(answer(id, 1, Scope::Run)))?;
        assert_eq!(r.reason, RejectReason::BadWidth);
        let mut model = answer(id, 0, Scope::Remember);
        model.source = Source::Model;
        let r = rejected(&mut client, Message::Answer(model))?;
        assert_eq!(r.reason, RejectReason::NotHuman);

        // The question is still open, and pentd wrote no rule.
        client.send(Message::Answer(answer(id, 0, Scope::Run)))?;
        assert!(matches!(client.recv()?, Message::Verdict(v) if v.id == id));
        assert!(!state.path().join("pent/rules/cargo.toml").exists());
        Ok(())
    }

    #[test]
    fn one_wide_answer_resolves_each_question_inside_its_width() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut session = Client::session(&rt, "cargo")?;
        let a = session.ask(read_ask("/home/u/reg/a", "/home/u/reg")?)?;
        let b = session.ask(read_ask("/home/u/reg/b", "/home/u/reg")?)?;
        let c = session.ask(read_ask("/home/u/other/c", "/home/u/other")?)?;
        let mut client = Client::connect(&rt)?;
        client.send(Message::Answer(answer(a, 1, Scope::Run)))?;
        let mut got = Vec::new();
        for _ in 0..2 {
            match session.recv()? {
                Message::Verdict(v) => got.push(v.id),
                other => return Err(format!("{other:?}").into()),
            }
        }
        // The verdicts come in the order of the asks.
        assert_eq!(got, vec![a, b]);
        // `c` is still open: an answer to it works.
        client.send(Message::Answer(answer(c, 0, Scope::Run)))?;
        let mut ids = Vec::new();
        for _ in 0..3 {
            if let Message::Verdict(v) = client.recv()? {
                ids.push(v.id);
            }
        }
        assert_eq!(ids, vec![a, b, c]);
        Ok(())
    }

    #[test]
    fn a_late_answer_becomes_a_rule_and_the_open_question_keeps_pentd_alive() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let mut pentd = pentd(&rt, state.path(), &["daemon", "--spawned"])?;
        let mut session = loop {
            if let Ok(client) = Client::session(&rt, "psql") {
                break client;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let id = session.ask(port_ask(5432)?)?;
        // The run ends before an answer; the deadline passed in `pent run`.
        drop(session);
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            pentd.0.try_wait()?.is_none(),
            "the open question must keep pentd alive"
        );

        let mut client = Client::connect(&rt)?;
        client.send(Message::Answer(answer(id, 0, Scope::Remember)))?;
        assert!(matches!(client.recv()?, Message::Verdict(v) if v.id == id));
        drop(client);
        let file = state.path().join("pent/rules/psql.toml");
        let text = std::fs::read_to_string(&file)?;
        assert!(text.contains("port = 5432"), "{text}");

        // With no hold and no open question, pentd stops.
        let status = wait_exit(&mut pentd.0, WAIT)?;
        assert!(status.is_some_and(|s| s.success()), "{status:?}");
        Ok(())
    }

    #[test]
    fn a_question_too_long_for_one_line_is_refused_and_the_numbers_stay_true() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        // The longest key: pentd puts it in the question.
        let mut session = Client::session(&rt, &"k".repeat(64))?;

        // An ask just below the limit: its question is longer, because
        // pentd adds the number and the key.
        let mut long = port_ask(5432)?;
        long.key = "x".parse()?;
        let base = Message::Ask(long.clone()).encode_line()?.len();
        long.program = "a".repeat(pent_profile::MAX_LINE_LEN - 10 - base);
        assert!(Message::Ask(long.clone()).encode_line().is_ok());
        session.send(Message::Ask(long))?;
        match session.recv()? {
            Message::Rejected(r) => {
                assert_eq!(r.id, None);
                assert_eq!(r.reason, RejectReason::TooLong);
            }
            other => return Err(format!("{other:?}").into()),
        }
        // The next ask gets its own number, and its answer reaches it.
        let id = session.ask(port_ask(80)?)?;
        let mut client = Client::connect(&rt)?;
        client.send(Message::Answer(answer(id, 0, Scope::Run)))?;
        assert!(matches!(session.recv()?, Message::Verdict(v) if v.id == id));
        Ok(())
    }

    #[test]
    fn a_rule_that_pentd_cannot_write_gives_a_verdict_for_this_run_and_an_error() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        // The user broke the rule file by hand.
        let rules = state.path().join("pent/rules");
        std::fs::create_dir_all(&rules)?;
        std::fs::write(rules.join("cargo.toml"), "this is not toml [")?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut session = Client::session(&rt, "cargo")?;
        let id = session.ask(read_ask("/home/u/reg/a", "/home/u/reg")?)?;
        // Another run of the same key waits inside the width.
        let mut other = Client::session(&rt, "cargo")?;
        let other_id = other.ask(read_ask("/home/u/reg/b", "/home/u/reg")?)?;
        let mut client = Client::connect(&rt)?;
        client.send(Message::Answer(answer(id, 1, Scope::Remember)))?;
        // The error comes before the verdicts, so a client that waits for
        // one verdict sees it.
        match client.recv()? {
            Message::Rejected(r) => {
                assert_eq!(r.id, Some(id));
                assert_eq!(r.reason, RejectReason::RuleNotKept);
            }
            other => return Err(format!("{other:?}").into()),
        }
        match client.recv()? {
            Message::Verdict(v) => assert_eq!(v.scope, Scope::Run),
            other => return Err(format!("{other:?}").into()),
        }
        match session.recv()? {
            Message::Verdict(v) => assert_eq!(v.scope, Scope::Run),
            other => return Err(format!("{other:?}").into()),
        }
        assert_eq!(
            std::fs::read_to_string(rules.join("cargo.toml"))?,
            "this is not toml ["
        );
        // The answer holds only for the run of the question, as `run`
        // does: the other run still waits, and its question is open.
        other
            .write
            .set_read_timeout(Some(Duration::from_millis(500)))?;
        assert!(other.recv().is_err(), "the other run got a verdict");
        client.send(Message::Answer(answer(other_id, 0, Scope::Run)))?;
        assert!(matches!(client.recv()?, Message::Verdict(v) if v.id == other_id));
        Ok(())
    }

    #[test]
    fn a_watcher_that_closes_its_side_gets_the_end_of_the_connection() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut watcher = Client::connect(&rt)?;
        watcher.send(Message::Watch)?;
        watcher.write.shutdown(std::net::Shutdown::Write)?;
        // At once, not after the drain limit of the writer (5 s): the end of
        // the connection removes the watcher, so the writer ends.
        watcher
            .write
            .set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut line = String::new();
        let n = watcher.read.read_line(&mut line)?;
        assert_eq!(n, 0, "pentd must end the connection: {line}");
        Ok(())
    }

    #[test]
    fn pentd_closes_a_watcher_that_does_not_read() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut watcher = Client::connect(&rt)?;
        watcher.send(Message::Watch)?;
        // Far more questions than the buffers of the socket and the outbox
        // hold, in six runs, because one run has at most 1024 open
        // questions. The watcher reads nothing meanwhile.
        let mut sessions = Vec::new();
        for run in 0..6_u16 {
            let mut session = Client::session(&rt, "cargo")?;
            for port in 1..=1000_u16 {
                session.ask(port_ask(run * 1000 + port)?)?;
            }
            sessions.push(session);
        }
        let mut session = sessions.pop().ok_or("no session")?;
        // pentd closed the watcher: a read of all that waits ends with the
        // end of the connection, not with the time limit.
        let mut seen = 0_usize;
        let mut line = String::new();
        loop {
            line.clear();
            match watcher.read.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => seen += 1,
                Err(e) => return Err(format!("no end after {seen} lines: {e}").into()),
            }
        }
        assert!(seen < 6000, "pentd sent all {seen} lines");
        // The session still works.
        let id = session.ask(port_ask(6001)?)?;
        let mut client = Client::connect(&rt)?;
        client.send(Message::Answer(answer(id, 0, Scope::Run)))?;
        assert!(matches!(session.recv()?, Message::Verdict(v) if v.id == id));
        Ok(())
    }

    #[test]
    fn a_watcher_that_answers_gets_one_verdict_and_a_second_watch_changes_nothing() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut monitor = Client::connect(&rt)?;
        monitor.send(Message::Watch)?;
        monitor.send(Message::Watch)?;
        let mut session = Client::session(&rt, "cargo")?;
        let id = session.ask(port_ask(5432)?)?;
        // One copy of the question, then one copy of the verdict.
        assert!(matches!(monitor.recv()?, Message::Question(q) if q.id == id));
        monitor.send(Message::Answer(answer(id, 0, Scope::Run)))?;
        assert!(matches!(monitor.recv()?, Message::Verdict(v) if v.id == id));
        monitor
            .write
            .set_read_timeout(Some(Duration::from_millis(500)))?;
        match monitor.recv() {
            Err(_) => Ok(()),
            Ok(extra) => Err(format!("a second copy: {extra:?}").into()),
        }
    }

    #[test]
    fn a_new_connection_keeps_pentd_alive_before_its_first_message() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let mut pentd = pentd(&rt, state.path(), &["daemon", "--spawned"])?;
        let mut client = loop {
            if let Ok(client) = Client::connect(&rt) {
                break client;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // Silent for longer than the linger time.
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            pentd.0.try_wait()?.is_none(),
            "pentd stopped under a live connection"
        );
        client.send(Message::Hold(Hold::Run {
            key: "cargo".parse()?,
            command: vec![],
        }))?;
        let id = client.ask(port_ask(80)?)?;
        let mut answerer = Client::connect(&rt)?;
        answerer.send(Message::Answer(answer(id, 0, Scope::Run)))?;
        assert!(matches!(client.recv()?, Message::Verdict(v) if v.id == id));
        Ok(())
    }
}

// ── The clients of the CLI ──────────────────────────────────────────────────

mod clients {
    use std::process::Output;

    use pent_profile::{
        DecidedBy, Decision, Event, FileKind, Message, PathWidth, Question, RejectReason, Request,
        RulePath, SessionId, Target, Timestamp,
    };

    use super::queue::{pentd, port_ask, read_ask, Client};
    use super::*;

    /// Run `pent ARGS` with the runtime directory of `rt` and the state
    /// directory `state`, and return its output.
    fn pent(rt: &Runtime, state: &Path, args: &[&str]) -> std::io::Result<Output> {
        rt.pent(args)
            .env("XDG_STATE_HOME", state)
            .env("HOME", state)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Return the output of a command that must succeed.
    fn ok(output: &Output) -> Result<(String, String), common::e2e::BoxError> {
        let (out, err) = (text(&output.stdout), text(&output.stderr));
        if !output.status.success() {
            return Err(format!("{:?}\nstdout: {out}\nstderr: {err}", output.status).into());
        }
        Ok((out, err))
    }

    /// Return stderr of a command that must fail.
    fn fails(output: &Output) -> Result<String, common::e2e::BoxError> {
        let err = text(&output.stderr);
        if output.status.success() {
            return Err(format!("the command succeeded: {err}").into());
        }
        Ok(err)
    }

    /// A pentd in the foreground, ready for connections.
    fn ready(rt: &Runtime, state: &Path) -> Result<Reap, common::e2e::BoxError> {
        let pentd = pentd(rt, state, &["daemon"])?;
        if !rt.wait_for_socket() {
            return Err("pentd never listened".into());
        }
        Ok(pentd)
    }

    #[test]
    fn pent_questions_and_pent_allow_answer_with_a_width_and_a_rule() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        let mut session = Client::session(&rt, "cargo")?;
        let id = session.ask(read_ask("/home/u/reg/a", "/home/u/reg")?)?;

        let (out, _) = ok(&pent(&rt, state.path(), &["questions"])?)?;
        assert!(
            out.starts_with(&format!("{id}  cargo  read /home/u/reg/a\n")),
            "{out}"
        );
        assert!(
            out.contains("    --width 1  read /home/u/reg/**\n"),
            "{out}"
        );
        let (json, _) = ok(&pent(&rt, state.path(), &["questions", "--json"])?)?;
        let question: Question = serde_json::from_str(json.trim())?;
        assert_eq!(question.id, id);

        let number = id.to_string();
        let args = ["allow", number.as_str(), "--width", "1", "--remember"];
        let (_, err) = ok(&pent(&rt, state.path(), &args)?)?;
        assert!(
            err.contains("allow read /home/u/reg/** (remembered)"),
            "{err}"
        );
        match session.recv()? {
            Message::Verdict(v) => {
                assert_eq!(v.id, id);
                assert_eq!(v.decision, Decision::Allow);
                assert_eq!(
                    v.target,
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Subtree(RulePath::new("/home/u/reg")?),
                    }
                );
            }
            other => return Err(format!("{other:?}").into()),
        }

        let (out, _) = ok(&pent(&rt, state.path(), &["rules", "list"])?)?;
        assert_eq!(out, format!("{:<24} 1 rule\n", "cargo"));
        let (out, _) = ok(&pent(&rt, state.path(), &["rules", "show", "cargo"])?)?;
        assert!(
            out.starts_with("  1  allow  read /home/u/reg/**  human  "),
            "{out}"
        );
        let (_, err) = ok(&pent(&rt, state.path(), &["questions"])?)?;
        assert!(err.contains("none"), "{err}");
        Ok(())
    }

    #[test]
    fn pent_deny_with_a_bad_width_fails_and_the_question_stays() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        let mut session = Client::session(&rt, "psql")?;
        let id = session.ask(port_ask(5432)?)?;
        let number = id.to_string();

        let err = fails(&pent(
            &rt,
            state.path(),
            &["deny", &number, "--width", "5"],
        )?)?;
        assert!(err.contains("the width is not in the menu"), "{err}");
        let err = fails(&pent(&rt, state.path(), &["allow", "zzzzzz"])?)?;
        assert!(err.contains("no open question has this code"), "{err}");
        // A number of the old form is not a code.
        let err = fails(&pent(&rt, state.path(), &["allow", "7"])?)?;
        assert!(err.contains("7 is not a code of pent"), "{err}");

        let (_, err) = ok(&pent(&rt, state.path(), &["deny", &number])?)?;
        assert!(err.contains("deny localhost 5432 (this run)"), "{err}");
        assert!(
            matches!(session.recv()?, Message::Verdict(v) if v.id == id && v.decision == Decision::Deny)
        );
        // The scope `run` writes no rule.
        assert!(!state.path().join("pent/rules/psql.toml").exists());
        Ok(())
    }

    fn event(time: i64, request: Request, decided_by: DecidedBy) -> Message {
        Message::Event(Event {
            // A false number: pentd puts the number of the session.
            session: SessionId(42),
            time: Timestamp(time),
            program: "node".into(),
            request,
            decided_by,
        })
    }

    #[test]
    fn pent_denials_shows_the_refusals_of_each_session() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        let domain = |name: &str| -> Result<Request, common::e2e::BoxError> {
            Ok(Request::Domain(name.parse()?))
        };
        let mut first = Client::session(&rt, "npm")?;
        first.send(event(
            1,
            domain("evil.example")?,
            DecidedBy::Rule(Decision::Deny),
        ))?;
        first.send(event(
            2,
            domain("ok.example")?,
            DecidedBy::Rule(Decision::Allow),
        ))?;
        // An ask after the events: pentd has the events when it numbers it.
        let first_q = first.ask(port_ask(1)?)?;
        let mut second = Client::session(&rt, "cargo")?;
        second.send(event(3, domain("x.example")?, DecidedBy::Hidden))?;
        second.ask(port_ask(2)?)?;
        let first_session = {
            let mut c = Client::connect(&rt)?;
            c.send(Message::Questions)?;
            match c.recv()? {
                Message::Question(q) if q.id == first_q => q.ask.session,
                other => return Err(format!("{other:?}").into()),
            }
        };

        let (out, _) = ok(&pent(&rt, state.path(), &["denials"])?)?;
        assert!(out.contains("  npm\n"), "{out}");
        assert!(
            out.contains("domain evil.example  by node  (a rule)"),
            "{out}"
        );
        assert!(
            !out.contains("ok.example"),
            "an allow is not a refusal: {out}"
        );
        assert!(out.contains("  cargo\n"), "{out}");
        assert!(
            out.contains("domain x.example  by node  (a file of pent (ENOENT))"),
            "{out}"
        );

        let number = first_session.to_string();
        let (out, _) = ok(&pent(&rt, state.path(), &["denials", &number])?)?;
        assert!(
            out.starts_with(&format!("session {number}  npm\n")),
            "{out}"
        );
        assert!(!out.contains("x.example"), "{out}");

        let err = fails(&pent(&rt, state.path(), &["denials", "zzzzzz"])?)?;
        assert!(err.contains("knows no session"), "{err}");
        Ok(())
    }

    #[test]
    fn only_a_session_sends_events_and_a_session_cannot_read_or_forget() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        let rejected = |client: &mut Client,
                        message: Message|
         -> Result<RejectReason, common::e2e::BoxError> {
            client.send(message)?;
            match client.recv()? {
                Message::Rejected(r) => Ok(r.reason),
                other => Err(format!("pentd sent {other:?}").into()),
            }
        };
        let mut client = Client::connect(&rt)?;
        let fake = event(
            1,
            Request::Localhost(std::num::NonZeroU16::MIN),
            DecidedBy::Hidden,
        );
        assert_eq!(rejected(&mut client, fake)?, RejectReason::NotPermitted);

        let mut session = Client::session(&rt, "cargo")?;
        let forget = Message::Forget(pent_profile::Forget {
            key: "cargo".parse()?,
            target: None,
        });
        for message in [Message::Questions, Message::Denials(None), forget] {
            assert_eq!(rejected(&mut session, message)?, RejectReason::NotPermitted);
        }
        // The client event left no refusal.
        let (_, err) = ok(&pent(&rt, state.path(), &["denials"])?)?;
        assert!(err.contains("none"), "{err}");
        Ok(())
    }

    const TWO_RULES: &str = r#"version = 1

# The registry.
[[rule]]
kind = "read"
width = "subtree"
path = "/home/u/reg"
decision = "allow"
source = "human"
created = 2026-11-22T12:00:00Z

# The database.
[[rule]]
kind = "localhost"
port = 5432
decision = "deny"
source = "human"
created = 2026-11-22T12:00:01Z
"#;

    #[test]
    fn pent_rules_forget_goes_through_pentd_and_keeps_the_other_rules() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let rules = state.path().join("pent/rules");
        std::fs::create_dir_all(&rules)?;
        let file = rules.join("cargo.toml");
        std::fs::write(&file, TWO_RULES)?;
        let _pentd = ready(&rt, state.path())?;

        let err = fails(&pent(
            &rt,
            state.path(),
            &["rules", "forget", "cargo", "3"],
        )?)?;
        assert!(err.contains("cargo has no rule 3"), "{err}");
        let err = fails(&pent(
            &rt,
            state.path(),
            &["rules", "forget", "cargo", "0"],
        )?)?;
        assert!(err.contains("cargo has no rule 0"), "{err}");

        let (_, err) = ok(&pent(
            &rt,
            state.path(),
            &["rules", "forget", "cargo", "1"],
        )?)?;
        assert!(
            err.contains("forgot 1 rule of cargo: read /home/u/reg/**"),
            "{err}"
        );
        let text = std::fs::read_to_string(&file)?;
        assert!(!text.contains("/home/u/reg"), "{text}");
        assert!(text.contains("# The database."), "{text}");
        assert!(text.contains("port = 5432"), "{text}");

        let (_, err) = ok(&pent(&rt, state.path(), &["rules", "forget", "cargo"])?)?;
        assert!(err.contains("forgot 1 rule of cargo"), "{err}");
        let (out, err) = ok(&pent(&rt, state.path(), &["rules", "show", "cargo"])?)?;
        assert!(out.is_empty() && err.contains("none"), "{out}{err}");

        // A key with no file gets no file.
        let (_, err) = ok(&pent(&rt, state.path(), &["rules", "forget", "node"])?)?;
        assert!(err.contains("node has no such rule now"), "{err}");
        assert!(!rules.join("node.toml").exists());
        Ok(())
    }

    #[test]
    fn a_forget_by_target_removes_only_that_target() -> TestResult {
        // The CLI sends the target, not the number, so a change of the
        // order of the file cannot make pentd remove another rule.
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let rules = state.path().join("pent/rules");
        std::fs::create_dir_all(&rules)?;
        std::fs::write(rules.join("cargo.toml"), TWO_RULES)?;
        let _pentd = ready(&rt, state.path())?;
        let mut client = Client::connect(&rt)?;
        let port = std::num::NonZeroU16::new(5432).ok_or("port 0")?;
        let key: pent_profile::RuleKey = "cargo".parse()?;
        let forget = |target| {
            Message::Forget(pent_profile::Forget {
                key: key.clone(),
                target: Some(target),
            })
        };
        client.send(forget(Target::Localhost(port)))?;
        assert!(matches!(client.recv()?, Message::Forgotten(f) if f.count == 1));
        // The same target again: nothing goes, and the other rule stays.
        client.send(forget(Target::Localhost(port)))?;
        assert!(matches!(client.recv()?, Message::Forgotten(f) if f.count == 0));
        let (out, _) = ok(&pent(&rt, state.path(), &["rules", "show", "cargo"])?)?;
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("read /home/u/reg/**"), "{out}");
        Ok(())
    }

    #[test]
    fn a_list_longer_than_the_outbox_reaches_the_client_whole() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        // 600 open questions: more than the 256 items of an outbox.
        let mut sessions = Vec::new();
        for run in 0..2_u16 {
            let mut session = Client::session(&rt, "cargo")?;
            for port in 1..=300_u16 {
                session.ask(port_ask(run * 1000 + port)?)?;
            }
            sessions.push(session);
        }
        let (out, _) = ok(&pent(&rt, state.path(), &["questions", "--json"])?)?;
        assert_eq!(out.lines().count(), 600);
        // A watcher gets each open question too.
        let mut watcher = Client::connect(&rt)?;
        watcher.send(Message::Watch)?;
        for i in 0..600 {
            if !matches!(watcher.recv()?, Message::Question(_)) {
                return Err(format!("message {i} is not a question").into());
            }
        }
        Ok(())
    }

    #[test]
    fn a_wide_answer_for_more_questions_than_the_outbox_reaches_each_one() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        let mut session = Client::session(&rt, "cargo")?;
        let mut first = None;
        for i in 0..300 {
            let id = session.ask(read_ask(&format!("/home/u/reg/f{i}"), "/home/u/reg")?)?;
            first.get_or_insert(id);
        }
        let first = first.ok_or("no question")?;
        let number = first.to_string();
        let (_, err) = ok(&pent(
            &rt,
            state.path(),
            &["allow", &number, "--width", "1"],
        )?)?;
        assert!(err.contains("allow read /home/u/reg/**"), "{err}");
        for i in 0..300 {
            if !matches!(session.recv()?, Message::Verdict(_)) {
                return Err(format!("message {i} is not a verdict").into());
            }
        }
        Ok(())
    }

    #[test]
    fn pentd_computes_the_class_and_the_menu_and_ignores_those_of_the_session() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = ready(&rt, state.path())?;
        // pentd has `HOME` = `state`. A faulty session calls a key in it
        // normal and offers the subtree of `.ssh`.
        let home = state.path().display().to_string();
        let mut session = Client::session(&rt, "cargo")?;
        let mut ask = read_ask(&format!("{home}/.ssh/id_ed25519"), &format!("{home}/.ssh"))?;
        ask.class = pent_profile::Class::Normal;
        session.send(Message::Ask(ask))?;
        let question = match session.recv()? {
            Message::Question(q) => q,
            other => return Err(format!("{other:?}").into()),
        };
        assert!(
            matches!(question.ask.class, pent_profile::Class::Sensitive(_)),
            "{:?}",
            question.ask.class
        );
        assert_eq!(question.ask.menu.len(), 1, "{:?}", question.ask.menu);
        let number = question.id.to_string();
        let err = fails(&pent(
            &rt,
            state.path(),
            &["allow", &number, "--width", "1"],
        )?)?;
        assert!(err.contains("the width is not in the menu"), "{err}");

        // An access in the pent class gets no question.
        let rules = format!("{home}/pent/rules/cargo.toml");
        session.send(Message::Ask(read_ask(
            &rules,
            &format!("{home}/pent/rules"),
        )?))?;
        match session.recv()? {
            Message::Rejected(r) => assert_eq!(r.reason, RejectReason::NoAnswer),
            other => return Err(format!("{other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn a_client_stops_when_pentd_does_not_reply() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        // A listener that never accepts: the connection and the request go
        // into the queue of the kernel, and no reply comes.
        std::fs::create_dir_all(rt.pent_dir())?;
        std::fs::set_permissions(rt.pent_dir(), std::fs::Permissions::from_mode(0o700))?;
        let _silent = std::os::unix::net::UnixListener::bind(rt.socket())?;
        let start = Instant::now();
        let output = rt
            .pent(&["questions"])
            .env("XDG_STATE_HOME", state.path())
            .env("HOME", state.path())
            .env("PENT_REPLY_WAIT_MS", "200")
            .stderr(Stdio::piped())
            .output()?;
        let err = fails(&output)?;
        assert!(err.contains("pentd sent no reply in time"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        Ok(())
    }

    #[test]
    fn each_client_fails_when_no_pentd_runs_and_starts_none() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        std::fs::create_dir_all(state.path().join("pent/rules"))?;
        std::fs::write(state.path().join("pent/rules/cargo.toml"), TWO_RULES)?;
        for args in [
            &["allow", "222223"][..],
            &["deny", "222223"],
            &["questions"],
            &["denials"],
            &["rules", "forget", "cargo"],
        ] {
            let err = fails(&pent(&rt, state.path(), args)?)?;
            assert!(err.contains("pentd does not run"), "{args:?}: {err}");
        }
        assert!(!rt.socket().exists(), "a client started pentd");
        // `list` and `show` read the files and need no pentd.
        let (out, _) = ok(&pent(&rt, state.path(), &["rules", "list"])?)?;
        assert!(out.contains("2 rules"), "{out}");
        Ok(())
    }
}

// ── pent monitor ─────────────────────────────────────────────────────────────

mod monitor {
    use pent_profile::{Decision, FileKind, Message, PathWidth, RulePath, Target};

    use super::common::e2e::Pty;
    use super::queue::{pentd, read_ask, Client};
    use super::*;

    /// The size of the terminal of the monitor.
    const SIZE: (u16, u16) = (110, 30);

    #[test]
    fn pent_monitor_answers_with_a_width_and_shows_the_new_rule() -> TestResult {
        let rt = Runtime::new()?;
        let state = tempfile::tempdir()?;
        let _pentd = pentd(&rt, state.path(), &["daemon"])?;
        assert!(rt.wait_for_socket());
        let mut session = Client::session(&rt, "cargo")?;
        let id = session.ask(read_ask("/home/u/reg/a", "/home/u/reg")?)?;

        let mut cmd = rt.pent(&["monitor"]);
        cmd.env("XDG_STATE_HOME", state.path())
            .env("HOME", state.path())
            .env("TERM", "xterm");
        let mut screen = Pty::spawn(cmd, Some(SIZE))?;
        screen.expect_screen(SIZE, "Questions (1)", WAIT)?;
        screen.expect_screen(SIZE, &format!("  {id}  read /home/u/reg/a"), WAIT)?;
        screen.expect_screen(SIZE, "(•) 0 read /home/u/reg/a", WAIT)?;
        // The wider place of the menu, the scope `remember`, then allow.
        screen.send("ls")?;
        screen.expect_screen(SIZE, "(•) 1 read /home/u/reg/**", WAIT)?;
        screen.expect_screen(SIZE, "scope   this run  [remember]", WAIT)?;
        screen.send("a")?;
        match session.recv()? {
            Message::Verdict(v) => {
                assert_eq!(v.id, id);
                assert_eq!(v.decision, Decision::Allow);
                assert_eq!(
                    v.target,
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Subtree(RulePath::new("/home/u/reg")?),
                    }
                );
            }
            other => return Err(format!("{other:?}").into()),
        }
        screen.expect_screen(SIZE, "allow read /home/u/reg/** (remembered)", WAIT)?;
        screen.expect_screen(SIZE, "Questions (0)", WAIT)?;
        // The rules tab shows the new rule.
        screen.send("\t\t")?;
        screen.expect_screen(SIZE, "cargo            1 rule", WAIT)?;
        screen.expect_screen(SIZE, "  1  allow  read /home/u/reg/**  human", WAIT)?;
        screen.send("q")?;
        let (status, text) = screen.wait(WAIT)?;
        assert!(status.success(), "{status:?}\n{text}");
        Ok(())
    }

    #[test]
    fn pent_monitor_needs_a_terminal_and_a_running_pentd() -> TestResult {
        let rt = Runtime::new()?;
        let output = rt.pent(&["monitor"]).stderr(Stdio::piped()).output()?;
        assert!(!output.status.success());
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(err.contains("pent monitor needs a terminal"), "{err}");

        let screen = Pty::spawn(rt.pent(&["monitor"]), Some((80, 24)))?;
        let (status, text) = screen.wait(WAIT)?;
        assert!(!status.success(), "{text}");
        assert!(text.contains("pentd does not run"), "{text}");
        assert!(!rt.socket().exists(), "pent monitor started pentd");
        Ok(())
    }
}

// ── The notification hook ───────────────────────────────────────────────────

mod notify {
    use super::queue::{port_ask, Client};
    use super::*;

    /// A pentd with a global `pent.toml` in `config` (when `command` is
    /// given) and a marker variable in its environment.
    struct Hooked {
        rt: Runtime,
        home: tempfile::TempDir,
        out: PathBuf,
        _pentd: Reap,
    }

    impl Hooked {
        /// `command` runs in `sh -c`, with the path prefix of the output
        /// files as `$0`.
        fn start(command: Option<&str>) -> Result<Self, common::e2e::BoxError> {
            let rt = Runtime::new()?;
            let home = tempfile::tempdir()?;
            let out = home.path().join("out");
            std::fs::create_dir(&out)?;
            let hooked = Self {
                _pentd: Reap(
                    rt.pent(&["daemon"])
                        .env("HOME", home.path())
                        .env("XDG_CONFIG_HOME", home.path().join("config"))
                        .env("XDG_STATE_HOME", home.path().join("state"))
                        .env("PENT_TEST_MARK", "inherited")
                        .spawn()?,
                ),
                rt,
                out,
                home,
            };
            if let Some(command) = command {
                hooked.set_command(command)?;
            }
            if !hooked.rt.wait_for_socket() {
                return Err("pentd never listened".into());
            }
            Ok(hooked)
        }

        /// Write the global `pent.toml` with `command`.
        fn set_command(&self, command: &str) -> TestResult {
            let dir = self.home.path().join("config/pent");
            std::fs::create_dir_all(&dir)?;
            let prefix = self.out.join("run");
            let toml = format!(
                "[notify]\ncommand = [\"sh\", \"-c\", {}, {}]\n",
                toml_string(command),
                toml_string(&prefix.display().to_string())
            );
            std::fs::write(dir.join("pent.toml"), toml)?;
            Ok(())
        }

        /// The environment of each run so far, in the order of the runs.
        fn runs(&self) -> Result<Vec<String>, common::e2e::BoxError> {
            let mut files: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&self.out)?
                .filter_map(Result::ok)
                .map(|e| (e.metadata().and_then(|m| m.modified()), e.path()))
                .filter_map(|(t, p)| t.ok().map(|t| (t, p)))
                .collect();
            files.sort();
            files
                .iter()
                .map(|(_, p)| Ok(std::fs::read_to_string(p)?))
                .collect()
        }

        /// Wait until there are `n` runs, then a while more, so a run too
        /// many shows.
        fn wait_runs(&self, n: usize) -> Result<Vec<String>, common::e2e::BoxError> {
            let deadline = Instant::now() + WAIT;
            while self.runs()?.len() < n {
                if Instant::now() >= deadline {
                    return Err(format!("only {} runs of the hook", self.runs()?.len()).into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(1500));
            self.runs()
        }
    }

    /// A TOML basic string.
    fn toml_string(text: &str) -> String {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// The value of `PENT_PENDING` in the environment of one run.
    fn pending(env: &str) -> Option<&str> {
        env.lines().find_map(|l| l.strip_prefix("PENT_PENDING="))
    }

    /// The hook writes its environment, one file for each run.
    const WRITE_ENV: &str = "env > \"$0.$$\"";

    #[test]
    fn one_burst_gives_one_run_with_the_number_of_open_questions() -> TestResult {
        let hooked = Hooked::start(Some(WRITE_ENV))?;
        let mut session = Client::session(&hooked.rt, "cargo")?;
        for port in [5432, 5433, 5434] {
            session.ask(port_ask(port)?)?;
        }
        let runs = hooked.wait_runs(1)?;
        assert_eq!(runs.len(), 1, "{} runs", runs.len());
        assert_eq!(pending(&runs[0]), Some("3"));
        // The hook gets the environment of pentd.
        assert!(runs[0].lines().any(|l| l == "PENT_TEST_MARK=inherited"));

        // The same access again is no new question: no run.
        session.ask(port_ask(5432)?)?;
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(hooked.runs()?.len(), 1);

        // A new question later is a new burst.
        session.ask(port_ask(80)?)?;
        let runs = hooked.wait_runs(2)?;
        assert_eq!(runs.len(), 2, "{} runs", runs.len());
        assert_eq!(pending(&runs[1]), Some("4"));
        Ok(())
    }

    #[test]
    fn questions_during_a_run_give_one_more_run_after_it() -> TestResult {
        // The hook takes one second.
        let hooked = Hooked::start(Some("env > \"$0.$$\"; sleep 1"))?;
        let mut session = Client::session(&hooked.rt, "cargo")?;
        session.ask(port_ask(1)?)?;
        // Wait until the first run started, then ask during it.
        let deadline = Instant::now() + WAIT;
        while hooked.runs()?.is_empty() {
            assert!(Instant::now() < deadline, "no first run");
            std::thread::sleep(Duration::from_millis(10));
        }
        session.ask(port_ask(2)?)?;
        session.ask(port_ask(3)?)?;
        let runs = hooked.wait_runs(2)?;
        assert_eq!(runs.len(), 2, "{} runs", runs.len());
        assert_eq!(pending(&runs[0]), Some("1"));
        assert_eq!(pending(&runs[1]), Some("3"));
        Ok(())
    }

    #[test]
    fn no_command_gives_no_run_and_a_new_command_applies_at_once() -> TestResult {
        let hooked = Hooked::start(None)?;
        let mut session = Client::session(&hooked.rt, "cargo")?;
        session.ask(port_ask(1)?)?;
        std::thread::sleep(Duration::from_millis(1500));
        assert!(hooked.runs()?.is_empty());

        // A broken file gives no run, and pentd goes on.
        let dir = hooked.home.path().join("config/pent");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("pent.toml"), "[notify]\ncommand = []\n")?;
        session.ask(port_ask(2)?)?;
        std::thread::sleep(Duration::from_millis(1500));
        assert!(hooked.runs()?.is_empty());

        // pentd reads the settings at each burst: no restart.
        hooked.set_command(WRITE_ENV)?;
        session.ask(port_ask(3)?)?;
        let runs = hooked.wait_runs(1)?;
        assert_eq!(runs.len(), 1, "{} runs", runs.len());
        assert_eq!(pending(&runs[0]), Some("3"));
        Ok(())
    }
}

#[test]
fn a_flag_that_names_a_parent_does_not_bring_back_the_socket_of_pentd() -> TestResult {
    let test = "a_flag_that_names_a_parent_does_not_bring_back_the_socket_of_pentd";
    if !sandbox_ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    // The flag names the runtime directory of the test itself, the parent
    // of `pent/`, as a flag can name `/run/user/<uid>`.
    let runtime = env.runtime.display().to_string();
    std::fs::write(env.runtime.join("visible"), "PENT_VISIBLE")?;
    let script = format!(
        "cat '{runtime}/visible'; echo; echo PENTLS $(ls -A '{runtime}/pent' 2>&1 | tr '\\n' ' ')"
    );
    // A rule over a parent of a directory of pent does not go into the
    // sandbox (`HeldBack::PentFiles`), so the test names the directory with
    // the flag.
    let out = env
        .command(&["run", "--read", &runtime, "--", "sh", "-c", &script])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // The positive control: the flag brought the directory back.
    assert!(text.contains("PENT_VISIBLE"), "{text}");
    // `pent run` started pentd there, so the host has the socket.
    assert!(
        env.runtime.join("pent/pentd.sock").exists()
            || env.runtime.join("pent/pentd.lock").exists()
    );
    let line = text
        .lines()
        .find(|l| l.starts_with("PENTLS"))
        .ok_or("no listing")?;
    assert_eq!(
        line.trim(),
        "PENTLS",
        "the child sees the files of pent: {line}"
    );
    Ok(())
}

#[test]
fn pent_watch_also_hides_the_socket_of_pentd_under_a_bound_parent() -> TestResult {
    let test = "pent_watch_also_hides_the_socket_of_pentd_under_a_bound_parent";
    if !sandbox_ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let runtime = env.runtime.display().to_string();
    // A global mount brings back the parent of `pent/`, as a mount of
    // `/run/user/<uid>` does.
    let settings = env.config_dir().join("pent/pent.toml");
    std::fs::create_dir_all(env.config_dir().join("pent"))?;
    std::fs::write(
        &settings,
        format!("[[sandbox.mounts]]\npath = \"{runtime}\"\n"),
    )?;
    std::fs::write(env.runtime.join("visible"), "PENT_VISIBLE")?;
    let _pentd = Reap(
        env.command(&["daemon"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + WAIT;
    while !env.runtime.join("pent/pentd.sock").exists() {
        if Instant::now() >= deadline {
            return Err("pentd never listened".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let script = format!(
        "cat '{runtime}/visible'; echo; echo PENTLS $(ls -A '{runtime}/pent' 2>&1 | tr '\\n' ' ')"
    );
    let out = env
        .command(&[
            "watch",
            "--yes",
            "--profile",
            "w",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // The positive control: the mount brought the directory back.
    assert!(text.contains("PENT_VISIBLE"), "{text}");
    let line = text
        .lines()
        .find(|l| l.starts_with("PENTLS"))
        .ok_or("no listing")?;
    assert_eq!(
        line.trim(),
        "PENTLS",
        "pent watch shows the files of pent: {line}"
    );
    Ok(())
}

#[test]
fn a_runtime_directory_that_appears_after_the_start_stays_hidden() -> TestResult {
    let test = "a_runtime_directory_that_appears_after_the_start_stays_hidden";
    if !sandbox_ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let runtime = env.runtime.display().to_string();
    // `pent run` makes the runtime directory before the sandbox when it
    // starts pentd. `pent watch` holds no pentd, so only the sandbox can
    // make the directory before the masks. A global mount brings back its
    // parent, as a mount of `/run/user/<uid>` does.
    std::fs::create_dir_all(env.config_dir().join("pent"))?;
    std::fs::write(
        env.config_dir().join("pent/pent.toml"),
        format!("[[sandbox.mounts]]\npath = \"{runtime}\"\n"),
    )?;
    // No `pent/` yet when the run starts.
    if env.runtime.join("pent").exists() {
        std::fs::remove_dir_all(env.runtime.join("pent"))?;
    }
    std::fs::write(env.runtime.join("visible"), "PENT_VISIBLE")?;
    let script = format!(
        "cat '{runtime}/visible'; echo; i=0; while [ $i -lt 50 ]; do ls -A '{runtime}/pent' 2>/dev/null | grep -q sock && break; \
         sleep 0.1; i=$((i+1)); done; echo PENTLS $(ls -A '{runtime}/pent' 2>&1 | tr '\\n' ' ')"
    );
    let mut child = Reap(
        env.command(&[
            "watch",
            "--yes",
            "--profile",
            "w",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?,
    );
    // A pentd that starts after the sandbox, as another `pent run` starts
    // it.
    std::thread::sleep(Duration::from_millis(300));
    let _pentd = Reap(
        Command::new(PENT)
            .args(["daemon"])
            .env("XDG_RUNTIME_DIR", &env.runtime)
            .env("PENTD_LINGER_MS", LINGER_MS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    // The loop of the script starts about 150 programs under the recorder
    // of `pent watch`, which traces each call; that takes several seconds.
    let status = wait_exit(&mut child.0, Duration::from_secs(30))?.ok_or("the run did not end")?;
    let mut text = String::new();
    if let Some(mut out) = child.0.stdout.take() {
        out.read_to_string(&mut text)?;
    }
    let mut err = String::new();
    if let Some(mut stream) = child.0.stderr.take() {
        stream.read_to_string(&mut err)?;
    }
    assert!(status.success(), "{status:?}: {text}: {err}");
    // The positive control: the mount brought the directory back.
    assert!(text.contains("PENT_VISIBLE"), "{text}");
    assert!(env.runtime.join("pent/pentd.lock").exists(), "no pentd ran");
    let line = text
        .lines()
        .find(|l| l.starts_with("PENTLS"))
        .ok_or("no listing")?;
    assert_eq!(
        line.trim(),
        "PENTLS",
        "the child sees the files of pent: {line}"
    );
    Ok(())
}

mod hook_fds {
    use super::queue::{port_ask, Client};
    use super::*;

    #[test]
    fn the_hook_does_not_get_the_socket_from_systemd() -> TestResult {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        let rt = Runtime::new()?;
        let home = tempfile::tempdir()?;
        let out = home.path().join("fds");
        let config = home.path().join("config/pent");
        std::fs::create_dir_all(&config)?;
        // The hook lists its open files.
        std::fs::write(
            config.join("pent.toml"),
            format!(
                "[notify]\ncommand = [\"sh\", \"-c\", \"for f in /proc/$$/fd/*; do readlink $f; done > '{}'\"]\n",
                out.display()
            ),
        )?;
        std::fs::create_dir(rt.pent_dir())?;
        std::fs::set_permissions(rt.pent_dir(), std::fs::Permissions::from_mode(0o700))?;
        let listener = std::os::unix::net::UnixListener::bind(rt.socket())?;
        let fd = listener.as_raw_fd();
        let inode = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" daemon", PENT]);
        rt.apply(&mut cmd)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_STATE_HOME", home.path().join("state"));
        // SAFETY: the hook runs in the child after the fork and calls only
        // `dup2` and `fcntl`, which are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                let rc = if fd == 3 {
                    libc::fcntl(3, libc::F_SETFD, 0)
                } else {
                    libc::dup2(fd, 3)
                };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let _pentd = Reap(cmd.spawn()?);
        drop(listener);

        let mut session = loop {
            if let Ok(client) = Client::session(&rt, "cargo") {
                break client;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        session.ask(port_ask(5432)?)?;
        let deadline = Instant::now() + WAIT;
        while !out.exists() || std::fs::read_to_string(&out)?.is_empty() {
            assert!(Instant::now() < deadline, "the hook did not run");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100));
        let fds = std::fs::read_to_string(&out)?;
        let socket = inode.display().to_string();
        assert!(
            !fds.lines().any(|l| l == socket),
            "the hook has the listening socket {socket}"
        );
        Ok(())
    }
}
