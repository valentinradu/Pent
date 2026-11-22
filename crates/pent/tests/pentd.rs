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

use common::e2e::{sandbox_ready, TestEnv, TestResult};
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
    env.install_profile("sh", "")?;
    let mut run = env.command(&["run", "--profile", "sh", "--", "sh", "-c", "sleep 2"]);
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
    env.install_profile("sh", "")?;
    let script = format!(
        "if [ -e '{sock}' ] || [ -e '{dir}' ]; then echo SEEN; else echo HIDDEN; fi",
        sock = rt.socket().display(),
        dir = rt.pent_dir().display()
    );
    let out = env
        .command(&["run", "--profile", "sh", "--", "sh", "-c", &script])
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
