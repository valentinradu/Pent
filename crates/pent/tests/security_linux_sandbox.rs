//! Security tests for the Linux filesystem and process sandbox of
//! `pent run`.
//!
//! Each test runs the real `pent` binary with a trusted profile in an
//! isolated `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` under
//! `CARGO_TARGET_TMPDIR` (not `/tmp`, because the sandbox always allows
//! `/tmp`). A test creates its own victim resources, so it needs no X11,
//! D-Bus or SSH agent on the host.
//!
//! A test that asserts the secure behaviour has two uses:
//! - It passes: the defense works, and the test is a regression guard.
//! - It fails: the sandbox is open. The test then has an
//!   `#[ignore = "OPEN VULN LS-<n>: ..."]` attribute, so the suite stays
//!   green, and the assertion stays as the proof of the finding. Run the
//!   suite with `--include-ignored` to see the failure.
//!
//! A test skips with a message when Landlock or a user namespace is not
//! available, or when `python3` is missing.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code; failures are the point

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

/// The compiled `pent` binary.
const PENT: &str = env!("CARGO_BIN_EXE_pent");

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A unique base directory for one test, with an isolated HOME and XDG.
struct Harness {
    base: PathBuf,
    config: PathBuf,
    state: PathBuf,
    home: PathBuf,
    /// The workspace (the cwd of the child); always read-write.
    workspace: PathBuf,
    /// A host directory that no profile names, for victim resources.
    outside: PathBuf,
}

static SEQ: AtomicU32 = AtomicU32::new(0);

impl Harness {
    /// Make the directories and install a trusted profile `name` with the
    /// content `profile_toml`.
    fn new(name: &str, profile_toml: &str) -> std::io::Result<Self> {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let base = root.join(format!("sec-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let h = Self {
            config: base.join("config"),
            state: base.join("state"),
            home: base.join("home"),
            workspace: base.join("workspace"),
            outside: base.join("outside"),
            base,
        };
        for d in [&h.config, &h.state, &h.home, &h.workspace, &h.outside] {
            std::fs::create_dir_all(d)?;
        }
        let draft = h.state.join("pent/drafts").join(format!("{name}.toml"));
        std::fs::create_dir_all(draft.parent().unwrap())?;
        std::fs::write(&draft, profile_toml)?;
        let out = h
            .command(&[PENT, "trust", name, "--yes"])
            .output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "pent trust {name} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(h)
    }

    /// A `Command` with the isolated environment set. `argv[0]` is the
    /// program; the rest are arguments.
    fn command(&self, argv: &[&str]) -> Command {
        let mut cmd = Command::new(argv[0]);
        cmd.args(&argv[1..])
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("HOME", &self.home)
            .env_remove("PENT_LOG")
            .current_dir(&self.workspace)
            .stdin(Stdio::null());
        cmd
    }

    /// Write `body` to `<workspace>/<name>` and return its path.
    fn script(&self, name: &str, body: &str) -> std::io::Result<PathBuf> {
        let path = self.workspace.join(name);
        std::fs::write(&path, body)?;
        Ok(path)
    }

    /// Run `pent run -- <argv>` and return the output.
    fn run(&self, argv: &[&str]) -> std::io::Result<Output> {
        let mut full = vec![PENT, "run", "--"];
        full.extend_from_slice(argv);
        self.command(&full).output()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The combined stdout and stderr of an output, for messages and markers.
fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// True when the output shows that the sandbox is not available on this host
/// (no Landlock or no user namespace). The caller then skips the test.
fn sandbox_unavailable(out: &Output) -> bool {
    let text = combined(out);
    text.contains("Landlock")
        || text.contains("user namespace")
        || text.contains("sandbox is not available")
}

/// The path of `python3`, or `None` when it is not in `PATH`.
fn python3() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
}

/// A minimal profile that allows nothing beyond the sandbox defaults.
const EMPTY_PROFILE: &str = "[filesystem]\nread = []\nread_write = []\nexecute = []\n\n\
                             [network]\ndomains = []\n";

// ============================================================================
// Verified defenses — these tests pass; they guard the sandbox.
// ============================================================================

/// The child cannot read a file outside its profile.
#[test]
fn test_read_outside_profile_denied() -> TestResult {
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    let secret = h.outside.join("secret");
    std::fs::write(&secret, "SECRETDATA")?;
    let script = h.script("probe.sh", &format!("cat '{}'\n", secret.display()))?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("SECRETDATA"),
        "the child read a file outside its profile:\n{text}"
    );
    Ok(())
}

/// The child cannot write a file outside its profile.
#[test]
fn test_write_outside_profile_denied() -> TestResult {
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    let target = h.outside.join("written");
    let script = h.script(
        "probe.sh",
        &format!("echo hi > '{}'; echo rc=$?\n", target.display()),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    assert!(
        !target.exists(),
        "the child wrote a file outside its profile: {}",
        target.display()
    );
    Ok(())
}

/// The new network namespace blocks a connection to an abstract Unix socket
/// of a host process.
#[test]
fn test_abstract_unix_socket_blocked() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    // The abstract name carries the base so that parallel tests do not clash.
    let name = format!("pent-victim-{}", std::process::id());
    let listener_src = format!(
        "import socket,threading,time\n\
         s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n\
         s.bind('\\0{name}'); s.listen(1)\n\
         def serve():\n    c,_=s.accept(); c.sendall(b'ABSSECRET')\n\
         threading.Thread(target=serve,daemon=True).start()\n\
         open('{ready}','w').close(); time.sleep(10)\n",
        ready = h.base.join("ready").display(),
    );
    let mut victim = Command::new(&py)
        .arg("-I")
        .arg("-c")
        .arg(&listener_src)
        .spawn()?;
    wait_for(&h.base.join("ready"));
    let probe = h.script(
        "c.py",
        &format!(
            "import socket\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)\n\
             try:\n    s.connect('\\0{name}'); print('CONNECTED', s.recv(16))\n\
             except Exception as e:\n    print('BLOCKED', e)\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    victim.kill().ok();
    victim.wait().ok();
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("CONNECTED"),
        "the child reached an abstract Unix socket of a host process:\n{text}"
    );
    Ok(())
}

/// The child cannot see the content of `/run/user/<uid>` (session D-Bus,
/// the systemd user manager, rootless Docker, the SSH and GPG agents). An
/// empty tmpfs covers it.
#[test]
fn test_runtime_dir_masked() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    let runtime = PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
    if !runtime.is_dir() {
        eprintln!("skip: no {} on this host", runtime.display());
        return Ok(());
    }
    let probe = h.script(
        "c.py",
        &format!(
            "import os\n\
             try:\n    print('COUNT', len(os.listdir('{}')))\n\
             except Exception as e:\n    print('COUNT 0', e)\n",
            runtime.display()
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        text.contains("COUNT 0"),
        "the child saw entries in the user runtime directory:\n{text}"
    );
    Ok(())
}

/// The child cannot send a signal to a host process of the same user. The
/// user namespace blocks it (EPERM).
#[test]
fn test_signal_to_host_process_denied() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    let (mut victim, pid) = spawn_victim(&py, &h)?;
    let probe = h.script(
        "c.py",
        &format!(
            "import os\n\
             try:\n    os.kill({pid}, 0); print('SIGNAL_ALLOWED')\n\
             except Exception as e:\n    print('SIGNAL_DENIED', e)\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    victim.kill().ok();
    victim.wait().ok();
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("SIGNAL_ALLOWED"),
        "the child sent a signal to a host process:\n{text}"
    );
    Ok(())
}

/// The child cannot read the environment of a host process of the same user.
/// `/proc/<pid>/environ` needs ptrace access, which the user namespace
/// refuses (EACCES).
#[test]
fn test_proc_environ_of_host_process_denied() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    let (mut victim, pid) = spawn_victim(&py, &h)?;
    let probe = h.script(
        "c.py",
        &format!(
            "import os\nd=b''\ntry:\n    d=open('/proc/{pid}/environ','rb').read()\nexcept Exception as e:\n    print('ENVIRON_DENIED', e)\nprint('ENVIRON_SECRET' if b'TOPSECRET_ENV' in d else 'ENVIRON_EMPTY')\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    victim.kill().ok();
    victim.wait().ok();
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("ENVIRON_SECRET"),
        "the child read the environment of a host process:\n{text}"
    );
    Ok(())
}

/// The child cannot create a new mount namespace or unmount a mask. It has no
/// capability after `execve` and `NO_NEW_PRIVS` is set.
#[test]
fn test_cannot_unshare_or_umount() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    let runtime = format!("/run/user/{}", unsafe { libc::getuid() });
    let probe = h.script(
        "c.py",
        &format!(
            "import ctypes\n\
             libc=ctypes.CDLL('libc.so.6',use_errno=True)\n\
             print('UNSHARE', libc.unshare(0x00020000))\n\
             print('UMOUNT', libc.umount2(b'{runtime}',0))\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        text.contains("UNSHARE -1"),
        "the child created a new mount namespace:\n{text}"
    );
    assert!(
        text.contains("UMOUNT -1"),
        "the child unmounted a mask:\n{text}"
    );
    Ok(())
}

/// The seccomp filter blocks `ioctl(TIOCSTI)`, so the child cannot push bytes
/// into the terminal input queue of the parent shell.
#[test]
fn test_tiocsti_blocked() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    // fd -1: without the filter the kernel returns EBADF (9); the filter
    // returns EPERM (1) before the fd check.
    let probe = h.script(
        "c.py",
        "import ctypes\n\
         libc=ctypes.CDLL('libc.so.6',use_errno=True)\n\
         r=libc.ioctl(-1,0x5412,ctypes.byref(ctypes.c_char(b'x')))\n\
         print('TIOCSTI errno', ctypes.get_errno())\n",
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        text.contains("TIOCSTI errno 1"),
        "ioctl(TIOCSTI) was not blocked with EPERM:\n{text}"
    );
    Ok(())
}

/// LS-2: the child must not read or change a file under `/tmp` that a host
/// program owns and that is not in its workspace. An empty tmpfs covers
/// `/tmp` in the mount namespace of the child, so the victim file is not
/// there.
#[test]
fn test_tmp_not_shared_with_host() -> TestResult {
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    // A host file under /tmp, outside the workspace, owned by this test.
    let victim = std::env::temp_dir().join(format!("pent-victim-{}", std::process::id()));
    std::fs::write(&victim, "HOST_TMP_DATA")?;
    let script = h.script(
        "probe.sh",
        &format!(
            "cat '{v}'\necho TAMPERED > '{v}'\n",
            v = victim.display()
        ),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    let after = std::fs::read_to_string(&victim).unwrap_or_default();
    let _ = std::fs::remove_file(&victim);
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("HOST_TMP_DATA"),
        "LS-2: the child read a host file under /tmp:\n{text}"
    );
    assert_eq!(
        after, "HOST_TMP_DATA",
        "LS-2: the child overwrote a host file under /tmp"
    );
    Ok(())
}

/// LS-2: the child must not reach a Unix socket that a host program keeps in
/// `/tmp`. This is the escape of a terminal multiplexer: the host server
/// runs a command for any program that reaches its socket, and that command
/// runs outside the sandbox.
#[test]
fn test_tmp_unix_socket_unreachable() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    let sock = std::env::temp_dir().join(format!("pent-victim-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"TMUX_SECRET");
        }
    });
    let probe = h.script(
        "c.py",
        &format!(
            "import socket\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)\n\
             try:\n    s.connect('{}'); print('CONNECTED', s.recv(32))\n\
             except Exception as e:\n    print('BLOCKED', e)\n",
            sock.display()
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    // Unblock the listener thread if the child never connected.
    if let Ok(s) = std::os::unix::net::UnixStream::connect(&sock) {
        drop(s);
    }
    handle.join().ok();
    let _ = std::fs::remove_file(&sock);
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("TMUX_SECRET"),
        "LS-2: the child reached a host socket in /tmp:\n{text}"
    );
    Ok(())
}

/// The child must not see the control sockets of the host daemons under
/// `/run`. An empty tmpfs covers `/run`, and pent binds back only the system
/// paths that a program needs.
#[test]
fn test_run_not_shared_with_host() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    // The entries of /run that pent binds back. Everything else of the host
    // must be absent.
    let kept = [
        "current-system",
        "booted-system",
        "wrappers",
        "opengl-driver",
        "opengl-driver-32",
        "user",
    ];
    let probe = h.script(
        "c.py",
        "import os\nprint('RUN', ' '.join(sorted(os.listdir('/run'))))\n",
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    let line = text
        .lines()
        .find(|l| l.starts_with("RUN "))
        .ok_or("the child could not list /run")?;
    for entry in line.trim_start_matches("RUN ").split_whitespace() {
        assert!(
            kept.contains(&entry),
            "the child saw the host entry /run/{entry}:\n{text}"
        );
    }
    Ok(())
}

/// A workspace under `/tmp` still works: pent binds it back into the private
/// tmpfs. A user can keep a scratch workspace there.
#[test]
fn test_workspace_under_tmp_still_works() -> TestResult {
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    let ws = std::env::temp_dir().join(format!("pent-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws)?;
    std::fs::write(ws.join("input"), "WORKSPACE_DATA")?;
    let mut cmd = h.command(&[PENT, "run", "--", "sh", "-c", "cat input; echo OUT > output"]);
    cmd.current_dir(&ws);
    let out = cmd.output()?;
    let written = std::fs::read_to_string(ws.join("output")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&ws);
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        text.contains("WORKSPACE_DATA"),
        "the child could not read its workspace under /tmp:\n{text}"
    );
    assert_eq!(
        written, "OUT\n",
        "the write of the child did not reach the workspace under /tmp"
    );
    Ok(())
}

/// LS-3: the child must not read the command line of a host process of the
/// same user. `/proc/<pid>/cmdline` is world-readable, and a command line
/// often holds a token or a password. The child runs in a new PID
/// namespace with its own `proc` mount, so it sees only the processes of
/// the sandbox.
#[test]
fn test_proc_cmdline_of_host_process_denied() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    let (mut victim, pid) = spawn_victim(&py, &h)?;
    let probe = h.script(
        "c.py",
        &format!(
            "d=b''\ntry:\n    d=open('/proc/{pid}/cmdline','rb').read()\nexcept Exception as e:\n    print('CMDLINE_DENIED', e)\nprint('CMDLINE_SECRET' if b'TOPSECRET_ARG' in d else 'CMDLINE_EMPTY')\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    victim.kill().ok();
    victim.wait().ok();
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("CMDLINE_SECRET"),
        "LS-3: the child read the command line of a host process:\n{text}"
    );
    Ok(())
}

/// LS-3: a background process of the child must not outlive pent. The
/// kernel ends every process of a PID namespace when the init of that
/// namespace exits.
#[test]
fn test_background_process_does_not_outlive_pent() -> TestResult {
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    let marker = h.workspace.join("alive");
    // The background process writes the marker every 200 ms for 30 s.
    let script = h.script(
        "probe.sh",
        &format!(
            "( i=0; while [ $i -lt 150 ]; do echo $i > '{}'; sleep 0.2; i=$((i+1)); done ) &\n\
             echo STARTED\n",
            marker.display()
        ),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(text.contains("STARTED"), "the probe did not start:\n{text}");
    // Pent has exited. The marker must stop to change.
    std::thread::sleep(std::time::Duration::from_millis(600));
    let first = std::fs::read_to_string(&marker).unwrap_or_default();
    std::thread::sleep(std::time::Duration::from_millis(800));
    let second = std::fs::read_to_string(&marker).unwrap_or_default();
    assert_eq!(
        first, second,
        "LS-3: a background process of the child still runs after pent exited"
    );
    Ok(())
}

/// The PID namespace must not change the exit status that pent reports.
/// The command is PID 2 of the namespace, and two supervisors pass the
/// status on.
#[test]
fn test_exit_status_passes_through_the_namespace() -> TestResult {
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    let script = h.script("probe.sh", "exit 42\n")?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    assert_eq!(
        out.status.code(),
        Some(42),
        "pent did not report the exit code of the command: {}",
        combined(&out)
    );
    Ok(())
}

/// The PID namespace must not change the signal that pent re-raises. A
/// command that a signal ends must end pent with the same signal.
#[test]
fn test_signal_status_passes_through_the_namespace() -> TestResult {
    use std::os::unix::process::ExitStatusExt as _;
    let h = Harness::new("sh", EMPTY_PROFILE)?;
    let script = h.script("probe.sh", "kill -TERM $$\nsleep 5\n")?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGTERM),
        "pent did not re-raise the signal of the command: {:?} {}",
        out.status,
        combined(&out)
    );
    Ok(())
}

// ============================================================================
// Open findings — these tests assert the secure behaviour and currently fail.
// Each is `#[ignore]` with its finding ID so the suite stays green.
// ============================================================================

/// LS-1: the child must not connect to a path-based Unix socket outside its
/// profile. Landlock does not control `connect(2)` on a path socket, and the
/// kernel needs no file right to walk through a directory. A private tmpfs
/// now hides every socket under `/tmp`, `/var/tmp` and `/run`, and a mask
/// hides the agent sockets of the home directory. A socket in any other
/// directory stays reachable, and this test proves it.
#[test]
#[ignore = "OPEN VULN LS-1 (partial): /tmp, /var/tmp, /run and the home agent \
            sockets are hidden; a path socket in another directory is still \
            reachable, because Landlock does not control connect(2). The full \
            fix is a connect(2) filter in the supervisor"]
fn test_unix_socket_connect_outside_profile() -> TestResult {
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3", EMPTY_PROFILE)?;
    // The victim socket is in `outside/`: not in the profile, not under /tmp.
    let sock = h.outside.join("victim.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"VICTIM_SECRET");
        }
    });
    let probe = h.script(
        "c.py",
        &format!(
            "import socket\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)\n\
             try:\n    s.connect('{}'); print('CONNECTED', s.recv(32))\n\
             except Exception as e:\n    print('BLOCKED', e)\n",
            sock.display()
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    // Unblock the listener thread if the child never connected.
    if let Ok(s) = std::os::unix::net::UnixStream::connect(&sock) {
        drop(s);
    }
    handle.join().ok();
    if sandbox_unavailable(&out) {
        eprintln!("skip: sandbox not available on this host");
        return Ok(());
    }
    let text = combined(&out);
    assert!(
        !text.contains("VICTIM_SECRET"),
        "LS-1: the child connected to a Unix socket outside its profile:\n{text}"
    );
    Ok(())
}

// ============================================================================
// Helpers that need a running victim process.
// ============================================================================

/// Spawn a host victim process of the same user with a secret in its
/// environment and in its command line. Returns the child and its PID. The
/// victim writes its PID to `<workspace>/vpid` (the workspace is readable by
/// the sandboxed child).
fn spawn_victim(py: &Path, h: &Harness) -> std::io::Result<(std::process::Child, u32)> {
    let vpid = h.workspace.join("vpid");
    let src = format!(
        "import os,time\n\
         open('{}','w').write(str(os.getpid()))\n\
         time.sleep(15)\n",
        vpid.display()
    );
    let child = Command::new(py)
        .arg("-I")
        .arg("-c")
        .arg(&src)
        .arg("TOPSECRET_ARG")
        .env("TOPSECRET_ENV", "1")
        .stdin(Stdio::null())
        .spawn()?;
    wait_for(&vpid);
    let pid = std::fs::read_to_string(&vpid)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(child.id());
    Ok((child, pid))
}

/// Wait up to 5 seconds for `path` to appear.
fn wait_for(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
