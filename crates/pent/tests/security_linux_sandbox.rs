//! Security tests for the Linux filesystem and process sandbox of
//! `pent run`.
//!
//! Each test runs the real `pent` binary with no rule file in an
//! isolated `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` under
//! `CARGO_TARGET_TMPDIR` (not `/tmp`, because the child gets its own empty
//! `/tmp`; a test of `/tmp` makes its victim there on purpose). A test
//! creates its own victim resources, so it needs no X11, D-Bus or SSH agent
//! on the host.
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

mod common;

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
    /// A host directory that no rule names, for victim resources.
    outside: PathBuf,
    /// The value of `XDG_RUNTIME_DIR` (see `common::runtime_dir`).
    runtime: tempfile::TempDir,
    /// The key of each run (`pent run --key`). It has no rule file, so a
    /// run gets only the base and the workspace.
    key: &'static str,
}

static SEQ: AtomicU32 = AtomicU32::new(0);

impl Harness {
    /// Make the directories. Each run uses the key `key`, which has no
    /// rule file.
    fn new(key: &'static str) -> std::io::Result<Self> {
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
            runtime: common::runtime_dir()?,
            key,
        };
        for d in [&h.config, &h.state, &h.home, &h.workspace, &h.outside] {
            std::fs::create_dir_all(d)?;
        }
        // These tests prove static refusals. A socket or a port with no
        // rule would ask a question; without pentd it gets the refusal at
        // once (RN-8).
        common::block_pentd(h.runtime.path())?;
        Ok(h)
    }

    /// A `Command` with the isolated environment set. `argv[0]` is the
    /// program; the rest are arguments.
    fn command(&self, argv: &[&str]) -> Command {
        let mut cmd = Command::new(argv[0]);
        common::use_runtime(&mut cmd, &self.runtime);
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

    /// Run `pent run --key <key> -- <argv>` and return the output.
    fn run(&self, argv: &[&str]) -> std::io::Result<Output> {
        let mut full = vec![PENT, "run", "-w", "--key", self.key, "--"];
        full.extend_from_slice(argv);
        self.command(&full).output()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The marker that each probe prints first. It is the positive control:
/// a test that asserts the absence of a secret also needs the proof that
/// the child ran. Without it a child that never started passes the test.
const RAN: &str = "PENT_CHILD_RAN";

/// Fail when the child did not run.
#[track_caller]
fn assert_child_ran(text: &str) {
    assert!(
        text.contains(RAN),
        "the child did not run, so the test proves nothing:\n{text}"
    );
}

/// The combined stdout and stderr of an output, for messages and markers.
fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// True when this host can run the sandbox.
///
/// The answer comes from `pent check`, one time, before any test runs. An
/// earlier version read the output of the test itself and skipped when it
/// held the words "Landlock" or "user namespace". A real defect of pent
/// prints those words too, so a broken sandbox passed every test in this
/// file. A guard must never read the result that it guards.
fn sandbox_ready() -> bool {
    use std::sync::OnceLock;
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        Command::new(PENT)
            .arg("check")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// Skip the test when the sandbox cannot run here. The skip prints its
/// reason, and it fails the test when `PENT_REQUIRE_ALL_TESTS` is set.
#[track_caller]
fn skip_without_sandbox() -> bool {
    if sandbox_ready() {
        return false;
    }
    assert!(
        std::env::var_os("PENT_REQUIRE_ALL_TESTS").is_none(),
        "the sandbox does not run on this host, and PENT_REQUIRE_ALL_TESTS is set"
    );
    eprintln!("SKIP: the sandbox does not run on this host");
    true
}

/// Return true and print the reason when this host gives the command no
/// private `/proc`.
///
/// A container runtime hides a part of `/proc`, and the kernel then refuses
/// a new `proc` mount. Pent runs the command there without the PID
/// namespace and says so, thus the protection of LS-3 is genuinely absent
/// and a test of it cannot hold. `PENT_REQUIRE_ALL_TESTS` does not make
/// this skip a failure: the same test must run and pass outside a
/// container.
fn skip_without_private_proc() -> bool {
    let isolation = pent_sandbox::proc_isolation();
    if isolation.is_private() {
        return false;
    }
    eprintln!(
        "SKIP (container): this host gives the command no private /proc: {}",
        isolation.warning_lines().join("; ")
    );
    true
}

/// The path of `python3`, or `None` when it is not in `PATH`.
fn python3() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
}

// ============================================================================
// Verified defenses — these tests pass; they guard the sandbox.
// ============================================================================

/// The child cannot read a file that no rule allows.
#[test]
fn test_read_outside_the_rules_denied() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let secret = h.outside.join("secret");
    std::fs::write(&secret, "SECRETDATA")?;
    let script = h.script(
        "probe.sh",
        &format!("echo PENT_CHILD_RAN\ncat '{}'\n", secret.display()),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    let text = combined(&out);
    assert!(
        !text.contains("SECRETDATA"),
        "the child read a file that no rule allows:\n{text}"
    );
    Ok(())
}

/// The child cannot write a file that no rule allows.
#[test]
fn test_write_outside_the_rules_denied() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let target = h.outside.join("written");
    let script = h.script(
        "probe.sh",
        &format!(
            "echo PENT_CHILD_RAN\necho hi > '{}'; echo rc=$?\n",
            target.display()
        ),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    assert!(
        !target.exists(),
        "the child wrote a file that no rule allows: {}",
        target.display()
    );
    Ok(())
}

/// The new network namespace blocks a connection to an abstract Unix socket
/// of a host process.
#[test]
fn test_abstract_unix_socket_blocked() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
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
            "print('PENT_CHILD_RAN')\nimport socket\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)\n\
             try:\n    s.connect('\\0{name}'); print('CONNECTED', s.recv(16))\n\
             except Exception as e:\n    print('BLOCKED', e)\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    victim.kill().ok();
    victim.wait().ok();
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    let runtime = PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
    if !runtime.is_dir() {
        eprintln!("skip: no {} on this host", runtime.display());
        return Ok(());
    }
    let probe = h.script(
        "c.py",
        &format!(
            "print('PENT_CHILD_RAN')\nimport os\n\
             try:\n    print('COUNT', len(os.listdir('{}')))\n\
             except Exception as e:\n    print('COUNT 0', e)\n",
            runtime.display()
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    let (mut victim, pid) = spawn_victim(&py, &h)?;
    let probe = h.script(
        "c.py",
        &format!(
            "print('PENT_CHILD_RAN')\nimport os\n\
             try:\n    os.kill({pid}, 0); print('SIGNAL_ALLOWED')\n\
             except Exception as e:\n    print('SIGNAL_DENIED', e)\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    victim.kill().ok();
    victim.wait().ok();
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    let (mut victim, pid) = spawn_victim(&py, &h)?;
    let probe = h.script(
        "c.py",
        &format!(
            "print('PENT_CHILD_RAN')\nimport os\nd=b''\ntry:\n    d=open('/proc/{pid}/environ','rb').read()\nexcept Exception as e:\n    print('ENVIRON_DENIED', e)\nprint('ENVIRON_SECRET' if b'TOPSECRET_ENV' in d else 'ENVIRON_EMPTY')\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    victim.kill().ok();
    victim.wait().ok();
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    let runtime = format!("/run/user/{}", unsafe { libc::getuid() });
    let probe = h.script(
        "c.py",
        &format!(
            "print('PENT_CHILD_RAN')\nimport ctypes\n\
             libc=ctypes.CDLL('libc.so.6',use_errno=True)\n\
             print('UNSHARE', libc.unshare(0x00020000))\n\
             print('UMOUNT', libc.umount2(b'{runtime}',0))\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    // fd -1: without the filter the kernel returns EBADF (9); the filter
    // returns EPERM (1) before the fd check.
    let probe = h.script(
        "c.py",
        "print('PENT_CHILD_RAN')\nimport ctypes\n\
         libc=ctypes.CDLL('libc.so.6',use_errno=True)\n\
         r=libc.ioctl(-1,0x5412,ctypes.byref(ctypes.c_char(b'x')))\n\
         print('TIOCSTI errno', ctypes.get_errno())\n",
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    // A host file under /tmp, outside the workspace, owned by this test.
    let victim = std::env::temp_dir().join(format!("pent-victim-{}", std::process::id()));
    std::fs::write(&victim, "HOST_TMP_DATA")?;
    let script = h.script(
        "probe.sh",
        &format!(
            "echo PENT_CHILD_RAN\ncat '{v}'\necho TAMPERED > '{v}'\n",
            v = victim.display()
        ),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    let after = std::fs::read_to_string(&victim).unwrap_or_default();
    let _ = std::fs::remove_file(&victim);
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
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
            "print('PENT_CHILD_RAN')\nimport socket\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)\n\
             try:\n    s.connect('{}'); print('CONNECTED', s.recv(32))\n\
             except Exception as e:\n    print('BLOCKED', e)\n",
            sock.display()
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    // Unblock the listener thread if the child never connected.
    if let Ok(s) = std::os::unix::net::UnixStream::connect(&sock) {
        drop(s);
    }
    handle.join().ok();
    let _ = std::fs::remove_file(&sock);
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
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
        "print('PENT_CHILD_RAN')\nimport os\nprint('RUN', ' '.join(sorted(os.listdir('/run'))))\n",
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let ws = std::env::temp_dir().join(format!("pent-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws)?;
    std::fs::write(ws.join("input"), "WORKSPACE_DATA")?;
    let mut cmd = h.command(&[
        PENT,
        "run",
        "-w",
        "--",
        "sh",
        "-c",
        "cat input; echo OUT > output",
    ]);
    cmd.current_dir(&ws);
    let out = cmd.output()?;
    let written = std::fs::read_to_string(ws.join("output")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&ws);
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
    if skip_without_sandbox() || skip_without_private_proc() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    let (mut victim, pid) = spawn_victim(&py, &h)?;
    let probe = h.script(
        "c.py",
        &format!(
            "print('PENT_CHILD_RAN')\nd=b''\ntry:\n    d=open('/proc/{pid}/cmdline','rb').read()\nexcept Exception as e:\n    print('CMDLINE_DENIED', e)\nprint('CMDLINE_SECRET' if b'TOPSECRET_ARG' in d else 'CMDLINE_EMPTY')\n"
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    victim.kill().ok();
    victim.wait().ok();
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let marker = h.workspace.join("alive");
    // The background process writes the marker every 200 ms for 30 s.
    let script = h.script(
        "probe.sh",
        &format!(
            "( i=0; while [ $i -lt 150 ]; do echo $i > '{}'; sleep 0.2; i=$((i+1)); done ) &\n\
             echo PENT_CHILD_RAN\n",
            marker.display()
        ),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    let text = combined(&out);
    assert!(text.contains(RAN), "the probe did not start:\n{text}");
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
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    // The exit status is the positive control: only the child can give 42.
    let script = h.script("probe.sh", "exit 42\n")?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
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
    if skip_without_sandbox() {
        return Ok(());
    }
    use std::os::unix::process::ExitStatusExt as _;
    let h = Harness::new("sh")?;
    // The signal status is the positive control: only the child can die
    // from the signal that it sends to itself.
    let script = h.script("probe.sh", "kill -TERM $$\nsleep 5\n")?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGTERM),
        "pent did not re-raise the signal of the command: {:?} {}",
        out.status,
        combined(&out)
    );
    Ok(())
}

/// LS-1: the child must not connect to a path Unix socket that no rule
/// allows. Landlock does not control `connect(2)` on a path socket, and
/// the kernel needs no file right to walk through a directory. The
/// supervisor now controls each connection: it makes a permitted
/// connection itself, and no rule here names a socket, so it refuses
/// each path.
#[test]
fn test_unix_socket_connect_outside_the_rules() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    // The victim socket is in `outside/`: no rule names it, not under /tmp.
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
            "print('PENT_CHILD_RAN')\nimport socket\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)\n\
             try:\n    s.connect('{}'); print('CONNECTED', s.recv(32))\n\
             except Exception as e:\n    print('BLOCKED', e)\n",
            sock.display()
        ),
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    assert_child_ran(&combined(&out));
    // Unblock the listener thread if the child never connected.
    if let Ok(s) = std::os::unix::net::UnixStream::connect(&sock) {
        drop(s);
    }
    handle.join().ok();
    let text = combined(&out);
    assert!(
        !text.contains("VICTIM_SECRET"),
        "LS-1: the child connected to a Unix socket that no rule allows:\n{text}"
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

// ============================================================================
// The base (step 4.1)
// ============================================================================

/// LS-4: `/dev/shm` is an empty private tmpfs. The child does not see the
/// shared memory of the host, it can write its own, and its files do not
/// reach the host.
#[test]
fn test_dev_shm_is_private() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    if !Path::new("/dev/shm").is_dir() {
        eprintln!("skip: this host has no /dev/shm");
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let pid = std::process::id();
    let victim = PathBuf::from(format!("/dev/shm/pent-victim-{pid}"));
    let made = PathBuf::from(format!("/dev/shm/pent-child-{pid}"));
    std::fs::write(&victim, "HOST_SHM_DATA")?;
    let script = h.script(
        "probe.sh",
        &format!(
            "echo PENT_CHILD_RAN\ncat '{v}'\necho TAMPERED > '{v}'\n\
             echo CHILD > '{m}' && cat '{m}' && echo SHM_WRITE_OK\n",
            v = victim.display(),
            m = made.display()
        ),
    )?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    let after = std::fs::read_to_string(&victim).unwrap_or_default();
    let leaked = made.exists();
    let _ = std::fs::remove_file(&victim);
    let _ = std::fs::remove_file(&made);
    let text = combined(&out);
    assert_child_ran(&text);
    assert!(
        text.contains("SHM_WRITE_OK"),
        "LS-4: the child cannot write in /dev/shm:\n{text}"
    );
    assert!(
        !text.contains("HOST_SHM_DATA"),
        "LS-4: the child read a host file in /dev/shm:\n{text}"
    );
    assert_eq!(
        after, "HOST_SHM_DATA",
        "LS-4: the child changed a host file"
    );
    assert!(
        !leaked,
        "LS-4: a file of the child reached /dev/shm of the host"
    );
    Ok(())
}

/// The Python `multiprocessing` module works: it needs a POSIX semaphore
/// in `/dev/shm` and the CPU files below `/sys`.
#[test]
fn test_python_multiprocessing_works() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let Some(py) = python3() else {
        eprintln!("skip: no python3");
        return Ok(());
    };
    let h = Harness::new("python3")?;
    let probe = h.script(
        "mp.py",
        "import multiprocessing as mp, os\n\
         def sq(x):\n    return x * x\n\
         if __name__ == '__main__':\n\
         \x20   print('PENT_CHILD_RAN')\n\
         \x20   lock = mp.Lock()\n\
         \x20   with mp.Pool(2) as pool:\n\
         \x20       print('POOL', pool.map(sq, [1, 2, 3]))\n\
         \x20   print('CPUS', os.cpu_count())\n",
    )?;
    let out = h.run(&[py.to_str().unwrap(), "-I", probe.to_str().unwrap()])?;
    let text = combined(&out);
    assert_child_ran(&text);
    assert!(
        text.contains("POOL [1, 4, 9]"),
        "multiprocessing fails in the sandbox:\n{text}"
    );
    assert!(
        !text.contains("CPUS None"),
        "the child cannot count the CPUs:\n{text}"
    );
    Ok(())
}

/// LS-5: the child sees a random machine identifier, a new one in each run,
/// and it cannot change it. The stage of the file is gone.
#[test]
fn test_machine_id_is_random_for_each_run() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let Ok(host) = std::fs::read_to_string("/etc/machine-id") else {
        eprintln!("skip: this host has no /etc/machine-id");
        return Ok(());
    };
    let h = Harness::new("sh")?;
    let script = h.script(
        "probe.sh",
        "echo PENT_CHILD_RAN\nprintf 'ID %s\\n' \"$(cat /etc/machine-id)\"\n\
         echo 0123 > /etc/machine-id 2>/dev/null && echo ID_WRITE_OK\n\
         ls -a /tmp /run /dev/shm | grep -q pent-machine-id && echo STAGE_LEFT\n",
    )?;
    let id_of = |out: &Output| -> Option<String> {
        combined(out)
            .lines()
            .find_map(|l| l.strip_prefix("ID ").map(str::to_owned))
    };
    let first = h.run(&["sh", script.to_str().unwrap()])?;
    let second = h.run(&["sh", script.to_str().unwrap()])?;
    let text = combined(&first);
    assert_child_ran(&text);
    let (a, b) = (id_of(&first), id_of(&second));
    assert!(
        a.is_some() && b.is_some(),
        "the child could not read /etc/machine-id:\n{text}"
    );
    let (a, b) = (a.unwrap_or_default(), b.unwrap_or_default());
    assert_ne!(
        a,
        host.trim(),
        "LS-5: the child read the machine-id of the host"
    );
    assert_ne!(a, b, "LS-5: two runs share one machine-id");
    assert!(
        a.len() == 32 && a.bytes().all(|c| c.is_ascii_hexdigit()),
        "the machine-id of the child has a bad form: {a:?}"
    );
    assert!(
        !text.contains("ID_WRITE_OK"),
        "the child changed its machine-id"
    );
    assert!(
        !text.contains("STAGE_LEFT"),
        "the stage of the machine-id stays:\n{text}"
    );
    Ok(())
}

/// The child reads the CPU files and the limits of its cgroup, and not the
/// list of the processes in the cgroup.
#[test]
fn test_cpu_and_cgroup_limits_are_readable() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
        })
        .map(|p| PathBuf::from(format!("/sys/fs/cgroup{p}")))
        .filter(|d| d.join("cgroup.procs").is_file());
    let mut body =
        String::from("echo PENT_CHILD_RAN\ncat /sys/devices/system/cpu/online && echo CPU_OK\n");
    let limit = cgroup
        .as_ref()
        .map(|d| d.join("memory.max"))
        .or_else(|| cgroup.as_ref().map(|d| d.join("cpu.max")))
        .filter(|f| f.is_file());
    if let Some(dir) = &cgroup {
        body.push_str(&format!(
            "cat '{}' >/dev/null 2>&1 && echo PROCS_OPEN\n",
            dir.join("cgroup.procs").display()
        ));
    }
    if let Some(file) = &limit {
        body.push_str(&format!(
            "cat '{}' >/dev/null && echo LIMIT_OK\n",
            file.display()
        ));
    }
    let script = h.script("probe.sh", &body)?;
    let out = h.run(&["sh", script.to_str().unwrap()])?;
    let text = combined(&out);
    assert_child_ran(&text);
    assert!(
        text.contains("CPU_OK"),
        "the child cannot read the CPU files:\n{text}"
    );
    if limit.is_some() {
        assert!(
            text.contains("LIMIT_OK"),
            "the child cannot read its cgroup limit:\n{text}"
        );
    } else {
        eprintln!("note: no cgroup v2 limit file on this host");
    }
    assert!(
        !text.contains("PROCS_OPEN"),
        "the child reads cgroup.procs:\n{text}"
    );
    Ok(())
}

/// LS-6: a directory of `PATH` outside the system paths is not in the base.
/// The child cannot run or read a program there with no rule.
#[test]
fn test_a_path_dir_outside_the_system_paths_is_not_in_the_base() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    let bin = h.outside.join("bin");
    std::fs::create_dir_all(&bin)?;
    let tool = bin.join("pent-own-tool");
    std::fs::write(&tool, "#!/bin/sh\necho OWN_TOOL_RAN\n")?;
    std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    let script = h.script(
        "probe.sh",
        &format!(
            "echo PENT_CHILD_RAN\npent-own-tool\ncat '{}' | grep -q OWN && echo TOOL_READ\n",
            tool.display()
        ),
    )?;
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = h
        .command(&[
            PENT,
            "run",
            "-w",
            "--key",
            h.key,
            "--",
            "sh",
            script.to_str().unwrap(),
        ])
        .env("PATH", path)
        .output()?;
    let text = combined(&out);
    assert_child_ran(&text);
    assert!(
        !text.contains("OWN_TOOL_RAN"),
        "LS-6: the child ran a program of a PATH directory outside the base:\n{text}"
    );
    assert!(
        !text.contains("TOOL_READ"),
        "LS-6: the child read a file of a PATH directory outside the base:\n{text}"
    );
    Ok(())
}

// ============================================================================
// The workspace flag (step 4.2)
// ============================================================================

/// LS-7: without `-w` the workspace is not in the base: the child cannot
/// read or write the working directory. `-w=DIR` gives DIR, and not the
/// working directory.
#[test]
fn test_the_workspace_is_in_the_base_only_with_the_flag() -> TestResult {
    if skip_without_sandbox() {
        return Ok(());
    }
    let h = Harness::new("sh")?;
    std::fs::write(h.workspace.join("secret"), "WORKSPACE_DATA")?;
    let other = h.base.join("other");
    std::fs::create_dir_all(&other)?;
    // The probe goes in `outside`: without `-w` the child cannot read a
    // script in the workspace.
    let probe = h.outside.join("probe.sh");
    std::fs::write(
        &probe,
        format!(
            "echo PENT_CHILD_RAN\ncat secret\necho X > made && echo WS_WRITE_OK\n\
             echo Y > '{o}/made' && echo OTHER_WRITE_OK\n",
            o = other.display()
        ),
    )?;
    let probe = probe.to_str().unwrap();
    let read_probe = format!("--read={}", h.outside.display());
    let run = |flags: &[&str]| {
        let mut argv = vec![PENT, "run", "--key", h.key];
        argv.extend_from_slice(flags);
        argv.extend_from_slice(&["--", "sh", probe]);
        h.command(&argv).output()
    };

    let bare = combined(&run(&[&read_probe])?);
    assert_child_ran(&bare);
    assert!(
        !bare.contains("WORKSPACE_DATA"),
        "LS-7: the child read the workspace:\n{bare}"
    );
    assert!(
        !bare.contains("WS_WRITE_OK"),
        "LS-7: the child wrote the workspace:\n{bare}"
    );
    assert!(!h.workspace.join("made").exists());

    let with = combined(&run(&["-w", &read_probe])?);
    assert!(with.contains("WORKSPACE_DATA"), "-w gives no read:\n{with}");
    assert!(with.contains("WS_WRITE_OK"), "-w gives no write:\n{with}");
    assert!(
        !with.contains("OTHER_WRITE_OK"),
        "-w gave another directory:\n{with}"
    );
    std::fs::remove_file(h.workspace.join("made"))?;

    let flag = format!("-w={}", other.display());
    let elsewhere = combined(&run(&[&flag, &read_probe])?);
    assert!(
        elsewhere.contains("OTHER_WRITE_OK"),
        "-w=DIR gives no write:\n{elsewhere}"
    );
    assert!(
        !elsewhere.contains("WS_WRITE_OK") && !elsewhere.contains("WORKSPACE_DATA"),
        "-w=DIR also gave the working directory:\n{elsewhere}"
    );
    Ok(())
}

/// `-w=DIR` with a path that is not a directory stops the run before the
/// command starts, and the message names the path.
#[test]
fn test_a_workspace_that_is_not_a_directory_stops_the_run() -> TestResult {
    let h = Harness::new("sh")?;
    let file = h.outside.join("file");
    std::fs::write(&file, "x")?;
    let flag = format!("-w={}", file.display());
    let marker = h.outside.join("ran");
    let script = format!("touch '{}'", marker.display());
    let out = h
        .command(&[
            PENT, "run", "--key", h.key, &flag, "--", "sh", "-c", &script,
        ])
        .output()?;
    assert!(!out.status.success());
    let text = combined(&out);
    assert!(text.contains(&file.display().to_string()), "{text}");
    assert!(!marker.exists(), "the command started");
    Ok(())
}
