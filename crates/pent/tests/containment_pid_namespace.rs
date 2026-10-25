//! Containment tests: the PID namespace of the Linux sandbox.
//!
//! `README.md` ("Processes") and `docs/security/linux-sandbox.md` (LS-3)
//! claim five properties:
//!
//! 1. The child sees only the processes of the sandbox.
//! 2. The exit code and the signal of the command reach the caller
//!    unchanged.
//! 3. No background process of the sandbox outlives `pent run`.
//! 4. A process of the sandbox cannot signal a process of the host.
//! 5. Pent sends `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` to the
//!    command.
//!
//! Each test states one property, and each test that asserts an absence
//! also proves in the same run that the child ran and that a permitted
//! action worked.
//!
//! The tests need unprivileged user namespaces, Landlock and `python3`.
//! They print `SKIP <test>: <reason>` and pass when the host cannot run
//! them. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.
//!
//! A container gives no private `/proc`, thus no PID namespace: the kernel
//! refuses the mount (see `private_proc_ready`). Property 1, and the
//! promptness of the exit code, need the namespace, so those two tests
//! print `SKIP (container)` there. The other properties hold without it.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a setup failure must abort loudly

mod common;

use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::e2e::{
    have_tools, private_proc_ready, sandbox_ready, stderr, stdout, TestEnv, TestResult,
};

/// The marker that each probe prints first.
const RAN: &str = "PENT_CHILD_RAN";

/// An empty profile: the sandbox defaults and nothing more.
const EMPTY: &str = "[filesystem]\nread = []\n";

fn ready(test: &str) -> bool {
    have_tools(test, &["sh", "python3"]) && sandbox_ready(test)
}

fn text(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

#[track_caller]
fn assert_ran(out: &Output) -> String {
    let all = text(out);
    assert!(
        all.contains(RAN),
        "the child did not run, so the test proves nothing:\n{all}"
    );
    all
}

/// Wait up to five seconds for `path` to appear.
fn wait_for(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    path.exists()
}

/// A host process of the same user. It writes its own PID to `pid_file`
/// and then changes `beat` every 100 milliseconds, so a test can see that
/// it still runs.
struct HostVictim {
    child: Child,
    /// The PID of the victim in the PID namespace of the test.
    pid: u32,
    /// The file that the victim changes while it runs.
    beat: PathBuf,
}

impl HostVictim {
    fn start(
        env: &TestEnv,
        python: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let pid_file = env.root.join("victim.pid");
        let beat = env.root.join("victim.beat");
        let src = format!(
            "import os, time\n\
             open({p:?},'w').write(str(os.getpid()))\n\
             for i in range(600):\n\
             \x20   open({b:?},'w').write(str(i))\n\
             \x20   time.sleep(0.1)\n",
            p = pid_file.display().to_string(),
            b = beat.display().to_string(),
        );
        let child = Command::new(python)
            .arg("-I")
            .arg("-c")
            .arg(&src)
            .arg("PENT_VICTIM_ARGUMENT")
            .env("PENT_VICTIM_ENVIRONMENT", "1")
            .stdin(Stdio::null())
            .spawn()?;
        if !wait_for(&pid_file) {
            return Err("the host victim did not start".into());
        }
        let pid = std::fs::read_to_string(&pid_file)?
            .trim()
            .parse()
            .unwrap_or_else(|_| child.id());
        Ok(Self { child, pid, beat })
    }

    /// True when the victim still runs.
    ///
    /// The first test is the wait status: a victim that a signal ended
    /// has one. The second test is the file that the victim changes
    /// every 100 milliseconds. A loaded machine makes the victim slow,
    /// so the wait is 30 seconds, not one step.
    fn still_runs(&mut self) -> bool {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return false;
        }
        let first = std::fs::read_to_string(&self.beat).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return false;
            }
            if std::fs::read_to_string(&self.beat).unwrap_or_default() != first {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for HostVictim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write the script of a background process that changes `beat` every
/// 100 milliseconds for 30 seconds. Return the path of the script.
fn write_beat(env: &TestEnv, beat: &Path) -> std::io::Result<PathBuf> {
    let path = env.ws.join("beat.sh");
    std::fs::write(
        &path,
        format!(
            "i=0\nwhile [ $i -lt 300 ]; do\n  echo $i > '{b}'\n  sleep 0.1\n  i=$((i+1))\ndone\n",
            b = beat.display()
        ),
    )?;
    Ok(path)
}

/// The path of `python3`.
fn python3() -> PathBuf {
    common::e2e::which("python3").unwrap_or_else(|| PathBuf::from("python3"))
}

// ── Property 1: the child sees only the processes of the sandbox ────────────

/// The child sees only the processes of the sandbox. A host process of
/// the same user is not in `/proc`, so its command line stays private.
#[test]
fn the_child_sees_only_the_processes_of_the_sandbox() -> TestResult {
    let test = "the_child_sees_only_the_processes_of_the_sandbox";
    if !ready(test) || !private_proc_ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let python = python3();
    let mut victim = HostVictim::start(&env, &python)?;
    env.install_profile("python3", EMPTY)?;
    let script = format!(
        "import os\n\
         print('{RAN}')\n\
         pids = sorted(int(p) for p in os.listdir('/proc') if p.isdigit())\n\
         print('PIDS', pids)\n\
         print('SELF', os.getpid(), os.getpid() in pids)\n\
         for name in ('cmdline', 'environ', 'comm'):\n\
         \x20   try:\n\
         \x20       print(name, open('/proc/{v}/' + name, 'rb').read()[:80])\n\
         \x20   except OSError as e:\n\
         \x20       print(name, 'ERR', e.errno)\n",
        v = victim.pid
    );
    let out = env.pent(&[
        "run",
        "--profile",
        "python3",
        "--",
        "python3",
        "-I",
        "-c",
        &script,
    ])?;
    let all = assert_ran(&out);
    // The positive control: the child sees itself, and the victim still
    // runs on the host, so its absence in /proc is the work of pent.
    assert!(
        all.contains("SELF")
            && all
                .lines()
                .any(|l| l.starts_with("SELF ") && l.ends_with("True")),
        "the child did not see its own process:\n{all}"
    );
    assert!(
        victim.still_runs(),
        "the host victim stopped, so the test proves nothing"
    );
    for marker in ["PENT_VICTIM_ARGUMENT", "PENT_VICTIM_ENVIRONMENT"] {
        assert!(
            !all.contains(marker),
            "the child read {marker} of a host process:\n{all}"
        );
    }
    let line = all
        .lines()
        .find(|l| l.starts_with("PIDS "))
        .ok_or("the child could not list /proc")?;
    assert!(
        !line.contains(&victim.pid.to_string()),
        "the child saw the PID of a host process: {line}\n{all}"
    );
    // The namespace starts at 1 and holds only the processes of the run.
    let count = line.matches(',').count() + 1;
    assert!(
        count < 16,
        "the child saw {count} processes, so this is not a private proc: {line}"
    );
    Ok(())
}

// ── Property 2: the status of the command reaches the caller ───────────────

/// The exit code of the command reaches the caller unchanged, through the
/// stub and through PID 1 of the namespace.
#[test]
fn the_exit_code_of_the_command_reaches_the_caller() -> TestResult {
    let test = "the_exit_code_of_the_command_reaches_the_caller";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("sh", EMPTY)?;
    for code in [0, 1, 7, 42, 127, 255] {
        let out = env.pent(&[
            "run",
            "--profile",
            "sh",
            "--",
            "sh",
            "-c",
            &format!("echo {RAN}; exit {code}"),
        ])?;
        let all = assert_ran(&out);
        assert_eq!(
            out.status.code(),
            Some(code),
            "pent did not report the exit code {code}:\n{all}"
        );
    }
    Ok(())
}

/// A signal that ends the command ends pent with the same signal. PID 1
/// of a namespace cannot end itself with a signal, so the status travels
/// through a pipe to the stub.
#[test]
fn each_signal_of_the_command_reaches_the_caller() -> TestResult {
    let test = "each_signal_of_the_command_reaches_the_caller";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("python3", EMPTY)?;
    let signals = [
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGPIPE,
        libc::SIGALRM,
        libc::SIGABRT,
        libc::SIGSEGV,
    ];
    for sig in signals {
        let out = kill_self_under_pent(&env, sig)?;
        let all = assert_ran(&out);
        assert_eq!(
            out.status.signal(),
            Some(sig),
            "pent did not re-raise the signal {sig}: {:?}\n{all}",
            out.status
        );
    }
    Ok(())
}

/// `SIGKILL` of the command must reach the caller like each other signal.
///
/// Pent reports the exit code 137 instead. `exit_like_child` in
/// `crates/pent/src/commands/session.rs` calls `signal(sig, SIG_DFL)`
/// first and raises the signal only when that call works. `SIGKILL` and
/// `SIGSTOP` always keep the default action, so the call gives `SIG_ERR`
/// and pent never raises the signal. The chain of the PID namespace is
/// correct: the stub does die from `SIGKILL`.
#[test]
fn sigkill_of_the_command_reaches_the_caller() -> TestResult {
    let test = "sigkill_of_the_command_reaches_the_caller";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("python3", EMPTY)?;
    let out = kill_self_under_pent(&env, libc::SIGKILL)?;
    let all = assert_ran(&out);
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGKILL),
        "pent did not re-raise SIGKILL: {:?}\n{all}",
        out.status
    );
    Ok(())
}

/// Run a command under pent that ends itself with `sig`.
fn kill_self_under_pent(env: &TestEnv, sig: libc::c_int) -> std::io::Result<Output> {
    let script = format!(
        "import os, signal, time\n\
         print('{RAN}', flush=True)\n\
         if {sig} not in (signal.SIGKILL, signal.SIGSTOP):\n\
         \x20   signal.signal({sig}, signal.SIG_DFL)\n\
         os.kill(os.getpid(), {sig})\n\
         time.sleep(5)\n"
    );
    env.pent(&[
        "run",
        "--profile",
        "python3",
        "--",
        "python3",
        "-I",
        "-c",
        &script,
    ])
}

/// The command exits while a grandchild still runs. The exit code of the
/// command still reaches the caller, and pent does not wait for the
/// grandchild.
#[test]
fn the_exit_code_passes_while_a_grandchild_still_runs() -> TestResult {
    let test = "the_exit_code_passes_while_a_grandchild_still_runs";
    // Without the PID namespace, pent is the subreaper of the orphans of
    // the command, and the teardown waits for them. The exit code then
    // comes after the grandchild, not before it.
    if !ready(test) || !private_proc_ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("sh", EMPTY)?;
    let script = format!("echo {RAN}; ( sleep 60 ) & setsid sh -c 'sleep 60' & exit 7");
    let start = Instant::now();
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let took = start.elapsed();
    let all = assert_ran(&out);
    assert_eq!(
        out.status.code(),
        Some(7),
        "pent did not report the exit code of the command:\n{all}"
    );
    assert!(
        took < Duration::from_secs(45),
        "pent waited {took:?} for a grandchild of the command; \
         the budget of this test is 45 seconds and the grandchild sleeps 60"
    );
    Ok(())
}

/// A signal that ends the command reaches the caller while a grandchild
/// still runs.
#[test]
fn the_signal_passes_while_a_grandchild_still_runs() -> TestResult {
    let test = "the_signal_passes_while_a_grandchild_still_runs";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("sh", EMPTY)?;
    let script = format!("echo {RAN}; setsid sh -c 'sleep 60' & kill -TERM $$; sleep 10");
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGTERM),
        "pent did not re-raise the signal of the command: {:?}\n{all}",
        out.status
    );
    Ok(())
}

// ── Property 3: no process of the session survives ─────────────────────────

/// No process of the session survives the end of the run, also when the
/// command exits at once and a grandchild stays.
#[test]
fn no_process_of_the_session_survives_the_run() -> TestResult {
    let test = "no_process_of_the_session_survives_the_run";
    if !ready(test) {
        return Ok(());
    }
    for (name, body) in [
        // A direct background child of the command.
        ("background", "sh BEAT &"),
        // A grandchild in its own session, orphaned at once.
        ("setsid", "setsid sh BEAT &"),
        // A double fork, the classic way to make a daemon.
        ("double-fork", "( sh BEAT & ) &"),
    ] {
        let env = TestEnv::new()?;
        env.install_profile("sh", EMPTY)?;
        let beat = env.ws.join("beat");
        let beat_script = write_beat(&env, &beat)?;
        let script = format!(
            "echo {RAN}; {start} sleep 0.5; exit 0",
            start = body.replace("BEAT", &format!("'{}'", beat_script.display()))
        );
        let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
        let all = assert_ran(&out);
        // The positive control: the background process really started.
        assert!(
            beat.exists(),
            "the {name} process never started, so the test proves nothing:\n{all}"
        );
        assert!(
            quiet_for(&beat, Duration::from_secs(5)),
            "a {name} process of the sandbox still changed its file \
             during the 5 seconds after pent exited"
        );
    }
    Ok(())
}

/// Watch `path` for `window` and return true when its content never
/// changed. A background process of the test writes the file every 100
/// milliseconds, so a window of several seconds holds also on a loaded
/// machine.
fn quiet_for(path: &Path, window: Duration) -> bool {
    // Let the last write of a process that the kernel just ended land.
    std::thread::sleep(Duration::from_millis(500));
    let first = std::fs::read_to_string(path).unwrap_or_default();
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if std::fs::read_to_string(path).unwrap_or_default() != first {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// The command exits at once while a grandchild stays. The kernel ends
/// the whole namespace when PID 1 exits.
#[test]
fn a_grandchild_does_not_outlive_a_command_that_exits_at_once() -> TestResult {
    let test = "a_grandchild_does_not_outlive_a_command_that_exits_at_once";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("sh", EMPTY)?;
    let beat = env.ws.join("beat");
    let beat_script = write_beat(&env, &beat)?;
    // The command waits until the grandchild wrote its file one time, so
    // that the positive control is sure, and then it exits at once.
    let script = format!(
        "echo {RAN}; setsid sh '{b}' & while [ ! -f '{beat}' ]; do sleep 0.05; done; exec true",
        b = beat_script.display(),
        beat = beat.display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    assert!(
        beat.exists(),
        "the grandchild never started, so the test proves nothing:\n{all}"
    );
    assert!(
        quiet_for(&beat, Duration::from_secs(5)),
        "a grandchild of the sandbox still changed its file during the \
         5 seconds after pent exited"
    );
    Ok(())
}

// ── Property 4: no signal to a process of the host ─────────────────────────

/// A process of the sandbox cannot signal a process of the host, by its
/// PID, by its process group, or by a broadcast.
#[test]
fn a_process_of_the_sandbox_cannot_signal_a_process_of_the_host() -> TestResult {
    let test = "a_process_of_the_sandbox_cannot_signal_a_process_of_the_host";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let python = python3();
    let mut victim = HostVictim::start(&env, &python)?;
    env.install_profile("python3", EMPTY)?;
    let script = format!(
        "import os, signal, time\n\
         print('{RAN}')\n\
         # The positive control: a signal to a process of the sandbox works.\n\
         pid = os.fork()\n\
         if pid == 0:\n\
         \x20   time.sleep(30)\n\
         \x20   os._exit(0)\n\
         os.kill(pid, signal.SIGKILL)\n\
         print('OWN', os.waitpid(pid, 0)[1])\n\
         for tag, target in (('PID', {v}), ('GROUP', -{v}), ('ALL', -1)):\n\
         \x20   try:\n\
         \x20       os.kill(target, signal.SIGKILL)\n\
         \x20       print(tag, 'SENT')\n\
         \x20   except OSError as e:\n\
         \x20       print(tag, 'ERR', e.errno)\n",
        v = victim.pid
    );
    let out = env.pent(&[
        "run",
        "--profile",
        "python3",
        "--",
        "python3",
        "-I",
        "-c",
        &script,
    ])?;
    let all = assert_ran(&out);
    assert!(
        all.contains("OWN 9"),
        "the child could not signal its own process, so the test proves nothing:\n{all}"
    );
    assert!(
        victim.still_runs(),
        "a process of the sandbox ended a process of the host:\n{all}"
    );
    Ok(())
}

// ── Property 5: pent forwards its signals to the command ───────────────────

/// Pent sends `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` to the
/// command. Each supervisor of the PID namespace passes them on.
#[test]
fn pent_forwards_its_signals_to_the_command() -> TestResult {
    let test = "pent_forwards_its_signals_to_the_command";
    if !ready(test) {
        return Ok(());
    }
    for (name, sig) in [
        ("TERM", libc::SIGTERM),
        ("HUP", libc::SIGHUP),
        ("USR1", libc::SIGUSR1),
        ("USR2", libc::SIGUSR2),
    ] {
        let env = TestEnv::new()?;
        env.install_profile("sh", EMPTY)?;
        let ready_file = env.ws.join("ready");
        let got = env.ws.join("got");
        let script = format!(
            "trap 'echo {name} > \"{g}\"; exit 9' {name}; echo {RAN}; echo y > \"{r}\"; \
             i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done",
            g = got.display(),
            r = ready_file.display()
        );
        let child = env
            .command(&["run", "--profile", "sh", "--", "sh", "-c", &script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        assert!(
            wait_for(&ready_file),
            "the command of the {name} run did not start"
        );
        let pid = i32::try_from(child.id()).unwrap_or(-1);
        // SAFETY: kill(2) with a PID of a child of this process.
        unsafe { libc::kill(pid, sig) };
        let out = child.wait_with_output()?;
        let all = assert_ran(&out);
        assert_eq!(
            std::fs::read_to_string(&got).unwrap_or_default().trim(),
            name,
            "pent did not forward SIG{name} to the command:\n{all}"
        );
        assert_eq!(
            out.status.code(),
            Some(9),
            "pent did not report the exit code after SIG{name}:\n{all}"
        );
    }
    Ok(())
}
