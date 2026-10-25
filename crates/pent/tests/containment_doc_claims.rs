//! Containment tests: the limits that `README.md` and `docs/security/`
//! claim and that no other file of this suite holds.
//!
//! Each test names the sentence that it states. A sentence that the
//! sandbox does not keep gets a test with `#[ignore = "OPEN CT-..."]`
//! and an entry in `docs/security/containment.md`.
//!
//! The tests need unprivileged user namespaces, Landlock and `python3`.
//! They print `SKIP <test>: <reason>` and pass when the host cannot run
//! them. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a setup failure must abort loudly

mod common;

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use common::e2e::{have_tools, sandbox_ready, stderr, stdout, TestEnv, TestResult};

/// The marker that each probe prints first.
const RAN: &str = "PENT_CHILD_RAN";

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

/// Wait up to `secs` seconds for `path` to appear. Returns the time that
/// the wait took.
fn wait_for(path: &Path, secs: u64) -> Option<Duration> {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    while !path.exists() {
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(start.elapsed())
}

// ── README: the terminal ───────────────────────────────────────────────────

/// "A seccomp filter blocks `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`, so
/// the process cannot push keystrokes into your shell." (README)
#[test]
fn the_filter_blocks_tiocsti_and_tioclinux() -> TestResult {
    let test = "the_filter_blocks_tiocsti_and_tioclinux";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("python3", "[filesystem]\nread = []\n")?;
    // The descriptor -1 is the control: without the filter the kernel
    // gives EBADF (9); the filter gives EPERM (1) before that check.
    let script = format!(
        "import ctypes\n\
         print('{RAN}')\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         b = ctypes.create_string_buffer(8)\n\
         for tag, req in (('TIOCSTI', 0x5412), ('TIOCLINUX', 0x541C), ('TIOCGWINSZ', 0x5413)):\n\
         \x20   ctypes.set_errno(0)\n\
         \x20   r = libc.ioctl(-1, req, b)\n\
         \x20   print(tag, r, ctypes.get_errno())\n"
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
    // The positive control: an ioctl that the filter does not trap still
    // reaches the kernel and gives EBADF.
    assert!(
        all.contains(&format!("TIOCGWINSZ -1 {}", libc::EBADF)),
        "an ioctl that the filter does not trap did not reach the kernel, \
         so the test proves nothing:\n{all}"
    );
    for tag in ["TIOCSTI", "TIOCLINUX"] {
        assert!(
            all.contains(&format!("{tag} -1 {}", libc::EPERM)),
            "the filter did not block {tag} with EPERM:\n{all}"
        );
    }
    Ok(())
}

// ── README: the workspace ──────────────────────────────────────────────────

/// "Pent makes `<workspace>/.pent` read-only inside the sandbox."
/// (README)
#[test]
fn the_dot_pent_directory_of_the_workspace_is_read_only() -> TestResult {
    let test = "the_dot_pent_directory_of_the_workspace_is_read_only";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    std::fs::create_dir_all(env.ws.join(".pent"))?;
    std::fs::write(env.ws.join(".pent/keep"), "PENT_DOT_PENT_DATA")?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    let script = format!(
        "echo {RAN}; cat .pent/keep; echo; \
         echo EVIL > .pent/new 2>&1; echo NEW rc=$?; \
         echo EVIL > .pent/keep 2>&1; echo OVER rc=$?; \
         echo OK > plain.txt; echo PLAIN rc=$?"
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    // The positive control: the workspace itself is read-write.
    assert!(
        all.contains("PLAIN rc=0") && env.ws.join("plain.txt").exists(),
        "a write in the workspace failed, so the test proves nothing:\n{all}"
    );
    assert!(
        all.contains("PENT_DOT_PENT_DATA"),
        "the child could not read <workspace>/.pent:\n{all}"
    );
    assert!(
        !env.ws.join(".pent/new").exists(),
        "the child made a file in <workspace>/.pent:\n{all}"
    );
    assert_eq!(
        std::fs::read_to_string(env.ws.join(".pent/keep"))?,
        "PENT_DOT_PENT_DATA",
        "the child changed a file in <workspace>/.pent"
    );
    Ok(())
}

// ── README: the process tree ───────────────────────────────────────────────

/// "A profile covers the full process tree: when `claude` starts `git`,
/// `git` gets the rules of the `claude` profile." (README)
#[test]
fn the_profile_covers_the_full_process_tree() -> TestResult {
    let test = "the_profile_covers_the_full_process_tree";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let secret = env.root.join("outside-secret");
    std::fs::write(&secret, "PENT_OUTSIDE_SECRET")?;
    std::fs::write(env.ws.join("allowed.txt"), "PENT_ALLOWED_DATA")?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    // Three levels deep, and the last level is a different program.
    let deep = env.ws.join("deep.py");
    std::fs::write(
        &deep,
        format!(
            "try:\n\
             \x20   print(open({s:?}).read())\n\
             except OSError as e:\n\
             \x20   print('DEEP ERR', e.errno)\n",
            s = secret.display().to_string()
        ),
    )?;
    let inner = env.ws.join("inner.sh");
    std::fs::write(
        &inner,
        format!("cat allowed.txt\npython3 -I '{d}'\n", d = deep.display()),
    )?;
    let script = format!("echo {RAN}; sh -c \"sh '{i}'\"", i = inner.display());
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    assert!(
        all.contains("PENT_ALLOWED_DATA"),
        "the grandchild did not run, so the test proves nothing:\n{all}"
    );
    assert!(
        !all.contains("PENT_OUTSIDE_SECRET"),
        "a process below the command read a file outside the profile:\n{all}"
    );
    assert!(
        all.contains(&format!("DEEP ERR {}", libc::EACCES)),
        "the deep process did not get EACCES:\n{all}"
    );
    Ok(())
}

// ── README: the signals of the terminal ────────────────────────────────────

/// "Pent ignores SIGINT and SIGQUIT while the child runs: the terminal
/// sends these signals to the child directly." (README) A process group
/// holds its members across a PID namespace, so the command gets the
/// signal and pent waits for it.
#[test]
fn pent_ignores_sigint_and_lets_the_command_see_it() -> TestResult {
    let test = "pent_ignores_sigint_and_lets_the_command_see_it";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    let ready_file = env.ws.join("ready");
    let got = env.ws.join("got");
    let script = format!(
        "trap 'echo INT > \"{g}\"' INT; echo {RAN}; echo y > \"{r}\"; \
         i=0; while [ $i -lt 600 ] && [ ! -f \"{g}\" ]; do sleep 0.1; i=$((i+1)); done; \
         sleep 0.2; exit 5",
        g = got.display(),
        r = ready_file.display()
    );
    let child = env
        .command(&["run", "--profile", "sh", "--", "sh", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let waited = wait_for(&ready_file, 60);
    assert!(
        waited.is_some(),
        "the command did not start within 60 seconds, so the test proves nothing"
    );
    let pid = i32::try_from(child.id()).unwrap_or(-1);
    // The terminal sends the signal to the whole process group.
    // SAFETY: kill(2) with the group of a child of this process.
    unsafe { libc::kill(-pid, libc::SIGINT) };
    let out = child.wait_with_output()?;
    let all = assert_ran(&out);
    assert_eq!(
        std::fs::read_to_string(&got).unwrap_or_default().trim(),
        "INT",
        "the command never saw SIGINT, so the test proves nothing:\n{all}"
    );
    assert_eq!(
        out.status.code(),
        Some(5),
        "pent did not wait for the command after SIGINT: {:?}\n{all}",
        out.status
    );
    Ok(())
}

// ── linux-sandbox.md (LS-2): the modes of the private directories ──────────

/// "`/tmp` and `/var/tmp` keep the mode `1777`; `/run` keeps `0755`."
/// (`docs/security/linux-sandbox.md`, LS-2)
#[test]
fn the_private_directories_keep_their_modes() -> TestResult {
    let test = "the_private_directories_keep_their_modes";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    let out = env.pent(&[
        "run",
        "--profile",
        "sh",
        "--",
        "sh",
        "-c",
        &format!("echo {RAN}; stat -c '%n %a' /tmp /var/tmp /run"),
    ])?;
    let all = assert_ran(&out);
    for (dir, mode) in [("/tmp", "1777"), ("/var/tmp", "1777"), ("/run", "755")] {
        assert!(
            all.contains(&format!("{dir} {mode}")),
            "the mode of {dir} is not {mode}:\n{all}"
        );
    }
    Ok(())
}

/// "Pent binds back only what the session needs: ... every directory of
/// `PATH` ..." (README) A tool in a `PATH` directory below `/tmp` still
/// runs.
#[test]
fn a_path_directory_below_a_private_directory_comes_back() -> TestResult {
    let test = "a_path_directory_below_a_private_directory_comes_back";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let dir = std::env::temp_dir().join(format!("pent-ct-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let tool = dir.join("pent-ct-tool");
    std::fs::write(&tool, "#!/bin/sh\necho PENT_TOOL_RAN\n")?;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))?;
    // A sibling of the PATH directory must stay hidden.
    let sibling = std::env::temp_dir().join(format!("pent-ct-bin-{}-other", std::process::id()));
    let _ = std::fs::remove_dir_all(&sibling);
    std::fs::create_dir_all(&sibling)?;
    std::fs::write(sibling.join("secret"), "PENT_SIBLING_SECRET")?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = env
        .command(&[
            "run",
            "--profile",
            "sh",
            "--",
            "sh",
            "-c",
            &format!(
                "echo {RAN}; pent-ct-tool; cat '{s}/secret' 2>&1",
                s = sibling.display()
            ),
        ])
        .env("PATH", &path)
        .output()?;
    let all = assert_ran(&out);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&sibling);
    assert!(
        all.contains("PENT_TOOL_RAN"),
        "a tool in a PATH directory below /tmp did not run:\n{all}"
    );
    assert!(
        !all.contains("PENT_SIBLING_SECRET"),
        "the bind of the PATH directory brought its sibling back:\n{all}"
    );
    Ok(())
}

// ── README: a socket of the mask list that the configuration names ─────────

/// `pent run --unix-socket PATH` works for a socket that the mask list
/// covers. The supervisor connects from the host, so the mask does not
/// stop it.
#[test]
fn a_named_agent_socket_still_works_behind_the_mask() -> TestResult {
    let test = "a_named_agent_socket_still_works_behind_the_mask";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let agent = agent_socket(&env)?;
    env.install_profile("python3", "[filesystem]\nread = []\n")?;
    let script = format!(
        "import socket\n\
         print('{RAN}')\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)\n\
         try:\n\
         \x20   s.connect({a:?}); print('DATA', s.recv(32).decode())\n\
         except OSError as e:\n\
         \x20   print('ERR', e.errno)\n",
        a = agent.display().to_string()
    );
    let out = env.pent(&[
        "run",
        "--profile",
        "python3",
        "--unix-socket",
        agent.to_str().ok_or("the socket path is not UTF-8")?,
        "--",
        "python3",
        "-I",
        "-c",
        &script,
    ])?;
    let all = assert_ran(&out);
    assert!(
        all.contains("PENT_AGENT_OK"),
        "pent did not connect to the agent socket that the run names:\n{all}"
    );
    Ok(())
}

/// "If your configuration names one of these paths, Pent does not hide
/// it." (README, about the sockets that pent covers with `/dev/null`)
///
/// A path rule keeps the claim. A name in `filesystem.unix_sockets`, or
/// `pent run --unix-socket PATH`, does not: `configured_paths` in
/// `crates/pent-sandbox/src/linux.rs` does not hold the Unix socket
/// list, so pent still binds `/dev/null` over the socket. The connection
/// works, because the supervisor connects from the host, but a program
/// that reads the kind of the file first does not try the connection.
#[test]
#[ignore = "OPEN CT-4: a socket that only `unix_sockets` names stays covered with /dev/null"]
fn a_socket_that_the_configuration_names_is_not_hidden() -> TestResult {
    let test = "a_socket_that_the_configuration_names_is_not_hidden";
    if !ready(test) {
        return Ok(());
    }
    // A path rule: the claim holds.
    let env = TestEnv::new()?;
    let agent = agent_socket(&env)?;
    env.install_profile(
        "python3",
        &format!("[filesystem]\nread = [{:?}]\n", agent.display().to_string()),
    )?;
    let all = assert_ran(&kind_of(&env, &agent, &[])?);
    assert!(
        all.contains("KIND True"),
        "a path rule did not stop the mask, so the test proves nothing:\n{all}"
    );

    // A name in `unix_sockets`: the claim must hold too.
    let env = TestEnv::new()?;
    let agent = agent_socket(&env)?;
    env.install_profile(
        "python3",
        &format!(
            "[filesystem]\nunix_sockets = [{:?}]\n",
            agent.display().to_string()
        ),
    )?;
    let all = assert_ran(&kind_of(&env, &agent, &[])?);
    assert!(
        all.contains("KIND True"),
        "pent covered a socket that `unix_sockets` names:\n{all}"
    );

    // The flag of one run: the claim must hold too.
    let env = TestEnv::new()?;
    let agent = agent_socket(&env)?;
    env.install_profile("python3", "[filesystem]\nread = []\n")?;
    let flag = agent.to_str().ok_or("the socket path is not UTF-8")?;
    let all = assert_ran(&kind_of(&env, &agent, &["--unix-socket", flag])?);
    assert!(
        all.contains("KIND True"),
        "pent covered a socket that `--unix-socket` names:\n{all}"
    );
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Make `~/.gnupg/S.gpg-agent` in the home directory of `env` and serve
/// `PENT_AGENT_OK` on it. The path is on the mask list of pent.
fn agent_socket(env: &TestEnv) -> std::io::Result<PathBuf> {
    let dir = env.home.join(".gnupg");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("S.gpg-agent");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.write_all(b"PENT_AGENT_OK");
        }
    });
    Ok(path)
}

/// Run a child that prints `KIND True` when `path` is still a socket in
/// the view of the sandbox.
fn kind_of(env: &TestEnv, path: &Path, extra: &[&str]) -> std::io::Result<Output> {
    let script = format!(
        "import os, stat\n\
         print('{RAN}')\n\
         print('KIND', stat.S_IFMT(os.stat({p:?}).st_mode) == stat.S_IFSOCK)\n",
        p = path.display().to_string()
    );
    let mut args = vec!["run", "--profile", "python3"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "python3", "-I", "-c", &script]);
    env.pent(&args)
}
