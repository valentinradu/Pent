//! Containment tests: the guard of watch mode and the recorder that the
//! supervisor feeds.
//!
//! `docs/design/watch.md` says: "The guard blocks a small set of
//! dangerous accesses. The kernel enforces it, so the program cannot race
//! it." `docs/security/watch-and-profiles.md` (Property 4) and
//! `docs/security/linux-sandbox.md` (H-13) say that the Linux mounts now
//! cover a file at any depth below the directory of a rule.
//!
//! The tests state two properties:
//!
//! 1. What the summary reports and what the kernel enforces agree.
//! 2. A file that the guard hides is not readable by any route: through a
//!    second path, through a symbolic link, through `/proc/self/root`,
//!    through a nested user namespace, and through a descriptor that the
//!    child inherits.
//!
//! Each test that asserts a refusal also proves in the same run that the
//! child ran and that a permitted access worked.
//!
//! The tests need unprivileged user namespaces, Landlock and `python3`.
//! They print `SKIP <test>: <reason>` and pass when the host cannot run
//! them. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a setup failure must abort loudly

mod common;

use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Output, Stdio};

use common::e2e::{
    have_tools, private_proc_ready, sandbox_ready, stderr, stdout, TestEnv, TestResult,
};

/// The marker that each probe prints first.
const RAN: &str = "PENT_CHILD_RAN";

/// The content of the credential that the guard must hide.
const KEY_SECRET: &str = "PENT_KEY_SECRET";

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

/// Run `pent watch` with the profile `probe` and a closed network, so
/// that the test needs no name server.
fn watch(env: &TestEnv, argv: &[&str]) -> std::io::Result<Output> {
    let mut args = vec![
        "watch",
        "--yes",
        "--network",
        "blocked",
        "--profile",
        "probe",
        "--",
    ];
    args.extend_from_slice(argv);
    env.pent(&args)
}

/// Make the home directory of a watch run: an SSH key at the top of
/// `~/.ssh`, one in a subdirectory, a shell start file, and a file that
/// no rule covers.
fn make_home(env: &TestEnv) -> std::io::Result<()> {
    env.write_home(".ssh/id_ed25519", KEY_SECRET)?;
    env.write_home(".ssh/keys/id_ed25519", "PENT_SUBKEY_SECRET")?;
    env.write_home(".ssh/known_hosts", "PENT_KNOWN_HOSTS")?;
    env.write_home(".bashrc", "PENT_ORIGINAL_RC")?;
    Ok(())
}

// ── Property 1: the summary and the kernel agree ───────────────────────────

/// The guard blocks the read of a credential and the write of a shell
/// start file, and the summary reports exactly what the kernel did.
#[test]
fn the_summary_and_the_kernel_agree_on_the_blocked_accesses() -> TestResult {
    let test = "the_summary_and_the_kernel_agree_on_the_blocked_accesses";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    make_home(&env)?;
    let key = env.home_path(".ssh/id_ed25519");
    let subkey = env.home_path(".ssh/keys/id_ed25519");
    let known = env.home_path(".ssh/known_hosts");
    let rc = env.home_path(".bashrc");
    let script = format!(
        "echo {RAN}; \
         echo KEY \"$(cat '{k}' 2>&1)\"; \
         echo SUBKEY \"$(cat '{s}' 2>&1)\"; \
         echo KNOWN \"$(cat '{n}' 2>&1)\"; \
         echo EVIL >> '{r}' 2>&1; echo RC rc=$?",
        k = key.display(),
        s = subkey.display(),
        n = known.display(),
        r = rc.display()
    );
    let out = watch(&env, &["sh", "-c", &script])?;
    let all = assert_ran(&out);
    // The positive control: a file in the same directory that no rule
    // covers stays readable, and the program really ran.
    assert!(
        all.contains("PENT_KNOWN_HOSTS"),
        "the program could not read a file that no rule covers, \
         so the test proves nothing:\n{all}"
    );
    // The kernel.
    assert!(
        !all.contains(KEY_SECRET),
        "the kernel did not hide the SSH key:\n{all}"
    );
    assert!(
        !all.contains("PENT_SUBKEY_SECRET"),
        "the kernel did not hide the SSH key of the subdirectory:\n{all}"
    );
    assert_eq!(
        std::fs::read_to_string(&rc)?,
        "PENT_ORIGINAL_RC",
        "the kernel did not stop the write to the shell start file"
    );
    // The summary.
    let events = env.watch_events("probe");
    for (path, class) in [
        (key.display().to_string(), "credential"),
        (subkey.display().to_string(), "credential"),
        (rc.display().to_string(), "persistence"),
    ] {
        let line = events
            .lines()
            .find(|l| l.contains(&format!("\"{path}\"")) && l.contains("\"blocked\""))
            .ok_or_else(|| format!("the summary does not report {path} as blocked:\n{events}"))?;
        assert!(
            line.contains(class),
            "the summary gives {path} the wrong class: {line}"
        );
    }
    assert!(
        !events
            .lines()
            .any(|l| l.contains(&format!("\"{}\"", known.display())) && l.contains("\"blocked\"")),
        "the summary reports a file as blocked that the kernel let through:\n{events}"
    );
    assert!(
        all.contains("The guard blocked 3 accesses"),
        "the header of the summary does not count the three blocked accesses:\n{all}"
    );
    Ok(())
}

/// A write rule on a path that does not exist at the start has no mount,
/// so the supervisor denies the call itself. The summary reports the same
/// decision.
#[test]
fn a_write_rule_on_a_missing_path_is_still_enforced() -> TestResult {
    let test = "a_write_rule_on_a_missing_path_is_still_enforced";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    // `~/.zshrc` does not exist, so `plan_guard` has no mount for it.
    let rc = env.home_path(".zshrc");
    let free = env.home_path("notes.txt");
    std::fs::create_dir_all(&env.home)?;
    let script = format!(
        "echo {RAN}; echo EVIL > '{r}' 2>&1; echo RC rc=$?; \
         echo OK > '{f}' 2>&1; echo FREE rc=$?",
        r = rc.display(),
        f = free.display()
    );
    let out = watch(&env, &["sh", "-c", &script])?;
    let all = assert_ran(&out);
    // The positive control: a write that no rule covers works.
    assert!(
        all.contains("FREE rc=0") && free.exists(),
        "a write that no rule covers failed, so the test proves nothing:\n{all}"
    );
    assert!(
        !rc.exists(),
        "the guard did not stop the creation of ~/.zshrc:\n{all}"
    );
    let events = env.watch_events("probe");
    assert!(
        events
            .lines()
            .any(|l| l.contains(&format!("\"{}\"", rc.display())) && l.contains("\"blocked\"")),
        "the summary does not report the write to ~/.zshrc as blocked:\n{events}"
    );
    Ok(())
}

/// The guard protects the files of pent, also when `XDG_CONFIG_HOME` and
/// `XDG_STATE_HOME` move them (H-11).
#[test]
fn the_guard_protects_the_store_of_pent_in_the_xdg_directories() -> TestResult {
    let test = "the_guard_protects_the_store_of_pent_in_the_xdg_directories";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    // The XDG directories of `TestEnv` are `~/.config` and
    // `~/.local/state`; install a profile so that the store exists.
    env.install_profile("victim", "[filesystem]\nread = []\n")?;
    let profile = env.profile_path("victim");
    let trusted = env.config_dir().join("pent/trusted.toml");
    let before_profile = std::fs::read_to_string(&profile)?;
    let before_trusted = std::fs::read_to_string(&trusted)?;
    let free = env.home_path("notes.txt");
    let script = format!(
        "echo {RAN}; echo 'read = [\"/\"]' > '{p}' 2>&1; echo P rc=$?; \
         echo x > '{t}' 2>&1; echo T rc=$?; \
         echo OK > '{f}' 2>&1; echo FREE rc=$?",
        p = profile.display(),
        t = trusted.display(),
        f = free.display()
    );
    let out = watch(&env, &["sh", "-c", &script])?;
    let all = assert_ran(&out);
    assert!(
        all.contains("FREE rc=0") && free.exists(),
        "a write that no rule covers failed, so the test proves nothing:\n{all}"
    );
    assert_eq!(
        std::fs::read_to_string(&profile)?,
        before_profile,
        "the watched program rewrote a profile of pent"
    );
    assert_eq!(
        std::fs::read_to_string(&trusted)?,
        before_trusted,
        "the watched program rewrote the trust store of pent"
    );
    Ok(())
}

// ── Property 2: no route to a hidden file ──────────────────────────────────

/// A file that the guard hides is not readable through a second path,
/// through a symbolic link, through `/proc/self/root`, or through a
/// nested user namespace.
#[test]
fn a_hidden_credential_is_not_readable_by_any_route() -> TestResult {
    let test = "a_hidden_credential_is_not_readable_by_any_route";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    make_home(&env)?;
    let key = env.home_path(".ssh/id_ed25519");
    let known = env.home_path(".ssh/known_hosts");
    // A second path to the same file, made before the run. The guard
    // masks the canonical path, so a symbolic link to it must not help.
    let link = env.home_path("link-to-key");
    std::os::unix::fs::symlink(&key, &link)?;
    let script = format!(
        "import ctypes, os, subprocess, sys\n\
         print('{RAN}')\n\
         def show(tag, path):\n\
         \x20   try:\n\
         \x20       print(tag, open(path, 'rb').read(64))\n\
         \x20   except OSError as e:\n\
         \x20       print(tag, 'ERR', e.errno)\n\
         show('CONTROL', {n:?})\n\
         show('DIRECT', {k:?})\n\
         show('LINK', {l:?})\n\
         show('PROCROOT', '/proc/self/root' + {k:?})\n\
         show('CWDROUTE', '/proc/self/cwd/../..' + {k:?})\n\
         # A hard link to the hidden path.\n\
         try:\n\
         \x20   os.link({k:?}, {h:?}); show('HARDLINK', {h:?})\n\
         except OSError as e:\n\
         \x20   print('HARDLINK ERR', e.errno)\n\
         # A nested user namespace and a recursive bind of the root.\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         rc = libc.unshare(0x10000000 | 0x00020000)\n\
         print('NESTED', rc, ctypes.get_errno())\n\
         if rc == 0:\n\
         \x20   try:\n\
         \x20       open('/proc/self/setgroups','w').write('deny')\n\
         \x20       open('/proc/self/uid_map','w').write('0 %d 1' % os.getuid())\n\
         \x20   except OSError as e:\n\
         \x20       print('MAP ERR', e.errno)\n\
         \x20   print('UMOUNT', libc.umount2({k:?}.encode(), 0), ctypes.get_errno())\n\
         \x20   print('LAZY', libc.umount2({k:?}.encode(), 2), ctypes.get_errno())\n\
         \x20   os.makedirs('/tmp/esc', exist_ok=True)\n\
         \x20   print('BIND', libc.mount(b'/', b'/tmp/esc', None, 4096, None), \
         ctypes.get_errno())\n\
         \x20   show('BINDROUTE', '/tmp/esc' + {k:?})\n\
         \x20   show('AFTER', {k:?})\n",
        k = key.display().to_string(),
        n = known.display().to_string(),
        l = link.display().to_string(),
        h = env.home_path("hardlink-to-key").display().to_string(),
    );
    let out = watch(&env, &["python3", "-I", "-c", &script])?;
    let all = assert_ran(&out);
    assert!(
        all.contains("PENT_KNOWN_HOSTS"),
        "the program could not read the control file, so the test proves nothing:\n{all}"
    );
    // Each route must have run. Without this check a script that stopped
    // early would pass the test.
    for tag in [
        "CONTROL",
        "DIRECT",
        "LINK",
        "PROCROOT",
        "CWDROUTE",
        "HARDLINK",
        "NESTED",
        "BINDROUTE",
        "AFTER",
    ] {
        assert!(
            all.lines().any(|l| l.starts_with(&format!("{tag} "))),
            "the route {tag} did not run, so the test proves nothing:\n{all}"
        );
    }
    assert!(
        !all.contains(KEY_SECRET),
        "the program read the hidden credential:\n{all}"
    );
    Ok(())
}

/// A descriptor that pent inherits does not reach the command. The
/// supervisor of the PID namespace closes each descriptor above the
/// standard streams, so a file that the caller of pent left open is no
/// route around Landlock and the guard.
#[test]
fn an_inherited_descriptor_does_not_reach_the_command() -> TestResult {
    let test = "an_inherited_descriptor_does_not_reach_the_command";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let secret = env.root.join("outside-secret");
    std::fs::write(&secret, "PENT_INHERITED_SECRET")?;
    std::fs::write(env.ws.join("allowed.txt"), "PENT_ALLOWED_DATA")?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    let file = std::fs::File::open(&secret)?;
    let raw = file.as_raw_fd();
    let mut cmd = env.command(&[
        "run",
        "--profile",
        "sh",
        "--",
        "sh",
        "-c",
        // `cat 0<&3` reads the inherited descriptor itself.
        // `/proc/self/fd/3` is a second open of the path, which Landlock
        // checks, so the test must not use it.
        &format!("echo {RAN}; cat allowed.txt; cat 0<&3 2>&1"),
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    // SAFETY: `dup2` and `fcntl` are async-signal-safe and take integers.
    // They run in the child between `fork` and `exec`.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output()?;
    let all = assert_ran(&out);
    // The second positive control: the same descriptor, without pent,
    // does give the secret. Without it a broken `pre_exec` would pass.
    let mut bare = std::process::Command::new("sh");
    bare.arg("-c").arg("cat 0<&3").stdin(Stdio::null());
    // SAFETY: as above.
    unsafe {
        bare.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let control = bare.output()?;
    drop(file);
    assert!(
        stdout(&control).contains("PENT_INHERITED_SECRET"),
        "the descriptor never held the secret, so the test proves nothing: {}",
        text(&control)
    );
    assert!(
        all.contains("PENT_ALLOWED_DATA"),
        "the command could not read its workspace, so the test proves nothing:\n{all}"
    );
    assert!(
        !all.contains("PENT_INHERITED_SECRET"),
        "the command read a file through a descriptor that pent inherited:\n{all}"
    );
    Ok(())
}

// ── The recorder ───────────────────────────────────────────────────────────

/// The recorder names the right process, also for an orphan that PID 1 of
/// the sandbox adopts. Watch mode takes a PID namespace, and
/// `SECCOMP_IOCTL_NOTIF_RECV` names the task in the namespace of the
/// reader, which is pent on the host.
#[test]
fn the_recorder_keeps_the_events_of_an_orphan() -> TestResult {
    let test = "the_recorder_keeps_the_events_of_an_orphan";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let target = env.home_path("orphan-read.txt");
    std::fs::create_dir_all(&env.home)?;
    std::fs::write(&target, "PENT_ORPHAN_DATA")?;
    // The orphan starts, its parent exits at once, and the orphan then
    // reads the file. PID 1 of the sandbox waits for it.
    let orphan = env.ws.join("orphan.sh");
    std::fs::write(
        &orphan,
        format!("sleep 0.5\ncat '{t}' > /dev/null\n", t = target.display()),
    )?;
    let script = format!("echo {RAN}; setsid sh '{o}' & exit 0", o = orphan.display());
    let out = watch(&env, &["sh", "-c", &script])?;
    let all = assert_ran(&out);
    let events = env.watch_events("probe");
    // The positive control: the recorder saw the events of the command
    // itself.
    assert!(
        events.contains("\"exec\""),
        "the recorder made no event at all, so the test proves nothing:\n{all}"
    );
    assert!(
        events.contains(&target.display().to_string()),
        "the recorder lost the read of the orphan:\n{events}"
    );
    Ok(())
}

/// Watch mode gives the program a PID namespace too, so it sees only the
/// processes of the sandbox.
#[test]
fn watch_mode_also_hides_the_processes_of_the_host() -> TestResult {
    let test = "watch_mode_also_hides_the_processes_of_the_host";
    if !ready(test) || !private_proc_ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    std::fs::create_dir_all(&env.home)?;
    let out = watch(
        &env,
        &[
            "sh",
            "-c",
            &format!("echo {RAN}; echo PIDS $(ls /proc | grep -c '^[0-9]*$')"),
        ],
    )?;
    let all = assert_ran(&out);
    let line = all
        .lines()
        .find(|l| l.starts_with("PIDS "))
        .ok_or("the program could not count the processes")?;
    let count: usize = line.trim_start_matches("PIDS ").trim().parse()?;
    assert!(
        count > 0,
        "the program saw no process at all, so the test proves nothing: {line}"
    );
    assert!(
        count < 16,
        "the program saw {count} processes, so watch mode has no private proc"
    );
    Ok(())
}

/// The path of a file in the home directory of the test.
#[allow(dead_code)]
fn home_of(env: &TestEnv, rel: &str) -> std::path::PathBuf {
    Path::new(&env.home).join(rel)
}
