//! Containment tests: the private `/tmp`, `/var/tmp` and `/run` of the
//! Linux sandbox.
//!
//! The documents claim four properties for these directories
//! (`README.md`, "Private `/tmp`, `/var/tmp` and `/run`", and
//! `docs/security/linux-sandbox.md`, LS-2):
//!
//! 1. Only the paths that the session needs come back.
//! 2. The child reaches neither the staging directory of the overlay nor
//!    the store of pent nor the socket of a daemon of the host.
//! 3. A symbolic link in a bound path does not lead outside.
//! 4. The child cannot undo a mount.
//!
//! Each test below states one property. A test that asserts that something
//! is not reachable also proves, in the same run, that the child ran and
//! that a permitted access worked. Without that positive control a child
//! that never started would pass the test.
//!
//! The tests need unprivileged user namespaces, Landlock and `python3`.
//! They print `SKIP <test>: <reason>` and pass when the host cannot run
//! them. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a setup failure must abort loudly

mod common;

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::e2e::{have_tools, sandbox_ready, stderr, stdout, TestEnv, TestResult};

/// The marker that each probe prints first. It is the positive control for
/// "the child ran at all".
const RAN: &str = "PENT_CHILD_RAN";

/// Return true when this machine can run the tests of this file.
fn ready(test: &str) -> bool {
    have_tools(test, &["sh", "python3"]) && sandbox_ready(test)
}

/// The output of pent and of the child, as one text.
fn text(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

/// Fail when the child did not run.
#[track_caller]
fn assert_ran(out: &Output) -> String {
    let all = text(out);
    assert!(
        all.contains(RAN),
        "the child did not run, so the test proves nothing:\n{all}"
    );
    all
}

/// Fail when the output does not hold `needle`. Use it for the positive
/// control of a test.
#[track_caller]
fn assert_allowed(all: &str, needle: &str, what: &str) {
    assert!(
        all.contains(needle),
        "the permitted access did not work ({what}), so the test proves nothing:\n{all}"
    );
}

/// Fail when the output holds `needle`.
#[track_caller]
fn assert_absent(all: &str, needle: &str, what: &str) {
    assert!(!all.contains(needle), "{what}:\n{all}");
}

/// A TOML list with one path.
fn one(path: &Path) -> String {
    format!("[{:?}]", path.display().to_string())
}

/// A unique directory of this test process under the host `/tmp`.
///
/// The sandbox covers `/tmp` with an empty tmpfs, so a victim file there
/// stands for the temporary file of another program of the user.
fn host_tmp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pent-ct-{}-{tag}", std::process::id()))
}

// ── Property 1: only the named path comes back ──────────────────────────────

/// A path that the profile names under `/tmp` comes back, and nothing
/// beside it does.
#[test]
fn only_the_named_path_under_tmp_comes_back() -> TestResult {
    let test = "only_the_named_path_under_tmp_comes_back";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let named = host_tmp("named");
    let sibling = host_tmp("sibling");
    let _ = std::fs::remove_dir_all(&named);
    let _ = std::fs::remove_dir_all(&sibling);
    std::fs::create_dir_all(&named)?;
    std::fs::create_dir_all(&sibling)?;
    std::fs::write(named.join("ok"), "PENT_NAMED_DATA")?;
    std::fs::write(sibling.join("secret"), "PENT_SIBLING_SECRET")?;
    env.install_profile("sh", &format!("[filesystem]\nread = {}\n", one(&named)))?;
    let script = format!(
        "echo {RAN}; cat '{n}/ok'; echo; cat '{s}/secret' 2>&1; echo; \
         echo TMPLS $(ls -a /tmp | tr '\\n' ' ')",
        n = named.display(),
        s = sibling.display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    let _ = std::fs::remove_dir_all(&named);
    let _ = std::fs::remove_dir_all(&sibling);
    assert_allowed(&all, "PENT_NAMED_DATA", "the named directory under /tmp");
    assert_absent(
        &all,
        "PENT_SIBLING_SECRET",
        "the child read a sibling of the named directory under /tmp",
    );
    let line = all
        .lines()
        .find(|l| l.starts_with("TMPLS "))
        .ok_or("the child could not list /tmp")?;
    let entries: Vec<&str> = line
        .trim_start_matches("TMPLS ")
        .split_whitespace()
        .filter(|e| *e != "." && *e != "..")
        .collect();
    let want = named.file_name().and_then(|n| n.to_str()).unwrap_or("");
    assert_eq!(
        entries,
        vec![want],
        "the private /tmp holds more than the named directory:\n{all}"
    );
    Ok(())
}

/// A workspace under `/tmp` keeps working, and the rest of the host
/// `/tmp` stays hidden. The README claims both.
#[test]
fn a_workspace_under_tmp_works_and_hides_the_rest() -> TestResult {
    let test = "a_workspace_under_tmp_works_and_hides_the_rest";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let ws = host_tmp("ws");
    let victim = host_tmp("victim");
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws)?;
    std::fs::write(ws.join("input"), "PENT_WORKSPACE_DATA")?;
    std::fs::write(&victim, "PENT_HOST_TMP_SECRET")?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;
    let script = format!(
        "echo {RAN}; cat input; echo OUT > output; cat '{v}' 2>&1",
        v = victim.display()
    );
    let mut cmd = env.command(&["run", "--profile", "sh", "--", "sh", "-c", &script]);
    cmd.current_dir(&ws);
    let out = cmd.output()?;
    let all = assert_ran(&out);
    let written = std::fs::read_to_string(ws.join("output")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_file(&victim);
    assert_allowed(&all, "PENT_WORKSPACE_DATA", "the workspace under /tmp");
    assert_eq!(written, "OUT\n", "the write did not reach the workspace");
    assert_absent(
        &all,
        "PENT_HOST_TMP_SECRET",
        "the child read a host file under /tmp",
    );
    Ok(())
}

/// A mount in the global settings cannot share `/tmp` with the host. The
/// README says: "There is no setting to share `/tmp` or `/run` with the
/// host."
#[test]
fn no_setting_shares_tmp_with_the_host() -> TestResult {
    let test = "no_setting_shares_tmp_with_the_host";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let victim = host_tmp("settings-victim");
    std::fs::write(&victim, "PENT_HOST_TMP_SECRET")?;
    let settings = env.config_dir().join("pent/pent.toml");
    std::fs::create_dir_all(settings.parent().unwrap())?;
    std::fs::write(
        &settings,
        "[[sandbox.mounts]]\npath = \"/tmp\"\nreadonly = false\n",
    )?;
    env.install_profile("sh", "[filesystem]\nread_write = [\"/tmp\"]\n")?;
    let script = format!(
        "echo {RAN}; echo MINE > /tmp/mine; cat /tmp/mine; cat '{v}' 2>&1",
        v = victim.display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    let _ = std::fs::remove_file(&victim);
    assert_allowed(&all, "MINE", "a write in the private /tmp of the child");
    assert_absent(
        &all,
        "PENT_HOST_TMP_SECRET",
        "a mount setting shared the host /tmp with the child",
    );
    Ok(())
}

/// `XDG_RUNTIME_DIR` and a `TMPDIR` below a private directory become an
/// empty directory; a `TMPDIR` outside them stays as it is.
#[test]
fn the_runtime_dir_is_empty_and_tmpdir_follows_the_rule() -> TestResult {
    let test = "the_runtime_dir_is_empty_and_tmpdir_follows_the_rule";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    // A `TMPDIR` below `/tmp`, with a file that must not come back.
    let inside = host_tmp("tmpdir-inside");
    let _ = std::fs::remove_dir_all(&inside);
    std::fs::create_dir_all(&inside)?;
    std::fs::write(inside.join("leak"), "PENT_TMPDIR_SECRET")?;
    // A `TMPDIR` outside the private directories: the workspace.
    let outside = env.ws.join("outside-tmpdir");
    std::fs::create_dir_all(&outside)?;
    std::fs::write(outside.join("keep"), "PENT_OUTSIDE_TMPDIR_DATA")?;
    env.install_profile("sh", "[filesystem]\nread = []\n")?;

    let script = format!(
        "echo {RAN}; echo INSIDE $(ls -a \"$TMPDIR\" | tr '\\n' ' '); cat \"$TMPDIR/leak\" 2>&1",
    );
    let out = env
        .command(&["run", "--profile", "sh", "--", "sh", "-c", &script])
        .env("TMPDIR", &inside)
        .output()?;
    let all = assert_ran(&out);
    let line = all
        .lines()
        .find(|l| l.starts_with("INSIDE "))
        .ok_or("the child could not list TMPDIR")?;
    let entries: Vec<&str> = line
        .trim_start_matches("INSIDE ")
        .split_whitespace()
        .filter(|e| *e != "." && *e != "..")
        .collect();
    assert!(
        entries.is_empty(),
        "a TMPDIR below /tmp is not empty: {entries:?}\n{all}"
    );
    assert_absent(
        &all,
        "PENT_TMPDIR_SECRET",
        "the child read the host content of its TMPDIR",
    );

    let script = format!("echo {RAN}; cat \"$TMPDIR/keep\"");
    let out = env
        .command(&["run", "--profile", "sh", "--", "sh", "-c", &script])
        .env("TMPDIR", &outside)
        .output()?;
    let all = assert_ran(&out);
    assert_allowed(
        &all,
        "PENT_OUTSIDE_TMPDIR_DATA",
        "a TMPDIR outside the private directories",
    );

    // The runtime directory of the session is an empty directory.
    let uid = unsafe { libc::getuid() };
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    if !runtime.is_dir() {
        eprintln!("SKIP (part) {test}: no {} on this host", runtime.display());
        let _ = std::fs::remove_dir_all(&inside);
        return Ok(());
    }
    let script = format!(
        "echo {RAN}; echo RT $(ls -a '{r}' | tr '\\n' ' '); echo W > '{r}/probe'; echo rc=$?",
        r = runtime.display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    let _ = std::fs::remove_dir_all(&inside);
    let line = all
        .lines()
        .find(|l| l.starts_with("RT "))
        .ok_or("the child could not list the runtime directory")?;
    let entries: Vec<&str> = line
        .trim_start_matches("RT ")
        .split_whitespace()
        .filter(|e| *e != "." && *e != "..")
        .collect();
    assert!(
        entries.is_empty(),
        "the runtime directory of the child is not empty: {entries:?}\n{all}"
    );
    assert!(
        !runtime.join("probe").exists(),
        "the write of the child reached the runtime directory of the host"
    );
    Ok(())
}

/// Each private directory is a tmpfs with `nosuid` and `nodev`, and it has
/// no size limit. The README claims all three.
#[test]
fn each_private_directory_is_nosuid_and_nodev() -> TestResult {
    let test = "each_private_directory_is_nosuid_and_nodev";
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
        &format!("echo {RAN}; cat /proc/self/mountinfo"),
    ])?;
    let all = assert_ran(&out);
    for dir in ["/tmp", "/var/tmp", "/run"] {
        // The last mount on the point wins. The private tmpfs is the last
        // one that pent makes on it.
        let line = all
            .lines()
            .rfind(|l| {
                let mut f = l.split(' ');
                f.nth(4) == Some(dir)
            })
            .ok_or_else(|| format!("no mount on {dir}:\n{all}"))?;
        assert!(
            line.contains(" - tmpfs "),
            "{dir} is not a tmpfs: {line}\n{all}"
        );
        for flag in ["nosuid", "nodev"] {
            assert!(
                line.split(' ').any(|f| f.split(',').any(|o| o == flag)),
                "the tmpfs on {dir} has no {flag}: {line}"
            );
        }
        assert!(
            !line.contains("size="),
            "the tmpfs on {dir} has a size limit: {line}"
        );
    }
    Ok(())
}

// ── Property 2: the private resources of pent and of the host ───────────────

/// The child cannot reach the staging directory of the overlay. A write
/// rule on a file makes an overlay over its directory, and the staging
/// directory of that overlay holds the stubs that hide the other files.
#[test]
fn the_child_cannot_reach_the_staging_directory_of_the_overlay() -> TestResult {
    let test = "the_child_cannot_reach_the_staging_directory_of_the_overlay";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = env.write_home("data/allowed.txt", "PENT_ALLOWED_DATA")?;
    env.write_home("data/secret.txt", "PENT_SIBLING_SECRET")?;
    env.install_profile(
        "sh",
        &format!("[filesystem]\nread_write = {}\n", one(&allowed)),
    )?;
    let uid = unsafe { libc::getuid() };
    let script = format!(
        "echo {RAN}; cat '{a}'; echo; echo MORE >> '{a}'; echo rc=$?; \
         cat '{s}' 2>&1; echo; echo STAGE $(ls -a /tmp/pent-{uid} 2>&1 | tr '\\n' ' ')",
        a = allowed.display(),
        s = env.home_path("data/secret.txt").display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    assert_allowed(&all, "PENT_ALLOWED_DATA", "the read-write file");
    assert_allowed(&all, "rc=0", "the write to the read-write file");
    assert_absent(
        &all,
        "PENT_SIBLING_SECRET",
        "the overlay did not hide the sibling of the write target",
    );
    let line = all
        .lines()
        .find(|l| l.starts_with("STAGE "))
        .ok_or("the child did not report the staging directory")?;
    assert!(
        line.contains("No such file") || line.contains("Permission denied"),
        "the child reached the staging root of the overlay: {line}\n{all}"
    );
    Ok(())
}

/// The child cannot read or change the store of pent. A program that
/// rewrites its own profile gets more access in the next run.
#[test]
fn the_child_cannot_read_or_change_the_store_of_pent() -> TestResult {
    let test = "the_child_cannot_read_or_change_the_store_of_pent";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = env.write_home("data/allowed.txt", "PENT_ALLOWED_DATA")?;
    env.install_profile(
        "sh",
        &format!("[filesystem]\nread_write = {}\n", one(&allowed)),
    )?;
    let profile = env.profile_path("sh");
    let trusted = env.config_dir().join("pent/trusted.toml");
    // A second profile file. Its content is the marker of a read.
    let decoy = env.config_dir().join("pent/profiles/decoy.toml");
    std::fs::write(&decoy, "# PENT_PROFILE_SECRET\n")?;
    let before = std::fs::read_to_string(&trusted)?;
    let script = format!(
        "echo {RAN}; cat '{a}'; echo; cat '{d}' 2>&1; cat '{t}' 2>&1; \
         echo 'read = [\"/\"]' > '{p}' 2>&1; echo w1=$?; \
         echo x > '{t}' 2>&1; echo w2=$?",
        a = allowed.display(),
        d = decoy.display(),
        p = profile.display(),
        t = trusted.display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    assert_allowed(&all, "PENT_ALLOWED_DATA", "the read-write file");
    assert_absent(
        &all,
        "PENT_PROFILE_SECRET",
        "the child read a profile of the store",
    );
    assert_absent(&all, "sha256", "the child read the trust store");
    assert_eq!(
        std::fs::read_to_string(&trusted)?,
        before,
        "the child changed the trust store"
    );
    let after = std::fs::read_to_string(&profile)?;
    assert!(
        !after.contains("read = [\"/\"]"),
        "the child rewrote its own profile:\n{after}"
    );
    Ok(())
}

/// An agent socket of the home directory is covered with `/dev/null`, and
/// the supervisor does not connect to it. The profile names another
/// socket, so the family `AF_UNIX` stays open and the test measures the
/// mask, not the refusal of the family.
#[test]
fn an_agent_socket_of_the_home_directory_is_covered() -> TestResult {
    let test = "an_agent_socket_of_the_home_directory_is_covered";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let gnupg = env.home.join(".gnupg");
    std::fs::create_dir_all(&gnupg)?;
    let agent = gnupg.join("S.gpg-agent");
    serve(&agent, b"PENT_AGENT_SECRET")?;
    let allowed = env.root.join("allowed.sock");
    serve(&allowed, b"PENT_ALLOWED_BANNER")?;
    env.install_profile(
        "python3",
        &format!(
            "[filesystem]\nread = [{:?}]\nunix_sockets = {}\n",
            gnupg.display().to_string(),
            one(&allowed)
        ),
    )?;
    let script = format!(
        "import socket, os, stat\n\
         print('{RAN}')\n\
         for tag, p in [('AGENT', {agent:?}), ('ALLOWED', {allowed:?})]:\n\
         \x20   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2)\n\
         \x20   try:\n\
         \x20       s.connect(p); print(tag, 'DATA', s.recv(64))\n\
         \x20   except OSError as e:\n\
         \x20       print(tag, 'ERR', e.errno)\n\
         print('AGENTKIND', stat.S_IFMT(os.stat({agent:?}).st_mode) == stat.S_IFSOCK)\n",
        agent = agent.display().to_string(),
        allowed = allowed.display().to_string(),
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
    assert_allowed(
        &all,
        "PENT_ALLOWED_BANNER",
        "the socket that the profile names",
    );
    assert_absent(
        &all,
        "PENT_AGENT_SECRET",
        "the child reached the agent socket of the home directory",
    );
    assert!(
        all.contains("AGENTKIND False"),
        "pent did not cover the agent socket with /dev/null:\n{all}"
    );
    Ok(())
}

// ── Property 3: a symbolic link does not lead outside ───────────────────────

/// A symbolic link in a bound path does not lead outside. The child
/// resolves the link, and Landlock refuses the target.
#[test]
fn a_symbolic_link_in_a_bound_path_does_not_lead_outside() -> TestResult {
    let test = "a_symbolic_link_in_a_bound_path_does_not_lead_outside";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let named = host_tmp("link-named");
    let _ = std::fs::remove_dir_all(&named);
    std::fs::create_dir_all(&named)?;
    std::fs::write(named.join("ok"), "PENT_NAMED_DATA")?;
    let outside = env.root.join("outside-secret");
    std::fs::write(&outside, "PENT_OUTSIDE_SECRET")?;
    let host_tmp_victim = host_tmp("link-victim");
    std::fs::write(&host_tmp_victim, "PENT_HOST_TMP_SECRET")?;
    std::os::unix::fs::symlink(&outside, named.join("to-outside"))?;
    std::os::unix::fs::symlink(&host_tmp_victim, named.join("to-host-tmp"))?;
    std::os::unix::fs::symlink("..", named.join("up"))?;
    env.install_profile("sh", &format!("[filesystem]\nread = {}\n", one(&named)))?;
    let script = format!(
        "echo {RAN}; cat '{n}/ok'; echo; cat '{n}/to-outside' 2>&1; echo; \
         cat '{n}/to-host-tmp' 2>&1; echo; \
         echo UP $(ls '{n}/up' 2>&1 | tr '\\n' ' ')",
        n = named.display()
    );
    let out = env.pent(&["run", "--profile", "sh", "--", "sh", "-c", &script])?;
    let all = assert_ran(&out);
    let _ = std::fs::remove_dir_all(&named);
    let _ = std::fs::remove_file(&host_tmp_victim);
    assert_allowed(&all, "PENT_NAMED_DATA", "the named directory under /tmp");
    assert_absent(
        &all,
        "PENT_OUTSIDE_SECRET",
        "a symbolic link in a bound path led outside the profile",
    );
    assert_absent(
        &all,
        "PENT_HOST_TMP_SECRET",
        "a symbolic link in a bound path led to the host /tmp",
    );
    let line = all
        .lines()
        .find(|l| l.starts_with("UP "))
        .ok_or("the child did not list the parent of the bound path")?;
    assert!(
        !line.contains("link-victim"),
        "the parent of the bound path shows the host /tmp: {line}\n{all}"
    );
    Ok(())
}

// ── Property 4: the child cannot undo a mount ───────────────────────────────

/// The child cannot undo a mount: no `umount`, no lazy `umount`, no new
/// mount namespace, no new mount, and no `pivot_root`.
#[test]
fn the_child_cannot_undo_a_mount() -> TestResult {
    let test = "the_child_cannot_undo_a_mount";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let victim = host_tmp("umount-victim");
    std::fs::write(&victim, "PENT_HOST_TMP_SECRET")?;
    let allowed = env.ws.join("allowed.txt");
    std::fs::write(&allowed, "PENT_ALLOWED_DATA")?;
    env.install_profile("python3", "[filesystem]\nread = []\n")?;
    let script = format!(
        "import ctypes, os\n\
         print('{RAN}')\n\
         print(open('allowed.txt').read())\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         MNT_DETACH = 2\n\
         CLONE_NEWNS = 0x00020000\n\
         CLONE_NEWUSER = 0x10000000\n\
         print('UMOUNT', libc.umount2(b'/tmp', 0), ctypes.get_errno())\n\
         print('LAZY', libc.umount2(b'/tmp', MNT_DETACH), ctypes.get_errno())\n\
         print('UNSHARE_NS', libc.unshare(CLONE_NEWNS), ctypes.get_errno())\n\
         print('MOUNT', libc.mount(b'none', b'/tmp', b'tmpfs', 0, None), ctypes.get_errno())\n\
         print('PIVOT', libc.syscall(155, b'/', b'/'), ctypes.get_errno())\n\
         try:\n\
         \x20   print('AFTER', open({v:?}).read())\n\
         except OSError as e:\n\
         \x20   print('AFTER ERR', e.errno)\n",
        v = victim.display().to_string()
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
    let _ = std::fs::remove_file(&victim);
    assert_allowed(&all, "PENT_ALLOWED_DATA", "a read in the workspace");
    for (tag, what) in [
        ("UMOUNT -1", "the child unmounted the private /tmp"),
        ("LAZY -1", "the child detached the private /tmp"),
        ("UNSHARE_NS -1", "the child made a new mount namespace"),
        ("MOUNT -1", "the child made a new mount"),
        ("PIVOT -1", "the child changed its root"),
    ] {
        assert!(all.contains(tag), "{what}:\n{all}");
    }
    assert_absent(
        &all,
        "PENT_HOST_TMP_SECRET",
        "the child reached the host /tmp after it tried to undo the mounts",
    );
    Ok(())
}

/// A nested user namespace does not remove the private directories. The
/// child gets capabilities only over its own new namespace, and the
/// mounts of the sandbox stay locked.
#[test]
fn a_nested_user_namespace_does_not_remove_the_private_directories() -> TestResult {
    let test = "a_nested_user_namespace_does_not_remove_the_private_directories";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let victim = host_tmp("nested-victim");
    std::fs::write(&victim, "PENT_HOST_TMP_SECRET")?;
    std::fs::write(env.ws.join("allowed.txt"), "PENT_ALLOWED_DATA")?;
    env.install_profile("python3", "[filesystem]\nread = []\n")?;
    // `unshare` without a privilege: a new user namespace and a new mount
    // namespace. Then try each way to bring the host `/tmp` back.
    let script = format!(
        "import ctypes, os, sys\n\
         print('{RAN}')\n\
         print(open('allowed.txt').read())\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         rc = libc.unshare(0x10000000 | 0x00020000)\n\
         print('NESTED', rc, ctypes.get_errno())\n\
         if rc == 0:\n\
         \x20   open('/proc/self/setgroups','w').write('deny')\n\
         \x20   open('/proc/self/uid_map','w').write('0 %d 1' % os.getuid())\n\
         \x20   print('UMOUNT', libc.umount2(b'/tmp', 0), ctypes.get_errno())\n\
         \x20   print('LAZY', libc.umount2(b'/tmp', 2), ctypes.get_errno())\n\
         \x20   os.makedirs('/tmp/esc', exist_ok=True)\n\
         \x20   print('BIND', libc.mount(b'/', b'/tmp/esc', None, 4096, None), ctypes.get_errno())\n\
         \x20   try:\n\
         \x20       print('ESC', open('/tmp/esc' + {v:?}).read())\n\
         \x20   except OSError as e:\n\
         \x20       print('ESC ERR', e.errno)\n\
         try:\n\
         \x20   print('AFTER', open({v:?}).read())\n\
         except OSError as e:\n\
         \x20   print('AFTER ERR', e.errno)\n",
        v = victim.display().to_string()
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
    let _ = std::fs::remove_file(&victim);
    assert_allowed(&all, "PENT_ALLOWED_DATA", "a read in the workspace");
    assert_absent(
        &all,
        "PENT_HOST_TMP_SECRET",
        "a nested user namespace brought the host /tmp back",
    );
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Bind a Unix socket at `path` and send `banner` to each client.
fn serve(path: &Path, banner: &'static [u8]) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.write_all(banner);
        }
    });
    Ok(())
}
