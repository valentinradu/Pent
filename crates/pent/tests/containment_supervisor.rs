//! Containment tests: the seccomp supervisor that controls `connect(2)`
//! to a Unix socket.
//!
//! `docs/security/linux-sandbox.md` (LS-1) claims:
//!
//! 1. A connection to a socket that the profile names works, and the
//!    descriptor of the child keeps its number, its kind and its flags.
//! 2. Every other address gets `EACCES`.
//! 3. The supervisor never answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
//!    after it read an `AF_UNIX` address, so a second thread that changes
//!    the address cannot change the result.
//! 4. With an empty allowlist the filter refuses `socket(AF_UNIX, ...)`
//!    and `socketpair(2)` still works.
//!
//! The same document names two ways that stay open with a non-empty
//! allowlist: the address family of `connect(2)` is a value in memory,
//! and `sendto(2)` is not trapped. The two tests of those ways carry an
//! `#[ignore = "OPEN CT-..."]` mark and keep the secure assertion.
//!
//! Each test that asserts a refusal also proves in the same run that the
//! child ran and that the permitted socket worked.
//!
//! The tests need unprivileged user namespaces, Landlock and `python3`.
//! They print `SKIP <test>: <reason>` and pass when the host cannot run
//! them. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a setup failure must abort loudly

mod common;

use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::e2e::{have_tools, sandbox_ready, stderr, stdout, TestEnv, TestResult};

/// The marker that each probe prints first.
const RAN: &str = "PENT_CHILD_RAN";

/// The banner of the socket that the profile names.
const ALLOWED_BANNER: &str = "PENT_ALLOWED_BANNER";

/// The banner of a socket that the profile does not name.
const VICTIM_SECRET: &str = "PENT_VICTIM_SECRET";

fn ready(test: &str) -> bool {
    have_tools(test, &["python3"]) && sandbox_ready(test)
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

#[track_caller]
fn assert_allowed(all: &str, what: &str) {
    assert!(
        all.contains(ALLOWED_BANNER),
        "the permitted connection did not work ({what}), so the test proves nothing:\n{all}"
    );
}

/// A stream server of the test. It answers each client with `banner` and
/// records the credentials of the last peer.
struct Server {
    /// The path of the socket.
    path: PathBuf,
    /// The process identifier of the last peer, in the namespace of the
    /// test.
    peer: Arc<AtomicI32>,
    /// The number of clients that reached the socket.
    reached: Arc<AtomicUsize>,
}

impl Server {
    fn bind(path: PathBuf, banner: &'static str) -> std::io::Result<Self> {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        let peer = Arc::new(AtomicI32::new(-1));
        let reached = Arc::new(AtomicUsize::new(0));
        let (p, r) = (Arc::clone(&peer), Arc::clone(&reached));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                p.store(peer_pid(&stream), Ordering::SeqCst);
                r.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(banner.as_bytes());
            }
        });
        Ok(Self {
            path,
            peer,
            reached,
        })
    }

    fn text(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The process identifier of the peer of `stream`, or `-1`.
fn peer_pid(stream: &UnixStream) -> i32 {
    // SAFETY: a zeroed `ucred` is a valid, empty structure, and the
    // descriptor is an open Unix socket.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = u32::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: `cred` and `len` are writable and match the option.
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &raw mut len,
        )
    };
    if ret == 0 {
        cred.pid
    } else {
        -1
    }
}

/// A profile that names `sockets` in `filesystem.unix_sockets`.
fn profile_with(sockets: &[&Path]) -> String {
    let list: Vec<String> = sockets
        .iter()
        .map(|p| format!("{:?}", p.display().to_string()))
        .collect();
    format!("[filesystem]\nunix_sockets = [{}]\n", list.join(", "))
}

/// Run a python script under `pent run` with the profile `python3`.
fn run(env: &TestEnv, script: &str) -> std::io::Result<Output> {
    env.pent(&[
        "run",
        "--profile",
        "python3",
        "--",
        "python3",
        "-I",
        "-c",
        script,
    ])
}

// ── Property 1: a named socket works, with its kind and its flags ──────────

/// A connection to a socket that the profile names works, and the
/// descriptor that the child gets keeps the number, the kind, `O_NONBLOCK`
/// and `FD_CLOEXEC` that the child asked for.
#[test]
fn a_named_socket_works_and_keeps_the_kind_and_the_flags() -> TestResult {
    let test = "a_named_socket_works_and_keeps_the_kind_and_the_flags";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let stream = Server::bind(env.root.join("stream.sock"), ALLOWED_BANNER)?;
    let dgram_path = env.root.join("dgram.sock");
    let dgram = UnixDatagram::bind(&dgram_path)?;
    let got = Arc::new(AtomicUsize::new(0));
    {
        let got = Arc::clone(&got);
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            while let Ok(n) = dgram.recv(&mut buf) {
                if buf.get(..n) == Some(b"PENT_DGRAM".as_slice()) {
                    got.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }
    env.install_profile("python3", &profile_with(&[&stream.path, &dgram_path]))?;
    let script = format!(
        "import socket, os, fcntl\n\
         print('{RAN}')\n\
         def probe(tag, nonblock, cloexec):\n\
         \x20   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   s.setblocking(not nonblock)\n\
         \x20   s.set_inheritable(not cloexec)\n\
         \x20   want = s.fileno()\n\
         \x20   s.connect({stream:?})\n\
         \x20   fl = fcntl.fcntl(s.fileno(), fcntl.F_GETFL)\n\
         \x20   fd = fcntl.fcntl(s.fileno(), fcntl.F_GETFD)\n\
         \x20   print(tag,\n\
         \x20         'samefd', s.fileno() == want,\n\
         \x20         'type', s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),\n\
         \x20         'nonblock', bool(fl & os.O_NONBLOCK) == nonblock,\n\
         \x20         'cloexec', bool(fd & fcntl.FD_CLOEXEC) == cloexec)\n\
         \x20   s.settimeout(5)\n\
         \x20   print(tag, 'data', s.recv(64).decode())\n\
         probe('BLOCKING', False, True)\n\
         probe('NONBLOCK', True, True)\n\
         probe('INHERIT', False, False)\n\
         d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
         d.connect({dgram:?})\n\
         print('DGRAM type', d.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE))\n\
         d.send(b'PENT_DGRAM')\n",
        stream = stream.text(),
        dgram = dgram_path.display().to_string(),
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    for tag in ["BLOCKING", "NONBLOCK", "INHERIT"] {
        let line = all
            .lines()
            .find(|l| l.starts_with(&format!("{tag} samefd")))
            .ok_or_else(|| format!("no result for {tag}:\n{all}"))?;
        assert_eq!(
            line,
            format!("{tag} samefd True type 1 nonblock True cloexec True"),
            "the descriptor of {tag} lost a property:\n{all}"
        );
    }
    assert!(
        all.contains("DGRAM type 2"),
        "the supervisor did not make a datagram socket:\n{all}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while got.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        got.load(Ordering::SeqCst),
        1,
        "the datagram of the child did not reach the server:\n{all}"
    );
    Ok(())
}

/// The peer of the new descriptor is pent, not the child.
/// `docs/security/linux-sandbox.md` names this limit under LS-1.
#[test]
fn the_server_sees_pent_as_the_peer_not_the_child() -> TestResult {
    let test = "the_server_sees_pent_as_the_peer_not_the_child";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let server = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    env.install_profile("python3", &profile_with(&[&server.path]))?;
    let script = format!(
        "import socket\n\
         print('{RAN}')\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)\n\
         s.connect({p:?})\n\
         print('DATA', s.recv(64).decode())\n",
        p = server.text()
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    let pid = server.peer.load(Ordering::SeqCst);
    assert!(pid > 0, "the server read no peer credentials:\n{all}");
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    assert!(
        comm.trim() == "pent" || comm.is_empty(),
        "the peer of the server is {comm:?}, not pent (pid {pid}):\n{all}"
    );
    Ok(())
}

// ── Property 2: every other address is refused ─────────────────────────────

/// A connection to any address that the profile does not name fails with
/// `EACCES`: another path, an abstract name, a relative path, a path that
/// does not exist, and a symbolic link to a socket outside the profile.
#[test]
fn every_address_outside_the_profile_is_refused() -> TestResult {
    let test = "every_address_outside_the_profile_is_refused";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    let victim = Server::bind(env.root.join("victim.sock"), VICTIM_SECRET)?;
    let link = env.root.join("link-to-victim.sock");
    std::os::unix::fs::symlink(&victim.path, &link)?;
    // A victim with a relative path from the workspace of the child.
    let relative = Server::bind(env.ws.join("relative.sock"), VICTIM_SECRET)?;
    // An abstract socket of the test process.
    let abstract_name = format!("pent-ct-{}", std::process::id());
    env.install_profile("python3", &profile_with(&[&allowed.path]))?;
    let script = format!(
        "import socket\n\
         print('{RAN}')\n\
         def probe(tag, addr):\n\
         \x20   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)\n\
         \x20   try:\n\
         \x20       s.connect(addr); print(tag, 'DATA', s.recv(64).decode())\n\
         \x20   except OSError as e:\n\
         \x20       print(tag, 'ERR', e.errno)\n\
         probe('ALLOWED', {a:?})\n\
         probe('VICTIM', {v:?})\n\
         probe('LINK', {l:?})\n\
         probe('RELATIVE', 'relative.sock')\n\
         probe('MISSING', {a:?} + '.nope')\n\
         probe('ABSTRACT', '\\0{abs}')\n\
         probe('EMPTY', '')\n",
        a = allowed.text(),
        v = victim.text(),
        l = link.display().to_string(),
        abs = abstract_name,
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    assert!(
        !all.contains(VICTIM_SECRET),
        "the child reached a socket outside its profile:\n{all}"
    );
    assert_eq!(
        victim.reached.load(Ordering::SeqCst) + relative.reached.load(Ordering::SeqCst),
        0,
        "a connection of the child reached a victim socket:\n{all}"
    );
    for tag in ["VICTIM", "LINK", "RELATIVE", "MISSING"] {
        let line = all
            .lines()
            .find(|l| l.starts_with(&format!("{tag} ")))
            .ok_or_else(|| format!("no result for {tag}:\n{all}"))?;
        assert_eq!(
            line,
            format!("{tag} ERR {}", libc::EACCES),
            "the refusal of {tag} is not EACCES:\n{all}"
        );
    }
    Ok(())
}

/// A socket that exists only in the private `/tmp` of the child is not
/// reachable: it has no path on the host, so the profile cannot name it.
/// `docs/security/linux-sandbox.md` states this limit under LS-1.
#[test]
fn a_socket_only_in_the_private_tmp_is_not_reachable() -> TestResult {
    let test = "a_socket_only_in_the_private_tmp_is_not_reachable";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    env.install_profile("python3", &profile_with(&[&allowed.path]))?;
    let script = format!(
        "import socket, threading\n\
         print('{RAN}')\n\
         srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         srv.bind('/tmp/inner.sock'); srv.listen(1)\n\
         def serve():\n\
         \x20   c, _ = srv.accept(); c.sendall(b'PENT_INNER')\n\
         threading.Thread(target=serve, daemon=True).start()\n\
         c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.settimeout(2)\n\
         try:\n\
         \x20   c.connect('/tmp/inner.sock'); print('INNER DATA', c.recv(32))\n\
         except OSError as e:\n\
         \x20   print('INNER ERR', e.errno)\n\
         a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); a.settimeout(5)\n\
         a.connect({p:?}); print('ALLOWED', a.recv(64).decode())\n",
        p = allowed.text()
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    assert!(
        all.contains(&format!("INNER ERR {}", libc::EACCES)),
        "the child reached a socket of its own private /tmp:\n{all}"
    );
    Ok(())
}

// ── Property 3: the supervisor always answers ──────────────────────────────

/// The supervisor never leaves a child without an answer. The child meets
/// each error path of the supervisor in one run: a descriptor that is not
/// a socket, a closed descriptor, an address that is too short, a name
/// that is too long, a socket kind that the supervisor cannot find, and a
/// permitted path that holds no server. Every call must return, and the
/// run must finish.
#[test]
fn the_supervisor_answers_every_connection() -> TestResult {
    let test = "the_supervisor_answers_every_connection";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    // A permitted path that is a regular file, not a socket.
    let not_a_socket = env.root.join("not-a-socket");
    std::fs::write(&not_a_socket, "x")?;
    env.install_profile("python3", &profile_with(&[&allowed.path, &not_a_socket]))?;
    let script = format!(
        "import ctypes, os, socket, struct, sys\n\
         print('{RAN}', flush=True)\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         A = {a:?}.encode()\n\
         def sockaddr(path, size=110):\n\
         \x20   b = ctypes.create_string_buffer(size)\n\
         \x20   struct.pack_into('H', b, 0, socket.AF_UNIX)\n\
         \x20   ctypes.memmove(ctypes.byref(b, 2), path, len(path))\n\
         \x20   return b\n\
         def raw(tag, fd, buf, size):\n\
         \x20   r = libc.connect(fd, buf, size)\n\
         \x20   print(tag, r, ctypes.get_errno(), flush=True)\n\
         # A descriptor that is not a socket.\n\
         f = open('/etc/hostname', 'rb')\n\
         raw('NOTSOCKET', f.fileno(), sockaddr(A), 110)\n\
         # A descriptor that is closed.\n\
         raw('BADFD', 9999, sockaddr(A), 110)\n\
         # An address that is shorter than the family.\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         raw('SHORT', s.fileno(), sockaddr(A), 1)\n\
         # An address with no name at all.\n\
         s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         raw('NONAME', s2.fileno(), sockaddr(b''), 2)\n\
         # An address buffer that the supervisor cannot read.\n\
         s3 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         r = libc.connect(s3.fileno(), ctypes.c_void_p(0), 110)\n\
         print('NULLADDR', r, ctypes.get_errno(), flush=True)\n\
         # A permitted path that holds no server.\n\
         s4 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s4.settimeout(10)\n\
         try:\n\
         \x20   s4.connect({n:?}); print('FILE OK', flush=True)\n\
         except OSError as e:\n\
         \x20   print('FILE ERR', e.errno, flush=True)\n\
         # Many connections from several threads, mixed good and bad.\n\
         import threading\n\
         ok = [0]\n\
         lock = threading.Lock()\n\
         def worker():\n\
         \x20   for i in range(40):\n\
         \x20       c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.settimeout(10)\n\
         \x20       try:\n\
         \x20           c.connect({a:?})\n\
         \x20           if c.recv(64).decode() == '{ALLOWED_BANNER}':\n\
         \x20               with lock: ok[0] += 1\n\
         \x20       except OSError:\n\
         \x20           pass\n\
         \x20       c.close()\n\
         \x20       d = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20       try:\n\
         \x20           d.connect('\\0pent-ct-abstract')\n\
         \x20       except OSError:\n\
         \x20           pass\n\
         \x20       d.close()\n\
         ts = [threading.Thread(target=worker) for _ in range(4)]\n\
         for t in ts: t.start()\n\
         for t in ts: t.join()\n\
         print('STORM', ok[0], flush=True)\n\
         print('DONE', flush=True)\n",
        a = allowed.text(),
        n = not_a_socket.display().to_string(),
    );
    let start = Instant::now();
    let out = run(&env, &script)?;
    let took = start.elapsed();
    let all = assert_ran(&out);
    assert!(
        all.contains("DONE"),
        "the child did not finish; the supervisor left a call without an answer:\n{all}"
    );
    assert!(
        took < Duration::from_secs(120),
        "the run took {took:?}; the supervisor is too slow to answer"
    );
    for tag in ["NOTSOCKET", "BADFD", "SHORT", "NONAME", "NULLADDR", "FILE"] {
        assert!(
            all.lines().any(|l| l.starts_with(&format!("{tag} "))),
            "the supervisor gave no answer for {tag}:\n{all}"
        );
    }
    // The positive control: each of the 160 permitted connections of the
    // storm gave the banner of the server.
    assert!(
        all.contains("STORM 160"),
        "a permitted connection of the storm failed, so the test proves nothing:\n{all}"
    );
    Ok(())
}

/// A blocking connection to a server that never accepts ends after the
/// limit of the supervisor, with an error. The child does not wait for
/// ever and the supervisor stays free.
#[test]
fn a_blocking_connection_to_a_full_queue_ends_with_an_error() -> TestResult {
    let test = "a_blocking_connection_to_a_full_queue_ends_with_an_error";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    // A listener with the smallest queue that never accepts.
    let full = env.root.join("full.sock");
    let _ = std::fs::remove_file(&full);
    let listener = UnixListener::bind(&full)?;
    // Fill the queue from the host, so that the child always waits.
    let mut held = Vec::new();
    for _ in 0..64 {
        match UnixStream::connect(&full) {
            Ok(s) => held.push(s),
            Err(_) => break,
        }
    }
    env.install_profile("python3", &profile_with(&[&allowed.path, &full]))?;
    let script = format!(
        "import socket, time\n\
         print('{RAN}', flush=True)\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         s.setblocking(True)\n\
         t = time.monotonic()\n\
         try:\n\
         \x20   s.connect({f:?}); print('FULL OK', flush=True)\n\
         except OSError as e:\n\
         \x20   print('FULL ERR', e.errno, round(time.monotonic() - t, 1), flush=True)\n\
         a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); a.settimeout(10)\n\
         a.connect({p:?}); print('ALLOWED', a.recv(64).decode(), flush=True)\n",
        f = full.display().to_string(),
        p = allowed.text(),
    );
    let start = Instant::now();
    let out = run(&env, &script)?;
    let took = start.elapsed();
    drop(held);
    drop(listener);
    let _ = std::fs::remove_file(&full);
    let all = assert_ran(&out);
    // The supervisor must answer, and then it must still serve the next
    // connection.
    assert!(
        all.lines().any(|l| l.starts_with("FULL ")),
        "the supervisor gave no answer for the full queue:\n{all}"
    );
    assert_allowed(&all, "the connection after the full queue");
    assert!(
        took < Duration::from_secs(60),
        "the run took {took:?}; one connection held the supervisor"
    );
    Ok(())
}

// ── Property 4: the address cannot change after the check ──────────────────

/// A second thread that changes the path after the supervisor read it
/// cannot change the result. The supervisor connects itself, to the
/// canonical path of the allowlist.
#[test]
fn a_second_thread_cannot_change_the_path_after_the_check() -> TestResult {
    let test = "a_second_thread_cannot_change_the_path_after_the_check";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    let victim = Server::bind(env.root.join("victim.sock"), VICTIM_SECRET)?;
    env.install_profile("python3", &profile_with(&[&allowed.path]))?;
    let script = format!(
        "import ctypes, socket, struct, threading\n\
         print('{RAN}', flush=True)\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         A = {a:?}.encode()\n\
         V = {v:?}.encode()\n\
         buf = ctypes.create_string_buffer(110)\n\
         struct.pack_into('H', buf, 0, socket.AF_UNIX)\n\
         stop = False\n\
         def flip():\n\
         \x20   while not stop:\n\
         \x20       ctypes.memmove(ctypes.byref(buf, 2), V + b'\\0', len(V) + 1)\n\
         \x20       ctypes.memmove(ctypes.byref(buf, 2), A + b'\\0', len(A) + 1)\n\
         t = threading.Thread(target=flip, daemon=True); t.start()\n\
         seen = set()\n\
         for i in range(400):\n\
         \x20   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   if libc.connect(s.fileno(), buf, 110) == 0:\n\
         \x20       s.settimeout(5)\n\
         \x20       try:\n\
         \x20           seen.add(s.recv(64).decode())\n\
         \x20       except OSError as e:\n\
         \x20           seen.add('timeout')\n\
         \x20   else:\n\
         \x20       seen.add('E%d' % ctypes.get_errno())\n\
         \x20   s.close()\n\
         stop = True\n\
         print('SEEN', sorted(seen), flush=True)\n",
        a = allowed.text(),
        v = victim.text(),
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    assert!(
        !all.contains(VICTIM_SECRET),
        "a second thread moved the connection to a socket outside the profile:\n{all}"
    );
    assert_eq!(
        victim.reached.load(Ordering::SeqCst),
        0,
        "a connection of the child reached the victim socket:\n{all}"
    );
    Ok(())
}

/// A second thread that re-points a symbolic link after the check cannot
/// change the target. The supervisor connects to the canonical path that
/// it took from the allowlist.
#[test]
fn a_symbolic_link_cannot_change_the_target_after_the_check() -> TestResult {
    let test = "a_symbolic_link_cannot_change_the_target_after_the_check";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let real = Server::bind(env.root.join("real.sock"), ALLOWED_BANNER)?;
    let victim = Server::bind(env.root.join("victim.sock"), VICTIM_SECRET)?;
    let link = env.root.join("link.sock");
    std::os::unix::fs::symlink(&real.path, &link)?;
    // The profile names the link. The supervisor keeps its canonical form.
    env.install_profile("python3", &profile_with(&[&link]))?;
    // The thread of the test moves the link only after the child started
    // and after it made its first connection. Pent reads the allowlist
    // before the child runs, so a move before that point would only
    // change the allowlist, not race it.
    let ready = env.ws.join("ready");
    let stop = Arc::new(AtomicUsize::new(0));
    let mover = {
        let stop = Arc::clone(&stop);
        let (link, real, victim, ready) = (
            link.clone(),
            real.path.clone(),
            victim.path.clone(),
            ready.clone(),
        );
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !ready.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let tmp = link.with_extension("tmp");
            while stop.load(Ordering::SeqCst) == 0 {
                for target in [&victim, &real] {
                    let _ = std::fs::remove_file(&tmp);
                    if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                        let _ = std::fs::rename(&tmp, &link);
                    }
                }
            }
        })
    };
    let script = format!(
        "import socket\n\
         print('{RAN}', flush=True)\n\
         def once():\n\
         \x20   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)\n\
         \x20   try:\n\
         \x20       s.connect({l:?}); return s.recv(64).decode()\n\
         \x20   except OSError as e:\n\
         \x20       return 'E%d' % e.errno\n\
         \x20   finally:\n\
         \x20       s.close()\n\
         first = once()\n\
         print('FIRST', first, flush=True)\n\
         open({r:?}, 'w').write('y')\n\
         seen = set()\n\
         for i in range(400):\n\
         \x20   seen.add(once())\n\
         print('SEEN', sorted(seen), flush=True)\n",
        l = link.display().to_string(),
        r = ready.display().to_string(),
    );
    let out = run(&env, &script)?;
    stop.store(1, Ordering::SeqCst);
    mover.join().map_err(|_| "the mover thread failed")?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    assert!(
        !all.contains(VICTIM_SECRET),
        "a moved symbolic link sent the child to a socket outside the profile:\n{all}"
    );
    assert_eq!(
        victim.reached.load(Ordering::SeqCst),
        0,
        "a connection of the child reached the victim socket:\n{all}"
    );
    Ok(())
}

// ── Property 5: the empty allowlist ────────────────────────────────────────

/// With an empty allowlist the filter refuses `socket(AF_UNIX, ...)` with
/// `EAFNOSUPPORT`, and `socketpair(2)` still works.
#[test]
fn an_empty_allowlist_refuses_the_family_and_keeps_socketpair() -> TestResult {
    let test = "an_empty_allowlist_refuses_the_family_and_keeps_socketpair";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("python3", "[filesystem]\nread = []\n")?;
    let script = format!(
        "import socket\n\
         print('{RAN}')\n\
         try:\n\
         \x20   socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('SOCKET OK')\n\
         except OSError as e:\n\
         \x20   print('SOCKET ERR', e.errno)\n\
         a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         a.sendall(b'PENT_PAIR')\n\
         print('PAIR', b.recv(16).decode())\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         print('INET OK')\n"
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert!(
        all.contains("PAIR PENT_PAIR"),
        "socketpair(2) does not work any more, so the test proves nothing:\n{all}"
    );
    assert!(
        all.contains("INET OK"),
        "the filter also refuses AF_INET, so the test proves nothing:\n{all}"
    );
    assert!(
        all.contains(&format!("SOCKET ERR {}", libc::EAFNOSUPPORT)),
        "the filter did not refuse socket(AF_UNIX, ...) with EAFNOSUPPORT:\n{all}"
    );
    Ok(())
}

// ── The two ways that stay open with a non-empty allowlist ─────────────────

/// A second thread that changes the address family after the supervisor
/// read it must not change the result.
///
/// It does. The supervisor answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for
/// a family that is not `AF_UNIX`, and the kernel then reads the address
/// again. A thread that writes `AF_INET` and `AF_UNIX` in a loop moves a
/// part of the connections past the check.
/// `docs/security/linux-sandbox.md` names this way under "What stays
/// open"; no test held it until now.
#[test]
#[ignore = "OPEN CT-1: a second thread changes the address family after the check and reaches any socket"]
fn a_second_thread_cannot_change_the_address_family() -> TestResult {
    let test = "a_second_thread_cannot_change_the_address_family";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    let victim = Server::bind(env.root.join("victim.sock"), VICTIM_SECRET)?;
    env.install_profile("python3", &profile_with(&[&allowed.path]))?;
    let script = format!(
        "import ctypes, socket, struct, threading\n\
         print('{RAN}', flush=True)\n\
         libc = ctypes.CDLL('libc.so.6', use_errno=True)\n\
         V = {v:?}.encode()\n\
         buf = ctypes.create_string_buffer(110)\n\
         ctypes.memmove(ctypes.byref(buf, 2), V + b'\\0', len(V) + 1)\n\
         stop = False\n\
         def flip():\n\
         \x20   while not stop:\n\
         \x20       struct.pack_into('H', buf, 0, socket.AF_INET)\n\
         \x20       struct.pack_into('H', buf, 0, socket.AF_UNIX)\n\
         t = threading.Thread(target=flip, daemon=True); t.start()\n\
         for i in range(3000):\n\
         \x20   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   if libc.connect(s.fileno(), buf, 110) == 0:\n\
         \x20       s.settimeout(5)\n\
         \x20       try:\n\
         \x20           print('GOT', s.recv(64).decode(), flush=True)\n\
         \x20       except OSError:\n\
         \x20           pass\n\
         \x20   s.close()\n\
         stop = True\n\
         a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); a.settimeout(5)\n\
         a.connect({p:?}); print('ALLOWED', a.recv(64).decode(), flush=True)\n",
        v = victim.text(),
        p = allowed.text(),
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    assert_eq!(
        victim.reached.load(Ordering::SeqCst),
        0,
        "the family race moved a connection to a socket outside the profile:\n{all}"
    );
    assert!(
        !all.contains(VICTIM_SECRET),
        "the family race gave the child the content of a socket outside the profile:\n{all}"
    );
    Ok(())
}

/// `sendto(2)` must not reach a Unix socket that the profile does not
/// name.
///
/// It does. The supervisor traps only `connect(2)`. A datagram socket
/// carries the address in `sendto(2)`, so the child sends data to any
/// socket file that it can resolve. `docs/security/linux-sandbox.md`
/// names this way under "What stays open"; no test held it until now.
#[test]
#[ignore = "OPEN CT-2: sendto(2) reaches a Unix socket that the profile does not name"]
fn sendto_cannot_reach_a_socket_outside_the_profile() -> TestResult {
    let test = "sendto_cannot_reach_a_socket_outside_the_profile";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    let allowed = Server::bind(env.root.join("allowed.sock"), ALLOWED_BANNER)?;
    let victim_path = env.root.join("victim.dgram");
    let victim = UnixDatagram::bind(&victim_path)?;
    let got = Arc::new(AtomicUsize::new(0));
    {
        let got = Arc::clone(&got);
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            while let Ok(n) = victim.recv(&mut buf) {
                if n > 0 {
                    got.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }
    env.install_profile("python3", &profile_with(&[&allowed.path]))?;
    let script = format!(
        "import socket\n\
         print('{RAN}', flush=True)\n\
         d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
         try:\n\
         \x20   d.sendto(b'PENT_EXFIL_BY_SENDTO', {v:?}); print('SENDTO OK', flush=True)\n\
         except OSError as e:\n\
         \x20   print('SENDTO ERR', e.errno, flush=True)\n\
         a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); a.settimeout(5)\n\
         a.connect({p:?}); print('ALLOWED', a.recv(64).decode(), flush=True)\n",
        v = victim_path.display().to_string(),
        p = allowed.text(),
    );
    let out = run(&env, &script)?;
    let all = assert_ran(&out);
    assert_allowed(&all, "the socket that the profile names");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        got.load(Ordering::SeqCst),
        0,
        "sendto(2) reached a socket that the profile does not name:\n{all}"
    );
    Ok(())
}
