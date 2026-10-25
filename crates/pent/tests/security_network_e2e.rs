#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // integration test: a setup failure should abort the test loudly
//! End-to-end network security tests for the real `pent` binary on Linux.
//!
//! Each test installs a trusted profile in its own `HOME` and XDG
//! directories, starts a victim server on the host, and runs a hostile
//! command under `pent run`. The command tries to reach a service that the
//! profile does not allow. A test that passes proves containment; a test
//! with `#[ignore = "OPEN VULN NET-<n>"]` keeps a failing assertion that
//! proves a bypass.
//!
//! # Each test makes what it needs
//!
//! A test of a denial must also prove that the child ran. Each test below
//! has a **positive control**: in the same run, the child reaches a service
//! that it may reach. Without it, a child that never started gives the same
//! output as a child that the sandbox contained.
//!
//! A test never needs a daemon of the host. It binds its own socket in a
//! directory that pent makes private, so the test runs on a machine with no
//! Tailscale, no message bus and no session. When the host has the real
//! socket, the test checks that one too.
//!
//! The tests need unprivileged user namespaces, Landlock and `python3`.
//! They print `SKIP <test>: <reason>` and pass when the environment cannot
//! run them. Set `PENT_REQUIRE_ALL_TESTS=1` to make each skip a failure.

#![cfg(target_os = "linux")]

mod common;

use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use common::e2e::{have_tools, sandbox_ready, stderr, stdout, TestEnv, TestResult};

/// Return true when this machine can run the tests of this file.
fn ready(test: &str) -> bool {
    have_tools(test, &["python3"]) && sandbox_ready(test)
}

/// A profile that allows only one harmless domain, so `pent run` chooses
/// proxy mode (the network namespace isolates the child).
const PROFILE: &str = "[network]\ndomains = [\"allowed.pent-test.invalid\"]\n";

/// Run `pent run` with the profile `probe` and the python script `script`.
fn run_sandboxed(env: &TestEnv, script: &str) -> std::io::Result<std::process::Output> {
    env.pent(&[
        "run",
        "--profile",
        "probe",
        "--",
        "python3",
        "-I",
        "-c",
        script,
    ])
}

/// The output of pent and of the child, as one text.
fn out_text(out: &std::process::Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

// ── The victim servers of the tests ─────────────────────────────────────────

/// A listening Unix socket of the test, with the number of clients that
/// reached it.
struct Victim {
    /// The path of the socket.
    path: PathBuf,
    /// The number of clients that the socket accepted.
    reached: Arc<AtomicUsize>,
}

impl Victim {
    /// Bind a Unix socket at `path` that sends `banner` to each client.
    fn bind(path: PathBuf, banner: &'static [u8]) -> std::io::Result<Self> {
        let listener = UnixListener::bind(&path)?;
        let reached = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&reached);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(banner);
            }
        });
        Ok(Self { path, reached })
    }

    /// The number of clients that reached the socket until now.
    fn reached(&self) -> usize {
        self.reached.load(Ordering::SeqCst)
    }

    /// The path, as a string for the python script.
    fn text(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for Victim {
    fn drop(&mut self) {
        // The socket file stays in a directory of the host; remove it.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The directory in which a test puts its own victim socket.
///
/// Pent covers `/run`, `/var/run`, `/tmp` and `/var/tmp` with an empty
/// tmpfs in the mount namespace of the child (`PRIVATE_DIRS` of
/// `pent-sandbox`), so a socket in one of them is not in the view of the
/// child. `/run/user/<uid>` comes first: a daemon of the session keeps its
/// socket there, which is the shape of NET-1 and NET-2. `/tmp` is the
/// fallback for a machine without a session directory.
fn private_dir() -> Option<PathBuf> {
    // SAFETY: getuid() has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let candidates = [
        PathBuf::from(format!("/run/user/{uid}")),
        PathBuf::from("/tmp"),
    ];
    candidates.into_iter().find(|dir| {
        let probe = dir.join(format!("pent-write-probe-{}", std::process::id()));
        let ok = std::fs::write(&probe, b"x").is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
    })
}

/// The python script that connects to each `(label, path)` pair and prints
/// one line for each one: `<LABEL> REACHED <bytes>` or `<LABEL> BLOCKED`.
fn unix_probe_script(targets: &[(&str, String)]) -> String {
    let mut script = String::from(
        "import socket\n\
         def probe(label, path):\n\
         \x20   s = socket.socket(socket.AF_UNIX)\n\
         \x20   s.settimeout(3)\n\
         \x20   try:\n\
         \x20       s.connect(path)\n\
         \x20   except OSError as e:\n\
         \x20       print(label, 'BLOCKED', e)\n\
         \x20       return\n\
         \x20   try:\n\
         \x20       data = s.recv(64)\n\
         \x20   except OSError as e:\n\
         \x20       data = b''\n\
         \x20   print(label, 'REACHED', data)\n",
    );
    for (label, path) in targets {
        script.push_str(&format!("probe({label:?}, {path:?})\n"));
    }
    script
}

// ── NET-1 and NET-2: the daemon sockets of the host under /run ──────────────

/// The Tailscale daemon LocalAPI socket. Its `ts-dial` upgrade opens a TCP
/// connection to any host over the tailnet, and to the public internet
/// through an exit node or a subnet route. The child reaching it bypasses
/// the proxy completely.
const TAILSCALE_SOCK: &str = "/run/tailscale/tailscaled.sock";

/// The system message bus. It gives the child `systemd-resolved` (name
/// resolution past the proxy), NetworkManager and polkit.
const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

/// The banner of the victim socket. It must never reach the child.
const VICTIM_SECRET: &str = "PENT_VICTIM_SECRET";

/// The banner of the socket that the profile allows.
const ALLOWED_BANNER: &str = "PENT_ALLOWED_BANNER";

/// Prove that the child cannot reach a daemon socket of the host below a
/// private directory.
///
/// The test binds its own socket in the private directory, with the shape
/// of the daemon socket of `host_socket` (a directory of the daemon and a
/// socket in it). When the host has the real socket too, the child probes
/// that one as well.
///
/// The positive control is a second socket in a directory that the profile
/// names. The child must reach that one in the same run.
fn daemon_socket_is_masked(test: &str, daemon: &str, host_socket: &str) -> TestResult {
    if !ready(test) {
        return Ok(());
    }
    let Some(private) = private_dir() else {
        common::e2e::skip(
            test,
            "no writable private directory (/run/user/<uid>, /tmp)",
        );
        return Ok(());
    };

    let env = TestEnv::new()?;
    // The directory of the positive control is outside every private
    // directory, and the profile names it.
    let allowed_dir = env.root.join("allowed");
    std::fs::create_dir_all(&allowed_dir)?;
    env.install_profile(
        "probe",
        &format!(
            // The profile names the socket of the positive control. Since
            // the supervisor makes each permitted connection itself, a
            // socket that no rule names is not reachable at all.
            "[filesystem]\nread_write = [{:?}]\nunix_sockets = [{:?}]\n\n{PROFILE}",
            allowed_dir.display().to_string(),
            allowed_dir.join("allowed.sock").display().to_string()
        ),
    )?;

    // The victim: a socket of a daemon of the host, in the private
    // directory. The profile does not name it.
    let daemon_dir = private.join(format!("pent-{daemon}-{}", std::process::id()));
    std::fs::create_dir_all(&daemon_dir)?;
    let victim = Victim::bind(
        daemon_dir.join(format!("{daemon}.sock")),
        VICTIM_SECRET.as_bytes(),
    )?;
    let allowed = Victim::bind(allowed_dir.join("allowed.sock"), ALLOWED_BANNER.as_bytes())?;

    let mut targets = vec![("ALLOWED", allowed.text()), ("VICTIM", victim.text())];
    let host_present = Path::new(host_socket).exists();
    if host_present {
        targets.push(("HOST", host_socket.to_string()));
    }
    let out = run_sandboxed(&env, &unix_probe_script(&targets))?;
    let text = out_text(&out);
    let _ = std::fs::remove_dir_all(&daemon_dir);

    // The positive control: the child ran, and a Unix socket that the
    // profile names works for it.
    assert!(
        text.contains(&format!("ALLOWED REACHED b'{ALLOWED_BANNER}'")),
        "the child did not reach the socket that the profile allows, so \
         this run proves no denial:\n{text}"
    );
    assert_eq!(allowed.reached(), 1, "the allowed socket got no client");

    assert!(
        text.contains("VICTIM BLOCKED"),
        "the child reached the socket of a daemon below {}; the private \
         directory does not mask it:\n{text}",
        private.display()
    );
    assert!(
        !text.contains(VICTIM_SECRET),
        "the content of the daemon socket reached the child:\n{text}"
    );
    assert_eq!(
        victim.reached(),
        0,
        "the victim socket accepted a client from the child"
    );

    if host_present {
        assert!(
            text.contains("HOST BLOCKED"),
            "the child reached {host_socket} on this host:\n{text}"
        );
    } else {
        println!("note {test}: {host_socket} is absent; the test used its own socket only");
    }
    Ok(())
}

/// NET-1. The child must not reach the LocalAPI socket of the Tailscale
/// daemon, or any other daemon socket below `/run`.
#[test]
fn tailscale_localapi_socket_is_masked() -> TestResult {
    daemon_socket_is_masked(
        "tailscale_localapi_socket_is_masked",
        "tailscaled",
        TAILSCALE_SOCK,
    )
}

/// NET-2. The child must not reach the system message bus, or any other
/// daemon socket below `/run`.
#[test]
fn system_dbus_socket_is_masked() -> TestResult {
    daemon_socket_is_masked("system_dbus_socket_is_masked", "dbus", SYSTEM_BUS)
}

/// NET-3 (open). A profile path below a private directory must give the
/// child that path, not the whole subtree above it.
///
/// `plan_private_dirs` keeps the traversal paths of each configured path,
/// and it binds only the outermost path of a subtree. The outermost path
/// of `/run/user/<uid>/x` is `/run/user`, thus one profile rule for a
/// directory below the runtime directory restores the whole runtime
/// directory of the user, with each daemon socket in it. See
/// `docs/security/network.md`.
#[test]
#[ignore = "OPEN NET-3: a profile path below /run or /tmp binds the whole \
            parent subtree back, so the sibling sockets of the host return"]
fn a_profile_path_below_a_private_dir_keeps_its_siblings_hidden() -> TestResult {
    let test = "a_profile_path_below_a_private_dir_keeps_its_siblings_hidden";
    if !ready(test) {
        return Ok(());
    }
    let Some(private) = private_dir() else {
        common::e2e::skip(
            test,
            "no writable private directory (/run/user/<uid>, /tmp)",
        );
        return Ok(());
    };
    // Both sockets are below the same directory of the host. The profile
    // names the directory of the first one only.
    let base = private.join(format!("pent-net3-{}", std::process::id()));
    let allowed_dir = base.join("allowed");
    std::fs::create_dir_all(&allowed_dir)?;
    let env = TestEnv::new()?;
    env.install_profile(
        "probe",
        &format!(
            // The profile names the socket of the positive control. Since
            // the supervisor makes each permitted connection itself, a
            // socket that no rule names is not reachable at all.
            "[filesystem]\nread_write = [{:?}]\nunix_sockets = [{:?}]\n\n{PROFILE}",
            allowed_dir.display().to_string(),
            allowed_dir.join("allowed.sock").display().to_string()
        ),
    )?;
    let allowed = Victim::bind(allowed_dir.join("allowed.sock"), ALLOWED_BANNER.as_bytes())?;
    let victim = Victim::bind(base.join("victim.sock"), VICTIM_SECRET.as_bytes())?;

    let targets = vec![("ALLOWED", allowed.text()), ("VICTIM", victim.text())];
    let out = run_sandboxed(&env, &unix_probe_script(&targets))?;
    let text = out_text(&out);
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        text.contains(&format!("ALLOWED REACHED b'{ALLOWED_BANNER}'")),
        "the child did not reach the socket that the profile allows:\n{text}"
    );
    assert!(
        text.contains("VICTIM BLOCKED"),
        "NET-3: the profile names one directory below {}, and the child \
         reached a sibling of it:\n{text}",
        base.display()
    );
    assert_eq!(victim.reached(), 0, "the sibling socket got a client");
    Ok(())
}

// ── Verified defenses ───────────────────────────────────────────────────────

#[test]
fn child_cannot_reach_a_host_loopback_service() -> TestResult {
    let test = "child_cannot_reach_a_host_loopback_service";
    if !ready(test) {
        return Ok(());
    }
    // A victim TCP server on the host loopback. The child in its own
    // network namespace must not reach it.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let (tx, rx) = mpsc::channel::<bool>();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let _ = s.write_all(b"VICTIM");
            let _ = tx.send(true);
        }
    });

    let env = TestEnv::new()?;
    env.install_profile("probe", PROFILE)?;
    // The positive control: the child starts its own server on its own
    // loopback and reaches it. Loopback works in the namespace of the
    // child; only the loopback of the host is out of reach.
    let script = format!(
        r#"
import socket, threading
own = socket.socket(); own.bind(("127.0.0.1", 0)); own.listen(1)
own_port = own.getsockname()[1]
def serve():
    c, _ = own.accept(); c.sendall(b"OWN"); c.close()
threading.Thread(target=serve, daemon=True).start()
c = socket.socket(); c.settimeout(3)
try:
    c.connect(("127.0.0.1", own_port)); print("OWN REACHED", c.recv(16))
except OSError as e:
    print("OWN BLOCKED", e)
h = socket.socket(); h.settimeout(3)
try:
    h.connect(("127.0.0.1", {port})); print("HOST REACHED", h.recv(16))
except OSError as e:
    print("HOST BLOCKED", e)
"#
    );
    let out = run_sandboxed(&env, &script)?;
    let text = out_text(&out);
    assert!(
        text.contains("OWN REACHED b'OWN'"),
        "the child could not reach its own loopback, so this run proves \
         no denial:\n{text}"
    );
    assert!(
        text.contains("HOST BLOCKED"),
        "the child reached host loopback:\n{text}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "the victim accepted a connection from the child"
    );
    Ok(())
}

/// With no socket in the profile, the child cannot make a socket of the
/// Unix family at all.
///
/// The supervisor makes each permitted connection itself, but a datagram
/// socket can send without a connection, so the default refuses the family
/// in the filter. The filter reads the family from a register, so no other
/// thread can change it.
#[test]
fn the_default_profile_refuses_the_unix_family() -> TestResult {
    if !ready("the_default_profile_refuses_the_unix_family") {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("probe", PROFILE)?;
    let script = r#"
import socket
print("PENT_CHILD_RAN")
try:
    socket.socket(socket.AF_UNIX); print("FAMILY ALLOWED")
except OSError as e:
    print("FAMILY REFUSED", e)
try:
    a, b = socket.socketpair(); print("SOCKETPAIR ALLOWED")
except OSError as e:
    print("SOCKETPAIR REFUSED", e)
"#;
    let out = run_sandboxed(&env, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("PENT_CHILD_RAN"),
        "the child did not run:\n{text}"
    );
    assert!(
        text.contains("FAMILY REFUSED"),
        "a profile with no socket must refuse the Unix family:\n{text}"
    );
    // socketpair makes a pair that reaches nothing outside the child, so
    // it stays available: many runtimes need it to talk to their children.
    assert!(
        text.contains("SOCKETPAIR ALLOWED"),
        "socketpair must stay available:\n{text}"
    );
    Ok(())
}

#[test]
#[ignore = "OPEN NET-4: pent refuses each abstract address, so a program cannot reach its own abstract socket"]
fn child_cannot_reach_a_host_abstract_unix_socket() -> TestResult {
    let test = "child_cannot_reach_a_host_abstract_unix_socket";
    if !ready(test) {
        return Ok(());
    }
    // An abstract Unix socket lives in the network namespace of the host.
    // The new network namespace of the child must isolate it. The name has
    // the process id, so two runs of the suite do not collide.
    let name = format!("pent-sec-abstract-victim-{}", std::process::id());
    let addr =
        <std::os::unix::net::SocketAddr as std::os::linux::net::SocketAddrExt>::from_abstract_name(
            name.as_bytes(),
        )
        .map_err(|e| format!("the abstract name {name:?} is not valid: {e}"))?;
    let listener = UnixListener::bind_addr(&addr).map_err(|e| {
        format!("the test must bind the abstract socket {name:?} to prove the denial: {e}")
    })?;
    let reached = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&reached);
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            let _ = s.write_all(b"VICTIM");
        }
    });

    let env = TestEnv::new()?;
    // The profile names one socket, so the child can make a socket of the
    // Unix family. With no name in the profile, pent refuses the family
    // itself; `the_default_profile_refuses_the_unix_family` states that.
    let named = env.root.join("allowed").join("unused.sock");
    std::fs::create_dir_all(env.root.join("allowed"))?;
    env.install_profile(
        "probe",
        &format!(
            "[filesystem]\nunix_sockets = [{:?}]\n\n{PROFILE}",
            named.display().to_string()
        ),
    )?;
    // The positive control: the child binds its own abstract socket and
    // reaches it. Abstract sockets work for the child; only the names of
    // the host are out of reach.
    let script = format!(
        r#"
import socket, threading
own_name = "\0pent-sec-abstract-own"
own = socket.socket(socket.AF_UNIX); own.bind(own_name); own.listen(1)
def serve():
    c, _ = own.accept(); c.sendall(b"OWN"); c.close()
threading.Thread(target=serve, daemon=True).start()
c = socket.socket(socket.AF_UNIX); c.settimeout(3)
try:
    c.connect(own_name); print("OWN REACHED", c.recv(16))
except OSError as e:
    print("OWN BLOCKED", e)
h = socket.socket(socket.AF_UNIX); h.settimeout(3)
try:
    h.connect("\0" + {name:?}); print("HOST REACHED", h.recv(16))
except OSError as e:
    print("HOST BLOCKED", e)
"#
    );
    let out = run_sandboxed(&env, &script)?;
    let text = out_text(&out);
    assert!(
        text.contains("OWN REACHED b'OWN'"),
        "the child could not reach its own abstract socket, so this run \
         proves no denial:\n{text}"
    );
    assert!(
        text.contains("HOST BLOCKED"),
        "the child reached a host abstract Unix socket:\n{text}"
    );
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "the abstract socket of the host accepted a client from the child"
    );
    Ok(())
}

#[test]
fn child_has_no_raw_udp_egress() -> TestResult {
    let test = "child_has_no_raw_udp_egress";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("probe", PROFILE)?;
    // A direct UDP datagram to a public resolver must not leave the
    // namespace. The only route is the loopback proxy, which is TCP/DNS.
    // The positive control: a datagram on the loopback of the child
    // arrives, so the socket itself works.
    let script = r#"
import socket
own = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
own.bind(("127.0.0.1", 0)); own.settimeout(3)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sender.sendto(b"own", own.getsockname())
    print("OWN REACHED", own.recv(16))
except OSError as e:
    print("OWN BLOCKED", e)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", ("1.1.1.1", 53)); print("HOST SENT")
except OSError as e:
    print("HOST BLOCKED", e)
"#;
    let out = run_sandboxed(&env, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("OWN REACHED b'own'"),
        "the child could not send a datagram on its own loopback, so this \
         run proves no denial:\n{text}"
    );
    assert!(
        text.contains("HOST BLOCKED"),
        "the child sent a raw UDP datagram out of the namespace:\n{text}"
    );
    Ok(())
}

#[test]
fn child_cannot_steal_the_proxy_port_with_reuseport() -> TestResult {
    let test = "child_cannot_steal_the_proxy_port_with_reuseport";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("probe", PROFILE)?;
    // The child must not bind 127.0.0.1:3128 again, with SO_REUSEPORT or
    // otherwise, to steal the connections of other processes in the
    // sandbox. The positive control: it binds a free port, so the refusal
    // is about the port of the proxy and not about the socket.
    let script = r#"
import socket
free = socket.socket()
try:
    free.bind(("127.0.0.1", 0)); free.listen(1); print("FREE BOUND")
except OSError as e:
    print("FREE REFUSED", e)
for opt in (None, socket.SO_REUSEPORT, socket.SO_REUSEADDR):
    s = socket.socket()
    if opt is not None:
        s.setsockopt(socket.SOL_SOCKET, opt, 1)
    try:
        s.bind(("127.0.0.1", 3128)); s.listen(1); print("PROXY BOUND", opt)
    except OSError as e:
        print("PROXY REFUSED", opt, e)
    s.close()
"#;
    let out = run_sandboxed(&env, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("FREE BOUND"),
        "the child could not bind a free port, so this run proves no \
         denial:\n{text}"
    );
    assert_eq!(
        text.matches("PROXY REFUSED").count(),
        3,
        "each of the three binds of the proxy port must fail:\n{text}"
    );
    assert!(
        !text.contains("PROXY BOUND"),
        "the child bound the proxy port and can steal connections:\n{text}"
    );
    Ok(())
}

#[test]
fn child_sees_proxy_resolv_conf() -> TestResult {
    let test = "child_sees_proxy_resolv_conf";
    if !ready(test) {
        return Ok(());
    }
    let env = TestEnv::new()?;
    env.install_profile("probe", PROFILE)?;
    // The child's /etc/resolv.conf must name only the loopback proxy. A
    // fixed external resolver would let the child resolve names off-proxy.
    let script = r#"
print(open("/etc/resolv.conf").read())
"#;
    let out = run_sandboxed(&env, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("nameserver 127.0.0.1"),
        "resolv.conf does not point only at the proxy:\n{text}"
    );
    assert!(
        !text.contains("8.8.8.8") && !text.contains("100.100.100.100"),
        "resolv.conf still names a host resolver:\n{text}"
    );
    Ok(())
}
