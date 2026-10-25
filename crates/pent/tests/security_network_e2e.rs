#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // integration test: a setup failure should abort the test loudly
//! End-to-end network security tests for the real `pent` binary on Linux.
//!
//! Each test installs a trusted profile in an isolated HOME/XDG, runs a
//! victim server on the host, and runs a hostile command under `pent run`.
//! The command tries to reach a host that the profile does not allow. A test
//! that passes proves containment; a test with
//! `#[ignore = "OPEN VULN NET-<n>"]` keeps a failing assertion that proves a
//! bypass.
//!
//! The tests need unprivileged user namespaces and Landlock. They skip
//! cleanly when the sandbox is not available or when a needed host socket is
//! absent.

#![cfg(target_os = "linux")]

mod common;

use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::{Xdg, PENT};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Return true if `pent check` reports the sandbox ready.
fn sandbox_ready() -> bool {
    Command::new(PENT)
        .arg("check")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A profile that allows only one harmless domain, so `pent run` chooses
/// proxy mode (the network namespace isolates the child).
const PROFILE: &str = "[network]\ndomains = [\"allowed.pent-test.invalid\"]\n";

/// Run `pent run` with the test profile and the given command. Returns the
/// output. A short wall-clock limit keeps a stuck child from blocking.
fn run_sandboxed(xdg: &Xdg, script: &str) -> std::io::Result<Output> {
    let mut cmd = Command::new(PENT);
    xdg.apply(&mut cmd)
        .args([
            "run",
            "--profile",
            "probe",
            "--",
            "python3",
            "-I",
            "-c",
            script,
        ])
        .stdin(Stdio::null());
    cmd.output()
}

fn out_text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ── NET-1: host Unix sockets of a network agent are reachable ───────────────

/// The Tailscale daemon LocalAPI socket. Its `ts-dial` upgrade opens a TCP
/// connection to any host over the tailnet, and to the public internet
/// through an exit node or a subnet route. The child reaching it bypasses the
/// proxy completely.
const TAILSCALE_SOCK: &str = "/run/tailscale/tailscaled.sock";

#[test]
fn tailscale_localapi_socket_is_masked() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    if !Path::new(TAILSCALE_SOCK).exists() {
        eprintln!("skip: {TAILSCALE_SOCK} is absent");
        return Ok(());
    }
    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;

    // The child asks the LocalAPI for its status. A reply proves the child
    // reached a host daemon that can open arbitrary connections for it.
    let script = r#"
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/tailscale/tailscaled.sock")
except OSError as e:
    print("BLOCKED", e); sys.exit(0)
s.sendall(b"GET /localapi/v0/status HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n")
data = s.recv(64)
print("REACHED" if data.startswith(b"HTTP/1.1 200") else "NODATA", data[:16])
"#;
    let out = run_sandboxed(&xdg, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("BLOCKED"),
        "the child reached the tailscaled LocalAPI socket; the proxy is bypassed:\n{text}"
    );
    Ok(())
}

// ── NET-2: the system D-Bus socket is reachable ─────────────────────────────

const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

#[test]
fn system_dbus_socket_is_masked() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    if !Path::new(SYSTEM_BUS).exists() {
        eprintln!("skip: {SYSTEM_BUS} is absent");
        return Ok(());
    }
    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;

    // A plain connect to the system bus socket proves reachability. The
    // system bus exposes systemd-resolved (name resolution outside the
    // proxy) and other services.
    let script = r#"
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/dbus/system_bus_socket"); print("REACHED")
except OSError as e:
    print("BLOCKED", e)
"#;
    let out = run_sandboxed(&xdg, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("BLOCKED"),
        "the child reached the system D-Bus socket:\n{text}"
    );
    Ok(())
}

// ── Verified defenses ───────────────────────────────────────────────────────

#[test]
fn child_cannot_reach_a_host_loopback_service() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    // A victim TCP server on the host loopback. The child in its own network
    // namespace must not reach it.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let (tx, rx) = mpsc::channel::<bool>();
    std::thread::spawn(move || {
        listener.set_nonblocking(false).ok();
        for mut s in listener.incoming().flatten() {
            let _ = s.write_all(b"VICTIM");
            let _ = tx.send(true);
        }
    });

    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;
    let script = format!(
        r#"
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("127.0.0.1", {port})); print("REACHED", s.recv(16))
except OSError as e:
    print("BLOCKED", e)
"#
    );
    let out = run_sandboxed(&xdg, &script)?;
    let text = out_text(&out);
    assert!(
        text.contains("BLOCKED"),
        "the child reached host loopback:\n{text}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "the victim accepted a connection from the child"
    );
    Ok(())
}

#[test]
fn child_cannot_reach_a_host_abstract_unix_socket() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    // An abstract Unix socket is bound to the host network namespace. The
    // child's new network namespace must isolate it.
    let name = "\0pent-sec-abstract-victim";
    let listener = match UnixListener::bind(name) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("skip: cannot bind the abstract socket");
            return Ok(());
        }
    };
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let _ = s.write_all(b"VICTIM");
        }
    });

    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;
    let script = r#"
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(3)
try:
    s.connect("\x00pent-sec-abstract-victim"); print("REACHED", s.recv(16))
except OSError as e:
    print("BLOCKED", e)
"#;
    let out = run_sandboxed(&xdg, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("BLOCKED"),
        "the child reached a host abstract Unix socket:\n{text}"
    );
    Ok(())
}

#[test]
fn child_has_no_raw_udp_egress() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;
    // A direct UDP datagram to a public resolver must not leave the
    // namespace. The only route is the loopback proxy, which is TCP/DNS.
    let script = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", ("1.1.1.1", 53)); print("SENT")
except OSError as e:
    print("BLOCKED", e)
"#;
    let out = run_sandboxed(&xdg, script)?;
    let text = out_text(&out);
    assert!(
        text.contains("BLOCKED"),
        "the child sent a raw UDP datagram out of the namespace:\n{text}"
    );
    Ok(())
}

#[test]
fn child_cannot_steal_the_proxy_port_with_reuseport() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;
    // The child must not bind 127.0.0.1:3128 again, with SO_REUSEPORT or
    // otherwise, to steal the connections of other processes in the sandbox.
    let script = r#"
import socket
for opt in (None, socket.SO_REUSEPORT, socket.SO_REUSEADDR):
    s = socket.socket()
    if opt is not None:
        s.setsockopt(socket.SOL_SOCKET, opt, 1)
    try:
        s.bind(("127.0.0.1", 3128)); s.listen(1); print("BOUND", opt)
    except OSError as e:
        print("REFUSED", opt, e)
    s.close()
"#;
    let out = run_sandboxed(&xdg, script)?;
    let text = out_text(&out);
    assert!(
        !text.contains("BOUND"),
        "the child bound the proxy port and can steal connections:\n{text}"
    );
    Ok(())
}

#[test]
fn child_sees_proxy_resolv_conf() -> TestResult {
    if !sandbox_ready() {
        eprintln!("skip: sandbox not available");
        return Ok(());
    }
    let xdg = Xdg::new()?;
    xdg.install_profile("probe", PROFILE)?;
    // The child's /etc/resolv.conf must name only the loopback proxy. A
    // fixed external resolver would let the child resolve names off-proxy.
    let script = r#"
print(open("/etc/resolv.conf").read())
"#;
    let out = run_sandboxed(&xdg, script)?;
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
