//! Linux network namespace management for network isolation.
//!
//! Creates isolated network namespaces for sandboxed processes.
//! Requires root or CAP_NET_ADMIN capability.
//!
//! # Network Namespace Architecture
//!
//! ```text
//! Host
//!   |
//!   +-- veth1 (10.200.x.1/24)
//!         |
//!         +-- [routing through pent-proxy]
//!         |
//! --------+-------- namespace boundary
//!         |
//!   +-- veth0 (10.200.x.2/24)
//!         |
//!         +-- default route via 10.200.x.1
//!         |
//!   Sandboxed Process
//! ```
//!
//! # Network Modes
//!
//! - LocalhostOnly: Namespace with loopback only
//! - ProxyOnly: Namespace with veth pair routing through proxy
//! - Blocked: Namespace with no interfaces

use crate::SandboxError;
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;

/// Network namespace configuration.
#[derive(Debug, Clone)]
pub struct NetnsConfig {
    /// Namespace name (e.g., "pent-12345").
    pub name: String,

    /// IP address inside namespace (veth0).
    pub inner_ip: Ipv4Addr,

    /// IP address on host side (veth1).
    pub outer_ip: Ipv4Addr,

    /// Subnet prefix length (e.g., 24 for /24).
    pub prefix_len: u8,
}

impl NetnsConfig {
    /// Create a network namespace config derived from the current process PID.
    ///
    /// The PID is used to derive both the namespace name (`pent-{pid}`) and
    /// the IP range (`10.200.{pid % 256}.0/24`). Using the PID ensures that
    /// each pent invocation gets a unique namespace name and IP range.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::from_pid()
    }

    /// Create a network namespace config using the current process PID.
    ///
    /// PIDs are unique among running processes, so each pent invocation gets
    /// its own namespace name and IP range.
    pub fn from_pid() -> Self {
        let pid = std::process::id();
        let octet = (pid % 256) as u8;

        Self {
            name: format!("pent-{}", pid),
            inner_ip: Ipv4Addr::new(10, 200, octet, 2),
            outer_ip: Ipv4Addr::new(10, 200, octet, 1),
            prefix_len: 24,
        }
    }
}

/// Handle to an anonymous network namespace for ProxyOnly sandbox mode.
///
/// Dropping the handle removes firewall/routing rules added during setup.
/// The namespace fd is closed via `close_fd()` (called by `linux.rs` after
/// `spawn()`) and again in `drop` if not already closed. The veth pair
/// auto-deletes when the namespace is released.
pub struct NetnsHandle {
    /// Namespace fd (O_RDONLY | O_CLOEXEC). The child closes it on exec;
    /// the parent closes it explicitly via `close_fd()` after spawn.
    pub fd: libc::c_int,
    /// User namespace fd (O_RDONLY | O_CLOEXEC). Kept alive so that the
    /// anchor's user namespace (which owns the network namespace) persists
    /// until after `spawn()`. The pre_exec child joins this user namespace
    /// before joining the network namespace. Closed alongside `fd`.
    pub userns_fd: libc::c_int,
    /// Host-side veth IP — injected into the child's env as HTTP_PROXY etc.
    pub outer_ip: std::net::Ipv4Addr,
    fd_closed: bool,
    anchor_pid: libc::pid_t,
    done_write: libc::c_int, // -1 when already released
    veth_outer: String,
    outer_cidr: String,
}

impl NetnsHandle {
    /// Close the namespace fd in the parent.
    ///
    /// Called by `linux.rs` right after `command.spawn()`. The child's copy
    /// was already closed by O_CLOEXEC on exec.
    pub fn close_fd(&mut self) {
        if !self.fd_closed {
            // SAFETY: fd and userns_fd are valid open file descriptors.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::close(self.fd);
                libc::close(self.userns_fd);
            }
            self.fd_closed = true;
        }
    }

    fn release_anchor(&mut self) {
        let done_write = std::mem::replace(&mut self.done_write, -1);
        if done_write >= 0 {
            // SAFETY: done_write is a valid pipe fd; closing it sends EOF to anchor.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::close(done_write);
                let mut status = 0;
                libc::waitpid(self.anchor_pid, &mut status, 0);
            }
        }
    }
}

impl Drop for NetnsHandle {
    fn drop(&mut self) {
        use std::process::Command;

        self.release_anchor();
        self.close_fd();

        if let Some(h) = nft_find_iface_rule_handle("input", "iifname", &self.veth_outer) {
            let _ = Command::new("nft")
                .args(["delete", "rule", "inet", "filter", "input", "handle", &h.to_string()])
                .output();
        }
        if let Some(h) = nft_find_iface_rule_handle("output", "oifname", &self.veth_outer) {
            let _ = Command::new("nft")
                .args(["delete", "rule", "inet", "filter", "output", "handle", &h.to_string()])
                .output();
        }

        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-i", &self.veth_outer, "-j", "ACCEPT"])
            .output();

        let _ = Command::new("ip")
            .args(["rule", "del", "to", &self.outer_cidr, "table", "main", "priority", "100"])
            .output();
    }
}

/// Fork an "anchor" process that creates an anonymous network namespace.
///
/// The anchor calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)` (unprivileged),
/// writes uid/gid maps, signals readiness, then blocks until the write end of
/// the done-pipe is closed.
///
/// Returns `(anchor_pid, done_pipe_write_fd)`. The caller must:
/// 1. Open `/proc/{anchor_pid}/ns/net` to obtain the namespace fd.
/// 2. Do all veth setup using `anchor_pid` as the netns target.
/// 3. Close `done_pipe_write_fd` (and `waitpid`) to release the anchor.
///
/// # Errors
/// Returns `NetworkSetupFailed` if `fork`, `pipe2`, or `unshare` fail.
pub fn spawn_anchor(uid: u32, gid: u32) -> Result<(libc::pid_t, libc::c_int), SandboxError> {
    // ready_pipe[0]=read  ready_pipe[1]=write  (anchor → parent)
    // done_pipe[0]=read   done_pipe[1]=write   (parent → anchor, via EOF)
    let mut ready_pipe = [0i32; 2];
    let mut done_pipe = [0i32; 2];
    // SAFETY: pipe2 is always safe to call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        if libc::pipe2(ready_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return Err(SandboxError::NetworkSetupFailed(format!(
                "pipe2 failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if libc::pipe2(done_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            libc::close(ready_pipe[0]);
            libc::close(ready_pipe[1]);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "pipe2 failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    let [ready_read, ready_write] = ready_pipe;
    let [done_read, done_write] = done_pipe;

    // Build map strings before fork so no heap allocation occurs in the child.
    let uid_map_str = format!("0 {} 1\n", uid);
    let gid_map_str = format!("0 {} 1\n", gid);

    // SAFETY: fork() is always safe. The child branch uses only async-signal-safe
    // operations and pre-fork-allocated stack buffers (uid_map_str, gid_map_str).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            // SAFETY: close is always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::close(ready_read);
                libc::close(ready_write);
                libc::close(done_read);
                libc::close(done_write);
            }
            Err(SandboxError::NetworkSetupFailed(format!(
                "fork failed: {}",
                std::io::Error::last_os_error()
            )))
        }
        0 => {
            // ── Anchor child ──────────────────────────────────────────────────
            // SAFETY: child is single-threaded; all ops are async-signal-safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::close(ready_read);
                libc::close(done_write);

                // Create new user + network namespace (completely unprivileged).
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                    libc::_exit(1);
                }

                // unshare(CLONE_NEWUSER) marks the process non-dumpable, which
                // causes ptrace_may_access() to deny the parent's open() of
                // /proc/<anchor_pid>/ns/net. Restore dumpability so the parent
                // can read our namespace fd.
                libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
            }

            // Write uid/gid maps: map host uid/gid → 0 inside the new user ns.
            // "deny" setgroups is required before writing gid_map.
            // All writes use raw libc syscalls (async-signal-safe); strings were
            // allocated before fork so no heap allocation occurs here.
            // SAFETY: open/write/close are async-signal-safe; paths are null-terminated
            // literals; uid_map_str/gid_map_str were allocated before fork.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                let setgroups_path = b"/proc/self/setgroups\0";
                let fd = libc::open(setgroups_path.as_ptr().cast(), libc::O_WRONLY);
                if fd >= 0 {
                    let n = libc::write(fd, b"deny".as_ptr().cast(), 4);
                    libc::close(fd);
                    if n < 0 {
                        libc::_exit(1);
                    }
                }
                let uid_map_path = b"/proc/self/uid_map\0";
                let fd = libc::open(uid_map_path.as_ptr().cast(), libc::O_WRONLY);
                if fd >= 0 {
                    let n = libc::write(fd, uid_map_str.as_ptr().cast(), uid_map_str.len());
                    libc::close(fd);
                    if n < 0 {
                        libc::_exit(1);
                    }
                }
                let gid_map_path = b"/proc/self/gid_map\0";
                let fd = libc::open(gid_map_path.as_ptr().cast(), libc::O_WRONLY);
                if fd >= 0 {
                    let n = libc::write(fd, gid_map_str.as_ptr().cast(), gid_map_str.len());
                    libc::close(fd);
                    if n < 0 {
                        libc::_exit(1);
                    }
                }
            }

            // Signal ready, then block until parent closes done_write (EOF on done_read).
            // SAFETY: write/read/close/_exit are async-signal-safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::write(ready_write, b"1".as_ptr().cast(), 1);
                libc::close(ready_write);
                let mut buf = [0u8; 1];
                libc::read(done_read, buf.as_mut_ptr().cast(), 1);
                libc::_exit(0);
            }
        }
        anchor_pid => {
            // ── Parent ────────────────────────────────────────────────────────
            // SAFETY: close is always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::close(ready_write);
                libc::close(done_read);
            }

            // Wait for the anchor's ready signal.
            let mut buf = [0u8; 1];
            // SAFETY: read on a valid pipe fd.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let n = unsafe { libc::read(ready_read, buf.as_mut_ptr().cast(), 1) };
            // SAFETY: close is always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(ready_read) };

            if n <= 0 {
                // Anchor failed; reap it.
                // SAFETY: close/waitpid are always safe.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe {
                    libc::close(done_write);
                    let mut status = 0;
                    libc::waitpid(anchor_pid, &mut status, 0);
                }
                return Err(SandboxError::NetworkSetupFailed(
                    "anchor process failed to create network namespace".to_string(),
                ));
            }

            Ok((anchor_pid, done_write))
        }
    }
}

/// Raise `CAP_NET_ADMIN` as an ambient capability in the calling process.
///
/// Called in a fork child (before exec) so that the exec'd `ip` binary
/// inherits `CAP_NET_ADMIN` in its effective set, even though `ip` has no
/// file capabilities of its own.
///
/// Requires `CAP_NET_ADMIN` already in the permitted set (set on the `pent`
/// binary via `setcap cap_net_admin=ep`).
fn raise_net_admin_ambient() -> std::io::Result<()> {
    const CAP_NET_ADMIN: u32 = 12;
    // _LINUX_CAPABILITY_VERSION_3 — two 32-bit data words, supports caps 0–63.
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // PR_CAP_AMBIENT = 47, PR_CAP_AMBIENT_RAISE = 2 (not in libc crate).
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

    // Raw kernel structs for capget/capset (not exposed by the libc crate).
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // SAFETY: capget/capset/prctl syscalls are safe with valid pointers;
    // this runs in a single-threaded fork child before exec.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];

        if libc::syscall(libc::SYS_capget, &mut hdr as *mut _, data.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Add CAP_NET_ADMIN to the inheritable set — required before raising as ambient.
        data[0].inheritable |= 1u32 << CAP_NET_ADMIN;
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        hdr.pid = 0;

        if libc::syscall(libc::SYS_capset, &mut hdr as *mut _, data.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Raise CAP_NET_ADMIN as ambient so the exec'd binary inherits it.
        if libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN as libc::c_ulong, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Check if running with sufficient privileges for network namespaces.
///
/// # Errors
/// Returns `PrivilegeRequired` with sudo/setcap hint if insufficient privileges.
pub fn check_netns_privileges() -> Result<(), SandboxError> {
    use std::fs;

    // Check if running as root
    // SAFETY: geteuid is always safe to call
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return Ok(());
    }

    // Check for CAP_NET_ADMIN in /proc/self/status
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                // Parse the effective capabilities
                if let Some(hex) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(hex, 16) {
                        // CAP_NET_ADMIN is bit 12
                        const CAP_NET_ADMIN: u64 = 1 << 12;
                        if caps & CAP_NET_ADMIN != 0 {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Err(SandboxError::PrivilegeRequired(
        "ProxyOnly mode on Linux requires CAP_NET_ADMIN to create the veth bridge \
         between the sandbox and the proxy. \
         Run: sudo setcap cap_net_admin=ep $(which pent)\n\
         Or use --network localhost/blocked which do not require elevated privileges.".to_string()
    ))
}

/// Create an anonymous network namespace for sandbox isolation.
///
/// Replaces `ip netns add` (which requires `CAP_SYS_ADMIN` for bind-mounts)
/// with a fork-based "anchor" process that calls
/// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` (unprivileged). The parent wires
/// the veth pair using the anchor's PID as the netns target and configures
/// the inner veth via `run_ip_in_netns`.
///
/// The returned `NetnsHandle` holds the namespace fd (for `setns` in the child)
/// and cleanup information. Dropping the handle removes firewall/routing rules.
///
/// # Errors
/// * `PrivilegeRequired` — if `CAP_NET_ADMIN` is absent
/// * `NetworkSetupFailed` — if any setup step fails
pub fn create_netns(config: &NetnsConfig) -> Result<NetnsHandle, SandboxError> {
    use std::ffi::CString;
    use std::process::Command;

    check_netns_privileges()?;

    let pid_str = config.name.strip_prefix("pent-").unwrap_or(&config.name);
    let veth_inner = format!("veth-{}-in", pid_str);
    let veth_outer = format!("veth-{}-out", pid_str);
    let inner_cidr = format!("{}/{}", config.inner_ip, config.prefix_len);
    let outer_cidr = format!("{}/{}", config.outer_ip, config.prefix_len);

    // SAFETY: getuid/getgid are always safe to call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let uid = unsafe { libc::getuid() };
    // SAFETY: getgid is always safe to call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let gid = unsafe { libc::getgid() };

    let run_ip = |args: &[&str]| -> Result<(), SandboxError> {
        let mut cmd = Command::new("ip");
        cmd.args(args);
        // SAFETY: pre_exec runs in a single-threaded fork child before exec;
        // raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        let output = cmd.output().map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("failed to run ip: {}", e))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "ip {} failed: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    };

    // ── Phase A: Create anonymous namespace ───────────────────────────────────
    let (anchor_pid, done_write) = spawn_anchor(uid, gid)?;

    let early_bail = |ns_fd: Option<libc::c_int>, err: SandboxError| -> SandboxError {
        // SAFETY: close/waitpid are always safe; these are known valid fds/pids.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if let Some(fd) = ns_fd {
                libc::close(fd);
            }
            libc::close(done_write);
            let mut status = 0;
            libc::waitpid(anchor_pid, &mut status, 0);
        }
        err
    };

    let ns_cstr = CString::new(format!("/proc/{}/ns/net", anchor_pid)).unwrap();
    // SAFETY: open with a valid CString path and standard flags.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ns_fd = unsafe { libc::open(ns_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if ns_fd < 0 {
        return Err(early_bail(
            None,
            SandboxError::NetworkSetupFailed(format!(
                "failed to open /proc/{}/ns/net: {}",
                anchor_pid,
                std::io::Error::last_os_error()
            )),
        ));
    }

    // Open the anchor's user namespace fd. run_ip_in_netns joins it first to
    // gain CAP_SYS_ADMIN inside the owning user namespace before setns(NEWNET).
    let userns_cstr = CString::new(format!("/proc/{}/ns/user", anchor_pid)).unwrap();
    // SAFETY: open with a valid CString path and standard flags.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let userns_fd =
        unsafe { libc::open(userns_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if userns_fd < 0 {
        return Err(early_bail(
            Some(ns_fd),
            SandboxError::NetworkSetupFailed(format!(
                "failed to open /proc/{}/ns/user: {}",
                anchor_pid,
                std::io::Error::last_os_error()
            )),
        ));
    }

    // Create veth pair on host.
    if let Err(e) = run_ip(&[
        "link", "add", &veth_inner, "type", "veth", "peer", "name", &veth_outer,
    ]) {
        // SAFETY: userns_fd is a valid open fd.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(userns_fd) };
        return Err(early_bail(Some(ns_fd), e));
    }

    // Move inner veth into anchor's namespace (referenced by PID).
    let anchor_pid_str = anchor_pid.to_string();
    if let Err(e) = run_ip(&["link", "set", &veth_inner, "netns", &anchor_pid_str]) {
        let _ = run_ip(&["link", "del", &veth_outer]);
        // SAFETY: userns_fd is a valid open fd.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(userns_fd) };
        return Err(early_bail(Some(ns_fd), e));
    }

    // ── Phase B: veth-in is in the namespace; Drop handles cleanup from here ──

    let mut handle = NetnsHandle {
        fd: ns_fd,
        userns_fd,
        outer_ip: config.outer_ip,
        fd_closed: false,
        anchor_pid,
        done_write,
        veth_outer: veth_outer.clone(),
        outer_cidr: outer_cidr.clone(),
    };

    // Configure outer veth on host.
    run_ip(&["addr", "add", &outer_cidr, "dev", &veth_outer])?;
    run_ip(&["link", "set", &veth_outer, "up"])?;

    // Add a policy routing rule so that packets destined for the veth subnet
    // are routed via the main table, bypassing any VPN policy routing rules.
    // Failure is silently ignored.
    let _ = Command::new("ip")
        .args(["rule", "add", "to", &outer_cidr, "table", "main", "priority", "100"])
        .output();

    // Allow traffic through the veth interface in the host firewall.
    // nftables and iptables rules are added; failure is silently ignored since
    // these tools may not be installed or the table may not exist.
    // NOTE: interface names with hyphens must be quoted in nft rule language.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nft insert rule inet filter input iifname '{}' accept",
            veth_outer
        ))
        .output();
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nft insert rule inet filter output oifname '{}' accept",
            veth_outer
        ))
        .output();
    let _ = Command::new("iptables")
        .args(["-I", "INPUT", "1", "-i", &veth_outer, "-j", "ACCEPT"])
        .output();

    // Disable strict reverse-path filter on the veth-out interface.
    // Failure is silently ignored.
    let _ = Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", veth_outer)])
        .output();

    // Configure inner veth inside the namespace via run_ip_in_netns.
    let gateway = config.outer_ip.to_string();
    run_ip_in_netns(userns_fd, ns_fd, &["addr", "add", &inner_cidr, "dev", &veth_inner])?;
    run_ip_in_netns(userns_fd, ns_fd, &["link", "set", &veth_inner, "up"])?;
    run_ip_in_netns(userns_fd, ns_fd, &["link", "set", "lo", "up"])?;
    run_ip_in_netns(userns_fd, ns_fd, &["route", "add", "default", "via", &gateway])?;

    // userns_fd is stored in the handle and kept open until close_fd() after
    // spawn, so that the anchor's user namespace persists for pre_exec setns.

    // Anchor's job is done; release it. The namespace stays alive via ns_fd.
    handle.release_anchor();

    Ok(handle)
}

/// Find the handle number of an nftables ACCEPT rule for a specific interface.
///
/// Runs `nft -a list chain inet filter {chain}` and returns the handle of the
/// first rule that references `{iface_name}` with `{iface_keyword}` (either
/// `iifname` for input or `oifname` for output). Returns `None` if the rule is
/// not found or if nftables is unavailable.
fn nft_find_iface_rule_handle(chain: &str, iface_keyword: &str, iface_name: &str) -> Option<u64> {
    use std::process::Command;

    let output = Command::new("nft")
        .args(["-a", "list", "chain", "inet", "filter", chain])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let quoted = format!("\"{}\"", iface_name);

    for line in stdout.lines() {
        if line.contains(iface_keyword) && line.contains(quoted.as_str()) {
            // Rule output looks like: `iifname "veth-X-out" accept # handle 42`
            if let Some(pos) = line.rfind("# handle ") {
                let handle_str = line[pos + 9..].trim();
                return handle_str.parse().ok();
            }
        }
    }

    None
}

/// Run `ip <args>` inside the network namespace identified by `ns_fd`.
///
/// Forks a helper process that joins the anchor's user namespace then the
/// network namespace, then `execvp("ip", args)`. The parent waits and
/// propagates non-zero exits as `NetworkSetupFailed`.
///
/// Joining the user namespace first gives the child full capabilities inside
/// it (uid 0 mapping), which satisfies the `CAP_SYS_ADMIN` requirement that
/// `setns(CLONE_NEWNET)` checks against the owning user namespace. Ambient
/// `CAP_NET_ADMIN` is then raised so the exec'd `ip` binary inherits it.
///
/// # Errors
/// Returns `NetworkSetupFailed` if `fork` fails, if `waitpid` fails, or if
/// the `ip` child exits with a non-zero status (exit 2 = setns user ns failed,
/// exit 3 = setns net ns failed, exit 4 = raise ambient failed,
/// exit 127 = execvp failed).
pub fn run_ip_in_netns(
    userns_fd: libc::c_int,
    net_fd: libc::c_int,
    args: &[&str],
) -> Result<(), SandboxError> {
    use std::ffi::CString;

    // SAFETY: fork() is always safe.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(SandboxError::NetworkSetupFailed(format!(
            "fork failed: {}",
            std::io::Error::last_os_error()
        ))),
        0 => {
            // ── Helper child ──────────────────────────────────────────────────
            // Join the anchor's user namespace first. This gives the child uid 0
            // (via the uid map) and full capabilities in that user namespace,
            // satisfying the CAP_SYS_ADMIN check for the subsequent CLONE_NEWNET
            // setns call against the owning user namespace.
            // SAFETY: single-threaded child; setns/_exit are async-signal-safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                if libc::setns(userns_fd, libc::CLONE_NEWUSER) != 0 {
                    libc::_exit(2);
                }
                if libc::setns(net_fd, libc::CLONE_NEWNET) != 0 {
                    libc::_exit(3);
                }
            }

            // Raise CAP_NET_ADMIN as ambient so the exec'd ip binary inherits it.
            if raise_net_admin_ambient().is_err() {
                // SAFETY: _exit is always safe.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { libc::_exit(4) };
            }

            let ip_cstr = CString::new("ip").unwrap();
            let mut c_args: Vec<CString> = vec![ip_cstr.clone()];
            c_args.extend(args.iter().map(|a| CString::new(*a).unwrap()));
            let mut ptrs: Vec<*const libc::c_char> =
                c_args.iter().map(|a| a.as_ptr()).collect();
            ptrs.push(std::ptr::null());

            // SAFETY: execvp with valid null-terminated argv array.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::execvp(ip_cstr.as_ptr(), ptrs.as_ptr()) };
            // SAFETY: _exit is always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::_exit(127) };
        }
        child_pid => {
            let mut status = 0;
            // SAFETY: waitpid on a known child pid; WIFEXITED/WEXITSTATUS on the
            // resulting status value are always safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let (exited, code) = unsafe {
                let ret = libc::waitpid(child_pid, &mut status, 0);
                if ret == -1 {
                    return Err(SandboxError::NetworkSetupFailed(format!(
                        "waitpid failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                (libc::WIFEXITED(status), libc::WEXITSTATUS(status))
            };

            if !exited || code != 0 {
                return Err(SandboxError::NetworkSetupFailed(format!(
                    "ip {} failed (exit {})",
                    args.join(" "),
                    if exited { code } else { -1 }
                )));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // ========================================================================
    // NetnsConfig::new tests
    // ========================================================================

    #[test]
    fn test_netns_config_name_format() {
        let config = NetnsConfig::new();
        assert!(config.name.starts_with("pent-"));
        let pid = std::process::id().to_string();
        assert!(config.name.contains(&pid));
    }

    #[test]
    fn test_netns_config_ip_range() {
        let config = NetnsConfig::new();
        // Inner IP should be 10.200.x.2
        assert_eq!(config.inner_ip.octets()[0], 10);
        assert_eq!(config.inner_ip.octets()[1], 200);
        assert_eq!(config.inner_ip.octets()[3], 2);

        // Outer IP should be 10.200.x.1
        assert_eq!(config.outer_ip.octets()[0], 10);
        assert_eq!(config.outer_ip.octets()[1], 200);
        assert_eq!(config.outer_ip.octets()[3], 1);
    }

    #[test]
    fn test_netns_config_prefix_len() {
        let config = NetnsConfig::new();
        assert_eq!(config.prefix_len, 24);
    }

    // ========================================================================
    // check_netns_privileges tests
    // ========================================================================

    #[test]
    fn test_check_netns_privileges_returns_result() {
        // This will likely fail unless running as root
        let result = check_netns_privileges();
        // Just verify it returns something sensible
        match result {
            Ok(()) => { /* Running as root or with CAP_NET_ADMIN */ }
            Err(SandboxError::PrivilegeRequired(_)) => { /* Expected for non-root */ }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // ========================================================================
    // create_netns tests
    // ========================================================================

    // Note: create_netns requires root/CAP_NET_ADMIN
    // These tests would need to run in a privileged environment

    #[test]
    fn test_create_netns_requires_privileges() {
        if check_netns_privileges().is_err() {
            let config = NetnsConfig::new();
            let result = create_netns(&config);
            // Should fail without privileges
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // NetnsHandle tests
    // ========================================================================

    #[test]
    fn test_spawn_anchor_creates_isolated_namespace() {
        // SAFETY: getuid/getgid are always safe to call.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid is always safe to call.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let gid = unsafe { libc::getgid() };

        let (anchor_pid, done_write) = spawn_anchor(uid, gid)
            .expect("spawn_anchor failed");

        // The anchor's /proc entry must exist
        let anchor_ns_path = format!("/proc/{}/ns/net", anchor_pid);
        assert!(
            std::path::Path::new(&anchor_ns_path).exists(),
            "anchor /proc entry missing"
        );

        // The anchor must be in a *different* network namespace from us
        use std::os::linux::fs::MetadataExt;
        let self_ino = std::fs::metadata("/proc/self/ns/net").unwrap().st_ino();
        let anchor_ino = std::fs::metadata(&anchor_ns_path).unwrap().st_ino();
        assert_ne!(self_ino, anchor_ino, "anchor should be in a different netns");

        // Signal anchor to exit and reap it
        // SAFETY: done_write is a valid open pipe fd; closing it sends EOF to the
        // anchor. waitpid on a valid child pid is always safe.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(done_write);
            let mut status = 0;
            libc::waitpid(anchor_pid, &mut status, 0);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    #[test]
    fn test_netns_handle_drop_is_idempotent() {
        // A handle with sentinel values should not panic when dropped.
        // Tests that the Drop impl guards against double-close.
        let handle = NetnsHandle {
            fd: -1,
            outer_ip: std::net::Ipv4Addr::new(10, 200, 1, 1),
            fd_closed: true,   // already closed — must not close again
            anchor_pid: -1,
            done_write: -1,    // already released — must not close again
            veth_outer: "veth-test-out".to_string(),
            outer_cidr: "10.200.1.1/24".to_string(),
        };
        drop(handle); // must not panic or crash
    }

    #[test]
    #[serial]
    fn test_create_netns_returns_valid_handle() {
        let config = NetnsConfig::from_pid();
        let handle = create_netns(&config).expect("create_netns failed");

        // fd must be a valid open file descriptor
        assert!(handle.fd >= 0);
        // outer_ip must match config
        assert_eq!(handle.outer_ip, config.outer_ip);

        // Capture veth name before drop
        let veth_outer = format!(
            "veth-{}-out",
            config.name.strip_prefix("pent-").unwrap_or(&config.name)
        );

        // drop cleans up — should not panic
        drop(handle);

        // veth-out should be gone after drop (namespace released → veth auto-deleted)
        let output = std::process::Command::new("ip")
            .args(["link", "show", &veth_outer])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "veth-out should be deleted after NetnsHandle drop"
        );
    }

    #[test]
    #[serial]
    fn test_run_ip_in_netns_lo_show() {
        // spawn_anchor to get a namespace, then verify we can run ip inside it.
        // SAFETY: getuid/getgid are always safe to call.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let uid = unsafe { libc::getuid() };
        // SAFETY: getuid/getgid are always safe to call.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let gid = unsafe { libc::getgid() };

        let (anchor_pid, done_write) = spawn_anchor(uid, gid)
            .expect("spawn_anchor failed");

        let ns_path = std::ffi::CString::new(
            format!("/proc/{}/ns/net", anchor_pid)
        ).unwrap();
        let userns_path = std::ffi::CString::new(
            format!("/proc/{}/ns/user", anchor_pid)
        ).unwrap();
        // SAFETY: open with valid CString path and standard flags.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ns_fd = unsafe {
            libc::open(ns_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        assert!(ns_fd >= 0, "open ns_fd failed");
        // SAFETY: open with valid CString path and standard flags.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let userns_fd = unsafe {
            libc::open(userns_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        assert!(userns_fd >= 0, "open userns_fd failed");

        // `ip link show lo` must succeed inside the namespace
        let result = run_ip_in_netns(userns_fd, ns_fd, &["link", "show", "lo"]);

        // SAFETY: done_write/ns_fd/userns_fd are valid open fds; waitpid on a known child pid.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(userns_fd);
            libc::close(ns_fd);
            libc::close(done_write);
            let mut status = 0;
            libc::waitpid(anchor_pid, &mut status, 0);
        }

        result.expect("run_ip_in_netns failed");
    }
}
