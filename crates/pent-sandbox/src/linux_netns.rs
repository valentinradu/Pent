//! Linux network namespace management for network isolation.
//!
//! Creates isolated network namespaces for sandboxed processes.
//! Requires root or `CAP_NET_ADMIN` capability.
#![allow(unreachable_pub)]
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
//! - `LocalhostOnly`: Namespace with loopback only
//! - `ProxyOnly`: Namespace with veth pair routing through proxy
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
    /// Create a network namespace config using the current process PID.
    ///
    /// PIDs are unique among running processes, so each pent invocation gets
    /// its own namespace name and IP range.
    pub fn from_pid() -> Self {
        let pid = std::process::id();
        #[allow(clippy::cast_possible_truncation)] // pid % 256 is always < 256
        let octet = (pid % 256) as u8;

        Self {
            name: format!("pent-{pid}"),
            inner_ip: Ipv4Addr::new(10, 200, octet, 2),
            outer_ip: Ipv4Addr::new(10, 200, octet, 1),
            prefix_len: 24,
        }
    }
}

/// Handle to a `ProxyOnly` sandbox network namespace.
///
/// The child process creates its own network namespace via
/// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in its `pre_exec` hook.
/// `create_netns` sets up the outer (host-side) veth and firewall rules;
/// the background thread in `spawn_with_landlock` moves the inner veth into
/// the child's namespace once it's ready (signalled via pipe).
///
/// Dropping the handle removes firewall/routing rules and deletes the veth pair.
pub struct NetnsHandle {
    /// Host-side veth IP — injected into the child's env as `HTTP_PROXY` etc.
    pub outer_ip: std::net::Ipv4Addr,
    /// Inner veth name (e.g. `veth-PID-in`). Captured in the `pre_exec` closure
    /// so the child can configure it after the parent moves it in.
    pub inner_veth: String,
    /// CIDR for the inner veth (e.g. `10.200.1.2/24`).
    pub inner_cidr: String,
    veth_outer: String,
    outer_cidr: String,
    /// Name of the per-instance nft table used for DNS PREROUTING redirect
    /// (e.g. `pent_dns_12345`). Empty if DNS redirect was not set up.
    nft_dns_table: String,
}

impl Drop for NetnsHandle {
    fn drop(&mut self) {
        use std::process::Command;

        let log_cleanup = |label: &str, result: std::io::Result<std::process::Output>| {
            match result {
                Ok(out) if !out.status.success() => {
                    tracing::debug!(
                        cmd = label,
                        stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                        "cleanup command failed (may be expected if resource already removed)"
                    );
                }
                Err(e) => tracing::warn!(cmd = label, err = %e, "failed to run cleanup command"),
                _ => {}
            }
        };

        // Delete the outer veth. If the child's namespace is already gone the
        // inner veth (and thus the outer peer) may already be deleted — that's
        // fine, ip link del is idempotent from our perspective.
        let mut del = Command::new("ip");
        del.args(["link", "del", &self.veth_outer]);
        // SAFETY: raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { del.pre_exec(raise_net_admin_ambient) };
        log_cleanup("ip link del", del.output());

        if let Some(h) = nft_find_iface_rule_handle("input", "iifname", &self.veth_outer) {
            let mut cmd = Command::new("nft");
            cmd.args(["delete", "rule", "inet", "filter", "input", "handle", &h.to_string()]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            log_cleanup("nft delete rule input", cmd.output());
        }
        if let Some(h) = nft_find_iface_rule_handle("output", "oifname", &self.veth_outer) {
            let mut cmd = Command::new("nft");
            cmd.args(["delete", "rule", "inet", "filter", "output", "handle", &h.to_string()]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            log_cleanup("nft delete rule output", cmd.output());
        }

        // Remove INPUT ACCEPT rule for the veth.
        {
            let mut cmd = Command::new("iptables");
            cmd.args(["-D", "INPUT", "-i", &self.veth_outer, "-j", "ACCEPT"]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            log_cleanup("iptables -D INPUT", cmd.output());
        }

        // Remove policy routing rule that bypasses VPN/tunnel policy routes for
        // the veth subnet.
        {
            let mut cmd = Command::new("ip");
            cmd.args(["rule", "del", "to", &self.outer_cidr, "table", "main", "priority", "100"]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            log_cleanup("ip rule del", cmd.output());
        }

        // Delete the per-instance nft DNS redirect table.
        if !self.nft_dns_table.is_empty() {
            let mut cmd = Command::new("nft");
            cmd.args(["delete", "table", "ip", &self.nft_dns_table]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            log_cleanup("nft delete table dns", cmd.output());
        }
    }
}

/// Raise `CAP_NET_ADMIN` as an ambient capability in the calling process.
///
/// Called in a fork child (before exec) so that the exec'd binary
/// inherits `CAP_NET_ADMIN` even if it has no file capabilities of its own.
///
/// If running as root (UID 0), this is a no-op since root has all capabilities.
/// Otherwise, requires `CAP_NET_ADMIN` in the permitted, effective, AND inheritable sets.
/// Set on the `pent` binary via `setcap cap_net_admin=eip pent` (note: must include 'i' flag).
///
/// Typical usage: `pent run --allow domain --` automatically uses `sudo` when needed,
/// which runs the entire process as root, so this function becomes a no-op.
pub fn raise_net_admin_ambient() -> std::io::Result<()> {
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

    // If running as root, we already have all capabilities; no need to do anything.
    // SAFETY: geteuid is always safe to call.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }

    // SAFETY: capget/capset/prctl syscalls are safe with valid pointers;
    // this runs in a single-threaded fork child before exec.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];

        if libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) != 0 {
            let errno = std::io::Error::last_os_error();
            // Write to stderr since logging from pre_exec doesn't work
            let msg = format!("capget failed: {errno}\n");
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
            return Err(errno);
        }

        // Check if CAP_NET_ADMIN is already in the effective set
        let cap_bit = 1u32 << CAP_NET_ADMIN;
        if (data[0].effective & cap_bit) == 0 {
            let effective = data[0].effective;
            let permitted = data[0].permitted;
            let msg = format!(
                "CAP_NET_ADMIN not in effective set (effective=0x{effective:x}, permitted=0x{permitted:x})\n"
            );
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        }

        // Add CAP_NET_ADMIN to the inheritable set — required before raising as ambient.
        data[0].inheritable |= cap_bit;
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        hdr.pid = 0;

        if libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) != 0 {
            let errno = std::io::Error::last_os_error();
            let msg = format!("capset failed: {errno}\n");
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
            return Err(errno);
        }

        // Raise CAP_NET_ADMIN as ambient so the exec'd binary inherits it.
        if libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, libc::c_ulong::from(CAP_NET_ADMIN), 0, 0) != 0 {
            let errno = std::io::Error::last_os_error();
            let msg = format!("prctl(CAP_AMBIENT_RAISE) failed: {errno}\n");
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
            return Err(errno);
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
        "ProxyOnly mode on Linux requires CAP_NET_ADMIN to create the veth pair \
         between the sandbox and the proxy. \
         Run: sudo setcap cap_net_admin=eip $(which pent)\n\
         Or use --network localhost/blocked which do not require elevated privileges.".to_string()
    ))
}

/// Create the host-side network plumbing for a `ProxyOnly` sandbox.
///
/// Creates a veth pair and configures the outer (host-side) end. The inner
/// veth is left in the host namespace until the child calls
/// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in its `pre_exec` hook; the
/// background thread in `spawn_with_landlock` then moves it with
/// `move_inner_veth_to_pid`. The child configures its end via `run_ip_local`
/// while still inside `pre_exec` (before Landlock is applied).
///
/// `dns_port` is the port of the proxy's DNS server (bound on 0.0.0.0). If
/// non-zero, a per-instance nft PREROUTING REDIRECT table is created so that
/// DNS queries (UDP/TCP port 53) arriving from the child on the outer veth are
/// redirected to the proxy DNS server. This runs in the initial user namespace
/// with ambient `CAP_NET_ADMIN`, so nft NAT works correctly.
///
/// Dropping the handle removes firewall/routing rules and the outer veth.
///
/// # Errors
/// * `PrivilegeRequired` — if `CAP_NET_ADMIN` is absent
/// * `NetworkSetupFailed` — if any setup step fails
#[allow(clippy::too_many_lines)]
pub fn create_netns(config: &NetnsConfig, dns_port: u16) -> Result<NetnsHandle, SandboxError> {
    use std::process::Command;

    check_netns_privileges()?;

    let pid_str = config.name.strip_prefix("pent-").unwrap_or(&config.name);
    let veth_inner = format!("veth-{pid_str}-in");
    let veth_outer = format!("veth-{pid_str}-out");
    let inner_cidr = format!("{}/{}", config.inner_ip, config.prefix_len);
    let outer_cidr = format!("{}/{}", config.outer_ip, config.prefix_len);

    let run_ip = |args: &[&str]| -> Result<(), SandboxError> {
        let mut cmd = Command::new("ip");
        cmd.args(args);
        // SAFETY: pre_exec runs in a single-threaded fork child before exec;
        // raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        let output = cmd.output().map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("failed to run ip: {e}"))
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

    let run_nft = |args: &[&str]| -> Result<(), SandboxError> {
        let mut cmd = Command::new("nft");
        cmd.args(args);
        // SAFETY: pre_exec runs in a single-threaded fork child before exec;
        // raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        let output = cmd.output().map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("failed to run nft: {e}"))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "nft {} failed: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    };

    // Create veth pair. Both ends start in the host namespace; the background
    // thread moves veth_inner to the child after it unshares.
    run_ip(&["link", "add", &veth_inner, "type", "veth", "peer", "name", &veth_outer])?;

    // Configure outer veth; on error clean up the pair.
    if let Err(e) = (|| -> Result<(), SandboxError> {
        run_ip(&["addr", "add", &outer_cidr, "dev", &veth_outer])?;
        run_ip(&["link", "set", &veth_outer, "up"])
    })() {
        let _ = run_ip(&["link", "del", &veth_outer]);
        return Err(e);
    }

    // Add a policy routing rule so that packets destined for the veth subnet
    // are always routed via the main table. Without this, policy routing rules
    // from VPNs, tunnels, or other tools (e.g. a default-route override with
    // high priority) might route return traffic for the child through the wrong
    // interface, causing the proxy ↔ child TCP connections to fail.
    {
        let mut cmd = Command::new("ip");
        cmd.args(["rule", "add", "to", &outer_cidr, "table", "main", "priority", "100"]);
        // SAFETY: raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        match cmd.output() {
            Ok(out) if !out.status.success() => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ip rule add for veth subnet failed; proxy connections may fail if \
                 high-priority policy routing overrides the main table for this subnet"
            ),
            Err(e) => tracing::debug!(err = %e, "failed to run ip rule add"),
            _ => {}
        }
    }

    // Allow traffic through the veth interface in the host firewall.
    // nftables and iptables rules are added as a best-effort; failure is logged
    // at debug level since these tools may not be installed or the default
    // filter table may not exist on this system.
    // NOTE: All firewall commands need CAP_NET_ADMIN; we raise it as ambient.
    {
        let mut cmd = Command::new("nft");
        cmd.args(["insert", "rule", "inet", "filter", "input",
            &format!("iifname \"{veth_outer}\" accept")]);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        match cmd.output() {
            Ok(out) if !out.status.success() => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "nft insert rule input failed (no inet filter table?)"
            ),
            Err(e) => tracing::debug!(err = %e, "failed to run nft insert rule input"),
            _ => {}
        }
    }
    {
        let mut cmd = Command::new("nft");
        cmd.args(["insert", "rule", "inet", "filter", "output",
            &format!("oifname \"{veth_outer}\" accept")]);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        match cmd.output() {
            Ok(out) if !out.status.success() => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "nft insert rule output failed (no inet filter table?)"
            ),
            Err(e) => tracing::debug!(err = %e, "failed to run nft insert rule output"),
            _ => {}
        }
    }
    {
        let mut cmd = Command::new("iptables");
        cmd.args(["-I", "INPUT", "1", "-i", &veth_outer, "-j", "ACCEPT"]);
        // SAFETY: raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        match cmd.output() {
            Ok(out) if !out.status.success() => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "iptables -I INPUT failed"
            ),
            Err(e) => tracing::debug!(err = %e, "failed to run iptables -I INPUT"),
            _ => {}
        }
    }

    // Set up a per-instance nft PREROUTING DNAT table to redirect DNS queries
    // (port 53) arriving from the child on the outer veth to the proxy's DNS
    // server at outer_ip:dns_port.
    //
    // This runs in the initial user namespace with ambient CAP_NET_ADMIN so
    // nft NAT operations succeed (unlike child-side NAT which requires
    // initial-namespace privileges and always fails in a user namespace).
    //
    // When the child sends a DNS query to outer_ip:53, the PREROUTING hook
    // fires before the routing decision and rewrites the destination port to
    // dns_port. The kernel then routes the packet locally to the proxy's DNS
    // socket. No ip_forward changes are needed.
    let nft_dns_table = if dns_port != 0 {
        let table = format!("pent_dns_{pid_str}");
        let result = (|| -> Result<(), SandboxError> {
            run_nft(&["add", "table", "ip", &table])?;
            run_nft(&[
                "add", "chain", "ip", &table, "prerouting",
                "{ type nat hook prerouting priority -100 ; }",
            ])?;
            for proto in &["udp", "tcp"] {
                let rule = format!(
                    "iifname \"{}\" {} dport 53 dnat to {}:{}",
                    veth_outer, proto, config.outer_ip, dns_port
                );
                run_nft(&["add", "rule", "ip", &table, "prerouting", &rule])?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => table,
            Err(e) => {
                tracing::warn!(
                    "DNS redirect via nft failed; non-proxy-aware DNS may not work: {}",
                    e
                );
                // Best-effort cleanup of the partially-created table.
                let mut cmd = Command::new("nft");
                cmd.args(["delete", "table", "ip", &table]);
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { cmd.pre_exec(raise_net_admin_ambient) };
                let _ = cmd.output();
                String::new()
            }
        }
    } else {
        String::new()
    };

    Ok(NetnsHandle {
        outer_ip: config.outer_ip,
        inner_veth: veth_inner,
        inner_cidr,
        veth_outer,
        outer_cidr,
        nft_dns_table,
    })
}

/// Find the handle number of an nftables ACCEPT rule for a specific interface.
///
/// Runs `nft -a list chain inet filter {chain}` and returns the handle of the
/// first rule that references `{iface_name}` with `{iface_keyword}` (either
/// `iifname` for input or `oifname` for output). Returns `None` if the rule is
/// not found or if nftables is unavailable.
fn nft_find_iface_rule_handle(chain: &str, iface_keyword: &str, iface_name: &str) -> Option<u64> {
    use std::process::Command;

    let mut cmd = Command::new("nft");
    cmd.args(["-a", "list", "chain", "inet", "filter", chain]);
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { cmd.pre_exec(raise_net_admin_ambient) };
    let output = cmd.output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let quoted = format!("\"{iface_name}\"");

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

/// Run `ip <args>` in the calling process's current network namespace.
///
/// Forks a helper, raises `CAP_NET_ADMIN` as ambient, then `execvp("ip",
/// args)`. Used inside the sandboxed child's `pre_exec` hook (after
/// `unshare(CLONE_NEWNET)`) to configure the inner veth once the parent
/// background thread has moved it in.
///
/// # Errors
/// Returns `NetworkSetupFailed` if fork/exec/waitpid fails or ip exits
/// non-zero (exit 4 = raise ambient failed, exit 127 = execvp failed).
pub fn run_ip_local(args: &[&str]) -> Result<(), SandboxError> {
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
            // SAFETY: single-threaded child; async-signal-safe ops only.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if raise_net_admin_ambient().is_err() {
                unsafe { libc::_exit(4) };
            }

            // SAFETY: "ip" contains no null bytes; _exit is async-signal-safe.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ip_cstr = match CString::new("ip") {
                Ok(s) => s,
                Err(_) => unsafe { libc::_exit(127) },
            };
            let mut c_args: Vec<CString> = vec![ip_cstr.clone()];
            for a in args {
                let cs = match CString::new(*a) {
                    Ok(s) => s,
                    Err(_) => unsafe { libc::_exit(127) },
                };
                c_args.push(cs);
            }
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
            // SAFETY: waitpid on a known child pid.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let (exited, code) = unsafe {
                let ret = libc::waitpid(child_pid, &raw mut status, 0);
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


/// Set up resolv.conf inside the child's own network namespace.
///
/// Must be called from the child's `pre_exec` hook, after the child has called
/// `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)` and configured its
/// veth/loopback/routes, but before Landlock is applied.
///
/// # What this does
///
/// 1. Makes the mount tree private (`MS_REC|MS_PRIVATE`) so subsequent mounts
///    don't propagate back to the host.  Must be called AFTER overlayfs mounts
///    (making the tree private before overlayfs causes EACCES on some kernels).
/// 2. Mounts a fresh tmpfs on `/run` to give us a writable scratch space
///    invisible to the host.
/// 3. Writes `nameserver <outer_ip>` to `/etc/resolv.conf` so that the child's
///    libc resolver sends DNS queries to the proxy's outer veth IP (port 53).
///    DNS PREROUTING rules set up on the host side (in `create_netns`) redirect
///    those port-53 packets to the proxy's DNS server port.
///
/// Failures are silently ignored — proxy-aware apps use `SOCKS5h` (hostname
/// resolved server-side) and are unaffected. Non-proxy-aware apps benefit from
/// the resolv.conf + host-side PREROUTING redirect.
pub fn setup_child_dns(outer_ip: &str, _dns_port: u16) {
    // ── 0. Make mount tree private ───────────────────────────────────────────
    // After unshare(CLONE_NEWNS), inherited mounts are "slaves".  We must
    // make the tree private before mounting tmpfs on /run or bind-mounting
    // resolv.conf, otherwise the kernel refuses with EPERM.
    //
    // IMPORTANT: this must happen AFTER mount_overlays (if any).  Making the
    // tree private before overlayfs causes EACCES on the overlay mount itself
    // (confirmed on kernel 6.18.9 with btrfs lower + tmpfs upper).
    // SAFETY: mount(2) is always safe with valid pointers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        // SAFETY: write(2) is async-signal-safe.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let msg = b"pent: mount --make-rprivate / failed; tmpfs/resolv.conf may not work\n";
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
        }
    }

    // ── 1. Mount tmpfs on /run ───────────────────────────────────────────────
    // The host's /run is root-owned so an unprivileged user can't write to it.
    // Mounting a fresh tmpfs here (inside CLONE_NEWNS) gives us a writable
    // /run that is invisible to the host.
    // SAFETY: mount(2) is always safe with valid pointers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            c"/run".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        // SAFETY: write(2) is async-signal-safe.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let msg = b"pent: mount tmpfs /run failed; resolv.conf setup may not work\n";
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
        }
    }

    // ── 2. Resolv.conf ───────────────────────────────────────────────────────
    // Point the resolver at outer_ip (the host-side veth IP). DNS queries to
    // port 53 on that IP are intercepted by the host-side nft PREROUTING rule
    // (set up in create_netns) and redirected to the proxy's DNS server port.
    let resolv_content = format!("nameserver {outer_ip}\n");
    setup_child_resolv_conf(&resolv_content);
}

/// Write a custom resolv.conf pointing at the proxy and make it visible.
///
/// Handles three cases:
/// - `/etc/resolv.conf` is a regular file → bind-mount our file over it.
/// - `/etc/resolv.conf` is a symlink into `/run/` → create the target path
///   inside the (now-tmpfs) `/run` and write our file there directly.
/// - Anything else → best-effort bind-mount; errors silently ignored.
fn setup_child_resolv_conf(content: &str) {
    let src = "/run/pent-resolv.conf";
    if let Err(e) = std::fs::write(src, content) {
        eprintln!("pent: write {src}: {e}");
    }

    // Check whether /etc/resolv.conf is a symlink.
    if let Ok(target) = std::fs::read_link("/etc/resolv.conf") {
        let abs_target = if target.is_absolute() {
            target
        } else {
            std::path::PathBuf::from("/etc").join(target)
        };
        // If the symlink target is under /run (e.g. systemd-resolved), create
        // the path inside our tmpfs and write our resolv.conf there.
        if abs_target.starts_with("/run") {
            if let Some(parent) = abs_target.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("pent: mkdir {}: {e}", parent.display());
                }
            }
            if let Err(e) = std::fs::write(&abs_target, content) {
                eprintln!("pent: write {}: {e}", abs_target.display());
            }
            return;
        }
        // Symlink points elsewhere — fall through to bind-mount attempt.
    }

    // Regular file (or symlink pointing outside /run): bind-mount our temp
    // file over /etc/resolv.conf.  MS_BIND follows symlinks for the target,
    // so this also works for symlinks to non-/run paths when the target exists.
    // SAFETY: mount(2) with valid pointers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            c"/run/pent-resolv.conf".as_ptr(),
            c"/etc/resolv.conf".as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        // SAFETY: write(2) is async-signal-safe.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let msg = b"pent: bind-mount /etc/resolv.conf failed; DNS may not work\n";
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
        }
    }
}

/// Move `inner_veth` into the network namespace of process `pid`.
///
/// Called from the background thread in `spawn_with_landlock` after the child
/// has signalled readiness (it has already called `unshare(CLONE_NEWNET)`).
/// Uses `ip link set <inner_veth> netns <pid>`, which only requires
/// `CAP_NET_ADMIN` in the source (host) network namespace.
///
/// # Errors
/// Returns `NetworkSetupFailed` if the `ip link set netns` call fails.
pub fn move_inner_veth_to_pid(
    inner_veth: &str,
    pid: libc::pid_t,
) -> Result<(), SandboxError> {
    use std::process::Command;

    let pid_str = pid.to_string();
    let mut cmd = Command::new("ip");
    cmd.args(["link", "set", inner_veth, "netns", &pid_str]);
    // SAFETY: pre_exec runs in a single-threaded fork child before exec.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { cmd.pre_exec(raise_net_admin_ambient) };
    let output = cmd.output().map_err(|e| {
        SandboxError::NetworkSetupFailed(format!("failed to run ip: {e}"))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::NetworkSetupFailed(format!(
            "ip link set {} netns {} failed: {}",
            inner_veth,
            pid,
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // ========================================================================
    // NetnsConfig::new tests
    // ========================================================================

    #[test]
    fn test_netns_config_name_format() {
        let config = NetnsConfig::from_pid();
        assert!(config.name.starts_with("pent-"));
        let pid = std::process::id().to_string();
        assert!(config.name.contains(&pid));
    }

    #[test]
    fn test_netns_config_ip_range() {
        let config = NetnsConfig::from_pid();
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
        let config = NetnsConfig::from_pid();
        assert_eq!(config.prefix_len, 24);
    }

    // ========================================================================
    // check_netns_privileges tests
    // ========================================================================

    #[test]
    fn test_check_netns_privileges_returns_result() -> TestResult {
        // This will likely fail unless running as root
        let result = check_netns_privileges();
        // Just verify it returns something sensible
        match result {
            Ok(()) | Err(SandboxError::PrivilegeRequired(_)) => {}
            Err(e) => return Err(format!("Unexpected error: {e:?}").into()),
        }
        Ok(())
    }

    // ========================================================================
    // create_netns tests
    // ========================================================================

    // Note: create_netns requires root/CAP_NET_ADMIN
    // These tests would need to run in a privileged environment

    #[test]
    fn test_create_netns_requires_privileges() {
        if check_netns_privileges().is_err() {
            let config = NetnsConfig::from_pid();
            let result = create_netns(&config, 0);
            // Should fail without privileges
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // NetnsHandle tests
    // ========================================================================

    #[test]
    fn test_netns_handle_drop_is_idempotent() {
        // A handle with sentinel values should not panic when dropped.
        // ip link del on a non-existent interface is a no-op from Drop's perspective.
        let handle = NetnsHandle {
            outer_ip: std::net::Ipv4Addr::new(10, 200, 1, 1),
            inner_veth: "veth-test-in".to_string(),
            inner_cidr: "10.200.1.2/24".to_string(),
            veth_outer: "veth-test-out-nonexistent".to_string(),
            outer_cidr: "10.200.1.1/24".to_string(),
            nft_dns_table: String::new(),
        };
        drop(handle); // must not panic or crash
    }

    #[test]
    #[serial]
    fn test_create_netns_returns_valid_handle() -> TestResult {
        if check_netns_privileges().is_err() {
            return Ok(()); // skip — requires CAP_NET_ADMIN
        }
        let config = NetnsConfig::from_pid();
        let handle = create_netns(&config, 0).map_err(|e| format!("create_netns failed: {e:?}"))?;

        // outer_ip must match config
        assert_eq!(handle.outer_ip, config.outer_ip);
        // inner_veth should be set
        assert!(!handle.inner_veth.is_empty());
        // inner_cidr should contain the inner IP
        assert!(handle.inner_cidr.contains(&config.inner_ip.to_string()));

        // Capture veth name before drop
        let veth_outer = format!(
            "veth-{}-out",
            config.name.strip_prefix("pent-").unwrap_or(&config.name)
        );

        // drop cleans up — should not panic
        drop(handle);

        // veth-out should be gone after drop
        let output = std::process::Command::new("ip")
            .args(["link", "show", &veth_outer])
            .output()
            .map_err(|e| format!("ip link show failed: {e}"))?;
        assert!(
            !output.status.success(),
            "veth-out should be deleted after NetnsHandle drop"
        );
        Ok(())
    }

}
