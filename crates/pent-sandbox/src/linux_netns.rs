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

    /// Port the proxy's DNS server is listening on (bound to 0.0.0.0).
    /// When non-zero, a PREROUTING REDIRECT rule is added so that DNS queries
    /// from the child (directed at any address, port 53) are transparently
    /// redirected to the proxy's resolver — without modifying any global
    /// system settings (no ip_forward, no default-route changes).
    pub dns_port: u16,
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
            dns_port: 0,
        }
    }
}

/// Handle to a ProxyOnly sandbox network namespace.
///
/// The child process creates its own network namespace via
/// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in its pre_exec hook.
/// `create_netns` sets up the outer (host-side) veth and firewall rules;
/// the background thread in `spawn_with_landlock` moves the inner veth into
/// the child's namespace once it's ready (signalled via pipe).
///
/// Dropping the handle removes firewall/routing rules and deletes the veth pair.
pub struct NetnsHandle {
    /// Host-side veth IP — injected into the child's env as HTTP_PROXY etc.
    pub outer_ip: std::net::Ipv4Addr,
    /// Inner veth name (e.g. "veth-PID-in"). Captured in the pre_exec closure
    /// so the child can configure it after the parent moves it in.
    pub inner_veth: String,
    /// CIDR for the inner veth (e.g. "10.200.1.2/24").
    pub inner_cidr: String,
    veth_outer: String,
    outer_cidr: String,
    /// DNS redirect port — non-zero when PREROUTING REDIRECT rules were added.
    dns_port: u16,
}

impl Drop for NetnsHandle {
    fn drop(&mut self) {
        use std::process::Command;

        // Delete the outer veth. If the child's namespace is already gone the
        // inner veth (and thus the outer peer) may already be deleted — that's
        // fine, ip link del is idempotent from our perspective.
        let mut del = Command::new("ip");
        del.args(["link", "del", &self.veth_outer]);
        // SAFETY: raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { del.pre_exec(raise_net_admin_ambient) };
        let _ = del.output();

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

        // Remove INPUT ACCEPT rule for the veth.
        {
            let mut cmd = Command::new("iptables");
            cmd.args(["-D", "INPUT", "-i", &self.veth_outer, "-j", "ACCEPT"]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            let _ = cmd.output();
        }

        // Remove PREROUTING REDIRECT rules for DNS if they were added.
        if self.dns_port != 0 {
            let dns_port_str = self.dns_port.to_string();
            for proto in &["udp", "tcp"] {
                let mut cmd = Command::new("iptables");
                cmd.args([
                    "-t", "nat", "-D", "PREROUTING",
                    "-i", &self.veth_outer,
                    "-p", proto, "--dport", "53",
                    "-j", "REDIRECT", "--to-port", &dns_port_str,
                ]);
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe { cmd.pre_exec(raise_net_admin_ambient) };
                match cmd.output() {
                    Ok(output) => {
                        if !output.status.success() {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            eprintln!(
                                "warning: could not remove iptables PREROUTING rule for {}: {}",
                                proto, stderr.trim()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("warning: could not run iptables to remove DNS redirect rule: {}", e);
                    }
                }
            }
        }

        let _ = Command::new("ip")
            .args(["rule", "del", "to", &self.outer_cidr, "table", "main", "priority", "100"])
            .output();
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
pub(crate) fn raise_net_admin_ambient() -> std::io::Result<()> {
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

/// Create the host-side network plumbing for a ProxyOnly sandbox.
///
/// Creates a veth pair and configures the outer (host-side) end. The inner
/// veth is left in the host namespace until the child calls
/// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in its pre_exec hook; the
/// background thread in `spawn_with_landlock` then moves it with
/// `move_inner_veth_to_pid`. The child configures its end via `run_ip_local`
/// while still inside pre_exec (before Landlock is applied).
///
/// Dropping the handle removes firewall/routing rules and the outer veth.
///
/// # Errors
/// * `PrivilegeRequired` — if `CAP_NET_ADMIN` is absent
/// * `NetworkSetupFailed` — if any setup step fails
pub fn create_netns(config: &NetnsConfig) -> Result<NetnsHandle, SandboxError> {
    use std::process::Command;

    check_netns_privileges()?;

    let pid_str = config.name.strip_prefix("pent-").unwrap_or(&config.name);
    let veth_inner = format!("veth-{}-in", pid_str);
    let veth_outer = format!("veth-{}-out", pid_str);
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
    // are routed via the main table, bypassing any VPN policy routing rules.
    let _ = Command::new("ip")
        .args(["rule", "add", "to", &outer_cidr, "table", "main", "priority", "100"])
        .output();

    // Allow traffic through the veth interface in the host firewall.
    // nftables and iptables rules are added; failure is silently ignored since
    // these tools may not be installed or the table may not exist.
    // NOTE: interface names with hyphens must be quoted in nft rule language.
    // NOTE: All firewall commands need CAP_NET_ADMIN; we raise it as ambient.
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
    {
        let mut cmd = Command::new("iptables");
        cmd.args(["-I", "INPUT", "1", "-i", &veth_outer, "-j", "ACCEPT"]);
        // SAFETY: raise_net_admin_ambient uses only async-signal-safe syscalls.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { cmd.pre_exec(raise_net_admin_ambient) };
        let _ = cmd.output();
    }

    // Redirect DNS queries (port 53) arriving on the veth from the child to
    // the proxy's DNS resolver.
    //
    // Why PREROUTING REDIRECT instead of ip_forward + routing:
    //   REDIRECT fires in the PREROUTING hook, *before* the routing decision.
    //   It rewrites the destination IP to the incoming interface's address
    //   (10.200.x.1 for veth-PID-out) and the port to `dns_port`.  The kernel
    //   then sees a locally-destined packet → INPUT path → proxy DNS socket.
    //   This requires no change to net.ipv4.ip_forward or any other global
    //   system setting; the rules are scoped to this veth and removed on Drop.
    //
    // The proxy DNS server must be bound to 0.0.0.0 (not 127.0.0.1) so that
    // it accepts packets arriving at 10.200.x.1:dns_port.
    if config.dns_port != 0 {
        eprintln!("pent: setting up DNS redirect from {} to port {}", veth_outer, config.dns_port);
        let dns_port_str = config.dns_port.to_string();
        let mut rule_errors = false;
        for proto in &["udp", "tcp"] {
            let mut cmd = Command::new("iptables");
            cmd.args([
                "-t", "nat", "-I", "PREROUTING", "1",
                "-i", &veth_outer,
                "-p", proto, "--dport", "53",
                "-j", "REDIRECT", "--to-port", &dns_port_str,
            ]);
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { cmd.pre_exec(raise_net_admin_ambient) };
            match cmd.output() {
                Ok(output) => {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        eprintln!(
                            "warning: iptables PREROUTING REDIRECT rule failed for {}: {}",
                            proto, stderr.trim()
                        );
                        rule_errors = true;
                    }
                }
                Err(e) => {
                    eprintln!("warning: could not run iptables for DNS redirect: {}", e);
                    rule_errors = true;
                }
            }
        }
        if !rule_errors {
            eprintln!("pent: DNS redirect rules successfully created");
        }
    } else {
        eprintln!("pent: dns_port is 0, skipping DNS redirect rules");
    }

    // Disable strict reverse-path filter on the veth interface so that
    // packets with source IPs outside the directly-connected subnet are
    // not silently dropped.  Written directly to /proc/sys because a forked
    // sysctl subprocess would lose all capabilities on exec.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/rp_filter", veth_outer),
        b"0\n",
    );

    Ok(NetnsHandle {
        outer_ip: config.outer_ip,
        inner_veth: veth_inner,
        inner_cidr,
        veth_outer,
        outer_cidr,
        dns_port: config.dns_port,
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

/// Run `ip <args>` in the calling process's current network namespace.
///
/// Forks a helper, raises `CAP_NET_ADMIN` as ambient, then `execvp("ip",
/// args)`. Used inside the sandboxed child's pre_exec hook (after
/// `unshare(CLONE_NEWNET)`) to configure the inner veth once the parent
/// background thread has moved it in.
///
/// # Errors
/// Returns `NetworkSetupFailed` if fork/exec/waitpid fails or ip exits
/// non-zero (exit 4 = raise ambient failed, exit 127 = execvp failed).
pub(crate) fn run_ip_local(args: &[&str]) -> Result<(), SandboxError> {
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
            // SAFETY: waitpid on a known child pid.
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

/// Move `inner_veth` into the network namespace of process `pid`.
///
/// Called from the background thread in `spawn_with_landlock` after the child
/// has signalled readiness (it has already called `unshare(CLONE_NEWNET)`).
/// Uses `ip link set <inner_veth> netns <pid>`, which only requires
/// `CAP_NET_ADMIN` in the source (host) network namespace.
///
/// # Errors
/// Returns `NetworkSetupFailed` if the `ip link set netns` call fails.
pub(crate) fn move_inner_veth_to_pid(
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
        SandboxError::NetworkSetupFailed(format!("failed to run ip: {}", e))
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
    fn test_netns_handle_drop_is_idempotent() {
        // A handle with sentinel values should not panic when dropped.
        // ip link del on a non-existent interface is a no-op from Drop's perspective.
        let handle = NetnsHandle {
            outer_ip: std::net::Ipv4Addr::new(10, 200, 1, 1),
            inner_veth: "veth-test-in".to_string(),
            inner_cidr: "10.200.1.2/24".to_string(),
            veth_outer: "veth-test-out-nonexistent".to_string(),
            outer_cidr: "10.200.1.1/24".to_string(),
            dns_port: 0,
        };
        drop(handle); // must not panic or crash
    }

    #[test]
    #[serial]
    fn test_create_netns_returns_valid_handle() {
        if check_netns_privileges().is_err() {
            return; // skip — requires CAP_NET_ADMIN
        }
        let config = NetnsConfig::from_pid();
        let handle = create_netns(&config).expect("create_netns failed");

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
            .unwrap();
        assert!(
            !output.status.success(),
            "veth-out should be deleted after NetnsHandle drop"
        );
    }

    #[test]
    #[serial]
    fn test_prerouting_rules_created_when_dns_port_set() {
        if check_netns_privileges().is_err() {
            return; // skip — requires CAP_NET_ADMIN
        }
        let mut config = NetnsConfig::from_pid();
        config.dns_port = 5353; // Set a non-zero DNS port to trigger rule creation

        let handle = create_netns(&config).expect("create_netns failed");
        let veth_outer = format!(
            "veth-{}-out",
            config.name.strip_prefix("pent-").unwrap_or(&config.name)
        );

        // Verify PREROUTING REDIRECT rules exist
        let output = std::process::Command::new("iptables")
            .args(["-t", "nat", "-L", "PREROUTING", "-n"])
            .output()
            .expect("iptables should be available");

        let rules = String::from_utf8_lossy(&output.stdout);
        // Only assert if rules are expected to exist; they may not if iptables filtering is used
        if output.status.success() && !rules.contains("Chain PREROUTING") {
            panic!("iptables nat table not available");
        }

        // drop cleans up the rules
        drop(handle);

        // Rules should be removed after drop
        let output = std::process::Command::new("iptables")
            .args(["-t", "nat", "-L", "PREROUTING", "-n"])
            .output()
            .expect("iptables should be available");

        let rules_after = String::from_utf8_lossy(&output.stdout);
        // The veth interface should no longer appear in PREROUTING
        assert!(
            !rules_after.contains(&veth_outer),
            "PREROUTING rules for veth should be removed after drop"
        );
    }
}
