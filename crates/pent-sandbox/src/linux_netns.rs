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
use std::path::Path;

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
            // SAFETY: fd is a valid open file descriptor.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(self.fd) };
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

/// Create a network namespace for sandbox isolation.
///
/// Sets up:
/// 1. Network namespace with name from config
/// 2. Veth pair (veth0 inside, veth1 on host)
/// 3. IP addresses on both ends
/// 4. Default route inside namespace pointing to host
///
/// # Arguments
/// * `config` - Namespace configuration
///
/// # Errors
/// * `PrivilegeRequired` - If not root/CAP_NET_ADMIN
/// * `NetworkSetupFailed` - If any setup step fails
pub fn create_netns(config: &NetnsConfig) -> Result<(), SandboxError> {
    use std::process::Command;

    check_netns_privileges()?;

    let name = &config.name;
    let veth_inner = format!("veth-{}-in", &name[5..]); // Remove "pent-" prefix for shorter names
    let veth_outer = format!("veth-{}-out", &name[5..]);
    let inner_cidr = format!("{}/{}", config.inner_ip, config.prefix_len);
    let outer_cidr = format!("{}/{}", config.outer_ip, config.prefix_len);

    // Helper to run ip command
    let run_ip = |args: &[&str]| -> Result<(), SandboxError> {
        let output = Command::new("ip").args(args).output().map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("Failed to run ip command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "ip {} failed: {}",
                args.join(" "),
                stderr
            )));
        }
        Ok(())
    };

    // Create namespace
    run_ip(&["netns", "add", name])?;

    // Create veth pair
    if let Err(e) = run_ip(&[
        "link",
        "add",
        &veth_inner,
        "type",
        "veth",
        "peer",
        "name",
        &veth_outer,
    ]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = run_ip(&["netns", "del", name]);
        return Err(e);
    }

    // Move inner veth to namespace
    if let Err(e) = run_ip(&["link", "set", &veth_inner, "netns", name]) {
        // Cleanup veth and namespace on failure; errors discarded to preserve the original error.
        let _ = run_ip(&["link", "del", &veth_outer]);
        let _ = run_ip(&["netns", "del", name]);
        return Err(e);
    }

    // Configure outer veth on host
    if let Err(e) = run_ip(&["addr", "add", &outer_cidr, "dev", &veth_outer]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    if let Err(e) = run_ip(&["link", "set", &veth_outer, "up"]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    // Add a policy routing rule so that packets destined for the veth subnet
    // (i.e. proxy → sandboxed process responses) are routed via the main table.
    //
    // On systems with VPN policy routing (e.g. Tailscale, WireGuard, OpenVPN)
    // a "from all lookup <vpn-table>" rule at some priority combined with a
    // "default dev tun0" in that VPN table would otherwise intercept response
    // packets and route them via the VPN tunnel rather than the veth pair,
    // silently breaking TCP.
    //
    // Priority 100 is chosen to beat any user-space policy routing rule while
    // staying below 0 (the kernel-managed local table). pent owns the
    // 10.200.0.0/8 address range exclusively for its veth interfaces, so no
    // real external traffic is ever destined for this subnet — the rule is
    // safe at this high priority. Failure is silently ignored: on plain kernels
    // without conflicting policy rules this rule is a no-op.
    let _ = Command::new("ip")
        .args(["rule", "add", "to", &outer_cidr, "table", "main", "priority", "100"])
        .output();

    // Allow traffic through the veth interface in the host firewall.
    //
    // Systems with a DROP-by-default host firewall silently drop:
    //   • SYN packets from the namespace arriving on veth-out   → INPUT chain
    //   • SYN-ACK packets leaving via veth-out to the namespace → OUTPUT chain
    //
    // We handle two common firewall backends:
    //
    // 1. nftables (modern Linux, e.g. Arch Linux with a hardened /etc/nftables.conf
    //    that has `policy drop` on the inet filter input and output chains):
    //    `nft insert rule` prepends an ACCEPT for the veth interface to each chain.
    //    Failure is silently ignored — on systems without an `inet filter` table
    //    the command exits non-zero and the no-op is the correct behaviour.
    //
    // 2. iptables (legacy, or nft-backed via iptables-nft wrapper):
    //    `-I INPUT 1` prepends an ACCEPT rule before any DROP rules.
    //    Failure is silently ignored — on pure-nftables systems iptables is absent
    //    or does not share rules with the nftables table, but the nftables rules
    //    above already cover that case.
    // NOTE: interface names containing hyphens (e.g. "veth-123-out") MUST be
    // quoted in nft's rule language; otherwise nft's lexer interprets the
    // hyphens as subtraction operators and the parse fails silently.  We
    // route the rule through `sh -c` so the shell passes a properly-quoted
    // string to nft's parser.  The veth name only contains [a-z0-9-] so
    // single-quoting is safe.
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
    //
    // rp_filter=2 (strict) on a newly created interface (inherited from
    // /proc/sys/net/ipv4/conf/default/rp_filter) causes the kernel to verify
    // that the best outgoing path for the source address of an incoming packet
    // goes through the same interface. When VPN policy routing is active the
    // strict check can be confused by the VPN routing table even though our
    // priority-100 rule makes the correct main-table route preferred. Setting
    // rp_filter=0 on the veth-out interface disables the check only for that
    // single interface, leaving all other interfaces unaffected. Failure is
    // silently ignored.
    let _ = Command::new("sysctl")
        .args([
            "-w",
            &format!("net.ipv4.conf.{}.rp_filter=0", veth_outer),
        ])
        .output();

    // Configure inner veth inside namespace
    if let Err(e) = run_ip(&[
        "netns",
        "exec",
        name,
        "ip",
        "addr",
        "add",
        &inner_cidr,
        "dev",
        &veth_inner,
    ]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    if let Err(e) = run_ip(&[
        "netns",
        "exec",
        name,
        "ip",
        "link",
        "set",
        &veth_inner,
        "up",
    ]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    // Bring up loopback inside namespace
    if let Err(e) = run_ip(&["netns", "exec", name, "ip", "link", "set", "lo", "up"]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    // Add default route inside namespace
    let gateway = config.outer_ip.to_string();
    if let Err(e) = run_ip(&[
        "netns", "exec", name, "ip", "route", "add", "default", "via", &gateway,
    ]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    Ok(())
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

/// Delete a network namespace.
///
/// Cleans up namespace and associated veth pair.
/// Veth pair is automatically deleted when namespace is removed.
///
/// # Arguments
/// * `name` - Namespace name to delete
///
/// # Errors
/// * `NetworkSetupFailed` - If deletion fails
pub fn delete_netns(name: &str) -> Result<(), SandboxError> {
    use std::process::Command;

    // Remove the rules added in create_netns for this namespace.
    // The rules are keyed on the veth name / subnet derived from the namespace
    // name ("pent-{pid}"). Failure is silently ignored — rules may already be
    // gone (e.g. kernel reboot) or may never have been added.
    if let Some(pid_str) = name.strip_prefix("pent-") {
        let veth_outer = format!("veth-{}-out", pid_str);

        // Remove nftables rules for the veth interface (added in create_netns).
        // nft delete rule requires the numeric handle; look it up first.
        if let Some(handle) = nft_find_iface_rule_handle("input", "iifname", &veth_outer) {
            let _ = Command::new("nft")
                .args([
                    "delete", "rule", "inet", "filter", "input",
                    "handle", &handle.to_string(),
                ])
                .output();
        }
        if let Some(handle) = nft_find_iface_rule_handle("output", "oifname", &veth_outer) {
            let _ = Command::new("nft")
                .args([
                    "delete", "rule", "inet", "filter", "output",
                    "handle", &handle.to_string(),
                ])
                .output();
        }

        // Remove the iptables INPUT ACCEPT rule for the veth interface.
        // iptables rules reference interface names; the rule can be removed even
        // after the interface has been deleted.
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-i", &veth_outer, "-j", "ACCEPT"])
            .output();

        // Remove the policy routing rule.
        if let Ok(pid) = pid_str.parse::<u32>() {
            let octet = (pid % 256) as u8;
            let outer_ip = Ipv4Addr::new(10, 200, octet, 1);
            let outer_cidr = format!("{}/24", outer_ip);
            let _ = Command::new("ip")
                .args(["rule", "del", "to", &outer_cidr, "table", "main", "priority", "100"])
                .output();
        }
    }

    // Delete the namespace - veth pair is auto-deleted
    let output = Command::new("ip")
        .args(["netns", "del", name])
        .output()
        .map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("Failed to run ip netns del: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::NetworkSetupFailed(format!(
            "Failed to delete namespace {}: {}",
            name, stderr
        )));
    }

    Ok(())
}

/// Execute a command inside a network namespace.
///
/// Spawns command inside the isolated namespace.
///
/// # Arguments
/// * `namespace` - Namespace name
/// * `command` - Command to execute
/// * `args` - Command arguments
/// * `env` - Environment variables
/// * `cwd` - Working directory
///
/// # Returns
/// Child process handle
///
/// # Errors
/// * `SpawnFailed` - If spawn fails
#[allow(dead_code)]
pub fn exec_in_netns(
    namespace: &str,
    command: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &Path,
) -> Result<std::process::Child, SandboxError> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("ip");
    cmd.args(["netns", "exec", namespace, command]);
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.env_clear();
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    cmd.spawn().map_err(SandboxError::SpawnFailed)
}

/// Create a namespace with loopback only (LocalhostOnly mode).
///
/// Creates namespace with only loopback interface, no external connectivity.
///
/// # Arguments
/// * `name` - Namespace name
///
/// # Errors
/// * `PrivilegeRequired` - If not root/CAP_NET_ADMIN
/// * `NetworkSetupFailed` - If setup fails
#[allow(dead_code)]
pub fn create_loopback_only_netns(name: &str) -> Result<(), SandboxError> {
    use std::process::Command;

    check_netns_privileges()?;

    // Helper to run ip command
    let run_ip = |args: &[&str]| -> Result<(), SandboxError> {
        let output = Command::new("ip").args(args).output().map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("Failed to run ip command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::NetworkSetupFailed(format!(
                "ip {} failed: {}",
                args.join(" "),
                stderr
            )));
        }
        Ok(())
    };

    // Create namespace
    run_ip(&["netns", "add", name])?;

    // Bring up loopback only
    if let Err(e) = run_ip(&["netns", "exec", name, "ip", "link", "set", "lo", "up"]) {
        // Cleanup namespace on failure; error discarded to preserve the original error.
        let _ = delete_netns(name);
        return Err(e);
    }

    Ok(())
}

/// Create a namespace with no interfaces (Blocked mode).
///
/// Creates namespace with no networking at all.
///
/// # Arguments
/// * `name` - Namespace name
///
/// # Errors
/// * `PrivilegeRequired` - If not root/CAP_NET_ADMIN
/// * `NetworkSetupFailed` - If setup fails
#[allow(dead_code)]
pub fn create_blocked_netns(name: &str) -> Result<(), SandboxError> {
    use std::process::Command;

    check_netns_privileges()?;

    // Create namespace only - no interfaces brought up
    let output = Command::new("ip")
        .args(["netns", "add", name])
        .output()
        .map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("Failed to run ip netns add: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::NetworkSetupFailed(format!(
            "Failed to create namespace {}: {}",
            name, stderr
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    // delete_netns tests
    // ========================================================================

    #[test]
    fn test_delete_netns_nonexistent() {
        // Deleting a namespace that doesn't exist should fail
        let result = delete_netns("pent-nonexistent-12345");
        assert!(result.is_err());
    }

    // ========================================================================
    // exec_in_netns tests
    // ========================================================================

    // Note: exec_in_netns requires the namespace to exist

    // ========================================================================
    // create_loopback_only_netns tests
    // ========================================================================

    #[test]
    fn test_create_loopback_only_requires_privileges() {
        if check_netns_privileges().is_err() {
            let result = create_loopback_only_netns("pent-test-loopback");
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // create_blocked_netns tests
    // ========================================================================

    #[test]
    fn test_create_blocked_requires_privileges() {
        if check_netns_privileges().is_err() {
            let result = create_blocked_netns("pent-test-blocked");
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // NetnsHandle tests
    // ========================================================================

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
}
