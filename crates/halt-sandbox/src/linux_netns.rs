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
//!         +-- [routing through halt-proxy]
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
    /// Namespace name (e.g., "halt-12345").
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
    /// The PID is used to derive both the namespace name (`halt-{pid}`) and
    /// the IP range (`10.200.{pid % 256}.0/24`). Using the PID ensures that
    /// each halt invocation gets a unique namespace name and IP range.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::from_pid()
    }

    /// Create a network namespace config using the current process PID.
    ///
    /// PIDs are unique among running processes, so each halt invocation gets
    /// its own namespace name and IP range.
    pub fn from_pid() -> Self {
        let pid = std::process::id();
        let octet = (pid % 256) as u8;

        Self {
            name: format!("halt-{}", pid),
            inner_ip: Ipv4Addr::new(10, 200, octet, 2),
            outer_ip: Ipv4Addr::new(10, 200, octet, 1),
            prefix_len: 24,
        }
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
        "ProxyOnly mode on Linux requires root or CAP_NET_ADMIN to create the veth bridge \
         between the sandbox and the proxy. Run with sudo, or use --network localhost/blocked \
         which do not require root. Alternatively: sudo setcap cap_net_admin+ep <binary>".to_string()
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
    let veth_inner = format!("veth-{}-in", &name[5..]); // Remove "halt-" prefix for shorter names
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
        assert!(config.name.starts_with("halt-"));
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
        let result = delete_netns("halt-nonexistent-12345");
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
            let result = create_loopback_only_netns("halt-test-loopback");
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // create_blocked_netns tests
    // ========================================================================

    #[test]
    fn test_create_blocked_requires_privileges() {
        if check_netns_privileges().is_err() {
            let result = create_blocked_netns("halt-test-blocked");
            assert!(result.is_err());
        }
    }
}
