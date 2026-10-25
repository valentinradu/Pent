//! Linux network namespace plumbing for `ProxyOnly` mode.
//!
//! The host side needs `CAP_NET_ADMIN` (root, or file capabilities on the
//! `pent` binary).
#![allow(unreachable_pub)]
//!
//! # Architecture
//!
//! ```text
//! Host
//!   |
//!   +-- pentXXXXXXXXo (10.200.a.b+1/30)  <- proxy and DNS server bind here
//!         |
//! --------+-------- namespace boundary (child user + net namespace)
//!         |
//!   +-- pentXXXXXXXXi (10.200.a.b+2/30)
//!         |
//!         +-- default route via 10.200.a.b+1
//!         |
//!   Sandboxed process
//! ```
//!
//! # Instance state and cleanup
//!
//! Each instance has a random 32-bit ID. The ID gives the interface names
//! (`pent<id>i`, `pent<id>o`, 13 bytes, less than `IFNAMSIZ`) and the nft
//! table names. Each instance writes a state file in
//! `$XDG_RUNTIME_DIR/pent/netns/`. The state file records the owner PID, the
//! start time of the owner, the subnet and the firewall rules. A lock file in
//! the same directory serializes the subnet allocation between concurrent
//! pent processes. [`cleanup_stale_netns`] removes the rules of instances
//! whose owner is dead (for example after `SIGKILL`).
//!
//! # Host firewall
//!
//! The host accepts only these packets from the veth: TCP to the proxy port,
//! and UDP and TCP to the DNS port, on the outer address. The host drops all
//! other packets from the veth (IPv4 and IPv6) and never forwards packets
//! from or to the veth. The host also drops packets to the outer address that
//! arrive on an interface other than the veth or the loopback, so other
//! hosts on the LAN cannot reach the proxy.

use crate::SandboxError;
use std::fs::File;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// First address of the pool for veth subnets (10.200.0.0/16).
const POOL_BASE: u32 = u32::from_be_bytes([10, 200, 0, 0]);
/// Prefix length of the pool.
const POOL_PREFIX: u8 = 16;
/// Prefix length of one instance subnet.
const SUBNET_PREFIX: u8 = 30;
/// Number of /30 subnets in the pool.
const POOL_SLOTS: u32 = 1 << (SUBNET_PREFIX - POOL_PREFIX);
/// Priority of the policy routing rule. The selector (`to <subnet>`) is
/// unique per instance, so a delete never removes the rule of another
/// instance.
const RULE_PRIORITY: &str = "100";

/// The firewall backend that holds the mandatory drop rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallKind {
    /// No firewall rules are installed yet.
    None,
    /// A per-instance `inet` nft table.
    Nft,
    /// `iptables` and `ip6tables` rules with a comment tag.
    Iptables,
}

impl FirewallKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Nft => "nft",
            Self::Iptables => "iptables",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "nft" => Some(Self::Nft),
            "iptables" => Some(Self::Iptables),
            _ => None,
        }
    }
}

/// The persistent state of one instance. Pent derives every cleanup command
/// from these fields. The state file holds no free-form commands, so a
/// changed state file cannot make pent run arbitrary commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstanceState {
    pub(crate) pid: u32,
    pub(crate) start_time: u64,
    pub(crate) id: u32,
    pub(crate) network: Ipv4Addr,
    pub(crate) veth_created: bool,
    pub(crate) rule_added: bool,
    pub(crate) firewall: FirewallKind,
    pub(crate) proxy_port: u16,
    pub(crate) dns_port: u16,
    pub(crate) dns_table: bool,
    pub(crate) distro_nft_accept: bool,
    pub(crate) distro_ipt_accept: bool,
}

impl InstanceState {
    fn new(pid: u32, start_time: u64, id: u32, network: Ipv4Addr) -> Self {
        Self {
            pid,
            start_time,
            id,
            network,
            veth_created: false,
            rule_added: false,
            firewall: FirewallKind::None,
            proxy_port: 0,
            dns_port: 0,
            dns_table: false,
            distro_nft_accept: false,
            distro_ipt_accept: false,
        }
    }

    pub(crate) fn veth_inner(&self) -> String {
        veth_names(self.id).0
    }

    pub(crate) fn veth_outer(&self) -> String {
        veth_names(self.id).1
    }

    pub(crate) fn tag(&self) -> String {
        format!("pent_{:08x}", self.id)
    }

    fn dns_table_name(&self) -> String {
        format!("pent_dns_{:08x}", self.id)
    }

    pub(crate) fn outer_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network).wrapping_add(1))
    }

    pub(crate) fn inner_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network).wrapping_add(2))
    }

    fn subnet_cidr(&self) -> String {
        format!("{}/{SUBNET_PREFIX}", self.network)
    }

    fn serialize(&self) -> String {
        format!(
            "pid={}\nstart={}\nid={:08x}\nnetwork={}\nveth={}\nrule={}\nfirewall={}\n\
             proxy_port={}\ndns_port={}\ndns_table={}\ndistro_nft={}\ndistro_ipt={}\n",
            self.pid,
            self.start_time,
            self.id,
            self.network,
            u8::from(self.veth_created),
            u8::from(self.rule_added),
            self.firewall.as_str(),
            self.proxy_port,
            self.dns_port,
            u8::from(self.dns_table),
            u8::from(self.distro_nft_accept),
            u8::from(self.distro_ipt_accept),
        )
    }

    /// Parse a state file. Returns `None` for any unknown or invalid value.
    fn parse(text: &str) -> Option<Self> {
        let mut map = std::collections::HashMap::new();
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            map.insert(k, v);
        }
        let flag = |k: &str| -> Option<bool> {
            match *map.get(k)? {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            }
        };
        let network: Ipv4Addr = map.get("network")?.parse().ok()?;
        if !subnet_in_pool(network) {
            return None;
        }
        Some(Self {
            pid: map.get("pid")?.parse().ok()?,
            start_time: map.get("start")?.parse().ok()?,
            id: u32::from_str_radix(map.get("id")?, 16).ok()?,
            network,
            veth_created: flag("veth")?,
            rule_added: flag("rule")?,
            firewall: FirewallKind::parse(map.get("firewall")?)?,
            proxy_port: map.get("proxy_port")?.parse().ok()?,
            dns_port: map.get("dns_port")?.parse().ok()?,
            dns_table: flag("dns_table")?,
            distro_nft_accept: flag("distro_nft")?,
            distro_ipt_accept: flag("distro_ipt")?,
        })
    }

    /// Remove all host resources that this state records.
    ///
    /// Each step is independent. A failed step is logged and the next step
    /// runs.
    fn undo(&self) {
        let veth_outer = self.veth_outer();
        let tag = self.tag();
        if self.veth_created {
            // Delete of one end deletes the pair.
            log_cleanup("ip link del", run_tool("ip", &["link", "del", &veth_outer]));
        }
        if self.rule_added {
            let cidr = self.subnet_cidr();
            log_cleanup(
                "ip rule del",
                run_tool(
                    "ip",
                    &[
                        "rule",
                        "del",
                        "to",
                        &cidr,
                        "table",
                        "main",
                        "priority",
                        RULE_PRIORITY,
                    ],
                ),
            );
        }
        if self.firewall == FirewallKind::Nft {
            log_cleanup(
                "nft delete table",
                run_tool("nft", &["delete", "table", "inet", &tag]),
            );
        }
        let rules = FirewallRules::new(self);
        if self.firewall == FirewallKind::Iptables || self.distro_ipt_accept {
            for rule in rules.iptables_accept() {
                log_cleanup("iptables -D", rule.delete());
            }
        }
        if self.firewall == FirewallKind::Iptables {
            for rule in rules.iptables_drop() {
                log_cleanup("iptables -D", rule.delete());
            }
        }
        if self.dns_table {
            let table = self.dns_table_name();
            log_cleanup(
                "nft delete dns table",
                run_tool("nft", &["delete", "table", "ip", &table]),
            );
        }
        if self.distro_nft_accept {
            for chain in ["input", "output"] {
                for handle in nft_find_tagged_rule_handles(chain, &tag) {
                    let h = handle.to_string();
                    log_cleanup(
                        "nft delete rule",
                        run_tool(
                            "nft",
                            &["delete", "rule", "inet", "filter", chain, "handle", &h],
                        ),
                    );
                }
            }
        }
    }
}

/// Return the inner and outer veth names for an instance ID.
///
/// The names have 13 bytes. `IFNAMSIZ` is 16 (15 bytes and a NUL).
#[must_use]
pub(crate) fn veth_names(id: u32) -> (String, String) {
    (format!("pent{id:08x}i"), format!("pent{id:08x}o"))
}

/// Return true if `network` is the base address of a /30 inside the pool.
fn subnet_in_pool(network: Ipv4Addr) -> bool {
    let n = u32::from(network);
    let pool_mask = u32::MAX << (32 - POOL_PREFIX);
    n & pool_mask == POOL_BASE && n & 0b11 == 0
}

/// Return the base address of slot `slot` in the pool.
fn slot_network(slot: u32) -> Ipv4Addr {
    Ipv4Addr::from(POOL_BASE | ((slot % POOL_SLOTS) << 2))
}

/// Return true if the two networks overlap.
#[must_use]
pub(crate) fn nets_overlap(a: Ipv4Addr, a_prefix: u8, b: Ipv4Addr, b_prefix: u8) -> bool {
    let prefix = a_prefix.min(b_prefix).min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(a) & mask == u32::from(b) & mask
}

/// Choose a free /30 in the pool.
///
/// The search starts at slot `start` and wraps. A slot is free if it does
/// not overlap any network in `taken`. A network with a prefix shorter than
/// the pool (for example a default route `0.0.0.0/0`) is ignored, because it
/// does not occupy the pool.
#[must_use]
pub(crate) fn choose_subnet(start: u32, taken: &[(Ipv4Addr, u8)]) -> Option<Ipv4Addr> {
    (0..POOL_SLOTS)
        .map(|i| slot_network(start.wrapping_add(i)))
        .find(|candidate| {
            !taken.iter().any(|(net, prefix)| {
                *prefix >= POOL_PREFIX && nets_overlap(*candidate, SUBNET_PREFIX, *net, *prefix)
            })
        })
}

/// Parse every `a.b.c.d/n` token in the output of `ip addr` or `ip route`.
#[must_use]
pub(crate) fn parse_ipv4_nets(text: &str) -> Vec<(Ipv4Addr, u8)> {
    text.split_whitespace()
        .filter_map(|tok| {
            let (addr, prefix) = tok.split_once('/')?;
            let addr: Ipv4Addr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            (prefix <= 32).then_some((addr, prefix))
        })
        .collect()
}

/// One `iptables` or `ip6tables` rule with its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IptRule {
    pub(crate) tool: &'static str,
    pub(crate) chain: &'static str,
    pub(crate) spec: Vec<String>,
}

impl IptRule {
    fn insert(&self) -> std::io::Result<std::process::Output> {
        let mut args = vec!["-I", self.chain, "1"];
        args.extend(self.spec.iter().map(String::as_str));
        run_tool(self.tool, &args)
    }

    fn delete(&self) -> std::io::Result<std::process::Output> {
        let mut args = vec!["-D", self.chain];
        args.extend(self.spec.iter().map(String::as_str));
        run_tool(self.tool, &args)
    }
}

/// The firewall rules of one instance.
pub(crate) struct FirewallRules {
    tag: String,
    veth: String,
    outer: Ipv4Addr,
    proxy_port: u16,
    dns_port: u16,
}

impl FirewallRules {
    pub(crate) fn new(state: &InstanceState) -> Self {
        Self {
            tag: state.tag(),
            veth: state.veth_outer(),
            outer: state.outer_ip(),
            proxy_port: state.proxy_port,
            dns_port: state.dns_port,
        }
    }

    /// The allowed (protocol, port) pairs from the veth to the outer address.
    fn allowed(&self) -> Vec<(&'static str, u16)> {
        let mut v = vec![("tcp", self.proxy_port)];
        if self.dns_port != 0 {
            v.push(("udp", self.dns_port));
            v.push(("tcp", self.dns_port));
        }
        v
    }

    /// The nft script for the per-instance filter table.
    pub(crate) fn nft_script(&self) -> String {
        let Self {
            tag, veth, outer, ..
        } = self;
        let mut accepts = String::new();
        for (proto, port) in self.allowed() {
            accepts.push_str(&format!(
                "    iifname \"{veth}\" ip daddr {outer} {proto} dport {port} accept\n"
            ));
        }
        format!(
            "table inet {tag} {{\n\
             \x20 chain input {{\n\
             \x20   type filter hook input priority -10; policy accept;\n\
             {accepts}\
             \x20   iifname \"{veth}\" drop\n\
             \x20   ip daddr {outer} iifname != \"lo\" drop\n\
             \x20 }}\n\
             \x20 chain forward {{\n\
             \x20   type filter hook forward priority -10; policy accept;\n\
             \x20   iifname \"{veth}\" drop\n\
             \x20   oifname \"{veth}\" drop\n\
             \x20 }}\n\
             }}\n"
        )
    }

    fn comment(&self) -> [String; 4] {
        [
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            self.tag.clone(),
        ]
    }

    /// The `iptables` ACCEPT rules for the proxy and DNS ports.
    pub(crate) fn iptables_accept(&self) -> Vec<IptRule> {
        self.allowed()
            .into_iter()
            .map(|(proto, port)| {
                let mut spec: Vec<String> = [
                    "-i",
                    &self.veth,
                    "-d",
                    &self.outer.to_string(),
                    "-p",
                    proto,
                    "--dport",
                    &port.to_string(),
                ]
                .iter()
                .map(ToString::to_string)
                .collect();
                spec.extend(self.comment());
                spec.extend(["-j".to_string(), "ACCEPT".to_string()]);
                IptRule {
                    tool: "iptables",
                    chain: "INPUT",
                    spec,
                }
            })
            .collect()
    }

    /// The `iptables` and `ip6tables` DROP rules (the fallback when nft is
    /// not available).
    pub(crate) fn iptables_drop(&self) -> Vec<IptRule> {
        let rule = |tool: &'static str, chain: &'static str, parts: &[&str]| {
            let mut spec: Vec<String> = parts.iter().map(ToString::to_string).collect();
            spec.extend(self.comment());
            spec.extend(["-j".to_string(), "DROP".to_string()]);
            IptRule { tool, chain, spec }
        };
        let outer = self.outer.to_string();
        vec![
            rule("iptables", "INPUT", &["-i", &self.veth]),
            rule("iptables", "INPUT", &["-d", &outer, "!", "-i", "lo"]),
            rule("iptables", "FORWARD", &["-i", &self.veth]),
            rule("iptables", "FORWARD", &["-o", &self.veth]),
            rule("ip6tables", "INPUT", &["-i", &self.veth]),
            rule("ip6tables", "FORWARD", &["-i", &self.veth]),
            rule("ip6tables", "FORWARD", &["-o", &self.veth]),
        ]
    }
}

/// Handle to the host side of a `ProxyOnly` network.
///
/// Dropping the handle removes the veth pair, the routing rule and the
/// firewall rules, and deletes the state file.
#[derive(Debug)]
pub struct NetnsHandle {
    /// Host-side veth IP. The proxy and the DNS server bind to this address.
    pub outer_ip: Ipv4Addr,
    /// Inner veth name. The parent moves it into the child namespace.
    pub inner_veth: String,
    /// CIDR for the inner veth (for example `10.200.1.2/30`).
    pub inner_cidr: String,
    state: InstanceState,
    state_path: PathBuf,
    resolv_path: Option<PathBuf>,
}

impl Drop for NetnsHandle {
    fn drop(&mut self) {
        self.state.undo();
        remove_file_logged(&self.state_path);
        if let Some(p) = &self.resolv_path {
            remove_file_logged(p);
        }
    }
}

fn remove_file_logged(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::debug!(path = %path.display(), err = %e, "cannot remove pent state file");
        }
    }
}

fn log_cleanup(label: &str, result: std::io::Result<std::process::Output>) {
    match result {
        Ok(out) if !out.status.success() => tracing::debug!(
            cmd = label,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "cleanup command failed (the resource can be gone already)"
        ),
        Err(e) => tracing::warn!(cmd = label, err = %e, "cannot run cleanup command"),
        Ok(_) => {}
    }
}

/// Run `tool args…` with `CAP_NET_ADMIN` raised as an ambient capability.
fn run_tool(tool: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new(tool);
    cmd.args(args);
    // SAFETY: `raise_net_admin_ambient` uses only async-signal-safe system
    // calls on stack data, so it is safe between fork and exec in a
    // multithreaded parent.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { cmd.pre_exec(raise_net_admin_ambient) };
    cmd.output()
}

/// Run `tool args…` and convert a failure into `NetworkSetupFailed`.
fn run_tool_checked(tool: &str, args: &[&str]) -> Result<(), SandboxError> {
    let output = run_tool(tool, args)
        .map_err(|e| SandboxError::NetworkSetupFailed(format!("cannot run {tool}: {e}")))?;
    if !output.status.success() {
        return Err(SandboxError::NetworkSetupFailed(format!(
            "{tool} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Write a static message to the error output. Async-signal-safe.
pub(crate) fn write_stderr_static(msg: &'static [u8]) {
    // SAFETY: write(2) on fd 2 with a static buffer is async-signal-safe.
    // The result is ignored because no other channel for the error exists.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
    }
}

/// Raise `CAP_NET_ADMIN` as an ambient capability in the calling process.
///
/// Call this between fork and exec so that the new program keeps
/// `CAP_NET_ADMIN`. As root (effective UID 0), the function does nothing.
/// Otherwise `CAP_NET_ADMIN` must be in the permitted set (for example
/// through `setcap cap_net_admin=eip pent`, or through `setns` into a user
/// namespace that this user owns).
///
/// The function is async-signal-safe: it uses only raw system calls and
/// static messages.
///
/// # Errors
/// Returns the OS error of the failed `capget`, `capset` or `prctl` call.
pub fn raise_net_admin_ambient() -> std::io::Result<()> {
    const CAP_NET_ADMIN: u32 = 12;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

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

    // SAFETY: geteuid has no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }

    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `hdr` and `data` are valid, writable, and have the layout that
    // capget(2) expects for version 3 (two data words).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) } != 0 {
        write_stderr_static(b"pent: capget failed\n");
        return Err(std::io::Error::last_os_error());
    }
    let cap_bit = 1u32 << CAP_NET_ADMIN;
    data[0].inheritable |= cap_bit;
    hdr.version = LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    // SAFETY: the same valid buffers as above, now read by capset(2).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) } != 0 {
        write_stderr_static(b"pent: capset failed (is CAP_NET_ADMIN permitted?)\n");
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: prctl with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_RAISE,
            libc::c_ulong::from(CAP_NET_ADMIN),
            0,
            0,
        )
    };
    if ret != 0 {
        write_stderr_static(b"pent: prctl(PR_CAP_AMBIENT_RAISE) failed\n");
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Check if the process has the privileges for the host side of a veth.
///
/// # Errors
/// Returns `PrivilegeRequired` with a hint if `CAP_NET_ADMIN` is absent.
pub fn check_netns_privileges() -> Result<(), SandboxError> {
    // SAFETY: geteuid has no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    const CAP_NET_ADMIN: u64 = 1 << 12;
    let has_cap = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & CAP_NET_ADMIN != 0);
    if has_cap {
        return Ok(());
    }
    Err(SandboxError::PrivilegeRequired(
        "ProxyOnly mode on Linux requires CAP_NET_ADMIN to create the veth pair \
         between the sandbox and the proxy. \
         Run: sudo setcap cap_net_admin=eip $(which pent)\n\
         Or use --network localhost/blocked which do not require elevated privileges."
            .to_string(),
    ))
}

// ── State directory, lock and liveness ─────────────────────────────────────

/// Return the directory for instance state files.
fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        if dir.is_absolute() && dir.is_dir() {
            return dir.join("pent").join("netns");
        }
    }
    // SAFETY: getuid/geteuid have no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if euid == 0 {
        return PathBuf::from("/run/pent/netns");
    }
    std::env::temp_dir()
        .join(format!("pent-{uid}"))
        .join("netns")
}

/// Create the state directory with mode 0700 and return it.
fn ensure_state_dir() -> Result<PathBuf, SandboxError> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = state_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| {
            SandboxError::NetworkSetupFailed(format!("cannot create {}: {e}", dir.display()))
        })?;
    Ok(dir)
}

/// An exclusive `flock` on the lock file. The lock is released on drop.
struct StateLock {
    _file: File,
}

impl StateLock {
    fn acquire(dir: &Path) -> Result<Self, SandboxError> {
        let path = dir.join("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| {
                SandboxError::NetworkSetupFailed(format!("cannot open {}: {e}", path.display()))
            })?;
        loop {
            // SAFETY: flock on a file descriptor that `file` owns.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Self { _file: file });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(SandboxError::NetworkSetupFailed(format!(
                    "cannot lock {}: {err}",
                    path.display()
                )));
            }
        }
    }
}

/// Return the start time of process `pid` (field 22 of `/proc/<pid>/stat`).
fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

/// Parse field 22 (`starttime`) of a `/proc/<pid>/stat` line.
fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name (field 2) can contain spaces and parentheses, so
    // split after the last ')'. Field 3 is the first field after it.
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(22 - 3)?.parse().ok()
}

fn process_alive(pid: u32, start_time: u64) -> bool {
    process_start_time(pid) == Some(start_time)
}

fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    // SAFETY: getrandom writes at most `buf.len()` bytes into `buf`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n == 4 {
        return u32::from_ne_bytes(buf);
    }
    // Fallback: the ID only needs to be unique among live instances, and the
    // allocation below checks that.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    nanos ^ std::process::id().rotate_left(16)
}

/// Read every valid state file in `dir`, with its path.
fn read_states(dir: &Path) -> Vec<(PathBuf, InstanceState)> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "state"))
        .filter_map(|p| {
            // Accept only files that this user owns.
            let meta = std::fs::symlink_metadata(&p).ok()?;
            if !meta.is_file() || meta.uid() != euid {
                return None;
            }
            let state = InstanceState::parse(&std::fs::read_to_string(&p).ok()?)?;
            Some((p, state))
        })
        .collect()
}

fn write_state(path: &Path, state: &InstanceState) -> Result<(), SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(state.serialize().as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        SandboxError::NetworkSetupFailed(format!("cannot write {}: {e}", path.display()))
    })
}

/// Collect the IPv4 networks that the host uses now.
fn host_networks() -> Vec<(Ipv4Addr, u8)> {
    let mut nets = Vec::new();
    for args in [
        &["-o", "-4", "addr", "show"][..],
        &["-4", "route", "show", "table", "all"][..],
    ] {
        match Command::new("ip").args(args).output() {
            Ok(out) if out.status.success() => {
                nets.extend(parse_ipv4_nets(&String::from_utf8_lossy(&out.stdout)));
            }
            Ok(out) => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ip {} failed", args.join(" ")
            ),
            Err(e) => tracing::debug!(err = %e, "cannot run ip"),
        }
    }
    nets
}

/// Remove the host resources of `ProxyOnly` instances whose owner is dead.
///
/// Call this at startup (next to `cleanup_stale_overlays`). The function
/// does nothing without `CAP_NET_ADMIN`, because the cleanup commands would
/// fail; the state files stay for a later run with privileges.
pub fn cleanup_stale_netns() {
    let dir = state_dir();
    if !dir.is_dir() || check_netns_privileges().is_err() {
        return;
    }
    let Ok(_lock) = StateLock::acquire(&dir) else {
        return;
    };
    for (path, state) in read_states(&dir) {
        if process_alive(state.pid, state.start_time) {
            continue;
        }
        tracing::debug!(id = %state.tag(), pid = state.pid, "removing stale pent network");
        state.undo();
        remove_file_logged(&path);
        remove_file_logged(&path.with_extension("resolv.conf"));
    }
}

// ── Creation ───────────────────────────────────────────────────────────────

/// Allocate a subnet and create the host side of a `ProxyOnly` network.
///
/// The function creates a veth pair with a unique name, gives the outer end
/// its address, brings it up and adds a per-instance policy routing rule.
/// Call [`NetnsHandle::install_firewall`] when the proxy ports are known.
///
/// # Errors
/// * `PrivilegeRequired` if `CAP_NET_ADMIN` is absent.
/// * `NetworkSetupFailed` if any step fails. The partial setup is removed.
pub fn create_netns() -> Result<NetnsHandle, SandboxError> {
    check_netns_privileges()?;
    let dir = ensure_state_dir()?;
    let pid = std::process::id();
    let start_time = process_start_time(pid).ok_or_else(|| {
        SandboxError::NetworkSetupFailed("cannot read the start time of pent".to_string())
    })?;

    // Allocate the ID and the subnet under the lock, and record them in the
    // state file before the lock is released.
    let (state, state_path) = {
        let _lock = StateLock::acquire(&dir)?;
        let live: Vec<InstanceState> = read_states(&dir)
            .into_iter()
            .map(|(_, s)| s)
            .filter(|s| process_alive(s.pid, s.start_time))
            .collect();
        let mut taken = host_networks();
        taken.extend(live.iter().map(|s| (s.network, SUBNET_PREFIX)));
        let mut id = random_u32();
        while live.iter().any(|s| s.id == id) || dir.join(format!("{id:08x}.state")).exists() {
            id = random_u32();
        }
        let network = choose_subnet(id, &taken).ok_or_else(|| {
            SandboxError::NetworkSetupFailed("no free subnet in 10.200.0.0/16".to_string())
        })?;
        let state = InstanceState::new(pid, start_time, id, network);
        let state_path = dir.join(format!("{id:08x}.state"));
        write_state(&state_path, &state)?;
        (state, state_path)
    };

    let mut handle = NetnsHandle {
        outer_ip: state.outer_ip(),
        inner_veth: state.veth_inner(),
        inner_cidr: format!("{}/{SUBNET_PREFIX}", state.inner_ip()),
        state,
        state_path,
        resolv_path: None,
    };
    // On error, `handle` drops and removes what exists.
    handle.create_veth()?;
    Ok(handle)
}

impl NetnsHandle {
    fn save(&self) -> Result<(), SandboxError> {
        write_state(&self.state_path, &self.state)
    }

    fn create_veth(&mut self) -> Result<(), SandboxError> {
        let inner = self.state.veth_inner();
        let outer = self.state.veth_outer();
        let outer_cidr = format!("{}/{SUBNET_PREFIX}", self.outer_ip);
        run_tool_checked(
            "ip",
            &[
                "link", "add", &inner, "type", "veth", "peer", "name", &outer,
            ],
        )?;
        self.state.veth_created = true;
        self.save()?;
        run_tool_checked("ip", &["addr", "add", &outer_cidr, "dev", &outer])?;
        run_tool_checked("ip", &["link", "set", &outer, "up"])?;

        // Packets to the veth subnet always use the main table. Without this
        // rule, policy routes of a VPN can send the replies to the child out
        // of the wrong interface.
        let cidr = self.state.subnet_cidr();
        match run_tool(
            "ip",
            &[
                "rule",
                "add",
                "to",
                &cidr,
                "table",
                "main",
                "priority",
                RULE_PRIORITY,
            ],
        ) {
            Ok(out) if out.status.success() => {
                self.state.rule_added = true;
                self.save()?;
            }
            Ok(out) => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ip rule add for the veth subnet failed; a VPN policy route can break the proxy"
            ),
            Err(e) => tracing::debug!(err = %e, "cannot run ip rule add"),
        }
        Ok(())
    }

    /// Install the host firewall rules for the proxy and DNS ports.
    ///
    /// The drop rules are mandatory: without them the child can reach every
    /// service that listens on the host. The function tries a per-instance
    /// nft table first and `iptables`/`ip6tables` next. The DNS redirect and
    /// the ACCEPT rules in the distribution firewall are best effort.
    ///
    /// # Errors
    /// Returns `NetworkSetupFailed` if neither nft nor iptables can install
    /// the drop rules.
    pub fn install_firewall(&mut self, proxy_port: u16, dns_port: u16) -> Result<(), SandboxError> {
        self.state.proxy_port = proxy_port;
        self.state.dns_port = dns_port;
        self.save()?;
        let rules = FirewallRules::new(&self.state);

        // 1. Mandatory drop rules.
        match nft_load(&rules.nft_script()) {
            Ok(()) => {
                self.state.firewall = FirewallKind::Nft;
                self.save()?;
            }
            Err(nft_err) => {
                tracing::debug!(err = %nft_err, "nft table failed; trying iptables");
                // Record the kind first, so that a partial install is undone.
                self.state.firewall = FirewallKind::Iptables;
                self.save()?;
                // `-I CHAIN 1` puts each rule on top, so insert in reverse.
                for rule in rules.iptables_drop().iter().rev() {
                    check_output(rule.tool, rule.insert()).map_err(|e| {
                        SandboxError::NetworkSetupFailed(format!(
                            "cannot install the host firewall (nft: {nft_err}; iptables: {e})"
                        ))
                    })?;
                }
                for rule in rules.iptables_accept().iter().rev() {
                    check_output(rule.tool, rule.insert())?;
                }
            }
        }

        // 2. DNS redirect: queries to port 53 from the child go to the DNS
        //    server of the proxy.
        if dns_port != 0 {
            let table = self.state.dns_table_name();
            self.state.dns_table = true;
            self.save()?;
            let veth = self.state.veth_outer();
            let outer = self.outer_ip;
            let script = format!(
                "table ip {table} {{\n\
                 \x20 chain prerouting {{\n\
                 \x20   type nat hook prerouting priority -100;\n\
                 \x20   iifname \"{veth}\" udp dport 53 dnat to {outer}:{dns_port}\n\
                 \x20   iifname \"{veth}\" tcp dport 53 dnat to {outer}:{dns_port}\n\
                 \x20 }}\n\
                 }}\n"
            );
            if let Err(e) = nft_load(&script) {
                tracing::warn!(
                    "DNS redirect via nft failed; DNS for apps that ignore the proxy can fail: {e}"
                );
                self.state.dns_table = false;
                self.save()?;
            }
        }

        // 3. Best effort: ACCEPT rules in the distribution firewall, so that
        //    its own input policy does not drop the proxy traffic.
        if self.state.firewall == FirewallKind::Nft {
            let tag = self.state.tag();
            let veth = self.state.veth_outer();
            let outer = self.outer_ip;
            self.state.distro_nft_accept = true;
            self.save()?;
            let mut rules_ok = 0usize;
            for (proto, port) in rules.allowed() {
                let rule = format!(
                    "iifname \"{veth}\" ip daddr {outer} {proto} dport {port} accept comment \"{tag}\""
                );
                if check_output(
                    "nft",
                    run_tool("nft", &["insert", "rule", "inet", "filter", "input", &rule]),
                )
                .is_ok()
                {
                    rules_ok += 1;
                }
            }
            let rule = format!("oifname \"{veth}\" accept comment \"{tag}\"");
            if check_output(
                "nft",
                run_tool(
                    "nft",
                    &["insert", "rule", "inet", "filter", "output", &rule],
                ),
            )
            .is_ok()
            {
                rules_ok += 1;
            }
            if rules_ok == 0 {
                tracing::debug!("no inet filter table; no nft ACCEPT rules added");
                self.state.distro_nft_accept = false;
                self.save()?;
            }

            self.state.distro_ipt_accept = true;
            self.save()?;
            let mut any = false;
            for rule in rules.iptables_accept().iter().rev() {
                any |= check_output(rule.tool, rule.insert()).is_ok();
            }
            if !any {
                self.state.distro_ipt_accept = false;
                self.save()?;
            }
        }
        Ok(())
    }

    /// Write the `resolv.conf` file for the child and return its path.
    ///
    /// The file points the resolver at the outer veth address. The child
    /// bind-mounts it over `/etc/resolv.conf` in its own mount namespace.
    ///
    /// # Errors
    /// Returns `NetworkSetupFailed` if the file cannot be written.
    pub fn write_resolv_conf(&mut self) -> Result<PathBuf, SandboxError> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.state_path.with_extension("resolv.conf");
        let content = format!("nameserver {}\n", self.outer_ip);
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o644)
            .open(&path)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .map_err(|e| {
                SandboxError::NetworkSetupFailed(format!("cannot write {}: {e}", path.display()))
            })?;
        self.resolv_path = Some(path.clone());
        Ok(path)
    }

    /// Return the data that the parent needs to configure the child side.
    #[must_use]
    pub(crate) fn child_config(&self) -> ChildNetConfig {
        ChildNetConfig {
            inner_veth: self.inner_veth.clone(),
            inner_cidr: self.inner_cidr.clone(),
            outer_ip: self.outer_ip,
        }
    }
}

/// The child side of a `ProxyOnly` network. The helper thread of the parent
/// uses it while the main thread waits in `spawn`.
#[derive(Debug, Clone)]
pub(crate) struct ChildNetConfig {
    inner_veth: String,
    inner_cidr: String,
    outer_ip: Ipv4Addr,
}

impl ChildNetConfig {
    /// Move the inner veth into the namespace of `pid` and configure it.
    ///
    /// The child must have created its user and network namespaces and
    /// written its UID and GID maps. The parent runs `ip` in the network
    /// namespace of the child: a helper process calls `setns` into the user
    /// namespace of the child (this user owns it, so the helper gets all
    /// capabilities there) and then into its network namespace.
    ///
    /// # Errors
    /// Returns `NetworkSetupFailed` if a step fails.
    pub(crate) fn configure(&self, pid: libc::pid_t) -> Result<(), SandboxError> {
        let inner = self.inner_veth.as_str();
        let pid_str = pid.to_string();
        run_tool_checked("ip", &["link", "set", inner, "netns", &pid_str])?;

        let open_ns = |kind: &str| -> Result<File, SandboxError> {
            File::open(format!("/proc/{pid}/ns/{kind}")).map_err(|e| {
                SandboxError::NetworkSetupFailed(format!("cannot open the {kind} namespace: {e}"))
            })
        };
        let user_ns = open_ns("user")?;
        let net_ns = open_ns("net")?;
        let gateway = self.outer_ip.to_string();
        let steps: [&[&str]; 4] = [
            &["addr", "add", &self.inner_cidr, "dev", inner],
            &["link", "set", inner, "up"],
            &["link", "set", "lo", "up"],
            &["route", "add", "default", "via", &gateway],
        ];
        for args in steps {
            run_ip_in_ns(user_ns.as_raw_fd(), net_ns.as_raw_fd(), args)?;
        }
        Ok(())
    }
}

/// Run `ip args…` inside the user and network namespaces `user_fd` and
/// `net_fd`.
fn run_ip_in_ns(
    user_fd: libc::c_int,
    net_fd: libc::c_int,
    args: &[&str],
) -> Result<(), SandboxError> {
    let mut cmd = Command::new("ip");
    cmd.args(args);
    // SAFETY: the hook runs between fork and exec. It uses only setns(2) on
    // file descriptors that the caller keeps open during `output()`, and the
    // async-signal-safe `raise_net_admin_ambient`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(user_fd, libc::CLONE_NEWUSER) != 0 {
                write_stderr_static(b"pent: setns(user) failed\n");
                return Err(std::io::Error::last_os_error());
            }
            if libc::setns(net_fd, libc::CLONE_NEWNET) != 0 {
                write_stderr_static(b"pent: setns(net) failed\n");
                return Err(std::io::Error::last_os_error());
            }
            raise_net_admin_ambient()
        })
    };
    let output = cmd
        .output()
        .map_err(|e| SandboxError::NetworkSetupFailed(format!("cannot run ip: {e}")))?;
    if !output.status.success() {
        return Err(SandboxError::NetworkSetupFailed(format!(
            "ip {} (in the child namespace) failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn check_output(
    tool: &str,
    result: std::io::Result<std::process::Output>,
) -> Result<(), SandboxError> {
    match result {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(SandboxError::NetworkSetupFailed(format!(
            "{tool} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
        Err(e) => Err(SandboxError::NetworkSetupFailed(format!(
            "cannot run {tool}: {e}"
        ))),
    }
}

/// Load an nft script with `nft -f -`.
fn nft_load(script: &str) -> Result<(), SandboxError> {
    use std::process::Stdio;
    let mut cmd = Command::new("nft");
    cmd.args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: see `run_tool`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { cmd.pre_exec(raise_net_admin_ambient) };
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::NetworkSetupFailed(format!("cannot run nft: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| SandboxError::NetworkSetupFailed(format!("cannot write to nft: {e}")))?;
    }
    check_output("nft", child.wait_with_output())
}

/// Find the handles of the rules in `inet filter <chain>` that carry the
/// comment `tag`.
fn nft_find_tagged_rule_handles(chain: &str, tag: &str) -> Vec<u64> {
    let Ok(output) = run_tool("nft", &["-a", "list", "chain", "inet", "filter", chain]) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    parse_tagged_handles(&String::from_utf8_lossy(&output.stdout), tag)
}

/// Parse `nft -a list chain` output and return the handles of the rules
/// with `comment "<tag>"`.
fn parse_tagged_handles(text: &str, tag: &str) -> Vec<u64> {
    const MARKER: &str = "# handle ";
    let comment = format!("comment \"{tag}\"");
    text.lines()
        .filter(|line| line.contains(&comment))
        .filter_map(|line| {
            let pos = line.rfind(MARKER)?;
            line.get(pos + MARKER.len()..)?.trim().parse().ok()
        })
        .collect()
}

// ── Prepared networks ──────────────────────────────────────────────────────

/// Networks that `prepare_proxy_network` created and no spawn took yet.
static PREPARED: std::sync::Mutex<Vec<NetnsHandle>> = std::sync::Mutex::new(Vec::new());

/// Create the host side of a `ProxyOnly` network before the proxy starts.
///
/// Returns the outer veth address. Bind the proxy and the DNS server to this
/// address, so that only the sandbox (and local processes) can reach them.
/// Then pass `NetworkMode::ProxyOnly { proxy_addr, .. }` with a `proxy_addr`
/// on this address: `spawn_sandboxed` uses the prepared network.
///
/// If no spawn takes the network, the next pent run removes it with
/// [`cleanup_stale_netns`].
///
/// # Errors
/// * `PrivilegeRequired` if `CAP_NET_ADMIN` is absent.
/// * `NetworkSetupFailed` if a step fails.
pub fn prepare_proxy_network() -> Result<Ipv4Addr, SandboxError> {
    let handle = create_netns()?;
    let ip = handle.outer_ip;
    PREPARED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(handle);
    Ok(ip)
}

/// Take the prepared network whose outer address is `ip`.
pub(crate) fn take_prepared(ip: IpAddr) -> Option<NetnsHandle> {
    let mut list = PREPARED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pos = list.iter().position(|h| IpAddr::V4(h.outer_ip) == ip)?;
    Some(list.swap_remove(pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_veth_names_fit_ifnamsiz() {
        for id in [0, 1, 0xdead_beef, u32::MAX] {
            let (inner, outer) = veth_names(id);
            assert!(inner.len() <= 15, "{inner} is too long");
            assert!(outer.len() <= 15, "{outer} is too long");
            assert_ne!(inner, outer);
            assert!(inner.starts_with("pent"));
        }
        assert_eq!(veth_names(0xdead_beef).1, "pentdeadbeefo");
    }

    #[test]
    fn test_nets_overlap() {
        let a = Ipv4Addr::new(10, 200, 0, 4);
        assert!(nets_overlap(a, 30, Ipv4Addr::new(10, 200, 0, 5), 32));
        assert!(!nets_overlap(a, 30, Ipv4Addr::new(10, 200, 0, 8), 30));
        assert!(nets_overlap(a, 30, Ipv4Addr::new(10, 200, 0, 0), 16));
        assert!(nets_overlap(a, 30, Ipv4Addr::new(0, 0, 0, 0), 0));
    }

    #[test]
    fn test_choose_subnet_skips_taken() {
        let taken = vec![
            (Ipv4Addr::new(10, 200, 0, 1), 30),
            (Ipv4Addr::new(10, 200, 0, 4), 30),
            (Ipv4Addr::new(0, 0, 0, 0), 0), // default route: ignored
        ];
        assert_eq!(choose_subnet(0, &taken), Some(Ipv4Addr::new(10, 200, 0, 8)));
        // The start slot wraps inside the pool.
        assert_eq!(
            choose_subnet(POOL_SLOTS + 3, &[]),
            Some(Ipv4Addr::new(10, 200, 0, 12))
        );
    }

    #[test]
    fn test_choose_subnet_full_pool() {
        let taken = vec![(Ipv4Addr::new(10, 200, 0, 0), 16)];
        assert_eq!(choose_subnet(7, &taken), None);
    }

    #[test]
    fn test_parse_ipv4_nets() {
        let text = "2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n\
                    default via 192.168.1.1 dev eth0\n10.200.3.0/30 dev pentx scope link\n";
        let nets = parse_ipv4_nets(text);
        assert!(nets.contains(&(Ipv4Addr::new(192, 168, 1, 5), 24)));
        assert!(nets.contains(&(Ipv4Addr::new(10, 200, 3, 0), 30)));
        assert_eq!(nets.len(), 2);
    }

    #[test]
    fn test_state_roundtrip() -> TestResult {
        let mut s = InstanceState::new(42, 12345, 0x0102_0304, Ipv4Addr::new(10, 200, 1, 4));
        s.veth_created = true;
        s.firewall = FirewallKind::Nft;
        s.proxy_port = 8080;
        s.dns_port = 5353;
        let parsed = InstanceState::parse(&s.serialize()).ok_or("parse failed")?;
        assert_eq!(parsed, s);
        assert_eq!(parsed.outer_ip(), Ipv4Addr::new(10, 200, 1, 5));
        assert_eq!(parsed.inner_ip(), Ipv4Addr::new(10, 200, 1, 6));
        Ok(())
    }

    #[test]
    fn test_state_parse_rejects_bad_values() {
        let good = InstanceState::new(1, 2, 3, Ipv4Addr::new(10, 200, 0, 0)).serialize();
        assert!(InstanceState::parse(&good).is_some());
        // A network outside the pool or not aligned to /30.
        assert!(InstanceState::parse(&good.replace("10.200.0.0", "192.168.0.0")).is_none());
        assert!(InstanceState::parse(&good.replace("10.200.0.0", "10.200.0.1")).is_none());
        // An unknown firewall kind.
        assert!(InstanceState::parse(&good.replace("firewall=none", "firewall=x")).is_none());
        // A free-form line.
        assert!(InstanceState::parse(&format!("{good}rm -rf /\n")).is_none());
    }

    #[test]
    fn test_parse_start_time() {
        let stat = "1234 (my (odd) cmd) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(parse_start_time(stat), Some(987_654));
        assert_eq!(parse_start_time("garbage"), None);
    }

    #[test]
    fn test_own_process_is_alive() -> TestResult {
        let pid = std::process::id();
        let start = process_start_time(pid).ok_or("no start time")?;
        assert!(process_alive(pid, start));
        assert!(!process_alive(pid, start.wrapping_add(1)));
        Ok(())
    }

    #[test]
    fn test_parse_tagged_handles() {
        let text = "table inet filter {\n\
                    chain input {\n\
                    iifname \"pentaao\" tcp dport 1 accept comment \"pent_000000aa\" # handle 42\n\
                    iifname \"other\" accept # handle 7\n\
                    iifname \"x\" accept comment \"pent_000000aa\" # handle\n\
                    }\n}";
        assert_eq!(parse_tagged_handles(text, "pent_000000aa"), vec![42]);
    }

    #[test]
    fn test_firewall_rules_cover_ports_and_drop() {
        let mut s = InstanceState::new(1, 2, 0xab, Ipv4Addr::new(10, 200, 0, 8));
        s.proxy_port = 3128;
        s.dns_port = 5353;
        let rules = FirewallRules::new(&s);
        let script = rules.nft_script();
        assert!(script.contains("table inet pent_000000ab"));
        assert!(script.contains("ip daddr 10.200.0.9 tcp dport 3128 accept"));
        assert!(script.contains("udp dport 5353 accept"));
        assert!(script.contains("iifname \"pent000000abo\" drop"));
        assert!(script.contains("hook forward"));
        assert!(script.contains("iifname != \"lo\" drop"));

        let accept = rules.iptables_accept();
        assert_eq!(accept.len(), 3);
        let drop = rules.iptables_drop();
        assert!(drop
            .iter()
            .any(|r| r.tool == "ip6tables" && r.chain == "INPUT"));
        assert!(drop.iter().any(|r| r.chain == "FORWARD"));
        assert!(drop
            .iter()
            .chain(&accept)
            .all(|r| r.spec.contains(&"pent_000000ab".to_string())));

        s.dns_port = 0;
        assert_eq!(FirewallRules::new(&s).iptables_accept().len(), 1);
    }

    #[test]
    fn test_check_netns_privileges_returns_result() -> TestResult {
        match check_netns_privileges() {
            Ok(()) | Err(SandboxError::PrivilegeRequired(_)) => Ok(()),
            Err(e) => Err(format!("Unexpected error: {e:?}").into()),
        }
    }

    #[test]
    fn test_create_netns_requires_privileges() {
        if check_netns_privileges().is_err() {
            assert!(create_netns().is_err());
        }
    }

    /// The parent can run `ip` in a user and network namespace that a child
    /// owns. This needs no host privileges, only unprivileged user
    /// namespaces.
    #[test]
    fn test_run_ip_in_child_namespace() -> TestResult {
        if Command::new("ip").arg("-V").output().is_err() {
            return Ok(()); // skip: no ip binary
        }
        let mut child = match Command::new("unshare")
            .args(["--user", "--map-current-user", "--net", "sleep", "5"])
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return Ok(()), // skip: no unshare binary
        };
        // Wait until the child is in its new network namespace.
        let pid = child.id();
        let own = std::fs::read_link("/proc/self/ns/net")?;
        let mut ready = false;
        for _ in 0..50 {
            if std::fs::read_link(format!("/proc/{pid}/ns/net")).is_ok_and(|ns| ns != own) {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if !ready {
            child.kill().ok();
            child.wait().ok();
            return Ok(()); // skip: user namespaces not available
        }
        let user_ns = File::open(format!("/proc/{pid}/ns/user"))?;
        let net_ns = File::open(format!("/proc/{pid}/ns/net"))?;
        let result = run_ip_in_ns(
            user_ns.as_raw_fd(),
            net_ns.as_raw_fd(),
            &["link", "set", "lo", "up"],
        );
        child.kill().ok();
        child.wait().ok();
        assert!(result.is_ok(), "ip in child namespace failed: {result:?}");
        Ok(())
    }
}
