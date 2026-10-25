//! Linux sandbox implementation using Landlock LSM.
// Items in this private module use `pub` so they are accessible through
// `super::linux::*` within the crate.  The `unreachable_pub` lint is
// suppressed because the lint fires on `pub` items in a private module even
// when those items are accessed crate-internally.
#![allow(unreachable_pub)]
//!
//! Uses Landlock for filesystem access control. Pent requires Landlock ABI v3
//! (Linux 6.2) and uses the highest ABI up to v6 (see `linux_landlock.rs`).
//!
//! # Namespaces
//!
//! With enforcement, the child always creates a user namespace, a mount
//! namespace and a PID namespace (and a network namespace unless the
//! network is `Unrestricted`):
//! - `LocalhostOnly`: new network namespace, the child brings up loopback.
//! - `ProxyOnly`: new network namespace; the child brings up loopback and
//!   makes the proxy listeners in it (see `linux_proxynet.rs`).
//! - `Blocked`: new network namespace with no interfaces.
//! - `Unrestricted`: no network namespace.
//!
//! The private mount namespace gives the child its own `/tmp`, `/var/tmp`
//! and `/run`, hides the Unix sockets that Landlock cannot control, and
//! makes `<workspace>/.pent` read-only.
//!
//! The PID namespace holds a private `proc` mount, so the child sees only
//! the processes of the sandbox, and no background process of the sandbox
//! outlives the command. `unshare(CLONE_NEWPID)` does not move the caller,
//! so the `pre_exec` hook forks twice; see [`fork_pid_namespace`].
//!
//! The two go together, and not every host gives them. In a container the
//! kernel refuses a new `proc` mount, because the runtime hides a part of
//! `/proc`. [`proc_isolation`] probes this one time before the first
//! `unshare`. Where the answer is [`ProcIsolation::Shared`], pent runs the
//! command without the PID namespace and names what the command can see.
//!
//! Watch mode (`SpawnMode::Watch`) creates the same three namespaces. It
//! applies no Landlock, no overlay and no masks. The mount namespace holds
//! the private directories and the mounts of the watch guard (see
//! `linux_watch.rs`). The PID namespace of watch mode differs in one
//! point: PID 1 waits for the orphans of the program before it exits, so
//! that the recorder gets their events (see [`Orphans`]).
//!
//! # Landlock architecture
//!
//! ```text
//! Ruleset (deny-all baseline)
//!   |
//!   +-- Allow workspace (rw)
//!   +-- Allow data_dir (rw)
//!   +-- Allow mounts (per config)
//!   +-- Allow PATH dirs (read+exec)
//!   +-- Allow execute paths (exec, no read)
//!   +-- Allow read paths (read only)
//!   +-- Allow system libs and /nix/store (read+exec)
//!   +-- Allow /tmp, /var/tmp (rw)
//!   +-- Allow /dev/null, /dev/tty, /dev/pts, ... (rw); /dev/urandom, ... (ro)
//!   +-- Allow /proc (ro)
//! ```
//!
//! # `pre_exec` and async-signal safety
//!
//! The parent is multithreaded. Between `fork` and `exec` the child may only
//! use async-signal-safe functions. Thus the parent prepares all data before
//! `fork`: the Landlock ruleset file descriptor and its rules as C strings,
//! the UID and GID maps, the mount targets and the working directory. The
//! `pre_exec` hook uses only raw system calls on this data.
//!
//! The overlayfs helpers (`linux_overlayfs::setup_overlay_dirs` and
//! `mount_overlays`) still allocate in the child. They run only when write
//! listed files need an overlay.
//!
//! # Private temporary and runtime directories
//!
//! `/tmp`, `/var/tmp` and `/run` of the host hold the temporary files and the
//! control sockets of the programs of the user. The child gets an empty
//! tmpfs over each of them (see [`PRIVATE_DIRS`]), and pent binds back only
//! the paths that the session needs: the workspace, the data directory, the
//! working directory, each configured path, each directory of `PATH`, and
//! the system paths of [`PRIVATE_KEEP`]. See [`plan_private_dirs`].
//!
//! # Limits
//!
//! Landlock (ABI v6 and earlier) does not control `connect(2)` on Unix
//! sockets that have a path. A sandboxed process can connect to a socket file
//! that it finds, if the socket is not hidden by a mount. The private
//! directories above hide the sockets under `/tmp`, `/var/tmp` and `/run`.
//! A socket in the home directory needs a mask (see [`HOME_AGENT_SOCKETS`]),
//! and a socket that the profile names stays reachable. The full fix is a
//! `connect(2)` filter in the supervisor.

use crate::linux_landlock::{access, PreparedRuleset};
use crate::{NetworkMode, SandboxConfig, SandboxError};
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(test)]
/// Minimum required Landlock ABI version.
pub const MIN_LANDLOCK_ABI: u32 = crate::linux_landlock::MIN_ABI;

/// System paths to allow read and execute access (libraries, config, etc.).
///
/// On NixOS, all binaries and libraries live in the immutable, world-readable
/// `/nix/store`. `/run/current-system` points into it. A missing path is
/// skipped.
const SYSTEM_PATHS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/share",
    "/etc",
    "/nix/store",
    "/run/current-system",
];

/// Temp paths to allow read/write access.
const TEMP_PATHS: &[&str] = &["/tmp", "/var/tmp"];

/// Device nodes with read/write access. `/dev/shm` and `/dev/mqueue` are not
/// in the list: add them to the configuration if a tool needs them.
pub(crate) const DEV_RW_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/pts",
    "/dev/ptmx",
];

/// Device nodes with read-only access.
///
/// `/dev/fd` and `/dev/std*` are not in the list: they are symbolic links
/// into `/proc/self/fd`. The `/proc` rule covers the link, and Landlock does
/// not control pipes and sockets that a process opens through it.
pub(crate) const DEV_READ_PATHS: &[&str] = &["/dev/random", "/dev/urandom"];

/// Proc paths to allow read access.
const PROC_PATHS: &[&str] = &["/proc"];

/// Unix sockets that give a way out of the sandbox. The child hides each one
/// that exists with a bind mount of `/dev/null`, unless the configuration
/// names it.
///
/// A fixed list can never be complete: each daemon that keeps a control
/// socket and offers a dial or an exec operation is an escape. The private
/// directories of [`PRIVATE_DIRS`] hide every socket under `/run`, `/tmp`
/// and `/var/tmp`, so this list is a second layer. It is also the list that
/// a user setting can extend later.
const ESCAPE_SOCKETS: &[&str] = &[
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
    // The system message bus. It gives access to systemd-resolved (name
    // resolution past the proxy), NetworkManager and polkit.
    "/run/dbus/system_bus_socket",
    "/var/run/dbus/system_bus_socket",
];

/// Unix sockets of host resolvers and of host network agents. A query or a
/// connection through them goes to the network of the host, past the proxy.
/// When the network is not `Unrestricted`, the child hides each one that
/// exists, like [`ESCAPE_SOCKETS`]. Then the C library uses
/// `/etc/resolv.conf`.
const RESOLVER_SOCKETS: &[&str] = &[
    "/run/nscd/socket",
    "/var/run/nscd/socket",
    "/run/systemd/resolve/io.systemd.Resolve",
    // The Tailscale daemon. Its LocalAPI has a "ts-dial" upgrade that opens
    // a TCP stream to any host of the tailnet, and through an exit node or a
    // subnet route to the public internet.
    "/run/tailscale/tailscaled.sock",
    "/var/run/tailscale/tailscaled.sock",
];

/// Unix sockets of an agent in the home directory, as a directory and a name
/// prefix. The agent signs a challenge or decrypts a secret for any program
/// that reaches its socket, so the child must not see it. The child hides
/// each socket in `<home>/<dir>` whose name starts with `prefix`, unless the
/// configuration names the socket.
///
/// The sockets under `/run/user/<uid>` need no entry here: [`PRIVATE_DIRS`]
/// hides all of `/run`.
const HOME_AGENT_SOCKETS: &[(&str, &str)] = &[
    (".gnupg", "S.gpg-agent"),
    (".gnupg", "S.dirmngr"),
    (".ssh", "agent."),
];

/// A directory that an empty tmpfs covers in the mount namespace of the
/// child.
struct PrivateDir {
    /// The directory of the host.
    path: &'static str,
    /// The mount data of the tmpfs.
    ///
    /// The data has no `size=`, so the tmpfs takes the kernel default of
    /// half of the memory. A build writes large temporary files, and a
    /// smaller limit breaks it.
    data: &'static CStr,
}

/// The directories that pent replaces with an empty tmpfs in the mount
/// namespace of the child.
///
/// `/tmp` and `/var/tmp` hold the temporary files of the programs of the
/// user; `/run` holds their control sockets. The child must see neither.
/// Each tmpfs is `nosuid` and `nodev`. `/tmp` and `/var/tmp` keep the mode
/// `1777` of a temporary directory; `/run` keeps `0755`.
///
/// A path that is a symbolic link is skipped: `/var/run` points to `/run` on
/// most systems, and the tmpfs on `/run` covers it.
const PRIVATE_DIRS: &[PrivateDir] = &[
    PrivateDir {
        path: "/tmp",
        data: c"mode=1777",
    },
    PrivateDir {
        path: "/var/tmp",
        data: c"mode=1777",
    },
    PrivateDir {
        path: "/run",
        data: c"mode=0755",
    },
    PrivateDir {
        path: "/var/run",
        data: c"mode=0755",
    },
];

/// The paths under a private directory that pent always binds back when they
/// exist. NixOS keeps the system profile, the setuid wrappers and the
/// graphics drivers under `/run`, and no program starts without them.
const PRIVATE_KEEP: &[&str] = &[
    "/run/current-system",
    "/run/booted-system",
    "/run/wrappers/bin",
    "/run/opengl-driver",
    "/run/opengl-driver-32",
];

/// Compute the set of paths the sandboxed process is allowed to read/execute.
///
/// The set is a part of the accessible set that `spawn_with_landlock` gives
/// to the overlay setup. The set does not tell the access type. To predict
/// whether the policy denies one access, the recorder uses [`AccessPolicy`].
#[must_use]
pub fn compute_accessible_set(config: &SandboxConfig, path_dirs: &[PathBuf]) -> HashSet<PathBuf> {
    let (_, read_expanded, execute_expanded, rw_expanded) = config.paths.expand_paths();
    let mut accessible: HashSet<PathBuf> = HashSet::new();
    for (p, _) in read_expanded
        .iter()
        .chain(&execute_expanded)
        .chain(&rw_expanded)
    {
        accessible.insert(p.clone());
    }
    accessible.insert(config.workspace.clone());
    accessible.insert(config.data_dir.clone());
    for mount in &config.mounts {
        accessible.insert(mount.path.clone());
    }
    for p in SYSTEM_PATHS
        .iter()
        .chain(TEMP_PATHS)
        .chain(DEV_RW_PATHS)
        .chain(DEV_READ_PATHS)
        .chain(PROC_PATHS)
    {
        accessible.insert(PathBuf::from(p));
    }
    for path_dir in path_dirs {
        accessible.insert(path_dir.clone());
    }
    accessible
}

/// A destination for Landlock rules: the real ruleset, or the prediction of
/// the recorder. Both get the same rules from `add_ruleset_rules`.
trait RuleSink {
    /// Grant `access` beneath `path`.
    fn add_rule(&mut self, path: &Path, access: u64);
}

impl RuleSink for PreparedRuleset {
    fn add_rule(&mut self, path: &Path, access: u64) {
        self.add(path, access);
    }
}

/// The Landlock policy of a sandbox as a list of path prefixes.
///
/// The seccomp recorder of `pent run --trace` sees each system call before
/// Landlock decides. Thus the recorder predicts the decision with this
/// policy. The policy has the same rules as the real ruleset (see
/// `add_ruleset_rules`). Landlock binds a rule to an inode, so the policy
/// keeps the canonical path of each rule and also the path as written.
///
/// Landlock is not the only layer that refuses an access. Below an overlay
/// mount, the upper layer hides each path that the profile does not name,
/// and the program gets `ENOENT` instead of `EACCES`. The policy holds the
/// overlay mount points and the paths that the overlay shows, so that such
/// a read becomes a recorded denial too (see [`AccessPolicy::hidden`]).
#[derive(Debug, Clone, Default)]
pub(crate) struct AccessPolicy {
    rules: Vec<(PathBuf, u64)>,
    /// The mount point of each overlay.
    overlay_roots: Vec<PathBuf>,
    /// The paths that the overlay shows below a mount point.
    shown: Vec<PathBuf>,
}

impl RuleSink for AccessPolicy {
    fn add_rule(&mut self, path: &Path, access: u64) {
        // Landlock skips a rule for a path that does not exist.
        let Ok(real) = std::fs::canonicalize(path) else {
            return;
        };
        if real != path {
            self.rules.push((path.to_path_buf(), access));
        }
        self.rules.push((real, access));
    }
}

impl AccessPolicy {
    /// Tell the policy which paths the overlay shows.
    ///
    /// `roots` are the mount points and `shown` is the accessible set that
    /// `linux_overlayfs::setup_overlay_dirs` uses. The function keeps the
    /// canonical form of each path and also the path as written, because
    /// the recorder does not resolve the symbolic links of a path.
    fn set_overlay(&mut self, roots: &HashSet<PathBuf>, shown: &HashSet<PathBuf>) {
        let both = |out: &mut Vec<PathBuf>, path: &Path| {
            out.push(path.to_path_buf());
            if let Ok(real) = std::fs::canonicalize(path) {
                if real != path {
                    out.push(real);
                }
            }
        };
        for root in roots {
            both(&mut self.overlay_roots, root);
        }
        for path in shown {
            both(&mut self.shown, path);
        }
    }

    /// Return true when the upper layer of an overlay hides `path`.
    ///
    /// `populate_upper_stubs` in `linux_overlayfs.rs` makes a stub for
    /// each entry below a mount point that the accessible set neither
    /// covers nor leads to. A path below such an entry is not there for
    /// the child, so a read of it gives `ENOENT` and no Landlock denial.
    ///
    /// The answer has one limit: the upper layer is writable, so a child
    /// that makes a file of its own at a hidden name can read that file
    /// back. The policy calls such a read a denial too. The report stays
    /// true, because the file of the host stays hidden: the child reads
    /// its own content, never the content that the overlay hides.
    fn hidden(&self, path: &Path) -> bool {
        if !self
            .overlay_roots
            .iter()
            .any(|root| path.starts_with(root) && path != root)
        {
            return false;
        }
        !self
            .shown
            .iter()
            .any(|p| path.starts_with(p) || p.starts_with(path))
    }

    /// Return the Landlock rights that the policy grants for `path`. Landlock
    /// adds the rights of all rules on the path and on its ancestors.
    fn rights(&self, path: &Path) -> u64 {
        self.rules
            .iter()
            .filter(|(p, _)| path.starts_with(p))
            .fold(0, |acc, (_, a)| acc | a)
    }

    /// Predict the result of the operation `op` on `path`. `is_dir` tells
    /// whether the path is a directory (a read of a directory needs only
    /// `READ_DIR`).
    #[must_use]
    pub(crate) fn predict(
        &self,
        op: pent_profile::FsOp,
        path: &Path,
        is_dir: bool,
    ) -> pent_profile::Outcome {
        use pent_profile::FsOp;
        // The overlay answers before Landlock. A read or an execution of a
        // path that the upper layer hides gives `ENOENT`, which is a
        // denial that the user must see (DIFF-1). A write or a create goes
        // to the upper layer and works inside the run, so it stays a
        // Landlock question.
        if matches!(op, FsOp::Read | FsOp::Exec) && self.hidden(path) {
            return pent_profile::Outcome::Denied;
        }
        let (subject, needed) = match op {
            FsOp::Read if is_dir => (path, access::READ_DIR),
            FsOp::Read => (path, access::READ_FILE),
            FsOp::Write if is_dir => (path, access::MAKE_REG),
            FsOp::Write => (path, access::WRITE_FILE),
            FsOp::Exec => (path, access::EXECUTE),
            // Landlock checks a new or a removed entry on the parent
            // directory.
            FsOp::Create => (path.parent().unwrap_or(path), access::MAKE_REG),
            FsOp::Delete => (path.parent().unwrap_or(path), access::REMOVE_FILE),
        };
        if self.rights(subject) & needed == needed {
            pent_profile::Outcome::Allowed
        } else {
            pent_profile::Outcome::Denied
        }
    }
}

/// Check that Landlock is enabled and supports the minimum ABI.
///
/// # Errors
/// Returns `SandboxUnavailable` with a remediation if Landlock is absent,
/// disabled at boot, or too old.
pub fn check_available() -> Result<(), SandboxError> {
    crate::linux_landlock::abi_version().map(|_| ())
}

/// Check that this user can create a user namespace with a network
/// namespace and a PID namespace in it. The sandbox needs all three, and no
/// other privilege.
///
/// The check forks a short-lived child that calls `unshare`.
///
/// # Errors
/// * `SandboxUnavailable` with a remediation if the kernel refuses.
/// * `SpawnFailed` if the fork or the wait fails.
pub fn check_user_namespaces() -> Result<(), SandboxError> {
    // SAFETY: the child of the fork calls only the async-signal-safe
    // unshare(2) and _exit(2), so the fork is safe in a multithreaded
    // process.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SandboxError::SpawnFailed(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: unshare(2) with integer flags.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ok =
            unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWPID) }
                == 0;
        let code = if ok {
            0
        } else {
            // The exit code carries the error number (all are below 256).
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EPERM)
                & 0xff
        };
        // SAFETY: _exit(2) ends the child without the atexit handlers of the
        // parent.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waitpid(2) on our own child with a valid status pointer.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if ret == pid {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(SandboxError::SpawnFailed(err));
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    let errno = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        libc::EPERM
    };
    Err(SandboxError::SandboxUnavailable {
        reason: format!(
            "this user cannot create a user namespace, a network namespace and a PID \
             namespace: {}",
            std::io::Error::from_raw_os_error(errno)
        ),
        remediation: "Let unprivileged users create user namespaces: set the sysctl \
                      user.max_user_namespaces above 0, and kernel.unprivileged_userns_clone \
                      to 1 where it exists. On Ubuntu 24.04 and later, also set \
                      kernel.apparmor_restrict_unprivileged_userns to 0, or add an AppArmor \
                      profile for pent"
            .to_string(),
    })
}

// ── The private `/proc` of the child (finding LS-3) ────────────────────────

/// The error number that the kernel gives when it refuses a new `proc`
/// mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcDenial(i32);

impl ProcDenial {
    /// The error of the mount that the kernel refused.
    #[must_use]
    pub fn error(self) -> std::io::Error {
        std::io::Error::from_raw_os_error(self.0)
    }

    /// The name of the error number.
    #[must_use]
    fn name(self) -> Option<&'static str> {
        match self.0 {
            libc::EPERM => Some("EPERM"),
            libc::EACCES => Some("EACCES"),
            libc::EINVAL => Some("EINVAL"),
            libc::ENOSYS => Some("ENOSYS"),
            libc::ENOMEM => Some("ENOMEM"),
            libc::EBUSY => Some("EBUSY"),
            _ => None,
        }
    }
}

impl std::fmt::Display for ProcDenial {
    /// Write the name of the error number, for example `EPERM`.
    ///
    /// The name, and not the message of the C library: a warning of pent
    /// must not hold the words that the sandbox prints for a denied
    /// access ("Operation not permitted"). A reader of the output, and a
    /// test, looks for those words.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "error number {}", self.0),
        }
    }
}

/// The kind of `/proc` that the child can get on this host.
///
/// The child needs a new PID namespace **and** a new `proc` mount to see
/// only the processes of the sandbox (finding LS-3 in
/// `docs/security/linux-sandbox.md`). The kernel gives a new `proc` mount to
/// a process that has no privilege on the host only when the mount namespace
/// already holds a `proc` mount that hides nothing. The rule is
/// `mount_too_revealing` in `fs/namespace.c`, and it looks at the mounts of
/// the namespace, not at the target of the new mount.
///
/// A container runtime hides a part of `/proc` with its own mounts, for
/// example on `/proc/acpi` and on `/proc/kcore`. Each inherited mount of a
/// child user namespace is locked, so pent can neither remove such a mount
/// nor move it away. The kernel then refuses a new `proc` mount with
/// `EPERM`, at any target: a mount on a fresh empty directory and a move of
/// it with `MS_MOVE` give the same error. Thus pent runs the command
/// without the PID namespace there, and it names what the command can see
/// (see [`ProcIsolation::warning_lines`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcIsolation {
    /// The child gets its own PID namespace and its own `proc` mount.
    Private,
    /// The kernel refuses a new `proc` mount. The child keeps the PID
    /// namespace and the `/proc` of this host.
    Shared(ProcDenial),
}

impl ProcIsolation {
    /// True when the child gets its own PID namespace and its own `/proc`.
    #[must_use]
    pub fn is_private(self) -> bool {
        matches!(self, Self::Private)
    }

    /// The lines that name what the command can see when the protection is
    /// absent. The list is empty when the child gets its own `/proc`.
    ///
    /// The caller prints one warning for each line.
    #[must_use]
    pub fn warning_lines(self) -> Vec<String> {
        self.warning_lines_from(&hidden_proc_paths_here())
    }

    /// The lines of [`ProcIsolation::warning_lines`], for the layout in
    /// `hidden`. The tests give the layout as data, so the lines do not
    /// follow the host of the test.
    fn warning_lines_from(self, hidden: &[String]) -> Vec<String> {
        let Self::Shared(denial) = self else {
            return Vec::new();
        };
        let mut lines = vec![format!(
            "pent cannot give the command a private /proc: the kernel refuses the mount \
             with {denial}"
        )];
        if hidden.is_empty() {
            lines.push("the kernel of this host refuses a new proc mount".to_string());
        } else {
            lines.push(format!(
                "a mount hides a part of /proc ({}), as a container runtime does",
                short_list(hidden)
            ));
        }
        lines.push(
            "thus the command keeps the PID namespace of this host and sees each process of it"
                .to_string(),
        );
        lines.push(
            "the command reads /proc/<pid>/cmdline of a neighbour, and a command line can hold \
             a token"
                .to_string(),
        );
        lines
    }
}

/// Whether the mode of the spawn asks for a new PID namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PidNamespace {
    /// The sandbox and watch mode ask for one.
    Wanted,
    /// A run without enforcement and without watch asks for none.
    NotWanted,
}

/// The `unshare` flag for the PID namespace of the child.
///
/// The PID namespace and the private `proc` mount go together: a child in a
/// new PID namespace that keeps the `/proc` of the host reads the PIDs of
/// another namespace there, and that confuses each tool. Thus a host that
/// gives no private `proc` mount gets no PID namespace either. See
/// [`ProcIsolation`].
fn pid_namespace_flag(wants: PidNamespace, isolation: ProcIsolation) -> libc::c_int {
    if wants == PidNamespace::Wanted && isolation.is_private() {
        libc::CLONE_NEWPID
    } else {
        0
    }
}

/// Join up to three paths for a message.
fn short_list(paths: &[String]) -> String {
    const SHOWN: usize = 3;
    let head = paths
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if paths.len() > SHOWN {
        format!("{head} and more")
    } else {
        head
    }
}

/// One line of `/proc/self/mountinfo`.
struct MountLine<'a> {
    /// The identifier of the mount.
    id: &'a str,
    /// The identifier of the parent mount.
    parent: &'a str,
    /// The mount point.
    mount_point: &'a str,
    /// The type of the filesystem.
    fs_type: &'a str,
}

/// Read the fields of one line of `/proc/self/mountinfo`.
///
/// The line holds the identifier of the mount, the identifier of the parent
/// mount, the device, the root, the mount point and the mount options. Then
/// come optional fields, a `-`, the type of the filesystem and the source.
fn parse_mount_line(line: &str) -> Option<MountLine<'_>> {
    let (head, tail) = line.split_once(" - ")?;
    let mut fields = head.split(' ');
    let id = fields.next()?;
    let parent = fields.next()?;
    let _device = fields.next()?;
    let _root = fields.next()?;
    let mount_point = fields.next()?;
    let fs_type = tail.split(' ').next()?;
    Some(MountLine {
        id,
        parent,
        mount_point,
        fs_type,
    })
}

/// The paths that another mount hides inside a `proc` mount.
///
/// `mountinfo` is the content of `/proc/self/mountinfo`. A mount whose
/// parent is a `proc` mount hides the part of `/proc` at its mount point.
/// This is the layout that makes the kernel refuse a new `proc` mount; see
/// [`ProcIsolation`].
///
/// The kernel makes one exception that this function does not make: a mount
/// on a directory that is permanently empty hides nothing. Thus the list can
/// name one path more than the kernel counts. The list is a message for the
/// user, and [`proc_isolation`] gives the answer.
fn hidden_proc_paths(mountinfo: &str) -> Vec<String> {
    let lines: Vec<MountLine<'_>> = mountinfo.lines().filter_map(parse_mount_line).collect();
    let proc_ids: Vec<&str> = lines
        .iter()
        .filter(|m| m.fs_type == "proc")
        .map(|m| m.id)
        .collect();
    let mut out: Vec<String> = lines
        .iter()
        .filter(|m| proc_ids.contains(&m.parent))
        .map(|m| m.mount_point.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The paths that another mount hides inside the `/proc` of this host.
fn hidden_proc_paths_here() -> Vec<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|text| hidden_proc_paths(&text))
        .unwrap_or_default()
}

/// How many times [`probe_proc_isolation`] forked. The cache must make it
/// run one time for the life of the process.
#[cfg(test)]
static PROBE_RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Ask whether the kernel gives the child its own PID namespace and its own
/// `/proc` on this host.
///
/// The answer comes from one probe, and the probe runs one time for the life
/// of the process.
///
/// The question must have an answer **before** the real child unshares. A
/// process cannot leave a PID namespace, and the `/proc` that it inherits
/// then names the processes of another namespace, which confuses each tool
/// that reads it.
#[must_use]
pub fn proc_isolation() -> ProcIsolation {
    static ANSWER: std::sync::OnceLock<ProcIsolation> = std::sync::OnceLock::new();
    *ANSWER.get_or_init(probe_proc_isolation)
}

/// Probe whether a new `proc` mount works on this host.
///
/// The probe forks a short-lived child, as [`check_user_namespaces`] does.
/// The child unshares a user namespace, a mount namespace and a PID
/// namespace, writes the identity maps, and forks again: only a child of
/// the process that unshares is in the new PID namespace. The grandchild
/// makes its mount tree private and mounts a new `proc` over `/proc`. The
/// exit status carries the answer: 0 for a mount that works, else the error
/// number of the step that failed.
///
/// Each mount of the probe lives in the mount namespace of the grandchild,
/// which the kernel removes with it. The probe changes nothing on the host.
fn probe_proc_isolation() -> ProcIsolation {
    #[cfg(test)]
    PROBE_RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // SAFETY: getuid/getgid have no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // The maps come from the parent: after `fork` the child may only call
    // async-signal-safe functions.
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();

    // SAFETY: the child of the fork calls only async-signal-safe system
    // calls (see `probe_child`), so the fork is safe in a multithreaded
    // process.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return ProcIsolation::Shared(ProcDenial(errno_now()));
    }
    if pid == 0 {
        let code = probe_child(&uid_map, &gid_map);
        // SAFETY: _exit(2) ends the child without the atexit handlers of
        // the parent.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::_exit(code) };
    }
    match wait_for_code(pid) {
        Ok(0) => ProcIsolation::Private,
        Ok(code) => ProcIsolation::Shared(ProcDenial(code)),
        Err(errno) => ProcIsolation::Shared(ProcDenial(errno)),
    }
}

/// The error number of the last system call, or `EPERM` when the error
/// carries none.
fn errno_now() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EPERM)
}

/// An error number that fits in an exit code.
fn exit_code_of_errno() -> libc::c_int {
    errno_now() & 0xff
}

/// Wait for `pid` and return its exit code.
///
/// # Errors
/// Returns the error number of the `waitpid` that failed, or `EPERM` when a
/// signal ended the child.
fn wait_for_code(pid: libc::pid_t) -> Result<libc::c_int, i32> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waitpid(2) on our own child with a valid status pointer.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if ret == pid {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err.raw_os_error().unwrap_or(libc::EPERM));
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else {
        Err(libc::EPERM)
    }
}

/// The steps of the probe in the short-lived child. Returns the exit code:
/// 0 for a private `/proc`, else an error number.
///
/// Async-signal-safe. The function writes no message: the caller reports the
/// answer one time, with [`ProcIsolation::warning_lines`].
fn probe_child(uid_map: &[u8], gid_map: &[u8]) -> libc::c_int {
    if prepare_caps_for_userns().is_err() {
        return exit_code_of_errno();
    }
    // SAFETY: unshare(2) with integer flags.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let unshared =
        unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID) == 0 };
    if !unshared {
        return exit_code_of_errno();
    }
    // The same three writes as `setup_userns_mappings`, without its
    // messages.
    if write_proc_file(c"/proc/self/setgroups", b"deny").is_err()
        || write_proc_file(c"/proc/self/gid_map", gid_map).is_err()
        || write_proc_file(c"/proc/self/uid_map", uid_map).is_err()
    {
        return exit_code_of_errno();
    }
    // SAFETY: the child of this fork calls only async-signal-safe system
    // calls (see `probe_proc_mount`).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return exit_code_of_errno();
    }
    if pid == 0 {
        let code = probe_proc_mount();
        // SAFETY: _exit(2) ends the grandchild at once.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::_exit(code) };
    }
    match wait_for_code(pid) {
        Ok(code) => code,
        Err(errno) => errno & 0xff,
    }
}

/// Mount a new `proc` over `/proc`, as [`MountPlan::apply`] does. Returns 0
/// or the error number. Async-signal-safe.
fn probe_proc_mount() -> libc::c_int {
    // Make the tree private, as the real child does. The result does not
    // change the answer: after `unshare(CLONE_NEWUSER | CLONE_NEWNS)` each
    // inherited mount is a slave already, so no mount of the probe reaches
    // the host.
    // SAFETY: mount(2) with static NUL-terminated strings.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let _ignored = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    // SAFETY: mount(2) with static NUL-terminated strings. The flags are
    // the flags of the real mount, because the kernel compares them with
    // the flags of the `proc` mount that the namespace already holds.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if ret == 0 {
        0
    } else {
        exit_code_of_errno()
    }
}

/// Add all filesystem rules for `config` to `ruleset`.
///
/// * `write_set` - write-listed files that an overlay covers (skipped here;
///   the overlay parent directory rule covers them).
/// * `overlay_dirs` - directories with an overlay mount (read/write).
fn add_ruleset_rules(
    ruleset: &mut impl RuleSink,
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
    write_set: &HashSet<PathBuf>,
    overlay_dirs: &HashSet<PathBuf>,
    resolv_target: Option<&Path>,
) {
    ruleset.add_rule(&config.workspace, access::ALL);
    ruleset.add_rule(&config.data_dir, access::ALL);
    for mount in &config.mounts {
        let a = if mount.readonly {
            access::READ
        } else {
            access::ALL
        };
        ruleset.add_rule(&mount.path, a);
    }

    // Configured SandboxPaths (from profiles and TOML config).
    // traversal = ReadDir only (stat/list, no file reads or exec).
    // read = ReadFile | ReadDir (config files, libraries, data; no exec).
    // execute = ReadDir | Execute (binary directories, installed tools; no ReadFile).
    // read_write = all access rights.
    let (traversal, read, execute, rw) = config.paths.expand_paths();
    for (path, _) in &traversal {
        ruleset.add_rule(path, access::TRAVERSAL);
    }
    for (path, _) in &read {
        ruleset.add_rule(path, access::READ);
    }
    for (path, _) in &execute {
        ruleset.add_rule(path, access::EXECUTE_ONLY);
    }
    for (path, _) in &rw {
        if !write_set.contains(path) {
            ruleset.add_rule(path, access::ALL);
        }
    }
    // Overlay parent directories: inside the namespace, writes go to the
    // upper layer; the watcher of the parent flushes write-listed files.
    // The rule gives no execution: a `read` entry is not an `execute`
    // entry, and the overlay must not turn one into the other (DIFF-4).
    // The right to run a file comes from the rule of its own entry.
    //
    // A directory that the profile names `read` or `traversal`, and that
    // holds nothing that the profile may write, keeps the read rights
    // only. Landlock joins the rights of each rule on one path, so the
    // wider rule of the overlay would otherwise give the write back, and a
    // write to a `read` entry would work inside the run (DIFF-3).
    let read_only_dirs: Vec<&PathBuf> = read
        .iter()
        .chain(&traversal)
        .map(|(path, _)| path)
        .filter(|path| {
            !write_set.iter().any(|w| w.starts_with(path))
                && !rw.iter().any(|(w, _)| w.starts_with(path))
                && *path != &config.workspace
                && *path != &config.data_dir
        })
        .collect();
    for dir in overlay_dirs {
        let rights = if read_only_dirs.iter().any(|p| **p == *dir) {
            access::READ
        } else {
            access::ALL_NO_EXECUTE
        };
        ruleset.add_rule(dir, rights);
    }
    // PATH directories and system libraries: the dynamic linker must open()
    // binaries and shared libraries, so these get ReadFile too.
    for path_dir in path_dirs {
        ruleset.add_rule(path_dir, access::READ_EXECUTE);
    }
    for p in SYSTEM_PATHS {
        ruleset.add_rule(Path::new(p), access::READ_EXECUTE);
    }
    for p in TEMP_PATHS.iter().chain(DEV_RW_PATHS) {
        ruleset.add_rule(Path::new(p), access::ALL);
    }
    for p in DEV_READ_PATHS.iter().chain(PROC_PATHS) {
        ruleset.add_rule(Path::new(p), access::READ);
    }
    // The `resolv.conf` of the proxy. On a host with `systemd-resolved`,
    // `/etc/resolv.conf` is a symbolic link into `/run`, and the target is
    // inside the private tmpfs of `/run`. No rule above covers that path,
    // and Landlock then refuses the read with `EACCES`. The child adds the
    // rule after the mounts, so the rule binds to the inode of the file of
    // pent (see `resolv_bind` and `PreparedRuleset::apply_in_child`).
    if let Some(path) = resolv_target {
        ruleset.add_rule(path, access::READ);
    }
}

/// Return the paths that the Landlock backend always allows, in addition to
/// the configuration: the system paths, the temporary paths, the device
/// nodes and `/proc`.
#[must_use]
pub(crate) fn implicit_paths() -> Vec<PathBuf> {
    SYSTEM_PATHS
        .iter()
        .chain(TEMP_PATHS)
        .chain(DEV_RW_PATHS)
        .chain(DEV_READ_PATHS)
        .chain(PROC_PATHS)
        .map(PathBuf::from)
        .collect()
}

/// Build the Landlock ruleset for `config` (test helper).
///
/// # Errors
/// Returns `SandboxUnavailable` if Landlock is not usable.
#[cfg(test)]
pub fn build_landlock_ruleset(
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
) -> Result<PreparedRuleset, SandboxError> {
    let mut ruleset = PreparedRuleset::create()?;
    add_ruleset_rules(
        &mut ruleset,
        config,
        path_dirs,
        &HashSet::new(),
        &HashSet::new(),
        None,
    );
    Ok(ruleset)
}

// ── Raw helpers for the pre_exec hook ──────────────────────────────────────

/// Write a static message to the error output. Async-signal-safe.
pub(crate) fn write_stderr_static(msg: &'static [u8]) {
    // SAFETY: write(2) on fd 2 with a static buffer is async-signal-safe.
    // The result is ignored because no other channel for the error exists.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
    }
}

/// Return the last OS error. `std::io::Error::last_os_error` does not
/// allocate, so this is async-signal-safe.
fn last_err(msg: &'static [u8]) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    write_stderr_static(msg);
    err
}

/// Write all of `buf` to `fd`. Retries on EINTR and on a short write.
/// Async-signal-safe.
fn write_all_fd(fd: libc::c_int, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is a valid slice for `buf.len()` bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        buf = buf.get(n.unsigned_abs()..).unwrap_or_default();
    }
    Ok(())
}

/// Open `path` for writing and write all of `buf` to it. Async-signal-safe.
fn write_proc_file(path: &std::ffi::CStr, buf: &[u8]) -> std::io::Result<()> {
    // SAFETY: `path` is a valid NUL-terminated string.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = write_all_fd(fd, buf);
    // SAFETY: `fd` is a file descriptor that this function opened.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(fd) };
    result
}

/// Bring up the loopback interface in the current network namespace.
///
/// Called after `unshare(CLONE_NEWNET)` for `LocalhostOnly` and `ProxyOnly`.
/// Async-signal-safe.
fn bring_up_loopback() -> std::io::Result<()> {
    const IFNAMSIZ: usize = 16;
    const IFF_UP: i16 = 0x1;

    /// Mirrors the C `struct ifreq` layout for SIOCGIFFLAGS / SIOCSIFFLAGS.
    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; IFNAMSIZ],
        ifr_flags: i16,
        _pad: [u8; 22],
    }
    // Compile-time check that our hand-written layout matches the expected size.
    const _: () = assert!(std::mem::size_of::<IfReq>() == 40);

    let mut req = IfReq {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: 0,
        _pad: [0; 22],
    };
    req.ifr_name[0] = b'l';
    req.ifr_name[1] = b'o';

    // SAFETY: socket(2) with constant arguments.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(last_err(b"pent: socket for loopback setup failed\n"));
    }
    // SAFETY: `req` is a valid `struct ifreq` for SIOCGIFFLAGS, and `sock`
    // is a socket that this function owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let got = unsafe {
        libc::ioctl(
            sock,
            libc::SIOCGIFFLAGS as _,
            std::ptr::addr_of_mut!(req).cast::<libc::c_void>(),
        )
    };
    let result = if got == 0 {
        req.ifr_flags |= IFF_UP;
        // SAFETY: as above, for SIOCSIFFLAGS.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let set = unsafe {
            libc::ioctl(
                sock,
                libc::SIOCSIFFLAGS as _,
                std::ptr::addr_of_mut!(req).cast::<libc::c_void>(),
            )
        };
        if set == 0 {
            Ok(())
        } else {
            Err(last_err(b"pent: SIOCSIFFLAGS on lo failed\n"))
        }
    } else {
        Err(last_err(b"pent: SIOCGIFFLAGS on lo failed\n"))
    };
    // SAFETY: `sock` is a file descriptor that this function opened.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(sock) };
    result
}

/// Write the UID and GID maps for a new user namespace.
///
/// The maps are identity maps that the parent prepared: the real UID and GID
/// map to themselves. The sandboxed process thus has the real UID of the
/// user (not root, not 65534). Async-signal-safe.
///
/// # Errors
/// Returns the OS error of the first write that fails. A failure is fatal:
/// without the maps the child runs as the overflow UID 65534.
fn setup_userns_mappings(uid_map: &[u8], gid_map: &[u8]) -> std::io::Result<()> {
    // An unprivileged process must write "deny" to setgroups before gid_map.
    write_proc_file(c"/proc/self/setgroups", b"deny")
        .map_err(|_| last_err(b"pent: write /proc/self/setgroups failed\n"))?;
    write_proc_file(c"/proc/self/gid_map", gid_map)
        .map_err(|_| last_err(b"pent: write /proc/self/gid_map failed\n"))?;
    write_proc_file(c"/proc/self/uid_map", uid_map)
        .map_err(|_| last_err(b"pent: write /proc/self/uid_map failed\n"))?;
    Ok(())
}

/// Clear the inheritable capability set and make the process dumpable.
///
/// A binary with file capabilities (for example an old install with
/// `setcap`) has two problems with the user namespace setup:
///
/// 1. The process is not dumpable. Its `/proc/self` files belong to root,
///    so the writes to `uid_map` fail with EACCES. `PR_SET_DUMPABLE` fixes
///    this.
/// 2. Linux 5.11 and later refuse `unshare(CLONE_NEWUSER)` with a non-empty
///    inheritable set. `capset` clears it.
///
/// Async-signal-safe.
fn prepare_caps_for_userns() -> std::io::Result<()> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const CAP_V3: u32 = 0x2008_0522;

    // SAFETY: prctl with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(last_err(b"pent: prctl(PR_SET_DUMPABLE) failed\n"));
    }
    let mut hdr = CapHeader {
        version: CAP_V3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `hdr` and `data` have the layout that capget(2) expects for
    // version 3 (two data words) and are writable.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) } != 0 {
        return Err(last_err(b"pent: capget failed\n"));
    }
    if data.iter().all(|d| d.inheritable == 0) {
        return Ok(());
    }
    for d in &mut data {
        d.inheritable = 0;
    }
    // SAFETY: the same valid buffers, now read by capset(2).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) } != 0 {
        return Err(last_err(b"pent: capset failed\n"));
    }
    Ok(())
}

/// Mark all file descriptors from 3 up as close-on-exec, so that file
/// descriptors of the embedding program that are not `O_CLOEXEC` do not leak
/// into the child. The socket pairs and the ruleset stay usable until `exec`.
/// Async-signal-safe.
fn cloexec_inherited_fds() {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    // SAFETY: close_range(2) with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if ret == 0 {
        return;
    }
    // Fallback for kernels before 5.11 (only possible with `no_enforcement`,
    // because Landlock ABI v3 needs Linux 6.2).
    for fd in 3..4096 {
        // SAFETY: fcntl(2) on a number; EBADF for a closed number is harmless.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
}

// ── The supervisors of the PID namespace ───────────────────────────────────

/// The process that the supervisor of this process waits for. A signal
/// handler reaches only a static, so the PID lives here.
static SUPERVISED_PID: AtomicI32 = AtomicI32::new(0);

/// The signals that a supervisor passes on.
///
/// The terminal sends `SIGINT`, `SIGQUIT` and `SIGWINCH` to the whole
/// process group. A process group holds its members across a PID namespace,
/// so the command gets these signals directly and needs no relay. The other
/// signals come from `kill`, and pent sends them to the direct child.
const FORWARDED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGTERM, libc::SIGHUP, libc::SIGUSR1, libc::SIGUSR2];

/// Pass the signal to the supervised process. Async-signal-safe.
extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = SUPERVISED_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill(2) with integer arguments only.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::kill(pid, sig) };
    }
}

/// Install [`forward_signal`] for each signal of [`FORWARDED_SIGNALS`].
/// Async-signal-safe.
fn install_signal_forwarders() {
    for sig in FORWARDED_SIGNALS {
        // SAFETY: a zeroed `sigaction` is a valid, empty structure, and the
        // code below fills each field that `sigaction(2)` reads.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = forward_signal as *const () as usize;
        act.sa_flags = libc::SA_RESTART;
        // SAFETY: `act` is a valid, writable structure, and then a valid
        // structure that sigaction(2) reads.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::sigemptyset(&raw mut act.sa_mask);
            libc::sigaction(sig, &raw const act, std::ptr::null_mut());
        }
    }
}

/// Close every inherited descriptor above the standard three, except
/// `keep`.
///
/// A supervisor must not keep the error pipe of `Command::spawn` open: the
/// parent reads that pipe until every copy of it is closed, and it holds
/// the spawn until then. Async-signal-safe.
fn close_inherited_fds(keep: libc::c_int) {
    let ranges = [
        (3, keep.saturating_sub(1)),
        (keep.saturating_add(1), i32::MAX),
    ];
    let mut ok = true;
    for (first, last) in ranges {
        if first > last {
            continue;
        }
        // SAFETY: close_range(2) with integer arguments only.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::syscall(libc::SYS_close_range, first as u32, last as u32, 0u32) };
        ok = ok && ret == 0;
    }
    if ok {
        return;
    }
    for fd in 3..4096 {
        if fd == keep {
            continue;
        }
        // SAFETY: close(2) on a number; EBADF for a closed number is
        // harmless.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
    }
}

/// End this process like the wait status `status`. Async-signal-safe; it
/// never returns.
fn exit_like(status: libc::c_int) -> ! {
    if libc::WIFEXITED(status) {
        // SAFETY: _exit(2) with an integer argument.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        // SAFETY: a zeroed `sigaction` is a valid, empty structure. The
        // default action must apply, and the signal must not be blocked,
        // so that `raise` ends this process with the same reason.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&raw mut act.sa_mask);
            libc::sigaction(sig, &raw const act, std::ptr::null_mut());
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, sig);
            libc::sigprocmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
            libc::raise(sig);
            // `raise` returned, so the default action does not end this
            // process. Use the convention of the shell.
            libc::_exit(128_i32.saturating_add(sig));
        }
    }
    // SAFETY: _exit(2) with an integer argument.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::_exit(1) };
}

/// Wait for `pid`, pass the signals on to it, and reap every other child.
/// Returns the wait status of `pid`. Async-signal-safe.
fn wait_and_reap(pid: libc::pid_t) -> libc::c_int {
    SUPERVISED_PID.store(pid, Ordering::Relaxed);
    install_signal_forwarders();
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid(2) on the children of this process, with a
        // writable status.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let done = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if done == pid {
            return status;
        }
        if done < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // ECHILD: the supervised process is gone and left no status.
            write_stderr_static(b"pent: the sandbox supervisor lost the command\n");
            // SAFETY: _exit(2) with an integer argument.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::_exit(1) };
        }
    }
}

/// Read all of `buf` from `fd`. Returns the number of bytes.
/// Async-signal-safe.
fn read_all_fd(fd: libc::c_int, buf: &mut [u8]) -> usize {
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        // SAFETY: `rest` is a valid, writable slice of `rest.len()` bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::read(fd, rest.as_mut_ptr().cast(), rest.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        filled = filled.saturating_add(n.unsigned_abs());
    }
    filled
}

/// The supervisor that stays in the old PID namespace. It is the direct
/// child of pent, so its status is the status that pent reports.
///
/// PID 1 of the new namespace cannot end itself with a signal (the kernel
/// drops a signal with the default action for the init of a namespace), so
/// it sends the wait status of the command through `status_fd`, and this
/// supervisor ends itself with that status.
///
/// Async-signal-safe; it never returns.
fn supervise_outer(init: libc::pid_t, status_fd: libc::c_int) -> ! {
    let status = wait_and_reap(init);
    let mut buf = [0u8; 4];
    if read_all_fd(status_fd, &mut buf) == buf.len() {
        exit_like(libc::c_int::from_ne_bytes(buf));
    }
    exit_like(status)
}

/// What PID 1 of the new namespace does with a process that outlives the
/// command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Orphans {
    /// End it. PID 1 exits with the command, and the kernel then ends
    /// every other process of the namespace. `pent run` takes this: no
    /// background process of the sandbox outlives the command.
    End,
    /// Wait for it, at most [`ORPHAN_GRACE_STEPS`] steps. `pent watch`
    /// takes this: an orphan of the program must keep its events, and the
    /// recorder reports an event only while the task runs.
    Wait,
}

/// The length of one step of the wait for the orphans, in milliseconds.
const ORPHAN_STEP_MS: libc::c_long = 50;

/// The number of steps that PID 1 waits for the orphans in watch mode.
/// 100 steps of 50 milliseconds are five seconds, the same limit that the
/// CLI gives to the last events of a watch run.
const ORPHAN_GRACE_STEPS: u32 = 100;

/// Wait for the remaining children of this process, at most
/// `ORPHAN_GRACE_STEPS` steps. Async-signal-safe: `waitpid` and
/// `nanosleep` are both on the list.
fn wait_for_orphans() {
    let pause = libc::timespec {
        tv_sec: 0,
        tv_nsec: ORPHAN_STEP_MS.saturating_mul(1_000_000),
    };
    for _ in 0..ORPHAN_GRACE_STEPS {
        // SAFETY: waitpid(2) on the children of this process, with a null
        // status pointer.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let done = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if done < 0 {
            return; // ECHILD: no child is left.
        }
        if done > 0 {
            continue; // Reap the next one at once.
        }
        // SAFETY: nanosleep(2) with a valid timespec and no remainder.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::nanosleep(&raw const pause, std::ptr::null_mut()) };
    }
}

/// The supervisor that is PID 1 of the new PID namespace. It reaps the
/// orphans of the session. When it exits, the kernel ends every other
/// process of the namespace.
///
/// With [`Orphans::Wait`] it first gives the orphans their time, so that
/// the recorder of watch mode gets their events.
///
/// Async-signal-safe; it never returns.
fn supervise_init(command: libc::pid_t, status_fd: libc::c_int, orphans: Orphans) -> ! {
    let status = wait_and_reap(command);
    if orphans == Orphans::Wait {
        wait_for_orphans();
    }
    // The outer supervisor needs the real status; see `supervise_outer`.
    // Nothing can answer a failure here, and the exit code below still
    // carries the reason.
    let _ = write_all_fd(status_fd, &status.to_ne_bytes());
    exit_like(status)
}

/// Make the two supervisors of the new PID namespace. Only the command
/// returns from this function; each supervisor ends its process.
///
/// `unshare(CLONE_NEWPID)` does not move the caller, so the first child of
/// the caller is PID 1 of the new namespace. The command must not be that
/// PID 1: the kernel drops each signal that has the default action for the
/// init of a namespace, so `kill` and the terminal could not stop the
/// command. Thus pent forks twice:
///
/// 1. the stub, in the old namespace: it is the direct child of pent, and
///    it passes the status and the signals of PID 1;
/// 2. PID 1 of the new namespace: it reaps the orphans of the session and
///    passes the status and the signals of the command;
/// 3. the command, PID 2.
///
/// Each step gets `PR_SET_PDEATHSIG`, so the whole namespace ends when pent
/// ends. Async-signal-safe.
///
/// # Errors
/// Returns the OS error of `pipe2(2)`, of `fork(2)` or of `prctl(2)`.
fn fork_pid_namespace(orphans: Orphans) -> std::io::Result<()> {
    // The pipe that carries the wait status of the command from PID 1 of
    // the namespace to the stub; see `supervise_outer`.
    let mut pipe_fds = [-1 as libc::c_int; 2];
    // SAFETY: pipe2(2) writes two descriptors into a valid array.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(last_err(b"pent: the status pipe of the sandbox failed\n"));
    }
    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);
    // SAFETY: fork(2) has no preconditions. The child uses only
    // async-signal-safe calls.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let init = unsafe { libc::fork() };
    if init < 0 {
        return Err(last_err(b"pent: fork for the PID namespace failed\n"));
    }
    if init > 0 {
        close_inherited_fds(read_fd);
        supervise_outer(init, read_fd);
    }
    // SAFETY: prctl(2) with integer arguments only. `fork` clears the
    // parent-death signal, so each step sets it again.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(last_err(b"pent: prctl(PR_SET_PDEATHSIG) failed\n"));
    }
    // SAFETY: as above.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let command = unsafe { libc::fork() };
    if command < 0 {
        return Err(last_err(b"pent: fork of the command failed\n"));
    }
    if command > 0 {
        close_inherited_fds(write_fd);
        supervise_init(command, write_fd, orphans);
    }
    // The command keeps no end of the status pipe.
    // SAFETY: close(2) on descriptors that `pipe2` made.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
    // SAFETY: prctl(2) with integer arguments only.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(last_err(b"pent: prctl(PR_SET_PDEATHSIG) failed\n"));
    }
    Ok(())
}

/// Mount flags that a bind mount inherits and must keep on a remount.
///
/// A remount that drops a flag of a mount from a less privileged mount
/// namespace fails with EPERM. Async-signal-safe.
fn locked_mount_flags(path: &std::ffi::CStr) -> std::io::Result<libc::c_ulong> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `path` is NUL-terminated and `st` is writable. glibc
    // implements statvfs with the statfs system call and the ST_* flags
    // that the kernel returns; it does not allocate.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded, so the struct is initialized.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let st = unsafe { st.assume_init() };
    let f = st.f_flag;
    let pairs: [(libc::c_ulong, libc::c_ulong); 6] = [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ];
    Ok(pairs
        .iter()
        .filter(|(st_flag, _)| f & st_flag != 0)
        .fold(0, |acc, (_, ms)| acc | ms))
}

// ── Mount plan ─────────────────────────────────────────────────────────────

/// The access that a private bind gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindAccess {
    /// The mount keeps the access of the source.
    ReadWrite,
    /// A remount makes the mount read-only.
    ReadOnly,
}

/// What the child does when a private bind fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnFailure {
    /// The spawn fails.
    Stop,
    /// The child writes a message and continues.
    Warn,
}

/// What the child makes at the mount point of a private bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindKind {
    /// Make a directory and bind the source on it.
    Directory,
    /// Make an empty file and bind the source on it.
    File,
    /// Make an empty directory with this mode and bind nothing. This keeps
    /// `TMPDIR` and `XDG_RUNTIME_DIR` usable inside the private tmpfs.
    EmptyDirectory(libc::mode_t),
    /// Make the parent directories only. The program creates the path
    /// itself.
    ParentsOnly,
}

/// One tmpfs that covers a directory of the host.
#[derive(Debug)]
struct PrivateMount {
    /// The mount point.
    target: CString,
    /// The mount data (see [`PrivateDir::data`]).
    data: &'static CStr,
}

/// The modes that the child sets on a mount point and on the directories
/// above it, whatever the umask of the parent is.
#[derive(Debug, Clone, Copy)]
struct ForcedMode {
    /// The mode of each directory of [`PrivateBind::parents`].
    dir: libc::mode_t,
    /// The mode of the mount point itself.
    file: libc::mode_t,
}

/// One mount that the child makes after the private tmpfs mounts.
///
/// The child opens an `O_PATH` descriptor of the source **before** the tmpfs
/// mounts hide it, and binds from `/proc/self/fd/<n>` afterwards. This is the
/// method of bubblewrap.
#[derive(Debug)]
struct PrivateBind {
    /// The source of the mount.
    source: CString,
    /// The descriptor of the source. The parent only makes the slot; the
    /// child opens the descriptor and stores it here.
    source_fd: AtomicI32,
    /// The mount point.
    target: CString,
    /// The directories to make before the mount point, outermost first.
    parents: Vec<CString>,
    /// What the child makes at the mount point.
    kind: BindKind,
    /// The access that the mount gives.
    access: BindAccess,
    /// What the child does when the mount fails.
    on_failure: OnFailure,
    /// The modes that the child sets on the mount point and on the
    /// directories above it. `None` keeps the mode of `mkdir(2)` and of
    /// `open(2)`, which the umask can make narrower. Only the `resolv.conf`
    /// of the proxy sets this field.
    forced_mode: Option<ForcedMode>,
}

/// The private mounts that the child makes before Landlock applies.
#[derive(Debug, Default)]
struct MountPlan {
    /// Make the mount tree private (only in a new mount namespace).
    make_private: bool,
    /// Mount a new `proc` on `/proc`. This needs a new PID namespace, and
    /// it then shows only the processes of the sandbox.
    private_proc: bool,
    /// Empty tmpfs mounts over the directories of [`PRIVATE_DIRS`].
    private_dirs: Vec<PrivateMount>,
    /// The mounts that restore what the session needs inside the private
    /// tmpfs mounts, and the `resolv.conf` of the proxy.
    private_binds: Vec<PrivateBind>,
    /// Paths to bind-mount read-only onto themselves (`<workspace>/.pent`,
    /// and the write targets of the watch guard).
    readonly: Vec<CString>,
    /// Directories to hide with an empty tmpfs. Only a directory that no
    /// private tmpfs already hides is in this list.
    mask_dirs: Vec<CString>,
    /// Socket files to hide with a bind mount of `/dev/null`.
    mask_files: Vec<CString>,
    /// Directories that the watch guard hides with an empty, read-only
    /// tmpfs.
    guard_dirs: Vec<CString>,
    /// Files that the watch guard hides with a read-only bind mount of
    /// `/dev/null`. A write fails with EROFS, so that the program does not
    /// lose data without an error.
    guard_files: Vec<CString>,
}

fn to_cstring(path: &Path) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).ok()
}

/// Return true if the configuration names `mask` or a path inside it.
///
/// A grant on an ancestor (for example the traversal grant on `/`) does not
/// count: the user must name the hidden path itself.
#[must_use]
pub(crate) fn is_explicitly_allowed(mask: &Path, configured: &[PathBuf]) -> bool {
    configured.iter().any(|p| p.starts_with(mask))
}

/// Return all paths that the configuration names explicitly.
///
/// The Unix socket list is in the result: a socket that the profile names
/// must not get a mask of `/dev/null`, because a program reads the kind
/// of the file before it connects (finding CT-4 in
/// `docs/security/containment.md`).
fn configured_paths(config: &SandboxConfig) -> Vec<PathBuf> {
    let (traversal, read, execute, rw) = config.paths.expand_paths();
    let mut v: Vec<PathBuf> = traversal
        .into_iter()
        .chain(read)
        .chain(execute)
        .chain(rw)
        .map(|(p, _)| p)
        .collect();
    v.extend(config.mounts.iter().map(|m| m.path.clone()));
    v.extend(config.unix_sockets.iter().cloned());
    v.push(config.workspace.clone());
    v.push(config.data_dir.clone());
    v.push(config.cwd.clone());
    v
}

/// Return the paths that pent binds back into a private tmpfs.
///
/// The list holds each path that the configuration names itself: the read,
/// the execute and the read-write paths, each mount, the workspace, the data
/// directory and the working directory.
///
/// The traversal paths are **not** in the list. The CLI puts each parent
/// directory of a rule in the traversal list, so that the program can
/// resolve the path. A bind of such a parent brings the whole subtree of the
/// host back into the tmpfs, with each socket of the host in it (finding
/// NET-3 in `docs/security/network.md`). The plan makes the directories
/// above a bind inside the tmpfs instead (see [`mount_point_parents`]).
fn bind_back_paths(config: &SandboxConfig) -> Vec<PathBuf> {
    let (_traversal, read, execute, rw) = config.paths.expand_paths();
    let mut v: Vec<PathBuf> = read
        .into_iter()
        .chain(execute)
        .chain(rw)
        .map(|(p, _)| p)
        .collect();
    v.extend(config.mounts.iter().map(|m| m.path.clone()));
    // The Unix socket list is not here. A socket below a private
    // directory stays hidden, and the supervisor connects to it from the
    // host, where the tmpfs of the child does not apply.
    v.push(config.workspace.clone());
    v.push(config.data_dir.clone());
    v.push(config.cwd.clone());
    v
}

/// The plan for the private temporary and runtime directories of the child.
#[derive(Debug, Default)]
struct PrivatePlan {
    /// The tmpfs mounts that cover the directories of the host.
    mounts: Vec<PrivateMount>,
    /// The mounts that restore what the session needs inside them.
    binds: Vec<PrivateBind>,
    /// The directories that the tmpfs mounts cover.
    covered: Vec<PathBuf>,
    /// The paths that stay reachable inside the covered directories.
    visible: Vec<PathBuf>,
}

impl PrivatePlan {
    /// Return true when a tmpfs of the plan hides `path`.
    fn hides(&self, path: &Path) -> bool {
        self.covered.iter().any(|c| path.starts_with(c))
            && !self.visible.iter().any(|v| path.starts_with(v))
    }
}

/// Return the directories to make before the mount point `target`, from the
/// outermost to the innermost. The list stops below `root`: the tmpfs itself
/// gives the root.
fn mount_point_parents(target: &Path, root: &Path) -> Vec<CString> {
    let mut chain: Vec<&Path> = target
        .ancestors()
        .skip(1)
        .take_while(|p| *p != root)
        .collect();
    chain.reverse();
    chain.iter().filter_map(|p| to_cstring(p)).collect()
}

/// Plan the private temporary and runtime directories of the child.
///
/// Each directory of [`PRIVATE_DIRS`] gets an empty tmpfs. Pent binds back
/// only the paths that the session needs: the workspace, the data directory,
/// the working directory, each configured path and mount, each directory of
/// `PATH`, the system paths, and `extra` (the overlay mount points and the
/// write targets of the watch guard).
///
/// Pent binds the path that the configuration names, not a parent of it: a
/// file over a file and a directory over a directory. The directories above
/// the bind come from [`mount_point_parents`] and stay inside the tmpfs, so
/// a rule for one path below `/run` or `/tmp` does not bring the siblings of
/// the host back (see [`bind_back_paths`]).
///
/// `TMPDIR` and `XDG_RUNTIME_DIR` get an empty directory inside the tmpfs
/// when they point into a covered directory, so that a program that reads
/// them still finds a place to write. A `TMPDIR` outside the covered
/// directories stays as it is.
fn plan_private_dirs(
    config: &SandboxConfig,
    path_dirs: &[PathBuf],
    extra: &[PathBuf],
    uid: libc::uid_t,
) -> PrivatePlan {
    let mut plan = PrivatePlan::default();
    for dir in PRIVATE_DIRS {
        let path = Path::new(dir.path);
        let Ok(real) = std::fs::canonicalize(path) else {
            continue;
        };
        // A symbolic link (`/var/run` points to `/run`): the target of the
        // link gets its own tmpfs.
        if real != path || !real.is_dir() {
            continue;
        }
        if plan.covered.iter().any(|c| real.starts_with(c)) {
            continue;
        }
        let Some(target) = to_cstring(&real) else {
            continue;
        };
        plan.covered.push(real);
        plan.mounts.push(PrivateMount {
            target,
            data: dir.data,
        });
    }
    if plan.covered.is_empty() {
        return plan;
    }

    let mut keep: Vec<PathBuf> = bind_back_paths(config);
    keep.extend(path_dirs.iter().cloned());
    keep.extend(SYSTEM_PATHS.iter().chain(PRIVATE_KEEP).map(PathBuf::from));
    keep.extend(extra.iter().cloned());
    keep.retain(|p| {
        plan.covered
            .iter()
            .any(|c| p.starts_with(c) && p.as_path() != c.as_path())
    });
    keep.sort();
    keep.dedup();
    // One recursive bind carries a whole subtree, so pent binds only the
    // outermost path of each subtree.
    let outermost: Vec<PathBuf> = keep
        .iter()
        .filter(|p| !keep.iter().any(|q| q != *p && p.starts_with(q)))
        .cloned()
        .collect();
    for path in outermost {
        let Some(root) = plan.covered.iter().find(|c| path.starts_with(c)) else {
            continue;
        };
        let parents = mount_point_parents(&path, root);
        let kind = match std::fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => BindKind::Directory,
            Ok(_) => BindKind::File,
            // The path does not exist yet. The program makes it itself, so
            // pent only makes the directories above it.
            Err(_) => BindKind::ParentsOnly,
        };
        let Some(target) = to_cstring(&path) else {
            continue;
        };
        if kind != BindKind::ParentsOnly {
            plan.visible.push(path);
        }
        plan.binds.push(PrivateBind {
            source: target.clone(),
            source_fd: AtomicI32::new(-1),
            target,
            parents,
            kind,
            access: BindAccess::ReadWrite,
            on_failure: OnFailure::Stop,
            forced_mode: None,
        });
    }

    let mut empty: Vec<PathBuf> = vec![PathBuf::from(format!("/run/user/{uid}"))];
    empty.extend(
        ["XDG_RUNTIME_DIR", "TMPDIR"]
            .iter()
            .filter_map(|k| config.env.get(*k))
            .map(PathBuf::from),
    );
    for path in empty {
        let Some(root) = plan
            .covered
            .iter()
            .find(|c| path.starts_with(c) && path.as_path() != c.as_path())
        else {
            continue;
        };
        // A path that a bind already restores needs no empty directory.
        if !plan.hides(&path) {
            continue;
        }
        if plan
            .binds
            .iter()
            .any(|b| b.target.as_bytes() == path.as_os_str().as_encoded_bytes())
        {
            continue;
        }
        let Some(target) = to_cstring(&path) else {
            continue;
        };
        plan.binds.push(PrivateBind {
            source: target.clone(),
            source_fd: AtomicI32::new(-1),
            target,
            parents: mount_point_parents(&path, root),
            kind: BindKind::EmptyDirectory(0o700),
            access: BindAccess::ReadWrite,
            on_failure: OnFailure::Stop,
            forced_mode: None,
        });
    }
    plan
}

/// The path that the C library reads to find the resolver.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// The limit on the length of the symbolic link chain of [`RESOLV_CONF_PATH`].
///
/// A real host has one link (`/etc/resolv.conf` to
/// `/run/systemd/resolve/stub-resolv.conf`) or two. The limit stops a loop.
const RESOLV_LINK_LIMIT: usize = 8;

/// The mode of each directory that pent makes above the `resolv.conf` of the
/// child. Every program of the child must be able to walk through it.
const RESOLV_DIR_MODE: libc::mode_t = 0o755;

/// The mode of the mount point of the `resolv.conf` of the child. Every
/// program of the child must be able to read the file.
const RESOLV_FILE_MODE: libc::mode_t = 0o644;

/// Join the target of a symbolic link to the directory of the link and
/// remove each `.` and `..` component.
///
/// The function reads nothing from the file system. A `..` after the root
/// stays at the root, as the kernel also does.
fn join_link_target(link: &Path, target: &Path) -> PathBuf {
    use std::path::Component;
    let joined = match link.parent() {
        Some(dir) if target.is_relative() => dir.join(target),
        _ => target.to_path_buf(),
    };
    let mut out = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Return true when a private tmpfs of [`PRIVATE_DIRS`] covers `path`.
fn in_private_dir(path: &Path) -> bool {
    PRIVATE_DIRS
        .iter()
        .any(|dir| path.starts_with(Path::new(dir.path)))
}

/// Follow the symbolic link chain of `link` and return the path at which the
/// child must find its `resolv.conf`.
///
/// `read_link` gives the target of a symbolic link, or `None` when the path
/// is not a link. The parameter keeps the function free of the layout of the
/// host, so a test gives the layout of Ubuntu as data.
///
/// The function returns `None` in two cases:
///
/// - The chain is longer than [`RESOLV_LINK_LIMIT`] steps. A loop ends here.
/// - A link inside a private directory points out of every private
///   directory. Pent owns only the tmpfs of [`PRIVATE_DIRS`]; it must not
///   put the file of the proxy at a path of the host that it does not
///   control.
///
/// The caller then leaves `/etc/resolv.conf` as it is. The child has no
/// resolver and each name lookup fails, which is the closed state.
fn resolv_link_target(
    link: &Path,
    read_link: impl Fn(&Path) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let mut current = link.to_path_buf();
    let mut inside = in_private_dir(&current);
    for _ in 0..RESOLV_LINK_LIMIT {
        let Some(target) = read_link(&current) else {
            // The path is not a symbolic link: it is the end of the chain.
            return Some(current);
        };
        let next = join_link_target(&current, &target);
        let next_inside = in_private_dir(&next);
        if inside && !next_inside {
            return None;
        }
        inside = next_inside;
        current = next;
    }
    None
}

/// Return the path at which the child must find its `resolv.conf` on this
/// host, and `None` when pent cannot give the child a resolver.
///
/// Pent makes a mount point only inside a directory that it covers with a
/// tmpfs of its own. Outside such a directory the file must exist already:
/// pent does not write in the `/etc` of the host. A host with no
/// `/etc/resolv.conf` therefore keeps no resolver in the sandbox, and each
/// name lookup of the child fails. The function writes a warning in that
/// case, because the state must be a decision and not a surprise.
fn resolv_mount_point() -> Option<PathBuf> {
    let Some(target) = resolv_link_target(Path::new(RESOLV_CONF_PATH), |path| {
        std::fs::read_link(path).ok()
    }) else {
        tracing::warn!(
            "the symbolic link chain of {RESOLV_CONF_PATH} is too long or leaves the private \
             directories of pent: the child gets no resolver, and each name lookup fails"
        );
        return None;
    };
    if in_private_dir(&target) || target.exists() {
        return Some(target);
    }
    tracing::warn!(
        "{} does not exist, and pent does not write in the /etc of the host: the child gets \
         no resolver, and each name lookup fails",
        target.display()
    );
    None
}

/// Return the bind that puts the `resolv.conf` of the proxy at `target`.
///
/// `target` comes from [`resolv_mount_point`]: it is `/etc/resolv.conf` itself on
/// a host where that path is a plain file, and the target of the link on a
/// host with `systemd-resolved`, where `/etc/resolv.conf` points into
/// `/run`. A tmpfs of `covered` then hides the target, so the child first
/// makes the directory chain and an empty file inside the tmpfs, and binds
/// the file of pent onto it. A directory and a mount point that the child
/// makes itself get the mode [`RESOLV_DIR_MODE`] and the mode
/// [`RESOLV_FILE_MODE`], whatever the umask of the parent is, so that every
/// program of the child can read the file. A path that is there already
/// belongs to the host and keeps its mode.
fn resolv_bind(source: &Path, target: &Path, covered: &[PathBuf]) -> Option<PrivateBind> {
    let parents = covered
        .iter()
        .find(|c| target.starts_with(c))
        .map(|root| mount_point_parents(target, root))
        .unwrap_or_default();
    Some(PrivateBind {
        source: to_cstring(source)?,
        source_fd: AtomicI32::new(-1),
        target: to_cstring(target)?,
        parents,
        kind: BindKind::File,
        access: BindAccess::ReadOnly,
        on_failure: OnFailure::Warn,
        forced_mode: Some(ForcedMode {
            dir: RESOLV_DIR_MODE,
            file: RESOLV_FILE_MODE,
        }),
    })
}

/// Compute the directories and socket files to hide.
fn mask_targets(config: &SandboxConfig, uid: libc::uid_t) -> (Vec<PathBuf>, Vec<PathBuf>) {
    use std::os::unix::fs::FileTypeExt;
    let configured = configured_paths(config);
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut runtime_dirs = vec![PathBuf::from(format!("/run/user/{uid}"))];
    if let Some(xdg) = config.env.get("XDG_RUNTIME_DIR") {
        runtime_dirs.push(PathBuf::from(xdg));
    }
    for d in runtime_dirs {
        let Ok(real) = std::fs::canonicalize(&d) else {
            continue;
        };
        if real != Path::new("/")
            && real.is_dir()
            && !is_explicitly_allowed(&d, &configured)
            && !is_explicitly_allowed(&real, &configured)
            && !dirs.contains(&real)
        {
            dirs.push(real);
        }
    }
    let mut files: Vec<PathBuf> = Vec::new();
    let resolvers: &[&str] = if config.network == NetworkMode::Unrestricted {
        &[]
    } else {
        RESOLVER_SOCKETS
    };
    let candidates: Vec<PathBuf> = ESCAPE_SOCKETS
        .iter()
        .chain(resolvers)
        .map(PathBuf::from)
        .chain(home_agent_sockets(config))
        .collect();
    for p in &candidates {
        let Ok(real) = std::fs::canonicalize(p) else {
            continue;
        };
        let is_socket = std::fs::symlink_metadata(&real).is_ok_and(|m| m.file_type().is_socket());
        if is_socket
            && !is_explicitly_allowed(p, &configured)
            && !is_explicitly_allowed(&real, &configured)
            && !dirs.iter().any(|d| real.starts_with(d))
            && !files.contains(&real)
        {
            files.push(real);
        }
    }
    (dirs, files)
}

/// Return the home directory of the child.
fn child_home(config: &SandboxConfig) -> Option<PathBuf> {
    config
        .env
        .get("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .filter(|p| p.is_absolute())
}

/// Return the agent sockets of [`HOME_AGENT_SOCKETS`] that exist in the home
/// directory of the child.
fn home_agent_sockets(config: &SandboxConfig) -> Vec<PathBuf> {
    let Some(home) = child_home(config) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (dir, prefix) in HOME_AGENT_SOCKETS {
        let Ok(entries) = std::fs::read_dir(home.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(prefix) {
                found.push(entry.path());
            }
        }
    }
    found
}

/// The length of the longest `/proc/self/fd/<n>` path.
const FD_PATH_LEN: usize = 32;

/// Write `/proc/self/fd/<fd>` into `buf` and return it.
///
/// A bind mount of a source that a tmpfs now hides goes through this path.
/// Async-signal-safe: the function makes no allocation.
fn fd_path(fd: libc::c_int, buf: &mut [u8; FD_PATH_LEN]) -> Option<&CStr> {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    let mut value = usize::try_from(fd).ok()?;
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    loop {
        let digit = u8::try_from(value % 10).ok()?;
        *digits.get_mut(count)? = b'0' + digit;
        count = count.checked_add(1)?;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let end = PREFIX.len().checked_add(count)?;
    buf.get_mut(..PREFIX.len())?.copy_from_slice(PREFIX);
    for (slot, digit) in buf
        .get_mut(PREFIX.len()..end)?
        .iter_mut()
        .zip(digits.iter().take(count).rev())
    {
        *slot = *digit;
    }
    *buf.get_mut(end)? = 0;
    CStr::from_bytes_with_nul(buf.get(..end.checked_add(1)?)?).ok()
}

/// Where a mount point comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountPoint {
    /// The child made the path itself, inside a private tmpfs.
    Made,
    /// The path was there already. It belongs to the host, so the child
    /// does not change its mode.
    Found,
}

/// Make the directory `path` with `mode`. A directory that exists already is
/// not an error. Async-signal-safe.
///
/// # Errors
/// Returns the OS error of `mkdir(2)`.
fn mkdir_if_missing(path: &CStr, mode: libc::mode_t) -> std::io::Result<MountPoint> {
    // SAFETY: mkdir(2) with a NUL-terminated string that the parent
    // prepared.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::mkdir(path.as_ptr(), mode) } == 0 {
        return Ok(MountPoint::Made);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        return Ok(MountPoint::Found);
    }
    write_stderr_static(b"pent: cannot make a directory for a private mount\n");
    Err(err)
}

/// Set the mode of `path`. Async-signal-safe.
///
/// `mkdir(2)` and `open(2)` take the umask of the process away from the mode
/// of a new file, so a mount point that every program of the child must
/// reach needs this call too. The caller uses it only on a path that the
/// child made itself: the mode of a path of the host stays as it is.
///
/// # Errors
/// Returns the OS error of `chmod(2)`.
fn chmod_path(path: &CStr, mode: libc::mode_t) -> std::io::Result<()> {
    // SAFETY: chmod(2) with a NUL-terminated string that the parent
    // prepared.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::chmod(path.as_ptr(), mode) } == 0 {
        return Ok(());
    }
    Err(last_err(
        b"pent: cannot set the mode of a private mount point\n",
    ))
}

/// Make an empty file at `path`. A file that exists already is not an error.
/// Async-signal-safe.
///
/// # Errors
/// Returns the OS error of `open(2)`.
fn create_if_missing(path: &CStr) -> std::io::Result<MountPoint> {
    // SAFETY: open(2) with a NUL-terminated string that the parent
    // prepared. O_EXCL keeps an existing file as it is.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            libc::c_int::from(0o600),
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` is the descriptor that this function opened.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
        return Ok(MountPoint::Made);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        return Ok(MountPoint::Found);
    }
    write_stderr_static(b"pent: cannot make a file for a private mount\n");
    Err(err)
}

impl PrivateBind {
    /// Open an `O_PATH` descriptor of the source. The child calls this
    /// before the tmpfs mounts hide the source. Async-signal-safe.
    fn open_source(&self) {
        if matches!(
            self.kind,
            BindKind::EmptyDirectory(_) | BindKind::ParentsOnly
        ) {
            return;
        }
        // SAFETY: open(2) with a NUL-terminated string that the parent
        // prepared. O_PATH opens the inode only; it reads nothing.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let fd = unsafe { libc::open(self.source.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        self.source_fd.store(fd, Ordering::Relaxed);
    }

    /// Make the mount point and the mount. Async-signal-safe.
    ///
    /// # Errors
    /// Returns the OS error of the directory, the file or the mount.
    fn apply(&self) -> std::io::Result<()> {
        for parent in &self.parents {
            let point = mkdir_if_missing(parent, 0o755)?;
            // The child sets the mode only on a directory that it made in
            // its own tmpfs. A directory of the host keeps its mode, and
            // the child often cannot change it anyway.
            if let (Some(mode), MountPoint::Made) = (self.forced_mode, point) {
                chmod_path(parent, mode.dir)?;
            }
        }
        let point = match self.kind {
            BindKind::ParentsOnly => return Ok(()),
            BindKind::EmptyDirectory(mode) => {
                mkdir_if_missing(&self.target, mode)?;
                return Ok(());
            }
            BindKind::Directory => mkdir_if_missing(&self.target, 0o755)?,
            BindKind::File => create_if_missing(&self.target)?,
        };
        if let (Some(mode), MountPoint::Made) = (self.forced_mode, point) {
            chmod_path(&self.target, mode.file)?;
        }
        let mut buf = [0u8; FD_PATH_LEN];
        let Some(source) = fd_path(self.source_fd.load(Ordering::Relaxed), &mut buf) else {
            write_stderr_static(b"pent: a private mount source is not open\n");
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        };
        if self.access == BindAccess::ReadOnly {
            return bind_readonly(source, &self.target, 0);
        }
        // SAFETY: mount(2) with NUL-terminated strings. The source is the
        // descriptor that `open_source` opened.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::mount(
                source.as_ptr(),
                self.target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(last_err(b"pent: a private bind mount failed\n"));
        }
        Ok(())
    }
}

impl MountPlan {
    /// Open an `O_PATH` descriptor of each private bind source, before the
    /// tmpfs mounts hide them. Async-signal-safe.
    fn open_private_sources(&self) {
        for bind in &self.private_binds {
            bind.open_source();
        }
    }

    /// Cover each private directory with an empty tmpfs, then make the
    /// mounts that restore what the session needs. Async-signal-safe.
    ///
    /// # Errors
    /// A failure of a tmpfs mount is fatal, and so is a failure of a bind
    /// with [`OnFailure::Stop`].
    fn apply_private_dirs(&self) -> std::io::Result<()> {
        for mount in &self.private_dirs {
            // SAFETY: mount(2) with NUL-terminated strings that the parent
            // prepared.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    mount.target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    mount.data.as_ptr().cast(),
                )
            };
            if ret != 0 {
                return Err(last_err(
                    b"pent: cannot make a private temporary directory\n",
                ));
            }
        }
        for bind in &self.private_binds {
            if let Err(err) = bind.apply() {
                match bind.on_failure {
                    OnFailure::Stop => return Err(err),
                    OnFailure::Warn => {
                        write_stderr_static(b"pent: an optional private mount failed\n");
                    }
                }
            }
        }
        Ok(())
    }

    /// Make the private mounts. Async-signal-safe.
    ///
    /// # Errors
    /// A failure to make the tree private, to make a path read-only or to
    /// hide a path is fatal. A failure of the `resolv.conf` mount is only
    /// reported.
    fn apply(&self) -> std::io::Result<()> {
        if !self.make_private {
            return Ok(());
        }
        // The sources must be open before a tmpfs hides them.
        self.open_private_sources();
        // After unshare(CLONE_NEWNS) in a user namespace, inherited mounts
        // are slaves. Make the tree private before new mounts, so that no
        // mount propagates to the host. This must come after the overlayfs
        // mounts: a private tree before overlayfs gives EACCES on some
        // kernels.
        // SAFETY: mount(2) with static NUL-terminated strings.
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
            return Err(last_err(b"pent: mount --make-rprivate / failed\n"));
        }

        if self.private_proc {
            // A new `proc` shows only the processes of the PID namespace of
            // the process that mounts it. The mount comes before the
            // private directories: their bind mounts go through
            // `/proc/self/fd`.
            // SAFETY: mount(2) with static NUL-terminated strings.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"proc".as_ptr(),
                    c"/proc".as_ptr(),
                    c"proc".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: cannot mount a private /proc\n"));
            }
        }

        // The private temporary and runtime directories, and the mounts
        // that restore what the session needs in them (the `resolv.conf` of
        // the proxy among them).
        self.apply_private_dirs()?;

        for path in &self.readonly {
            bind_readonly(path, path, libc::MS_REC)?;
        }

        for dir in &self.mask_dirs {
            // SAFETY: mount(2) with NUL-terminated strings.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    dir.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    c"size=16k,mode=0700".as_ptr().cast(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: cannot hide a directory with a tmpfs\n"));
            }
        }

        for file in &self.mask_files {
            // SAFETY: mount(2) with NUL-terminated strings.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"/dev/null".as_ptr(),
                    file.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: cannot hide a container socket\n"));
            }
        }

        // The watch guard. The read-only bind mounts above come first, so a
        // mask can be on a path below a read-only directory.
        for dir in &self.guard_dirs {
            // SAFETY: mount(2) with NUL-terminated strings.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    dir.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    c"size=4k,mode=0700".as_ptr().cast(),
                )
            };
            if ret != 0 {
                return Err(last_err(b"pent: the guard cannot hide a directory\n"));
            }
        }
        for file in &self.guard_files {
            bind_readonly(c"/dev/null", file, 0)?;
        }
        Ok(())
    }
}

/// Bind-mount `src` on `dst` and make the new mount read-only. `extra` adds
/// flags to the bind (for example `MS_REC`). Async-signal-safe.
///
/// # Errors
/// Returns the OS error of the mount or of the remount.
fn bind_readonly(
    src: &std::ffi::CStr,
    dst: &std::ffi::CStr,
    extra: libc::c_ulong,
) -> std::io::Result<()> {
    // SAFETY: mount(2) with NUL-terminated strings that the parent prepared.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | extra,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_err(b"pent: a read-only bind mount failed\n"));
    }
    let locked =
        locked_mount_flags(dst).map_err(|_| last_err(b"pent: statfs of a bind mount failed\n"))?;
    // SAFETY: as above.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_err(b"pent: a read-only remount failed\n"));
    }
    Ok(())
}

/// Everything that the `pre_exec` hook needs, prepared before `fork`.
struct ChildPlan {
    parent_pid: libc::pid_t,
    unshare_flags: libc::c_int,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    /// `ProxyOnly`: make the proxy listeners and send them to the parent.
    proxy_sockets: Option<crate::linux_proxynet::ProxySocketsChild>,
    overlays: Vec<super::linux_overlayfs::OverlayMount>,
    accessible: HashSet<PathBuf>,
    mounts: MountPlan,
    cwd: Option<CString>,
    bring_up_lo: bool,
    /// Set `PR_SET_NO_NEW_PRIVS` and install the TIOCSTI filter.
    no_new_privs: bool,
    /// What PID 1 of the new namespace does with an orphan of the command.
    orphans: Orphans,
    /// `None` when enforcement is off (`--no-sandbox`) and in watch mode.
    ruleset: Option<PreparedRuleset>,
    /// The seccomp recorder (watch mode and `--trace`).
    recorder: Option<crate::linux_watch::RecorderChild>,
}

impl ChildPlan {
    /// The body of the `pre_exec` hook.
    ///
    /// Order matters:
    /// 1. Parent-death signal and close-on-exec for inherited fds.
    /// 2. All namespace work while `/proc/self` is still writable: unshare,
    ///    UID/GID maps, overlay and private mounts, loopback, and the proxy
    ///    listeners (the child still has all capabilities in its user
    ///    namespace).
    /// 3. `PR_SET_NO_NEW_PRIVS`, the seccomp filter and Landlock.
    /// 4. The seccomp filter of the recorder as the last step: after it, the
    ///    supervisor in the parent must answer each recorded system call.
    fn run(&self) -> std::io::Result<()> {
        // SAFETY: prctl with integer arguments only. PDEATHSIG fires when the
        // *thread* that forked exits, so `spawn_sandboxed` must run on a
        // thread that lives as long as the child (see its documentation).
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(last_err(b"pent: prctl(PR_SET_PDEATHSIG) failed\n"));
        }
        // The parent can exit before the prctl call; then no signal comes.
        // SAFETY: getppid has no preconditions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::getppid() } != self.parent_pid {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        cloexec_inherited_fds();

        if self.unshare_flags != 0 {
            if self.unshare_flags & libc::CLONE_NEWUSER != 0 {
                prepare_caps_for_userns()?;
            }
            // SAFETY: unshare(2) with integer flags.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::unshare(self.unshare_flags) } != 0 {
                return Err(last_err(b"pent: unshare failed\n"));
            }
            if self.unshare_flags & libc::CLONE_NEWUSER != 0 {
                setup_userns_mappings(&self.uid_map, &self.gid_map)?;
            }
            if self.unshare_flags & libc::CLONE_NEWPID != 0 {
                // Only the command returns here; see `fork_pid_namespace`.
                fork_pid_namespace(self.orphans)?;
            }
        }

        if !self.overlays.is_empty() {
            // These helpers live in linux_overlayfs.rs. They create the
            // upper/work directories inside the user namespace (doing so in
            // the parent gives EACCES on the overlay mount with a btrfs
            // lower layer) and mount the overlays.
            super::linux_overlayfs::setup_overlay_dirs(&self.overlays, &self.accessible)?;
            // SAFETY: we are in the post-fork child, after
            // unshare(CLONE_NEWUSER | CLONE_NEWNS) and the UID/GID maps.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { super::linux_overlayfs::mount_overlays(&self.overlays) }?;
        }

        self.mounts.apply()?;

        // Re-chdir after the mounts: std calls chdir() before pre_exec hooks,
        // so the CWD can point to an inode under a new mount. Landlock rules
        // bind to the inodes that the new mounts show.
        if let Some(cwd) = &self.cwd {
            // SAFETY: `cwd` is a NUL-terminated string that the parent prepared.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
                return Err(last_err(b"pent: chdir to the working directory failed\n"));
            }
        }

        if self.bring_up_lo {
            bring_up_loopback()?;
        }
        if let Some(proxy) = self.proxy_sockets {
            // SAFETY: we are in the pre_exec hook, in the new network
            // namespace, and `lo` is up.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { proxy.create_and_send() }
                .map_err(|_| last_err(b"pent: cannot make the proxy listeners\n"))?;
        }

        if self.no_new_privs {
            // SAFETY: prctl with integer arguments only.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(last_err(b"pent: prctl(PR_SET_NO_NEW_PRIVS) failed\n"));
            }
            // SAFETY: we are in the pre_exec hook and NO_NEW_PRIVS is set.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { crate::linux_landlock::install_tiocsti_filter() }
                .map_err(|_| last_err(b"pent: seccomp filter failed\n"))?;
        }
        if let Some(ruleset) = &self.ruleset {
            // SAFETY: we are in the pre_exec hook and NO_NEW_PRIVS is set;
            // the function uses only raw system calls on prepared data.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { ruleset.apply_in_child() }
                .map_err(|_| last_err(b"pent: Landlock restriction failed\n"))?;
        }
        if let Some(recorder) = &self.recorder {
            // SAFETY: we are in the pre_exec hook and NO_NEW_PRIVS is set;
            // the function uses only raw system calls on prepared data.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { recorder.install_in_child() }
                .map_err(|_| last_err(b"pent: the seccomp recorder failed\n"))?;
        }
        Ok(())
    }
}

/// Add the proxy variables to the environment of the child.
fn proxy_env(
    env: &std::collections::HashMap<String, String>,
    addr: std::net::SocketAddr,
) -> std::collections::HashMap<String, String> {
    let http_url = format!("http://{addr}");
    // socks5h = hostname resolved by the proxy, so the sandboxed process
    // never calls getaddrinfo for external hosts — DNS stays on the proxy side.
    let socks_url = format!("socks5h://{addr}");
    let no_proxy = "localhost,127.0.0.1,::1";
    let mut e = env.clone();
    e.insert("HTTP_PROXY".to_string(), http_url.clone());
    e.insert("HTTPS_PROXY".to_string(), http_url.clone());
    e.insert("http_proxy".to_string(), http_url.clone());
    e.insert("https_proxy".to_string(), http_url);
    e.insert("ALL_PROXY".to_string(), socks_url.clone());
    e.insert("all_proxy".to_string(), socks_url.clone());
    e.insert("GRPC_PROXY".to_string(), socks_url.clone());
    e.insert("grpc_proxy".to_string(), socks_url);
    e.insert("NO_PROXY".to_string(), no_proxy.to_string());
    e.insert("no_proxy".to_string(), no_proxy.to_string());
    // Route git-over-SSH through the SOCKS5 proxy (nc -X 5 = SOCKS5).
    e.insert(
        "GIT_SSH_COMMAND".to_string(),
        format!("ssh -o ProxyCommand='nc -X 5 -x {addr} %h %p'"),
    );
    // Signal to the sandboxed process that it is running inside a proxy sandbox.
    // Claude Code checks this flag to activate its own proxy-aware networking.
    e.insert("SANDBOX_RUNTIME".to_string(), "1".to_string());
    e
}

/// Spawn command with Landlock sandbox using `pre_exec`.
///
/// For write-listed file paths, overlayfs is mounted over their parent directories
/// inside the child's mount namespace so that atomic writes (rename-based) go to
/// the overlay upper layer. An inotify watcher in the parent flushes completed
/// writes back to the real file inodes in-place, preserving the inodes that
/// Landlock rules are bound to.
///
/// The child gets `PR_SET_PDEATHSIG(SIGKILL)`. Call this function on a thread
/// that lives as long as the child: the signal fires when the forking thread
/// exits.
///
/// # Returns
/// `(child_handle, overlay_handle, proxy_listeners)` — `overlay_handle` is `Some`
/// when overlayfs is in use; pass it to [`super::linux_overlayfs::teardown`]
/// after the child exits.
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock unavailable
/// * `NetworkSetupFailed` - If the proxy listeners do not arrive
/// * `SpawnFailed` - If spawn fails
///
/// Only the tests use this form; the crate calls [`spawn_linux`].
#[cfg(test)]
pub fn spawn_with_landlock(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
) -> Result<
    (
        std::process::Child,
        Option<super::linux_overlayfs::OverlayHandle>,
        Option<super::linux_proxynet::ProxyListeners>,
    ),
    SandboxError,
> {
    let spawned = spawn_linux(config, cmd, args, env, path_dirs, SpawnMode::Sandbox)?;
    Ok((spawned.child, spawned.overlay, spawned.proxy_listeners))
}

/// The kind of a Linux spawn.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SpawnMode<'a> {
    /// The sandbox: Landlock (unless `no_enforcement`), the overlay and the
    /// masks. The recorder runs next to it when `config.record_events` is
    /// set.
    Sandbox,
    /// Watch mode: no Landlock, no overlay and no masks. The child gets the
    /// mounts of the watch guard, and the recorder always runs.
    Watch {
        /// The mounts of the watch guard.
        guard: &'a crate::linux_watch::GuardPlan,
        /// The Unix socket paths of the profile. Watch mode does not
        /// enforce them; it marks each connection with the decision that
        /// `pent run` would make.
        unix_sockets: &'a [PathBuf],
    },
}

/// The result of [`spawn_linux`].
pub(crate) struct Spawned {
    /// The child process.
    pub child: std::process::Child,
    /// The overlay handle (only with enforcement and write-listed files).
    pub overlay: Option<super::linux_overlayfs::OverlayHandle>,
    /// The proxy listeners that the child made for `ProxyOnly`.
    pub proxy_listeners: Option<super::linux_proxynet::ProxyListeners>,
    /// The events of the recorder, if it runs.
    pub events: Option<std::sync::mpsc::Receiver<pent_profile::WatchEvent>>,
}

/// Spawn `cmd` for the sandbox or for watch mode (see [`SpawnMode`]).
///
/// The child gets `PR_SET_PDEATHSIG(SIGKILL)`. Call this function on a thread
/// that lives as long as the child.
///
/// # Errors
/// * `SandboxUnavailable` - If Landlock is unavailable (sandbox mode)
/// * `NetworkSetupFailed` - If the proxy listeners do not arrive
/// * `SpawnFailed` - If the spawn or the recorder setup fails
#[allow(clippy::too_many_lines)]
pub(crate) fn spawn_linux(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
    env: &std::collections::HashMap<String, String>,
    path_dirs: &[PathBuf],
    mode: SpawnMode<'_>,
) -> Result<Spawned, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let (guard, unix_sockets) = match mode {
        SpawnMode::Sandbox => (None, config.unix_sockets.as_slice()),
        SpawnMode::Watch {
            guard,
            unix_sockets,
        } => (Some(guard), unix_sockets),
    };
    let watch = guard.is_some();
    let enforce = !watch && !config.no_enforcement;
    let record = watch || config.record_events;

    // Identify write-listed file paths (as opposed to directories) and prepare
    // overlayfs staging directories for them. Directories use regular Landlock
    // write rules; files get inode-stable access via the overlayfs + inotify path.
    let (_, read_expanded, execute_expanded, rw_expanded) = config.paths.expand_paths();
    let overlay_file_paths: Vec<PathBuf> = rw_expanded
        .iter()
        .filter_map(|(path, _)| {
            // Include paths that are files, or don't exist yet but whose parent
            // directory exists (will be created as a file on first write).
            if path.is_file() || (!path.exists() && path.parent().is_some_and(Path::is_dir)) {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    let write_set: HashSet<PathBuf> = overlay_file_paths.iter().cloned().collect();

    // Directory-type read_write entries: all files created or modified inside
    // these directories during the session should be flushed back to the real FS.
    // Include paths that are directories AND paths that don't exist yet but
    // whose parent does (they may be created as directories in the sandbox).
    let mut rw_dirs: HashSet<PathBuf> = rw_expanded
        .iter()
        .filter_map(|(path, _)| {
            if path.is_dir()
                || (!path.is_file() && !path.exists() && path.parent().is_some_and(Path::is_dir))
            {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    // The workspace and data_dir are always flushed back: they may fall inside
    // an overlayfs mount (e.g. the home-dir overlay).
    rw_dirs.insert(config.workspace.clone());
    rw_dirs.insert(config.data_dir.clone());

    // Build the set of paths the sandboxed process is allowed to read.
    // Traversal-only paths are intentionally excluded (ReadDir but not ReadFile).
    let mut accessible: HashSet<PathBuf> = HashSet::new();
    for (p, _) in read_expanded
        .iter()
        .chain(&execute_expanded)
        .chain(&rw_expanded)
    {
        accessible.insert(p.clone());
    }
    accessible.extend(write_set.iter().cloned());
    accessible.extend(compute_accessible_set(config, path_dirs));
    // A profile entry can name a symbolic link. The overlay shows only
    // the paths of this set, and Landlock binds a rule to an inode, so an
    // entry that names a link needs the file that the link reaches too;
    // without it the entry gives access to nothing (DIFF-2). The messages
    // keep the path as the user wrote it.
    let resolved: Vec<PathBuf> = accessible
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok().filter(|real| real != p))
        .collect();
    accessible.extend(resolved);

    let home_dir: PathBuf = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| config.workspace.clone());

    let pid = std::process::id();
    let overlay_mounts = if enforce {
        super::linux_overlayfs::prepare_overlay_dirs(&accessible, &home_dir, pid)?
    } else {
        Vec::new()
    };
    // Teardown must wait for orphaned session processes before the final
    // flush. As a child subreaper, pent gets them instead of init.
    if !overlay_mounts.is_empty() {
        if let Err(e) = super::linux_overlayfs::enable_child_subreaper() {
            tracing::warn!("cannot become a child subreaper: {e}");
        }
    }

    let overlay_dirs: HashSet<PathBuf> =
        overlay_mounts.iter().map(|m| m.real_dir.clone()).collect();

    // ProxyOnly: the child makes the proxy listeners in its network namespace
    // and sends them over a socket pair. It resolves names through the proxy
    // DNS on 127.0.0.1:53.
    let is_proxy = matches!(config.network, NetworkMode::ProxyOnly { .. });
    let proxy_sockets = if is_proxy {
        Some(super::linux_proxynet::ProxySocketsSetup::new()?)
    } else {
        None
    };
    // The `resolv.conf` of the proxy, and the path at which the child must
    // find it. The parent reads the symbolic link chain of
    // `/etc/resolv.conf` here, before the tmpfs of the child hides the
    // target of the link. The Landlock rules need the path too, so this
    // comes before the ruleset.
    let resolv_src: Option<PathBuf> = if is_proxy {
        Some(super::linux_proxynet::resolv_conf()?)
    } else {
        None
    };
    let resolv_dst: Option<PathBuf> = if is_proxy { resolv_mount_point() } else { None };

    // Landlock ruleset: created in the parent, rules applied in the child.
    let ruleset = if enforce {
        let mut rs = PreparedRuleset::create()?;
        add_ruleset_rules(
            &mut rs,
            config,
            path_dirs,
            &write_set,
            &overlay_dirs,
            resolv_dst.as_deref(),
        );
        Some(rs)
    } else {
        None
    };

    // Namespaces.
    let net_flag = match config.network {
        NetworkMode::Unrestricted => 0,
        _ => libc::CLONE_NEWNET,
    };
    // A new PID namespace hides the processes of the host, so the child
    // cannot read `/proc/<pid>/cmdline` of another process of the user.
    // Watch mode takes it too: the seccomp filter goes to each descendant,
    // and `SECCOMP_IOCTL_NOTIF_RECV` names the task in the namespace of
    // the reader, so an orphan that PID 1 of the sandbox adopts keeps its
    // events. Only the end differs; see `Orphans`.
    //
    // The namespace needs the private `proc` mount: a child in a new PID
    // namespace with the `/proc` of the host sees the PIDs of another
    // namespace, which confuses each tool that reads it. Thus the two go
    // together, and the probe answers before the `unshare`. In a container
    // the kernel refuses the mount, and pent then runs the command without
    // the protection and names what the command can see; see
    // [`ProcIsolation`].
    let pid_flag = pid_namespace_flag(
        if enforce || watch {
            PidNamespace::Wanted
        } else {
            PidNamespace::NotWanted
        },
        proc_isolation(),
    );
    let orphans = if watch { Orphans::Wait } else { Orphans::End };
    let unshare_flags = if enforce || watch {
        libc::CLONE_NEWUSER | libc::CLONE_NEWNS | net_flag | pid_flag
    } else if net_flag != 0 {
        let ns = if is_proxy { libc::CLONE_NEWNS } else { 0 };
        libc::CLONE_NEWUSER | net_flag | ns
    } else {
        0
    };
    let has_mntns = unshare_flags & libc::CLONE_NEWNS != 0;

    // SAFETY: getuid/getgid have no preconditions.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    let mut mounts = MountPlan {
        make_private: has_mntns,
        private_proc: pid_flag != 0,
        ..MountPlan::default()
    };
    // The private temporary and runtime directories. The child keeps the
    // overlay mount points and the write targets of the guard, because a
    // mount needs a target that exists.
    let mut keep_private: Vec<PathBuf> =
        overlay_mounts.iter().map(|m| m.real_dir.clone()).collect();
    if let Some(plan) = guard {
        keep_private.extend(plan.ro_binds.iter().cloned());
    }
    let mut private = if enforce || watch {
        plan_private_dirs(config, path_dirs, &keep_private, uid)
    } else {
        PrivatePlan::default()
    };
    mounts.private_dirs = std::mem::take(&mut private.mounts);
    mounts.private_binds = std::mem::take(&mut private.binds);
    if let (Some(src), Some(dst)) = (&resolv_src, &resolv_dst) {
        // The mount is read-only: the file is shared with other pent
        // processes.
        mounts
            .private_binds
            .extend(resolv_bind(src, dst, &private.covered));
    }
    // The masks also tell the recorder which sockets the policy hides. A
    // path that a private tmpfs already hides needs no mask, and a mask on
    // a path that the tmpfs removed would fail.
    let (mut mask_dirs, mask_files) = mask_targets(config, uid);
    // The overlay staging root holds the stub layers that hide the files
    // which are not on the allowlist. If the child deletes a whiteout
    // there, the hidden file appears. A private tmpfs over `/tmp` or over
    // the runtime directory already covers the staging root; the mask is
    // for a host that has neither.
    for staging_root in overlay_mounts.iter().filter_map(|m| m.base_dir.parent()) {
        if !mask_dirs.iter().any(|d| staging_root.starts_with(d)) {
            mask_dirs.push(staging_root.to_path_buf());
        }
    }
    let mask_dirs: Vec<PathBuf> = mask_dirs
        .into_iter()
        .filter(|p| !private.hides(p))
        .collect();
    let mask_files: Vec<PathBuf> = mask_files
        .into_iter()
        .filter(|p| !private.hides(p))
        .collect();
    if let Some(plan) = guard {
        mounts.readonly.extend(
            plan.ro_binds
                .iter()
                .filter(|p| !private.hides(p))
                .filter_map(|p| to_cstring(p)),
        );
        mounts.guard_dirs.extend(
            plan.mask_dirs
                .iter()
                .filter(|p| !private.hides(p))
                .filter_map(|p| to_cstring(p)),
        );
        mounts.guard_files.extend(
            plan.mask_files
                .iter()
                .filter(|p| !private.hides(p))
                .filter_map(|p| to_cstring(p)),
        );
    }
    if enforce {
        let dot_pent = config.workspace.join(".pent");
        if dot_pent.exists() {
            mounts.readonly.extend(to_cstring(&dot_pent));
        }
        mounts
            .mask_dirs
            .extend(mask_dirs.iter().filter_map(|p| to_cstring(p)));
        mounts
            .mask_files
            .extend(mask_files.iter().filter_map(|p| to_cstring(p)));
    }

    // The recorder. The supervisor thread starts before `spawn`: the child
    // sends the listener file descriptor during `spawn`, and its `execve`
    // waits for an answer from the supervisor.
    //
    // The supervisor also controls each `connect(2)` to a Unix socket, so
    // it runs with enforcement too, even without `--trace`. It then traps
    // only `connect` and makes no event. The cost is one notification for
    // each connection of the child.
    // An abstract name belongs to a network namespace. With its own
    // namespace the child reaches only its own names; with
    // `--network unrestricted` it reaches the names of the host.
    let abstract_names = if net_flag == 0 {
        crate::linux_unixconn::AbstractNames::Shared
    } else {
        crate::linux_unixconn::AbstractNames::Private
    };
    let unix_policy = crate::linux_unixconn::UnixPolicy::new(unix_sockets, abstract_names);
    let unix = if enforce {
        crate::linux_unixconn::UnixControl::Enforce(unix_policy)
    } else {
        crate::linux_unixconn::UnixControl::Observe(unix_policy)
    };
    let recorder = if record || enforce {
        let judge = if record {
            Some(match guard {
                Some(plan) => crate::linux_watch::Judge::Guard {
                    enforced: plan.effective.clone(),
                    unenforced: plan.unenforced.clone(),
                },
                None => {
                    let mut policy = AccessPolicy::default();
                    add_ruleset_rules(
                        &mut policy,
                        config,
                        path_dirs,
                        &write_set,
                        &overlay_dirs,
                        resolv_dst.as_deref(),
                    );
                    policy.set_overlay(&overlay_dirs, &accessible);
                    crate::linux_watch::Judge::Policy(policy)
                }
            })
        } else {
            None
        };
        Some(crate::linux_watch::start_recorder(
            crate::linux_watch::RecorderPlan { judge, unix },
        )?)
    } else {
        None
    };

    let plan = ChildPlan {
        // The PID fits in pid_t: the kernel limit is 2^22.
        #[allow(clippy::cast_possible_wrap)]
        parent_pid: pid as libc::pid_t,
        unshare_flags,
        uid_map: format!("{uid} {uid} 1\n").into_bytes(),
        gid_map: format!("{gid} {gid} 1\n").into_bytes(),
        proxy_sockets: proxy_sockets.as_ref().map(|p| p.child),
        overlays: overlay_mounts.clone(),
        accessible,
        mounts,
        cwd: if has_mntns {
            to_cstring(&config.cwd)
        } else {
            None
        },
        bring_up_lo: config.network == NetworkMode::LocalhostOnly || is_proxy,
        orphans,
        no_new_privs: ruleset.is_some() || recorder.is_some(),
        ruleset,
        recorder: recorder.as_ref().map(|r| r.child.clone()),
    };

    let effective_env = if is_proxy {
        proxy_env(env, super::linux_proxynet::child_proxy_addr())
    } else {
        env.clone()
    };

    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(&config.cwd);
    command.env_clear();
    command.envs(&effective_env);
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    // SAFETY: `ChildPlan::run` uses only async-signal-safe raw system calls
    // on data prepared before fork (except the overlayfs helpers, see the
    // module documentation).
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        command.pre_exec(move || plan.run());
    }

    let spawn_result = command.spawn();
    // Drop the closure (and with it the ruleset fd).
    drop(command);
    // Drop the parent copy of the socket end of the child. The supervisor
    // then sees EOF if the child died before it sent the listener.
    let events = recorder.map(crate::linux_watch::RecorderSetup::into_events);
    // A recorder that only controls the Unix socket connections makes no
    // event. The caller gets no channel, so it starts no reader. The
    // supervisor then sends into a closed channel and ignores the error.
    let events = if record { events } else { None };

    let mut child = spawn_result.map_err(SandboxError::SpawnFailed)?;
    // `spawn` returns after the `exec` of the child, so the child has sent
    // its proxy listeners.
    let proxy_listeners = match proxy_sockets.map(|p| p.receive()).transpose() {
        Ok(listeners) => listeners,
        Err(e) => {
            // The child runs without its proxy; stop it. A failure means that
            // it has already exited.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };

    // Start the inotify watcher now that the child is running.
    let overlay_handle = if overlay_mounts.is_empty() {
        None
    } else {
        Some(super::linux_overlayfs::spawn_watcher(
            overlay_mounts,
            write_set,
            rw_dirs,
            child.id(),
        ))
    };

    Ok(Spawned {
        child,
        overlay: overlay_handle,
        proxy_listeners,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPaths;
    use serial_test::serial;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct TestDirs {
        workspace: PathBuf,
        data_dir: PathBuf,
        _temp: TempDir,
    }

    fn make_test_dirs() -> TestDirs {
        #[allow(clippy::unwrap_used)] // infra-only helper, no meaningful error recovery
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&workspace).ok();
        std::fs::create_dir_all(&data_dir).ok();
        TestDirs {
            workspace,
            data_dir,
            _temp: temp,
        }
    }

    // ========================================================================
    // Constants tests
    // ========================================================================

    #[test]
    fn test_min_landlock_abi() {
        assert_eq!(MIN_LANDLOCK_ABI, 3);
    }

    // ========================================================================
    // The private `/proc` of the child (finding LS-3)
    // ========================================================================

    /// The mount table of a plain host: one `proc` mount and nothing in it.
    const HOST_MOUNTINFO: &str = "\
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
24 28 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
25 28 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=1622056k
28 1 0:21 / / rw,relatime shared:1 - tmpfs none rw
";

    /// The mount table inside a container. The runtime hides `/proc/acpi`
    /// with a tmpfs and `/proc/kcore` with a bind mount of `/dev/null`.
    /// This layout makes the kernel refuse a new `proc` mount.
    const CONTAINER_MOUNTINFO: &str = "\
875 307 0:35 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
888 875 0:107 / /proc/acpi rw,relatime - tmpfs tmpfs rw,size=16k
889 875 0:7 /null /proc/kcore rw,nosuid - devtmpfs devtmpfs rw,size=1622056k
890 875 0:7 /null /proc/keys rw,nosuid - devtmpfs devtmpfs rw,size=1622056k
307 1 0:36 / / rw,relatime - overlay overlay rw
";

    #[test]
    fn a_plain_host_hides_no_part_of_proc() {
        assert!(hidden_proc_paths(HOST_MOUNTINFO).is_empty());
    }

    #[test]
    fn a_container_hides_the_masked_paths_of_proc() {
        assert_eq!(
            hidden_proc_paths(CONTAINER_MOUNTINFO),
            vec![
                "/proc/acpi".to_string(),
                "/proc/kcore".to_string(),
                "/proc/keys".to_string(),
            ]
        );
    }

    #[test]
    fn a_mount_below_another_filesystem_is_not_a_hidden_part_of_proc() {
        // The parent of the tmpfs is the root mount, not the `proc` mount,
        // so the path is not inside `/proc`.
        let layout = "\
23 28 0:22 / /proc rw,relatime - proc proc rw
30 28 0:40 / /var/tmp rw,relatime - tmpfs tmpfs rw
28 1 0:21 / / rw,relatime - tmpfs none rw
";
        assert!(hidden_proc_paths(layout).is_empty());
    }

    #[test]
    fn a_line_without_the_separator_does_not_stop_the_reader() {
        let layout = format!("this line has no separator\n{CONTAINER_MOUNTINFO}");
        assert_eq!(hidden_proc_paths(&layout).len(), 3);
    }

    #[test]
    fn the_mount_step_follows_the_answer_of_the_probe() {
        let shared = ProcIsolation::Shared(ProcDenial(libc::EPERM));
        // The sandbox and watch mode ask for the namespace. They get it
        // only where the kernel gives the private `proc` mount with it.
        assert_eq!(
            pid_namespace_flag(PidNamespace::Wanted, ProcIsolation::Private),
            libc::CLONE_NEWPID
        );
        assert_eq!(pid_namespace_flag(PidNamespace::Wanted, shared), 0);
        // A run without enforcement never gets the namespace.
        assert_eq!(
            pid_namespace_flag(PidNamespace::NotWanted, ProcIsolation::Private),
            0
        );
        assert_eq!(pid_namespace_flag(PidNamespace::NotWanted, shared), 0);
    }

    #[test]
    fn a_private_proc_makes_no_warning() {
        assert!(ProcIsolation::Private.warning_lines().is_empty());
    }

    #[test]
    fn a_shared_proc_names_what_the_command_can_see() {
        // The layout comes from the data of the test, not from the host, so
        // the lines are the same on each machine.
        let hidden = hidden_proc_paths(CONTAINER_MOUNTINFO);
        let lines = ProcIsolation::Shared(ProcDenial(libc::EPERM)).warning_lines_from(&hidden);
        let text = lines.join("\n");
        assert!(
            text.contains("private /proc"),
            "the warning must name the protection:\n{text}"
        );
        assert!(
            text.contains("EPERM"),
            "the warning must name the error of the kernel:\n{text}"
        );
        // The words of a denied access must not appear: a reader of the
        // output, and a test, looks for them.
        assert!(
            !text.contains("Operation not permitted"),
            "the warning must not read like a denied access:\n{text}"
        );
        assert!(
            text.contains("/proc/acpi"),
            "the warning must name the mount that hides a part of /proc:\n{text}"
        );
        assert!(
            text.contains("PID namespace of this host"),
            "the warning must say which processes the command sees:\n{text}"
        );
        assert!(
            text.contains("/proc/<pid>/cmdline"),
            "the warning must name the file that leaks:\n{text}"
        );
        // Each line is short enough for one warning of the terminal.
        for line in &lines {
            assert!(line.len() <= 100, "the line is too long: {line}");
        }
    }

    #[test]
    fn the_short_list_names_three_paths_and_counts_the_rest() {
        let four = vec![
            "/proc/a".to_string(),
            "/proc/b".to_string(),
            "/proc/c".to_string(),
            "/proc/d".to_string(),
        ];
        assert_eq!(short_list(&four), "/proc/a, /proc/b, /proc/c and more");
        assert_eq!(short_list(&four[..2]), "/proc/a, /proc/b");
        assert_eq!(short_list(&[]), "");
    }

    /// The children of the thread that runs this test.
    ///
    /// `/proc/self/task/<tid>/children` names only the children of one
    /// thread, so another test that spawns a process does not appear here.
    fn children_of_this_thread() -> Option<String> {
        // SAFETY: gettid(2) has no preconditions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let tid = unsafe { libc::gettid() };
        std::fs::read_to_string(format!("/proc/self/task/{tid}/children")).ok()
    }

    #[test]
    #[serial]
    fn the_probe_answers_and_leaves_no_process_behind() {
        let Some(before) = children_of_this_thread() else {
            eprintln!(
                "SKIP the_probe_answers_and_leaves_no_process_behind: \
                 this kernel has no /proc/<pid>/task/<tid>/children"
            );
            return;
        };
        assert!(
            before.trim().is_empty(),
            "the test starts with a child of its own thread: {before}"
        );
        let answer = probe_proc_isolation();
        // The host of this test either gives the private `proc` mount or
        // names the reason. Both answers are correct; the probe must not
        // hang and must not leave a process.
        match answer {
            ProcIsolation::Private => {}
            ProcIsolation::Shared(denial) => {
                assert_ne!(
                    denial.error().raw_os_error(),
                    Some(0),
                    "a refusal must carry an error number"
                );
            }
        }
        let after = children_of_this_thread().unwrap_or_default();
        assert!(
            after.trim().is_empty(),
            "the probe left a process behind: {after}"
        );
    }

    #[test]
    #[serial]
    fn the_probe_costs_one_fork_for_the_life_of_the_process() {
        use std::sync::atomic::Ordering;
        // The answer comes from the cache after the first call, whichever
        // test asked first.
        let first = proc_isolation();
        let runs = PROBE_RUNS.load(Ordering::SeqCst);
        assert!(runs >= 1, "the first call must run the probe");
        for _ in 0..5 {
            assert_eq!(proc_isolation(), first, "the answer must not change");
        }
        assert_eq!(
            PROBE_RUNS.load(Ordering::SeqCst),
            runs,
            "a later call must not fork again"
        );
    }

    // ========================================================================
    // check_available tests
    // ========================================================================

    #[test]
    fn test_check_available_matches_the_abi_of_the_kernel() {
        // The function says that Landlock is available exactly when the
        // kernel reports an ABI version. An earlier version of this test
        // asserted nothing.
        let abi = crate::linux_landlock::abi_version();
        assert_eq!(
            check_available().is_ok(),
            abi.is_ok(),
            "check_available and abi_version disagree: {abi:?}"
        );
        if let Ok(abi) = abi {
            assert!(
                abi >= crate::linux_landlock::MIN_ABI,
                "pent requires ABI {} or later, and the kernel reports {abi}",
                crate::linux_landlock::MIN_ABI
            );
        }
    }

    // ========================================================================
    // build_landlock_ruleset tests
    // ========================================================================

    fn make_test_config() -> SandboxConfig {
        SandboxConfig::new(
            PathBuf::from("/tmp/test-workspace"),
            SandboxPaths::default(),
            PathBuf::from("/tmp/test-workspace"),
        )
        .with_data_dir(PathBuf::from("/tmp/test-data"))
    }

    #[test]
    fn test_build_landlock_ruleset_basic() {
        let config = make_test_config();
        let result = build_landlock_ruleset(&config, &[]);
        // May fail if Landlock not available, that's ok
        if check_available().is_ok() {
            assert!(
                result.is_ok(),
                "Should build ruleset on Landlock-enabled system"
            );
        }
    }

    #[test]
    fn test_build_landlock_ruleset_with_path_dirs() {
        let config = make_test_config();
        let path_dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let result = build_landlock_ruleset(&config, &path_dirs);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_build_landlock_ruleset_with_mounts() {
        use crate::Mount;
        let config = make_test_config()
            .with_mount(Mount {
                path: PathBuf::from("/opt/tools"),
                readonly: true,
            })
            .with_mount(Mount {
                path: PathBuf::from("/var/data"),
                readonly: false,
            });
        let result = build_landlock_ruleset(&config, &[]);
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_build_landlock_ruleset_skips_nonexistent_paths() {
        let config = SandboxConfig::new(
            PathBuf::from("/nonexistent/workspace/12345"),
            SandboxPaths::default(),
            PathBuf::from("/tmp"),
        )
        .with_data_dir(PathBuf::from("/nonexistent/data/12345"));
        let result = build_landlock_ruleset(&config, &[]);
        // Should not fail due to nonexistent paths - they're skipped
        if check_available().is_ok() {
            assert!(result.is_ok());
        }
    }

    // ========================================================================
    // spawn_with_landlock tests
    // ========================================================================

    #[test]
    #[serial]
    fn test_spawn_with_landlock_true_command() -> TestResult {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir);
        let Some(true_bin) = which("true") else {
            return Ok(()); // skip: no `true` in PATH
        };
        let path_dirs = test_path_dirs(&true_bin);
        let env = HashMap::new();

        let result =
            spawn_with_landlock(&config, &true_bin.to_string_lossy(), &[], &env, &path_dirs);

        if check_available().is_ok() {
            match result {
                Ok((mut child, _overlay, _proxy)) => {
                    let status = child
                        .wait()
                        .map_err(|e| format!("Failed to wait on child: {e}"))?;
                    assert!(status.success(), "true command should succeed");
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    // Some CI/container environments expose Landlock but deny
                    // applying it in pre_exec.
                }
                Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    fn test_spawn_with_landlock_echo_command() -> TestResult {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir);
        let Some(echo_bin) = which("echo") else {
            return Ok(()); // skip: no `echo` in PATH
        };
        let path_dirs = test_path_dirs(&echo_bin);
        let env = HashMap::new();

        let result = spawn_with_landlock(
            &config,
            &echo_bin.to_string_lossy(),
            &["hello".to_string()],
            &env,
            &path_dirs,
        );

        if check_available().is_ok() {
            match result {
                Ok((mut child, _overlay, _proxy)) => {
                    let status = child
                        .wait()
                        .map_err(|e| format!("Failed to wait on child: {e}"))?;
                    assert!(status.success());
                }
                Err(SandboxError::SpawnFailed(err))
                    if err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    // Some CI/container environments expose Landlock but deny
                    // applying it in pre_exec.
                }
                Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    fn test_spawn_with_landlock_nonexistent_command() {
        use std::collections::HashMap;

        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir);
        let env = HashMap::new();

        let result = spawn_with_landlock(&config, "/nonexistent/command/12345", &[], &env, &[]);

        if check_available().is_ok() {
            // Should fail to spawn nonexistent command
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // Live inotify flush test (writes flushed mid-session, not just at exit)
    //
    // This is the scenario that matters for long-running apps like Claude:
    // writes happen throughout the session and must reach the real FS as they
    // occur (inotify path), not only when the process exits (teardown flush).
    // ========================================================================

    /// Spawn a long-running process that writes files in phases separated by
    /// sleeps, and verify that each write reaches the real filesystem while
    /// the process is still running (inotify live-flush), not only at teardown.
    ///
    /// This reproduces the "files are gone when I leave the sandbox" failure
    /// mode: if only the teardown flush worked, the files would appear at exit
    /// but not during the session — but since we check mid-session they would
    /// be missing here if the live path is broken.
    #[test]
    #[serial]
    fn test_overlay_live_flush_during_long_running_session() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let rw_dir = temp.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("create_dir_all: {e}"))?;

        // Marker files the sandbox will create at different phases.
        let file_a = rw_dir.join("phase_a.txt");
        let file_b = rw_dir.join("sub").join("phase_b.txt");

        // Flag files must be inside rw_dir so they are under an rw_dirs entry
        // and get live-flushed to the real FS (the parent polls the real path).
        let flag_a = rw_dir.join("flag_a");
        let flag_b = rw_dir.join("flag_b");

        // The shell script:
        //  1. Write phase_a.txt, signal flag_a
        //  2. Sleep briefly
        //  3. Create sub/, write phase_b.txt, signal flag_b
        //  4. Sleep briefly so the parent can check before exit
        let cmd = format!(
            "printf 'content-a' > '{file_a}' && touch '{flag_a}' && \
             sleep 0.2 && \
             mkdir -p '{subdir}' && printf 'content-b' > '{file_b}' && touch '{flag_b}' && \
             sleep 0.5",
            file_a = file_a.display(),
            flag_a = flag_a.display(),
            subdir = rw_dir.join("sub").display(),
            file_b = file_b.display(),
            flag_b = flag_b.display(),
        );

        let Some((mut child, overlay_handle)) =
            spawn_rw(temp.path(), &[rw_dir.to_str().unwrap_or("")], &cmd)
        else {
            return Ok(()); // overlayfs unavailable
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(()); // overlay not active, skip
        };

        // Wait for the sandbox to write phase_a (flag_a appears).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !flag_a.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for flag_a"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // Give the inotify watcher time to pick up the event (polls at 50 ms).
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Phase A: file_a must be on the real FS NOW — process still running.
        assert!(
            file_a.exists(),
            "live inotify flush failed: file_a not on real FS while sandbox is still running"
        );
        assert_eq!(
            std::fs::read_to_string(&file_a).unwrap_or_default(),
            "content-a",
            "file_a content wrong after live flush"
        );

        // Wait for phase_b.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !flag_b.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for flag_b"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Phase B: nested file in a new subdir must also be on real FS mid-session.
        assert!(
            file_b.exists(),
            "live inotify flush failed: file_b (nested) not on real FS while sandbox is still running"
        );
        assert_eq!(
            std::fs::read_to_string(&file_b).unwrap_or_default(),
            "content-b",
            "file_b content wrong after live flush"
        );

        let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
        crate::linux_overlayfs::teardown(handle);
        assert!(status.success());
        Ok(())
    }

    // ========================================================================
    // Overlay flush correctness tests
    //
    // These tests verify that writes made inside the sandbox are flushed back
    // to the real filesystem on teardown.  All tests use /tmp (always rw, no
    // network required) and fall back gracefully when overlayfs is unavailable.
    // ========================================================================

    /// Helper: spawn a sandboxed shell command with the given `read_write` paths
    /// and return `(child, overlay_handle)`.  Falls back gracefully when the
    /// kernel does not support user namespaces or overlayfs.
    ///
    /// The overlay subsystem is only activated when `read_write` contains at
    /// least one **file** entry (or a path that does not yet exist but whose
    /// parent does — treated as a future file).  A config that lists only
    /// directories produces no overlay and the handle will be `None`.
    ///
    /// To ensure the overlay is always active, this helper adds a sentinel
    /// file (`workspace/.pent_sentinel`) to the `read_write` list.  Because
    /// the sentinel lives in `workspace`, the overlay is mounted on `workspace`
    /// itself — which is also the root of every `rw_paths` directory used in
    /// these tests.  All rw directories therefore fall inside the overlay and
    /// are covered by the `rw_dirs` flush path.
    fn spawn_rw(
        workspace: &std::path::Path,
        rw_paths: &[&str],
        cmd: &str,
    ) -> Option<(
        std::process::Child,
        Option<crate::linux_overlayfs::OverlayHandle>,
    )> {
        use std::collections::HashMap;

        if check_available().is_err() {
            return None;
        }

        let mut paths = SandboxPaths::default();
        for p in rw_paths {
            paths.read_write.push((*p).to_string());
        }
        // Add a sentinel file entry so the overlay is always mounted on
        // `workspace`.  Without at least one file-type entry the overlay is
        // never created and all directory-based flush tests would skip.
        let sentinel = workspace.join(".pent_sentinel");
        std::fs::write(&sentinel, "sentinel").ok();
        #[allow(clippy::unwrap_used)] // path always valid UTF-8 in tests
        paths
            .read_write
            .push(sentinel.to_str().unwrap().to_string());

        let config = SandboxConfig::new(workspace.to_path_buf(), paths, workspace.to_path_buf())
            .with_data_dir(workspace.to_path_buf())
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();

        match spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd.to_string()],
            &test_env,
            &path_dirs,
        ) {
            Ok((child, handle, _proxy)) => Some((child, handle)),
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                None
            }
            #[allow(clippy::panic)] // unexpected spawn error — fail loudly in test helper
            Err(e) => panic!("spawn_with_landlock failed: {e:?}"),
        }
    }

    /// Run `spawn_rw`, wait for the child, call teardown, then return whether
    /// the overlay was active (`Some` handle → true, `None` → false).
    fn run_sandboxed_rw(workspace: &std::path::Path, rw_paths: &[&str], cmd: &str) -> bool {
        let Some((mut child, overlay_handle)) = spawn_rw(workspace, rw_paths, cmd) else {
            return false;
        };
        #[allow(clippy::expect_used)] // infra helper — unexpected wait failure should fail loudly
        let status = child.wait().expect("wait failed");
        assert!(status.success(), "sandboxed command failed: {cmd}");
        overlay_handle.is_some_and(|handle| {
            crate::linux_overlayfs::teardown(handle);
            true
        })
    }

    /// Reproduce the real Claude-session failure mode:
    ///
    /// In a typical Claude session `~/.claude.json` is in `read_write` (file),
    /// which causes the overlay to be mounted on `~`.  The workspace
    /// `~/projects/myrepo` is under `~`, so all its writes go to the upper
    /// layer.  But the workspace was NOT in `rw_dirs`, so those writes were
    /// never flushed — every edit Claude made disappeared on session exit.
    ///
    /// This test fails before the fix (workspace added to `rw_dirs`) and passes
    /// after it.
    #[test]
    #[serial]
    fn test_overlay_flush_workspace_under_home_overlay() -> TestResult {
        use std::collections::HashMap;

        if check_available().is_err() {
            return Ok(());
        }

        // fake_home/ mimics ~/.  fake_home/workspace/ mimics ~/projects/myrepo.
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let workspace = fake_home.path().join("workspace");
        std::fs::create_dir_all(&workspace).map_err(|e| format!("create_dir_all: {e}"))?;

        // Pre-create a source file the sandbox will edit.
        let src_dir = workspace.join("src");
        std::fs::create_dir_all(&src_dir).map_err(|e| format!("create_dir_all src: {e}"))?;
        let target = src_dir.join("main.rs");
        std::fs::write(&target, "fn main() {}").map_err(|e| format!("write: {e}"))?;

        // Only the dot-file at home level is in read_write — this triggers the
        // overlay on fake_home/, the same as ~/.claude.json does in production.
        let dot_file = fake_home.path().join(".app.json");
        std::fs::write(&dot_file, "{}").map_err(|e| format!("write dot_file: {e}"))?;

        let mut paths = SandboxPaths::default();
        paths
            .read_write
            .push(dot_file.to_str().unwrap_or("").to_string());
        // workspace is intentionally NOT in read_write — it's the workspace arg.

        let config = SandboxConfig::new(workspace.clone(), paths, workspace.clone())
            .with_data_dir(workspace)
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();
        let cmd = format!(
            "printf 'fn main() {{ println!(\"hi\"); }}' > '{}'",
            target.display()
        );

        let result = spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd],
            &test_env,
            &path_dirs,
        );

        let (mut child, overlay_handle, _proxy) = match result {
            Ok(r) => r,
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(())
            }
            Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
        };

        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(()); // no overlay active
        };

        let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
        assert!(status.success(), "sandboxed command failed");
        crate::linux_overlayfs::teardown(handle);

        let content = std::fs::read_to_string(&target).unwrap_or_default();
        assert_eq!(
            content, "fn main() { println!(\"hi\"); }",
            "workspace file edited inside sandbox must be flushed to real FS \
             (overlay mounted on parent dir, workspace not in read_write)"
        );
        Ok(())
    }

    /// Modify an existing file that is listed directly in `read_write` (file-level
    /// entry).  This is the original `write_set` path.
    #[test]
    #[serial]
    fn test_overlay_flush_direct_file_entry() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let target = temp.path().join("config.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[target.to_str().unwrap_or("")],
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(
            content, r#"{"v":2}"#,
            "direct file-level write_set entry must be flushed"
        );
        Ok(())
    }

    /// Modify a file inside a directory listed in `read_write` (directory-level
    /// entry — the `rw_dirs` path that was broken before this fix).
    #[test]
    #[serial]
    fn test_overlay_flush_file_inside_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("mydir");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("settings.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")], // directory, not file
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(content, r#"{"v":2}"#, "file inside rw_dir must be flushed");
        Ok(())
    }

    /// Modify multiple files inside the same rw directory in one session.
    #[test]
    #[serial]
    fn test_overlay_flush_multiple_files_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("store");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "old-a").map_err(|e| format!("write a: {e}"))?;
        std::fs::write(&b, "old-b").map_err(|e| format!("write b: {e}"))?;

        let cmd = format!(
            "printf 'new-a' > '{}' && printf 'new-b' > '{}'",
            a.display(),
            b.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert_eq!(
            std::fs::read_to_string(&a).map_err(|e| format!("read a: {e}"))?,
            "new-a",
            "a.txt must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&b).map_err(|e| format!("read b: {e}"))?,
            "new-b",
            "b.txt must be flushed"
        );
        Ok(())
    }

    /// Create a new file inside an rw directory (file did not exist at spawn time).
    #[test]
    #[serial]
    fn test_overlay_flush_newly_created_file_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("newdir");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("created.txt");
        assert!(!target.exists());

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")],
            &format!("printf 'hello' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        assert!(
            target.exists(),
            "newly created file must exist on real FS after teardown"
        );
        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            "hello"
        );
        Ok(())
    }

    /// Edit an existing file that is deeply nested inside an rw directory.
    /// All parent directories exist at spawn time.
    #[test]
    #[serial]
    fn test_overlay_flush_deeply_nested_existing_file() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let rw_dir = temp.path().join("store");
        // Pre-create the full hierarchy before spawning.
        let deep = rw_dir.join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).map_err(|e| format!("create_dir: {e}"))?;
        let target = deep.join("state.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[rw_dir.to_str().unwrap_or("")],
            &format!("printf '{{\"v\":2}}' > '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(
            content, r#"{"v":2}"#,
            "deeply nested existing file must be flushed to real FS"
        );
        Ok(())
    }

    /// Create a new subdirectory and file inside an rw directory.
    /// The subdirectory did not exist at spawn time.
    #[test]
    #[serial]
    fn test_overlay_flush_file_in_new_subdir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let rw_dir = temp.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("create_dir: {e}"))?;
        // subdir does NOT exist at spawn time
        let subdir = rw_dir.join("projects").join("alpha");
        let target = subdir.join("state.json");

        let cmd = format!(
            "mkdir -p '{}' && printf '{{\"ok\":true}}' > '{}'",
            subdir.display(),
            target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert!(
            subdir.exists(),
            "new subdirectory must exist on real FS after teardown"
        );
        assert!(
            target.exists(),
            "file in new subdir must be flushed to real FS"
        );
        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            r#"{"ok":true}"#
        );
        Ok(())
    }

    /// Atomic write (write-to-tmp then rename) inside an rw directory.
    #[test]
    #[serial]
    fn test_overlay_flush_atomic_write_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("cfg");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("config.toml");
        std::fs::write(&target, "version = 1").map_err(|e| format!("write: {e}"))?;
        let tmp = dir.join("config.toml.tmp");

        let cmd = format!(
            "printf 'version = 2' > '{}' && mv '{}' '{}'",
            tmp.display(),
            tmp.display(),
            target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            "version = 2",
            "atomic write (tmp→rename) in rw_dir must be flushed"
        );
        Ok(())
    }

    /// Mix of a direct file entry and a directory entry in the same session.
    #[test]
    #[serial]
    fn test_overlay_flush_mixed_file_and_dir_entries() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let file_entry = temp.path().join("config.json");
        let dir_entry = temp.path().join("cache");
        std::fs::write(&file_entry, "old").map_err(|e| format!("write file_entry: {e}"))?;
        std::fs::create_dir_all(&dir_entry).map_err(|e| format!("create_dir: {e}"))?;
        let cache_file = dir_entry.join("data.bin");
        std::fs::write(&cache_file, "stale").map_err(|e| format!("write cache_file: {e}"))?;

        let cmd = format!(
            "printf 'new' > '{}' && printf 'fresh' > '{}'",
            file_entry.display(),
            cache_file.display()
        );
        let active = run_sandboxed_rw(
            temp.path(),
            &[
                file_entry.to_str().unwrap_or(""),
                dir_entry.to_str().unwrap_or(""),
            ],
            &cmd,
        );
        if !active {
            return Ok(());
        }

        assert_eq!(
            std::fs::read_to_string(&file_entry).map_err(|e| format!("read file_entry: {e}"))?,
            "new",
            "direct file entry must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&cache_file).map_err(|e| format!("read cache_file: {e}"))?,
            "fresh",
            "file inside directory entry must be flushed"
        );
        Ok(())
    }

    /// Append to an existing file inside an rw directory.
    #[test]
    #[serial]
    fn test_overlay_flush_append_to_file_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("logs");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("app.log");
        std::fs::write(&target, "line1\n").map_err(|e| format!("write: {e}"))?;

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")],
            &format!("printf 'line2\\n' >> '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        let content = std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?;
        assert_eq!(
            content, "line1\nline2\n",
            "appended content must be flushed"
        );
        Ok(())
    }

    /// A `read_write` path that does not exist at spawn time and is created as a
    /// directory by the sandbox process.  Its contents must be flushed.
    #[test]
    #[serial]
    fn test_overlay_flush_nonexistent_rw_path_created_as_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        // rw_dir does NOT exist at spawn time — it will be created by the sandbox.
        let rw_dir = temp.path().join("cache");
        assert!(!rw_dir.exists());
        let target = rw_dir.join("state.json");

        let cmd = format!(
            "mkdir -p '{}' && printf '{{\"ok\":true}}' > '{}'",
            rw_dir.display(),
            target.display()
        );
        let active = run_sandboxed_rw(temp.path(), &[rw_dir.to_str().unwrap_or("")], &cmd);
        if !active {
            return Ok(());
        }

        assert!(
            rw_dir.exists(),
            "directory created by sandbox must exist on real FS"
        );
        assert!(
            target.exists(),
            "file inside newly-created rw dir must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&target).map_err(|e| format!("read: {e}"))?,
            r#"{"ok":true}"#
        );
        Ok(())
    }

    /// Files outside both the workspace and all `read_write` directories must NOT
    /// be flushed to the real FS.  The overlay covers the entire parent
    /// directory, so writes from the sandbox land in the upper layer, but the
    /// flush logic only persists files that are in `write_set` or `rw_dirs`
    /// (which includes the workspace).  Files in a sibling directory that is
    /// neither the workspace nor an explicit rw path are protected on two
    /// levels: Landlock denies the write entirely, and even if a write somehow
    /// reached the upper layer, the flush condition would not match.
    #[test]
    #[serial]
    fn test_overlay_no_flush_for_non_rw_dir() -> TestResult {
        use std::collections::HashMap;

        if check_available().is_err() {
            return Ok(());
        }

        // base/ is the overlay root (triggered by base/.sentinel file entry).
        // workspace/ is the workspace — its contents ARE flushed.
        // sibling/ is a sibling directory outside the workspace — writes are
        // blocked by Landlock and must not be flushed.
        // The default temp dir is under /tmp, which the sandbox can always
        // write. This test needs a directory outside of it.
        let Some(base) = non_tmp_tempdir() else {
            return Ok(());
        };
        let workspace = base.path().join("workspace");
        let sibling = base.path().join("sibling");
        std::fs::create_dir_all(&workspace).map_err(|e| format!("create workspace: {e}"))?;
        std::fs::create_dir_all(&sibling).map_err(|e| format!("create sibling: {e}"))?;

        let ws_file = workspace.join("ok.txt");
        let sibling_file = sibling.join("secret.txt");
        std::fs::write(&ws_file, "original-ws").map_err(|e| format!("write ws_file: {e}"))?;
        std::fs::write(&sibling_file, "original-sibling")
            .map_err(|e| format!("write sibling_file: {e}"))?;

        // Sentinel in base/ triggers overlay on base/ (covering both workspace/
        // and sibling/).
        let sentinel = base.path().join(".sentinel");
        std::fs::write(&sentinel, "s").map_err(|e| format!("write sentinel: {e}"))?;

        let mut paths = SandboxPaths::default();
        paths
            .read_write
            .push(sentinel.to_str().unwrap_or("").to_string());
        // workspace is NOT in read_write but is the workspace arg — it gets
        // added to rw_dirs automatically and its files are flushed.

        let config = SandboxConfig::new(workspace.clone(), paths, workspace.clone())
            .with_data_dir(workspace)
            .with_env(HashMap::new());
        let (test_env, path_dirs) = host_path_env();

        // The sandbox can write to workspace (Landlock allows it) but not to
        // sibling (Landlock denies it — the write fails silently).
        let cmd = format!(
            "printf 'modified-ws' > '{}'; printf 'should-not-persist' > '{}' 2>/dev/null; true",
            ws_file.display(),
            sibling_file.display()
        );

        let result = spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd],
            &test_env,
            &path_dirs,
        );
        let (mut child, overlay_handle, _proxy) = match result {
            Ok(r) => r,
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return Ok(())
            }
            Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };
        let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
        assert!(status.success());
        crate::linux_overlayfs::teardown(handle);

        assert_eq!(
            std::fs::read_to_string(&ws_file).map_err(|e| format!("read ws_file: {e}"))?,
            "modified-ws",
            "workspace file must be flushed"
        );
        assert_eq!(
            std::fs::read_to_string(&sibling_file)
                .map_err(|e| format!("read sibling_file: {e}"))?,
            "original-sibling",
            "file outside workspace and rw_dirs must NOT be modified on real FS"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_overlay_atomic_write_preserves_inode() -> TestResult {
        // Verify that the overlayfs + inotify pipeline correctly:
        //   1. lets the child atomically replace a write-listed file
        //      (create-temp → rename), and
        //   2. flushes the new content to the *real* inode so the inode
        //      number is unchanged after teardown.
        //
        // The test only asserts inode-preservation when the overlay handle is
        // `Some` (i.e. overlayfs mounted successfully). If the kernel lacks
        // user namespaces or the overlayfs module, the handle will be `None`
        // and the test exits without assertion failures.
        use std::collections::HashMap;
        use std::os::unix::fs::MetadataExt;
        if check_available().is_err() {
            return Ok(());
        }

        // The default temp dir is under /tmp, which the sandbox can always
        // write. This test needs a directory outside of it.
        let Some(temp) = non_tmp_tempdir() else {
            return Ok(());
        };
        let target = temp.path().join("target.json");
        std::fs::write(&target, r#"{"version":1}"#).map_err(|e| format!("write: {e}"))?;
        let inode_before = std::fs::metadata(&target)
            .map_err(|e| format!("metadata: {e}"))?
            .ino();

        // A SandboxConfig that lists target.json in read_write.
        let workspace = temp.path().to_path_buf();
        let mut paths = SandboxPaths::default();
        paths
            .read_write
            .push(target.to_str().unwrap_or("").to_string());

        let config = SandboxConfig::new(workspace.clone(), paths, workspace)
            .with_data_dir(temp.path().to_path_buf())
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();

        let new_content = r#"{"version":2}"#;
        // Atomic write: write to a sibling tmp file then rename into place.
        let tmp_path = temp.path().join("target.json.tmp");
        let cmd = format!(
            "printf '{}' > '{}' && mv '{}' '{}'",
            new_content,
            tmp_path.display(),
            tmp_path.display(),
            target.display(),
        );

        let result = spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd],
            &test_env,
            &path_dirs,
        );

        let (mut child, overlay_handle, _proxy) = match result {
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                // Some CI/container environments deny pre_exec operations.
                return Ok(());
            }
            Err(e) => return Err(format!("spawn_with_landlock failed: {e:?}").into()),
            Ok(pair) => pair,
        };

        let status = child
            .wait()
            .map_err(|e| format!("Failed to wait on child: {e}"))?;

        if let Some(handle) = overlay_handle {
            // Flush upper-layer writes back to real inodes and clean up staging.
            crate::linux_overlayfs::teardown(handle);

            assert!(
                status.success(),
                "atomic write shell command should succeed"
            );

            let content = std::fs::read_to_string(&target).unwrap_or_default();
            let inode_after = std::fs::metadata(&target).map(|m| m.ino()).unwrap_or(0);

            assert_eq!(
                content, new_content,
                "overlayfs flush must write new content to real file"
            );
            assert_eq!(
                inode_before, inode_after,
                "real file inode must not change after overlayfs flush"
            );
        }
        // If overlay_handle is None, overlayfs is unavailable; skip assertions.
        Ok(())
    }

    // ========================================================================
    // Overlay coverage and permission tests
    //
    // These tests verify that:
    //   1. Non-accessible siblings inside an overlay dir get EACCES (mode 0000).
    //   2. The mode 0000 stub in the upper layer never leaks to the real FS.
    //   3. execute_access does not include ReadFile (execute-only enforcement).
    //
    // Tests that control $HOME set it temporarily via HomeGuard, which restores
    // the original value on drop — safe under #[serial] (tests don't run in
    // parallel).
    // ========================================================================

    /// RAII guard that saves and restores the HOME environment variable.
    ///
    /// Used by tests that temporarily redirect HOME to a temp directory so that
    /// `spawn_with_landlock` computes overlay roots relative to a fake home.
    struct HomeGuard(String);

    impl HomeGuard {
        fn set(new_home: &std::path::Path) -> Self {
            let old = std::env::var("HOME").unwrap_or_default();
            // SAFETY: this is a single-threaded test context (enforced by #[serial]).
            #[allow(deprecated)] // set_var is safe in single-threaded serial tests
            std::env::set_var("HOME", new_home);
            Self(old)
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            #[allow(deprecated)]
            std::env::set_var("HOME", &self.0);
        }
    }

    /// Spawn a sandboxed shell command with HOME pointed at `fake_home`.
    ///
    /// `rw_files` are added to `read_write` (file-level entries, which trigger
    /// overlay mounts via the MCA algorithm).  `rw_dirs` are added as directory
    /// entries so their writes are flushed back.  The command's working
    /// directory and data_dir are both `work_dir`.
    #[allow(clippy::too_many_arguments)]
    fn spawn_with_fake_home(
        fake_home: &std::path::Path,
        work_dir: &std::path::Path,
        rw_files: &[&std::path::Path],
        rw_dirs: &[&std::path::Path],
        cmd: &str,
    ) -> Option<(
        std::process::Child,
        Option<crate::linux_overlayfs::OverlayHandle>,
    )> {
        use std::collections::HashMap;

        if check_available().is_err() {
            return None;
        }

        let mut paths = SandboxPaths::default();
        for f in rw_files {
            if let Some(s) = f.to_str() {
                paths.read_write.push(s.to_string());
            }
        }
        for d in rw_dirs {
            if let Some(s) = d.to_str() {
                paths.read_write.push(s.to_string());
            }
        }

        let config = SandboxConfig::new(work_dir.to_path_buf(), paths, work_dir.to_path_buf())
            .with_data_dir(work_dir.to_path_buf())
            .with_env(HashMap::new());

        let (test_env, path_dirs) = host_path_env();

        // HOME must be set to fake_home before this call so that
        // spawn_with_landlock computes overlay roots relative to it.
        let _guard = HomeGuard::set(fake_home);

        match spawn_with_landlock(
            &config,
            "/bin/sh",
            &["-c".to_string(), cmd.to_string()],
            &test_env,
            &path_dirs,
        ) {
            Ok((child, handle, _proxy)) => Some((child, handle)),
            Err(SandboxError::SpawnFailed(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                None
            }
            #[allow(clippy::panic)] // unexpected spawn error in test helper — fail loudly
            Err(e) => panic!("spawn_with_landlock failed unexpectedly: {e:?}"),
        }
    }

    /// Non-accessible directories that are siblings of an accessible file inside
    /// the overlay root must be EACCES inside the sandbox.
    ///
    /// Setup: fake_home/.config/allowed.txt (accessible via read_write) and
    ///        fake_home/.config/secret/ (not accessible).
    ///
    /// Overlay root: ~/.config (MCA of accessible paths under home).
    ///
    /// Inside the overlay, `secret/` gets mode 0000 + opaque=y in the upper
    /// layer.  The sandboxed `ls` on that directory must return non-zero.
    #[test]
    #[serial]
    fn test_overlay_non_accessible_sibling_is_eacces() -> TestResult {
        // The default temp dir is under /tmp, which the sandbox can always
        // write. This test needs a directory outside of it.
        let Some(fake_home) = non_tmp_tempdir() else {
            return Ok(());
        };
        let config_dir = fake_home.path().join(".config");
        let allowed_file = config_dir.join("allowed.txt");
        let secret_dir = config_dir.join("secret");
        let work_dir = fake_home.path().join("work");
        let result_file = work_dir.join("ls_exit.txt");

        std::fs::create_dir_all(&config_dir).map_err(|e| format!("mkdir config: {e}"))?;
        std::fs::create_dir_all(&secret_dir).map_err(|e| format!("mkdir secret: {e}"))?;
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;
        std::fs::write(&allowed_file, "allowed").map_err(|e| format!("write: {e}"))?;
        std::fs::write(secret_dir.join("top-secret.txt"), "secret")
            .map_err(|e| format!("write secret: {e}"))?;

        // Command: attempt ls on the non-accessible dir; record exit status in work_dir.
        let cmd = format!(
            "ls '{secret}' > /dev/null 2>&1; echo $? > '{out}'",
            secret = secret_dir.display(),
            out = result_file.display(),
        );

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&allowed_file],
            &[&work_dir],
            &cmd,
        ) else {
            return Ok(()); // overlayfs or user namespaces unavailable
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(()); // overlay not active (no file-type rw entries produced roots)
        };

        let status = child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(status.success(), "outer shell command should exit 0");

        let ls_exit: i32 = std::fs::read_to_string(&result_file)
            .map_err(|e| format!("read result: {e}"))?
            .trim()
            .parse()
            .map_err(|e| format!("parse exit: {e}"))?;

        assert_ne!(
            ls_exit, 0,
            "ls on non-accessible dir must fail inside sandbox \
             (expected EACCES from mode-0000 upper-layer stub)"
        );
        Ok(())
    }

    /// Mode 0000 stubs in the overlay's upper layer must NOT leak to the real
    /// filesystem after teardown.
    ///
    /// The upper layer is a separate staging directory; the real directory is
    /// never chmod'd.  After the sandbox exits and teardown() is called, the
    /// real directory permissions must be identical to what they were before
    /// the sandbox ran.
    #[test]
    #[serial]
    fn test_overlay_real_permissions_not_leaked() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let config_dir = fake_home.path().join(".config");
        let allowed_file = config_dir.join("allowed.txt");
        let private_dir = config_dir.join("private");
        let work_dir = fake_home.path().join("work");

        std::fs::create_dir_all(&config_dir).map_err(|e| format!("mkdir config: {e}"))?;
        std::fs::create_dir_all(&private_dir).map_err(|e| format!("mkdir private: {e}"))?;
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;
        std::fs::write(&allowed_file, "data").map_err(|e| format!("write: {e}"))?;

        // Record original permissions of private_dir before the sandbox touches anything.
        let perms_before = std::fs::metadata(&private_dir)
            .map_err(|e| format!("metadata before: {e}"))?
            .permissions()
            .mode();

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&allowed_file],
            &[&work_dir],
            "true",
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        let perms_after = std::fs::metadata(&private_dir)
            .map_err(|e| format!("metadata after: {e}"))?
            .permissions()
            .mode();

        assert_eq!(
            perms_before, perms_after,
            "mode 0000 in overlay upper layer must not leak to real filesystem: \
             before=0o{perms_before:o} after=0o{perms_after:o}"
        );
        Ok(())
    }

    /// Delete a pre-existing file that lives inside an rw directory.
    /// After teardown the file must be gone from the real filesystem.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_file_in_rw_dir() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let dir = temp.path().join("data");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir: {e}"))?;
        let target = dir.join("to_delete.txt");
        std::fs::write(&target, "will be deleted").map_err(|e| format!("write: {e}"))?;
        assert!(
            target.exists(),
            "pre-condition: file must exist before sandbox"
        );

        let active = run_sandboxed_rw(
            temp.path(),
            &[dir.to_str().unwrap_or("")],
            &format!("rm '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        assert!(
            !target.exists(),
            "file deleted inside sandbox must be removed from real FS after teardown"
        );
        Ok(())
    }

    /// Delete a pre-existing file that is listed directly in `read_write`
    /// (write_set entry rather than rw_dir).  After teardown the file must be
    /// gone from the real filesystem.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_direct_write_set_entry() -> TestResult {
        let temp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let target = temp.path().join("config.json");
        std::fs::write(&target, r#"{"v":1}"#).map_err(|e| format!("write: {e}"))?;
        assert!(
            target.exists(),
            "pre-condition: file must exist before sandbox"
        );

        let active = run_sandboxed_rw(
            temp.path(),
            &[target.to_str().unwrap_or("")],
            &format!("rm '{}'", target.display()),
        );
        if !active {
            return Ok(());
        }

        assert!(
            !target.exists(),
            "write_set file deleted inside sandbox must be removed from real FS after teardown"
        );
        Ok(())
    }

    /// Delete a pre-existing file inside an rw_dir that lives under the overlay
    /// root (i.e. under `fake_home`).
    ///
    /// This is the scenario that exposed the char-device whiteout bug: overlayfs
    /// only creates a `user.overlay.whiteout` xattr when USERSPACE creates the
    /// whiteout stub.  When the kernel itself handles `unlink(2)` for a file that
    /// exists in the lower layer, it creates a **char device (major=0, minor=0)**
    /// whiteout instead.  The old `is_overlay_whiteout` only checked for the
    /// xattr, so kernel-created whiteouts were silently skipped and the real file
    /// was never deleted.
    ///
    /// The previous deletion tests (`test_overlay_flush_delete_file_in_rw_dir`)
    /// used a temp dir under `/tmp`, which is outside `home_dir`.  No overlayfs
    /// is mounted for paths outside `home_dir`, so `rm` hit the real FS directly
    /// and no whiteout was ever produced — the bug was invisible.
    ///
    /// This test uses `spawn_with_fake_home` so the rw_dir IS under the overlay
    /// root, triggering the full overlayfs whiteout path.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_under_overlay_root() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        // Place the rw_dir and the target file INSIDE fake_home so that
        // `overlay_roots_for_accessible` computes an overlay root and
        // overlayfs is actually mounted.
        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;
        let target = rw_dir.join("to_delete.txt");
        std::fs::write(&target, "will be deleted").map_err(|e| format!("write: {e}"))?;
        assert!(
            target.exists(),
            "pre-condition: file must exist before sandbox"
        );

        // A file-level read_write entry is needed to trigger the overlay mount
        // on fake_home (the MCA algorithm picks the parent of file entries as
        // the overlay root).
        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file], // file entry → overlay mounted on fake_home/
            &[&rw_dir],   // dir entry → deletions inside rw_dir are flushed
            &format!("rm '{}'", target.display()),
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            !target.exists(),
            "file deleted inside sandbox must be removed from real FS: \
             char-device whiteout (major=0, minor=0) must be detected by \
             is_overlay_whiteout, not just the user.overlay.whiteout xattr"
        );
        Ok(())
    }

    /// An upper-layer-only directory that is deleted inside the sandbox must be
    /// removed from the real filesystem.
    ///
    /// When an upper-layer-only directory is removed with `rmdir`/`rm -rf`,
    /// overlayfs simply removes it from upper with no whiteout — it fires
    /// `IN_DELETE | IN_ISDIR` on the parent.  Previously the `IN_ISDIR` branch
    /// only handled creation events, so directory deletions were silently ignored
    /// and the real directory was left behind.
    #[test]
    #[serial]
    fn test_overlay_delete_session_created_dir() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        // Reproduce the exact sequence from the manual test:
        // mkdir sub, write sub/file, mv sub/file .., rm -rf sub
        let sub = rw_dir.join("sub");
        let kept = rw_dir.join("kept.txt");
        let cmd = format!(
            "mkdir -p '{sub}' && \
             echo hi > '{sub}/tmp.txt' && \
             mv '{sub}/tmp.txt' '{kept}' && \
             rm -rf '{sub}'",
            sub = sub.display(),
            kept = kept.display(),
        );
        let Some((mut child, overlay_handle)) =
            spawn_with_fake_home(fake_home.path(), &work_dir, &[&dot_file], &[&rw_dir], &cmd)
        else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            kept.exists(),
            "file moved out of deleted subdir must exist on real FS"
        );
        assert!(
            !sub.exists(),
            "upper-layer-only directory deleted inside sandbox must be removed \
             from real FS: IN_DELETE|IN_ISDIR must trigger flush_deletion"
        );
        Ok(())
    }

    /// Atomic write pattern (write tmp → rename to target) must not leave the
    /// tmp file on the real filesystem.
    ///
    /// This is the Edit tool pattern: write content to `file.rs.tmp.PID.TS`,
    /// then `rename(tmp, file.rs)`.  In overlayfs, if `tmp` has no lower-layer
    /// copy, the rename produces only `IN_MOVED_FROM` on `tmp` — no whiteout,
    /// no `IN_DELETE`.  Without watching `IN_MOVED_FROM` the tmp file flushed
    /// during `IN_CLOSE_WRITE` would stay on the real FS forever.
    #[test]
    #[serial]
    fn test_overlay_atomic_write_no_tmp_residue() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;
        let target = rw_dir.join("file.rs");
        let tmp = rw_dir.join("file.rs.tmp.99999.1234567890");

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        // Simulate Edit tool: write to tmp, then atomically rename to target.
        let cmd = format!(
            "echo 'content' > '{}' && mv '{}' '{}'",
            tmp.display(),
            tmp.display(),
            target.display(),
        );
        let Some((mut child, overlay_handle)) =
            spawn_with_fake_home(fake_home.path(), &work_dir, &[&dot_file], &[&rw_dir], &cmd)
        else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            target.exists(),
            "target file must exist on real FS after atomic write"
        );
        assert!(
            !tmp.exists(),
            "tmp file must be deleted from real FS after rename: \
             IN_MOVED_FROM must trigger flush_deletion for upper-layer-only files"
        );
        Ok(())
    }

    /// Delete a pre-existing directory (with nested content) inside an rw_dir
    /// that lives under the overlay root.
    ///
    /// `rm -rf dir` triggers an overlayfs opaque-directory whiteout followed by
    /// an `IN_DELETE | IN_ISDIR` inotify event on the parent.  `flush_deletion`
    /// must use `remove_dir_all`, not `remove_file`, to propagate this.
    #[test]
    #[serial]
    fn test_overlay_flush_delete_dir_under_overlay_root() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        let target_dir = rw_dir.join("to_delete");
        let nested_file = target_dir.join("sub").join("file.txt");
        let nested_parent = nested_file.parent().ok_or("nested file has no parent")?;
        std::fs::create_dir_all(nested_parent).map_err(|e| format!("mkdir nested: {e}"))?;
        std::fs::write(&nested_file, "nested").map_err(|e| format!("write nested: {e}"))?;
        assert!(
            target_dir.exists(),
            "pre-condition: dir must exist before sandbox"
        );

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file],
            &[&rw_dir],
            &format!("rm -rf '{}'", target_dir.display()),
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            !target_dir.exists(),
            "directory deleted inside sandbox must be removed from real FS: \
             flush_deletion must handle EISDIR by falling back to remove_dir_all"
        );
        Ok(())
    }

    /// A file written inside the sandbox with non-default permissions must have
    /// those permissions flushed to the real filesystem.
    ///
    /// Regression for the case where `flush_file` preserved content but the
    /// flushed file ended up with default umask permissions instead of the
    /// permissions set inside the sandbox.
    #[test]
    #[serial]
    fn test_overlay_flush_permissions_under_overlay_root() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        let rw_dir = fake_home.path().join("data");
        std::fs::create_dir_all(&rw_dir).map_err(|e| format!("mkdir rw_dir: {e}"))?;
        let target = rw_dir.join("script.sh");
        std::fs::write(&target, "#!/bin/sh\necho hi\n").map_err(|e| format!("write: {e}"))?;

        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        // chmod 755 inside the sandbox; teardown must preserve 0o755.
        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file],
            &[&rw_dir],
            &format!("chmod 755 '{}'", target.display()),
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        let mode = std::fs::metadata(&target)
            .map_err(|e| format!("metadata: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "permissions set inside sandbox must be flushed to real FS: got 0o{mode:o}"
        );
        Ok(())
    }

    /// Deleting a non-rw file inside the sandbox must NOT affect the real FS.
    ///
    /// Files and directories that are accessible (readable) but not in any
    /// `rw_dir` or `write_set` entry are session-scoped: the overlayfs whiteout
    /// stays in the upper layer but is never flushed back.  The real file must
    /// survive the sandbox session intact.
    #[test]
    #[serial]
    fn test_overlay_delete_readonly_not_flushed() -> TestResult {
        let fake_home = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let work_dir = fake_home.path().join("work");
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;

        // readonly_dir is accessible but NOT in rw_dirs — deletions must not
        // propagate to real FS.
        let readonly_dir = fake_home.path().join("readonly");
        std::fs::create_dir_all(&readonly_dir).map_err(|e| format!("mkdir readonly: {e}"))?;
        let readonly_file = readonly_dir.join("protected.txt");
        std::fs::write(&readonly_file, "must survive").map_err(|e| format!("write: {e}"))?;

        let readonly_subdir = readonly_dir.join("subdir");
        std::fs::create_dir_all(&readonly_subdir).map_err(|e| format!("mkdir subdir: {e}"))?;
        let readonly_nested = readonly_subdir.join("nested.txt");
        std::fs::write(&readonly_nested, "also survives").map_err(|e| format!("write: {e}"))?;

        // dot_file triggers the overlay mount; rw_dirs is empty so nothing is
        // ever flushed back.
        let dot_file = fake_home.path().join(".sentinel");
        std::fs::write(&dot_file, "").map_err(|e| format!("write sentinel: {e}"))?;

        let cmd = format!(
            "rm '{}' && rm -rf '{}'",
            readonly_file.display(),
            readonly_subdir.display(),
        );
        let Some((mut child, overlay_handle)) = spawn_with_fake_home(
            fake_home.path(),
            &work_dir,
            &[&dot_file],
            &[], // no rw_dirs → nothing flushed
            &cmd,
        ) else {
            return Ok(());
        };
        let Some(handle) = overlay_handle else {
            child.wait().ok();
            return Ok(());
        };

        child.wait().map_err(|e| format!("wait: {e}"))?;
        crate::linux_overlayfs::teardown(handle);

        assert!(
            readonly_file.exists(),
            "non-rw file deleted inside sandbox must still exist on real FS"
        );
        assert!(
            readonly_subdir.exists(),
            "non-rw directory deleted inside sandbox must still exist on real FS"
        );
        assert!(
            readonly_nested.exists(),
            "non-rw nested file deleted inside sandbox must still exist on real FS"
        );
        Ok(())
    }

    /// Execute-only access must NOT include `ReadFile`.
    ///
    /// Paths in `paths.execute` should be execute-only: the sandboxed process
    /// can `execve` binaries there but cannot `open(O_RDONLY)` them (which
    /// would let an attacker exfiltrate binary content).
    ///
    /// System library paths (`READ_EXECUTE`) intentionally DO include
    /// `ReadFile` because the dynamic linker uses `open()` to load `.so` files.
    #[test]
    fn test_execute_access_excludes_read_file() {
        assert_eq!(access::EXECUTE_ONLY & access::READ_FILE, 0);
        assert_ne!(access::READ_EXECUTE & access::READ_FILE, 0);
        assert_eq!(access::ALL & access::EXECUTE_ONLY, access::EXECUTE_ONLY);
    }

    // ========================================================================
    // Device set, masks and ordering
    // ========================================================================

    #[test]
    fn test_dev_paths_are_minimal() {
        assert!(!DEV_RW_PATHS.contains(&"/dev"));
        assert!(!DEV_READ_PATHS.contains(&"/dev"));
        for p in ["/dev/shm", "/dev/mqueue"] {
            assert!(
                !DEV_RW_PATHS.contains(&p),
                "{p} must not be writable by default"
            );
            assert!(!DEV_READ_PATHS.contains(&p));
        }
        for p in ["/dev/null", "/dev/tty", "/dev/pts", "/dev/ptmx"] {
            assert!(DEV_RW_PATHS.contains(&p), "{p} must be writable");
        }
        assert!(DEV_READ_PATHS.contains(&"/dev/urandom"));
        let set = compute_accessible_set(&make_test_config(), &[]);
        assert!(!set.contains(Path::new("/dev")));
        assert!(set.contains(Path::new("/dev/null")));
    }

    #[test]
    fn test_system_paths_include_nix_store() {
        assert!(SYSTEM_PATHS.contains(&"/nix/store"));
        assert!(!SYSTEM_PATHS.contains(&"/"));
    }

    // ========================================================================
    // Private temporary and runtime directories
    // ========================================================================

    /// A configuration with the workspace under `/tmp`.
    fn private_test_config(workspace: &Path) -> SandboxConfig {
        SandboxConfig::new(
            workspace.to_path_buf(),
            SandboxPaths::default(),
            workspace.to_path_buf(),
        )
        .with_data_dir(workspace.join("data"))
    }

    #[test]
    fn test_private_dirs_cover_tmp_and_run() {
        let plan = plan_private_dirs(&make_test_config(), &[], &[], 4242);
        assert!(
            plan.covered.contains(&PathBuf::from("/tmp")),
            "/tmp must get a private tmpfs"
        );
        assert!(
            plan.covered.contains(&PathBuf::from("/run")),
            "/run must get a private tmpfs"
        );
        // `/var/run` points to `/run` on this host, so it needs no own mount.
        assert_eq!(plan.covered.len(), plan.mounts.len());
    }

    #[test]
    fn test_private_dirs_bind_a_workspace_under_tmp() -> TestResult {
        let temp = tempfile::Builder::new()
            .prefix("pent-private-")
            .tempdir_in("/tmp")?;
        let workspace = temp.path().join("ws");
        std::fs::create_dir_all(&workspace)?;
        let plan = plan_private_dirs(&private_test_config(&workspace), &[], &[], 4242);
        assert!(
            plan.visible.contains(&workspace),
            "the workspace under /tmp must stay visible: {:?}",
            plan.visible
        );
        assert!(!plan.hides(&workspace));
        assert!(plan.hides(Path::new("/tmp/some-host-file")));
        Ok(())
    }

    #[test]
    fn test_private_dirs_keep_the_system_paths() {
        let plan = plan_private_dirs(&make_test_config(), &[], &[], 4242);
        for keep in ["/run/current-system", "/run/wrappers/bin"] {
            if !Path::new(keep).exists() {
                continue; // not a NixOS host
            }
            assert!(
                plan.visible.contains(&PathBuf::from(keep)),
                "{keep} must stay visible"
            );
        }
        assert!(plan.hides(Path::new("/run/dbus/system_bus_socket")));
        assert!(plan.hides(Path::new("/run/tailscale/tailscaled.sock")));
    }

    #[test]
    fn test_private_dirs_make_an_empty_runtime_directory() {
        let plan = plan_private_dirs(&make_test_config(), &[], &[], 4242);
        let runtime = CString::new("/run/user/4242").unwrap_or_default();
        let bind = plan.binds.iter().find(|b| b.target == runtime);
        assert_eq!(
            bind.map(|b| b.kind),
            Some(BindKind::EmptyDirectory(0o700)),
            "the plan must make an empty /run/user/4242"
        );
        assert!(
            plan.hides(Path::new("/run/user/4242/bus")),
            "the runtime directory stays empty"
        );
    }

    /// NET-3. A rule for one path below a private directory gives the child
    /// that path only. The parent of the path stays an empty directory of
    /// the tmpfs, so the sibling sockets of the host do not come back.
    #[test]
    fn test_private_dirs_bind_the_named_path_not_its_parent() -> TestResult {
        let temp = tempfile::Builder::new()
            .prefix("pent-net3-")
            .tempdir_in("/tmp")?;
        let base = std::fs::canonicalize(temp.path())?;
        let allowed = base.join("allowed");
        std::fs::create_dir_all(&allowed)?;
        let mut config = make_test_config();
        config.paths.read_write = vec![allowed.to_string_lossy().into_owned()];
        // The CLI adds each parent of a rule to the traversal list.
        config.paths.traversal = base
            .ancestors()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let plan = plan_private_dirs(&config, &[], &[], 4242);
        assert!(
            plan.visible.contains(&allowed),
            "the named directory must stay visible: {:?}",
            plan.visible
        );
        assert!(
            plan.hides(&base.join("victim.sock")),
            "a sibling of the named directory must stay hidden"
        );
        assert!(
            !plan.visible.contains(&base),
            "the parent of the named directory must not be bound: {:?}",
            plan.visible
        );
        Ok(())
    }

    /// NET-3. A rule for a file below a private directory binds that file,
    /// not the directory that holds it.
    #[test]
    fn test_private_dirs_bind_a_named_file() -> TestResult {
        let temp = tempfile::Builder::new()
            .prefix("pent-net3-file-")
            .tempdir_in("/tmp")?;
        let base = std::fs::canonicalize(temp.path())?;
        let file = base.join("config.toml");
        std::fs::write(&file, b"x")?;
        let mut config = make_test_config();
        config.paths.read = vec![file.to_string_lossy().into_owned()];
        config.paths.traversal = vec![base.to_string_lossy().into_owned()];
        let plan = plan_private_dirs(&config, &[], &[], 4242);
        let target = CString::new(file.to_string_lossy().as_bytes()).unwrap_or_default();
        let bind = plan.binds.iter().find(|b| b.target == target);
        assert_eq!(
            bind.map(|b| b.kind),
            Some(BindKind::File),
            "the plan must bind the file itself"
        );
        assert!(plan.hides(&base.join("secret")));
        Ok(())
    }

    #[test]
    fn test_mount_point_parents() {
        let parents = mount_point_parents(Path::new("/tmp/a/b/c"), Path::new("/tmp"));
        let want: Vec<CString> = ["/tmp/a", "/tmp/a/b"]
            .iter()
            .filter_map(|p| CString::new(*p).ok())
            .collect();
        assert_eq!(parents, want);
        assert!(mount_point_parents(Path::new("/tmp/a"), Path::new("/tmp")).is_empty());
    }

    #[test]
    fn test_fd_path() {
        let mut buf = [0u8; FD_PATH_LEN];
        assert_eq!(fd_path(0, &mut buf), Some(c"/proc/self/fd/0"));
        let mut buf = [0u8; FD_PATH_LEN];
        assert_eq!(fd_path(1234, &mut buf), Some(c"/proc/self/fd/1234"));
        let mut buf = [0u8; FD_PATH_LEN];
        assert_eq!(fd_path(-1, &mut buf), None);
    }

    #[test]
    fn test_escape_sockets_hold_the_system_bus() {
        assert!(ESCAPE_SOCKETS.contains(&"/run/dbus/system_bus_socket"));
        assert!(ESCAPE_SOCKETS.contains(&"/var/run/dbus/system_bus_socket"));
        assert!(RESOLVER_SOCKETS.contains(&"/run/tailscale/tailscaled.sock"));
    }

    #[test]
    fn test_home_agent_sockets_find_a_gpg_socket() -> TestResult {
        use std::os::unix::net::UnixListener;
        let temp = tempfile::tempdir()?;
        let gnupg = temp.path().join(".gnupg");
        std::fs::create_dir_all(&gnupg)?;
        let socket = gnupg.join("S.gpg-agent.ssh");
        let listener = UnixListener::bind(&socket)?;
        let mut config = make_test_config();
        config.env.insert(
            "HOME".to_string(),
            temp.path().to_string_lossy().into_owned(),
        );
        let found = home_agent_sockets(&config);
        drop(listener);
        assert!(found.contains(&socket), "{found:?}");
        Ok(())
    }

    #[test]
    fn test_mask_targets_hide_a_home_agent_socket() -> TestResult {
        use std::os::unix::net::UnixListener;
        let temp = tempfile::tempdir()?;
        let ssh = temp.path().join(".ssh");
        std::fs::create_dir_all(&ssh)?;
        let socket = ssh.join("agent.4242");
        let listener = UnixListener::bind(&socket)?;
        let mut config = make_test_config();
        config.env.insert(
            "HOME".to_string(),
            temp.path().to_string_lossy().into_owned(),
        );
        let (_, files) = mask_targets(&config, 4242);
        let real = std::fs::canonicalize(&socket)?;
        drop(listener);
        assert!(files.contains(&real), "{files:?}");
        Ok(())
    }

    /// The layout of Ubuntu, of Fedora and of every host with
    /// `systemd-resolved`: `/etc/resolv.conf` is a relative symbolic link
    /// into `/run`. The test gives the link as data, so it runs on a host
    /// of any layout.
    #[test]
    fn test_resolv_target_follows_a_link_into_run() {
        let target = resolv_link_target(Path::new(RESOLV_CONF_PATH), |path| {
            if path == Path::new("/etc/resolv.conf") {
                Some(PathBuf::from("../run/systemd/resolve/stub-resolv.conf"))
            } else {
                None
            }
        });
        assert_eq!(
            target,
            Some(PathBuf::from("/run/systemd/resolve/stub-resolv.conf"))
        );
    }

    /// The plan of the child must hold the directory chain inside the tmpfs
    /// of `/run` and the bind at the target of the link. Without the chain
    /// the bind has no mount point, and the child reads no resolver.
    #[test]
    fn test_resolv_bind_makes_the_chain_inside_the_tmpfs() -> TestResult {
        let target = resolv_link_target(Path::new(RESOLV_CONF_PATH), |path| {
            if path == Path::new("/etc/resolv.conf") {
                Some(PathBuf::from("../run/systemd/resolve/stub-resolv.conf"))
            } else {
                None
            }
        })
        .ok_or("the link chain must have a target")?;
        let covered = vec![PathBuf::from("/tmp"), PathBuf::from("/run")];
        let source = Path::new("/run/user/1000/pent/resolv.conf");
        let bind = resolv_bind(source, &target, &covered).ok_or("the bind must exist")?;
        assert_eq!(
            bind.target.to_bytes(),
            b"/run/systemd/resolve/stub-resolv.conf"
        );
        let parents: Vec<&[u8]> = bind.parents.iter().map(|p| p.to_bytes()).collect();
        assert_eq!(parents, vec![&b"/run/systemd"[..], b"/run/systemd/resolve"]);
        assert_eq!(bind.kind, BindKind::File);
        assert_eq!(bind.access, BindAccess::ReadOnly);
        let mode = bind.forced_mode.ok_or("the bind must force the modes")?;
        assert_eq!((mode.dir, mode.file), (0o755, 0o644));
        Ok(())
    }

    /// A host where `/etc/resolv.conf` is a plain file (NixOS): the chain
    /// has no step, and the bind needs no directory above it.
    #[test]
    fn test_resolv_bind_of_a_plain_file_needs_no_chain() -> TestResult {
        let target = resolv_link_target(Path::new(RESOLV_CONF_PATH), |_| None)
            .ok_or("a plain file is its own target")?;
        assert_eq!(target, PathBuf::from("/etc/resolv.conf"));
        let covered = vec![PathBuf::from("/tmp"), PathBuf::from("/run")];
        let bind = resolv_bind(Path::new("/tmp/pent-1000/resolv.conf"), &target, &covered)
            .ok_or("the bind must exist")?;
        assert!(bind.parents.is_empty(), "{:?}", bind.parents);
        assert_eq!(bind.target.to_bytes(), b"/etc/resolv.conf");
        Ok(())
    }

    /// A chain of two links ends at the last path, and the chain stops at
    /// [`RESOLV_LINK_LIMIT`] steps, so a loop gives no target.
    #[test]
    fn test_resolv_target_follows_two_links_and_keeps_a_limit() {
        let two = |path: &Path| match path.to_str() {
            Some("/etc/resolv.conf") => Some(PathBuf::from("/run/resolvconf/resolv.conf")),
            Some("/run/resolvconf/resolv.conf") => {
                Some(PathBuf::from("../systemd/resolve/resolv.conf"))
            }
            _ => None,
        };
        assert_eq!(
            resolv_link_target(Path::new(RESOLV_CONF_PATH), two),
            Some(PathBuf::from("/run/systemd/resolve/resolv.conf"))
        );
        // A loop of two links. The limit ends the walk.
        let loop_links = |path: &Path| match path.to_str() {
            Some("/etc/resolv.conf") => Some(PathBuf::from("/run/a")),
            Some("/run/a") => Some(PathBuf::from("/run/b")),
            Some("/run/b") => Some(PathBuf::from("/run/a")),
            _ => None,
        };
        assert_eq!(
            resolv_link_target(Path::new(RESOLV_CONF_PATH), loop_links),
            None
        );
        // A chain of exactly the limit of links still has no end.
        let long = |path: &Path| {
            let name = path.to_str()?;
            let step: usize = name.strip_prefix("/run/step")?.parse().ok()?;
            Some(PathBuf::from(format!(
                "/run/step{}",
                step.saturating_add(1)
            )))
        };
        assert_eq!(resolv_link_target(Path::new("/run/step0"), long), None);
    }

    /// A link inside a private directory that points out of every private
    /// directory gives no target: pent does not control that path, so the
    /// child keeps no resolver and each name lookup fails.
    #[test]
    fn test_resolv_target_refuses_a_link_out_of_a_private_dir() {
        let out = |path: &Path| match path.to_str() {
            Some("/etc/resolv.conf") => Some(PathBuf::from("/run/resolvconf/resolv.conf")),
            Some("/run/resolvconf/resolv.conf") => Some(PathBuf::from("/etc/resolv.conf.host")),
            _ => None,
        };
        assert_eq!(resolv_link_target(Path::new(RESOLV_CONF_PATH), out), None);
    }

    #[test]
    fn test_is_explicitly_allowed() {
        let mask = Path::new("/run/user/1000");
        let ancestor_only = vec![PathBuf::from("/"), PathBuf::from("/run")];
        assert!(!is_explicitly_allowed(mask, &ancestor_only));
        let inside = vec![PathBuf::from("/run/user/1000/bus")];
        assert!(is_explicitly_allowed(mask, &inside));
        let exact = vec![PathBuf::from("/run/user/1000")];
        assert!(is_explicitly_allowed(mask, &exact));
        let sibling = vec![PathBuf::from("/run/user/10000")];
        assert!(!is_explicitly_allowed(mask, &sibling));
    }

    #[test]
    fn test_mask_targets_skip_configured_runtime_dir() {
        let mut paths = SandboxPaths::default();
        paths.read_write.push("/run/user/4242/app".to_string());
        let config = SandboxConfig::new(PathBuf::from("/tmp"), paths, PathBuf::from("/tmp"));
        let (dirs, _) = mask_targets(&config, 4242);
        assert!(!dirs.contains(&PathBuf::from("/run/user/4242")));
    }

    /// The child hides the host resolver sockets unless the network is
    /// unrestricted. The test checks only the sockets that exist here.
    #[test]
    fn test_mask_targets_hide_resolver_sockets() {
        let present: Vec<PathBuf> = RESOLVER_SOCKETS
            .iter()
            .filter_map(|s| std::fs::canonicalize(s).ok())
            .collect();
        let base = || {
            SandboxConfig::new(
                PathBuf::from("/tmp"),
                SandboxPaths::default(),
                PathBuf::from("/tmp"),
            )
        };
        let (_, restricted) = mask_targets(
            &base().with_network(NetworkMode::ProxyOnly {
                proxy_addr: crate::linux_proxynet::child_proxy_addr(),
                dns_port: crate::linux_proxynet::CHILD_DNS_PORT,
            }),
            4242,
        );
        let (_, open) = mask_targets(&base().with_network(NetworkMode::Unrestricted), 4242);
        for socket in &present {
            assert!(restricted.contains(socket), "{}", socket.display());
            assert!(!open.contains(socket), "{}", socket.display());
        }
    }

    #[test]
    fn test_write_helper_writes_all() -> TestResult {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        let (mut r, w) = std::os::unix::net::UnixStream::pair()?;
        write_all_fd(w.as_raw_fd(), b"abcd")?;
        drop(w);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        assert_eq!(buf, b"abcd");
        Ok(())
    }

    /// With no overlays and `LocalhostOnly`, the child must write its UID map
    /// before Landlock applies. A wrong order runs the child as UID 65534.
    #[test]
    #[serial]
    fn test_spawn_keeps_real_uid() -> TestResult {
        use std::collections::HashMap;
        if check_available().is_err() {
            return Ok(());
        }
        let (Some(sh), Some(id_bin)) = (which("sh"), which("id")) else {
            return Ok(()); // skip: no sh or id in PATH
        };
        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir)
        .with_network(NetworkMode::LocalhostOnly);
        let mut path_dirs = test_path_dirs(&sh);
        path_dirs.extend(test_path_dirs(&id_bin));
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let script = format!("[ \"$({} -u)\" = {uid} ]", id_bin.display());
        let (mut child, _overlay, _proxy) = spawn_with_landlock(
            &config,
            &sh.to_string_lossy(),
            &["-c".to_string(), script],
            &HashMap::new(),
            &path_dirs,
        )
        .map_err(|e| format!("spawn failed: {e:?}"))?;
        assert!(
            child.wait()?.success(),
            "the child must run with the real UID, not 65534"
        );
        Ok(())
    }

    /// `ProxyOnly` without privileges: the child makes the proxy listeners
    /// in its network namespace, and the parent receives them. The child
    /// reaches the proxy on 127.0.0.1:3128 and its DNS on 127.0.0.1:53, and
    /// it has no route to another address.
    #[test]
    #[serial]
    fn test_proxy_only_passes_the_listeners() -> TestResult {
        use std::io::Read as _;
        if check_available().is_err() || check_user_namespaces().is_err() {
            return Ok(());
        }
        let Some(bash) = which("bash") else {
            return Ok(()); // skip: the test uses /dev/tcp of bash
        };
        let dirs = make_test_dirs();
        let config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths::default(),
            dirs.workspace.clone(),
        )
        .with_data_dir(dirs.data_dir)
        .with_network(NetworkMode::ProxyOnly {
            proxy_addr: crate::linux_proxynet::child_proxy_addr(),
            dns_port: crate::linux_proxynet::CHILD_DNS_PORT,
        });
        // The first connection succeeds. A connection to a public address
        // fails at once (no route), so the script then writes "isolated".
        let script = "exec 3<>/dev/tcp/127.0.0.1/3128 && printf ok >&3; \
                      if (exec 4<>/dev/tcp/192.0.2.1/80) 2>/dev/null; then printf leak >&3; \
                      else printf ' isolated' >&3; fi; \
                      read -r ns < /etc/resolv.conf; \
                      [ \"$ns\" = 'nameserver 127.0.0.1' ] && printf ' resolv' >&3; \
                      [ \"$HTTPS_PROXY\" = http://127.0.0.1:3128 ] && printf ' env' >&3";
        let (mut child, _overlay, listeners) = spawn_with_landlock(
            &config,
            &bash.to_string_lossy(),
            &["-c".to_string(), script.to_string()],
            &std::collections::HashMap::new(),
            &test_path_dirs(&bash),
        )
        .map_err(|e| format!("spawn failed: {e:?}"))?;
        let listeners = listeners.ok_or("no proxy listeners")?;
        assert_eq!(listeners.dns_udp.local_addr()?.to_string(), "127.0.0.1:53");
        assert_eq!(listeners.dns_tcp.local_addr()?.to_string(), "127.0.0.1:53");
        let tcp = listeners.tcp.first().ok_or("no TCP listener")?;
        assert_eq!(tcp.local_addr()?.to_string(), "127.0.0.1:3128");
        let (mut conn, _) = tcp.accept()?;
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        let mut got = String::new();
        conn.read_to_string(&mut got)?;
        assert!(child.wait()?.success());
        assert_eq!(got, "ok isolated resolv env");
        Ok(())
    }

    // ========================================================================
    // Test helpers
    // ========================================================================

    /// A temp dir outside /tmp and /var/tmp (which the sandbox can always
    /// write), in the crate directory. Returns `None` if the crate directory
    /// is itself under a temp path.
    fn non_tmp_tempdir() -> Option<TempDir> {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"));
        if TEMP_PATHS.iter().any(|t| base.starts_with(t)) {
            return None;
        }
        tempfile::tempdir_in(base).ok()
    }

    /// The PATH of the test process as a child environment, and the PATH
    /// directories with their canonical targets (for the Landlock rules).
    fn host_path_env() -> (std::collections::HashMap<String, String>, Vec<PathBuf>) {
        let path = std::env::var("PATH").unwrap_or_default();
        let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
        for d in dirs.clone() {
            if let Ok(real) = std::fs::canonicalize(&d) {
                dirs.push(real);
            }
        }
        dirs.push(PathBuf::from("/bin"));
        dirs.push(PathBuf::from("/usr/bin"));
        let mut env = std::collections::HashMap::new();
        env.insert("PATH".to_string(), path);
        (env, dirs)
    }

    /// Find `name` in PATH (like `which`). Returns `None` if it is absent.
    fn which(name: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|d| d.join(name))
                .find(|p| p.is_file())
        })
    }

    /// PATH-like directories for a test binary: its directory and the
    /// directory of its canonical target.
    fn test_path_dirs(bin: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = bin.parent().map(Path::to_path_buf).into_iter().collect();
        if let Some(real) = std::fs::canonicalize(bin)
            .ok()
            .and_then(|r| r.parent().map(Path::to_path_buf))
        {
            v.push(real);
        }
        v.push(PathBuf::from("/usr/bin"));
        v.push(PathBuf::from("/bin"));
        v
    }

    #[test]
    fn access_policy_predicts_landlock() -> TestResult {
        use pent_profile::{FsOp, Outcome};
        let dirs = make_test_dirs();
        let mut config = SandboxConfig::new(
            dirs.workspace.clone(),
            SandboxPaths {
                traversal: vec!["/".to_string()],
                read: vec!["/etc".to_string()],
                execute: Vec::new(),
                read_write: Vec::new(),
            },
            dirs.workspace.clone(),
        );
        config.data_dir = dirs.data_dir.clone();
        let mut policy = AccessPolicy::default();
        add_ruleset_rules(
            &mut policy,
            &config,
            &[],
            &HashSet::new(),
            &HashSet::new(),
            None,
        );
        let ws = std::fs::canonicalize(&dirs.workspace)?;
        let allowed = Outcome::Allowed;
        let denied = Outcome::Denied;
        assert_eq!(
            policy.predict(FsOp::Read, Path::new("/etc/passwd"), false),
            allowed
        );
        assert_eq!(
            policy.predict(FsOp::Write, Path::new("/etc/passwd"), false),
            denied
        );
        assert_eq!(
            policy.predict(FsOp::Create, Path::new("/etc/new"), false),
            denied
        );
        assert_eq!(
            policy.predict(FsOp::Create, &ws.join("new"), false),
            allowed
        );
        assert_eq!(
            policy.predict(FsOp::Delete, &ws.join("old"), false),
            allowed
        );
        // The traversal grant on / allows a directory listing, not a read.
        assert_eq!(policy.predict(FsOp::Read, Path::new("/var"), true), allowed);
        assert_eq!(
            policy.predict(FsOp::Read, Path::new("/var/x"), false),
            denied
        );
        assert_eq!(
            policy.predict(FsOp::Exec, Path::new("/var/x"), false),
            denied
        );
        Ok(())
    }

    /// DIFF-1. A read that the overlay hides must be a recorded denial.
    /// Landlock permits the path, because the rule of the overlay mount
    /// point covers the whole home directory; the upper layer hides each
    /// path that the profile does not name.
    #[test]
    fn access_policy_reports_a_path_that_the_overlay_hides() -> TestResult {
        use pent_profile::{FsOp, Outcome};
        let tmp = tempfile::tempdir()?;
        let home = std::fs::canonicalize(tmp.path())?;
        let open = home.join("open.txt");
        let secret = home.join("secret.txt");
        std::fs::write(&open, "o")?;
        std::fs::write(&secret, "s")?;
        let mut policy = AccessPolicy::default();
        // The rule of the overlay mount point, as `add_ruleset_rules`
        // makes it.
        policy.add_rule(&home, access::ALL_NO_EXECUTE);
        let roots: HashSet<PathBuf> = [home.clone()].into_iter().collect();
        let shown: HashSet<PathBuf> = [open.clone()].into_iter().collect();
        policy.set_overlay(&roots, &shown);
        assert_eq!(policy.predict(FsOp::Read, &open, false), Outcome::Allowed);
        assert_eq!(policy.predict(FsOp::Read, &secret, false), Outcome::Denied);
        // The mount point itself and a parent of a shown path stay open.
        assert_eq!(policy.predict(FsOp::Read, &home, true), Outcome::Allowed);
        // A write goes to the upper layer and works inside the run.
        assert_eq!(
            policy.predict(FsOp::Write, &secret, false),
            Outcome::Allowed
        );
        Ok(())
    }
}
