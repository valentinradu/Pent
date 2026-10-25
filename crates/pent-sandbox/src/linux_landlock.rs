//! Raw Landlock and seccomp helpers for the Linux backend.
//!
//! The parent process prepares all data before `fork`. The parent detects the
//! Landlock ABI, creates the ruleset file descriptor and converts each path
//! rule to a `CString` and an access mask. The child (in `pre_exec`) then uses
//! only raw system calls on this prepared data. The child does not allocate,
//! does not lock and does not use `std::fs`.
//!
//! The child adds the path rules after it mounts overlayfs and the other
//! private mounts. Landlock binds a rule to an inode. Thus the child must open
//! each path after the mounts, so that the rule binds to the inode that the
//! sandboxed process sees.
//!
//! # Enforcement level
//!
//! Pent requires Landlock ABI v3 or later (Linux 6.2). ABI v3 is the first ABI
//! that controls `truncate(2)`. Without it, a read-only file can be truncated.
//! Pent handles all the rights that the running kernel supports, up to ABI v6:
//!
//! - v2: `Refer` (rename and link across directories).
//! - v3: `Truncate`.
//! - v5: `IoctlDev` (`ioctl(2)` on device files that the process opens).
//! - v6: the `AbstractUnixSocket` and `Signal` scopes.
//!
//! Pent uses the raw system calls. A successful `landlock_create_ruleset`
//! with these rights and a successful `landlock_restrict_self` mean full
//! enforcement. There is no "best effort" mode.
//!
//! # Limits
//!
//! Landlock (ABI v6 and earlier) does not control `connect(2)` on Unix
//! sockets that have a path. A sandboxed process can connect to any socket
//! file that it can find. Pent decreases this risk with private mounts that
//! hide the well-known sockets (see `linux.rs`).
#![allow(unreachable_pub)]

use crate::SandboxError;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// The minimum Landlock ABI that pent accepts.
pub const MIN_ABI: u32 = 3;

/// The highest Landlock ABI that pent knows.
pub const MAX_KNOWN_ABI: u32 = 6;

/// Landlock filesystem access rights (from `<linux/landlock.h>`).
pub mod access {
    /// Execute a file.
    pub const EXECUTE: u64 = 1 << 0;
    /// Open a file with write access.
    pub const WRITE_FILE: u64 = 1 << 1;
    /// Open a file with read access.
    pub const READ_FILE: u64 = 1 << 2;
    /// Open a directory or list its content.
    pub const READ_DIR: u64 = 1 << 3;
    // Bits 4 to 12 are REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR,
    // MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK and MAKE_SYM. Pent grants
    // them only together, through `ALL`.
    /// Remove a file from a directory. Only the policy prediction of the
    /// recorder uses this bit by itself.
    pub const REMOVE_FILE: u64 = 1 << 5;
    /// Create a regular file in a directory. Only the policy prediction of
    /// the recorder uses this bit by itself.
    pub const MAKE_REG: u64 = 1 << 8;
    /// Link or rename a file from or to a different directory (ABI v2).
    pub const REFER: u64 = 1 << 13;
    /// Truncate a file (ABI v3).
    pub const TRUNCATE: u64 = 1 << 14;
    /// Send `ioctl(2)` to a device file (ABI v5).
    pub const IOCTL_DEV: u64 = 1 << 15;

    /// The rights that apply to a file that is not a directory.
    pub const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

    /// Read files and list directories. No execution.
    pub const READ: u64 = READ_FILE | READ_DIR;
    /// List directories and execute files. No file reads.
    pub const EXECUTE_ONLY: u64 = READ_DIR | EXECUTE;
    /// Read, list and execute. The dynamic linker must read the libraries.
    pub const READ_EXECUTE: u64 = READ_FILE | READ_DIR | EXECUTE;
    /// List directories only.
    pub const TRAVERSAL: u64 = READ_DIR;
    /// All rights. The ruleset mask removes the rights that the kernel does
    /// not support.
    pub const ALL: u64 = (1 << 16) - 1;
}

/// Landlock scope flags (ABI v6).
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

/// Mirrors `struct landlock_ruleset_attr` (ABI v6 size).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// Mirrors `struct landlock_path_beneath_attr`. The kernel struct is packed.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Return the filesystem rights that ABI `abi` supports.
#[must_use]
pub const fn handled_fs_for_abi(abi: u32) -> u64 {
    let mut mask = (1 << 13) - 1; // ABI v1
    if abi >= 2 {
        mask |= access::REFER;
    }
    if abi >= 3 {
        mask |= access::TRUNCATE;
    }
    if abi >= 5 {
        mask |= access::IOCTL_DEV;
    }
    mask
}

/// Return the scope flags that ABI `abi` supports.
#[must_use]
pub const fn scopes_for_abi(abi: u32) -> u64 {
    if abi >= 6 {
        SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
    } else {
        0
    }
}

/// Return the Landlock ABI version of the running kernel.
///
/// Calls `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
/// This call tells if Landlock is compiled in *and* enabled at boot.
///
/// # Errors
/// Returns `SandboxUnavailable` if Landlock is absent, disabled, or older
/// than [`MIN_ABI`].
pub fn abi_version() -> Result<u32, SandboxError> {
    // SAFETY: the call takes a null attribute pointer and a zero size with the
    // VERSION flag. The kernel reads no memory and only returns an integer.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        let reason = match err.raw_os_error() {
            Some(libc::ENOSYS) => "Landlock is not compiled into this kernel".to_string(),
            Some(libc::EOPNOTSUPP) => "Landlock is disabled on this system".to_string(),
            _ => format!("Landlock is not available: {err}"),
        };
        return Err(SandboxError::SandboxUnavailable {
            reason,
            remediation: "Use Linux 6.2 or later and add \"landlock\" to the lsm= kernel \
                          boot parameter (or to CONFIG_LSM)"
                .to_string(),
        });
    }
    let abi = u32::try_from(ret).unwrap_or(0);
    if abi < MIN_ABI {
        return Err(SandboxError::SandboxUnavailable {
            reason: format!("Landlock ABI v{abi} is too old; pent requires ABI v{MIN_ABI}"),
            remediation: "Upgrade to Linux 6.2 or later".to_string(),
        });
    }
    Ok(abi)
}

/// One path rule, prepared in the parent.
#[derive(Debug)]
struct PreparedRule {
    path: CString,
    access: u64,
}

/// A Landlock ruleset that the parent creates and the child applies.
#[derive(Debug)]
pub struct PreparedRuleset {
    fd: OwnedFd,
    handled: u64,
    rules: Vec<PreparedRule>,
}

impl PreparedRuleset {
    /// Create the ruleset file descriptor for the highest ABI available.
    ///
    /// # Errors
    /// Returns `SandboxUnavailable` if Landlock is not usable, or
    /// `SpawnFailed` if the kernel refuses the ruleset.
    pub fn create() -> Result<Self, SandboxError> {
        let abi = abi_version()?.min(MAX_KNOWN_ABI);
        let handled = handled_fs_for_abi(abi);
        let attr = RulesetAttr {
            handled_access_fs: handled,
            handled_access_net: 0,
            scoped: scopes_for_abi(abi),
        };
        // SAFETY: `attr` is a valid, initialized struct and the size argument
        // is its exact size. The kernel accepts a larger struct if the extra
        // fields are zero, so this is correct for all ABI versions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::addr_of!(attr),
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if ret < 0 {
            return Err(SandboxError::SpawnFailed(std::io::Error::last_os_error()));
        }
        let raw = libc::c_int::try_from(ret).map_err(|_| {
            SandboxError::SpawnFailed(std::io::Error::from_raw_os_error(libc::EBADF))
        })?;
        // SAFETY: the kernel returned a new file descriptor that this process
        // owns. The kernel sets O_CLOEXEC on a ruleset file descriptor.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd,
            handled,
            rules: Vec::new(),
        })
    }

    /// Record a rule that grants `access` beneath `path`.
    ///
    /// The child opens the path later. A path that does not exist at that
    /// time is skipped. A path with a NUL byte cannot exist and is skipped.
    pub fn add(&mut self, path: &Path, access: u64) {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(path) = CString::new(path.as_os_str().as_bytes()) {
            self.rules.push(PreparedRule { path, access });
        }
    }

    /// Add all rules to the ruleset and restrict the calling process.
    ///
    /// The caller must set `PR_SET_NO_NEW_PRIVS` first.
    ///
    /// # Safety
    /// Call this only in a `pre_exec` hook. The function uses only raw system
    /// calls on data that the parent prepared. It does not allocate.
    ///
    /// # Errors
    /// Returns the OS error of the first system call that fails.
    pub unsafe fn apply_in_child(&self) -> std::io::Result<()> {
        let ruleset_fd = self.fd.as_raw_fd();
        for rule in &self.rules {
            let fd = libc::open(rule.path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES | libc::ELOOP) => continue,
                    _ => return Err(err),
                }
            }
            let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
            if libc::fstat(fd, st.as_mut_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            let st = st.assume_init();
            let mut allowed = rule.access & self.handled;
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                allowed &= access::FILE_RIGHTS;
            }
            if allowed != 0 {
                let attr = PathBeneathAttr {
                    allowed_access: allowed,
                    parent_fd: fd,
                };
                let ret = libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    std::ptr::addr_of!(attr),
                    0u32,
                );
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    libc::close(fd);
                    // EBADFD: the path is on an internal filesystem (a pipe
                    // or a socket through /proc/self/fd). Landlock does not
                    // control such files, so no rule is necessary.
                    if err.raw_os_error() == Some(libc::EBADFD) {
                        continue;
                    }
                    return Err(err);
                }
            }
            libc::close(fd);
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// ── seccomp: deny TIOCSTI and TIOCLINUX ─────────────────────────────────────
//
// A sandboxed process keeps the controlling terminal, because interactive
// tools need it. `ioctl(TIOCSTI)` pushes bytes into the input queue of the
// terminal. The parent shell reads these bytes after the sandbox exits, so
// the sandboxed process can run commands outside the sandbox. `TIOCLINUX`
// has a similar subcommand on the Linux virtual console. Landlock `IoctlDev`
// does not help here: it applies only to files that the process opens after
// the restriction, and the terminal file descriptor is inherited.
//
// This filter returns EPERM for these two requests and allows all other
// system calls. bubblewrap uses the same filter.

// Classic BPF opcodes: BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K and
// BPF_RET|BPF_K (BPF_LD, BPF_W and BPF_K are zero).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x05 | 0x10;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
// The cast is exact: EPERM is 1.
#[allow(clippy::cast_sign_loss)]
const RET_EPERM: u32 = SECCOMP_RET_ERRNO | (libc::EPERM as u32);
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
/// Low 32 bits of `args[1]` (the `ioctl` request) on a little-endian CPU.
const OFF_ARG1_LO: u32 = 24;
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541C;

const fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt,
        jf,
        k,
    }
}

#[cfg(target_arch = "x86_64")]
const TIOCSTI_FILTER: &[libc::sock_filter] = &[
    /* 0 */ stmt(BPF_LD_W_ABS, OFF_ARCH),
    /* 1 */ jeq(0xC000_003E, 0, 3), // AUDIT_ARCH_X86_64, else 5
    /* 2 */ stmt(BPF_LD_W_ABS, OFF_NR),
    /* 3 */ jeq(16, 4, 0), // ioctl -> 8
    /* 4 */ jeq(0x4000_0000 | 514, 3, 6), // x32 ioctl -> 8, else 11
    /* 5 */ jeq(0x4000_0003, 0, 5), // AUDIT_ARCH_I386, else 11
    /* 6 */ stmt(BPF_LD_W_ABS, OFF_NR),
    /* 7 */ jeq(54, 0, 3), // i386 ioctl -> 8, else 11
    /* 8 */ stmt(BPF_LD_W_ABS, OFF_ARG1_LO),
    /* 9 */ jeq(TIOCSTI, 2, 0), // -> 12
    /* 10 */ jeq(TIOCLINUX, 1, 0), // -> 12
    /* 11 */ stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    /* 12 */ stmt(BPF_RET_K, RET_EPERM),
];

#[cfg(target_arch = "aarch64")]
const TIOCSTI_FILTER: &[libc::sock_filter] = &[
    /* 0 */ stmt(BPF_LD_W_ABS, OFF_ARCH),
    /* 1 */ jeq(0xC000_00B7, 0, 2), // AUDIT_ARCH_AARCH64, else 4
    /* 2 */ stmt(BPF_LD_W_ABS, OFF_NR),
    /* 3 */ jeq(29, 3, 6), // ioctl -> 7, else 10
    /* 4 */ jeq(0x4000_0028, 0, 5), // AUDIT_ARCH_ARM, else 10
    /* 5 */ stmt(BPF_LD_W_ABS, OFF_NR),
    /* 6 */ jeq(54, 0, 3), // arm ioctl -> 7, else 10
    /* 7 */ stmt(BPF_LD_W_ABS, OFF_ARG1_LO),
    /* 8 */ jeq(TIOCSTI, 2, 0), // -> 11
    /* 9 */ jeq(TIOCLINUX, 1, 0), // -> 11
    /* 10 */ stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    /* 11 */ stmt(BPF_RET_K, RET_EPERM),
];

/// Install the seccomp filter that denies `ioctl(TIOCSTI)` and
/// `ioctl(TIOCLINUX)`.
///
/// The caller must set `PR_SET_NO_NEW_PRIVS` first. On a CPU architecture
/// without a filter, the function does nothing.
///
/// # Safety
/// Call this only in a `pre_exec` hook (or in a process that accepts the
/// filter for its whole life). The function uses only `prctl(2)` on static
/// data.
///
/// # Errors
/// Returns the OS error if the kernel refuses the filter.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub unsafe fn install_tiocsti_filter() -> std::io::Result<()> {
    // The filter has fewer than 20 instructions, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    let prog = libc::sock_fprog {
        len: TIOCSTI_FILTER.len() as libc::c_ushort,
        filter: TIOCSTI_FILTER.as_ptr().cast_mut(),
    };
    if libc::prctl(
        libc::PR_SET_SECCOMP,
        libc::SECCOMP_MODE_FILTER,
        std::ptr::addr_of!(prog),
        0,
        0,
    ) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No filter exists for this CPU architecture.
///
/// # Safety
/// The function does nothing.
///
/// # Errors
/// The function does not fail.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn install_tiocsti_filter() -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handled_fs_grows_with_abi() {
        assert_eq!(handled_fs_for_abi(1) & access::REFER, 0);
        assert_ne!(handled_fs_for_abi(2) & access::REFER, 0);
        assert_eq!(handled_fs_for_abi(2) & access::TRUNCATE, 0);
        assert_ne!(handled_fs_for_abi(3) & access::TRUNCATE, 0);
        assert_eq!(handled_fs_for_abi(4) & access::IOCTL_DEV, 0);
        assert_ne!(handled_fs_for_abi(5) & access::IOCTL_DEV, 0);
        assert_eq!(handled_fs_for_abi(6), access::ALL);
    }

    #[test]
    fn test_scopes_only_on_v6() {
        assert_eq!(scopes_for_abi(5), 0);
        assert_eq!(scopes_for_abi(6), SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL);
    }

    #[test]
    fn test_execute_only_excludes_read_file() {
        assert_eq!(access::EXECUTE_ONLY & access::READ_FILE, 0);
        assert_ne!(access::READ_EXECUTE & access::READ_FILE, 0);
        assert_eq!(access::READ & access::EXECUTE, 0);
    }

    #[test]
    fn test_abi_version_meets_minimum_or_errors() {
        match abi_version() {
            Ok(abi) => assert!(abi >= MIN_ABI),
            Err(e) => assert!(
                matches!(e, SandboxError::SandboxUnavailable { .. }),
                "unexpected error: {e:?}"
            ),
        }
    }

    /// Fork a child, install the filter there, and check the `ioctl` result.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn test_tiocsti_filter_returns_eperm() {
        // SAFETY: the child uses only async-signal-safe calls and `_exit`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // SAFETY: raw system calls in the forked child, then `_exit`.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(10);
                }
                if install_tiocsti_filter().is_err() {
                    libc::_exit(11);
                }
                // fd -1: without the filter the kernel returns EBADF.
                let c = 0u8;
                let r = libc::ioctl(-1, libc::TIOCSTI, &c);
                let e = *libc::__errno_location();
                if r != -1 || e != libc::EPERM {
                    libc::_exit(12);
                }
                let mut ws = std::mem::zeroed::<libc::winsize>();
                let r = libc::ioctl(-1, libc::TIOCGWINSZ, &mut ws);
                let e = *libc::__errno_location();
                if r != -1 || e != libc::EBADF {
                    libc::_exit(13);
                }
                libc::_exit(0);
            }
        }
        let mut status = 0;
        // SAFETY: wait for the child that this test forked.
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(ret, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0, "filter check failed");
    }
}
