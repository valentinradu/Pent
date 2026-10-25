//! Watch mode on Linux: the guard and the seccomp recorder.
//!
//! # The guard
//!
//! Watch mode does not sandbox the program. The child gets a private mount
//! namespace, and pent makes the mounts of the guard in it before `exec`:
//!
//! - A read guard on a file: a read-only bind mount of `/dev/null`.
//! - A read guard on a directory: an empty, read-only tmpfs.
//! - A write guard: a read-only bind mount of the target on itself.
//! - An exec guard (`sudo`, ...): `PR_SET_NO_NEW_PRIVS` makes setuid
//!   binaries fail. Pent only marks the attempt.
//!
//! A bind mount needs a target that exists. For a write guard on a path that
//! does not exist when the child starts (for example `~/.zshrc`), the
//! supervisor denies the create or the write itself with EACCES and reports
//! `Outcome::Blocked`. Another thread of the process can race that check, so
//! it stops accidents, not a hostile program. A read guard on a path that
//! does not exist needs no protection: there is nothing to read.
//!
//! # The recorder
//!
//! The child installs a seccomp filter as the last step before `exec`. The
//! filter returns `SECCOMP_RET_USER_NOTIF` for the path system calls (see
//! `CALLS`) and `ENOSYS` for `io_uring_setup`, because seccomp does not see
//! io_uring operations. Runtimes then use normal system calls.
//!
//! The listener file descriptor goes to the parent with `SCM_RIGHTS` over a
//! socket pair. This needs no ptrace permission and no extra round trip: the
//! child sends the descriptor, closes its copy and continues to `exec`. If
//! the child dies before it sends, the supervisor reads EOF.
//!
//! A supervisor thread in the parent receives each notification. It reads
//! the path from the memory of the process (`process_vm_readv`), resolves it
//! against `/proc/PID/cwd` or the directory descriptor, checks with
//! `SECCOMP_IOCTL_NOTIF_ID_VALID` that the data is still valid, and answers
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The recorder only observes: another
//! thread can change the path after the check, so seccomp-notify is not
//! usable for enforcement.
//!
//! The filter returns `ENOSYS` for each system call of another ABI (i386
//! and x32 on x86_64, arm32 on aarch64), so that such a call cannot bypass
//! the recorder. Thus a 32-bit program does not run under the recorder.
//!
//! The same recorder runs next to Landlock for `pent run --trace`
//! (`SandboxConfig::record_events`). Seccomp sees a call before Landlock
//! decides, so the recorder predicts the decision (see `AccessPolicy` in
//! `linux.rs`). The filter also blocks `io_uring_setup` in this mode. A
//! program that uses io_uring then falls back to normal system calls; this
//! change occurs only with `--trace`.
//!
//! On Linux 6.6 and later, the supervisor asks for synchronous wake-ups
//! (`SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`). This decreases the cost of one
//! notification.
//!
//! The supervisor fails open. On each error it answers `CONTINUE` and logs.
//! It never stops while a process uses the filter: if the listener closes,
//! each recorded system call of the program fails with `ENOSYS`.
//!
//! The kernel reports `POLLHUP` on the listener when no task uses the filter
//! any more. A task stops to use the filter when its parent reaps it. Then
//! the supervisor ends and the event channel closes. Thus the caller must
//! wait for the direct child before it waits for the end of the channel.
//!
//! # Paths
//!
//! The recorder makes each path absolute and removes `.` and `..` without a
//! look at the filesystem. It does not resolve the symbolic links in the
//! directories. For a system call that follows a symbolic link in the last
//! component, the recorder emits the link path and also the canonical target.
//! The recorder drops a call that fails for certain: a read, write, exec or
//! delete of a path that does not exist, and a create of a path that exists.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;

use pent_profile::{
    classify, FsOp, GuardAccess, GuardRule, GuardTarget, Outcome, ProcessInfo, WatchEvent,
};

use crate::linux::{AccessPolicy, SpawnMode};
use crate::{SandboxChild, SandboxConfig, SandboxError, WatchOptions, WatchedChild};

// ── The guard ───────────────────────────────────────────────────────────────

/// The mounts of the watch guard, and the rules that they enforce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GuardPlan {
    /// The paths to bind-mount read-only on themselves (write guard).
    pub(crate) ro_binds: Vec<PathBuf>,
    /// The directories to hide with an empty, read-only tmpfs (read guard).
    pub(crate) mask_dirs: Vec<PathBuf>,
    /// The files to hide with a read-only bind mount of `/dev/null` (read
    /// guard).
    pub(crate) mask_files: Vec<PathBuf>,
    /// The rules that the mounts enforce. The recorder classifies each event
    /// with these rules. A rule on a path that did not exist at the start is
    /// not in this list.
    pub(crate) effective: Vec<GuardRule>,
    /// The write rules on paths that did not exist at the start. A bind mount
    /// cannot enforce them, so the supervisor denies a write or a create on
    /// these paths itself (see [`Judge::denies`]).
    pub(crate) unenforced: Vec<GuardRule>,
}

impl GuardPlan {
    /// Add the mount for `rule` on the existing `path`. Skip a path that does
    /// not exist.
    fn add_existing(&mut self, rule: &GuardRule, path: &Path) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let Ok(real) = std::fs::canonicalize(path) else {
            return;
        };
        let is_dir = meta.is_dir();
        match rule.access {
            GuardAccess::Read if is_dir => self.mask_dirs.push(real.clone()),
            GuardAccess::Read => self.mask_files.push(real.clone()),
            GuardAccess::Write => self.ro_binds.push(real.clone()),
            GuardAccess::ExecName => return,
        }
        let mut add_rule = |p: &Path| {
            let target = if is_dir {
                GuardTarget::Subtree(p.to_path_buf())
            } else {
                GuardTarget::Exact(p.to_path_buf())
            };
            let r = GuardRule {
                class: rule.class,
                access: rule.access,
                target,
            };
            if !self.effective.contains(&r) {
                self.effective.push(r);
            }
        };
        add_rule(path);
        if real != path {
            add_rule(&real);
        }
    }

    /// Sort the mount lists, remove duplicates, and remove each mask below a
    /// masked directory. The empty tmpfs hides such a path, so a mount on it
    /// fails.
    fn finish(&mut self) {
        for list in [
            &mut self.ro_binds,
            &mut self.mask_dirs,
            &mut self.mask_files,
        ] {
            list.sort();
            list.dedup();
        }
        let dirs = self.mask_dirs.clone();
        let below_other = |p: &PathBuf| dirs.iter().any(|d| d != p && p.starts_with(d));
        self.mask_dirs.retain(|p| !below_other(p));
        self.mask_files.retain(|p| !below_other(p));
    }
}

/// Compute the mounts for the guard `rules`. The function looks at the
/// filesystem: only paths that exist get a mount.
#[must_use]
pub(crate) fn plan_guard(rules: &[GuardRule]) -> GuardPlan {
    let mut plan = GuardPlan::default();
    for rule in rules {
        match (&rule.access, &rule.target) {
            (GuardAccess::ExecName, GuardTarget::BinaryName(_)) => {
                plan.effective.push(rule.clone());
            }
            (
                GuardAccess::Read | GuardAccess::Write,
                GuardTarget::Exact(p) | GuardTarget::Subtree(p),
            ) => {
                if rule.access == GuardAccess::Write && std::fs::symlink_metadata(p).is_err() {
                    plan.unenforced.push(rule.clone());
                } else {
                    plan.add_existing(rule, p);
                }
            }
            (GuardAccess::Read | GuardAccess::Write, GuardTarget::FilesInDir { dir, .. }) => {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if rule.matches(&path, rule.access) {
                        plan.add_existing(rule, &path);
                    }
                }
            }
            // A target that does not fit the access has no effect.
            _ => {}
        }
    }
    plan.finish();
    plan
}

// ── The seccomp filter ──────────────────────────────────────────────────────

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
// The cast is exact: ENOSYS is 38.
#[allow(clippy::cast_sign_loss)]
const RET_ENOSYS: u32 = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32);
const RET_NOTIFY: u32 = libc::SECCOMP_RET_USER_NOTIF;
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
/// The x32 ABI on x86_64 sets this bit in the system call number.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

/// The input of [`build_filter`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct FilterSpec<'a> {
    /// The `AUDIT_ARCH_*` value of the native ABI. A system call of another
    /// ABI gets `ENOSYS`, so that it cannot bypass the recorder.
    pub(crate) audit_arch: u32,
    /// A system call number at or above this value belongs to another ABI
    /// with the same `AUDIT_ARCH` (x32 on x86_64). It gets `ENOSYS`.
    pub(crate) foreign_nr_min: Option<u32>,
    /// The system calls that get `ENOSYS`.
    pub(crate) enosys: &'a [u32],
    /// The system calls that go to the supervisor.
    pub(crate) notify: &'a [u32],
}

const fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build the classic BPF program of the recorder.
///
/// The layout:
///
/// ```text
/// ld arch; jeq NATIVE else -> ENOSYS
/// ld nr
/// jge FOREIGN_MIN -> ENOSYS        (x86_64 only)
/// jeq E1 -> ENOSYS ...             (io_uring_setup)
/// jeq N1 -> NOTIFY ...             (the path system calls)
/// ret ALLOW
/// ret USER_NOTIF
/// ret ERRNO(ENOSYS)
/// ```
///
/// # Errors
/// Returns `InvalidConfig` if a jump is longer than 255 instructions.
pub(crate) fn build_filter(spec: &FilterSpec<'_>) -> Result<Vec<libc::sock_filter>, SandboxError> {
    let checks = spec.enosys.len() + spec.notify.len() + usize::from(spec.foreign_nr_min.is_some());
    let len = checks + 6;
    let ret_notify = len - 2;
    let ret_enosys = len - 1;
    let offset = |from: usize, to: usize| -> Result<u8, SandboxError> {
        to.checked_sub(from + 1)
            .and_then(|d| u8::try_from(d).ok())
            .ok_or_else(|| SandboxError::InvalidConfig("the seccomp filter is too long".into()))
    };
    let mut prog = Vec::with_capacity(len);
    prog.push(stmt(BPF_LD_W_ABS, OFF_ARCH));
    prog.push(jump(
        BPF_JMP_JEQ_K,
        spec.audit_arch,
        0,
        offset(1, ret_enosys)?,
    ));
    prog.push(stmt(BPF_LD_W_ABS, OFF_NR));
    if let Some(min) = spec.foreign_nr_min {
        let i = prog.len();
        prog.push(jump(BPF_JMP_JGE_K, min, offset(i, ret_enosys)?, 0));
    }
    for &nr in spec.enosys {
        let i = prog.len();
        prog.push(jump(BPF_JMP_JEQ_K, nr, offset(i, ret_enosys)?, 0));
    }
    for &nr in spec.notify {
        let i = prog.len();
        prog.push(jump(BPF_JMP_JEQ_K, nr, offset(i, ret_notify)?, 0));
    }
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, RET_NOTIFY));
    prog.push(stmt(BPF_RET_K, RET_ENOSYS));
    Ok(prog)
}

// ── The recorded system calls ───────────────────────────────────────────────

/// Where a system call has its path: the index of the directory descriptor
/// argument (`None` for `AT_FDCWD`) and of the path argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathArg {
    dirfd: Option<usize>,
    path: usize,
}

/// Where an open call has its flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenFlags {
    /// In an argument.
    Arg(usize),
    /// In the `struct open_how` that an argument points to (`openat2`).
    OpenHow(usize),
    /// `creat(2)`: `O_CREAT | O_WRONLY | O_TRUNC`.
    Creat,
}

/// The kind of a recorded system call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Open(PathArg, OpenFlags),
    /// The second field is the index of the flags argument (`execveat`).
    Exec(PathArg, Option<usize>),
    Create(PathArg),
    Delete(PathArg),
    Rename(PathArg, PathArg),
    Truncate(PathArg),
    Connect,
}

const fn p(path: usize) -> PathArg {
    PathArg { dirfd: None, path }
}

const fn at(dirfd: usize, path: usize) -> PathArg {
    PathArg {
        dirfd: Some(dirfd),
        path,
    }
}

/// The recorded system calls of the native ABI.
#[cfg(target_arch = "x86_64")]
const CALLS: &[(libc::c_long, Call)] = &[
    (libc::SYS_open, Call::Open(p(0), OpenFlags::Arg(1))),
    (libc::SYS_openat, Call::Open(at(0, 1), OpenFlags::Arg(2))),
    (
        libc::SYS_openat2,
        Call::Open(at(0, 1), OpenFlags::OpenHow(2)),
    ),
    (libc::SYS_creat, Call::Open(p(0), OpenFlags::Creat)),
    (libc::SYS_execve, Call::Exec(p(0), None)),
    (libc::SYS_execveat, Call::Exec(at(0, 1), Some(4))),
    (libc::SYS_mkdir, Call::Create(p(0))),
    (libc::SYS_mkdirat, Call::Create(at(0, 1))),
    (libc::SYS_unlink, Call::Delete(p(0))),
    (libc::SYS_unlinkat, Call::Delete(at(0, 1))),
    (libc::SYS_rmdir, Call::Delete(p(0))),
    (libc::SYS_rename, Call::Rename(p(0), p(1))),
    (libc::SYS_renameat, Call::Rename(at(0, 1), at(2, 3))),
    (libc::SYS_renameat2, Call::Rename(at(0, 1), at(2, 3))),
    (libc::SYS_link, Call::Create(p(1))),
    (libc::SYS_linkat, Call::Create(at(2, 3))),
    (libc::SYS_symlink, Call::Create(p(1))),
    (libc::SYS_symlinkat, Call::Create(at(1, 2))),
    (libc::SYS_truncate, Call::Truncate(p(0))),
    (libc::SYS_connect, Call::Connect),
];

/// The recorded system calls of the native ABI. The generic system call
/// table of aarch64 has only the `*at` forms.
#[cfg(target_arch = "aarch64")]
const CALLS: &[(libc::c_long, Call)] = &[
    (libc::SYS_openat, Call::Open(at(0, 1), OpenFlags::Arg(2))),
    (
        libc::SYS_openat2,
        Call::Open(at(0, 1), OpenFlags::OpenHow(2)),
    ),
    (libc::SYS_execve, Call::Exec(p(0), None)),
    (libc::SYS_execveat, Call::Exec(at(0, 1), Some(4))),
    (libc::SYS_mkdirat, Call::Create(at(0, 1))),
    (libc::SYS_unlinkat, Call::Delete(at(0, 1))),
    (libc::SYS_renameat, Call::Rename(at(0, 1), at(2, 3))),
    (libc::SYS_renameat2, Call::Rename(at(0, 1), at(2, 3))),
    (libc::SYS_linkat, Call::Create(at(2, 3))),
    (libc::SYS_symlinkat, Call::Create(at(1, 2))),
    (libc::SYS_truncate, Call::Truncate(p(0))),
    (libc::SYS_connect, Call::Connect),
];

/// No recorder exists for this CPU architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const CALLS: &[(libc::c_long, Call)] = &[];

#[cfg(target_arch = "x86_64")]
const NATIVE: Option<(u32, Option<u32>)> = Some((0xC000_003E, Some(X32_SYSCALL_BIT)));
#[cfg(target_arch = "aarch64")]
const NATIVE: Option<(u32, Option<u32>)> = Some((0xC000_00B7, None));
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE: Option<(u32, Option<u32>)> = None;

/// Return the call kind of the native system call `nr`.
fn decode(nr: i32) -> Option<Call> {
    let nr = libc::c_long::from(nr);
    CALLS.iter().find(|(n, _)| *n == nr).map(|(_, c)| *c)
}

/// Build the filter for the native ABI.
fn native_filter() -> Result<Vec<libc::sock_filter>, SandboxError> {
    let Some((audit_arch, foreign_nr_min)) = NATIVE else {
        return Err(SandboxError::SandboxUnavailable {
            reason: "the seccomp recorder does not support this CPU architecture".into(),
            remediation: "Use x86_64 or aarch64".into(),
        });
    };
    let to_u32 = |n: libc::c_long| {
        u32::try_from(n).map_err(|_| SandboxError::InvalidConfig(format!("system call {n}")))
    };
    let notify = CALLS
        .iter()
        .map(|(n, _)| to_u32(*n))
        .collect::<Result<Vec<_>, _>>()?;
    let enosys = [to_u32(libc::SYS_io_uring_setup)?];
    build_filter(&FilterSpec {
        audit_arch,
        foreign_nr_min,
        enosys: &enosys,
        notify: &notify,
    })
}

// ── Flags and paths (pure helpers) ──────────────────────────────────────────

/// What the supervisor sees at a path before the system call runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PathState {
    /// The path exists (`lstat`).
    exists: bool,
    /// The last component is a symbolic link.
    is_link: bool,
    /// The path exists after the last symbolic link (`stat`).
    target_exists: bool,
    /// The path is a directory after the last symbolic link.
    is_dir: bool,
}

impl PathState {
    fn probe(path: &Path) -> Self {
        match std::fs::symlink_metadata(path) {
            Err(_) => Self::default(),
            Ok(m) if m.file_type().is_symlink() => {
                let target = std::fs::metadata(path);
                Self {
                    exists: true,
                    is_link: true,
                    target_exists: target.is_ok(),
                    is_dir: target.is_ok_and(|t| t.is_dir()),
                }
            }
            Ok(m) => Self {
                exists: true,
                is_link: false,
                target_exists: true,
                is_dir: m.is_dir(),
            },
        }
    }
}

/// Map the flags of an open call to the operation. Return `None` for a call
/// that does not access the content (`O_PATH`) or that fails for certain.
fn open_op(flags: u64, st: PathState) -> Option<FsOp> {
    // The kernel uses the low 32 bits of the flags argument of open(2).
    #[allow(clippy::cast_possible_truncation)]
    let f = flags as libc::c_int;
    if f & libc::O_PATH != 0 {
        return None;
    }
    if f & libc::O_TMPFILE == libc::O_TMPFILE {
        // An unnamed file in the directory: a write to the directory.
        return (st.target_exists && st.is_dir).then_some(FsOp::Write);
    }
    let follows = f & libc::O_NOFOLLOW == 0;
    if !follows && st.is_link {
        return None; // ELOOP
    }
    let exists = st.target_exists;
    let writes =
        matches!(f & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR) || f & libc::O_TRUNC != 0;
    if f & libc::O_CREAT != 0 {
        if !exists {
            return Some(FsOp::Create);
        }
        if f & libc::O_EXCL != 0 {
            return None; // EEXIST
        }
    } else if !exists {
        return None; // ENOENT
    }
    Some(if writes { FsOp::Write } else { FsOp::Read })
}

/// Remove `.` and `..` and repeated slashes from the absolute `path`, without
/// a look at the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// Make the raw path `raw` absolute. `base` gives the directory for a
/// relative path (the working directory or the directory descriptor). With
/// `in_root`, an absolute path is also relative to `base`
/// (`RESOLVE_IN_ROOT`).
fn resolve_path(
    raw: &[u8],
    in_root: bool,
    base: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    let raw = Path::new(OsStr::from_bytes(raw));
    if raw.is_absolute() && !in_root {
        return Some(normalize(raw));
    }
    let base = base()?;
    if !base.is_absolute() {
        return None; // for example "pipe:[123]" or "anon_inode:..."
    }
    let rel = raw.strip_prefix("/").unwrap_or(raw);
    Some(normalize(&base.join(rel)))
}

/// Return the `Tgid` field of the text of `/proc/<tid>/status`.
fn parse_tgid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Split the remote range `[addr, addr + len)` at page boundaries, so that a
/// read can stop at an unmapped page. `len` must not be larger than `page`.
/// Returns the ranges and their count.
fn remote_ranges(addr: u64, len: usize, page: usize) -> ([(u64, usize); 2], usize) {
    let page64 = page as u64;
    let to_end = usize::try_from(page64 - addr % page64).unwrap_or(page);
    let first = len.min(to_end);
    let second = len - first;
    let ranges = [(addr, first), (addr.wrapping_add(first as u64), second)];
    (ranges, if second == 0 { 1 } else { 2 })
}

/// Make the target of a `connect()` to a Unix socket from the bytes of
/// `sun_path` (the `sockaddr_un` without the family field). Returns `None`
/// for an unnamed socket.
fn unix_target(sun_path: &[u8], resolve: impl FnOnce(&[u8]) -> Option<PathBuf>) -> Option<String> {
    match sun_path.split_first() {
        None => None,
        Some((0, name)) => Some(format!("@{}", String::from_utf8_lossy(name))),
        Some(_) => {
            let end = sun_path
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(sun_path.len());
            let raw = sun_path.get(..end)?;
            resolve(raw).map(|p| p.to_string_lossy().into_owned())
        }
    }
}

// ── The child side ──────────────────────────────────────────────────────────

/// The data that the `pre_exec` hook needs to install the recorder.
#[derive(Clone)]
pub(crate) struct RecorderChild {
    filter: Vec<libc::sock_filter>,
    /// The socket end of the child. The child sends the listener on it.
    sock: RawFd,
}

impl RecorderChild {
    /// Install the recorder filter, send the listener to the parent, and
    /// close the copy of the child.
    ///
    /// # Safety
    /// Call this only in a `pre_exec` hook, after `PR_SET_NO_NEW_PRIVS`. The
    /// function uses only raw system calls on data that the parent prepared.
    ///
    /// # Errors
    /// Returns the OS error if the kernel refuses the filter or the send
    /// fails.
    pub(crate) unsafe fn install_in_child(&self) -> std::io::Result<()> {
        let len = libc::c_ushort::try_from(self.filter.len())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let prog = libc::sock_fprog {
            len,
            filter: self.filter.as_ptr().cast_mut(),
        };
        // SAFETY: `prog` points to a valid BPF program that lives until the
        // call returns. NO_NEW_PRIVS is set (see the caller).
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                std::ptr::addr_of!(prog),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = libc::c_int::try_from(ret)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EBADF))?;
        // SAFETY: `fd` and `self.sock` are open file descriptors of this
        // process.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sent = unsafe { crate::linux_fdpass::send_fds(self.sock, &[fd]) };
        // SAFETY: close the copies of this process; the parent has the
        // listener now, and `exec` does not need the socket.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(fd);
            libc::close(self.sock);
        }
        sent
    }
}

// ── The parent side ─────────────────────────────────────────────────────────

/// How the recorder decides the outcome of an event.
pub(crate) enum Judge {
    /// Watch mode: the rules that the guard mounts enforce, and the write
    /// rules on paths that did not exist at the start.
    Guard {
        /// The rules that the mounts enforce.
        enforced: Vec<GuardRule>,
        /// The write rules that the supervisor enforces.
        unenforced: Vec<GuardRule>,
    },
    /// `pent run --trace`: the prediction of the Landlock policy.
    Policy(AccessPolicy),
}

impl Judge {
    fn fs(&self, op: FsOp, path: &Path, is_dir: bool) -> Outcome {
        match self {
            Self::Guard {
                enforced,
                unenforced,
            } => {
                let access = guard_access(op);
                classify(enforced, path, access)
                    .or_else(|| {
                        (access == GuardAccess::Write)
                            .then(|| classify(unenforced, path, access))
                            .flatten()
                    })
                    .map_or(Outcome::Allowed, Outcome::Blocked)
            }
            Self::Policy(policy) => policy.predict(op, path, is_dir),
        }
    }

    /// Return true if the supervisor must deny the call. This is a write to
    /// a guarded path that has no mount, because it did not exist at the
    /// start (for example `~/.zshrc`). Another thread of the process can
    /// race this check, so it stops accidents, not a hostile program.
    fn denies(&self, op: FsOp, path: &Path) -> bool {
        match self {
            Self::Guard { unenforced, .. } => {
                let access = guard_access(op);
                access == GuardAccess::Write && classify(unenforced, path, access).is_some()
            }
            Self::Policy(_) => false,
        }
    }

    fn unix(&self, target: &str) -> Outcome {
        match self {
            Self::Guard { .. } => Outcome::Allowed,
            Self::Policy(policy) => policy.predict_unix(target),
        }
    }
}

/// The guard access that matches a filesystem operation.
const fn guard_access(op: FsOp) -> GuardAccess {
    match op {
        FsOp::Read => GuardAccess::Read,
        FsOp::Exec => GuardAccess::ExecName,
        FsOp::Write | FsOp::Create | FsOp::Delete => GuardAccess::Write,
    }
}

/// The recorder before the spawn: the data for the child and the event
/// channel.
pub(crate) struct RecorderSetup {
    /// The data for the `pre_exec` hook.
    pub(crate) child: RecorderChild,
    child_sock: OwnedFd,
    events: mpsc::Receiver<WatchEvent>,
}

impl RecorderSetup {
    /// Close the parent copy of the socket end of the child, and return the
    /// event channel. Call this after `spawn`.
    pub(crate) fn into_events(self) -> mpsc::Receiver<WatchEvent> {
        drop(self.child_sock);
        self.events
    }
}

/// Start the supervisor thread of the recorder.
///
/// # Errors
/// Returns `SandboxUnavailable` on a CPU architecture without a recorder, or
/// `SpawnFailed` if the socket pair or the thread cannot be created.
pub(crate) fn start_recorder(judge: Judge) -> Result<RecorderSetup, SandboxError> {
    let filter = native_filter()?;
    let (parent_sock, child_sock) = crate::linux_fdpass::seqpacket_pair()?;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("pent-recorder".to_string())
        .spawn(move || supervise(&parent_sock, judge, &tx))
        .map_err(SandboxError::SpawnFailed)?;
    Ok(RecorderSetup {
        child: RecorderChild {
            filter,
            sock: child_sock.as_raw_fd(),
        },
        child_sock,
        events: rx,
    })
}

/// The body of the supervisor thread.
fn supervise(sock: &OwnedFd, judge: Judge, tx: &mpsc::Sender<WatchEvent>) {
    let listener = match crate::linux_fdpass::recv_fds(sock) {
        Ok(Some(fds)) => {
            // The child sends exactly one descriptor. `recv_fds` checks
            // that the count byte matches, so more than one is not possible
            // from the hook; take the first and close the rest.
            let Some(fd) = fds.into_iter().next() else {
                return;
            };
            fd
        }
        Ok(None) => return,
        Err(e) => {
            // The listener closes with the socket. Then the recorded system
            // calls of the child fail with ENOSYS and the spawn fails.
            tracing::warn!("the recorder did not get the seccomp listener: {e}");
            return;
        }
    };
    Supervisor::new(listener, judge).run(tx);
}

/// Build an ioctl request number (`_IOC`) for the seccomp magic `'!'`.
#[allow(clippy::cast_possible_truncation)]
const fn seccomp_ioc(dir: u32, nr: u32, size: usize) -> libc::Ioctl {
    ((dir << 30) | ((size as u32) << 16) | (0x21 << 8) | nr) as libc::Ioctl
}

const IOC_WRITE: u32 = 1;
const IOC_READ_WRITE: u32 = 3;
const NOTIF_RECV: libc::Ioctl = seccomp_ioc(
    IOC_READ_WRITE,
    0,
    std::mem::size_of::<libc::seccomp_notif>(),
);
const NOTIF_SEND: libc::Ioctl = seccomp_ioc(
    IOC_READ_WRITE,
    1,
    std::mem::size_of::<libc::seccomp_notif_resp>(),
);
const NOTIF_ID_VALID: libc::Ioctl = seccomp_ioc(IOC_WRITE, 2, std::mem::size_of::<u64>());
const NOTIF_SET_FLAGS: libc::Ioctl = seccomp_ioc(IOC_WRITE, 4, std::mem::size_of::<u64>());
/// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` (Linux 6.6): the kernel switches
/// directly between the task and the supervisor on one CPU.
const NOTIF_FD_SYNC_WAKE_UP: libc::c_ulong = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
/// `RESOLVE_IN_ROOT` of `openat2(2)`.
const RESOLVE_IN_ROOT: u64 = 0x10;
/// The size of `struct sockaddr_un`.
const SOCKADDR_UN_LEN: usize = std::mem::size_of::<libc::sockaddr_un>();

/// A buffer of `len` bytes with the alignment of `u64`.
fn aligned_buffer(len: usize) -> Vec<u64> {
    vec![0u64; len.div_ceil(8).max(1)]
}

/// A cache of the process of each thread: the TGID and the `comm` of the
/// process.
#[derive(Default)]
struct ProcCache {
    map: HashMap<u32, ProcessInfo>,
}

impl ProcCache {
    const MAX: usize = 4096;

    fn get(&mut self, tid: u32) -> ProcessInfo {
        if let Some(info) = self.map.get(&tid) {
            return info.clone();
        }
        if self.map.len() >= Self::MAX {
            self.map.clear();
        }
        let pid = std::fs::read_to_string(format!("/proc/{tid}/status"))
            .ok()
            .and_then(|s| parse_tgid(&s))
            .unwrap_or(tid);
        let name = std::fs::read(format!("/proc/{pid}/comm"))
            .map(|b| String::from_utf8_lossy(b.strip_suffix(b"\n").unwrap_or(&b)).into_owned())
            .unwrap_or_default();
        let info = ProcessInfo { pid, name };
        self.map.insert(tid, info.clone());
        info
    }

    /// Forget a thread and its process. `execve` changes the name.
    fn forget(&mut self, tid: u32, pid: u32) {
        self.map.remove(&tid);
        self.map.remove(&pid);
    }
}

struct Supervisor {
    listener: OwnedFd,
    judge: Judge,
    /// Deny the current call with EACCES instead of `CONTINUE`.
    deny: bool,
    procs: ProcCache,
    page: usize,
    /// The buffer for `SECCOMP_IOCTL_NOTIF_RECV` (the kernel size or more).
    req: Vec<u64>,
    /// The buffer for `SECCOMP_IOCTL_NOTIF_SEND`.
    resp: Vec<u64>,
    /// The buffer for a path from the memory of the process.
    path_buf: Box<[u8]>,
    /// The events of the current notification.
    out: Vec<WatchEvent>,
    /// The number of unexpected errors (the log shows only the first few).
    errors: u32,
}

impl Supervisor {
    fn new(listener: OwnedFd, judge: Judge) -> Self {
        let mut sizes = libc::seccomp_notif_sizes {
            seccomp_notif: 0,
            seccomp_notif_resp: 0,
            seccomp_data: 0,
        };
        // SAFETY: the kernel writes a `struct seccomp_notif_sizes` into
        // `sizes`.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_GET_NOTIF_SIZES,
                0u32,
                std::ptr::addr_of_mut!(sizes),
            )
        };
        let (req_len, resp_len) = if ret == 0 {
            (
                usize::from(sizes.seccomp_notif),
                usize::from(sizes.seccomp_notif_resp),
            )
        } else {
            (0, 0)
        };
        // SAFETY: sysconf has no preconditions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|&p| p >= 4096)
            .unwrap_or(4096);
        Self {
            listener,
            judge,
            deny: false,
            procs: ProcCache::default(),
            page,
            req: aligned_buffer(req_len.max(std::mem::size_of::<libc::seccomp_notif>())),
            resp: aligned_buffer(resp_len.max(std::mem::size_of::<libc::seccomp_notif_resp>())),
            path_buf: vec![0u8; libc::PATH_MAX as usize].into_boxed_slice(),
            out: Vec::new(),
            errors: 0,
        }
    }

    fn log_error(&mut self, what: &str, err: &std::io::Error) {
        self.errors = self.errors.saturating_add(1);
        if self.errors <= 5 {
            tracing::warn!("seccomp recorder: {what}: {err}");
        }
    }

    /// Serve notifications until no task uses the filter.
    fn run(mut self, tx: &mpsc::Sender<WatchEvent>) {
        // SAFETY: the ioctl takes an integer argument. An older kernel
        // returns EINVAL; the recorder then works with normal wake-ups.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                NOTIF_SET_FLAGS,
                NOTIF_FD_SYNC_WAKE_UP,
            )
        };
        if ret != 0 {
            tracing::debug!(
                "seccomp recorder: no synchronous wake-up: {}",
                std::io::Error::last_os_error()
            );
        }
        loop {
            let mut pfd = libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is one valid pollfd.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe { libc::poll(&raw mut pfd, 1, -1) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    // Do not stop: a closed listener breaks the program.
                    self.log_error("poll", &err);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                continue;
            }
            if pfd.revents & libc::POLLIN != 0 {
                self.serve_one();
                for event in self.out.drain(..) {
                    // The caller can drop the receiver; the recorder still
                    // answers each notification, so the error is ignored.
                    let _ = tx.send(event);
                }
                continue;
            }
            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return;
            }
        }
    }

    /// Receive one notification, record it and answer `CONTINUE`.
    fn serve_one(&mut self) {
        self.req.fill(0);
        // SAFETY: `req` is a zeroed, aligned buffer at least as large as the
        // kernel `struct seccomp_notif`.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret =
            unsafe { libc::ioctl(self.listener.as_raw_fd(), NOTIF_RECV, self.req.as_mut_ptr()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // ENOENT: the task died or a signal interrupted the call.
            if !matches!(err.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) {
                self.log_error("NOTIF_RECV", &err);
            }
            return;
        }
        // SAFETY: the buffer is aligned for u64 and holds an initialized
        // `struct seccomp_notif` (plain integers) at its start.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let notif = unsafe { std::ptr::read(self.req.as_ptr().cast::<libc::seccomp_notif>()) };
        self.out.clear();
        self.deny = false;
        self.record(&notif);
        if !self.out.is_empty() && !self.id_valid(notif.id) {
            // The task died; its PID can belong to another process now.
            self.out.clear();
        }
        self.respond(notif.id);
    }

    fn id_valid(&self, id: u64) -> bool {
        // SAFETY: the ioctl reads one u64.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::ioctl(self.listener.as_raw_fd(), NOTIF_ID_VALID, &raw const id) == 0 }
    }

    fn respond(&mut self, id: u64) {
        self.resp.fill(0);
        let resp = if self.deny {
            libc::seccomp_notif_resp {
                id,
                val: 0,
                error: -libc::EACCES,
                flags: 0,
            }
        } else {
            libc::seccomp_notif_resp {
                id,
                val: 0,
                error: 0,
                // The flag value is 1.
                #[allow(clippy::cast_possible_truncation)]
                flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
            }
        };
        // SAFETY: `resp` buffer is aligned for u64 and at least as large as
        // `struct seccomp_notif_resp`.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::ptr::write(
                self.resp.as_mut_ptr().cast::<libc::seccomp_notif_resp>(),
                resp,
            )
        };
        // SAFETY: the buffer holds a valid response; the kernel reads it.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                NOTIF_SEND,
                self.resp.as_mut_ptr(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                self.log_error("NOTIF_SEND", &err);
            }
        }
    }

    /// Read `buf.len()` bytes (at most one page) at `addr` in the memory of
    /// `pid`. Returns the number of bytes read.
    fn read_remote(&self, pid: u32, addr: u64, buf: &mut [u8]) -> usize {
        let len = buf.len().min(self.page);
        let (ranges, count) = remote_ranges(addr, len, self.page);
        let remote = ranges.map(|(a, l)| libc::iovec {
            iov_base: a as usize as *mut libc::c_void,
            iov_len: l,
        });
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: len,
        };
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return 0;
        };
        // SAFETY: `local` points to `len` writable bytes of `buf`; the
        // remote ranges are only read in the other process.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe {
            libc::process_vm_readv(
                pid,
                &raw const local,
                1,
                remote.as_ptr(),
                count as libc::c_ulong,
                0,
            )
        };
        usize::try_from(n).unwrap_or(0)
    }

    /// Read the NUL-terminated string at `addr` in the memory of `pid`.
    fn read_cstr(&mut self, pid: u32, addr: u64) -> Option<Vec<u8>> {
        if addr == 0 {
            return None;
        }
        let mut buf = std::mem::take(&mut self.path_buf);
        let n = self.read_remote(pid, addr, &mut buf);
        let s = buf.get(..n).and_then(|b| {
            let end = b.iter().position(|&c| c == 0)?;
            b.get(..end).map(<[u8]>::to_vec)
        });
        self.path_buf = buf;
        s
    }

    /// Return the directory for a relative path: the working directory for
    /// `AT_FDCWD`, else the path of the directory descriptor.
    fn base_dir(pid: u32, dirfd: i32) -> Option<PathBuf> {
        if dirfd == libc::AT_FDCWD {
            std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
        } else if dirfd >= 0 {
            std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()
        } else {
            None
        }
    }

    /// Read and resolve the path of `arg`. An empty path is the directory
    /// descriptor itself when `empty_ok` (`AT_EMPTY_PATH`).
    fn path_of(
        &mut self,
        pid: u32,
        args: &[u64; 6],
        arg: PathArg,
        empty_ok: bool,
        in_root: bool,
    ) -> Option<PathBuf> {
        let raw = self.read_cstr(pid, *args.get(arg.path)?)?;
        // The kernel uses the low 32 bits of a descriptor argument.
        #[allow(clippy::cast_possible_truncation)]
        let dirfd = arg
            .dirfd
            .and_then(|i| args.get(i))
            .map_or(libc::AT_FDCWD, |&v| v as i32);
        if raw.is_empty() {
            return if empty_ok {
                Self::base_dir(pid, dirfd).filter(|p| p.is_absolute())
            } else {
                None
            };
        }
        resolve_path(&raw, in_root, || Self::base_dir(pid, dirfd))
    }

    /// Add an event for `path`. If the call follows a symbolic link in the
    /// last component, add an event for the canonical target too.
    fn push_fs(
        &mut self,
        process: &ProcessInfo,
        op: FsOp,
        path: PathBuf,
        st: PathState,
        follows: bool,
    ) {
        let target = (follows && st.is_link)
            .then(|| std::fs::canonicalize(&path).ok())
            .flatten()
            .filter(|t| *t != path);
        let outcome = self.judge.fs(op, &path, st.is_dir);
        self.deny |= self.judge.denies(op, &path);
        self.out.push(WatchEvent::Fs {
            op,
            path,
            process: process.clone(),
            outcome,
        });
        if let Some(target) = target {
            let outcome = self.judge.fs(op, &target, st.is_dir);
            self.deny |= self.judge.denies(op, &target);
            self.out.push(WatchEvent::Fs {
                op,
                path: target,
                process: process.clone(),
                outcome,
            });
        }
    }

    /// Turn one notification into events in `self.out`.
    fn record(&mut self, notif: &libc::seccomp_notif) {
        let Some(call) = decode(notif.data.nr) else {
            return;
        };
        let tid = notif.pid;
        let args = notif.data.args;
        match call {
            Call::Open(arg, flags) => {
                let (flags, in_root) = match flags {
                    OpenFlags::Arg(i) => (args.get(i).copied().unwrap_or(0), false),
                    OpenFlags::Creat => {
                        // The flag values are small and positive.
                        #[allow(clippy::cast_sign_loss)]
                        let f = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;
                        (f, false)
                    }
                    OpenFlags::OpenHow(i) => {
                        // struct open_how { u64 flags; u64 mode; u64 resolve; }
                        let mut how = [0u8; 24];
                        let addr = args.get(i).copied().unwrap_or(0);
                        if self.read_remote(tid, addr, &mut how) < how.len() {
                            return;
                        }
                        let word = |k: usize| {
                            how.get(k * 8..k * 8 + 8)
                                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                                .map_or(0, u64::from_ne_bytes)
                        };
                        (word(0), word(2) & RESOLVE_IN_ROOT != 0)
                    }
                };
                let Some(path) = self.path_of(tid, &args, arg, false, in_root) else {
                    return;
                };
                let st = PathState::probe(&path);
                let Some(op) = open_op(flags, st) else {
                    return;
                };
                let process = self.procs.get(tid);
                self.push_fs(&process, op, path, st, true);
            }
            Call::Exec(arg, flags_arg) => {
                let empty_ok = flags_arg
                    .and_then(|i| args.get(i))
                    .is_some_and(|&f| f & (libc::AT_EMPTY_PATH as u64) != 0);
                let Some(path) = self.path_of(tid, &args, arg, empty_ok, false) else {
                    return;
                };
                let st = PathState::probe(&path);
                if !st.target_exists {
                    return;
                }
                let process = self.procs.get(tid);
                self.push_fs(&process, FsOp::Exec, path, st, true);
                self.procs.forget(tid, process.pid);
            }
            Call::Create(arg) => {
                let Some(path) = self.path_of(tid, &args, arg, false, false) else {
                    return;
                };
                let st = PathState::probe(&path);
                if st.exists {
                    return; // EEXIST
                }
                let process = self.procs.get(tid);
                self.push_fs(&process, FsOp::Create, path, st, false);
            }
            Call::Delete(arg) => {
                let Some(path) = self.path_of(tid, &args, arg, false, false) else {
                    return;
                };
                let st = PathState::probe(&path);
                if !st.exists {
                    return; // ENOENT
                }
                let process = self.procs.get(tid);
                self.push_fs(&process, FsOp::Delete, path, st, false);
            }
            Call::Rename(old, new) => {
                let Some(old) = self.path_of(tid, &args, old, false, false) else {
                    return;
                };
                let st = PathState::probe(&old);
                if !st.exists {
                    return; // ENOENT
                }
                let Some(new) = self.path_of(tid, &args, new, false, false) else {
                    return;
                };
                let new_st = PathState::probe(&new);
                let process = self.procs.get(tid);
                self.push_fs(&process, FsOp::Delete, old, st, false);
                self.push_fs(&process, FsOp::Create, new, new_st, false);
            }
            Call::Truncate(arg) => {
                let Some(path) = self.path_of(tid, &args, arg, false, false) else {
                    return;
                };
                let st = PathState::probe(&path);
                if !st.target_exists {
                    return;
                }
                let process = self.procs.get(tid);
                self.push_fs(&process, FsOp::Write, path, st, true);
            }
            Call::Connect => self.record_connect(tid, &args),
        }
    }

    /// Record a `connect()` to a Unix socket. Other address families go to
    /// the proxy, which records them.
    fn record_connect(&mut self, tid: u32, args: &[u64; 6]) {
        let (Some(&addr), Some(&len)) = (args.get(1), args.get(2)) else {
            return;
        };
        let len = usize::try_from(len).unwrap_or(0).min(SOCKADDR_UN_LEN);
        let mut sa = [0u8; SOCKADDR_UN_LEN];
        let Some(buf) = sa.get_mut(..len) else {
            return;
        };
        let n = self.read_remote(tid, addr, buf);
        let Some(bytes) = sa.get(..n) else {
            return;
        };
        let family = bytes
            .get(..2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_ne_bytes);
        // AF_UNIX is 1.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if family != Some(libc::AF_UNIX as u16) {
            return;
        }
        let sun_path = bytes.get(2..).unwrap_or_default();
        let Some(target) = unix_target(sun_path, |raw| {
            resolve_path(raw, false, || Self::base_dir(tid, libc::AT_FDCWD))
        }) else {
            return;
        };
        let process = self.procs.get(tid);
        let outcome = self.judge.unix(&target);
        self.out.push(WatchEvent::UnixConnect {
            target,
            process,
            outcome,
        });
    }
}

// ── Spawn ───────────────────────────────────────────────────────────────────

/// Spawn `cmd` in watch mode (see [`crate::spawn_watched`]).
///
/// # Errors
/// Returns a spawn error, a network setup error, or `SandboxUnavailable` on
/// a CPU architecture without a recorder.
pub(crate) fn spawn_watched(
    config: &SandboxConfig,
    options: &WatchOptions,
    cmd: &str,
    args: &[String],
) -> Result<WatchedChild, SandboxError> {
    let plan = plan_guard(&options.guard);
    let spawned =
        crate::linux::spawn_linux(config, cmd, args, &config.env, &[], SpawnMode::Watch(&plan))?;
    let Some(events) = spawned.events else {
        // The watch spawn always starts the recorder; this branch exists
        // only to avoid a panic.
        let mut child = spawned.child;
        // The child runs without a recorder; stop it. A failure means that
        // it has already exited.
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::SandboxUnavailable {
            reason: "the seccomp recorder did not start".into(),
            remediation: "Report this problem".into(),
        });
    };
    Ok(WatchedChild {
        child: SandboxChild {
            child: spawned.child,
            overlay: spawned.overlay,
            proxy_listeners: spawned.proxy_listeners,
            events: None,
        },
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pent_profile::GuardClass;
    use serial_test::serial;
    use std::time::{Duration, Instant};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // ── BPF ────────────────────────────────────────────────────────────────

    /// A small classic BPF interpreter for the instructions that
    /// `build_filter` uses. Returns `None` for an invalid program.
    fn run_bpf(prog: &[libc::sock_filter], nr: u32, arch: u32) -> Option<u32> {
        let mut data = [0u8; 64];
        data.get_mut(0..4)?.copy_from_slice(&nr.to_ne_bytes());
        data.get_mut(4..8)?.copy_from_slice(&arch.to_ne_bytes());
        let mut acc = 0u32;
        let mut pc = 0usize;
        for _ in 0..prog.len() {
            let ins = prog.get(pc)?;
            let k = ins.k as usize;
            match ins.code {
                BPF_LD_W_ABS => {
                    acc = u32::from_ne_bytes(data.get(k..k + 4)?.try_into().ok()?);
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc += 1 + usize::from(if acc == ins.k { ins.jt } else { ins.jf });
                }
                BPF_JMP_JGE_K => {
                    pc += 1 + usize::from(if acc >= ins.k { ins.jt } else { ins.jf });
                }
                BPF_RET_K => return Some(ins.k),
                _ => return None,
            }
        }
        None
    }

    #[test]
    fn filter_routes_each_class() -> TestResult {
        let spec = FilterSpec {
            audit_arch: 0xC000_003E,
            foreign_nr_min: Some(X32_SYSCALL_BIT),
            enosys: &[425],
            notify: &[2, 257, 42],
        };
        let prog = build_filter(&spec)?;
        let arch = spec.audit_arch;
        assert_eq!(run_bpf(&prog, 257, arch), Some(RET_NOTIFY));
        assert_eq!(run_bpf(&prog, 2, arch), Some(RET_NOTIFY));
        assert_eq!(run_bpf(&prog, 42, arch), Some(RET_NOTIFY));
        assert_eq!(run_bpf(&prog, 39, arch), Some(SECCOMP_RET_ALLOW));
        assert_eq!(run_bpf(&prog, 425, arch), Some(RET_ENOSYS));
        // x32: openat with the x32 bit must not bypass the recorder.
        assert_eq!(
            run_bpf(&prog, X32_SYSCALL_BIT | 257, arch),
            Some(RET_ENOSYS)
        );
        // i386 compat calls get ENOSYS.
        assert_eq!(run_bpf(&prog, 5, 0x4000_0003), Some(RET_ENOSYS));
        Ok(())
    }

    #[test]
    fn filter_without_foreign_range() -> TestResult {
        let spec = FilterSpec {
            audit_arch: 0xC000_00B7,
            foreign_nr_min: None,
            enosys: &[425],
            notify: &[56],
        };
        let prog = build_filter(&spec)?;
        assert_eq!(run_bpf(&prog, 56, 0xC000_00B7), Some(RET_NOTIFY));
        assert_eq!(
            run_bpf(&prog, 0x4000_0038, 0xC000_00B7),
            Some(SECCOMP_RET_ALLOW)
        );
        assert_eq!(run_bpf(&prog, 56, 0x4000_0028), Some(RET_ENOSYS));
        Ok(())
    }

    #[test]
    fn filter_rejects_a_too_long_jump() {
        let notify: Vec<u32> = (0..300).collect();
        let spec = FilterSpec {
            audit_arch: 1,
            foreign_nr_min: None,
            enosys: &[],
            notify: &notify,
        };
        assert!(build_filter(&spec).is_err());
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn native_filter_covers_the_calls() -> TestResult {
        let prog = native_filter()?;
        let Some((arch, _)) = NATIVE else {
            return Err("no native spec".into());
        };
        for (nr, _) in CALLS {
            assert_eq!(run_bpf(&prog, u32::try_from(*nr)?, arch), Some(RET_NOTIFY));
        }
        let uring = u32::try_from(libc::SYS_io_uring_setup)?;
        assert_eq!(run_bpf(&prog, uring, arch), Some(RET_ENOSYS));
        let getpid = u32::try_from(libc::SYS_getpid)?;
        assert_eq!(run_bpf(&prog, getpid, arch), Some(SECCOMP_RET_ALLOW));
        assert_eq!(
            decode(i32::try_from(libc::SYS_openat)?),
            Some(Call::Open(at(0, 1), OpenFlags::Arg(2)))
        );
        assert_eq!(decode(i32::try_from(libc::SYS_getpid)?), None);
        Ok(())
    }

    #[test]
    fn ioctl_numbers_match_the_kernel_headers() {
        assert_eq!(NOTIF_RECV, 0xC050_2100);
        assert_eq!(NOTIF_SEND, 0xC018_2101);
        assert_eq!(NOTIF_ID_VALID, 0x4008_2102);
        assert_eq!(NOTIF_SET_FLAGS, 0x4008_2104);
    }

    // ── Flags and paths ────────────────────────────────────────────────────

    const FILE: PathState = PathState {
        exists: true,
        is_link: false,
        target_exists: true,
        is_dir: false,
    };
    const MISSING: PathState = PathState {
        exists: false,
        is_link: false,
        target_exists: false,
        is_dir: false,
    };
    const DIR: PathState = PathState {
        exists: true,
        is_link: false,
        target_exists: true,
        is_dir: true,
    };
    const LINK: PathState = PathState {
        exists: true,
        is_link: true,
        target_exists: true,
        is_dir: false,
    };

    #[allow(clippy::cast_sign_loss)]
    const fn f(flags: libc::c_int) -> u64 {
        flags as u64
    }

    #[test]
    fn open_flags_map_to_operations() {
        use libc::{
            O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_PATH, O_RDONLY, O_RDWR, O_TMPFILE, O_TRUNC,
            O_WRONLY,
        };
        assert_eq!(open_op(f(O_RDONLY), FILE), Some(FsOp::Read));
        assert_eq!(open_op(f(O_RDONLY | O_DIRECTORY), DIR), Some(FsOp::Read));
        assert_eq!(open_op(f(O_RDONLY), MISSING), None);
        assert_eq!(open_op(f(O_WRONLY), FILE), Some(FsOp::Write));
        assert_eq!(open_op(f(O_RDWR), FILE), Some(FsOp::Write));
        assert_eq!(open_op(f(O_RDONLY | O_TRUNC), FILE), Some(FsOp::Write));
        assert_eq!(open_op(f(O_WRONLY), MISSING), None);
        assert_eq!(
            open_op(f(O_WRONLY | O_CREAT | O_TRUNC), MISSING),
            Some(FsOp::Create)
        );
        assert_eq!(
            open_op(f(O_WRONLY | O_CREAT | O_TRUNC), FILE),
            Some(FsOp::Write)
        );
        assert_eq!(open_op(f(O_WRONLY | O_CREAT | O_EXCL), FILE), None);
        assert_eq!(open_op(f(O_RDONLY | O_CREAT), FILE), Some(FsOp::Read));
        assert_eq!(open_op(f(O_PATH), FILE), None);
        assert_eq!(open_op(f(O_RDONLY | O_NOFOLLOW), LINK), None);
        assert_eq!(open_op(f(O_RDONLY), LINK), Some(FsOp::Read));
        assert_eq!(open_op(f(O_RDWR | O_TMPFILE), DIR), Some(FsOp::Write));
        assert_eq!(open_op(f(O_RDWR | O_TMPFILE), MISSING), None);
    }

    #[test]
    fn normalize_removes_dots() {
        assert_eq!(
            normalize(Path::new("/a/./b//c/../d")),
            PathBuf::from("/a/b/d")
        );
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
        assert_eq!(normalize(Path::new("/a/b/")), PathBuf::from("/a/b"));
    }

    #[test]
    fn resolve_uses_the_base_only_for_relative_paths() {
        let base = || Some(PathBuf::from("/work/dir"));
        assert_eq!(
            resolve_path(b"/etc/passwd", false, base),
            Some(PathBuf::from("/etc/passwd"))
        );
        assert_eq!(
            resolve_path(b"x/../y", false, base),
            Some(PathBuf::from("/work/dir/y"))
        );
        assert_eq!(
            resolve_path(b"../z", false, base),
            Some(PathBuf::from("/work/z"))
        );
        assert_eq!(
            resolve_path(b"/etc/passwd", true, base),
            Some(PathBuf::from("/work/dir/etc/passwd"))
        );
        assert_eq!(
            resolve_path(b"x", false, || Some(PathBuf::from("pipe:[7]"))),
            None
        );
        assert_eq!(resolve_path(b"x", false, || None), None);
    }

    #[test]
    fn tgid_is_parsed_from_status() {
        let status =
            "Name:\tnode\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4250\n";
        assert_eq!(parse_tgid(status), Some(4242));
        assert_eq!(parse_tgid("Name:\tx\n"), None);
    }

    #[test]
    fn remote_ranges_split_at_the_page_end() {
        let (r, n) = remote_ranges(0x1000, 4096, 4096);
        assert_eq!((n, r[0]), (1, (0x1000, 4096)));
        let (r, n) = remote_ranges(0x1ff0, 4096, 4096);
        assert_eq!(n, 2);
        assert_eq!(r[0], (0x1ff0, 16));
        assert_eq!(r[1], (0x2000, 4080));
        let (r, n) = remote_ranges(0x1ff0, 8, 4096);
        assert_eq!((n, r[0]), (1, (0x1ff0, 8)));
    }

    #[test]
    fn unix_targets() {
        let resolve = |raw: &[u8]| resolve_path(raw, false, || Some(PathBuf::from("/cwd")));
        assert_eq!(
            unix_target(b"/run/x.sock\0\0", resolve),
            Some("/run/x.sock".to_string())
        );
        assert_eq!(
            unix_target(b"rel.sock", resolve),
            Some("/cwd/rel.sock".to_string())
        );
        assert_eq!(
            unix_target(b"\0abstract", resolve),
            Some("@abstract".to_string())
        );
        assert_eq!(unix_target(b"", resolve), None);
    }

    // ── The guard plan ─────────────────────────────────────────────────────

    #[test]
    fn guard_plan_expands_existing_targets() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let root = std::fs::canonicalize(tmp.path())?;
        let ssh = root.join(".ssh");
        std::fs::create_dir(&ssh)?;
        std::fs::write(ssh.join("id_ed25519"), "k")?;
        std::fs::write(ssh.join("id_ed25519.pub"), "p")?;
        std::fs::write(ssh.join("known_hosts"), "h")?;
        let gnupg = root.join(".gnupg");
        std::fs::create_dir_all(gnupg.join("private"))?;
        std::fs::write(root.join(".bashrc"), "rc")?;
        let rules = vec![
            GuardRule {
                class: GuardClass::Credential,
                access: GuardAccess::Read,
                target: GuardTarget::FilesInDir {
                    dir: ssh.clone(),
                    prefix: "id_".into(),
                    exclude_suffix: Some(".pub".into()),
                },
            },
            GuardRule {
                class: GuardClass::Credential,
                access: GuardAccess::Read,
                target: GuardTarget::Subtree(gnupg.clone()),
            },
            // Nested below a masked directory: no own mount.
            GuardRule {
                class: GuardClass::Credential,
                access: GuardAccess::Read,
                target: GuardTarget::Subtree(gnupg.join("private")),
            },
            GuardRule {
                class: GuardClass::Persistence,
                access: GuardAccess::Write,
                target: GuardTarget::Exact(root.join(".bashrc")),
            },
            // Missing: cannot be enforced.
            GuardRule {
                class: GuardClass::Persistence,
                access: GuardAccess::Write,
                target: GuardTarget::Exact(root.join(".zshrc")),
            },
            GuardRule {
                class: GuardClass::PrivilegeEscalation,
                access: GuardAccess::ExecName,
                target: GuardTarget::BinaryName("sudo".into()),
            },
        ];
        let plan = plan_guard(&rules);
        assert_eq!(plan.mask_files, vec![ssh.join("id_ed25519")]);
        assert_eq!(plan.mask_dirs, vec![gnupg.clone()]);
        assert_eq!(plan.ro_binds, vec![root.join(".bashrc")]);
        let judge = Judge::Guard {
            enforced: plan.effective,
            unenforced: plan.unenforced,
        };
        let cred = Outcome::Blocked(GuardClass::Credential);
        let pers = Outcome::Blocked(GuardClass::Persistence);
        assert_eq!(judge.fs(FsOp::Read, &ssh.join("id_ed25519"), false), cred);
        assert_eq!(
            judge.fs(FsOp::Read, &ssh.join("id_ed25519.pub"), false),
            Outcome::Allowed
        );
        assert_eq!(judge.fs(FsOp::Read, &gnupg.join("private/k"), false), cred);
        assert_eq!(judge.fs(FsOp::Write, &root.join(".bashrc"), false), pers);
        assert_eq!(
            judge.fs(FsOp::Read, &root.join(".bashrc"), false),
            Outcome::Allowed
        );
        // `.zshrc` does not exist, so no mount enforces the rule: the
        // supervisor denies the create.
        assert_eq!(judge.fs(FsOp::Create, &root.join(".zshrc"), false), pers);
        assert!(judge.denies(FsOp::Create, &root.join(".zshrc")));
        assert!(!judge.denies(FsOp::Write, &root.join(".bashrc")));
        assert_eq!(
            judge.fs(FsOp::Exec, Path::new("/usr/bin/sudo"), false),
            Outcome::Blocked(GuardClass::PrivilegeEscalation)
        );
        Ok(())
    }

    // ── End-to-end ─────────────────────────────────────────────────────────

    /// Return true if this host permits a user namespace, a mount namespace
    /// and a seccomp listener for an unprivileged process.
    fn recorder_available() -> bool {
        let prog = [stmt(BPF_RET_K, SECCOMP_RET_ALLOW)];
        // SAFETY: the child uses only raw system calls and `_exit`.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            // SAFETY: raw system calls in the forked child, then `_exit`.
            unsafe {
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                    libc::_exit(1);
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(2);
                }
                let fprog = libc::sock_fprog {
                    len: 1,
                    filter: prog.as_ptr().cast_mut(),
                };
                let fd = libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_SET_MODE_FILTER,
                    libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    std::ptr::addr_of!(fprog),
                );
                libc::_exit(if fd < 0 { 3 } else { 0 });
            }
        }
        let mut status = 0;
        // SAFETY: wait for the child that this function forked.
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        ret == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    struct Setup {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        sh: PathBuf,
        config: SandboxConfig,
    }

    fn setup() -> Result<Option<Setup>, Box<dyn std::error::Error>> {
        if !recorder_available() {
            eprintln!("skip: user namespaces or seccomp listeners are not available");
            return Ok(None);
        }
        let mut env = crate::build_env(&[]);
        let path_env = env.get("PATH").cloned().unwrap_or_default();
        let Some(sh) = crate::find_in_path("sh", &path_env) else {
            eprintln!("skip: no sh in PATH");
            return Ok(None);
        };
        let tmp = tempfile::tempdir()?;
        let dir = std::fs::canonicalize(tmp.path())?;
        env.insert("T".to_string(), dir.to_string_lossy().into_owned());
        let config = SandboxConfig::new(dir.clone(), crate::system_default_paths(), dir.clone())
            .with_env(env)
            .with_network(crate::NetworkMode::Unrestricted);
        Ok(Some(Setup {
            _tmp: tmp,
            dir,
            sh,
            config,
        }))
    }

    /// Reap orphans if this process is a child subreaper (another test can
    /// set the attribute). The filter stays in use until the parent reaps a
    /// task.
    fn reap_orphans() {
        let mut flag: libc::c_int = 0;
        // SAFETY: the kernel writes one int.
        let ret = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut flag, 0, 0, 0) };
        if ret == 0 && flag != 0 {
            // SAFETY: waitpid with WNOHANG and a null status pointer.
            while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        }
    }

    /// Read the events until the channel closes.
    fn drain(
        rx: &mpsc::Receiver<WatchEvent>,
    ) -> Result<Vec<WatchEvent>, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut events = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(e) => events.push(e),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(events),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    reap_orphans();
                    if Instant::now() > deadline {
                        return Err("the event channel did not close".into());
                    }
                }
            }
        }
    }

    /// Wait for the child, then read the events until the channel closes.
    fn collect(
        mut watched: WatchedChild,
    ) -> Result<(u32, Vec<WatchEvent>), Box<dyn std::error::Error>> {
        let pid = watched.child.child.id();
        watched.child.child.wait()?;
        Ok((pid, drain(&watched.events)?))
    }

    fn has_fs(events: &[WatchEvent], op: FsOp, path: &Path, outcome: Outcome) -> bool {
        events.iter().any(|e| {
            matches!(e, WatchEvent::Fs { op: o, path: p, outcome: r, .. }
                if *o == op && p == path && *r == outcome)
        })
    }

    fn sh_args(script: &str) -> Vec<String> {
        vec!["-c".to_string(), script.to_string()]
    }

    #[test]
    #[serial]
    fn watch_records_a_shell_session() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let script = "cat /etc/hostname >/dev/null; echo x > $T/new; ls $T >/dev/null; rm $T/new";
        let watched = crate::spawn_watched(
            &s.config,
            &WatchOptions { guard: Vec::new() },
            &s.sh.to_string_lossy(),
            &sh_args(script),
        )?;
        let (_, events) = collect(watched)?;
        let new = s.dir.join("new");
        let allowed = Outcome::Allowed;
        let hostname = Path::new("/etc/hostname");
        assert!(
            has_fs(&events, FsOp::Read, hostname, allowed),
            "{events:#?}"
        );
        assert!(has_fs(&events, FsOp::Create, &new, allowed), "{events:#?}");
        assert!(has_fs(&events, FsOp::Delete, &new, allowed), "{events:#?}");
        assert!(has_fs(&events, FsOp::Read, &s.dir, allowed), "{events:#?}");
        let sh_real = std::fs::canonicalize(&s.sh)?;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, WatchEvent::Fs { op: FsOp::Exec, path, .. }
                if *path == s.sh || *path == sh_real)),
            "{events:#?}"
        );
        assert!(
            events.iter().any(
                |e| matches!(e, WatchEvent::Fs { op: FsOp::Read, process, .. }
                if process.name == "cat")
            ),
            "{events:#?}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn watch_guard_blocks_and_reports() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let secret = s.dir.join("secret");
        let rc = s.dir.join("rc");
        std::fs::write(&secret, "TOPSECRET")?;
        std::fs::write(&rc, "orig\n")?;
        let guard = vec![
            GuardRule {
                class: GuardClass::Credential,
                access: GuardAccess::Read,
                target: GuardTarget::Exact(secret.clone()),
            },
            GuardRule {
                class: GuardClass::Persistence,
                access: GuardAccess::Write,
                target: GuardTarget::Exact(rc.clone()),
            },
        ];
        let script = "cat $T/secret > $T/out; echo evil >> $T/rc; true";
        let watched = crate::spawn_watched(
            &s.config,
            &WatchOptions { guard },
            &s.sh.to_string_lossy(),
            &sh_args(script),
        )?;
        let (_, events) = collect(watched)?;
        assert_eq!(std::fs::read_to_string(s.dir.join("out"))?, "");
        assert_eq!(std::fs::read_to_string(&rc)?, "orig\n");
        assert_eq!(std::fs::read_to_string(&secret)?, "TOPSECRET");
        let cred = Outcome::Blocked(GuardClass::Credential);
        let pers = Outcome::Blocked(GuardClass::Persistence);
        assert!(has_fs(&events, FsOp::Read, &secret, cred), "{events:#?}");
        assert!(has_fs(&events, FsOp::Write, &rc, pers), "{events:#?}");
        Ok(())
    }

    #[test]
    #[serial]
    fn watch_keeps_the_events_of_an_orphan() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let script = "(sleep 0.2; cat /etc/hostname >/dev/null) &";
        let watched = crate::spawn_watched(
            &s.config,
            &WatchOptions { guard: Vec::new() },
            &s.sh.to_string_lossy(),
            &sh_args(script),
        )?;
        let (pid, events) = collect(watched)?;
        assert!(
            events.iter().any(
                |e| matches!(e, WatchEvent::Fs { op: FsOp::Read, path, process, .. }
                if path == Path::new("/etc/hostname") && process.pid != pid)
            ),
            "{events:#?}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn trace_predicts_the_policy() -> TestResult {
        let Some(mut s) = setup()? else {
            return Ok(());
        };
        if crate::check_availability().is_err() {
            eprintln!("skip: Landlock is not available");
            return Ok(());
        }
        // The crate directory is outside the policy of the test sandbox.
        let outside = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        s.config.record_events = true;
        let script = format!(
            "cat /etc/hostname >/dev/null; cat {} >/dev/null 2>&1; echo x > $T/f",
            outside.display()
        );
        let mut child =
            crate::spawn_sandboxed(&s.config, &s.sh.to_string_lossy(), &sh_args(&script))?;
        let rx = child.events.take().ok_or("no event channel")?;
        child.child.wait()?;
        if let Some(overlay) = child.overlay.take() {
            let _report = crate::teardown_overlay(overlay);
        }
        let events = drain(&rx)?;
        let hostname = Path::new("/etc/hostname");
        let created = s.dir.join("f");
        assert!(
            has_fs(&events, FsOp::Read, hostname, Outcome::Allowed),
            "{events:#?}"
        );
        assert!(
            has_fs(&events, FsOp::Read, &outside, Outcome::Denied),
            "{events:#?}"
        );
        assert!(
            has_fs(&events, FsOp::Create, &created, Outcome::Allowed),
            "{events:#?}"
        );
        Ok(())
    }

    /// Measure the overhead of the recorder. Run with
    /// `cargo test -p pent-sandbox --release -- --ignored --nocapture bench_`.
    #[test]
    #[ignore = "a benchmark, not a check"]
    #[serial]
    fn bench_recorder_overhead() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let path_env = s.config.env.get("PATH").cloned().unwrap_or_default();
        let mut workloads: Vec<(PathBuf, Vec<String>)> = Vec::new();
        if let Some(node) = crate::find_in_path("node", &path_env) {
            workloads.push((node, vec!["-e".into(), "0".into()]));
        }
        if let Some(py) = crate::find_in_path("python3", &path_env) {
            workloads.push((py.clone(), vec!["-c".into(), "0".into()]));
            // 20000 opens: the cost of one notification.
            let many = "import os\nfor _ in range(20000): os.close(os.open('/etc/passwd', 0))";
            workloads.push((py, vec!["-c".into(), many.into()]));
        }
        let runs = 10u32;
        for (prog, args) in workloads {
            let start = Instant::now();
            for _ in 0..runs {
                std::process::Command::new(&prog).args(&args).status()?;
            }
            let plain = start.elapsed() / runs;
            let start = Instant::now();
            let mut count = 0usize;
            for _ in 0..runs {
                let watched = crate::spawn_watched(
                    &s.config,
                    &WatchOptions { guard: Vec::new() },
                    &prog.to_string_lossy(),
                    &args,
                )?;
                count += collect(watched)?.1.len();
            }
            let watched = start.elapsed() / runs;
            eprintln!(
                "{} {:?}: plain {plain:?}, watched {watched:?}, {} events per run",
                prog.display(),
                args.last(),
                count / runs as usize
            );
        }
        Ok(())
    }
}
