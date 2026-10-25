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
//! A mount cannot hold every rule. A bind mount needs a target that
//! exists, and it covers one inode. Two shapes get no mount:
//!
//! - A path that does not exist when the child starts, for example
//!   `~/.zshrc`, or a key that the program makes during the run.
//! - A file below a guarded directory that a symbolic link reaches, for
//!   example `~/.ssh/linked/id_rsa` where `linked` points at
//!   `~/keystore`. The walk of the directory does not follow the link, so
//!   the mask never covers the name that the program uses.
//!
//! For these the supervisor refuses the call itself with EACCES and
//! reports `Outcome::Blocked` (see [`Judge::denies`]). Another thread of
//! the process can change the path after that check, so it stops
//! accidents, not a hostile program. The mounts stay the first layer, and
//! they have no race. The two layers together keep the report of the
//! summary and the answer of the kernel in agreement.
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
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. For a path the recorder only
//! observes: another thread can change the path after the check, so
//! seccomp-notify is not usable to enforce a path rule.
//!
//! # The control of the Unix sockets
//!
//! `connect(2)`, `sendto(2)`, `sendmsg(2)` and `sendmmsg(2)` are the
//! exception. The supervisor does not answer `CONTINUE` for an `AF_UNIX`
//! path there; it makes each permitted call itself, or it refuses the
//! call. This pattern has no race, because the kernel never reads the
//! address again. See [`crate::linux_unixconn`], which states the answer
//! of each of the four calls. The control runs in `pent run` with
//! enforcement, also without `--trace`: the recorder then traps only
//! these calls and makes no event. The cost is one notification for each
//! such call of the child.
//!
//! The filter also lets a `sendto(2)` with a null address pointer through
//! without a notification, because the address is an argument. A
//! `sendmsg(2)` carries its address in memory, so each one costs a
//! notification.
//!
//! The child must not hand the seccomp listener over with `SCM_RIGHTS`:
//! the filter traps `sendmsg(2)`, and the supervisor cannot answer a
//! notification before it holds the listener. It sends a pidfd of itself
//! first and the supervisor takes the listener with `pidfd_getfd(2)`; see
//! [`RecorderChild::install_in_child`].
//!
//! The filter returns `ENOSYS` for each system call of another ABI (i386
//! and x32 on x86_64, arm32 on aarch64), so that such a call cannot bypass
//! the recorder. Thus a 32-bit program does not run under the recorder.
//!
//! The same recorder runs next to Landlock for `pent run --trace`
//! (`SandboxConfig::record_events`). Seccomp sees a call before Landlock
//! decides, so the recorder predicts the decision (see `AccessPolicy` in
//! `linux.rs`).
//!
//! The filter always blocks `io_uring_setup`, because io_uring has a
//! connect operation and a send operation that seccomp does not see. A
//! program that uses io_uring falls back to normal system calls. The
//! filter also gives
//! `ENOSYS` to each system call of another ABI, so a 32-bit program does
//! not run under `pent run`.
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
use crate::linux_unixconn::{UnixAddr, UnixDecision};
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
    /// The rules that no mount enforces. A mount needs a target that exists
    /// and covers one inode, so it cannot hold a path that the program makes
    /// during the run, and it cannot hold each name that reaches one inode.
    /// The supervisor refuses these accesses itself (see [`Judge::denies`]).
    pub(crate) unenforced: Vec<GuardRule>,
}

impl GuardPlan {
    /// Add the mount for `rule` on the existing `path`.
    ///
    /// Returns `false` when the path does not exist, or when pent cannot
    /// resolve it. The caller then puts the rule in
    /// [`GuardPlan::unenforced`].
    fn add_existing(&mut self, rule: &GuardRule, path: &Path) -> bool {
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        let Ok(real) = std::fs::canonicalize(path) else {
            return false;
        };
        let is_dir = meta.is_dir();
        match rule.access {
            GuardAccess::Read if is_dir => self.mask_dirs.push(real.clone()),
            GuardAccess::Read => self.mask_files.push(real.clone()),
            GuardAccess::Write => self.ro_binds.push(real.clone()),
            GuardAccess::ExecName => return false,
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
        true
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

/// The maximum depth of the walk below the directory of a
/// [`GuardTarget::FilesInDir`] rule.
const GUARD_WALK_DEPTH: u32 = 8;

/// The maximum number of entries that the walk of one guard directory
/// looks at. A directory with more entries is not a store of credentials,
/// and the walk must not hold the start of the program.
const GUARD_WALK_ENTRIES: usize = 4096;

/// Call `visit` for each regular file below `dir`, down to `depth` levels.
///
/// The walk does not follow a symbolic link: it reads the type of each
/// entry with `symlink_metadata`, so a link to another directory is not a
/// way out of `dir`. `budget` limits the number of entries.
fn walk_guard_dir(dir: &Path, depth: u32, budget: &mut usize, visit: &mut impl FnMut(&Path)) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget = budget.saturating_sub(1);
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            walk_guard_dir(&path, depth.saturating_sub(1), budget, visit);
        } else if meta.is_file() {
            visit(&path);
        }
    }
}

/// Compute the mounts for the guard `rules`. The function looks at the
/// filesystem: only paths that exist get a mount.
///
/// A rule that the mounts cannot hold goes to [`GuardPlan::unenforced`],
/// and the supervisor refuses the access itself. Two shapes need this:
///
/// - A path that does not exist when the child starts. A bind mount needs
///   a target, so a file that the program makes during the run has none.
/// - A [`GuardTarget::FilesInDir`] rule. The walk sees only the files of
///   today, and it does not follow a symbolic link, so a key below
///   `~/.ssh/linked` (a link to `~/keystore`) gets no mask under the name
///   that the program uses.
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
                if !plan.add_existing(rule, p) {
                    plan.unenforced.push(rule.clone());
                }
            }
            (GuardAccess::Read | GuardAccess::Write, GuardTarget::FilesInDir { dir, .. }) => {
                // The rule matches a file at any depth below `dir`, so the
                // mounts must cover the whole tree. A key in a
                // subdirectory needs a mask too.
                let mut found: Vec<PathBuf> = Vec::new();
                let mut budget = GUARD_WALK_ENTRIES;
                walk_guard_dir(dir, GUARD_WALK_DEPTH, &mut budget, &mut |path| {
                    if rule.matches(path, rule.access) {
                        found.push(path.to_path_buf());
                    }
                });
                for path in &found {
                    plan.add_existing(rule, path);
                }
                // The mounts hold the names of today only. The supervisor
                // holds the whole rule.
                plan.unenforced.push(rule.clone());
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
/// The offset of the first argument in `struct seccomp_data`: `nr` (4) +
/// `arch` (4) + `instruction_pointer` (8).
const OFF_ARGS: u32 = 16;
/// The offsets of the low and of the high word of the argument `n`. A
/// classic BPF program reads four bytes at a time.
const fn arg_words(n: u32) -> (u32, u32) {
    let base = OFF_ARGS + 8 * n;
    if cfg!(target_endian = "big") {
        (base + 4, base)
    } else {
        (base, base + 4)
    }
}
/// The x32 ABI on x86_64 sets this bit in the system call number.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

/// What the recorder traps and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecorderScope {
    /// The path system calls and the calls of the Unix socket control.
    /// Each call makes an event.
    Full,
    /// Only the calls of the Unix socket control, and no event. `pent run`
    /// without `--trace` takes this scope.
    ConnectOnly,
}

/// A system call that the supervisor needs only when it carries an
/// address. The address of `sendto(2)` is an argument, so the filter can
/// let a call without one through, with no cost for the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddrCall {
    /// The system call number.
    pub(crate) nr: u32,
    /// The index of the address argument.
    pub(crate) arg: u32,
}

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
    /// The system calls that go to the supervisor only when the argument
    /// `arg` is not a null pointer.
    pub(crate) addr_calls: &'a [AddrCall],
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
/// jeq N1 -> NOTIFY ...             (the path system calls, connect, ...)
/// jeq sendto else -> next block    (one block for each address call)
/// ld args[n].lo; jeq 0 else -> NOTIFY
/// ld args[n].hi; jeq 0 -> ALLOW else -> NOTIFY
/// ret ALLOW
/// ret USER_NOTIF
/// ret ERRNO(ENOSYS)
/// ```
///
/// A block of an address call reads both words of the pointer: a program
/// can map a page whose address has the low word zero, and a half test
/// would let the call through.
///
/// # Errors
/// Returns `InvalidConfig` if a jump is longer than 255 instructions.
pub(crate) fn build_filter(spec: &FilterSpec<'_>) -> Result<Vec<libc::sock_filter>, SandboxError> {
    let checks = spec.enosys.len() + spec.notify.len() + usize::from(spec.foreign_nr_min.is_some());
    // The three returns, the two loads and the arch check, plus the five
    // instructions of each address call.
    let len = checks + 6 + spec.addr_calls.len() * 5;
    let ret_allow = len - 3;
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
    for call in spec.addr_calls {
        // The block keeps the system call number in the accumulator for
        // the next block: the jump of another call leaves it alone.
        let (low, high) = arg_words(call.arg);
        let i = prog.len();
        prog.push(jump(BPF_JMP_JEQ_K, call.nr, 0, offset(i, i + 5)?));
        prog.push(stmt(BPF_LD_W_ABS, low));
        let i = prog.len();
        prog.push(jump(BPF_JMP_JEQ_K, 0, 0, offset(i, ret_notify)?));
        prog.push(stmt(BPF_LD_W_ABS, high));
        let i = prog.len();
        prog.push(jump(
            BPF_JMP_JEQ_K,
            0,
            offset(i, ret_allow)?,
            offset(i, ret_notify)?,
        ));
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
    /// A send that can carry a destination address.
    Send(SendCall),
}

/// The send system calls of the Unix socket control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendCall {
    /// `sendto(2)`: the address and the payload are arguments.
    To,
    /// `sendmsg(2)`: a `struct msghdr` holds the address and the payload.
    Msg,
    /// `sendmmsg(2)`: an array of `struct mmsghdr`.
    Many,
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
];

/// No recorder exists for this CPU architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const CALLS: &[(libc::c_long, Call)] = &[];

/// The system calls of the Unix socket control. The filter traps them in
/// both scopes: the control runs also without `--trace`.
///
/// `sendto(2)` is not in this list. Its address is an argument, so the
/// filter tests it and traps only a call that carries one (see
/// [`SENDTO_CALL`]).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const CONTROL_CALLS: &[(libc::c_long, Call)] = &[
    (libc::SYS_connect, Call::Connect),
    (libc::SYS_sendmsg, Call::Send(SendCall::Msg)),
    (libc::SYS_sendmmsg, Call::Send(SendCall::Many)),
];

/// No recorder exists for this CPU architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const CONTROL_CALLS: &[(libc::c_long, Call)] = &[];

/// `sendto(2)` and the index of its address argument.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SENDTO_CALL: Option<(libc::c_long, u32)> = Some((libc::SYS_sendto, 4));

/// No recorder exists for this CPU architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const SENDTO_CALL: Option<(libc::c_long, u32)> = None;

#[cfg(target_arch = "x86_64")]
const NATIVE: Option<(u32, Option<u32>)> = Some((0xC000_003E, Some(X32_SYSCALL_BIT)));
#[cfg(target_arch = "aarch64")]
const NATIVE: Option<(u32, Option<u32>)> = Some((0xC000_00B7, None));
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE: Option<(u32, Option<u32>)> = None;

/// Return the call kind of the native system call `nr`.
fn decode(nr: i32) -> Option<Call> {
    let nr = libc::c_long::from(nr);
    if let Some((sendto, _)) = SENDTO_CALL {
        if sendto == nr {
            return Some(Call::Send(SendCall::To));
        }
    }
    CALLS
        .iter()
        .chain(CONTROL_CALLS)
        .find(|(n, _)| *n == nr)
        .map(|(_, c)| *c)
}

/// Build the filter for the native ABI.
///
/// `scope` selects the system calls that go to the supervisor. The calls
/// of the Unix socket control are in both scopes.
fn native_filter(scope: RecorderScope) -> Result<Vec<libc::sock_filter>, SandboxError> {
    let Some((audit_arch, foreign_nr_min)) = NATIVE else {
        return Err(SandboxError::SandboxUnavailable {
            reason: "the seccomp recorder does not support this CPU architecture".into(),
            remediation: "Use x86_64 or aarch64".into(),
        });
    };
    let to_u32 = |n: libc::c_long| {
        u32::try_from(n).map_err(|_| SandboxError::InvalidConfig(format!("system call {n}")))
    };
    let path_calls: &[(libc::c_long, Call)] = match scope {
        RecorderScope::Full => CALLS,
        RecorderScope::ConnectOnly => &[],
    };
    let notify = path_calls
        .iter()
        .chain(CONTROL_CALLS)
        .map(|(n, _)| to_u32(*n))
        .collect::<Result<Vec<_>, _>>()?;
    // io_uring hides its operations from seccomp, and it has a connect
    // operation. The filter must remove it in both scopes.
    let enosys = [to_u32(libc::SYS_io_uring_setup)?];
    let addr_calls: Vec<AddrCall> = SENDTO_CALL
        .map(|(nr, arg)| to_u32(nr).map(|nr| AddrCall { nr, arg }))
        .transpose()?
        .into_iter()
        .collect();
    build_filter(&FilterSpec {
        audit_arch,
        foreign_nr_min,
        enosys: &enosys,
        notify: &notify,
        addr_calls: &addr_calls,
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

/// Make the address of a `connect()` to a Unix socket from the bytes of
/// `sun_path` (the `sockaddr_un` without the family field). Returns `None`
/// for an unnamed socket and for a path that does not resolve.
fn unix_target(
    sun_path: &[u8],
    resolve: impl FnOnce(&[u8]) -> Option<PathBuf>,
) -> Option<UnixAddr> {
    match sun_path.split_first() {
        None => None,
        Some((0, name)) => {
            // The abstract name ends with the address, not with a zero
            // byte, and it can hold any byte.
            let end = name.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            let name = name.get(..end)?;
            Some(UnixAddr::Abstract(
                String::from_utf8_lossy(name).into_owned(),
            ))
        }
        Some(_) => {
            let end = sun_path
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(sun_path.len());
            let raw = sun_path.get(..end)?;
            resolve(raw).map(UnixAddr::Path)
        }
    }
}

/// The fields of a `struct msghdr` that the control of the Unix sockets
/// needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct MsgHdr {
    /// `msg_name`: the address of the message, or 0.
    name: u64,
    /// `msg_namelen`: the length of the address.
    namelen: u64,
    /// `msg_iov`: the array of the payload ranges.
    iov: u64,
    /// `msg_iovlen`: the number of entries of that array.
    iovlen: u64,
    /// `msg_controllen`: the length of the ancillary data.
    controllen: u64,
}

/// The size of `struct msghdr`.
const MSGHDR_LEN: usize = std::mem::size_of::<libc::msghdr>();
/// The size of `struct mmsghdr`.
const MMSGHDR_LEN: usize = std::mem::size_of::<libc::mmsghdr>();
/// The size of `struct iovec`.
const IOVEC_LEN: usize = std::mem::size_of::<libc::iovec>();
/// `UIO_MAXIOV`: the greatest number of entries that the kernel takes in
/// an `iovec` array and in one `sendmmsg(2)`.
const UIO_MAXIOV: usize = 1024;

/// Read the machine word at `at` in `bytes`.
fn word(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(std::mem::size_of::<u64>())?;
    let b = bytes.get(at..end)?;
    Some(u64::from_ne_bytes(<[u8; 8]>::try_from(b).ok()?))
}

/// Read the 32-bit value at `at` in `bytes`.
fn word32(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(std::mem::size_of::<u32>())?;
    let b = bytes.get(at..end)?;
    Some(u64::from(u32::from_ne_bytes(<[u8; 4]>::try_from(b).ok()?)))
}

/// Read the fields of a `struct msghdr` from its bytes. The offsets come
/// from the type of the C library, so they follow the ABI of the target.
fn parse_msghdr(bytes: &[u8]) -> Option<MsgHdr> {
    // `msg_namelen` is a `socklen_t` (32 bits); the other fields are
    // machine words.
    Some(MsgHdr {
        name: word(bytes, std::mem::offset_of!(libc::msghdr, msg_name))?,
        namelen: word32(bytes, std::mem::offset_of!(libc::msghdr, msg_namelen))?,
        iov: word(bytes, std::mem::offset_of!(libc::msghdr, msg_iov))?,
        iovlen: word(bytes, std::mem::offset_of!(libc::msghdr, msg_iovlen))?,
        controllen: word(bytes, std::mem::offset_of!(libc::msghdr, msg_controllen))?,
    })
}

/// Read the `(address, length)` pairs of an `iovec` array from its bytes.
/// The result holds one entry for each `iovec` that the array has.
fn parse_iovecs(bytes: &[u8], count: usize) -> Vec<(u64, usize)> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = i.saturating_mul(IOVEC_LEN);
        let (Some(base), Some(len)) = (
            word(bytes, at + std::mem::offset_of!(libc::iovec, iov_base)),
            word(bytes, at + std::mem::offset_of!(libc::iovec, iov_len)),
        ) else {
            break;
        };
        let Ok(len) = usize::try_from(len) else {
            break;
        };
        out.push((base, len));
    }
    out
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
    /// Install the recorder filter, give the listener to the parent, and
    /// close the copy of the child.
    ///
    /// The child does **not** pass the listener with `SCM_RIGHTS`. The
    /// filter traps `sendmsg(2)` for the control of the Unix sockets, and
    /// the supervisor cannot answer a notification before it holds the
    /// listener, so such a send would wait forever. Instead:
    ///
    /// 1. The child sends a pidfd of itself, while no filter traps the
    ///    call.
    /// 2. It installs the filter and writes the number of the listener
    ///    with `write(2)`, which the filter does not trap.
    /// 3. It waits for one byte: the parent took the listener with
    ///    `pidfd_getfd(2)`. The number of the listener must stay valid
    ///    until then, so the child closes it only after the answer.
    ///
    /// # Safety
    /// Call this only in a `pre_exec` hook, after `PR_SET_NO_NEW_PRIVS`. The
    /// function uses only raw system calls on data that the parent prepared.
    ///
    /// # Errors
    /// Returns the OS error if the kernel refuses the filter or a step of
    /// the hand-over fails.
    pub(crate) unsafe fn install_in_child(&self) -> std::io::Result<()> {
        // SAFETY: the `pre_exec` hook runs in a new process of pent.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let pidfd = unsafe { crate::linux_fdpass::self_pidfd() }?;
        // SAFETY: `pidfd` and `self.sock` are open file descriptors.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sent = unsafe { crate::linux_fdpass::send_fds(self.sock, &[pidfd]) };
        // SAFETY: the parent holds its own copy of the pidfd now.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(pidfd) };
        sent?;
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
        // SAFETY: `self.sock` is an open file descriptor, and `write(2)`
        // and `read(2)` are not in the filter.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let done = unsafe {
            crate::linux_fdpass::write_all(self.sock, &fd.to_ne_bytes()).and_then(|()| {
                let mut ack = [0u8; 1];
                crate::linux_fdpass::read_message(self.sock, &mut ack)
            })
        };
        // SAFETY: close the copies of this process; the parent has the
        // listener now, and `exec` does not need the socket.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(fd);
            libc::close(self.sock);
        }
        match done {
            Ok(true) => Ok(()),
            // The parent went away before it took the listener.
            Ok(false) => Err(std::io::Error::from_raw_os_error(libc::EPIPE)),
            Err(e) => Err(e),
        }
    }
}

// ── The parent side ─────────────────────────────────────────────────────────

/// How the recorder decides the outcome of an event.
pub(crate) enum Judge {
    /// Watch mode: the rules that the guard mounts enforce, and the rules
    /// that the supervisor enforces itself.
    Guard {
        /// The rules that the mounts enforce.
        enforced: Vec<GuardRule>,
        /// The rules that the supervisor enforces.
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
                    .or_else(|| classify(unenforced, path, access))
                    .map_or(Outcome::Allowed, Outcome::Blocked)
            }
            Self::Policy(policy) => policy.predict(op, path, is_dir),
        }
    }

    /// Return true if the supervisor must refuse the call. This is an
    /// access to a guarded path that has no mount: a path that did not
    /// exist at the start (for example `~/.zshrc` or a key that the
    /// program makes), or a name that reaches a key through a symbolic
    /// link below the guarded directory.
    ///
    /// Another thread of the process can change the path after this
    /// check, so it stops accidents, not a hostile program. The mounts
    /// stay the first layer, and they have no race.
    fn denies(&self, op: FsOp, path: &Path) -> bool {
        match self {
            Self::Guard { unenforced, .. } => {
                classify(unenforced, path, guard_access(op)).is_some()
            }
            Self::Policy(_) => false,
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

/// The setup of the recorder for one spawn.
pub(crate) struct RecorderPlan {
    /// How the recorder decides the outcome of each filesystem event.
    /// `None` turns the events off: the recorder then traps only
    /// `connect(2)` for the control of the Unix sockets.
    pub(crate) judge: Option<Judge>,
    /// The control of `connect(2)` to a Unix socket.
    pub(crate) unix: crate::linux_unixconn::UnixControl,
}

/// Start the supervisor thread of the recorder.
///
/// # Errors
/// Returns `SandboxUnavailable` on a CPU architecture without a recorder, or
/// `SpawnFailed` if the socket pair or the thread cannot be created.
pub(crate) fn start_recorder(plan: RecorderPlan) -> Result<RecorderSetup, SandboxError> {
    let scope = if plan.judge.is_some() {
        RecorderScope::Full
    } else {
        RecorderScope::ConnectOnly
    };
    let filter = native_filter(scope)?;
    let (parent_sock, child_sock) = crate::linux_fdpass::seqpacket_pair()?;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("pent-recorder".to_string())
        .spawn(move || supervise(&parent_sock, plan, &tx))
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
fn supervise(sock: &OwnedFd, plan: RecorderPlan, tx: &mpsc::Sender<WatchEvent>) {
    let listener = match take_listener(sock) {
        Ok(Some(listener)) => listener,
        Ok(None) => return,
        Err(e) => {
            // The listener closes with the socket. Then the recorded system
            // calls of the child fail with ENOSYS and the spawn fails.
            tracing::warn!("the recorder did not get the seccomp listener: {e}");
            return;
        }
    };
    Supervisor::new(listener, plan).run(tx);
}

/// Take the seccomp listener of the child (see
/// [`RecorderChild::install_in_child`]). Returns `Ok(None)` when the child
/// died before the hand-over.
///
/// # Errors
/// Returns the OS error of a step of the hand-over.
fn take_listener(sock: &OwnedFd) -> std::io::Result<Option<OwnedFd>> {
    let Some(fds) = crate::linux_fdpass::recv_fds(sock)? else {
        return Ok(None);
    };
    // The child sends exactly one descriptor. `recv_fds` checks that the
    // count byte matches, so more than one is not possible from the hook;
    // take the first and close the rest.
    let Some(pidfd) = fds.into_iter().next() else {
        return Ok(None);
    };
    let mut number = [0u8; std::mem::size_of::<RawFd>()];
    // SAFETY: the socket of the parent is open.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if !unsafe { crate::linux_fdpass::read_message(sock.as_raw_fd(), &mut number) }? {
        return Ok(None);
    }
    let listener = crate::linux_fdpass::take_remote_fd(&pidfd, RawFd::from_ne_bytes(number))?;
    // The child waits for this byte before it closes the listener.
    // SAFETY: the socket of the parent is open.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { crate::linux_fdpass::write_all(sock.as_raw_fd(), &[1u8]) }?;
    Ok(Some(listener))
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
const NOTIF_ADDFD: libc::Ioctl = seccomp_ioc(IOC_WRITE, 3, std::mem::size_of::<NotifAddfd>());
const NOTIF_SET_FLAGS: libc::Ioctl = seccomp_ioc(IOC_WRITE, 4, std::mem::size_of::<u64>());
/// `SECCOMP_ADDFD_FLAG_SETFD`: the new descriptor takes the number in
/// `newfd`, as `dup2(2)` does.
const ADDFD_FLAG_SETFD: u32 = 1;

/// `struct seccomp_notif_addfd` of the kernel.
///
/// The supervisor does not use `SECCOMP_ADDFD_FLAG_SEND`. That flag makes
/// the system call return the number of the new descriptor, and
/// `connect(2)` must return 0. Thus the supervisor adds the descriptor and
/// then answers. The child waits in the notification the whole time, so it
/// cannot see a half-finished step; a task that dies between the two steps
/// makes both of them fail with `ENOENT`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct NotifAddfd {
    /// The identifier of the notification.
    id: u64,
    /// `SECCOMP_ADDFD_FLAG_*`.
    flags: u32,
    /// The descriptor of the supervisor.
    srcfd: u32,
    /// The number that the descriptor takes in the child.
    newfd: u32,
    /// `O_CLOEXEC`, or 0.
    newfd_flags: u32,
}
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

/// The address that the supervisor read from the memory of the child.
struct SeenAddr {
    /// The bytes of the address, as the child wrote them.
    raw: [u8; SOCKADDR_UN_LEN],
    /// The number of bytes that the supervisor read.
    len: usize,
    /// What the bytes name.
    kind: AddrKind,
}

impl SeenAddr {
    /// The bytes that the supervisor read.
    fn bytes(&self) -> &[u8] {
        self.raw.get(..self.len).unwrap_or_default()
    }
}

/// What the bytes of an address name.
enum AddrKind {
    /// An `AF_UNIX` address with a name.
    Unix(UnixAddr),
    /// An address of another family, or an `AF_UNIX` address with no
    /// name. The policy reads nothing from it; the kernel gives its own
    /// answer.
    Raw,
    /// The memory of the address is not readable. The kernel gives
    /// `EFAULT`.
    Unreadable,
}

/// The socket that a trapped call names.
enum SocketOfCall {
    /// A socket of another family. It reaches no Unix socket, so the
    /// control lets the call through.
    Other,
    /// A socket of the `AF_UNIX` family, with a copy of the descriptor.
    Unix(crate::linux_unixconn::ChildSocket),
    /// A socket of the `AF_UNIX` family that the supervisor could not
    /// copy. It refuses each call that it cannot make itself.
    UnixOpaque,
}

impl SocketOfCall {
    /// True when the socket belongs to the `AF_UNIX` family.
    fn is_unix(&self) -> bool {
        !matches!(self, Self::Other)
    }

    /// True when the kernel uses the address of a send on this socket.
    /// Only a datagram socket of the `AF_UNIX` family does.
    fn uses_the_send_address(&self) -> bool {
        match self {
            Self::Other => false,
            Self::Unix(sock) => sock.send_uses_the_address(),
            // Without the type of the socket the supervisor takes the
            // careful answer.
            Self::UnixOpaque => true,
        }
    }

    /// The type of the socket (`SOCK_DGRAM`, ...), when it is known.
    fn kind(&self) -> Option<libc::c_int> {
        match self {
            Self::Unix(sock) => Some(sock.kind()),
            Self::Other | Self::UnixOpaque => None,
        }
    }
}

/// One send that carries an address, as the supervisor read it.
struct SeenSend<'a> {
    /// The thread that made the call.
    tid: u32,
    /// The socket of the child.
    sockfd: RawFd,
    /// The flags of the call.
    flags: u64,
    /// The payload of the message, in the memory of the child.
    ranges: &'a [(u64, usize)],
    /// Whether the message carries ancillary data.
    control: Control,
}

/// Whether a message carries ancillary data (`msg_control`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Control {
    /// The message carries ancillary data.
    Yes,
    /// The message carries none.
    No,
}

/// The answer to one notification.
enum Answer {
    /// Let the kernel run the system call.
    Continue,
    /// Fail the call with this error number.
    Fail(i32),
    /// The supervisor did the work; the call returns this value.
    Return(i64),
    /// Put `fd` at the number `at` in the child and return the value 0.
    Give {
        /// The connected socket of the supervisor.
        fd: OwnedFd,
        /// The number that it takes in the child (the socket of the child).
        at: RawFd,
        /// The descriptor of the child was close-on-exec.
        cloexec: bool,
    },
}

struct Supervisor {
    listener: OwnedFd,
    /// How the recorder decides the outcome of a filesystem event. `None`
    /// turns the events off.
    judge: Option<Judge>,
    /// The control of `connect(2)` to a Unix socket.
    unix: crate::linux_unixconn::UnixControl,
    /// The answer to the current notification.
    answer: Answer,
    procs: ProcCache,
    page: usize,
    /// The buffer for `SECCOMP_IOCTL_NOTIF_RECV` (the kernel size or more).
    req: Vec<u64>,
    /// The buffer for `SECCOMP_IOCTL_NOTIF_SEND`.
    resp: Vec<u64>,
    /// The buffer for a path from the memory of the process.
    path_buf: Box<[u8]>,
    /// The buffer for the payload of a send that the supervisor performs.
    send_buf: Vec<u8>,
    /// The events of the current notification.
    out: Vec<WatchEvent>,
    /// The number of unexpected errors (the log shows only the first few).
    errors: u32,
}

impl Supervisor {
    fn new(listener: OwnedFd, plan: RecorderPlan) -> Self {
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
            judge: plan.judge,
            unix: plan.unix,
            answer: Answer::Continue,
            procs: ProcCache::default(),
            page,
            req: aligned_buffer(req_len.max(std::mem::size_of::<libc::seccomp_notif>())),
            resp: aligned_buffer(resp_len.max(std::mem::size_of::<libc::seccomp_notif_resp>())),
            path_buf: vec![0u8; libc::PATH_MAX as usize].into_boxed_slice(),
            send_buf: Vec::new(),
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
        self.answer = Answer::Continue;
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

    /// Put the descriptor `fd` of the supervisor at the number `at` in the
    /// child of the notification `id`.
    ///
    /// # Errors
    /// Returns the error number of the ioctl. `ENOENT` means that the task
    /// died; the answer then fails too, and the child needs none.
    fn add_fd(&self, id: u64, fd: &OwnedFd, at: RawFd, cloexec: bool) -> Result<(), i32> {
        let req = NotifAddfd {
            id,
            flags: ADDFD_FLAG_SETFD,
            srcfd: u32::try_from(fd.as_raw_fd()).map_err(|_| libc::EBADF)?,
            newfd: u32::try_from(at).map_err(|_| libc::EBADF)?,
            // The flag value is positive and small.
            #[allow(clippy::cast_sign_loss)]
            newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
        };
        // SAFETY: the ioctl reads one `struct seccomp_notif_addfd`, and
        // `req` lives until the call returns.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe { libc::ioctl(self.listener.as_raw_fd(), NOTIF_ADDFD, &raw const req) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        Ok(())
    }

    fn respond(&mut self, id: u64) {
        self.resp.fill(0);
        let answer = std::mem::replace(&mut self.answer, Answer::Continue);
        let resp = match answer {
            Answer::Continue => libc::seccomp_notif_resp {
                id,
                val: 0,
                error: 0,
                // The flag value is 1.
                #[allow(clippy::cast_possible_truncation)]
                flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
            },
            Answer::Fail(err) => libc::seccomp_notif_resp {
                id,
                val: 0,
                error: -err,
                flags: 0,
            },
            Answer::Return(val) => libc::seccomp_notif_resp {
                id,
                val,
                error: 0,
                flags: 0,
            },
            Answer::Give { fd, at, cloexec } => {
                // The child keeps its descriptor number, so `connect(2)`
                // returns 0 and the program goes on with a connected
                // socket.
                let error = match self.add_fd(id, &fd, at, cloexec) {
                    Ok(()) => 0,
                    Err(e) => -e,
                };
                libc::seccomp_notif_resp {
                    id,
                    val: 0,
                    error,
                    flags: 0,
                }
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

    /// The outcome that the judge gives to one filesystem operation.
    /// Without a judge the recorder makes no event.
    fn judge_fs(&self, op: FsOp, path: &Path, is_dir: bool) -> Outcome {
        self.judge
            .as_ref()
            .map_or(Outcome::Allowed, |j| j.fs(op, path, is_dir))
    }

    /// True if the supervisor must deny the operation itself.
    fn judge_denies(&self, op: FsOp, path: &Path) -> bool {
        self.judge.as_ref().is_some_and(|j| j.denies(op, path))
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
        let outcome = self.judge_fs(op, &path, st.is_dir);
        if self.judge_denies(op, &path) {
            self.answer = Answer::Fail(libc::EACCES);
        }
        self.out.push(WatchEvent::Fs {
            op,
            path,
            process: process.clone(),
            outcome,
        });
        if let Some(target) = target {
            let outcome = self.judge_fs(op, &target, st.is_dir);
            if self.judge_denies(op, &target) {
                self.answer = Answer::Fail(libc::EACCES);
            }
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
            Call::Connect => self.record_connect(notif),
            Call::Send(kind) => self.record_send(notif, kind),
        }
    }

    /// Read the address at `addr` in the memory of `tid`.
    ///
    /// The supervisor reads the address one time. It never reads it again
    /// and never lets the kernel read it again after a decision, so no
    /// other thread can change the target (see
    /// [`crate::linux_unixconn`]).
    fn read_unix_addr(&mut self, tid: u32, addr: u64, len: u64) -> SeenAddr {
        let len = usize::try_from(len).unwrap_or(0).min(SOCKADDR_UN_LEN);
        let mut seen = SeenAddr {
            raw: [0u8; SOCKADDR_UN_LEN],
            len: 0,
            kind: AddrKind::Unreadable,
        };
        let Some(buf) = seen.raw.get_mut(..len) else {
            return seen;
        };
        let n = self.read_remote(tid, addr, buf);
        seen.len = n;
        let Some(family) = seen
            .raw
            .get(..n.min(2))
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_ne_bytes)
        else {
            // The address is shorter than a family or its memory is not
            // readable.
            return seen;
        };
        // AF_UNIX is 1.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if family != libc::AF_UNIX as u16 {
            seen.kind = AddrKind::Raw;
            return seen;
        }
        let sun_path = seen.raw.get(2..n).unwrap_or_default().to_vec();
        seen.kind = unix_target(&sun_path, |raw| {
            resolve_path(raw, false, || Self::base_dir(tid, libc::AT_FDCWD))
        })
        .map_or(AddrKind::Raw, AddrKind::Unix);
        seen
    }

    /// The socket that a trapped call names.
    ///
    /// The supervisor takes the family from the socket, never from the
    /// `sockaddr`: a second thread can change the memory of the child
    /// after the check, the domain of a socket never (finding CT-1 in
    /// `docs/security/containment.md`).
    fn socket_of_call(&mut self, tid: u32, fd: RawFd) -> SocketOfCall {
        let pid = self.procs.get(tid).pid;
        match crate::linux_unixconn::child_socket(pid, fd) {
            Some(sock) if sock.is_unix() => SocketOfCall::Unix(sock),
            Some(_) => SocketOfCall::Other,
            // Without a copy of the descriptor the supervisor asks the
            // table of the Unix sockets of the task. It then knows the
            // family, but it cannot make a call on the socket itself.
            None if crate::linux_unixconn::is_unix_socket(tid, fd) => SocketOfCall::UnixOpaque,
            None => SocketOfCall::Other,
        }
    }

    /// Add the event of one decision of the Unix socket control. Watch
    /// mode proposes the socket from it, and `pent run --trace` reports
    /// the denial.
    fn record_unix_event(&mut self, tid: u32, target: &UnixAddr, outcome: Outcome) {
        if self.judge.is_none() {
            return;
        }
        let process = self.procs.get(tid);
        self.out.push(WatchEvent::UnixConnect {
            target: target.display(),
            process,
            outcome,
        });
    }

    /// Control a `connect()` on a socket of the `AF_UNIX` family.
    ///
    /// The supervisor answers `CONTINUE` only for a socket of another
    /// family. For an `AF_UNIX` socket it makes the connection itself or
    /// fails the call, whatever the address says: the kernel reads the
    /// address again after a `CONTINUE` (see [`crate::linux_unixconn`]).
    fn record_connect(&mut self, notif: &libc::seccomp_notif) {
        let tid = notif.pid;
        let args = notif.data.args;
        let (Some(&sockfd), Some(&addr), Some(&len)) = (args.first(), args.get(1), args.get(2))
        else {
            return;
        };
        // The kernel uses the low 32 bits of a descriptor argument.
        #[allow(clippy::cast_possible_truncation)]
        let sockfd = sockfd as RawFd;
        let socket = self.socket_of_call(tid, sockfd);
        if !socket.is_unix() {
            // A socket of another family reaches no Unix socket, whatever
            // another thread writes in the address.
            return;
        }
        let seen = self.read_unix_addr(tid, addr, len);
        let flags = crate::linux_unixconn::fd_flags(tid, sockfd);
        let target = match &seen.kind {
            // A `CONTINUE` here would trust memory that the supervisor
            // could not read. The kernel gives the same error.
            AddrKind::Unreadable => return self.fail_if_enforced(libc::EFAULT),
            // An address of another family, or one with no name. Only the
            // kernel knows the right answer (`AF_UNSPEC` breaks the
            // association of a datagram socket, every other form gives an
            // error), so the supervisor makes the call on the socket of
            // the child. There is no Unix target, thus no event.
            AddrKind::Raw => {
                if self.unix.enforces() {
                    if !self.id_valid(notif.id) {
                        return;
                    }
                    self.answer = Self::connect_on_child(&socket, &seen, flags);
                }
                return;
            }
            AddrKind::Unix(target) => target.clone(),
        };
        let decision = self.unix.policy().decide(&target);
        if self.unix.enforces() {
            // The address must belong to a task that still runs: a dead
            // task must get no descriptor, and its identifier can belong
            // to another process now.
            if !self.id_valid(notif.id) {
                return;
            }
            self.answer = match &decision {
                UnixDecision::Perform(path) => {
                    match crate::linux_unixconn::connect_for_child(
                        tid,
                        sockfd,
                        socket.kind(),
                        path,
                        flags,
                        crate::linux_unixconn::CONNECT_LIMIT,
                    ) {
                        Ok(fd) => Answer::Give {
                            fd,
                            at: sockfd,
                            cloexec: flags.cloexec,
                        },
                        Err(err) => Answer::Fail(err),
                    }
                }
                // An abstract name: the supervisor cannot reach it with a
                // socket of its own, because the name belongs to the
                // network namespace of the socket of the child.
                UnixDecision::Child => Self::connect_on_child(&socket, &seen, flags),
                UnixDecision::Refuse => Answer::Fail(libc::EACCES),
            };
        }
        self.record_unix_event(tid, &target, decision.outcome());
    }

    /// Connect the socket of the child itself to the address that the
    /// supervisor read.
    fn connect_on_child(
        socket: &SocketOfCall,
        seen: &SeenAddr,
        flags: crate::linux_unixconn::FdFlags,
    ) -> Answer {
        let SocketOfCall::Unix(sock) = socket else {
            // Without a copy of the descriptor the supervisor cannot make
            // the call, and it must not give the address to the kernel.
            return Answer::Fail(libc::EACCES);
        };
        match crate::linux_unixconn::connect_child_socket(
            sock,
            seen.bytes(),
            flags,
            crate::linux_unixconn::CONNECT_LIMIT,
        ) {
            Ok(()) => Answer::Return(0),
            Err(err) => Answer::Fail(err),
        }
    }

    /// Fail the current call with `err`, but only with enforcement. Watch
    /// mode records and changes nothing.
    fn fail_if_enforced(&mut self, err: i32) {
        if self.unix.enforces() {
            self.answer = Answer::Fail(err);
        }
    }

    /// Control a send that carries an address.
    fn record_send(&mut self, notif: &libc::seccomp_notif, kind: SendCall) {
        match kind {
            SendCall::To => self.record_send_to(notif),
            SendCall::Msg => self.record_send_msg(notif),
            SendCall::Many => self.record_send_many(notif),
        }
    }

    /// `sendto(fd, buf, len, flags, addr, addrlen)`.
    ///
    /// The filter traps the call only with an address: the pointer is an
    /// argument, so a null one needs no notification and no thread can
    /// change it.
    fn record_send_to(&mut self, notif: &libc::seccomp_notif) {
        let tid = notif.pid;
        let args = notif.data.args;
        let (Some(&sockfd), Some(&buf), Some(&buflen), Some(&flags)) =
            (args.first(), args.get(1), args.get(2), args.get(3))
        else {
            return;
        };
        let (Some(&addr), Some(&addrlen)) = (args.get(4), args.get(5)) else {
            return;
        };
        if addr == 0 || addrlen == 0 {
            // A connected socket: the call carries no address.
            return;
        }
        // The kernel uses the low 32 bits of a descriptor argument.
        #[allow(clippy::cast_possible_truncation)]
        let sockfd = sockfd as RawFd;
        let socket = self.socket_of_call(tid, sockfd);
        if !socket.uses_the_send_address() {
            return;
        }
        let seen = self.read_unix_addr(tid, addr, addrlen);
        let ranges = [(buf, usize::try_from(buflen).unwrap_or(0))];
        let send = SeenSend {
            tid,
            sockfd,
            flags,
            ranges: &ranges,
            control: Control::No,
        };
        self.decide_send(notif, &socket, &seen, &send);
    }

    /// `sendmsg(fd, msghdr, flags)`.
    fn record_send_msg(&mut self, notif: &libc::seccomp_notif) {
        let tid = notif.pid;
        let args = notif.data.args;
        let (Some(&sockfd), Some(&hdr), Some(&flags)) = (args.first(), args.get(1), args.get(2))
        else {
            return;
        };
        // The kernel uses the low 32 bits of a descriptor argument.
        #[allow(clippy::cast_possible_truncation)]
        let sockfd = sockfd as RawFd;
        let socket = self.socket_of_call(tid, sockfd);
        if !socket.uses_the_send_address() {
            // A stream socket refuses an address and a sequential packet
            // socket drops it, so the message reaches only the peer of
            // the socket. The call keeps its way, with its ancillary
            // data.
            return;
        }
        let Some(msg) = self.read_msghdr(tid, hdr) else {
            return self.fail_if_enforced(libc::EFAULT);
        };
        let Some(ranges) = self.read_iovecs(tid, msg.iov, msg.iovlen) else {
            return self.fail_if_enforced(libc::EFAULT);
        };
        let control = if msg.controllen == 0 {
            Control::No
        } else {
            Control::Yes
        };
        let send = SeenSend {
            tid,
            sockfd,
            flags,
            ranges: &ranges,
            control,
        };
        if msg.name == 0 || msg.namelen == 0 {
            // A connected datagram socket. The address of the message
            // lives in memory, so another thread can put a path there
            // after the check; the supervisor sends on the socket of the
            // child itself instead of answering `CONTINUE`.
            if self.unix.enforces() {
                if !self.id_valid(notif.id) {
                    return;
                }
                self.answer = self.send_on_child(&socket, &send);
            }
            return;
        }
        let seen = self.read_unix_addr(tid, msg.name, msg.namelen);
        self.decide_send(notif, &socket, &seen, &send);
    }

    /// `sendmmsg(fd, mmsghdr[], vlen, flags)`.
    ///
    /// One call carries several messages, so the supervisor does not
    /// perform it. A message with an `AF_UNIX` path fails the whole call
    /// with `EACCES`, also for a path that the profile names (see
    /// [`crate::linux_unixconn`]).
    fn record_send_many(&mut self, notif: &libc::seccomp_notif) {
        let tid = notif.pid;
        let args = notif.data.args;
        let (Some(&sockfd), Some(&base), Some(&vlen)) = (args.first(), args.get(1), args.get(2))
        else {
            return;
        };
        // The kernel uses the low 32 bits of a descriptor argument.
        #[allow(clippy::cast_possible_truncation)]
        let sockfd = sockfd as RawFd;
        if !self.socket_of_call(tid, sockfd).uses_the_send_address() {
            return;
        }
        let count = usize::try_from(vlen).unwrap_or(0).min(UIO_MAXIOV);
        let mut refuse = false;
        for i in 0..count {
            let Some(at) = u64::try_from(i.saturating_mul(MMSGHDR_LEN))
                .ok()
                .and_then(|off| base.checked_add(off))
            else {
                break;
            };
            let Some(msg) = self.read_msghdr(tid, at) else {
                return self.fail_if_enforced(libc::EFAULT);
            };
            if msg.name == 0 || msg.namelen == 0 {
                // A message with no address reaches only the peer of the
                // socket.
                continue;
            }
            let target = match self.read_unix_addr(tid, msg.name, msg.namelen).kind {
                AddrKind::Raw => continue,
                AddrKind::Unreadable => return self.fail_if_enforced(libc::EFAULT),
                AddrKind::Unix(target) => target,
            };
            let decision = self.unix.policy().decide_many(&target);
            refuse = refuse || decision == UnixDecision::Refuse;
            self.record_unix_event(tid, &target, decision.outcome());
        }
        if refuse {
            self.fail_if_enforced(libc::EACCES);
        }
    }

    /// Apply the policy to one send on a socket of the `AF_UNIX` family,
    /// and record the decision.
    fn decide_send(
        &mut self,
        notif: &libc::seccomp_notif,
        socket: &SocketOfCall,
        seen: &SeenAddr,
        send: &SeenSend,
    ) {
        let target = match &seen.kind {
            AddrKind::Unreadable => return self.fail_if_enforced(libc::EFAULT),
            // The kernel takes only an `AF_UNIX` address with a name on a
            // Unix socket; every other form gives `EINVAL`.
            AddrKind::Raw => return self.fail_if_enforced(libc::EINVAL),
            AddrKind::Unix(target) => target.clone(),
        };
        let decision = self.unix.policy().decide(&target);
        if self.unix.enforces() {
            // The call must belong to a task that still runs: its
            // identifier can belong to another process now.
            if !self.id_valid(notif.id) {
                return;
            }
            self.answer = match &decision {
                UnixDecision::Perform(path) => {
                    let path = path.clone();
                    self.perform_send(&path, socket, send)
                }
                // An abstract name: only the socket of the child reaches
                // the names of its own network namespace.
                UnixDecision::Child => self.send_to_name_on_child(socket, seen, send),
                UnixDecision::Refuse => Answer::Fail(libc::EACCES),
            };
        }
        self.record_unix_event(send.tid, &target, decision.outcome());
    }

    /// Send the payload of the child to `path` from a socket of the
    /// supervisor, and return the answer for the call.
    fn perform_send(&mut self, path: &Path, socket: &SocketOfCall, send: &SeenSend) -> Answer {
        let len = match self.payload_of(send) {
            Ok(len) => len,
            Err(err) => return Answer::Fail(err),
        };
        // The kernel uses the low 32 bits of the flags argument.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let flags = send.flags as libc::c_int;
        let payload = self.send_buf.get(..len).unwrap_or_default();
        match crate::linux_unixconn::send_for_child(
            send.tid,
            send.sockfd,
            socket.kind(),
            path,
            payload,
            flags,
            crate::linux_unixconn::CONNECT_LIMIT,
        ) {
            Ok(sent) => i64::try_from(sent).map_or(Answer::Fail(libc::EIO), Answer::Return),
            Err(err) => Answer::Fail(err),
        }
    }

    /// Send the payload of the child on the socket of the child itself,
    /// to the peer of that socket.
    fn send_on_child(&mut self, socket: &SocketOfCall, send: &SeenSend) -> Answer {
        let SocketOfCall::Unix(sock) = socket else {
            return Answer::Fail(libc::EACCES);
        };
        let len = match self.payload_of(send) {
            Ok(len) => len,
            Err(err) => return Answer::Fail(err),
        };
        // The kernel uses the low 32 bits of the flags argument.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let flags = send.flags as libc::c_int;
        let fd_flags = crate::linux_unixconn::fd_flags(send.tid, send.sockfd);
        let payload = self.send_buf.get(..len).unwrap_or_default();
        match crate::linux_unixconn::send_on_child_socket(
            sock,
            payload,
            flags,
            fd_flags,
            crate::linux_unixconn::CONNECT_LIMIT,
        ) {
            Ok(sent) => i64::try_from(sent).map_or(Answer::Fail(libc::EIO), Answer::Return),
            Err(err) => Answer::Fail(err),
        }
    }

    /// Send the payload of the child to an abstract name, on the socket
    /// of the child itself.
    fn send_to_name_on_child(
        &mut self,
        socket: &SocketOfCall,
        seen: &SeenAddr,
        send: &SeenSend,
    ) -> Answer {
        let SocketOfCall::Unix(sock) = socket else {
            return Answer::Fail(libc::EACCES);
        };
        let len = match self.payload_of(send) {
            Ok(len) => len,
            Err(err) => return Answer::Fail(err),
        };
        // The kernel uses the low 32 bits of the flags argument.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let flags = send.flags as libc::c_int;
        let fd_flags = crate::linux_unixconn::fd_flags(send.tid, send.sockfd);
        let payload = self.send_buf.get(..len).unwrap_or_default();
        match crate::linux_unixconn::send_to_name_on_child_socket(
            sock,
            seen.bytes(),
            payload,
            flags,
            fd_flags,
            crate::linux_unixconn::CONNECT_LIMIT,
        ) {
            Ok(sent) => i64::try_from(sent).map_or(Answer::Fail(libc::EIO), Answer::Return),
            Err(err) => Answer::Fail(err),
        }
    }

    /// Put the payload of `send` in the buffer of the supervisor and
    /// return its length.
    ///
    /// # Errors
    /// Returns `EOPNOTSUPP` when the message carries ancillary data,
    /// which the supervisor cannot pass on, and the errors of
    /// [`Self::read_payload`].
    fn payload_of(&mut self, send: &SeenSend) -> Result<usize, i32> {
        if send.control == Control::Yes {
            // The supervisor cannot pass the descriptors or the
            // credentials of the child.
            return Err(libc::EOPNOTSUPP);
        }
        self.read_payload(send.tid, send.ranges)
    }

    /// Read a `struct msghdr` at `addr` in the memory of `tid`.
    fn read_msghdr(&mut self, tid: u32, addr: u64) -> Option<MsgHdr> {
        let mut bytes = [0u8; MSGHDR_LEN];
        if self.read_remote(tid, addr, &mut bytes) < MSGHDR_LEN {
            return None;
        }
        parse_msghdr(&bytes)
    }

    /// Read the payload ranges of a `struct msghdr` from the `iovec` array
    /// at `addr`. An empty list is a message with no payload; `None` means
    /// that the supervisor cannot read the array, and the call then fails
    /// with `EFAULT`, as it would in the kernel.
    fn read_iovecs(&mut self, tid: u32, addr: u64, count: u64) -> Option<Vec<(u64, usize)>> {
        let count = usize::try_from(count).unwrap_or(0).min(UIO_MAXIOV);
        if count == 0 || addr == 0 {
            return Some(Vec::new());
        }
        let mut bytes = vec![0u8; count.saturating_mul(IOVEC_LEN)];
        let n = self.read_ranges(tid, &[(addr, bytes.len())], &mut bytes);
        if n < bytes.len() {
            return None;
        }
        Some(parse_iovecs(&bytes, count))
    }

    /// Copy the payload of `ranges` into the buffer of the supervisor and
    /// return its length.
    ///
    /// # Errors
    /// Returns `EMSGSIZE` for a payload above
    /// [`crate::linux_unixconn::SEND_PAYLOAD_LIMIT`], and `EFAULT` when the
    /// memory of the child is not readable.
    fn read_payload(&mut self, tid: u32, ranges: &[(u64, usize)]) -> Result<usize, i32> {
        let mut total: usize = 0;
        for (_, len) in ranges {
            total = total.checked_add(*len).ok_or(libc::EMSGSIZE)?;
        }
        if total > crate::linux_unixconn::SEND_PAYLOAD_LIMIT {
            return Err(libc::EMSGSIZE);
        }
        if ranges.is_empty() && total == 0 {
            // A message with no payload. `sendto` with a null pointer and
            // the length 0 is one of them.
            self.send_buf.clear();
            return Ok(0);
        }
        let mut buf = std::mem::take(&mut self.send_buf);
        buf.clear();
        buf.resize(total, 0);
        let n = self.read_ranges(tid, ranges, &mut buf);
        self.send_buf = buf;
        if n < total {
            return Err(libc::EFAULT);
        }
        Ok(total)
    }

    /// Read the memory ranges `ranges` of the process `pid` into `buf`.
    /// Returns the number of bytes that the call read.
    fn read_ranges(&self, pid: u32, ranges: &[(u64, usize)], buf: &mut [u8]) -> usize {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return 0;
        };
        let remote: Vec<libc::iovec> = ranges
            .iter()
            .map(|(addr, len)| libc::iovec {
                iov_base: *addr as usize as *mut libc::c_void,
                iov_len: *len,
            })
            .collect();
        let Ok(count) = libc::c_ulong::try_from(remote.len()) else {
            return 0;
        };
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: `local` points to `buf.len()` writable bytes; the remote
        // ranges are only read in the other process.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n =
            unsafe { libc::process_vm_readv(pid, &raw const local, 1, remote.as_ptr(), count, 0) };
        usize::try_from(n).unwrap_or(0)
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
    let spawned = crate::linux::spawn_linux(
        config,
        cmd,
        args,
        &config.env,
        &[],
        SpawnMode::Watch {
            guard: &plan,
            unix_sockets: &options.unix_sockets,
        },
    )?;
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
        run_bpf_with_args(prog, nr, arch, &[])
    }

    /// The same interpreter, with the arguments of the system call.
    fn run_bpf_with_args(
        prog: &[libc::sock_filter],
        nr: u32,
        arch: u32,
        args: &[u64],
    ) -> Option<u32> {
        let mut data = [0u8; 64];
        data.get_mut(0..4)?.copy_from_slice(&nr.to_ne_bytes());
        data.get_mut(4..8)?.copy_from_slice(&arch.to_ne_bytes());
        for (i, arg) in args.iter().enumerate() {
            let at = 16 + i * 8;
            data.get_mut(at..at + 8)?
                .copy_from_slice(&arg.to_ne_bytes());
        }
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
            addr_calls: &[],
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
            addr_calls: &[],
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
            addr_calls: &[],
        };
        assert!(build_filter(&spec).is_err());
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn native_filter_covers_the_calls() -> TestResult {
        let prog = native_filter(RecorderScope::Full)?;
        let Some((arch, _)) = NATIVE else {
            return Err("no native spec".into());
        };
        for (nr, _) in CALLS.iter().chain(CONTROL_CALLS) {
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
        assert_eq!(NOTIF_ADDFD, 0x4018_2103);
        assert_eq!(NOTIF_SET_FLAGS, 0x4008_2104);
        assert_eq!(std::mem::size_of::<NotifAddfd>(), 24);
    }

    /// A call with an address goes to the supervisor; the same call
    /// without one runs with no notification. The filter reads both words
    /// of the pointer: a program can map a page whose address has the low
    /// word zero.
    #[test]
    fn filter_traps_a_send_that_carries_an_address() -> TestResult {
        let spec = FilterSpec {
            audit_arch: 0xC000_003E,
            foreign_nr_min: Some(X32_SYSCALL_BIT),
            enosys: &[425],
            notify: &[42],
            addr_calls: &[AddrCall { nr: 44, arg: 4 }, AddrCall { nr: 307, arg: 1 }],
        };
        let prog = build_filter(&spec)?;
        let arch = spec.audit_arch;
        let with_addr = [0, 0, 0, 0, 0x7fff_0000_1234, 110];
        let no_addr = [0, 0, 0, 0, 0, 0];
        // Only the low word is zero: the pointer is not null.
        let high_only = [0u64, 0, 0, 0, 0x1_0000_0000, 110];
        assert_eq!(
            run_bpf_with_args(&prog, 44, arch, &with_addr),
            Some(RET_NOTIFY)
        );
        assert_eq!(
            run_bpf_with_args(&prog, 44, arch, &no_addr),
            Some(SECCOMP_RET_ALLOW)
        );
        assert_eq!(
            run_bpf_with_args(&prog, 44, arch, &high_only),
            Some(RET_NOTIFY)
        );
        // The second block reads its own argument.
        assert_eq!(
            run_bpf_with_args(&prog, 307, arch, &[0, 0x4242, 0, 0, 0, 0]),
            Some(RET_NOTIFY)
        );
        assert_eq!(
            run_bpf_with_args(&prog, 307, arch, &no_addr),
            Some(SECCOMP_RET_ALLOW)
        );
        // The other classes keep their answer.
        assert_eq!(
            run_bpf_with_args(&prog, 42, arch, &no_addr),
            Some(RET_NOTIFY)
        );
        assert_eq!(run_bpf(&prog, 425, arch), Some(RET_ENOSYS));
        assert_eq!(run_bpf(&prog, 39, arch), Some(SECCOMP_RET_ALLOW));
        assert_eq!(run_bpf(&prog, 5, 0x4000_0003), Some(RET_ENOSYS));
        Ok(())
    }

    /// The filter leaves `socket(2)` and `socketpair(2)` alone: the child
    /// makes a Unix socket of its own, and the control of the address
    /// decides what it reaches.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn filter_permits_the_unix_family() -> TestResult {
        let Some((arch, _)) = NATIVE else {
            return Err("no native spec".into());
        };
        // The cast is exact: AF_UNIX is 1.
        #[allow(clippy::cast_sign_loss)]
        let unix = libc::AF_UNIX as u64;
        for scope in [RecorderScope::Full, RecorderScope::ConnectOnly] {
            let prog = native_filter(scope)?;
            for call in [libc::SYS_socket, libc::SYS_socketpair] {
                let nr = u32::try_from(call)?;
                assert_eq!(
                    run_bpf_with_args(&prog, nr, arch, &[unix, 0, 0, 0, 0, 0]),
                    Some(SECCOMP_RET_ALLOW),
                    "the call {call} of the scope {scope:?} must run"
                );
            }
        }
        Ok(())
    }

    /// The connect-only scope traps the calls of the Unix socket control
    /// and nothing else, and it keeps `io_uring_setup` away: io_uring has
    /// a connect operation that seccomp does not see.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn connect_only_filter_traps_the_control_calls() -> TestResult {
        let prog = native_filter(RecorderScope::ConnectOnly)?;
        let Some((arch, _)) = NATIVE else {
            return Err("no native spec".into());
        };
        for call in [libc::SYS_connect, libc::SYS_sendmsg, libc::SYS_sendmmsg] {
            assert_eq!(
                run_bpf(&prog, u32::try_from(call)?, arch),
                Some(RET_NOTIFY),
                "the call {call} must go to the supervisor"
            );
        }
        // `sendto` goes to the supervisor only with an address.
        let sendto = u32::try_from(libc::SYS_sendto)?;
        assert_eq!(
            run_bpf_with_args(&prog, sendto, arch, &[3, 0, 0, 0, 0x7fff_0000, 110]),
            Some(RET_NOTIFY)
        );
        assert_eq!(
            run_bpf_with_args(&prog, sendto, arch, &[3, 0, 0, 0, 0, 0]),
            Some(SECCOMP_RET_ALLOW)
        );
        let openat = u32::try_from(libc::SYS_openat)?;
        assert_eq!(run_bpf(&prog, openat, arch), Some(SECCOMP_RET_ALLOW));
        let uring = u32::try_from(libc::SYS_io_uring_setup)?;
        assert_eq!(run_bpf(&prog, uring, arch), Some(RET_ENOSYS));
        Ok(())
    }

    /// The offsets of `struct msghdr` and the parse of its fields.
    #[test]
    fn msghdr_fields_come_from_the_bytes() {
        assert_eq!(MSGHDR_LEN, 56, "the layout of a 64-bit kernel");
        assert_eq!(MMSGHDR_LEN, 64);
        assert_eq!(IOVEC_LEN, 16);
        let mut bytes = [0u8; MSGHDR_LEN];
        let put = |b: &mut [u8; MSGHDR_LEN], at: usize, v: u64| {
            if let Some(slot) = b.get_mut(at..at + 8) {
                slot.copy_from_slice(&v.to_ne_bytes());
            }
        };
        put(
            &mut bytes,
            std::mem::offset_of!(libc::msghdr, msg_name),
            0x11,
        );
        put(
            &mut bytes,
            std::mem::offset_of!(libc::msghdr, msg_namelen),
            110,
        );
        put(
            &mut bytes,
            std::mem::offset_of!(libc::msghdr, msg_iov),
            0x22,
        );
        put(
            &mut bytes,
            std::mem::offset_of!(libc::msghdr, msg_iovlen),
            2,
        );
        put(
            &mut bytes,
            std::mem::offset_of!(libc::msghdr, msg_controllen),
            16,
        );
        assert_eq!(
            parse_msghdr(&bytes),
            Some(MsgHdr {
                name: 0x11,
                namelen: 110,
                iov: 0x22,
                iovlen: 2,
                controllen: 16,
            })
        );
        // `msg_namelen` is 32 bits wide: the next field does not leak in.
        assert_eq!(parse_msghdr(&[0u8; 8]), None);
    }

    /// The payload ranges come from the `iovec` array of the message.
    #[test]
    fn iovecs_give_the_payload_ranges() {
        let mut bytes = [0u8; 2 * IOVEC_LEN];
        let put = |b: &mut [u8], at: usize, v: u64| {
            if let Some(slot) = b.get_mut(at..at + 8) {
                slot.copy_from_slice(&v.to_ne_bytes());
            }
        };
        put(&mut bytes, 0, 0x1000);
        put(&mut bytes, 8, 4);
        put(&mut bytes, IOVEC_LEN, 0x2000);
        put(&mut bytes, IOVEC_LEN + 8, 7);
        assert_eq!(parse_iovecs(&bytes, 2), vec![(0x1000, 4), (0x2000, 7)]);
        // A count above the bytes stops at the end of the array.
        assert_eq!(parse_iovecs(&bytes, 4), vec![(0x1000, 4), (0x2000, 7)]);
        assert!(parse_iovecs(&[], 2).is_empty());
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
        let target = |bytes: &[u8]| unix_target(bytes, resolve).map(|a| a.display());
        assert_eq!(target(b"/run/x.sock\0\0"), Some("/run/x.sock".to_string()));
        assert_eq!(target(b"rel.sock"), Some("/cwd/rel.sock".to_string()));
        assert_eq!(target(b"\0abstract"), Some("@abstract".to_string()));
        // The kernel keeps the whole address of an abstract name, so the
        // trailing zero bytes of the buffer do not belong to it.
        assert_eq!(target(b"\0abs\0\0"), Some("@abs".to_string()));
        assert_eq!(target(b""), None);
        assert_eq!(
            unix_target(b"/run/x.sock", resolve),
            Some(UnixAddr::Path(PathBuf::from("/run/x.sock")))
        );
    }

    // ── The guard plan ─────────────────────────────────────────────────────

    /// The mounts must cover each file that the rule matches, also a key in
    /// a subdirectory and a key whose name matches a suffix pattern.
    #[test]
    fn guard_plan_masks_a_key_below_a_subdirectory() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let root = std::fs::canonicalize(tmp.path())?;
        let ssh = root.join(".ssh");
        std::fs::create_dir_all(ssh.join("old/keys"))?;
        std::fs::write(ssh.join("work_rsa"), "k")?;
        std::fs::write(ssh.join("old/keys/deep_rsa"), "k")?;
        std::fs::write(ssh.join("old/notes.txt"), "n")?;
        let rules = vec![GuardRule {
            class: GuardClass::Credential,
            access: GuardAccess::Read,
            target: GuardTarget::FilesInDir {
                dir: ssh.clone(),
                prefix: "*_rsa".into(),
                exclude_suffix: Some(".pub".into()),
            },
        }];
        let plan = plan_guard(&rules);
        assert_eq!(
            plan.mask_files,
            vec![ssh.join("old/keys/deep_rsa"), ssh.join("work_rsa")]
        );
        let judge = Judge::Guard {
            enforced: plan.effective,
            unenforced: plan.unenforced,
        };
        let cred = Outcome::Blocked(GuardClass::Credential);
        assert_eq!(judge.fs(FsOp::Read, &ssh.join("work_rsa"), false), cred);
        assert_eq!(
            judge.fs(FsOp::Read, &ssh.join("old/keys/deep_rsa"), false),
            cred
        );
        assert_eq!(
            judge.fs(FsOp::Read, &ssh.join("old/notes.txt"), false),
            Outcome::Allowed
        );
        Ok(())
    }

    /// The walk does not follow a symbolic link to another directory, so
    /// the mounts cover no key behind the link. The supervisor must refuse
    /// the read instead (DIFF-5).
    #[test]
    fn guard_plan_does_not_follow_a_link_out_of_the_directory() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let root = std::fs::canonicalize(tmp.path())?;
        let ssh = root.join(".ssh");
        let other = root.join("other");
        std::fs::create_dir(&ssh)?;
        std::fs::create_dir(&other)?;
        std::fs::write(other.join("id_rsa"), "k")?;
        std::os::unix::fs::symlink(&other, ssh.join("link"))?;
        let rules = vec![GuardRule {
            class: GuardClass::Credential,
            access: GuardAccess::Read,
            target: GuardTarget::FilesInDir {
                dir: ssh.clone(),
                prefix: "id_".into(),
                exclude_suffix: None,
            },
        }];
        let plan = plan_guard(&rules);
        assert!(plan.mask_files.is_empty(), "{:?}", plan.mask_files);
        let judge = Judge::Guard {
            enforced: plan.effective,
            unenforced: plan.unenforced,
        };
        let linked = ssh.join("link/id_rsa");
        assert_eq!(
            judge.fs(FsOp::Read, &linked, false),
            Outcome::Blocked(GuardClass::Credential)
        );
        assert!(
            judge.denies(FsOp::Read, &linked),
            "the summary says blocked, so the supervisor must refuse the read"
        );
        Ok(())
    }

    /// A key that the program makes during the run has no mount, because
    /// the file does not exist when the child starts. The supervisor must
    /// refuse the read (DIFF-6).
    #[test]
    fn guard_plan_refuses_a_key_made_during_the_run() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let root = std::fs::canonicalize(tmp.path())?;
        let ssh = root.join(".ssh");
        std::fs::create_dir(&ssh)?;
        let rules = vec![GuardRule {
            class: GuardClass::Credential,
            access: GuardAccess::Read,
            target: GuardTarget::FilesInDir {
                dir: ssh.clone(),
                prefix: "id_".into(),
                exclude_suffix: Some(".pub".into()),
            },
        }];
        let plan = plan_guard(&rules);
        assert!(plan.mask_files.is_empty(), "{:?}", plan.mask_files);
        let judge = Judge::Guard {
            enforced: plan.effective,
            unenforced: plan.unenforced,
        };
        let new_key = ssh.join("id_new");
        // The program may make the file; only the read is a credential
        // read.
        assert!(!judge.denies(FsOp::Create, &new_key));
        assert_eq!(
            judge.fs(FsOp::Read, &new_key, false),
            Outcome::Blocked(GuardClass::Credential)
        );
        assert!(judge.denies(FsOp::Read, &new_key));
        // The public key is not a credential.
        assert!(!judge.denies(FsOp::Read, &ssh.join("id_new.pub")));
        Ok(())
    }

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
            &WatchOptions {
                guard: Vec::new(),
                unix_sockets: Vec::new(),
            },
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
            &WatchOptions {
                guard,
                unix_sockets: Vec::new(),
            },
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
            &WatchOptions {
                guard: Vec::new(),
                unix_sockets: Vec::new(),
            },
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

    /// A grandchild of two forks keeps its events. PID 1 of the new PID
    /// namespace adopts it, and `SECCOMP_IOCTL_NOTIF_RECV` names the task
    /// in the namespace of the reader, which is pent on the host.
    #[test]
    #[serial]
    fn watch_keeps_the_events_of_a_double_forked_grandchild() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let script = "( ( sleep 0.3; cat /etc/hostname >/dev/null ) & ) &";
        let watched = crate::spawn_watched(
            &s.config,
            &WatchOptions {
                guard: Vec::new(),
                unix_sockets: Vec::new(),
            },
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

    /// Watch mode gets the PID namespace and a private `proc`, so the
    /// program sees only the processes of the sandbox.
    ///
    /// A container gives neither: the runtime hides a part of `/proc`, and
    /// the kernel then refuses a new `proc` mount. The test then skips,
    /// because the protection is genuinely absent there. See
    /// `linux::ProcIsolation`.
    #[test]
    #[serial]
    fn watch_proc_shows_only_the_sandbox() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        if !crate::linux::proc_isolation().is_private() {
            eprintln!(
                "skip (container): this host gives the program no private /proc, \
                 so watch mode cannot hide the processes of the host"
            );
            return Ok(());
        }
        let out = s.dir.join("procs");
        let script = format!("ls /proc > {}", out.display());
        let watched = crate::spawn_watched(
            &s.config,
            &WatchOptions {
                guard: Vec::new(),
                unix_sockets: Vec::new(),
            },
            &s.sh.to_string_lossy(),
            &sh_args(&script),
        )?;
        collect(watched)?;
        let text = std::fs::read_to_string(&out)?;
        let pids: Vec<&str> = text
            .lines()
            .filter(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
            .collect();
        let own = std::process::id().to_string();
        assert!(
            !pids.contains(&own.as_str()),
            "the program sees the test process: {pids:?}"
        );
        assert!(
            pids.len() < 16,
            "the program sees the processes of the host: {pids:?}"
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

    // ── The control of the Unix socket connections ─────────────────────────

    /// A sandbox that runs `python3` with the allowlist `sockets`. The
    /// probe writes its result to `<dir>/out`, because the child keeps the
    /// standard streams of the test process.
    fn python_sandbox(s: &Setup, sockets: Vec<PathBuf>) -> Option<(SandboxConfig, PathBuf)> {
        if crate::check_availability().is_err() {
            eprintln!("skip: Landlock is not available");
            return None;
        }
        let path_env = s.config.env.get("PATH").cloned().unwrap_or_default();
        let Some(py) = crate::find_in_path("python3", &path_env) else {
            eprintln!("skip: no python3 in PATH");
            return None;
        };
        let mut config = s.config.clone();
        config.unix_sockets = sockets;
        Some((config, py))
    }

    /// Run `script` with `python3` under the sandbox and return the text
    /// that the script wrote to `<dir>/out`.
    fn run_probe(
        s: &Setup,
        config: &SandboxConfig,
        py: &Path,
        script: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let out = s.dir.join("out");
        let _ = std::fs::remove_file(&out);
        let file = s.dir.join("probe.py");
        std::fs::write(&file, script)?;
        let args = vec![
            "-I".to_string(),
            file.to_string_lossy().into_owned(),
            out.to_string_lossy().into_owned(),
        ];
        let mut child = crate::spawn_sandboxed(config, &py.to_string_lossy(), &args)?;
        child.child.wait()?;
        if let Some(overlay) = child.overlay.take() {
            let _report = crate::teardown_overlay(overlay);
        }
        Ok(std::fs::read_to_string(&out).unwrap_or_default())
    }

    /// The body of one probe: connect, and write the result to the file.
    fn probe_script(kind: &str, target: &str) -> String {
        format!(
            "import socket, sys\n\
             out = open(sys.argv[1], 'w')\n\
             try:\n\
             \x20   s = socket.socket(socket.AF_UNIX, socket.{kind})\n\
             \x20   s.settimeout(5)\n\
             \x20   s.connect({target})\n\
             \x20   s.sendall(b'PING')\n\
             \x20   out.write('OK ' + repr(s.recv(32)))\n\
             except OSError as e:\n\
             \x20   out.write('ERR %d' % (e.errno or 0))\n\
             out.close()\n"
        )
    }

    /// The child reaches a socket that the allowlist names: the supervisor
    /// makes the connection and gives the connected socket to the child.
    #[test]
    #[serial]
    fn unix_connect_to_a_socket_on_the_list_works() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let sock = s.dir.join("allowed.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock)?;
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4];
                let _ = std::io::Read::read_exact(&mut stream, &mut buf);
                let _ = std::io::Write::write_all(&mut stream, b"PONG");
            }
        });
        let Some((config, py)) = python_sandbox(&s, vec![sock.clone()]) else {
            return Ok(());
        };
        let script = probe_script("SOCK_STREAM", &format!("{:?}", sock.to_string_lossy()));
        let text = run_probe(&s, &config, &py, &script)?;
        server.join().map_err(|_| "the server thread failed")?;
        assert!(text.contains("PONG"), "{text}");
        Ok(())
    }

    /// A socket that the allowlist does not name gets EACCES.
    #[test]
    #[serial]
    fn unix_connect_outside_the_list_gets_eacces() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let allowed = s.dir.join("allowed.sock");
        let denied = s.dir.join("denied.sock");
        let _keep = std::os::unix::net::UnixListener::bind(&allowed)?;
        let victim = std::os::unix::net::UnixListener::bind(&denied)?;
        let server = std::thread::spawn(move || {
            // The child must not reach this socket. The accept ends with
            // the connection of the test below.
            if let Ok((mut stream, _)) = victim.accept() {
                let _ = std::io::Write::write_all(&mut stream, b"SECRET");
            }
        });
        let Some((config, py)) = python_sandbox(&s, vec![allowed]) else {
            return Ok(());
        };
        let script = probe_script("SOCK_STREAM", &format!("{:?}", denied.to_string_lossy()));
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, format!("ERR {}", libc::EACCES), "{text}");
        drop(std::os::unix::net::UnixStream::connect(&denied));
        server.join().map_err(|_| "the server thread failed")?;
        Ok(())
    }

    /// An abstract address is refused when the child has no network
    /// namespace of its own: the names of the host are then in reach. The
    /// `setup` configuration has `--network unrestricted`.
    #[test]
    #[serial]
    fn unix_connect_to_an_abstract_name_is_refused() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let allowed = s.dir.join("allowed.sock");
        let _keep = std::os::unix::net::UnixListener::bind(&allowed)?;
        let Some((config, py)) = python_sandbox(&s, vec![allowed]) else {
            return Ok(());
        };
        let script = probe_script("SOCK_STREAM", "'\\0pent-test-abstract'");
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, format!("ERR {}", libc::EACCES), "{text}");
        Ok(())
    }

    /// A datagram socket on the list works too: the supervisor reads the
    /// kind of the socket of the child and makes a socket of that kind.
    #[test]
    #[serial]
    fn unix_connect_works_for_a_datagram_socket() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let sock = s.dir.join("dgram.sock");
        let server = std::os::unix::net::UnixDatagram::bind(&sock)?;
        server.set_read_timeout(Some(Duration::from_secs(10)))?;
        let Some((config, py)) = python_sandbox(&s, vec![sock.clone()]) else {
            return Ok(());
        };
        let script = probe_script("SOCK_DGRAM", &format!("{:?}", sock.to_string_lossy()));
        let text = run_probe(&s, &config, &py, &script)?;
        let mut buf = [0u8; 8];
        let n = server.recv(&mut buf)?;
        assert_eq!(buf.get(..n), Some(b"PING".as_slice()), "{text}");
        Ok(())
    }

    /// A connection to a TCP address keeps its way: the supervisor answers
    /// `CONTINUE` for an address family that is not `AF_UNIX`.
    #[test]
    #[serial]
    fn a_tcp_connect_is_not_affected() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = std::io::Write::write_all(&mut stream, b"TCPOK");
            }
        });
        let Some((config, py)) = python_sandbox(&s, Vec::new()) else {
            return Ok(());
        };
        let script = format!(
            "import socket, sys\n\
             out = open(sys.argv[1], 'w')\n\
             try:\n\
             \x20   s = socket.create_connection(('127.0.0.1', {port}), 5)\n\
             \x20   out.write('OK ' + repr(s.recv(32)))\n\
             except OSError as e:\n\
             \x20   out.write('ERR %d' % (e.errno or 0))\n\
             out.close()\n"
        );
        let text = run_probe(&s, &config, &py, &script)?;
        server.join().map_err(|_| "the server thread failed")?;
        assert!(text.contains("TCPOK"), "{text}");
        Ok(())
    }

    /// With an empty allowlist the child still makes a Unix socket: the
    /// control of the address decides what it reaches, and every path gets
    /// `EACCES`. `socketpair` keeps working too.
    #[test]
    #[serial]
    fn an_empty_list_permits_the_family_and_refuses_each_path() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let sock = s.dir.join("victim.sock");
        let _keep = std::os::unix::net::UnixListener::bind(&sock)?;
        let Some((config, py)) = python_sandbox(&s, Vec::new()) else {
            return Ok(());
        };
        let script = probe_script("SOCK_STREAM", &format!("{:?}", sock.to_string_lossy()));
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, format!("ERR {}", libc::EACCES), "{text}");
        let pair = "import socket, sys\n\
                    out = open(sys.argv[1], 'w')\n\
                    a, b = socket.socketpair()\n\
                    a.sendall(b'PAIR')\n\
                    c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
                    out.write(repr(b.recv(8)) + ' FAMILY OK')\n\
                    out.close()\n";
        let text = run_probe(&s, &config, &py, pair)?;
        assert!(text.contains("PAIR"), "{text}");
        assert!(text.contains("FAMILY OK"), "{text}");
        Ok(())
    }

    /// The body of one datagram probe: `sendto` to a path, and the result
    /// in the file.
    fn sendto_script(target: &str) -> String {
        format!(
            "import socket, sys\n\
             out = open(sys.argv[1], 'w')\n\
             s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
             try:\n\
             \x20   n = s.sendto(b'PING', {target})\n\
             \x20   out.write('OK %d' % n)\n\
             except OSError as e:\n\
             \x20   out.write('ERR %d' % (e.errno or 0))\n\
             out.close()\n"
        )
    }

    /// A `sendto` to a socket that the allowlist names arrives: the
    /// supervisor sends the payload itself.
    #[test]
    #[serial]
    fn sendto_a_socket_on_the_list_arrives() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let sock = s.dir.join("notify.sock");
        let server = std::os::unix::net::UnixDatagram::bind(&sock)?;
        server.set_read_timeout(Some(Duration::from_secs(10)))?;
        let Some((config, py)) = python_sandbox(&s, vec![sock.clone()]) else {
            return Ok(());
        };
        let script = sendto_script(&format!("{:?}", sock.to_string_lossy()));
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, "OK 4", "{text}");
        let mut buf = [0u8; 8];
        let n = server.recv(&mut buf)?;
        assert_eq!(buf.get(..n), Some(b"PING".as_slice()));
        Ok(())
    }

    /// A `sendto` to a socket that the allowlist does not name gets
    /// `EACCES`, and the message does not arrive. A datagram needs no
    /// `connect`, so the control of `connect` alone would miss it.
    #[test]
    #[serial]
    fn sendto_outside_the_list_gets_eacces() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let allowed = s.dir.join("allowed.sock");
        let denied = s.dir.join("denied.sock");
        let _keep = std::os::unix::net::UnixDatagram::bind(&allowed)?;
        let victim = std::os::unix::net::UnixDatagram::bind(&denied)?;
        victim.set_read_timeout(Some(Duration::from_millis(200)))?;
        let Some((config, py)) = python_sandbox(&s, vec![allowed]) else {
            return Ok(());
        };
        let script = sendto_script(&format!("{:?}", denied.to_string_lossy()));
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, format!("ERR {}", libc::EACCES), "{text}");
        let mut buf = [0u8; 8];
        assert!(
            victim.recv(&mut buf).is_err(),
            "the victim socket got a message"
        );
        Ok(())
    }

    /// `sendmsg` takes the same way as `sendto`: the address is in the
    /// `struct msghdr`, and a path outside the list gets `EACCES`.
    #[test]
    #[serial]
    fn sendmsg_outside_the_list_gets_eacces() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let allowed = s.dir.join("allowed.sock");
        let denied = s.dir.join("denied.sock");
        let _keep = std::os::unix::net::UnixDatagram::bind(&allowed)?;
        let victim = std::os::unix::net::UnixDatagram::bind(&denied)?;
        victim.set_read_timeout(Some(Duration::from_millis(200)))?;
        let Some((config, py)) = python_sandbox(&s, vec![allowed.clone()]) else {
            return Ok(());
        };
        // `sendmsg` of python takes a list of buffers, so the message has
        // two `iovec` entries.
        let script = format!(
            "import socket, sys\n\
             out = open(sys.argv[1], 'w')\n\
             s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
             def send(path):\n\
             \x20   return s.sendmsg([b'PI', b'NG'], [], 0, path)\n\
             try:\n\
             \x20   out.write('ALLOWED %d ' % send({allowed:?}))\n\
             except OSError as e:\n\
             \x20   out.write('ALLOWED ERR %d ' % (e.errno or 0))\n\
             try:\n\
             \x20   out.write('DENIED %d' % send({denied:?}))\n\
             except OSError as e:\n\
             \x20   out.write('DENIED ERR %d' % (e.errno or 0))\n\
             out.close()\n",
            allowed = allowed.to_string_lossy(),
            denied = denied.to_string_lossy(),
        );
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(
            text,
            format!("ALLOWED 4 DENIED ERR {}", libc::EACCES),
            "{text}"
        );
        let mut buf = [0u8; 8];
        assert!(
            victim.recv(&mut buf).is_err(),
            "the victim socket got a message"
        );
        Ok(())
    }

    /// Without a network namespace of its own the child shares the
    /// abstract names of the host, so each abstract address is refused.
    /// The `setup` configuration has `--network unrestricted`.
    #[test]
    #[serial]
    fn an_abstract_address_is_refused_without_a_network_namespace() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let Some((config, py)) = python_sandbox(&s, Vec::new()) else {
            return Ok(());
        };
        assert_eq!(config.network, crate::NetworkMode::Unrestricted);
        let script = probe_script("SOCK_STREAM", "'\\0pent-test-abstract'");
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, format!("ERR {}", libc::EACCES), "{text}");
        let script = sendto_script("'\\0pent-test-abstract'");
        let text = run_probe(&s, &config, &py, &script)?;
        assert_eq!(text, format!("ERR {}", libc::EACCES), "{text}");
        Ok(())
    }

    /// With its own network namespace the child reaches its own abstract
    /// socket, with `connect` and with `sendto`. The names of the host are
    /// not in that namespace.
    #[test]
    #[serial]
    fn an_abstract_address_works_in_a_private_network_namespace() -> TestResult {
        let Some(s) = setup()? else {
            return Ok(());
        };
        let Some((mut config, py)) = python_sandbox(&s, Vec::new()) else {
            return Ok(());
        };
        config.network = crate::NetworkMode::LocalhostOnly;
        let script = "import socket, sys, threading\n\
             out = open(sys.argv[1], 'w')\n\
             name = '\\0pent-own-abstract'\n\
             srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
             srv.bind(name); srv.listen(1)\n\
             def serve():\n\
             \x20   c, _ = srv.accept(); c.sendall(b'OWN'); c.close()\n\
             threading.Thread(target=serve, daemon=True).start()\n\
             c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
             c.settimeout(5)\n\
             try:\n\
             \x20   c.connect(name)\n\
             \x20   out.write('CONNECT ' + repr(c.recv(8)) + ' ')\n\
             except OSError as e:\n\
             \x20   out.write('CONNECT ERR %d ' % (e.errno or 0))\n\
             d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
             d.bind('\\0pent-own-dgram-peer')\n\
             peer = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
             peer.settimeout(5)\n\
             try:\n\
             \x20   peer.sendto(b'PING', '\\0pent-own-dgram-peer')\n\
             \x20   out.write('SENDTO ' + repr(d.recv(8)))\n\
             except OSError as e:\n\
             \x20   out.write('SENDTO ERR %d' % (e.errno or 0))\n\
             out.close()\n";
        let text = run_probe(&s, &config, &py, script)?;
        assert_eq!(text, "CONNECT b'OWN' SENDTO b'PING'", "{text}");
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
                    &WatchOptions {
                        guard: Vec::new(),
                        unix_sockets: Vec::new(),
                    },
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
