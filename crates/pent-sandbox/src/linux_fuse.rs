//! The FUSE server of pent (design, section 5.5).
//!
//! The server gives a real directory of the host through a FUSE mount. The
//! child mounts `/dev/fuse` in the user namespace of the session
//! ([`mount_fuse`]) and sends the descriptor to the parent. The parent
//! serves it ([`serve`]) with the `fuser` crate.
//!
//! - **A node is an inode.** Each FUSE node holds an `O_PATH` descriptor of
//!   the real inode, and each operation uses the `*at` system calls on that
//!   descriptor. A rename on the host thus does not change the node. The
//!   real `(st_dev, st_ino)` pair names the node, so two names of one inode
//!   give one node.
//! - **One name, one component.** The kernel sends one component in each
//!   request. The server refuses a name with `/`, a NUL byte, `.` or `..`,
//!   and it opens each component with `O_NOFOLLOW`, so a request never
//!   leaves the tree through a symbolic link.
//! - **One thread for each request.** A slow request, for example one that
//!   waits for a question in a later step, blocks no other request. The
//!   answer to `INIT` has `FUSE_PARALLEL_DIROPS`, so the kernel also sends
//!   parallel requests in one directory.
//! - **The first `GETATTR` of the root.** The kernel makes the root inode
//!   with UID 0 and GID 0; the `user_id` option is only for the access
//!   check. In a user namespace that maps only the real user, UID 0 has no
//!   map, so the kernel refuses each write in the root until it reads the
//!   attributes of the root. The process that mounts thus does one `stat`
//!   of the mount root after the server runs.
//! - **The policy of an area** (step 5.3). In a sandbox, Landlock gives
//!   all rights on each FUSE root, and the server checks each access
//!   instead: it computes the Landlock rights that the grants give at the
//!   path ([`AreaPolicy`]), and it checks the right that Landlock would
//!   check for the operation. A new or a removed entry is checked at the
//!   path of the entry, where Landlock checks its directory: the rights at
//!   a path hold the rights of each parent, so the two differ only for a
//!   rule on the entry itself, and such a rule (`write ~/made/**`) means
//!   that the program may make the entry. An access with no right gets
//!   `EACCES`. A
//!   lookup, `getattr`, `readlink`, `access` and `statfs` need no right, as
//!   with Landlock. Each node keeps its parent and its name, so the server
//!   knows the path of the node, also after a rename.
//! - **The inode number** that `stat` gives is the number of the node,
//!   because `fuser` uses the same number for both. A listing gives the
//!   number of the node when the node exists, else the real inode number.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirEntryExt, FileExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, InitFlags, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    Session, SessionACL, TimeOrNow, WriteFlags,
};
use thiserror::Error;

/// The validity time of an entry and of its attributes in the kernel.
const TTL: Duration = Duration::from_secs(1);

/// The generation of each node. A node number is never used two times in
/// one session, so the generation stays 0.
const GENERATION: Generation = Generation(0);

/// The open flags that the server removes before it opens the real file:
/// the kernel did the create, and the node is not a symbolic link.
const REOPEN_STRIP: libc::c_int = libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY | libc::O_NOFOLLOW;

/// An error of the FUSE server.
#[derive(Debug, Error)]
pub(crate) enum FuseError {
    /// The root directory of the tree cannot be read.
    #[error("cannot read the root of the FUSE tree: {0}")]
    Root(#[source] std::io::Error),
    /// The `INIT` exchange with the kernel failed.
    #[error("the FUSE handshake failed: {0}")]
    Handshake(#[source] std::io::Error),
    /// The thread of the session did not start.
    #[error("cannot start the FUSE session thread: {0}")]
    Thread(#[source] std::io::Error),
    /// The session stopped with an error.
    #[cfg(test)]
    #[error("the FUSE session failed: {0}")]
    Session(#[source] std::io::Error),
    /// The session thread panicked.
    #[cfg(test)]
    #[error("the FUSE session thread panicked")]
    Panicked,
}

/// Open `/dev/fuse` and mount it on `target`, with `uid` and `gid` as the
/// owner of the mount. Returns the descriptor of `/dev/fuse` (with
/// `O_CLOEXEC`), which the caller sends to the server.
///
/// After the server runs, the caller must `stat` the mount root one time
/// (see the module documentation).
///
/// The caller must be in a user namespace and a mount namespace that it
/// owns: the kernel refuses a descriptor that another user namespace
/// opened. Async-signal-safe.
///
/// # Safety
/// `target` must name a directory. The function calls only `open`, `mount`
/// and `close`.
///
/// # Errors
/// Returns the OS error of `open(2)` or `mount(2)`.
pub(crate) unsafe fn mount_fuse(target: &CStr, uid: u32, gid: u32) -> std::io::Result<RawFd> {
    // SAFETY: a static NUL-terminated path.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::open(c"/dev/fuse".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut opts = OptionBuf::new();
    opts.push(b"fd=");
    opts.push_num(u32::try_from(fd).unwrap_or_default(), 10);
    opts.push(b",rootmode=40000,user_id=");
    opts.push_num(uid, 10);
    opts.push(b",group_id=");
    opts.push_num(gid, 10);
    // SAFETY: each pointer is a NUL-terminated string that lives until the
    // call returns: `OptionBuf` keeps a NUL byte after its text.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::mount(
            c"pent".as_ptr(),
            target.as_ptr(),
            c"fuse".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            opts.as_ptr().cast(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `fd` is a descriptor that this function opened.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

/// The text of the mount options, made with no allocation. The buffer
/// always ends with a NUL byte; text that does not fit is cut.
struct OptionBuf {
    buf: [u8; 96],
    len: usize,
}

impl OptionBuf {
    fn new() -> Self {
        Self {
            buf: [0; 96],
            len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        for b in bytes {
            // Keep the last byte for the NUL.
            if self.len.saturating_add(1) >= self.buf.len() {
                return;
            }
            if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = *b;
                self.len = self.len.saturating_add(1);
            }
        }
    }

    /// Push `n` in the base `radix` (2 to 10).
    fn push_num(&mut self, mut n: u32, radix: u32) {
        let radix = radix.clamp(2, 10);
        // `u32::MAX` has 32 digits in base 2.
        let mut digits = [0u8; 32];
        let mut i = digits.len();
        loop {
            i = i.saturating_sub(1);
            if let Some(d) = digits.get_mut(i) {
                // `n % radix` is less than 10, so the cast is exact.
                #[allow(clippy::cast_possible_truncation)]
                let digit = (n % radix) as u8;
                *d = b'0'.saturating_add(digit);
            }
            n /= radix;
            if n == 0 || i == 0 {
                break;
            }
        }
        let tail = digits.get(i..).unwrap_or_default();
        self.push(tail);
    }

    fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    #[cfg(test)]
    fn text(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

/// A running FUSE server.
///
/// The session ends by itself when the mount namespace goes, so pent does
/// not wait for it. Only the tests wait.
pub(crate) struct FuseServer {
    #[cfg_attr(not(test), allow(dead_code))] // Only the tests wait.
    thread: JoinHandle<std::io::Result<()>>,
}

impl FuseServer {
    /// Wait until the session ends. The session ends when the kernel closes
    /// the connection: the mount goes away with the last process of its
    /// mount namespace.
    ///
    /// # Errors
    /// Returns [`FuseError::Session`] if the session failed, or
    /// [`FuseError::Panicked`] if its thread panicked.
    #[cfg(test)]
    pub(crate) fn wait(self) -> Result<(), FuseError> {
        match self.thread.join() {
            Ok(result) => result.map_err(FuseError::Session),
            Err(_) => Err(FuseError::Panicked),
        }
    }
}

/// Serve the real directory `root` on the FUSE connection `dev`.
///
/// `dev` is the descriptor that [`mount_fuse`] returned, and `root` is a
/// descriptor of the real directory (`O_PATH` is enough). With a `policy`,
/// the server refuses each access that the policy does not give; without
/// one it serves each access. The function does the `INIT` exchange, and
/// then it serves the requests in a new thread.
///
/// # Errors
/// Returns [`FuseError::Root`] if `root` is not readable,
/// [`FuseError::Handshake`] if the `INIT` exchange fails, or
/// [`FuseError::Thread`] if the session thread does not start.
pub(crate) fn serve(
    dev: OwnedFd,
    root: OwnedFd,
    policy: Option<AreaPolicy>,
) -> Result<FuseServer, FuseError> {
    serve_tree(dev, FuseTree::new(root, policy).map_err(FuseError::Root)?)
}

/// The policy of one area: the Landlock rights that the grants of the
/// sandbox give at each path.
pub(crate) struct AreaPolicy {
    /// The path of the area: the root of the tree has this path.
    pub(crate) area: PathBuf,
    /// The grants, with the same rules as the Landlock ruleset, without
    /// the rule on the FUSE root.
    pub(crate) grants: Arc<crate::linux::AccessPolicy>,
    /// The private directories above the area. Their rules (all rights on
    /// an empty tmpfs) do not reach into an area that pent binds back
    /// below them.
    pub(crate) private_above: Vec<PathBuf>,
}

/// The flag of an open for `execve(2)` (`__FMODE_EXEC`): the kernel puts it
/// in the flags of the `OPEN` request.
const OPEN_FOR_EXEC: libc::c_int = 0x20;

/// The Landlock rights that an open with `flags` needs.
fn open_rights(flags: libc::c_int) -> u64 {
    use crate::linux_landlock::access;
    if flags & OPEN_FOR_EXEC != 0 {
        return access::EXECUTE;
    }
    let mut rights = match flags & libc::O_ACCMODE {
        libc::O_WRONLY => access::WRITE_FILE,
        libc::O_RDWR => access::READ_FILE | access::WRITE_FILE,
        _ => access::READ_FILE,
    };
    if flags & libc::O_TRUNC != 0 {
        rights |= access::TRUNCATE;
    }
    rights
}

/// The Landlock rights that a new entry and a removed entry of the type of
/// `mode` need on their directory.
fn entry_rights(mode: u32) -> (u64, u64) {
    use crate::linux_landlock::access;
    match mode & libc::S_IFMT {
        libc::S_IFDIR => (access::MAKE_DIR, access::REMOVE_DIR),
        libc::S_IFLNK => (access::MAKE_SYM, access::REMOVE_FILE),
        libc::S_IFIFO => (access::MAKE_FIFO, access::REMOVE_FILE),
        libc::S_IFSOCK => (access::MAKE_SOCK, access::REMOVE_FILE),
        libc::S_IFCHR => (access::MAKE_CHAR, access::REMOVE_FILE),
        libc::S_IFBLK => (access::MAKE_BLOCK, access::REMOVE_FILE),
        _ => (access::MAKE_REG, access::REMOVE_FILE),
    }
}

fn serve_tree(dev: OwnedFd, tree: FuseTree) -> Result<FuseServer, FuseError> {
    let session = Session::from_fd(tree, dev, SessionACL::Owner, Config::default())
        .map_err(FuseError::Handshake)?;
    let thread = std::thread::Builder::new()
        .name("pent-fuse".to_string())
        .spawn(move || session.run())
        .map_err(FuseError::Thread)?;
    Ok(FuseServer { thread })
}

/// One node: an `O_PATH` descriptor of a real inode.
struct Node {
    fd: Arc<OwnedFd>,
    key: InodeKey,
    /// The lookup count of the kernel. The node goes when it is 0.
    lookups: u64,
    /// The directory and the name of the last lookup, a create or a
    /// rename. The root has none.
    parent: u64,
    name: OsString,
}

/// The longest chain of parents that [`Tree::path`] follows.
const MAX_DEPTH: usize = 4096;

/// The real identity of an inode: `(st_dev, st_ino)`.
type InodeKey = (u64, u64);

/// The table of nodes.
struct Inodes {
    nodes: HashMap<u64, Node>,
    by_key: HashMap<InodeKey, u64>,
    next: u64,
}

/// One entry of a directory listing.
struct DirItem {
    name: OsString,
    ino: u64,
    kind: FileType,
}

/// The state of the server. Each request thread holds an `Arc` of it.
struct Tree {
    inodes: Mutex<Inodes>,
    files: Mutex<HashMap<u64, Arc<File>>>,
    dirs: Mutex<HashMap<u64, Arc<Vec<DirItem>>>>,
    next_fh: AtomicU64,
    /// The policy of the area, or `None` to serve each access.
    policy: Option<AreaPolicy>,
    /// A test hook: a lookup of this name waits this long.
    #[cfg(test)]
    slow_lookup: Option<(OsString, Duration)>,
}

/// The `fuser` filesystem: it sends each request to its own thread.
struct FuseTree {
    tree: Arc<Tree>,
}

/// Lock a mutex. A panic in another thread does not make the table
/// invalid, because each change of a table is one insert or one remove.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The error number of the last system call.
fn last_errno() -> Errno {
    Errno::from(std::io::Error::last_os_error())
}

/// Check one name of a request and make a C string of it.
fn component(name: &OsStr) -> Result<CString, Errno> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(Errno::EINVAL);
    }
    CString::new(bytes).map_err(|_| Errno::EINVAL)
}

/// The path `/proc/self/fd/N` of a descriptor. It opens the inode of the
/// descriptor, also for an `O_PATH` descriptor.
fn proc_path(fd: BorrowedFd<'_>) -> CString {
    let text = format!("/proc/self/fd/{}", fd.as_raw_fd());
    // The text has no NUL byte.
    CString::new(text).unwrap_or_default()
}

/// Wrap a new descriptor, or return the error of the call.
fn owned(fd: libc::c_int) -> Result<OwnedFd, Errno> {
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open `name` in the directory `dir` with `O_PATH | O_NOFOLLOW`.
fn open_path(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, Errno> {
    // SAFETY: `name` is NUL-terminated; `dir` is an open descriptor.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

/// The `stat` of the inode of `fd`, without a follow of a symbolic link.
fn stat_fd(fd: BorrowedFd<'_>) -> Result<libc::stat, Errno> {
    // SAFETY: all zero bytes is a valid `stat`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: the empty path is NUL-terminated, and `st` is writable.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::fstatat(
            fd.as_raw_fd(),
            c"".as_ptr(),
            &raw mut st,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        return Err(last_errno());
    }
    Ok(st)
}

/// Set the mode of the inode of `fd` to `mode`, through `/proc`.
fn chmod_fd(fd: BorrowedFd<'_>, mode: u32) -> Result<(), Errno> {
    let path = proc_path(fd);
    // SAFETY: `path` is NUL-terminated.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::chmod(path.as_ptr(), mode & 0o7777) };
    if ret != 0 {
        return Err(last_errno());
    }
    Ok(())
}

fn key_of(st: &libc::stat) -> InodeKey {
    (st.st_dev, st.st_ino)
}

fn kind_of(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        _ => FileType::RegularFile,
    }
}

fn time_of(sec: i64, nsec: i64) -> SystemTime {
    let nanos = u32::try_from(nsec).unwrap_or(0);
    match u64::try_from(sec) {
        Ok(s) => UNIX_EPOCH
            .checked_add(Duration::new(s, nanos))
            .unwrap_or(UNIX_EPOCH),
        Err(_) => UNIX_EPOCH
            .checked_sub(Duration::from_secs(sec.unsigned_abs()))
            .and_then(|t| t.checked_add(Duration::from_nanos(u64::from(nanos))))
            .unwrap_or(UNIX_EPOCH),
    }
}

fn attr_of(node: u64, st: &libc::stat) -> FileAttr {
    FileAttr {
        ino: INodeNo(node),
        size: u64::try_from(st.st_size).unwrap_or(0),
        blocks: u64::try_from(st.st_blocks).unwrap_or(0),
        atime: time_of(st.st_atime, st.st_atime_nsec),
        mtime: time_of(st.st_mtime, st.st_mtime_nsec),
        ctime: time_of(st.st_ctime, st.st_ctime_nsec),
        crtime: UNIX_EPOCH,
        kind: kind_of(st.st_mode),
        perm: u16::try_from(st.st_mode & 0o7777).unwrap_or(0),
        nlink: u32::try_from(st.st_nlink).unwrap_or(u32::MAX),
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: u32::try_from(st.st_rdev).unwrap_or(0),
        blksize: u32::try_from(st.st_blksize).unwrap_or(4096),
        flags: 0,
    }
}

/// A `timespec` for `utimensat(2)`.
fn timespec_of(t: Option<TimeOrNow>) -> libc::timespec {
    match t {
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        Some(TimeOrNow::Now) => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        Some(TimeOrNow::SpecificTime(t)) => {
            let (sec, nsec) = match t.duration_since(UNIX_EPOCH) {
                Ok(d) => (
                    i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                    d.subsec_nanos(),
                ),
                Err(e) => {
                    // A time before 1970: the seconds round down, and the
                    // nanoseconds count up from them.
                    let d = e.duration();
                    let whole = 0i64.saturating_sub(i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
                    match d.subsec_nanos() {
                        0 => (whole, 0),
                        n => (whole.saturating_sub(1), 1_000_000_000u32.saturating_sub(n)),
                    }
                }
            };
            libc::timespec {
                tv_sec: sec,
                tv_nsec: i64::from(nsec),
            }
        }
    }
}

impl Tree {
    fn new(root: OwnedFd, policy: Option<AreaPolicy>) -> std::io::Result<Self> {
        let st = stat_fd(root.as_fd()).map_err(|e| std::io::Error::from_raw_os_error(e.code()))?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let key = key_of(&st);
        let root_id = u64::from(INodeNo::ROOT);
        let mut nodes = HashMap::new();
        nodes.insert(
            root_id,
            Node {
                fd: Arc::new(root),
                key,
                lookups: 1,
                parent: 0,
                name: OsString::new(),
            },
        );
        let mut by_key = HashMap::new();
        by_key.insert(key, root_id);
        Ok(Self {
            inodes: Mutex::new(Inodes {
                nodes,
                by_key,
                next: root_id.saturating_add(1),
            }),
            files: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            policy,
            #[cfg(test)]
            slow_lookup: None,
        })
    }

    /// The descriptor of the node `ino`.
    fn fd(&self, ino: INodeNo) -> Result<Arc<OwnedFd>, Errno> {
        lock(&self.inodes)
            .nodes
            .get(&u64::from(ino))
            .map(|n| Arc::clone(&n.fd))
            .ok_or(Errno::ESTALE)
    }

    /// Add one lookup of the inode of `fd`, the entry `name` of `parent`,
    /// and return its node number. A known inode keeps its node, takes the
    /// new name, and `fd` closes.
    fn remember(
        &self,
        fd: OwnedFd,
        st: &libc::stat,
        parent: INodeNo,
        name: &OsStr,
    ) -> Result<u64, Errno> {
        let key = key_of(st);
        let mut inodes = lock(&self.inodes);
        if let Some(id) = inodes.by_key.get(&key).copied() {
            if let Some(node) = inodes.nodes.get_mut(&id) {
                node.lookups = node.lookups.saturating_add(1);
                if id != u64::from(INodeNo::ROOT) {
                    node.parent = u64::from(parent);
                    node.name = name.to_owned();
                }
                return Ok(id);
            }
        }
        let id = inodes.next;
        inodes.next = id.checked_add(1).ok_or(Errno::ENOSPC)?;
        inodes.nodes.insert(
            id,
            Node {
                fd: Arc::new(fd),
                key,
                lookups: 1,
                parent: u64::from(parent),
                name: name.to_owned(),
            },
        );
        inodes.by_key.insert(key, id);
        Ok(id)
    }

    /// The path of the node `ino` on the host, from its chain of parents.
    fn path(&self, ino: INodeNo) -> Result<PathBuf, Errno> {
        let Some(policy) = &self.policy else {
            return Ok(PathBuf::new());
        };
        let inodes = lock(&self.inodes);
        let mut names: Vec<&OsStr> = Vec::new();
        let mut id = u64::from(ino);
        while id != u64::from(INodeNo::ROOT) {
            let node = inodes.nodes.get(&id).ok_or(Errno::ESTALE)?;
            if names.len() >= MAX_DEPTH {
                return Err(Errno::ELOOP);
            }
            names.push(&node.name);
            id = node.parent;
        }
        let mut path = policy.area.clone();
        path.extend(names.iter().rev());
        Ok(path)
    }

    /// Refuse with `EACCES` unless the policy gives `needed` at the node
    /// `ino`, or at its entry `child`. Without a policy each access passes.
    fn require(&self, ino: INodeNo, child: Option<&OsStr>, needed: u64) -> Result<(), Errno> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        let mut path = self.path(ino)?;
        if let Some(child) = child {
            path.push(child);
        }
        if policy.grants.rights_except(&path, &policy.private_above) & needed == needed {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }

    /// Give the node of the inode `key` the entry `newname` of `newparent`,
    /// after a rename.
    fn moved(&self, key: InodeKey, newparent: INodeNo, newname: &OsStr) {
        let mut inodes = lock(&self.inodes);
        if let Some(id) = inodes.by_key.get(&key).copied() {
            if let Some(node) = inodes.nodes.get_mut(&id) {
                node.parent = u64::from(newparent);
                node.name = newname.to_owned();
            }
        }
    }

    /// Remove `count` lookups of the node `ino`. The root never goes.
    fn forget(&self, ino: INodeNo, count: u64) {
        let id = u64::from(ino);
        if ino == INodeNo::ROOT {
            return;
        }
        let mut inodes = lock(&self.inodes);
        let gone = match inodes.nodes.get_mut(&id) {
            Some(node) => {
                node.lookups = node.lookups.saturating_sub(count);
                (node.lookups == 0).then_some(node.key)
            }
            None => None,
        };
        if let Some(key) = gone {
            inodes.nodes.remove(&id);
            if inodes.by_key.get(&key) == Some(&id) {
                inodes.by_key.remove(&key);
            }
        }
    }

    /// Open `name` in `parent`, remember the node, and give its attributes.
    fn lookup(&self, parent: INodeNo, name: &OsStr) -> Result<FileAttr, Errno> {
        #[cfg(test)]
        if let Some((slow, wait)) = &self.slow_lookup {
            if slow == name {
                std::thread::sleep(*wait);
            }
        }
        let cname = component(name)?;
        let dir = self.fd(parent)?;
        let fd = open_path(dir.as_fd(), &cname)?;
        self.entry(fd, parent, name)
    }

    /// Remember the node of `fd`, the entry `name` of `parent`, and give
    /// its attributes.
    fn entry(&self, fd: OwnedFd, parent: INodeNo, name: &OsStr) -> Result<FileAttr, Errno> {
        let st = stat_fd(fd.as_fd())?;
        let id = self.remember(fd, &st, parent, name)?;
        Ok(attr_of(id, &st))
    }

    fn getattr(&self, ino: INodeNo) -> Result<FileAttr, Errno> {
        let fd = self.fd(ino)?;
        let st = stat_fd(fd.as_fd())?;
        Ok(attr_of(u64::from(ino), &st))
    }

    fn file(&self, fh: FileHandle) -> Result<Arc<File>, Errno> {
        lock(&self.files)
            .get(&u64::from(fh))
            .cloned()
            .ok_or(Errno::EBADF)
    }

    fn new_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }

    fn add_file(&self, file: File) -> FileHandle {
        let fh = self.new_fh();
        lock(&self.files).insert(fh, Arc::new(file));
        FileHandle(fh)
    }

    #[allow(clippy::too_many_arguments)] // The arguments of the FUSE request.
    fn setattr(
        &self,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        fh: Option<FileHandle>,
    ) -> Result<FileAttr, Errno> {
        let fd = self.fd(ino)?;
        // Landlock controls only the truncation; the mode, the owner and
        // the times stay free, as with Landlock.
        if size.is_some() {
            self.require(ino, None, crate::linux_landlock::access::TRUNCATE)?;
        }
        if let Some(mode) = mode {
            chmod_fd(fd.as_fd(), mode)?;
        }
        if uid.is_some() || gid.is_some() {
            // `u32::MAX` is -1: no change.
            let (u, g) = (uid.unwrap_or(u32::MAX), gid.unwrap_or(u32::MAX));
            // SAFETY: the empty path is NUL-terminated.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe {
                libc::fchownat(
                    fd.as_raw_fd(),
                    c"".as_ptr(),
                    u,
                    g,
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if ret != 0 {
                return Err(last_errno());
            }
        }
        if let Some(size) = size {
            let open = fh.and_then(|fh| self.file(fh).ok());
            let file = match open {
                Some(file) => file,
                None => {
                    let path = proc_path(fd.as_fd());
                    // SAFETY: `path` is NUL-terminated.
                    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                    let new = owned(unsafe {
                        libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC)
                    })?;
                    Arc::new(File::from(new))
                }
            };
            file.set_len(size).map_err(Errno::from)?;
        }
        if atime.is_some() || mtime.is_some() {
            let times = [timespec_of(atime), timespec_of(mtime)];
            let path = proc_path(fd.as_fd());
            // SAFETY: `path` is NUL-terminated and `times` has two entries.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let ret = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) };
            if ret != 0 {
                return Err(last_errno());
            }
        }
        self.getattr(ino)
    }

    fn readlink(&self, ino: INodeNo) -> Result<Vec<u8>, Errno> {
        let fd = self.fd(ino)?;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        // SAFETY: the empty path is NUL-terminated, and `buf` has
        // `buf.len()` writable bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe {
            libc::readlinkat(
                fd.as_raw_fd(),
                c"".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        let n = usize::try_from(n).map_err(|_| last_errno())?;
        buf.truncate(n);
        Ok(buf)
    }

    fn mkdir(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<FileAttr, Errno> {
        self.require(parent, Some(name), crate::linux_landlock::access::MAKE_DIR)?;
        let cname = component(name)?;
        let dir = self.fd(parent)?;
        let mode = mode & !umask & 0o7777;
        // SAFETY: `cname` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::mkdirat(dir.as_raw_fd(), cname.as_ptr(), mode) } != 0 {
            return Err(last_errno());
        }
        let fd = open_path(dir.as_fd(), &cname)?;
        // The umask of pent also cut the mode; set the mode of the request.
        chmod_fd(fd.as_fd(), mode)?;
        self.entry(fd, parent, name)
    }

    fn symlink(&self, parent: INodeNo, name: &OsStr, target: &Path) -> Result<FileAttr, Errno> {
        self.require(parent, Some(name), crate::linux_landlock::access::MAKE_SYM)?;
        let cname = component(name)?;
        let ctarget = CString::new(target.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
        let dir = self.fd(parent)?;
        // SAFETY: both strings are NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::symlinkat(ctarget.as_ptr(), dir.as_raw_fd(), cname.as_ptr()) } != 0 {
            return Err(last_errno());
        }
        let fd = open_path(dir.as_fd(), &cname)?;
        self.entry(fd, parent, name)
    }

    /// Make a named pipe, a Unix socket or an empty regular file. A device
    /// node gets `EPERM`.
    fn mknod(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<FileAttr, Errno> {
        use crate::linux_landlock::access;
        let needed = match mode & libc::S_IFMT {
            libc::S_IFIFO => access::MAKE_FIFO,
            libc::S_IFSOCK => access::MAKE_SOCK,
            libc::S_IFREG | 0 => access::MAKE_REG,
            _ => return Err(Errno::EPERM),
        };
        self.require(parent, Some(name), needed)?;
        let cname = component(name)?;
        let dir = self.fd(parent)?;
        let perm = mode & !umask & 0o7777;
        // SAFETY: `cname` is NUL-terminated; the rest are integers.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::mknodat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                (mode & libc::S_IFMT) | perm,
                0,
            )
        };
        if ret != 0 {
            return Err(last_errno());
        }
        let fd = open_path(dir.as_fd(), &cname)?;
        // The umask of pent also cut the mode; set the mode of the request.
        chmod_fd(fd.as_fd(), perm)?;
        self.entry(fd, parent, name)
    }

    fn fallocate(&self, fh: FileHandle, offset: u64, length: u64, mode: i32) -> Result<(), Errno> {
        let file = self.file(fh)?;
        let offset = libc::off_t::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let length = libc::off_t::try_from(length).map_err(|_| Errno::EINVAL)?;
        // SAFETY: fallocate(2) on an open file with integer arguments.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::fallocate(file.as_raw_fd(), mode, offset, length) } != 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    fn lseek(&self, fh: FileHandle, offset: i64, whence: i32) -> Result<i64, Errno> {
        let file = self.file(fh)?;
        // SAFETY: lseek(2) on an open file with integer arguments. The
        // descriptor of the server has its own offset, so only `SEEK_DATA`
        // and `SEEK_HOLE` matter here.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let at = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
        if at < 0 {
            return Err(last_errno());
        }
        Ok(at)
    }

    fn unlink(&self, parent: INodeNo, name: &OsStr, flags: libc::c_int) -> Result<(), Errno> {
        let needed = if flags & libc::AT_REMOVEDIR != 0 {
            crate::linux_landlock::access::REMOVE_DIR
        } else {
            crate::linux_landlock::access::REMOVE_FILE
        };
        self.require(parent, Some(name), needed)?;
        let name = component(name)?;
        let dir = self.fd(parent)?;
        // SAFETY: `name` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    fn rename(
        &self,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
    ) -> Result<(), Errno> {
        let (cname, cnewname) = (component(name)?, component(newname)?);
        let (from, to) = (self.fd(parent)?, self.fd(newparent)?);
        let source = stat_fd(open_path(from.as_fd(), &cname)?.as_fd())?;
        let exchange = flags.contains(RenameFlags::RENAME_EXCHANGE);
        let target = if exchange {
            Some(stat_fd(open_path(to.as_fd(), &cnewname)?.as_fd())?)
        } else {
            None
        };
        if self.policy.is_some() {
            use crate::linux_landlock::access;
            let (make, remove) = entry_rights(source.st_mode);
            let (mut on_from, mut on_to) = (remove, make);
            if let Some(target) = &target {
                let (make_back, remove_back) = entry_rights(target.st_mode);
                on_from |= make_back;
                on_to |= remove_back;
            }
            // Landlock needs `REFER` for a move to another directory.
            if parent != newparent {
                on_from |= access::REFER;
                on_to |= access::REFER;
            }
            self.require(parent, Some(name), on_from)?;
            self.require(newparent, Some(newname), on_to)?;
        }
        // SAFETY: both names are NUL-terminated; the flags are integers.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                cname.as_ptr(),
                to.as_raw_fd(),
                cnewname.as_ptr(),
                flags.bits(),
            )
        };
        if ret != 0 {
            return Err(last_errno());
        }
        self.moved(key_of(&source), newparent, newname);
        if let Some(target) = &target {
            self.moved(key_of(target), parent, name);
        }
        Ok(())
    }

    fn open(&self, ino: INodeNo, flags: OpenFlags) -> Result<FileHandle, Errno> {
        self.require(ino, None, open_rights(flags.0))?;
        let fd = self.fd(ino)?;
        let path = proc_path(fd.as_fd());
        let flags = (flags.0 & !REOPEN_STRIP) | libc::O_CLOEXEC;
        // SAFETY: `path` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let file = owned(unsafe { libc::open(path.as_ptr(), flags) })?;
        Ok(self.add_file(File::from(file)))
    }

    fn create(
        &self,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<(FileAttr, FileHandle), Errno> {
        self.require(
            parent,
            Some(name),
            crate::linux_landlock::access::MAKE_REG | open_rights(flags),
        )?;
        let cname = component(name)?;
        let dir = self.fd(parent)?;
        let mode = mode & !umask & 0o7777;
        let base = (flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY))
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC;
        // SAFETY: `name` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let made = owned(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                base | libc::O_CREAT | libc::O_EXCL,
                mode,
            )
        });
        let (file, created) = match made {
            Ok(file) => (file, true),
            // A host process made the name after the lookup of the kernel.
            Err(e) if e == Errno::EEXIST && flags & libc::O_EXCL == 0 => {
                // SAFETY: `name` is NUL-terminated.
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                let file = owned(unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), base) })?;
                (file, false)
            }
            Err(e) => return Err(e),
        };
        if created {
            // The umask of pent also cut the mode; set the mode of the
            // request.
            chmod_fd(file.as_fd(), mode)?;
        }
        let node = open_path(dir.as_fd(), &cname)?;
        let attr = self.entry(node, parent, name)?;
        Ok((attr, self.add_file(File::from(file))))
    }

    fn read(&self, fh: FileHandle, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        let file = self.file(fh)?;
        let mut buf = vec![0u8; usize::try_from(size).unwrap_or(0)];
        let mut done = 0usize;
        while let Some(rest) = buf.get_mut(done..).filter(|r| !r.is_empty()) {
            let at = offset.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            match file.read_at(rest, at) {
                Ok(0) => break,
                Ok(n) => done = done.saturating_add(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Errno::from(e)),
            }
        }
        buf.truncate(done);
        Ok(buf)
    }

    fn write(&self, fh: FileHandle, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        let file = self.file(fh)?;
        file.write_all_at(data, offset).map_err(Errno::from)?;
        u32::try_from(data.len()).map_err(|_| Errno::EINVAL)
    }

    fn release(&self, fh: FileHandle) {
        lock(&self.files).remove(&u64::from(fh));
    }

    fn fsync(&self, fh: FileHandle, datasync: bool) -> Result<(), Errno> {
        let file = self.file(fh)?;
        let result = if datasync {
            file.sync_data()
        } else {
            file.sync_all()
        };
        result.map_err(Errno::from)
    }

    /// Read the whole directory at `opendir`, so that the offsets of
    /// `readdir` stay valid while the directory changes.
    fn opendir(&self, ino: INodeNo) -> Result<FileHandle, Errno> {
        self.require(ino, None, crate::linux_landlock::access::READ_DIR)?;
        let fd = self.fd(ino)?;
        let path = proc_path(fd.as_fd());
        let path = std::path::Path::new(OsStr::from_bytes(path.as_bytes()));
        let mut items = vec![
            DirItem {
                name: ".".into(),
                ino: u64::from(ino),
                kind: FileType::Directory,
            },
            DirItem {
                name: "..".into(),
                ino: u64::from(INodeNo::ROOT),
                kind: FileType::Directory,
            },
        ];
        let dev = stat_fd(fd.as_fd())?.st_dev;
        for entry in std::fs::read_dir(path).map_err(Errno::from)? {
            let entry = entry.map_err(Errno::from)?;
            let kind = entry
                .file_type()
                .ok()
                .and_then(FileType::from_std)
                .unwrap_or(FileType::RegularFile);
            let real = entry.ino();
            // A mount point below has another device; the real number is
            // then only a hint.
            let known = lock(&self.inodes).by_key.get(&(dev, real)).copied();
            items.push(DirItem {
                name: entry.file_name(),
                ino: known.unwrap_or(real),
                kind,
            });
        }
        let fh = self.new_fh();
        lock(&self.dirs).insert(fh, Arc::new(items));
        Ok(FileHandle(fh))
    }

    fn readdir(&self, fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        let Some(items) = lock(&self.dirs).get(&u64::from(fh)).cloned() else {
            reply.error(Errno::EBADF);
            return;
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (i, item) in items.iter().enumerate().skip(start) {
            let next = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
            if reply.add(INodeNo(item.ino), next, item.kind, &item.name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(&self, fh: FileHandle) {
        lock(&self.dirs).remove(&u64::from(fh));
    }

    fn statfs(&self, ino: INodeNo, reply: ReplyStatfs) {
        let fd = match self.fd(ino) {
            Ok(fd) => fd,
            Err(e) => return reply.error(e),
        };
        // SAFETY: all zero bytes is a valid `statvfs`.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut st = unsafe { std::mem::zeroed::<libc::statvfs>() };
        // SAFETY: `st` is writable; `fstatvfs` accepts an `O_PATH`
        // descriptor.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::fstatvfs(fd.as_raw_fd(), &raw mut st) } != 0 {
            return reply.error(last_errno());
        }
        let small = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        reply.statfs(
            st.f_blocks,
            st.f_bfree,
            st.f_bavail,
            st.f_files,
            st.f_ffree,
            small(st.f_bsize),
            small(st.f_namemax),
            small(st.f_frsize),
        );
    }

    fn access(&self, ino: INodeNo, mask: AccessFlags) -> Result<(), Errno> {
        let fd = self.fd(ino)?;
        // SAFETY: the empty path is NUL-terminated; the rest are integers.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                fd.as_raw_fd(),
                c"".as_ptr(),
                mask.bits(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if ret != 0 {
            return Err(last_errno());
        }
        Ok(())
    }
}

impl FuseTree {
    fn new(root: OwnedFd, policy: Option<AreaPolicy>) -> std::io::Result<Self> {
        Ok(Self {
            tree: Arc::new(Tree::new(root, policy)?),
        })
    }

    /// Run `job` in a new thread. If the thread does not start, run it
    /// here, so that the request still gets its answer.
    fn spawn<F>(&self, job: F)
    where
        F: FnOnce(&Tree) + Send + 'static,
    {
        let slot = Arc::new(Mutex::new(Some(job)));
        let theirs = Arc::clone(&slot);
        let tree = Arc::clone(&self.tree);
        let started = std::thread::Builder::new()
            .name("pent-fuse-req".to_string())
            .spawn(move || {
                if let Some(job) = lock(&theirs).take() {
                    job(&tree);
                }
            });
        if started.is_err() {
            if let Some(job) = lock(&slot).take() {
                job(&self.tree);
            }
        }
    }
}

/// Send `result` as an entry reply.
fn reply_entry(reply: ReplyEntry, result: Result<FileAttr, Errno>) {
    match result {
        Ok(attr) => reply.entry(&TTL, &attr, GENERATION),
        Err(e) => reply.error(e),
    }
}

fn reply_empty(reply: ReplyEmpty, result: Result<(), Errno>) {
    match result {
        Ok(()) => reply.ok(),
        Err(e) => reply.error(e),
    }
}

fn reply_attr(reply: ReplyAttr, result: Result<FileAttr, Errno>) {
    match result {
        Ok(attr) => reply.attr(&TTL, &attr),
        Err(e) => reply.error(e),
    }
}

fn reply_open(reply: ReplyOpen, result: Result<FileHandle, Errno>) {
    match result {
        Ok(fh) => reply.opened(fh, FopenFlags::empty()),
        Err(e) => reply.error(e),
    }
}

impl Filesystem for FuseTree {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        config
            .add_capabilities(InitFlags::FUSE_PARALLEL_DIROPS)
            .map_err(|_| std::io::Error::other("the kernel has no FUSE_PARALLEL_DIROPS"))
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_owned();
        self.spawn(move |t| reply_entry(reply, t.lookup(parent, &name)));
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.tree.forget(ino, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.spawn(move |t| reply_attr(reply, t.getattr(ino)));
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        self.spawn(move |t| {
            reply_attr(
                reply,
                t.setattr(ino, mode, uid, gid, size, atime, mtime, fh),
            );
        });
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        self.spawn(move |t| match t.readlink(ino) {
            Ok(target) => reply.data(&target),
            Err(e) => reply.error(e),
        });
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let name = name.to_owned();
        self.spawn(move |t| reply_entry(reply, t.mkdir(parent, &name, mode, umask)));
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let (name, target) = (link_name.to_owned(), target.to_owned());
        self.spawn(move |t| reply_entry(reply, t.symlink(parent, &name, &target)));
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let name = name.to_owned();
        self.spawn(move |t| reply_entry(reply, t.mknod(parent, &name, mode, umask)));
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        // The tree shows no extended attribute.
        reply.error(Errno::ENODATA);
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: fuser::ReplyXattr) {
        // The list is empty.
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOTSUP);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::ENOTSUP);
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        self.spawn(move |t| reply_empty(reply, t.fallocate(fh, offset, length, mode)));
    }

    fn lseek(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: fuser::ReplyLseek,
    ) {
        self.spawn(move |t| match t.lseek(fh, offset, whence) {
            Ok(at) => reply.offset(at),
            Err(e) => reply.error(e),
        });
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name = name.to_owned();
        self.spawn(move |t| reply_empty(reply, t.unlink(parent, &name, 0)));
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name = name.to_owned();
        self.spawn(move |t| reply_empty(reply, t.unlink(parent, &name, libc::AT_REMOVEDIR)));
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _owner: Option<fuser::Owner>,
        reply: ReplyEmpty,
    ) {
        let (name, newname) = (name.to_owned(), newname.to_owned());
        self.spawn(move |t| {
            reply_empty(reply, t.rename(parent, &name, newparent, &newname, flags));
        });
    }

    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        self.spawn(move |t| reply_open(reply, t.open(ino, flags)));
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.spawn(move |t| match t.read(fh, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        });
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let data = data.to_vec();
        self.spawn(move |t| match t.write(fh, offset, &data) {
            Ok(n) => reply.written(n),
            Err(e) => reply.error(e),
        });
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Each write goes to the real file at once: nothing waits.
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.spawn(move |t| {
            t.release(fh);
            reply.ok();
        });
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.spawn(move |t| reply_empty(reply, t.fsync(fh, datasync)));
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        self.spawn(move |t| reply_open(reply, t.opendir(ino)));
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        self.spawn(move |t| t.readdir(fh, offset, reply));
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.spawn(move |t| {
            t.releasedir(fh);
            reply.ok();
        });
    }

    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        self.spawn(move |t| t.statfs(ino, reply));
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        self.spawn(move |t| reply_empty(reply, t.access(ino, mask)));
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        _owner: fuser::Owner,
        reply: ReplyCreate,
    ) {
        let name = name.to_owned();
        self.spawn(move |t| match t.create(parent, &name, mode, umask, flags) {
            Ok((attr, fh)) => reply.created(&TTL, &attr, GENERATION, fh, FopenFlags::empty()),
            Err(e) => reply.error(e),
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::sync::OnceLock;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The steps of a child before it can mount: a user namespace and a
    /// mount namespace, and identity maps. Async-signal-safe.
    fn enter_namespaces(uid_map: &[u8], gid_map: &[u8]) -> std::io::Result<()> {
        // SAFETY: unshare(2) with integer flags.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        crate::linux::write_proc_file(c"/proc/self/setgroups", b"deny")?;
        crate::linux::write_proc_file(c"/proc/self/gid_map", gid_map)?;
        crate::linux::write_proc_file(c"/proc/self/uid_map", uid_map)
    }

    fn ids() -> (u32, u32, Vec<u8>, Vec<u8>) {
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let uid_map = format!("{uid} {uid} 1\n").into_bytes();
        let gid_map = format!("{gid} {gid} 1\n").into_bytes();
        (uid, gid, uid_map, gid_map)
    }

    /// Return true if this host lets an unprivileged process mount FUSE in
    /// a user namespace.
    pub(crate) fn fuse_available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            let Ok(dir) = tempfile::tempdir() else {
                return false;
            };
            let Ok(target) = CString::new(dir.path().as_os_str().as_bytes()) else {
                return false;
            };
            let (uid, gid, uid_map, gid_map) = ids();
            // SAFETY: the child uses only raw system calls and `_exit`.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return false;
            }
            if pid == 0 {
                let ok = enter_namespaces(&uid_map, &gid_map).is_ok()
                    // SAFETY: `target` names a directory.
                    && unsafe { mount_fuse(&target, uid, gid) }.is_ok();
                // SAFETY: end the child at once.
                unsafe { libc::_exit(if ok { 0 } else { 1 }) };
            }
            let mut status = 0;
            // SAFETY: wait for the child that this function forked.
            let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            ret == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        })
    }

    /// A real tree and an empty mount point.
    struct Trees {
        _tmp: tempfile::TempDir,
        real: PathBuf,
        mnt: PathBuf,
        /// A lookup of this name waits this long (see `Tree::slow_lookup`).
        slow_lookup: Option<(OsString, Duration)>,
    }

    fn trees() -> Result<Option<Trees>, Box<dyn std::error::Error>> {
        if !fuse_available() {
            let reason = "no unprivileged FUSE mount in a user namespace";
            // The pipelines set the variable: there a skip is a defect.
            assert!(
                std::env::var_os("PENT_REQUIRE_ALL_TESTS").is_none(),
                "the test does not run, and PENT_REQUIRE_ALL_TESTS is set: {reason}"
            );
            eprintln!("skip: {reason}");
            return Ok(None);
        }
        let tmp = tempfile::tempdir()?;
        let base = std::fs::canonicalize(tmp.path())?;
        let (real, mnt) = (base.join("real"), base.join("mnt"));
        std::fs::create_dir(&real)?;
        std::fs::create_dir(&mnt)?;
        Ok(Some(Trees {
            _tmp: tmp,
            real,
            mnt,
            slow_lookup: None,
        }))
    }

    /// Run `script` with `sh` in a child that mounts the FUSE tree of
    /// `t.real` on `t.mnt`. The script finds the mount in `$M`. The
    /// function also checks that the session ends cleanly.
    fn run_sh(t: &Trees, script: &str) -> Result<Output, Box<dyn std::error::Error>> {
        run_sh_with(t, script, || Ok(()))
    }

    /// [`run_sh`], and `host` runs on the host while the script runs.
    fn run_sh_with(
        t: &Trees,
        script: &str,
        host: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        // The first `GETATTR` of the root, as the module documentation says.
        let script = format!("stat \"$M\" > /dev/null || exit 99\n{script}");
        run_raw(t, &script, host)
    }

    /// [`run_sh_with`] without the first `stat` of the root.
    fn run_raw(
        t: &Trees,
        script: &str,
        host: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let (uid, gid, uid_map, gid_map) = ids();
        let root = OwnedFd::from(File::open(&t.real)?);
        let target = CString::new(t.mnt.as_os_str().as_bytes())?;
        let (ours, theirs) = crate::linux_fdpass::seqpacket_pair()?;
        let sock = theirs.as_raw_fd();
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .env("M", &t.mnt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the hook uses only async-signal-safe system calls; the
        // maps and the path were made before the fork.
        unsafe {
            cmd.pre_exec(move || {
                enter_namespaces(&uid_map, &gid_map)?;
                let fd = mount_fuse(&target, uid, gid)?;
                crate::linux_fdpass::send_fds(sock, &[fd])?;
                libc::close(fd);
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        drop(theirs);
        let Some(mut fds) = crate::linux_fdpass::recv_fds(&ours)? else {
            return Err(format!(
                "the child sent no descriptor: {:?}",
                child.wait_with_output()?
            )
            .into());
        };
        let dev = fds.pop().ok_or("no descriptor")?;
        let server = match &t.slow_lookup {
            None => serve(dev, root, None)?,
            Some(slow) => {
                let mut tree = Tree::new(root, None)?;
                tree.slow_lookup = Some(slow.clone());
                let tree = Arc::new(tree);
                serve_tree(dev, FuseTree { tree })?
            }
        };
        let hosted = host();
        // A script that hangs (for example a listing that never ends) must
        // fail the test, not hang it.
        let pid = libc::pid_t::try_from(child.id())?;
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // The receiver can be gone after a timeout.
            let _ = out_tx.send(child.wait_with_output());
        });
        let out = match out_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(out) => out?,
            Err(_) => {
                // SAFETY: kill(2) on our own child, which has not been
                // reaped: the wait thread still waits for it.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                return Err("the script did not end in 30 s".into());
            }
        };
        hosted?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // The receiver can be gone after a timeout.
            let _ = tx.send(server.wait().map_err(|e| e.to_string()));
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("the session failed: {e}").into()),
            Err(_) => return Err("the session did not end".into()),
        }
        if !out.status.success() {
            return Err(format!(
                "sh failed: {}\nstdout: {}\nstderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(out)
    }

    fn stdout(out: &Output) -> String {
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn mode(path: &Path) -> Result<u32, std::io::Error> {
        Ok(std::fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
    }

    #[test]
    fn option_text_has_the_numbers() {
        let mut opts = OptionBuf::new();
        opts.push(b"fd=");
        opts.push_num(7, 10);
        opts.push(b",rootmode=");
        opts.push_num(0o40000, 8);
        opts.push(b",user_id=");
        opts.push_num(0, 10);
        opts.push(b",group_id=");
        opts.push_num(u32::MAX, 10);
        assert_eq!(
            opts.text(),
            b"fd=7,rootmode=40000,user_id=0,group_id=4294967295"
        );
        assert_eq!(opts.buf.get(opts.len), Some(&0));
    }

    #[test]
    fn option_text_is_cut_and_keeps_the_nul() {
        let mut opts = OptionBuf::new();
        for _ in 0..20 {
            opts.push(b"abcdefgh");
        }
        assert_eq!(opts.len, opts.buf.len() - 1);
        assert_eq!(opts.buf.last(), Some(&0));
    }

    #[test]
    fn component_refuses_names_that_leave_the_directory() {
        for bad in ["", ".", "..", "a/b", "/", "a\0b"] {
            assert_eq!(component(OsStr::new(bad)), Err(Errno::EINVAL), "{bad:?}");
        }
        assert!(component(OsStr::new("...")).is_ok());
        assert!(component(OsStr::new(".hidden")).is_ok());
    }

    #[test]
    fn negative_times_survive() {
        let t = time_of(-2, 500);
        let ts = timespec_of(Some(TimeOrNow::SpecificTime(t)));
        assert_eq!((ts.tv_sec, ts.tv_nsec), (-2, 500));
        let ts = timespec_of(Some(TimeOrNow::SpecificTime(time_of(-3, 0))));
        assert_eq!((ts.tv_sec, ts.tv_nsec), (-3, 0));
        let t = time_of(1_000_000_000, 7);
        let ts = timespec_of(Some(TimeOrNow::SpecificTime(t)));
        assert_eq!((ts.tv_sec, ts.tv_nsec), (1_000_000_000, 7));
        assert_eq!(timespec_of(None).tv_nsec, libc::UTIME_OMIT);
    }

    #[test]
    fn lookup_getattr_and_read() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("a.txt"), "hello\n")?;
        let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(t.real.join("big"), &big)?;
        std::fs::create_dir(t.real.join("d"))?;
        let out = run_sh(
            &t,
            r#"set -e
            stat -c '%s %F' "$M/a.txt"
            stat -c '%F' "$M/d"
            cat "$M/a.txt"
            test -e "$M/none" || echo missing
            cmp "$M/big" "$T/big" && echo same"#
                .replace("$T", &t.real.to_string_lossy())
                .as_str(),
        )?;
        assert_eq!(
            stdout(&out),
            "6 regular file\ndirectory\nhello\nmissing\nsame\n"
        );
        Ok(())
    }

    #[test]
    fn a_write_in_the_root_waits_for_its_first_getattr() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        let out = run_raw(
            &t,
            r#"printf a > "$M/early" 2>/dev/null || echo refused
            stat "$M" > /dev/null
            printf b > "$M/late" && echo written"#,
            || Ok(()),
        )?;
        assert_eq!(stdout(&out), "refused\nwritten\n");
        assert!(!t.real.join("early").exists());
        assert_eq!(std::fs::read_to_string(t.real.join("late"))?, "b");
        Ok(())
    }

    #[test]
    fn create_write_and_modes() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        run_sh(
            &t,
            r#"set -e
            umask 002
            printf new > "$M/new.txt"
            printf more >> "$M/new.txt"
            mkdir "$M/sub"
            umask 077
            printf s > "$M/secret""#,
        )?;
        assert_eq!(std::fs::read_to_string(t.real.join("new.txt"))?, "newmore");
        // The umask of the program decides the mode, not the umask of pent.
        assert_eq!(mode(&t.real.join("new.txt"))?, 0o664);
        assert_eq!(mode(&t.real.join("sub"))?, 0o775);
        assert_eq!(mode(&t.real.join("secret"))?, 0o600);
        Ok(())
    }

    #[test]
    fn rename_unlink_mkdir_and_rmdir() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("a"), "a")?;
        std::fs::write(t.real.join("gone"), "x")?;
        std::fs::write(t.real.join("target"), "old")?;
        std::fs::create_dir(t.real.join("full"))?;
        std::fs::write(t.real.join("full/f"), "f")?;
        let out = run_sh(
            &t,
            r#"set -e
            mkdir "$M/d" "$M/empty"
            mv "$M/a" "$M/b"
            mv "$M/b" "$M/d/c"
            rm "$M/gone"
            rmdir "$M/empty"
            rmdir "$M/full" 2>/dev/null || echo notempty
            printf new > "$M/target.tmp.1"
            mv "$M/target.tmp.1" "$M/target"
            cat "$M/target""#,
        )?;
        assert_eq!(stdout(&out), "notempty\nnew");
        assert_eq!(std::fs::read_to_string(t.real.join("d/c"))?, "a");
        assert!(!t.real.join("a").exists());
        assert!(!t.real.join("b").exists());
        assert!(!t.real.join("gone").exists());
        assert!(!t.real.join("empty").exists());
        assert!(t.real.join("full/f").exists());
        assert_eq!(std::fs::read_to_string(t.real.join("target"))?, "new");
        assert!(!t.real.join("target.tmp.1").exists());
        Ok(())
    }

    #[test]
    fn setattr_mode_size_and_times() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("f"), "0123456789")?;
        std::fs::write(t.real.join("g"), "content")?;
        let out = run_sh(
            &t,
            r#"set -e
            chmod 600 "$M/f"
            truncate -s 4 "$M/f"
            touch -m -d @1000000000 "$M/f"
            : > "$M/g"
            stat -c '%a %s %Y' "$M/f""#,
        )?;
        assert_eq!(stdout(&out), "600 4 1000000000\n");
        assert_eq!(mode(&t.real.join("f"))?, 0o600);
        assert_eq!(std::fs::read(t.real.join("f"))?, b"0123");
        let mtime = std::fs::metadata(t.real.join("f"))?
            .modified()?
            .duration_since(UNIX_EPOCH)?;
        assert_eq!(mtime.as_secs(), 1_000_000_000);
        assert_eq!(std::fs::read(t.real.join("g"))?, b"");
        Ok(())
    }

    #[test]
    fn readdir_lists_all_names() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("x"), "")?;
        std::fs::write(t.real.join(".hidden"), "")?;
        std::fs::create_dir(t.real.join("many"))?;
        // More names than one reply holds, so that `readdir` must go on
        // from an offset.
        for i in 0..600 {
            std::fs::write(
                t.real.join(format!("many/entry-with-a-long-name-{i:04}")),
                "",
            )?;
        }
        let out = run_sh(
            &t,
            r#"set -e
            ls -a "$M" | tr '\n' ' '
            echo
            ls "$M/many" | wc -l
            ls "$M/many" | sort -u | wc -l"#,
        )?;
        let text = stdout(&out);
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some(". .. .hidden many x "));
        assert_eq!(lines.next().map(str::trim), Some("600"));
        assert_eq!(lines.next().map(str::trim), Some("600"));
        Ok(())
    }

    #[test]
    fn symlink_exec_access_and_statfs() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        std::os::unix::fs::symlink("/nowhere/target", t.real.join("link"))?;
        let script = t.real.join("run.sh");
        std::fs::write(&script, "#!/bin/sh\necho ran\n")?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        std::fs::write(t.real.join("ro"), "r")?;
        std::fs::set_permissions(t.real.join("ro"), std::fs::Permissions::from_mode(0o444))?;
        let out = run_sh(
            &t,
            r#"set -e
            readlink "$M/link"
            "$M/run.sh"
            test -x "$M/run.sh" && echo x
            test -w "$M/ro" || echo notw
            stat -f -c '%l' "$M""#,
        )?;
        let text = stdout(&out);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.get(..4),
            Some(&["/nowhere/target", "ran", "x", "notw"][..])
        );
        assert!(lines
            .get(4)
            .is_some_and(|l| l.parse::<u32>().is_ok_and(|n| n > 0)));
        Ok(())
    }

    #[test]
    fn a_node_follows_its_inode_after_a_host_rename() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("before"), "data")?;
        // The script opens the file and says so. The host renames the file
        // and says so. Then the script reads the open file and the new
        // name.
        let out = run_sh_with(
            &t,
            r#"set -e
            stat -c %i "$M/before"
            exec 3< "$M/before"
            : > "$M/opened"
            i=0
            while [ ! -e "$M/renamed" ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done
            cat <&3
            echo
            cat "$M/after"
            echo
            stat -c %i "$M/after""#,
            || {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                while !t.real.join("opened").exists() {
                    if std::time::Instant::now() > deadline {
                        return Err("the script did not open the file".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::fs::rename(t.real.join("before"), t.real.join("after"))?;
                std::fs::write(t.real.join("renamed"), "")?;
                Ok(())
            },
        )?;
        let text = stdout(&out);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.get(1..3), Some(&["data", "data"][..]));
        // One inode under two names is one node, with one number.
        assert_eq!(lines.first(), lines.get(3));
        Ok(())
    }

    #[test]
    fn a_slow_lookup_blocks_no_other_lookup_in_its_directory() -> TestResult {
        let Some(mut t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("slow"), "")?;
        std::fs::write(t.real.join("fast"), "")?;
        t.slow_lookup = Some(("slow".into(), Duration::from_secs(3)));
        // Both names are in the root. Without `FUSE_PARALLEL_DIROPS` the
        // kernel sends one lookup at a time in a directory, and without a
        // thread for each request the server answers one at a time: in both
        // cases the lookup of "fast" waits for the lookup of "slow".
        let out = run_sh(
            &t,
            r#"set -e
            stat "$M/slow" > /dev/null &
            sleep 0.3
            start=$(date +%s%N)
            stat "$M/fast" > /dev/null
            end=$(date +%s%N)
            echo $(( (end - start) / 1000000 ))
            wait"#,
        )?;
        let millis: u64 = stdout(&out).trim().parse()?;
        assert!(millis < 1500, "the fast lookup took {millis} ms");
        Ok(())
    }

    #[test]
    fn the_mount_has_nosuid_and_nodev() -> TestResult {
        let Some(t) = trees()? else { return Ok(()) };
        let out = run_sh(&t, r#"grep " $M " /proc/self/mountinfo"#)?;
        let line = stdout(&out);
        let opts = line.split_whitespace().nth(5).unwrap_or_default();
        let opts: Vec<&str> = opts.split(',').collect();
        assert!(opts.contains(&"nosuid"), "{line}");
        assert!(opts.contains(&"nodev"), "{line}");
        assert!(line.contains(" fuse pent "), "{line}");
        Ok(())
    }
}
