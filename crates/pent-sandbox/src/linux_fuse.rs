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
//! - **A pool of workers that grows.** Each request that can ask or wait
//!   (a lookup, an open, a create, a change of the tree) goes to an idle
//!   worker thread; when no worker is idle, the pool starts one more
//!   ([`Pool`]). An operation on a handle or a known node that never asks
//!   runs at once in one of the threads that read the requests.
//!   So a slow request, for example one that waits for a question, blocks
//!   no other request, and a request does not pay for the start of a
//!   thread. The answer to `INIT` has `FUSE_PARALLEL_DIROPS`, so the kernel
//!   also sends parallel requests in one directory.
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
//! - **The negative cache** (step 5.5). A lookup of a missing name gets a
//!   negative entry with a long validity time ([`NEGATIVE_TTL`]), so a
//!   repeated probe costs no request. The server watches the real
//!   directory with inotify, and when a process of the host makes the name,
//!   it tells the kernel to drop the entry (`FUSE_NOTIFY_INVAL_ENTRY`, or
//!   the expiry of `FUSE_HAS_EXPIRE_ONLY`, which keeps a mount below the
//!   entry). A directory that inotify cannot watch gets no negative entry.
//! - **The cache of a file** (step 5.10). An open in a watched directory
//!   keeps the page cache (`FOPEN_KEEP_CACHE`), so a second read makes no
//!   request. The watch also sees each change of a file there (a write, a
//!   new mode, a removal, a move away), and the server drops the cache of
//!   exactly that inode (`FUSE_NOTIFY_INVAL_INODE`) or that entry. A file
//!   in a directory with no watch is read again at each open.
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

/// The validity time of a negative entry. The watch of its directory
/// drops the entry when the name appears, so the time can be long.
const NEGATIVE_TTL: Duration = Duration::from_secs(3600);

/// The events of a watched directory that make a name appear.
const APPEAR: u32 = libc::IN_CREATE | libc::IN_MOVED_TO;

/// The events of a watched directory that make a name go.
const GONE: u32 = libc::IN_DELETE | libc::IN_MOVED_FROM;

/// The events of a watched directory that change a file or the directory.
const CHANGE: u32 = libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_CLOSE_WRITE;

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
    /// What the areas of one sandbox share: the decider, the events and
    /// the `/proc` of the child.
    pub(crate) shared: Arc<FileContext>,
}

/// What the areas of one sandbox share.
pub(crate) struct FileContext {
    /// The decider of an access that the grants do not give, or `None` to
    /// refuse such an access with `EACCES`.
    pub(crate) decider: Option<Arc<dyn crate::AccessDecider>>,
    /// The channel of the events of the run, or `None`.
    pub(crate) events: Option<std::sync::mpsc::Sender<pent_profile::WatchEvent>>,
    /// An `O_PATH` descriptor of the `/proc` of the child: the PID of a
    /// request is in the PID namespace of the child.
    pub(crate) proc_dir: Option<OwnedFd>,
    /// The channel to the graft helper, for the graft of an answer.
    pub(crate) grafter: Arc<crate::linux_graft::Grafter>,
    /// The widths that an answer grafted, so that no width gets two
    /// grafts.
    pub(crate) grafted: Mutex<std::collections::HashSet<PathBuf>>,
}

impl FileContext {
    /// The process of a request, for a question and its event.
    fn process(&self, caller: Caller) -> pent_profile::ProcessInfo {
        let name = self
            .proc_dir
            .as_ref()
            .and_then(|dir| read_comm(dir.as_fd(), caller.0))
            .unwrap_or_default();
        pent_profile::ProcessInfo {
            pid: caller.0,
            name,
        }
    }
}

/// Read `<pid>/comm` below the `/proc` directory `dir`.
fn read_comm(dir: BorrowedFd<'_>, pid: u32) -> Option<String> {
    let name = CString::new(format!("{pid}/comm")).ok()?;
    // SAFETY: `name` is NUL-terminated; `dir` is an open descriptor.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })
    .ok()?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut File::from(fd), &mut text).ok()?;
    Some(text.trim_end().to_string())
}

/// The process that made a request: its PID in the PID namespace of the
/// child, as the kernel gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Caller(pub(crate) u32);

/// The kind of file access that the Landlock rights `needed` stand for.
fn file_kind_of(needed: u64) -> pent_profile::FileKind {
    use crate::linux_landlock::access;
    use pent_profile::FileKind;
    if needed & access::EXECUTE != 0 {
        FileKind::Exec
    } else if needed & !(access::READ_FILE | access::READ_DIR) != 0 {
        FileKind::Write
    } else if needed & access::READ_FILE != 0 {
        FileKind::Read
    } else {
        FileKind::List
    }
}

/// The names that a temporary sibling `name` can stand for, the longest
/// first: `.claude.json.tmp.123` stands for `.claude.json.tmp`,
/// `.claude.json` and `.claude`; `notes.txt~` for `notes.txt`; the swap
/// file `.notes.txt.swp` also for `notes.txt` and `notes`.
fn sibling_candidates(name: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = Vec::new();
    dot_prefixes(name, &mut out);
    if let Some(rest) = name.strip_suffix(b"~") {
        out.push(rest);
    }
    if let Some(rest) = name.strip_prefix(b".") {
        dot_prefixes(rest, &mut out);
    }
    out.retain(|c| !c.is_empty() && *c != name && *c != b".");
    out.sort_by_key(|c| std::cmp::Reverse(c.len()));
    out.dedup();
    out
}

/// Push each part of `text` before a `.` that is not the first byte.
fn dot_prefixes<'a>(text: &'a [u8], out: &mut Vec<&'a [u8]>) {
    for (i, b) in text.iter().enumerate() {
        if *b == b'.' && i > 0 {
            if let Some(prefix) = text.get(..i) {
                out.push(prefix);
            }
        }
    }
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
    let shared = Arc::clone(&tree.tree);
    // Several threads read the requests, so the operations that run at
    // once (`FuseTree::now`) still run in parallel. Each thread has its own
    // copy of the descriptor (`FUSE_DEV_IOC_CLONE`).
    let readers = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 8));
    let mut config = Config::default();
    config.n_threads = Some(readers);
    config.clone_fd = true;
    let session =
        Session::from_fd(tree, dev, SessionACL::Owner, config).map_err(FuseError::Handshake)?;
    // The negative cache needs the notifier, and the notifier needs the
    // session; a second `set` cannot happen.
    let _ = shared.notifier.set(session.notifier());
    if let Some(watches) = &shared.watches {
        let fd = Arc::clone(&watches.fd);
        let tree = Arc::downgrade(&shared);
        // Without the thread no entry is dropped: the tree then gives no
        // negative entry (`Watches::running`).
        if std::thread::Builder::new()
            .name("pent-fuse-watch".to_string())
            .spawn(move || watch_loop(&fd, &tree))
            .is_ok()
        {
            watches.running.store(true, Ordering::Release);
        }
    }
    let thread = std::thread::Builder::new()
        .name("pent-fuse".to_string())
        .spawn(move || session.run())
        .map_err(FuseError::Thread)?;
    Ok(FuseServer { thread })
}

/// The inotify watches of the directories that hold a negative entry.
struct Watches {
    fd: Arc<OwnedFd>,
    /// The watch of each directory, both ways.
    maps: Mutex<WatchMaps>,
    /// True when the thread that reads the events runs.
    running: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct WatchMaps {
    by_wd: HashMap<i32, u64>,
    by_node: HashMap<u64, i32>,
}

impl Watches {
    fn new() -> Option<Self> {
        // SAFETY: inotify_init1(2) with integer flags.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let fd =
            owned(unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) }).ok()?;
        Some(Self {
            fd: Arc::new(fd),
            maps: Mutex::new(WatchMaps::default()),
            running: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

/// Read the events of `fd` until the tree goes, and drop the entry of each
/// name that appears in a watched directory.
fn watch_loop(fd: &OwnedFd, tree: &std::sync::Weak<Tree>) {
    let mut buf = [0u8; 4096];
    loop {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`; the timeout lets the loop see the end
        // of the tree.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ready = unsafe { libc::poll(&raw mut poll, 1, 500) };
        let Some(tree) = tree.upgrade() else {
            return;
        };
        if ready <= 0 {
            continue;
        }
        // SAFETY: `buf` has `buf.len()` writable bytes.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        let Ok(n) = usize::try_from(n) else {
            continue;
        };
        tree.events(buf.get(..n).unwrap_or_default());
    }
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
    /// The node of each entry (a directory node and a name), for the
    /// events of the watches.
    by_entry: HashMap<(u64, OsString), u64>,
    next: u64,
}

impl Inodes {
    /// Give the node `id` the entry `name` of `parent`, and keep the index.
    fn set_entry(&mut self, id: u64, parent: u64, name: &OsStr) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        let old = (
            node.parent,
            std::mem::replace(&mut node.name, name.to_owned()),
        );
        node.parent = parent;
        if self.by_entry.get(&old) == Some(&id) {
            self.by_entry.remove(&old);
        }
        self.by_entry.insert((parent, name.to_owned()), id);
    }
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
    /// The temporary siblings that the program made in this run, with the
    /// path of the file whose answer each one gets.
    stand_ins: Mutex<HashMap<PathBuf, PathBuf>>,
    /// The watches of the negative cache, or `None` without inotify.
    watches: Option<Watches>,
    /// The notifier of the session, to drop an entry.
    notifier: std::sync::OnceLock<fuser::Notifier>,
    /// A test hook: the number of lookups of each name.
    #[cfg(test)]
    lookups_seen: Option<Arc<Mutex<HashMap<OsString, u32>>>>,
    /// A test hook: the number of `READ` requests.
    #[cfg(test)]
    reads_seen: Option<Arc<AtomicU64>>,
    /// A test hook: a lookup of this name waits this long.
    #[cfg(test)]
    slow_lookup: Option<(OsString, Duration)>,
}

/// The `fuser` filesystem: it sends each request to the pool.
struct FuseTree {
    tree: Arc<Tree>,
    pool: Arc<Pool>,
}

impl Drop for FuseTree {
    /// The session ends: the workers end, and with them the last holds on
    /// the tree (its event sender too).
    fn drop(&mut self) {
        self.pool.close();
    }
}

/// One request for a worker of the pool.
type Job = Box<dyn FnOnce(&Tree) + Send>;

/// The most workers of one tree. A request waits in the queue when all of
/// them are busy.
const MAX_WORKERS: usize = 1024;

/// The workers that stay when they have no job.
const MIN_WORKERS: usize = 4;

/// How long a worker with no job waits before it ends.
const IDLE_LIFE: Duration = Duration::from_secs(5);

/// The worker threads of one tree. A request goes to an idle worker. When
/// no worker is idle, the pool starts one more, up to [`MAX_WORKERS`], so a
/// request that waits for a question blocks no other request. A worker
/// with no job for [`IDLE_LIFE`] ends, but [`MIN_WORKERS`] stay.
#[derive(Default)]
struct Pool {
    state: Mutex<PoolState>,
    wake: std::sync::Condvar,
}

#[derive(Default)]
struct PoolState {
    jobs: std::collections::VecDeque<Job>,
    workers: usize,
    idle: usize,
    closed: bool,
}

impl Pool {
    /// Give `job` to a worker. If no worker can start and none runs, run
    /// the job here, so that the request still gets its answer.
    fn submit(self: &Arc<Self>, tree: &Arc<Tree>, job: Job) {
        let mut state = lock(&self.state);
        state.jobs.push_back(job);
        if state.idle >= state.jobs.len() || state.workers >= MAX_WORKERS {
            self.wake.notify_one();
            return;
        }
        state.workers = state.workers.saturating_add(1);
        drop(state);
        let (pool, theirs) = (Arc::clone(self), Arc::clone(tree));
        let started = std::thread::Builder::new()
            .name("pent-fuse-req".to_string())
            .spawn(move || pool.work(&theirs));
        if started.is_err() {
            let mut state = lock(&self.state);
            state.workers = state.workers.saturating_sub(1);
            if state.workers == 0 {
                let job = state.jobs.pop_front();
                drop(state);
                if let Some(job) = job {
                    job(tree);
                }
            }
        }
    }

    /// The loop of one worker.
    fn work(&self, tree: &Tree) {
        let mut state = lock(&self.state);
        loop {
            if let Some(job) = state.jobs.pop_front() {
                drop(state);
                job(tree);
                state = lock(&self.state);
                continue;
            }
            if state.closed {
                break;
            }
            state.idle = state.idle.saturating_add(1);
            let (next, wait) = self
                .wake
                .wait_timeout(state, IDLE_LIFE)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            state.idle = state.idle.saturating_sub(1);
            if wait.timed_out() && state.jobs.is_empty() && state.workers > MIN_WORKERS {
                break;
            }
        }
        state.workers = state.workers.saturating_sub(1);
    }

    /// Let each worker end when the queue is empty.
    fn close(&self) {
        lock(&self.state).closed = true;
        self.wake.notify_all();
    }
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
                by_entry: HashMap::new(),
                nodes,
                by_key,
                next: root_id.saturating_add(1),
            }),
            files: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            policy,
            stand_ins: Mutex::new(HashMap::new()),
            watches: Watches::new(),
            notifier: std::sync::OnceLock::new(),
            #[cfg(test)]
            lookups_seen: None,
            #[cfg(test)]
            reads_seen: None,
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
                    inodes.set_entry(id, u64::from(parent), name);
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
        inodes
            .by_entry
            .insert((u64::from(parent), name.to_owned()), id);
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

    /// Decide the operation `op`, which needs the Landlock rights
    /// `needed`, of `caller` on the node `ino`, or on its entry `child`.
    /// Without a policy each access passes.
    ///
    /// The order: the pent class gives `ENOENT`; then the grants; then the
    /// target of a temporary sibling; then the decider, which asks when no
    /// rule, flag or answer knows the access. A deny or the deadline gives
    /// `EACCES`.
    fn require(
        &self,
        caller: Caller,
        ino: INodeNo,
        child: Option<&OsStr>,
        needed: u64,
        op: pent_profile::FsOp,
    ) -> Result<(), Errno> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        let mut path = self.path(ino)?;
        if let Some(child) = child {
            path.push(child);
        }
        if self.hidden(&path) {
            return Err(Errno::ENOENT);
        }
        let grants = |p: &Path| {
            policy
                .grants
                .rights_in_area(p, &policy.area, &policy.private_above)
                & needed
                == needed
        };
        if grants(&path) {
            return Ok(());
        }
        // A temporary sibling gets the answer of its target. Only a name
        // that the program makes in this run becomes one, so a file of the
        // host never takes the answer of another name.
        let known = lock(&self.stand_ins).get(&path).cloned();
        let new = match (&known, op, child) {
            (None, pent_profile::FsOp::Create, Some(name)) => self.sibling_target(ino, name),
            _ => None,
        };
        let subject = known
            .clone()
            .or_else(|| new.clone())
            .unwrap_or_else(|| path.clone());
        if subject != path {
            if self.hidden(&subject) {
                return Err(Errno::EACCES);
            }
            if grants(&subject) {
                self.keep_stand_in(&path, new);
                return Ok(());
            }
        }
        let Some(decider) = &policy.shared.decider else {
            return Err(Errno::EACCES);
        };
        let Ok(rule_path) = pent_profile::RulePath::new(subject.clone()) else {
            return Err(Errno::EACCES);
        };
        let request = pent_profile::Request::File {
            kind: file_kind_of(needed),
            path: rule_path,
        };
        let process = policy.shared.process(caller);
        // The decider knows a rule, a flag or an answer first, and asks only
        // when none decides. The target of an allow becomes a graft, also
        // for a rule that the static grants could not hold (a sensitive
        // place inside it gives the graft its holes).
        let (decision, target) =
            decider.decide_target(&process.name, request, pent_profile::FILE_DEADLINE);
        if let Some(events) = &policy.shared.events {
            // The run can be at its end; then nobody reads the event.
            let _ = events.send(pent_profile::WatchEvent::Fs {
                op,
                path: subject,
                process,
                outcome: match decision {
                    pent_profile::Decision::Allow => pent_profile::Outcome::Allowed,
                    pent_profile::Decision::Deny => pent_profile::Outcome::Denied,
                },
            });
        }
        match decision {
            pent_profile::Decision::Allow => {
                self.keep_stand_in(&path, new);
                if let Some(target) = target {
                    self.graft_answer(policy, &target);
                }
                Ok(())
            }
            pent_profile::Decision::Deny => Err(Errno::EACCES),
        }
    }

    /// Graft the width of an answer in a new thread, when the decider lets
    /// a graft give it. This access goes through FUSE; the later ones go to
    /// the graft. A graft must not wait in the thread of a request: the
    /// kernel can hold the lock of a directory that the graft must look up.
    fn graft_answer(&self, policy: &AreaPolicy, target: &pent_profile::Target) {
        let pent_profile::Target::File {
            kind,
            width: pent_profile::PathWidth::Subtree(base),
        } = target
        else {
            return;
        };
        let Some(access) = crate::linux_graft::GraftAccess::of_kind(*kind) else {
            return;
        };
        let base = base.as_path();
        let Ok(rel) = base.strip_prefix(&policy.area) else {
            return;
        };
        let plan = policy
            .shared
            .decider
            .as_ref()
            .and_then(|d| d.graft_plan(target))
            .and_then(|holes| crate::linux_graft::relative_holes(base, &holes));
        let Some(holes) = plan else {
            return;
        };
        if !std::fs::symlink_metadata(base).is_ok_and(|m| m.is_dir()) {
            return;
        }
        if !lock(&policy.shared.grafted).insert(base.to_path_buf()) {
            return;
        }
        let Ok(root) = self
            .fd(INodeNo::ROOT)
            .and_then(|fd| fd.try_clone().map_err(Errno::from))
        else {
            return;
        };
        let grafter = Arc::clone(&policy.shared.grafter);
        let (area, rel) = (policy.area.clone(), rel.to_path_buf());
        let spawned = std::thread::Builder::new()
            .name("pent-fuse-graft".to_string())
            .spawn(move || {
                if let Err(e) = grafter.graft(root.as_fd(), &area, &rel, &holes, access) {
                    tracing::debug!("no graft of {}: {e}", area.join(&rel).display());
                }
            });
        // Without the thread FUSE serves the width; that is still correct.
        drop(spawned);
    }

    /// Return true if `path` is in the pent class.
    fn hidden(&self, path: &Path) -> bool {
        self.policy
            .as_ref()
            .and_then(|p| p.shared.decider.as_ref())
            .is_some_and(|d| d.hidden(path))
    }

    /// Remember the new temporary sibling `path` of `target`.
    fn keep_stand_in(&self, path: &Path, target: Option<PathBuf>) {
        if let Some(target) = target {
            lock(&self.stand_ins).insert(path.to_path_buf(), target);
        }
    }

    /// Forget the temporary sibling `path`: it was renamed or removed.
    fn drop_stand_in(&self, path: &Path) {
        lock(&self.stand_ins).remove(path);
    }

    /// The file whose answer the new name `name` in the directory `dir`
    /// gets: the longest candidate (see [`sibling_candidates`]) that is a
    /// regular file in the directory, or that a grant lets the program
    /// write.
    fn sibling_target(&self, dir: INodeNo, name: &OsStr) -> Option<PathBuf> {
        let policy = self.policy.as_ref()?;
        let dir_path = self.path(dir).ok()?;
        let dir_fd = self.fd(dir).ok()?;
        for candidate in sibling_candidates(name.as_bytes()) {
            let candidate = OsStr::from_bytes(candidate);
            let target = dir_path.join(candidate);
            let is_file = component(candidate)
                .ok()
                .and_then(|c| open_path(dir_fd.as_fd(), &c).ok())
                .and_then(|fd| stat_fd(fd.as_fd()).ok())
                .is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG);
            let writable =
                policy
                    .grants
                    .rights_in_area(&target, &policy.area, &policy.private_above)
                    & crate::linux_landlock::access::WRITE_FILE
                    != 0;
            if is_file || writable {
                return Some(target);
            }
        }
        None
    }

    /// Give the node of the inode `key` the entry `newname` of `newparent`,
    /// after a rename.
    fn moved(&self, key: InodeKey, newparent: INodeNo, newname: &OsStr) {
        let mut inodes = lock(&self.inodes);
        if let Some(id) = inodes.by_key.get(&key).copied() {
            inodes.set_entry(id, u64::from(newparent), newname);
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
            if let Some(node) = inodes.nodes.remove(&id) {
                let entry = (node.parent, node.name);
                if inodes.by_entry.get(&entry) == Some(&id) {
                    inodes.by_entry.remove(&entry);
                }
            }
            if inodes.by_key.get(&key) == Some(&id) {
                inodes.by_key.remove(&key);
            }
            drop(inodes);
            self.unwatch(id);
        }
    }

    /// Open `name` in `parent`, remember the node, and give its attributes.
    fn lookup(&self, parent: INodeNo, name: &OsStr) -> Result<Lookup, Errno> {
        #[cfg(test)]
        if let Some((slow, wait)) = &self.slow_lookup {
            if slow == name {
                std::thread::sleep(*wait);
            }
        }
        #[cfg(test)]
        if let Some(seen) = &self.lookups_seen {
            *lock(seen).entry(name.to_owned()).or_default() += 1;
        }
        let cname = component(name)?;
        if self.policy.is_some() && self.hidden(&self.path(parent)?.join(name)) {
            return Err(Errno::ENOENT);
        }
        let dir = self.fd(parent)?;
        match open_path(dir.as_fd(), &cname) {
            Ok(fd) => self.entry(fd, parent, name).map(Lookup::Found),
            Err(e) if e == Errno::ENOENT && self.watch(parent, &dir) => Ok(Lookup::Missing),
            Err(e) => Err(e),
        }
    }

    /// Watch the directory `dir` (the node `ino`) for new names. Returns
    /// true when a watch holds it, so a negative entry there is safe.
    fn watch(&self, ino: INodeNo, dir: &OwnedFd) -> bool {
        let Some(watches) = &self.watches else {
            return false;
        };
        if !watches.running.load(Ordering::Acquire) {
            return false;
        }
        let id = u64::from(ino);
        let mut maps = lock(&watches.maps);
        if maps.by_node.contains_key(&id) {
            return true;
        }
        let path = proc_path(dir.as_fd());
        // SAFETY: `path` is NUL-terminated; the rest are integers.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let wd = unsafe {
            libc::inotify_add_watch(
                watches.fd.as_raw_fd(),
                path.as_ptr(),
                APPEAR | GONE | CHANGE | libc::IN_ONLYDIR,
            )
        };
        if wd < 0 {
            // At the limit of watches the tree just gives no negative
            // entry.
            return false;
        }
        maps.by_wd.insert(wd, id);
        maps.by_node.insert(id, wd);
        true
    }

    /// Handle a buffer of inotify events: drop the entry of each name that
    /// appears, and forget a watch that the kernel removed.
    fn events(&self, mut buf: &[u8]) {
        const HEADER: usize = std::mem::size_of::<libc::inotify_event>();
        let word = |b: &[u8], at: usize| {
            b.get(at..at.saturating_add(4))
                .and_then(|w| <[u8; 4]>::try_from(w).ok())
                .map(u32::from_ne_bytes)
        };
        while buf.len() >= HEADER {
            let (Some(wd), Some(mask), Some(len)) = (word(buf, 0), word(buf, 4), word(buf, 12))
            else {
                return;
            };
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            let Some(name) = buf.get(HEADER..HEADER.saturating_add(len)) else {
                return;
            };
            // The name is padded with NUL bytes.
            let name = name.split(|b| *b == 0).next().unwrap_or_default();
            let wd = i32::from_ne_bytes(wd.to_ne_bytes());
            self.event(wd, mask, OsStr::from_bytes(name));
            buf = buf.get(HEADER.saturating_add(len)..).unwrap_or_default();
        }
    }

    fn event(&self, wd: i32, mask: u32, name: &OsStr) {
        let Some(watches) = &self.watches else {
            return;
        };
        let node = {
            let mut maps = lock(&watches.maps);
            if mask & libc::IN_IGNORED != 0 {
                if let Some(node) = maps.by_wd.remove(&wd) {
                    maps.by_node.remove(&node);
                }
                return;
            }
            maps.by_wd.get(&wd).copied()
        };
        let (Some(dir), Some(notifier)) = (node, self.notifier.get()) else {
            return;
        };
        // The kernel may know no entry and no cache for the name; an error
        // of a notification then means nothing.
        if name.is_empty() {
            // An event of the directory itself.
            if mask & CHANGE != 0 {
                let _ = notifier.inval_inode(INodeNo(dir), 0, 0);
            }
            return;
        }
        if mask & (APPEAR | GONE) != 0 {
            // The expiry keeps a mount below the entry; an old kernel has
            // only the invalidation.
            if notifier.expire_entry(INodeNo(dir), name).is_err() {
                let _ = notifier.inval_entry(INodeNo(dir), name);
            }
        }
        if mask & (CHANGE | GONE) != 0 {
            let file = lock(&self.inodes)
                .by_entry
                .get(&(dir, name.to_owned()))
                .copied();
            if let Some(file) = file {
                // The attributes and each page of the file.
                let _ = notifier.inval_inode(INodeNo(file), 0, 0);
            }
        }
    }

    /// The flags of an open of the node `ino`: keep the page cache when a
    /// watch of its directory holds, so that a change is seen at once.
    fn open_flags(&self, ino: INodeNo) -> FopenFlags {
        let parent = lock(&self.inodes)
            .nodes
            .get(&u64::from(ino))
            .map(|n| n.parent);
        let watched = parent.is_some_and(|p| {
            self.fd(INodeNo(p))
                .is_ok_and(|dir| self.watch(INodeNo(p), &dir))
        });
        if watched {
            FopenFlags::FOPEN_KEEP_CACHE
        } else {
            FopenFlags::empty()
        }
    }

    /// Remove the watch of the node `id`, which the kernel forgot.
    fn unwatch(&self, id: u64) {
        let Some(watches) = &self.watches else {
            return;
        };
        let mut maps = lock(&watches.maps);
        if let Some(wd) = maps.by_node.remove(&id) {
            maps.by_wd.remove(&wd);
            // SAFETY: inotify_rm_watch(2) with integers.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::inotify_rm_watch(watches.fd.as_raw_fd(), wd) };
        }
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
        caller: Caller,
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
            self.require(
                caller,
                ino,
                None,
                crate::linux_landlock::access::TRUNCATE,
                pent_profile::FsOp::Write,
            )?;
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
        caller: Caller,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<FileAttr, Errno> {
        self.require(
            caller,
            parent,
            Some(name),
            crate::linux_landlock::access::MAKE_DIR,
            pent_profile::FsOp::Create,
        )?;
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

    fn symlink(
        &self,
        caller: Caller,
        parent: INodeNo,
        name: &OsStr,
        target: &Path,
    ) -> Result<FileAttr, Errno> {
        self.require(
            caller,
            parent,
            Some(name),
            crate::linux_landlock::access::MAKE_SYM,
            pent_profile::FsOp::Create,
        )?;
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
        caller: Caller,
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
        self.require(
            caller,
            parent,
            Some(name),
            needed,
            pent_profile::FsOp::Create,
        )?;
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

    fn unlink(
        &self,
        caller: Caller,
        parent: INodeNo,
        name: &OsStr,
        flags: libc::c_int,
    ) -> Result<(), Errno> {
        let needed = if flags & libc::AT_REMOVEDIR != 0 {
            crate::linux_landlock::access::REMOVE_DIR
        } else {
            crate::linux_landlock::access::REMOVE_FILE
        };
        self.require(
            caller,
            parent,
            Some(name),
            needed,
            pent_profile::FsOp::Delete,
        )?;
        let cname = component(name)?;
        let dir = self.fd(parent)?;
        // SAFETY: `cname` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), flags) } != 0 {
            return Err(last_errno());
        }
        if self.policy.is_some() {
            if let Ok(dir_path) = self.path(parent) {
                self.drop_stand_in(&dir_path.join(name));
            }
        }
        Ok(())
    }

    fn rename(
        &self,
        caller: Caller,
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
            self.require(
                caller,
                parent,
                Some(name),
                on_from,
                pent_profile::FsOp::Delete,
            )?;
            self.require(
                caller,
                newparent,
                Some(newname),
                on_to,
                pent_profile::FsOp::Create,
            )?;
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
        if self.policy.is_some() {
            if let Ok(dir_path) = self.path(parent) {
                self.drop_stand_in(&dir_path.join(name));
            }
        }
        self.moved(key_of(&source), newparent, newname);
        if let Some(target) = &target {
            self.moved(key_of(target), parent, name);
        }
        Ok(())
    }

    fn open(&self, caller: Caller, ino: INodeNo, flags: OpenFlags) -> Result<FileHandle, Errno> {
        let needed = open_rights(flags.0);
        let op = match file_kind_of(needed) {
            pent_profile::FileKind::Exec => pent_profile::FsOp::Exec,
            pent_profile::FileKind::Write => pent_profile::FsOp::Write,
            pent_profile::FileKind::Read | pent_profile::FileKind::List => pent_profile::FsOp::Read,
        };
        self.require(caller, ino, None, needed, op)?;
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
        caller: Caller,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<(FileAttr, FileHandle), Errno> {
        self.require(
            caller,
            parent,
            Some(name),
            crate::linux_landlock::access::MAKE_REG | open_rights(flags),
            pent_profile::FsOp::Create,
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
        #[cfg(test)]
        if let Some(seen) = &self.reads_seen {
            seen.fetch_add(1, Ordering::Relaxed);
        }
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
    fn opendir(&self, caller: Caller, ino: INodeNo) -> Result<FileHandle, Errno> {
        self.require(
            caller,
            ino,
            None,
            crate::linux_landlock::access::READ_DIR,
            pent_profile::FsOp::List,
        )?;
        // The names of the pent class are not in a listing.
        let dir_path = if self.policy.is_some() {
            Some(self.path(ino)?)
        } else {
            None
        };
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
            if dir_path
                .as_ref()
                .is_some_and(|d| self.hidden(&d.join(entry.file_name())))
            {
                continue;
            }
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
        Ok(Self::of(Arc::new(Tree::new(root, policy)?)))
    }

    fn of(tree: Arc<Tree>) -> Self {
        Self {
            tree,
            pool: Arc::new(Pool::default()),
        }
    }

    /// Run `job` at once, in the thread that read the request: for an
    /// operation that never asks and never waits long (the handle or the
    /// node exists already). The session reads with several threads, so
    /// such operations still run in parallel.
    fn now<F>(&self, job: F)
    where
        F: FnOnce(&Tree),
    {
        job(&self.tree);
    }

    /// Run `job` in a worker of the pool: for an operation that can ask a
    /// question or wait.
    fn spawn<F>(&self, job: F)
    where
        F: FnOnce(&Tree) + Send + 'static,
    {
        self.pool.submit(&self.tree, Box::new(job));
    }
}

/// The answer of a lookup.
enum Lookup {
    /// The name exists.
    Found(FileAttr),
    /// The name is missing, and a watch of its directory holds: the kernel
    /// may keep a negative entry.
    Missing,
}

/// The attributes of a negative entry: node 0.
fn negative_attr() -> FileAttr {
    FileAttr {
        ino: INodeNo(0),
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 0,
        flags: 0,
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
            .map_err(|_| std::io::Error::other("the kernel has no FUSE_PARALLEL_DIROPS"))?;
        // The expiry of an entry keeps a mount below it. An old kernel
        // does not offer it; the server then invalidates the entry.
        if config
            .capabilities()
            .contains(InitFlags::FUSE_HAS_EXPIRE_ONLY)
        {
            let _ = config.add_capabilities(InitFlags::FUSE_HAS_EXPIRE_ONLY);
        }
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_owned();
        self.spawn(move |t| match t.lookup(parent, &name) {
            Ok(Lookup::Found(attr)) => reply.entry(&TTL, &attr, GENERATION),
            Ok(Lookup::Missing) => reply.entry(&NEGATIVE_TTL, &negative_attr(), GENERATION),
            Err(e) => reply.error(e),
        });
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.tree.forget(ino, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.now(move |t| reply_attr(reply, t.getattr(ino)));
    }

    fn setattr(
        &self,
        req: &Request,
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
        let caller = Caller(req.pid());
        self.spawn(move |t| {
            reply_attr(
                reply,
                t.setattr(caller, ino, mode, uid, gid, size, atime, mtime, fh),
            );
        });
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        self.now(move |t| match t.readlink(ino) {
            Ok(target) => reply.data(&target),
            Err(e) => reply.error(e),
        });
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let caller = Caller(req.pid());
        let name = name.to_owned();
        self.spawn(move |t| reply_entry(reply, t.mkdir(caller, parent, &name, mode, umask)));
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let caller = Caller(req.pid());
        let (name, target) = (link_name.to_owned(), target.to_owned());
        self.spawn(move |t| reply_entry(reply, t.symlink(caller, parent, &name, &target)));
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let caller = Caller(req.pid());
        let name = name.to_owned();
        self.spawn(move |t| reply_entry(reply, t.mknod(caller, parent, &name, mode, umask)));
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
        self.now(move |t| reply_empty(reply, t.fallocate(fh, offset, length, mode)));
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
        self.now(move |t| match t.lseek(fh, offset, whence) {
            Ok(at) => reply.offset(at),
            Err(e) => reply.error(e),
        });
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let caller = Caller(req.pid());
        let name = name.to_owned();
        self.spawn(move |t| reply_empty(reply, t.unlink(caller, parent, &name, 0)));
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let caller = Caller(req.pid());
        let name = name.to_owned();
        self.spawn(move |t| {
            reply_empty(reply, t.unlink(caller, parent, &name, libc::AT_REMOVEDIR))
        });
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _owner: Option<fuser::Owner>,
        reply: ReplyEmpty,
    ) {
        let caller = Caller(req.pid());
        let (name, newname) = (name.to_owned(), newname.to_owned());
        self.spawn(move |t| {
            reply_empty(
                reply,
                t.rename(caller, parent, &name, newparent, &newname, flags),
            );
        });
    }

    fn open(
        &self,
        req: &Request,
        ino: INodeNo,
        flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        let caller = Caller(req.pid());
        self.spawn(move |t| match t.open(caller, ino, flags) {
            Ok(fh) => reply.opened(fh, t.open_flags(ino)),
            Err(e) => reply.error(e),
        });
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
        self.now(move |t| match t.read(fh, offset, size) {
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
        self.now(move |t| match t.write(fh, offset, &data) {
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
        // Each write goes to the real file at once: nothing waits. After
        // `ENOSYS` the kernel sends no more `FLUSH`, and `close(2)` gives 0:
        // one request less for each open.
        reply.error(Errno::ENOSYS);
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
        self.now(move |t| {
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
        self.now(move |t| reply_empty(reply, t.fsync(fh, datasync)));
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let caller = Caller(req.pid());
        self.spawn(move |t| reply_open(reply, t.opendir(caller, ino)));
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        self.now(move |t| t.readdir(fh, offset, reply));
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.now(move |t| {
            t.releasedir(fh);
            reply.ok();
        });
    }

    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        self.now(move |t| t.statfs(ino, reply));
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        self.now(move |t| reply_empty(reply, t.access(ino, mask)));
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        _owner: fuser::Owner,
        reply: ReplyCreate,
    ) {
        let caller = Caller(req.pid());
        let name = name.to_owned();
        self.spawn(
            move |t| match t.create(caller, parent, &name, mode, umask, flags) {
                Ok((attr, fh)) => reply.created(&TTL, &attr, GENERATION, fh, FopenFlags::empty()),
                Err(e) => reply.error(e),
            },
        );
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
        /// The count of the lookups of each name (see `Tree::lookups_seen`).
        lookups_seen: Option<Arc<Mutex<HashMap<OsString, u32>>>>,
        /// The count of the `READ` requests (see `Tree::reads_seen`).
        reads_seen: Option<Arc<AtomicU64>>,
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
            lookups_seen: None,
            reads_seen: None,
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
        let hooked = t.slow_lookup.is_some() || t.lookups_seen.is_some() || t.reads_seen.is_some();
        let server = if !hooked {
            serve(dev, root, None)?
        } else {
            let mut tree = Tree::new(root, None)?;
            tree.slow_lookup.clone_from(&t.slow_lookup);
            tree.lookups_seen.clone_from(&t.lookups_seen);
            tree.reads_seen.clone_from(&t.reads_seen);
            let tree = Arc::new(tree);
            serve_tree(dev, FuseTree::of(tree))?
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

    /// A repeated probe of a missing name makes one lookup: the kernel
    /// keeps the negative entry. A file that a process of the host makes
    /// then becomes visible at once, long before the validity time ends.
    #[test]
    fn a_missing_name_is_cached_until_the_host_makes_it() -> TestResult {
        let Some(mut t) = trees()? else { return Ok(()) };
        let seen = Arc::new(Mutex::new(HashMap::new()));
        t.lookups_seen = Some(Arc::clone(&seen));
        let marker = t.real.join("made-by-host");
        let created = marker.clone();
        let out = run_sh_with(
            &t,
            r#"set -e
            i=0
            while [ $i -lt 100 ]; do [ -e "$M/later" ] && echo early; i=$((i+1)); done
            : > "$M/probed"
            j=0
            while [ ! -e "$M/made-by-host" ] && [ $j -lt 400 ]; do sleep 0.05; j=$((j+1)); done
            k=0
            while [ ! -e "$M/later" ] && [ $k -lt 40 ]; do sleep 0.05; k=$((k+1)); done
            [ -e "$M/later" ] && echo visible"#,
            move || {
                let probed = created.with_file_name("probed");
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                while !probed.exists() {
                    if std::time::Instant::now() > deadline {
                        return Err("the script did not probe".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::fs::write(created.with_file_name("later"), "")?;
                std::fs::write(&created, "")?;
                Ok(())
            },
        )?;
        assert_eq!(stdout(&out), "visible\n");
        assert!(marker.exists());
        // One lookup for the 100 probes, and one more after the host made
        // the file.
        let count = lock(&seen).get(OsStr::new("later")).copied().unwrap_or(0);
        assert_eq!(count, 2, "lookups of the probed name");
        Ok(())
    }

    /// A second read of a file in a watched directory makes no `READ`: the
    /// kernel keeps the page cache. A change by a process of the host is
    /// visible at once: the watch drops the cache of the file.
    #[test]
    fn a_kept_file_cache_drops_at_a_change_of_the_host() -> TestResult {
        let Some(mut t) = trees()? else { return Ok(()) };
        std::fs::write(t.real.join("f"), "old\n")?;
        let reads = Arc::new(AtomicU64::new(0));
        t.reads_seen = Some(Arc::clone(&reads));
        let real = t.real.clone();
        let seen = Arc::clone(&reads);
        let before = Arc::new(AtomicU64::new(u64::MAX));
        let kept = Arc::clone(&before);
        let out = run_sh_with(
            &t,
            r#"set -e
            cat "$M/f"
            cat "$M/f"
            : > "$M/probed"
            j=0
            while [ ! -e "$M/changed" ] && [ $j -lt 400 ]; do sleep 0.05; j=$((j+1)); done
            k=0
            while [ "$(cat "$M/f")" != new ] && [ $k -lt 40 ]; do sleep 0.05; k=$((k+1)); done
            cat "$M/f""#,
            move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                while !real.join("probed").exists() {
                    if std::time::Instant::now() > deadline {
                        return Err("the script did not read".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                kept.store(seen.load(Ordering::Relaxed), Ordering::Relaxed);
                // The same inode, new content.
                std::fs::write(real.join("f"), "new\n")?;
                std::fs::write(real.join("changed"), "")?;
                Ok(())
            },
        )?;
        assert_eq!(stdout(&out), "old\nold\nnew\n");
        assert_eq!(
            before.load(Ordering::Relaxed),
            1,
            "two reads made more than one READ"
        );
        Ok(())
    }
}
