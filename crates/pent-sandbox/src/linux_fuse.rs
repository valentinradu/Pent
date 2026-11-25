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
//! - **The inode number** that `stat` gives is the number of the node,
//!   because `fuser` uses the same number for both. A listing gives the
//!   number of the node when the node exists, else the real inode number.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirEntryExt, FileExt};
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
/// descriptor of the real directory (`O_PATH` is enough). The function does
/// the `INIT` exchange, and then it serves the requests in a new thread.
///
/// # Errors
/// Returns [`FuseError::Root`] if `root` is not readable,
/// [`FuseError::Handshake`] if the `INIT` exchange fails, or
/// [`FuseError::Thread`] if the session thread does not start.
pub(crate) fn serve(dev: OwnedFd, root: OwnedFd) -> Result<FuseServer, FuseError> {
    serve_tree(dev, FuseTree::new(root).map_err(FuseError::Root)?)
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
}

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
    fn new(root: OwnedFd) -> std::io::Result<Self> {
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

    /// Add one lookup of the inode of `fd`, and return its node number. A
    /// known inode keeps its node, and `fd` closes.
    fn remember(&self, fd: OwnedFd, st: &libc::stat) -> Result<u64, Errno> {
        let key = key_of(st);
        let mut inodes = lock(&self.inodes);
        if let Some(id) = inodes.by_key.get(&key).copied() {
            if let Some(node) = inodes.nodes.get_mut(&id) {
                node.lookups = node.lookups.saturating_add(1);
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
            },
        );
        inodes.by_key.insert(key, id);
        Ok(id)
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
        let name = component(name)?;
        let dir = self.fd(parent)?;
        let fd = open_path(dir.as_fd(), &name)?;
        self.entry(fd)
    }

    /// Remember the node of `fd` and give its attributes.
    fn entry(&self, fd: OwnedFd) -> Result<FileAttr, Errno> {
        let st = stat_fd(fd.as_fd())?;
        let id = self.remember(fd, &st)?;
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
        let name = component(name)?;
        let dir = self.fd(parent)?;
        let mode = mode & !umask & 0o7777;
        // SAFETY: `name` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) } != 0 {
            return Err(last_errno());
        }
        let fd = open_path(dir.as_fd(), &name)?;
        // The umask of pent also cut the mode; set the mode of the request.
        chmod_fd(fd.as_fd(), mode)?;
        self.entry(fd)
    }

    fn unlink(&self, parent: INodeNo, name: &OsStr, flags: libc::c_int) -> Result<(), Errno> {
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
        let (name, newname) = (component(name)?, component(newname)?);
        let (from, to) = (self.fd(parent)?, self.fd(newparent)?);
        // SAFETY: both names are NUL-terminated; the flags are integers.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let ret = unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                name.as_ptr(),
                to.as_raw_fd(),
                newname.as_ptr(),
                flags.bits(),
            )
        };
        if ret != 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    fn open(&self, ino: INodeNo, flags: OpenFlags) -> Result<FileHandle, Errno> {
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
        let name = component(name)?;
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
                name.as_ptr(),
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
                let file = owned(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), base) })?;
                (file, false)
            }
            Err(e) => return Err(e),
        };
        if created {
            // The umask of pent also cut the mode; set the mode of the
            // request.
            chmod_fd(file.as_fd(), mode)?;
        }
        let node = open_path(dir.as_fd(), &name)?;
        let attr = self.entry(node)?;
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
    fn new(root: OwnedFd) -> std::io::Result<Self> {
        Ok(Self {
            tree: Arc::new(Tree::new(root)?),
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
            None => serve(dev, root)?,
            Some(slow) => {
                let mut tree = Tree::new(root)?;
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
