//! The server of pentd.
//!
//! - **One instance for each user.** pentd takes `flock` on
//!   `<runtime>/pentd.lock` before it touches the socket. Thus only the
//!   holder of the lock removes a stale socket or binds a new one.
//! - **The socket** `<runtime>/pentd.sock` has the mode `0600` in a
//!   directory with the mode `0700`. pentd also checks the user ID of each
//!   peer with `SO_PEERCRED`, and it closes the connection of another user.
//! - **A hold is a live connection** that sent [`Message::Hold`]. pentd
//!   stops [`linger`](super::linger) after the last hold ends. A crash of a
//!   holder closes its connection, so a crash cannot leave a count behind.
//!   pentd also stops after the linger time when no hold comes at all, for
//!   example when the `pent run` that started it stops at once.

use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pent_settings::RuntimeDir;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};

use super::hub::{ConnectionGuard, Hub, Outbox, Role};
use super::{read_message, DaemonError};

/// The first fd of socket activation (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: i32 = 3;

/// How long a spawned or an activated pentd waits for the lock. A pentd
/// that stops gives the lock to the next one in this time.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The pause after a failed `accept(2)`, for example at the limit of file
/// descriptors, so the loop does not spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// How a pentd starts.
#[derive(Debug)]
pub(crate) enum Start {
    /// `pent daemon` by hand. It holds itself and stops on a signal. A
    /// second one gives `DaemonError::Busy`.
    Foreground,
    /// `pent daemon --spawned`, from `pent run`. It does not hold itself. It
    /// waits for the lock, and when another pentd keeps it, it stops in
    /// silence: that pentd serves.
    Spawned,
    /// The systemd user unit, with the socket from `LISTEN_FDS`. It holds
    /// itself, and it never removes the socket: systemd owns it.
    Activated(std::os::unix::net::UnixListener),
}

/// Take the listener of socket activation, when the variables of systemd
/// name this process.
///
/// # Errors
/// Returns `DaemonError::BadActivation` when the variables name this
/// process but fd 3 is not a Unix socket.
pub(crate) fn activated_listener() -> Result<Option<std::os::unix::net::UnixListener>, DaemonError>
{
    let ours = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|p| p == std::process::id());
    let one = std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    if !ours || !one {
        return Ok(None);
    }
    // pentd keeps the variables. A change of the environment in a process
    // with more than one thread is not safe, and the runtime of tokio runs
    // already. A child of pentd sees `LISTEN_PID` with the PID of pentd, not
    // its own PID, so it ignores the variables, as systemd says.

    // SAFETY: `fstat` writes only into `stat`, a valid buffer of the right
    // size, and an invalid fd gives an error, not undefined behaviour.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: see above.
    let rc = unsafe { libc::fstat(LISTEN_FDS_START, &raw mut stat) };
    if rc != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(DaemonError::BadActivation);
    }
    // systemd passes fd 3 without `FD_CLOEXEC`. Without the flag, each child
    // of pentd (the notification hook) would get the listening socket of
    // pentd.sock and could accept the connections of `pent run`.
    // SAFETY: `fcntl` with `F_GETFD` and `F_SETFD` on a fd only reads and
    // sets the flags of the fd; it has no effect on memory.
    let flags = unsafe { libc::fcntl(LISTEN_FDS_START, libc::F_GETFD) };
    // SAFETY: see above.
    if flags < 0
        || unsafe { libc::fcntl(LISTEN_FDS_START, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(DaemonError::BadActivation);
    }
    // SAFETY: systemd gave fd 3 to this process for this purpose, the check
    // above shows that it is a socket, and nothing else in pent owns it.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(LISTEN_FDS_START) };
    // A fd that is a socket but not an `AF_UNIX` listener fails here.
    if listener.local_addr().is_err() {
        return Err(DaemonError::BadActivation);
    }
    Ok(Some(listener))
}

/// The lock of pentd. The kernel ends it when the process ends.
struct Lock {
    _file: std::fs::File,
}

/// Take the lock in `path`. `Foreground` tries one time. `Spawned` and
/// `Activated` wait up to [`LOCK_WAIT`], because another pentd can stop in
/// that time. Returns `None` for a `Spawned` pentd that did not get the
/// lock: the other pentd serves.
async fn take_lock(path: &Path, start: &Start) -> Result<Option<Lock>, DaemonError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |source| DaemonError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    let deadline = Instant::now() + LOCK_WAIT;
    let waits = matches!(start, Start::Spawned | Start::Activated(_));
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if waits && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                if matches!(start, Start::Spawned) {
                    return Ok(None);
                }
                return Err(DaemonError::Busy {
                    pid: holder_pid(&mut file).await,
                });
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(io(e)),
        }
    }
    file.set_len(0).map_err(io)?;
    file.rewind().map_err(io)?;
    file.write_all(std::process::id().to_string().as_bytes())
        .map_err(io)?;
    Ok(Some(Lock { _file: file }))
}

/// The PID in the lock file of the holder. The holder writes it just after
/// it takes the lock, so the file can still be empty: read it again for a
/// short time. The PID is only for the message; an unreadable file gives
/// `None`.
async fn holder_pid(file: &mut std::fs::File) -> Option<u32> {
    for _ in 0..20 {
        let mut text = String::new();
        if file.rewind().is_ok() && file.read_to_string(&mut text).is_ok() {
            if let Ok(pid) = text.trim().parse() {
                return Some(pid);
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

/// The identity of a socket file: its device and its inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    /// The identity of the file at `path`, without a link.
    fn of(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

/// Remove the socket at `path` only when it is still the socket `id`. Thus
/// pentd never removes a socket that another process put at the path, for
/// example the socket of systemd. A failure only leaves a stale socket, and
/// the next pentd removes it.
fn remove_own_socket(path: &Path, id: FileId) {
    match FileId::of(path) {
        Ok(now) if now == id => {
            if let Err(e) = std::fs::remove_file(path) {
                tracing::debug!("cannot remove {}: {e}", path.display());
            }
        }
        Ok(_) => tracing::debug!("{} is another socket now; pentd keeps it", path.display()),
        Err(e) => tracing::debug!("cannot read {}: {e}", path.display()),
    }
}

/// Bind the socket at `path` with the mode `0600`.
///
/// The caller holds the lock, so no other pentd serves a socket at the path.
/// But systemd can listen there before its pentd starts, and systemd does
/// not hold the lock. Thus pentd removes a socket only when a connection to
/// it fails: then nobody listens, and the socket is stale.
fn bind(path: &Path) -> Result<(UnixListener, FileId), DaemonError> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    let io = |source| DaemonError::Io {
        path: path.to_path_buf(),
        source,
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(DaemonError::Listening {
                    path: path.to_path_buf(),
                });
            }
            std::fs::remove_file(path).map_err(io)?;
        }
        Ok(_) => {
            return Err(DaemonError::NotASocket {
                path: path.to_path_buf(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    let listener = UnixListener::bind(path).map_err(io)?;
    // The directory has the mode 0700, so no other user can reach the
    // socket between the bind and the chmod.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    let id = FileId::of(path).map_err(io)?;
    Ok((listener, id))
}

/// Run pentd until a signal, or until [`linger`](super::linger) after the
/// last hold.
///
/// # Errors
/// Returns the errors of the runtime directory, of the lock and of the
/// socket.
pub(crate) async fn serve(
    runtime: &RuntimeDir,
    start: Start,
    linger: Duration,
) -> Result<(), DaemonError> {
    runtime.ensure()?;
    let Some(_lock) = take_lock(&runtime.pentd_lock(), &start).await? else {
        tracing::debug!("another pentd serves; this one stops");
        return Ok(());
    };
    let socket = runtime.pentd_socket();
    let (listener, holds_itself, own_socket) = match start {
        Start::Foreground => {
            let (listener, id) = bind(&socket)?;
            (listener, true, Some(id))
        }
        Start::Spawned => match bind(&socket) {
            Ok((listener, id)) => (listener, false, Some(id)),
            // systemd listens: its pentd serves, so this one stops.
            Err(DaemonError::Listening { .. }) => {
                tracing::debug!("another process listens on the socket; this pentd stops");
                return Ok(());
            }
            Err(e) => return Err(e),
        },
        Start::Activated(listener) => {
            listener
                .set_nonblocking(true)
                .map_err(|source| DaemonError::Io {
                    path: socket.clone(),
                    source,
                })?;
            let listener = UnixListener::from_std(listener).map_err(|source| DaemonError::Io {
                path: socket.clone(),
                source,
            })?;
            (listener, true, None)
        }
    };
    tracing::info!("pentd listens on {}", socket.display());

    let result = accept_loop(&listener, holds_itself, linger).await;
    // Remove the socket before the lock ends, so the next pentd never sees
    // a socket that nobody serves. The socket of systemd stays.
    if let Some(id) = own_socket {
        remove_own_socket(&socket, id);
    }
    result
}

/// How long the writer of an ended connection may send what is left.
const WRITER_DRAIN: Duration = Duration::from_secs(5);

/// How often pentd drops the old questions of ended sessions.
const EXPIRE_EVERY: Duration = Duration::from_secs(30);

/// Accept connections until a signal, or until the linger time after the
/// last hold and the last open question.
async fn accept_loop(
    listener: &UnixListener,
    holds_itself: bool,
    linger: Duration,
) -> Result<(), DaemonError> {
    use tokio::signal::unix::{signal, SignalKind};
    let signal_err = |source| DaemonError::Io {
        path: "signal handler".into(),
        source,
    };
    let mut term = signal(SignalKind::terminate()).map_err(signal_err)?;
    let mut int = signal(SignalKind::interrupt()).map_err(signal_err)?;

    let rules = match pent_settings::RuleStore::open_default() {
        Ok(store) => Some(store),
        Err(e) => {
            tracing::warn!("pentd cannot find the rule files: {e}");
            None
        }
    };
    let hub = Hub::new(rules, classifier());
    let _notifier = NotifyTask(tokio::spawn(super::notify::run(Arc::clone(&hub))));
    let mut changes = hub.subscribe();
    let own_uid = pent_settings::current_uid();
    let mut idle_since = (!holds_itself).then(tokio::time::Instant::now);
    let mut expire = tokio::time::interval(EXPIRE_EVERY);
    let mut flush = tokio::time::interval(super::hub::FLUSH_EVERY);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let stop_at = idle_since.map(|t| t + linger);
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    // The count starts here, before the task, so the linger
                    // cannot stop pentd before the first message.
                    let live = hub.connection();
                    tokio::spawn(connection(stream, Arc::clone(&hub), own_uid, live));
                }
                Err(e) => {
                    tracing::warn!("pentd cannot accept a connection: {e}");
                    tokio::time::sleep(ACCEPT_PAUSE).await;
                }
            },
            Ok(()) = changes.changed() => {
                let idle = changes.borrow_and_update().is_idle();
                idle_since = match (idle && !holds_itself, idle_since) {
                    (true, Some(since)) => Some(since),
                    (true, None) => Some(tokio::time::Instant::now()),
                    (false, _) => None,
                };
            }
            _ = expire.tick() => hub.expire(),
            _ = flush.tick() => hub.flush_events(),
            () = sleep_until(stop_at) => {
                tracing::info!(
                    "pentd stops: no hold and no open question for {} ms",
                    linger.as_millis()
                );
                return Ok(());
            }
            _ = term.recv() => return Ok(()),
            _ = int.recv() => return Ok(()),
        }
    }
}

/// The classes of the user: the home directory, and the directories of pent
/// (config, state, runtime) also when the XDG variables move them. Returns
/// `None` when the home directory is not known.
fn classifier() -> Option<pent_profile::Classifier> {
    let Some(home) = dirs::home_dir() else {
        tracing::warn!("pentd does not know the home directory; it refuses each question");
        return None;
    };
    let mut pent_dirs = vec![RuntimeDir::from_env().path().to_path_buf()];
    if let Some(dirs) = pent_settings::PentDirs::from_env() {
        pent_dirs.push(dirs.config);
        pent_dirs.push(dirs.state);
    }
    Some(pent_profile::Classifier::new(&home, &pent_dirs))
}

/// The task of the notification hook. It stops when pentd stops.
struct NotifyTask(tokio::task::JoinHandle<()>);

impl Drop for NotifyTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sleep until `at`, or forever for `None`.
async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Return true if a peer with the user ID `peer` may talk to pentd.
const fn peer_allowed(peer: u32, own: u32) -> bool {
    peer == own
}

/// Serve one connection: a reader, and a writer task for the messages of
/// pentd.
async fn connection(stream: UnixStream, hub: Arc<Hub>, own_uid: u32, live: ConnectionGuard) {
    match stream.peer_cred() {
        Ok(cred) if peer_allowed(cred.uid(), own_uid) => {}
        Ok(cred) => {
            tracing::warn!("pentd refuses a peer with the user ID {}", cred.uid());
            return;
        }
        Err(e) => {
            tracing::warn!("pentd cannot read the credentials of a peer: {e}");
            return;
        }
    }
    let fd = stream.as_raw_fd();
    let (read, mut write) = stream.into_split();
    let (outbox, mut inbox, close) = Outbox::new();
    let mut writer = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        // The hub encodes each message; the writer only writes.
        while let Some(batch) = inbox.recv().await {
            if write.write_all(batch.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut reader = BufReader::new(read);
    let mut role = Role::Client;
    let full = loop {
        tokio::select! {
            read = read_message(&mut reader) => match read {
                Ok(Some(message)) => hub.handle(&mut role, &outbox, message).await,
                Ok(None) => break false,
                Err(e) => {
                    tracing::debug!("fd {fd}: pentd closes the connection: {e}");
                    break false;
                }
            },
            () = close.notified() => {
                tracing::debug!("fd {fd}: the client does not read; pentd closes the connection");
                break true;
            }
        }
    };
    hub.end(role, &outbox);
    drop(outbox);
    if full {
        // The writer waits on a client that does not read.
        writer.abort();
    } else if tokio::time::timeout(WRITER_DRAIN, &mut writer)
        .await
        .is_err()
    {
        // The writer sends what is left; a client that stops reading now
        // does not keep the task alive.
        writer.abort();
    }
    drop(live);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_same_user_may_talk_to_pentd() {
        assert!(peer_allowed(1000, 1000));
        assert!(!peer_allowed(0, 1000));
        assert!(!peer_allowed(1001, 1000));
    }

    #[test]
    fn bind_refuses_a_file_that_is_not_a_socket() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("pentd.sock");
        std::fs::write(&path, "x")?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = rt.block_on(async { bind(&path).map(drop) });
        assert!(matches!(result, Err(DaemonError::NotASocket { .. })));
        assert_eq!(std::fs::read_to_string(&path)?, "x");
        Ok(())
    }
}
