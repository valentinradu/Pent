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

use pent_profile::Message;
use pent_settings::RuntimeDir;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use super::{read_message, DaemonError};

/// The first fd of socket activation (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: i32 = 3;

/// How long a spawned pentd waits for the lock. A pentd that stops gives
/// the lock to the next one in this time.
const SPAWNED_LOCK_WAIT: Duration = Duration::from_secs(5);

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
    // The children of pentd must not see the variables.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    // SAFETY: `fstat` writes only into `stat`, a valid buffer of the right
    // size, and an invalid fd gives an error, not undefined behaviour.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: see above.
    let rc = unsafe { libc::fstat(LISTEN_FDS_START, &raw mut stat) };
    if rc != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
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

/// Take the lock in `path`. `Foreground` and `Activated` try one time;
/// `Spawned` waits up to [`SPAWNED_LOCK_WAIT`]. Returns `None` for a
/// `Spawned` pentd that did not get the lock.
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
    let deadline = Instant::now() + SPAWNED_LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                if matches!(start, Start::Spawned) && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                if matches!(start, Start::Spawned) {
                    return Ok(None);
                }
                let mut text = String::new();
                // The PID is only for the message; an unreadable file gives
                // the message without it.
                let pid = file
                    .read_to_string(&mut text)
                    .ok()
                    .and_then(|_| text.trim().parse().ok());
                return Err(DaemonError::Busy { pid });
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

/// Bind the socket at `path` with the mode `0600`. The caller holds the
/// lock, so a socket at the path is stale: no other pentd serves it.
fn bind(path: &Path) -> Result<(UnixListener, FileId), DaemonError> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    let io = |source| DaemonError::Io {
        path: path.to_path_buf(),
        source,
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path).map_err(io)?,
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
        Start::Spawned => {
            let (listener, id) = bind(&socket)?;
            (listener, false, Some(id))
        }
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

/// Accept connections until a signal, or until the linger time after the
/// last hold.
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

    let holds = Arc::new(watch::Sender::new(0_usize));
    let mut changes = holds.subscribe();
    let own_uid = current_uid();
    let mut idle_since = (!holds_itself).then(tokio::time::Instant::now);

    loop {
        let stop_at = idle_since.map(|t| t + linger);
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(connection(stream, Arc::clone(&holds), own_uid));
                }
                Err(e) => tracing::warn!("pentd cannot accept a connection: {e}"),
            },
            Ok(()) = changes.changed() => {
                let count = *changes.borrow_and_update();
                idle_since = (count == 0 && !holds_itself).then(tokio::time::Instant::now);
            }
            () = sleep_until(stop_at) => {
                tracing::info!("pentd stops: no hold for {} ms", linger.as_millis());
                return Ok(());
            }
            _ = term.recv() => return Ok(()),
            _ = int.recv() => return Ok(()),
        }
    }
}

/// Sleep until `at`, or forever for `None`.
async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// One hold. The count goes down when the value drops, also when the task
/// of the connection ends with an error.
struct HoldGuard(Arc<watch::Sender<usize>>);

impl HoldGuard {
    fn new(holds: Arc<watch::Sender<usize>>) -> Self {
        holds.send_modify(|n| *n = n.saturating_add(1));
        Self(holds)
    }
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// Return true if a peer with the user ID `peer` may talk to pentd.
const fn peer_allowed(peer: u32, own: u32) -> bool {
    peer == own
}

/// Serve one connection.
async fn connection(stream: UnixStream, holds: Arc<watch::Sender<usize>>, own_uid: u32) {
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
    let mut reader = BufReader::new(stream);
    let mut hold: Option<HoldGuard> = None;
    loop {
        match read_message(&mut reader).await {
            Ok(Some(Message::Hold(holder))) => {
                if hold.is_none() {
                    tracing::debug!("fd {fd}: hold {holder:?}");
                    hold = Some(HoldGuard::new(Arc::clone(&holds)));
                }
            }
            Ok(Some(message)) => {
                // Step 2.2 of PLAN.md adds the queue. Until then pentd reads
                // the other messages and does nothing with them.
                tracing::debug!("fd {fd}: no handler yet for {message:?}");
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("fd {fd}: pentd closes the connection: {e}");
                break;
            }
        }
    }
    drop(hold);
}

/// The user ID of this process.
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
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
    fn a_hold_guard_counts_up_and_down() {
        let holds = Arc::new(watch::Sender::new(0_usize));
        let a = HoldGuard::new(Arc::clone(&holds));
        let b = HoldGuard::new(Arc::clone(&holds));
        assert_eq!(*holds.borrow(), 2);
        drop(a);
        assert_eq!(*holds.borrow(), 1);
        drop(b);
        assert_eq!(*holds.borrow(), 0);
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
