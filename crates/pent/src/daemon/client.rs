//! The client side of pentd for `pent run`.
//!
//! `pent run` holds pentd for the whole run. When no pentd answers, it
//! starts one (`pent daemon --spawned`) and connects again. When the
//! connection ends during the run, for example because a pentd stopped at
//! the moment of the connect, the client connects again, a few times. A
//! connection that lasts [`STABLE`] resets the count, so a long run keeps
//! its hold over each restart of pentd.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pent_profile::{Hold, Message};
use pent_settings::RuntimeDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use super::DaemonError;

/// How long the client waits for a pentd that it started.
const START_WAIT: Duration = Duration::from_secs(3);

/// The pause between two tries to connect.
const RETRY_PAUSE: Duration = Duration::from_millis(25);

/// How many times in a row the client holds again after a lost connection.
const MAX_RECONNECTS: u32 = 3;

/// A connection that lasts this long resets the count of reconnects.
const STABLE: Duration = Duration::from_secs(30);

/// A hold on pentd. The hold ends when the value drops.
#[derive(Debug)]
pub(crate) struct HoldHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HoldHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Hold pentd with `hold`, and start pentd when no pentd answers.
///
/// # Errors
/// Returns the errors of the runtime directory, `DaemonError::Unreachable`
/// when no pentd answers after a start, and the errors of the first write.
pub(crate) async fn hold(runtime: &RuntimeDir, hold: Hold) -> Result<HoldHandle, DaemonError> {
    let socket = runtime.pentd_socket();
    let line = Message::Hold(hold).encode_line()?;
    let stream = connect_or_start(runtime, &socket, &line).await?;
    let task = tokio::spawn(keep(runtime.clone(), socket, line, stream));
    Ok(HoldHandle { task })
}

/// Keep the hold: wait for the end of the connection, then hold again.
async fn keep(runtime: RuntimeDir, socket: PathBuf, line: String, mut stream: UnixStream) {
    let mut reconnects = 0_u32;
    loop {
        let since = tokio::time::Instant::now();
        // pentd sends nothing on a hold yet, so a read returns only at the
        // end of the connection. Any byte that comes is not used.
        let mut buf = [0_u8; 256];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        if since.elapsed() >= STABLE {
            reconnects = 0;
        }
        if reconnects >= MAX_RECONNECTS {
            tracing::debug!("the hold on pentd ended; no more tries");
            return;
        }
        reconnects = reconnects.saturating_add(1);
        match connect_or_start(&runtime, &socket, &line).await {
            Ok(next) => stream = next,
            Err(e) => {
                tracing::debug!("cannot hold pentd again: {e}");
                return;
            }
        }
    }
}

/// Connect and send the hold. When no pentd answers, start one and try
/// again until [`START_WAIT`]. When the started pentd stops before a
/// connection works, the client stops at once: pentd cannot start (for
/// example, a file is at the path of the socket), and the run must not wait
/// for nothing.
async fn connect_or_start(
    runtime: &RuntimeDir,
    socket: &Path,
    line: &str,
) -> Result<UnixStream, DaemonError> {
    if let Ok(stream) = connect_and_send(socket, line).await {
        return Ok(stream);
    }
    runtime.ensure()?;
    let started = start_pentd(socket)?;
    let deadline = tokio::time::Instant::now() + START_WAIT;
    loop {
        // Read the end of pentd before the connect, so a pentd that served
        // and then stopped still gets its last try.
        let ended = started.try_recv().is_ok();
        match connect_and_send(socket, line).await {
            Ok(stream) => return Ok(stream),
            Err(source) if ended || tokio::time::Instant::now() >= deadline => {
                return Err(DaemonError::Unreachable {
                    path: socket.to_path_buf(),
                    source,
                })
            }
            Err(_) => tokio::time::sleep(RETRY_PAUSE).await,
        }
    }
}

/// Connect to `socket` and send `line`.
async fn connect_and_send(socket: &Path, line: &str) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(line.as_bytes()).await?;
    Ok(stream)
}

/// Start `pent daemon --spawned` in its own process group, with no
/// terminal, so a Ctrl-C in the terminal of `pent run` does not stop it.
/// The receiver gets a message when that pentd ends.
fn start_pentd(socket: &Path) -> Result<std::sync::mpsc::Receiver<()>, DaemonError> {
    use std::os::unix::process::CommandExt as _;
    let io = |source| DaemonError::Io {
        path: socket.to_path_buf(),
        source,
    };
    let exe = std::env::current_exe().map_err(io)?;
    let mut child = std::process::Command::new(exe)
        .args(["daemon", "--spawned"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(io)?;
    // Reap the child when it ends, so it does not stay as a zombie while
    // `pent run` runs. pentd normally ends after `pent run`.
    let (ended, ended_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Err(e) = child.wait() {
            tracing::debug!("cannot wait for pentd: {e}");
        }
        // The client can be gone already; then nobody needs the message.
        let _ = ended.send(());
    });
    Ok(ended_rx)
}
