//! One request to pentd from a command of the CLI: `pent allow`,
//! `pent deny`, `pent questions`, `pent denials` and `pent rules forget`.
//!
//! A [`Call`] connects without a hold and never starts pentd: without
//! pentd no question waits, and pentd alone writes the rules. Each read
//! waits at most [`REPLY_WAIT`], so a pentd that does not answer cannot
//! stop a script.

use std::path::Path;
use std::time::Duration;

use pent_profile::Message;
use pent_settings::RuntimeDir;
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use super::{read_message, DaemonError};

/// How long a call waits for each message of pentd, when [`REPLY_WAIT_VAR`]
/// is not set. A forget waits for a write of the rule file, so the time
/// leaves room for a slow disk.
const REPLY_WAIT: Duration = Duration::from_secs(10);

/// The variable that sets the reply wait in milliseconds. The tests use it
/// to see the limit without a wait of 10 s.
pub(crate) const REPLY_WAIT_VAR: &str = "PENT_REPLY_WAIT_MS";

/// How long a call waits for each message of pentd.
fn reply_wait() -> Duration {
    std::env::var(REPLY_WAIT_VAR)
        .ok()
        .and_then(|v| v.parse().ok())
        .map_or(REPLY_WAIT, Duration::from_millis)
}

/// One connection to pentd for one request.
#[derive(Debug)]
pub(crate) struct Call {
    reader: BufReader<OwnedReadHalf>,
    /// The write side stays open until the call drops: pentd closes a
    /// connection when its peer closes.
    _write: OwnedWriteHalf,
}

impl Call {
    /// Connect to pentd and send `message`.
    ///
    /// # Errors
    /// Returns `DaemonError::NotRunning` when no pentd listens, and
    /// `DaemonError::Io` or `DaemonError::Protocol` when the send fails.
    pub(crate) async fn send(runtime: &RuntimeDir, message: &Message) -> Result<Self, DaemonError> {
        let socket = runtime.pentd_socket();
        let stream = connect(&socket).await?;
        let (read, mut write) = stream.into_split();
        let line = message.encode_line()?;
        write
            .write_all(line.as_bytes())
            .await
            .map_err(|source| DaemonError::Io {
                path: socket.clone(),
                source,
            })?;
        Ok(Self {
            reader: BufReader::new(read),
            _write: write,
        })
    }

    /// The next message of pentd.
    ///
    /// # Errors
    /// Returns `DaemonError::NoReply` after the reply wait (default
    /// [`REPLY_WAIT`]) with no message,
    /// `DaemonError::Closed` when pentd closed the connection, and
    /// `DaemonError::Read` for a line that is not valid.
    pub(crate) async fn next(&mut self) -> Result<Message, DaemonError> {
        match tokio::time::timeout(reply_wait(), read_message(&mut self.reader)).await {
            Err(_) => Err(DaemonError::NoReply),
            Ok(Ok(Some(message))) => Ok(message),
            Ok(Ok(None)) => Err(DaemonError::Closed),
            Ok(Err(e)) => Err(DaemonError::Read(e)),
        }
    }
}

/// Connect to `socket`. A missing socket and a refused connection mean
/// that no pentd runs.
pub(crate) async fn connect(socket: &Path) -> Result<UnixStream, DaemonError> {
    UnixStream::connect(socket).await.map_err(|source| {
        if matches!(
            source.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ) {
            DaemonError::NotRunning {
                path: socket.to_path_buf(),
            }
        } else {
            DaemonError::Io {
                path: socket.to_path_buf(),
                source,
            }
        }
    })
}
