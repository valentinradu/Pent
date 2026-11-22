//! pentd: one daemon for each user, with the queue of questions.
//!
//! See `docs/design/pent.md`, section 10. This module has:
//!
//! - [`server`]: the daemon itself. `pent daemon` runs it.
//! - [`client`]: the connection of `pent run`, which holds pentd and starts
//!   it when no pentd runs.
//!
//! A hold is a live connection. pentd stops [`linger`] after the last hold
//! ends. `pent daemon` in the foreground and the systemd unit hold pentd
//! themselves, so they never stop for this reason.

pub(crate) mod client;
pub(crate) mod server;

use std::path::PathBuf;
use std::time::Duration;

use pent_profile::{Message, ProtocolError, MAX_LINE_LEN};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _};

use crate::cli::DaemonArgs;
use crate::error::CliError;

/// The variable that sets the linger time in milliseconds. The tests use it
/// to make pentd stop at once.
pub(crate) const LINGER_VAR: &str = "PENTD_LINGER_MS";

/// The linger time when [`LINGER_VAR`] is not set.
const DEFAULT_LINGER: Duration = Duration::from_secs(5);

/// An error of pentd or of its client.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DaemonError {
    /// The runtime directory is not usable.
    #[error(transparent)]
    RuntimeDir(#[from] pent_settings::RuntimeDirError),

    /// An I/O operation on a file of pentd failed.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },

    /// Another pentd holds the lock.
    #[error(
        "pentd runs already{}",
        pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
    )]
    Busy {
        /// The process that holds the lock, when the lock file names it.
        pid: Option<u32>,
    },

    /// Something that is not a socket is at the path of the socket. pentd
    /// does not remove it.
    #[error("{} exists and is not a socket; remove it to start pentd", path.display())]
    NotASocket {
        /// The path of the socket.
        path: PathBuf,
    },

    /// Another process listens on the path of the socket, for example
    /// systemd with `pentd.socket` before its pentd starts.
    #[error(
        "another process listens on {}; with pentd.socket enabled, systemd \
         starts pentd (systemctl --user status pentd.socket)",
        path.display()
    )]
    Listening {
        /// The path of the socket.
        path: PathBuf,
    },

    /// The variables of socket activation are set, but fd 3 is not a socket.
    #[error("LISTEN_FDS is set, but fd 3 is not a listening Unix socket")]
    BadActivation,

    /// The client could not reach pentd, also after a start.
    #[error("cannot reach pentd at {}: {source}", path.display())]
    Unreachable {
        /// The path of the socket.
        path: PathBuf,
        /// The last error of `connect(2)`.
        source: std::io::Error,
    },

    /// A message could not be encoded or decoded.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// How long pentd waits after the last hold before it stops.
pub(crate) fn linger() -> Duration {
    std::env::var(LINGER_VAR)
        .ok()
        .and_then(|v| v.parse().ok())
        .map_or(DEFAULT_LINGER, Duration::from_millis)
}

/// `pent daemon`: run pentd.
pub(crate) async fn daemon(args: &DaemonArgs) -> Result<(), CliError> {
    let start = if let Some(listener) = server::activated_listener()? {
        server::Start::Activated(listener)
    } else if args.spawned {
        server::Start::Spawned
    } else {
        server::Start::Foreground
    };
    let runtime = pent_settings::RuntimeDir::from_env();
    server::serve(&runtime, start, linger()).await?;
    Ok(())
}

/// A line that a reader refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LineError {
    /// The read failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The line is longer than the limit and has no newline in it.
    #[error("the line has more than {MAX_LINE_LEN} bytes")]
    TooLong,
    /// The line is not valid UTF-8.
    #[error("the line is not valid UTF-8")]
    NotUtf8,
    /// The line is not a valid message.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Read one message. Returns `None` at the end of the stream.
///
/// The reader stops at [`MAX_LINE_LEN`] bytes and the newline, so a peer
/// that sends no newline cannot make the reader buffer without a limit.
pub(crate) async fn read_message<R>(reader: &mut R) -> Result<Option<Message>, LineError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    // The limit counts the newline too: `MAX_LINE_LEN` bytes and `\r\n`.
    let limit = u64::try_from(MAX_LINE_LEN.saturating_add(2)).unwrap_or(u64::MAX);
    let read = (&mut *reader)
        .take(limit)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') && read >= usize::try_from(limit).unwrap_or(usize::MAX) {
        return Err(LineError::TooLong);
    }
    let text = std::str::from_utf8(&line).map_err(|_| LineError::NotUtf8)?;
    Ok(Some(Message::decode_line(text)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pent_profile::Hold;

    #[tokio::test]
    async fn the_reader_gives_each_message_and_the_end() -> Result<(), LineError> {
        let line = Message::Hold(Hold::Daemon).encode_line()?;
        let text = format!("{line}{line}");
        let mut reader = tokio::io::BufReader::new(text.as_bytes());
        assert_eq!(
            read_message(&mut reader).await?,
            Some(Message::Hold(Hold::Daemon))
        );
        assert_eq!(
            read_message(&mut reader).await?,
            Some(Message::Hold(Hold::Daemon))
        );
        assert_eq!(read_message(&mut reader).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn the_reader_stops_a_line_with_no_newline_at_the_limit() {
        let endless = vec![b'a'; MAX_LINE_LEN * 3];
        let mut reader = tokio::io::BufReader::new(endless.as_slice());
        assert!(matches!(
            read_message(&mut reader).await,
            Err(LineError::TooLong)
        ));
        let bad = b"\xff\xfe\n".to_vec();
        let mut reader = tokio::io::BufReader::new(bad.as_slice());
        assert!(matches!(
            read_message(&mut reader).await,
            Err(LineError::NotUtf8)
        ));
    }
}
