//! The event type that all recorders emit.
//!
//! Pent writes one event as one JSON line in the raw log
//! (`~/.local/state/pent/watch/<name>/<run>.jsonl`). The user never reads the
//! raw log. The summary step reads it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The process that caused an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// The process ID.
    pub pid: u32,
    /// The short process name (`comm` on Linux, the name in the Seatbelt
    /// message on macOS). Empty when the recorder does not know it.
    pub name: String,
}

/// A filesystem operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsOp {
    /// Open for reading, or read a directory.
    Read,
    /// Open an existing file for writing, truncate it, or change its mode.
    Write,
    /// Create a file, a directory or a link.
    Create,
    /// Delete a file or a directory, or rename it away.
    Delete,
    /// Execute a file.
    Exec,
}

/// The class of a dangerous access that the watch guard blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardClass {
    /// A read of credentials (SSH keys, cloud credentials, keyrings, browser
    /// logins, password stores).
    Credential,
    /// A write that can make code run later (shell rc files,
    /// `authorized_keys`, autostart entries, systemd user units, launch
    /// agents, crontab).
    Persistence,
    /// A write to the files of pent itself (profiles, trust store, drafts).
    PentFiles,
    /// An exec of a privilege escalation tool (`sudo`, `su`, `pkexec`,
    /// `doas`).
    PrivilegeEscalation,
}

/// The result of an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "class")]
pub enum Outcome {
    /// The access went through.
    Allowed,
    /// The watch guard blocked the access.
    Blocked(GuardClass),
    /// The sandbox policy of `pent run` denied the access (or the recorder
    /// predicts that the policy denies it).
    Denied,
}

/// The protocol of a network connection through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetProtocol {
    /// SOCKS5 `CONNECT`.
    Socks5,
    /// HTTP `CONNECT`.
    HttpConnect,
}

/// One recorded access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum WatchEvent {
    /// A filesystem access. `path` is absolute and canonical where the
    /// recorder can resolve it. Recorders do not follow the last symbolic
    /// link: for a link, they emit the link path and also the target path.
    Fs {
        /// The operation.
        op: FsOp,
        /// The absolute path.
        path: PathBuf,
        /// The process.
        process: ProcessInfo,
        /// The result.
        outcome: Outcome,
    },
    /// A `connect()` to a Unix socket.
    UnixConnect {
        /// The socket path, or `@name` for an abstract socket.
        target: String,
        /// The process.
        process: ProcessInfo,
        /// The result.
        outcome: Outcome,
    },
    /// A DNS query to the proxy resolver.
    Dns {
        /// The queried name, normalized (lowercase ASCII, no trailing dot).
        name: String,
        /// The query type (`A`, `AAAA`, ...).
        qtype: String,
        /// The result.
        outcome: Outcome,
    },
    /// A TCP connection through the proxy.
    Connect {
        /// The destination host: a normalized domain name when the proxy
        /// knows it (from the request, the TLS SNI or the DNS cache), else
        /// the IP address as text.
        host: String,
        /// The destination port.
        port: u16,
        /// The proxy protocol.
        protocol: NetProtocol,
        /// The result.
        outcome: Outcome,
    },
}

impl WatchEvent {
    /// Return the outcome of the event.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        match self {
            Self::Fs { outcome, .. }
            | Self::UnixConnect { outcome, .. }
            | Self::Dns { outcome, .. }
            | Self::Connect { outcome, .. } => *outcome,
        }
    }

    /// Encode the event as one JSON line (without the newline).
    ///
    /// # Errors
    /// Returns an error if serialization fails. This does not occur for the
    /// types in this module, but `serde_json` declares the error.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Decode one JSON line.
    ///
    /// # Errors
    /// Returns an error if the line is not a valid event.
    pub fn from_json_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() -> Result<(), serde_json::Error> {
        let events = vec![
            WatchEvent::Fs {
                op: FsOp::Create,
                path: PathBuf::from("/home/u/.claude/x.json"),
                process: ProcessInfo {
                    pid: 7,
                    name: "claude".to_string(),
                },
                outcome: Outcome::Allowed,
            },
            WatchEvent::Fs {
                op: FsOp::Read,
                path: PathBuf::from("/home/u/.ssh/id_ed25519"),
                process: ProcessInfo {
                    pid: 9,
                    name: "ssh".to_string(),
                },
                outcome: Outcome::Blocked(GuardClass::Credential),
            },
            WatchEvent::Connect {
                host: "api.anthropic.com".to_string(),
                port: 443,
                protocol: NetProtocol::HttpConnect,
                outcome: Outcome::Allowed,
            },
        ];
        for e in events {
            let line = e.to_json_line()?;
            assert_eq!(WatchEvent::from_json_line(&line)?, e);
        }
        Ok(())
    }
}
