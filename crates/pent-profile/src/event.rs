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
        /// The absolute path. See [`path_json`] for the JSON form of a path
        /// that is not valid UTF-8.
        #[serde(with = "path_json")]
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

/// The JSON form of the path of a [`WatchEvent::Fs`] event.
///
/// A path that is valid UTF-8 is a JSON string, as a plain `PathBuf` is.
/// `serde_json` cannot encode a path that is not valid UTF-8, and the Linux
/// recorder reads the raw bytes of each path, so a program can make such a
/// path. Pent writes it as an object with the raw bytes
/// (`{"bytes":[47,255]}`). Thus one crafted path cannot stop the log and
/// hide the later accesses.
///
/// The decoder reads both forms, so pent also reads the logs of an earlier
/// version.
pub mod path_json {
    use std::fmt;
    use std::path::{Path, PathBuf};

    use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
    use serde::ser::SerializeMap as _;
    use serde::{Deserializer, Serializer};

    /// The field name of the raw bytes form.
    const BYTES_FIELD: &str = "bytes";

    /// Write `path` as a JSON string, or as `{"bytes":[...]}`.
    ///
    /// # Errors
    /// Returns the error of the serializer.
    pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(text) = path.to_str() {
            return serializer.serialize_str(text);
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(BYTES_FIELD, path.as_os_str().as_bytes())?;
            map.end()
        }
        // On a platform without raw path bytes, a lossy string is the only
        // form. Such a platform has no recorder yet.
        #[cfg(not(unix))]
        {
            serializer.serialize_str(&path.to_string_lossy())
        }
    }

    /// Read a path from a JSON string or from `{"bytes":[...]}`.
    ///
    /// # Errors
    /// Returns an error when the value is neither form, or when the object
    /// has no `bytes` field.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        deserializer.deserialize_any(PathVisitor)
    }

    /// The visitor of [`deserialize`].
    struct PathVisitor;

    impl<'de> Visitor<'de> for PathVisitor {
        type Value = PathBuf;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a path as a string, or an object with the field \"bytes\"")
        }

        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
            Ok(PathBuf::from(text))
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut bytes: Option<Vec<u8>> = None;
            while let Some(key) = map.next_key::<String>()? {
                if key == BYTES_FIELD {
                    bytes = Some(map.next_value()?);
                } else {
                    // An unknown field comes from a later version.
                    map.next_value::<IgnoredAny>()?;
                }
            }
            let bytes = bytes.ok_or_else(|| A::Error::missing_field(BYTES_FIELD))?;
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt as _;
                Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
            }
            #[cfg(not(unix))]
            {
                Ok(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // a test that reaches a branch it must not reach fails
mod tests {
    use super::*;
    use std::path::Path;

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

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_round_trips() -> Result<(), serde_json::Error> {
        use std::os::unix::ffi::OsStringExt as _;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/home/u/\xff\xfe/x".to_vec()));
        let event = WatchEvent::Fs {
            op: FsOp::Read,
            path,
            process: ProcessInfo {
                pid: 3,
                name: "tool".to_string(),
            },
            outcome: Outcome::Allowed,
        };
        let line = event.to_json_line()?;
        assert!(line.contains("\"bytes\""), "{line}");
        assert!(!line.contains('\n'), "{line}");
        assert_eq!(WatchEvent::from_json_line(&line)?, event);
        Ok(())
    }

    /// A log of an earlier version holds the path as a plain string.
    #[test]
    fn a_path_as_a_plain_string_still_reads() -> Result<(), serde_json::Error> {
        let line = "{\"type\":\"fs\",\"op\":\"read\",\"path\":\"/a/b\",\
                    \"process\":{\"pid\":1,\"name\":\"p\"},\"outcome\":{\"kind\":\"allowed\"}}";
        let event = WatchEvent::from_json_line(line)?;
        assert!(
            matches!(&event, WatchEvent::Fs { path, .. } if path == Path::new("/a/b")),
            "{event:?}"
        );
        Ok(())
    }

    // ========================================================================
    // The lines that the coverage run found open.
    // See docs/testing/fuzzing-and-coverage.md.
    // ========================================================================

    /// `outcome` answers for an event of each kind. The summary reads the
    /// outcome of every event, so one arm that gives the wrong value would
    /// put a blocked access in the rules.
    #[test]
    fn the_outcome_of_each_kind_of_event() {
        let process = ProcessInfo {
            pid: 1,
            name: "p".to_string(),
        };
        let events = [
            WatchEvent::Fs {
                op: FsOp::Read,
                path: PathBuf::from("/a"),
                process: process.clone(),
                outcome: Outcome::Allowed,
            },
            WatchEvent::UnixConnect {
                target: "/run/x".to_string(),
                process: process.clone(),
                outcome: Outcome::Blocked(GuardClass::Credential),
            },
            WatchEvent::Dns {
                name: "a.example".to_string(),
                qtype: "A".to_string(),
                outcome: Outcome::Denied,
            },
            WatchEvent::Connect {
                host: "a.example".to_string(),
                port: 443,
                protocol: NetProtocol::Socks5,
                outcome: Outcome::Allowed,
            },
        ];
        let outcomes: Vec<Outcome> = events.iter().map(WatchEvent::outcome).collect();
        assert_eq!(
            outcomes,
            vec![
                Outcome::Allowed,
                Outcome::Blocked(GuardClass::Credential),
                Outcome::Denied,
                Outcome::Allowed,
            ]
        );
    }

    /// A path that is neither a string nor an object gives an error that
    /// names both forms. The user sees this message when a log line is
    /// broken.
    #[test]
    fn a_path_of_another_type_names_both_forms() {
        let line = "{\"type\":\"fs\",\"op\":\"read\",\"path\":5,\
                    \"process\":{\"pid\":1,\"name\":\"p\"},\"outcome\":{\"kind\":\"allowed\"}}";
        let Err(error) = WatchEvent::from_json_line(line) else {
            panic!("a number is not a path");
        };
        let message = error.to_string();
        assert!(
            message.contains("a path as a string"),
            "the message must name the string form: {message}"
        );
        assert!(
            message.contains("bytes"),
            "the message must name the raw form: {message}"
        );
    }

    /// An object with no `bytes` field is not a path either.
    #[test]
    fn a_path_object_without_bytes_is_an_error() {
        let line = "{\"type\":\"fs\",\"op\":\"read\",\"path\":{\"other\":1},\
                    \"process\":{\"pid\":1,\"name\":\"p\"},\"outcome\":{\"kind\":\"allowed\"}}";
        let Err(error) = WatchEvent::from_json_line(line) else {
            panic!("an object with no bytes field is not a path");
        };
        assert!(
            error.to_string().contains("bytes"),
            "the message must name the field: {error}"
        );
    }
}

/// Property tests of the event line.
///
/// Pent writes one event as one JSON line, and it reads the file back from
/// its own state directory. A program with write access to that directory
/// can change a line, and the path of an event holds bytes that the
/// program chose. See `docs/testing/fuzzing-and-coverage.md`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod event_properties {
    use super::*;
    use crate::fixture::{rounds, Rng};

    /// The number of events that each property test reads by default.
    const ROUNDS: usize = 50_000;

    /// The byte strings that the generator puts in a path or a name.
    const PIECES: [&[u8]; 10] = [
        b"/home/u",
        b"/a b",
        b"\xff\xfe",
        b"\n",
        b"\r",
        b"\"",
        b"\\",
        b"\x00",
        b"\x1b[31m",
        "\u{202e}".as_bytes(),
    ];

    /// Build a byte string out of the pieces.
    fn gen_bytes(rng: &mut Rng) -> Vec<u8> {
        let parts = rng.below(5);
        let mut out = Vec::new();
        for _ in 0..parts {
            out.extend_from_slice(PIECES.get(rng.below(PIECES.len())).copied().unwrap_or(b"a"));
        }
        out
    }

    /// Build an event of each kind.
    fn gen_event(rng: &mut Rng) -> WatchEvent {
        let outcome = match rng.below(6) {
            0 => Outcome::Blocked(GuardClass::Credential),
            1 => Outcome::Blocked(GuardClass::Persistence),
            2 => Outcome::Blocked(GuardClass::PentFiles),
            3 => Outcome::Blocked(GuardClass::PrivilegeEscalation),
            4 => Outcome::Denied,
            _ => Outcome::Allowed,
        };
        let name = String::from_utf8_lossy(&gen_bytes(rng)).into_owned();
        #[allow(clippy::cast_possible_truncation, reason = "a PID fits in 32 bits")]
        let process = ProcessInfo {
            pid: rng.next_u64() as u32,
            name: name.clone(),
        };
        match rng.below(4) {
            0 => {
                use std::os::unix::ffi::OsStringExt as _;
                let op = match rng.below(5) {
                    0 => FsOp::Read,
                    1 => FsOp::Write,
                    2 => FsOp::Create,
                    3 => FsOp::Delete,
                    _ => FsOp::Exec,
                };
                WatchEvent::Fs {
                    op,
                    path: PathBuf::from(std::ffi::OsString::from_vec(gen_bytes(rng))),
                    process,
                    outcome,
                }
            }
            1 => WatchEvent::UnixConnect {
                target: name,
                process,
                outcome,
            },
            2 => WatchEvent::Dns {
                name,
                qtype: "A".to_string(),
                outcome,
            },
            _ => {
                #[allow(clippy::cast_possible_truncation, reason = "a port fits in 16 bits")]
                let port = rng.next_u64() as u16;
                WatchEvent::Connect {
                    host: name,
                    port,
                    protocol: if rng.one_in(2) {
                        NetProtocol::Socks5
                    } else {
                        NetProtocol::HttpConnect
                    },
                    outcome,
                }
            }
        }
    }

    /// One event is one line, and the line reads back as the same event.
    ///
    /// A newline inside the line would let a program with a crafted path
    /// write a second, false event into the watch log.
    #[test]
    fn one_event_is_one_line_and_reads_back() {
        let mut rng = Rng::new(0x5EED_0701);
        let total = rounds(ROUNDS);
        for _ in 0..total {
            let event = gen_event(&mut rng);
            let Ok(line) = event.to_json_line() else {
                panic!("the event {event:?} does not encode");
            };
            assert!(
                !line.contains('\n') && !line.contains('\r'),
                "the line of {event:?} holds a line break: {line:?}"
            );
            match WatchEvent::from_json_line(&line) {
                Ok(again) => assert_eq!(again, event, "the event does not round trip: {line}"),
                Err(e) => panic!("the line {line} does not parse: {e}"),
            }
        }
    }

    /// The reader must not panic for a line that a program changed, and it
    /// must give back the same event for a line that it accepts.
    #[test]
    fn a_changed_line_gives_an_error_or_the_same_event() {
        let mut rng = Rng::new(0x5EED_0702);
        let total = rounds(ROUNDS);
        let mut accepted = 0usize;
        for _ in 0..total {
            let event = gen_event(&mut rng);
            let Ok(line) = event.to_json_line() else {
                panic!("the event {event:?} does not encode");
            };
            let mut bytes = line.into_bytes();
            for _ in 0..rng.below(4) {
                let at = rng.below(bytes.len().max(1));
                if let Some(byte) = bytes.get_mut(at) {
                    #[allow(clippy::cast_possible_truncation, reason = "one byte is the goal")]
                    {
                        *byte = rng.next_u64() as u8;
                    }
                }
            }
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            let Ok(parsed) = WatchEvent::from_json_line(&text) else {
                continue;
            };
            accepted = accepted.saturating_add(1);
            let Ok(again) = parsed.to_json_line() else {
                panic!("the event {parsed:?} does not encode");
            };
            match WatchEvent::from_json_line(&again) {
                Ok(twice) => assert_eq!(twice, parsed, "the event does not round trip: {again}"),
                Err(e) => panic!("the line {again} does not parse: {e}"),
            }
        }
        assert!(
            accepted > total / 100,
            "only {accepted} of {total} changed lines parsed; the test proves little"
        );
    }
}
