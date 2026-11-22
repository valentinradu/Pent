//! The protocol of `pentd.sock`: JSON lines.
//!
//! Each line is one frame, `{"v":1,"msg":{...}}`, and ends with `\n`. The
//! decoder reads the version before the message, so a frame of a newer pent
//! gives [`ProtocolError::Version`] and not a parse error. A line has at
//! most [`MAX_LINE_LEN`] bytes.
//!
//! The decoder checks each value with the types of the rules: a path is
//! absolute and normal, a domain is valid, a wildcard does not cover a public
//! suffix, a key is a safe file name. Thus a frame cannot carry a target
//! that a rule file refuses. An unknown field is an error.
//!
//! The messages (`docs/design/pent.md`, sections 7 and 10):
//!
//! - [`Hold`]: the first message of a connection that keeps pentd alive.
//! - [`Question`]: an access that no rule answers, from `pent run` to pentd,
//!   and from pentd to `pent monitor`.
//! - [`Answer`]: the answer to a question, from `pent monitor` or
//!   `pent allow` to pentd, and from pentd to `pent run`.
//! - [`Event`]: a decision of `pent run`, for `pent denials` and for the
//!   events of a session in `pent monitor`.

use std::num::NonZeroU16;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::class::Class;
use crate::rule::{Access, Decision, DomainName, FileKind, RuleKey, RulePath, Source, Target};

/// The version of the protocol that this code speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// The longest line, in bytes, without the `\n`. A question with a long
/// path and its menu fits many times.
pub const MAX_LINE_LEN: usize = 64 * 1024;

/// An error of the codec.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The line is longer than [`MAX_LINE_LEN`].
    #[error("the line has {0} bytes; the limit is {MAX_LINE_LEN}")]
    TooLong(usize),
    /// The line holds a `\n` before its end.
    #[error("the line holds a newline before its end")]
    EmbeddedNewline,
    /// The frame has a version that this pent does not speak.
    #[error("the protocol version {0} is not known; this pent speaks version {PROTOCOL_VERSION}")]
    Version(u64),
    /// The line is not a valid frame or message.
    #[error("the line is not a valid message: {0}")]
    Json(#[from] serde_json::Error),
}

/// The number of a session: one run of `pent run`. pentd gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub u64);

/// The number of a question. pentd gives it, and `pent allow ID` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuestionId(pub u64);

/// The place of a target in the width menu of a question, from 0 (the
/// narrowest). pentd checks it against the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MenuIndex(pub u16);

/// An access that `pent run` must decide: the owned form of [`Access`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// A file access.
    File {
        /// The kind of the access.
        kind: FileKind,
        /// The path.
        path: RulePath,
    },
    /// A connection to a domain.
    Domain(DomainName),
    /// A connection to a Unix socket with a path.
    UnixSocket(RulePath),
    /// A TCP connection to a port on the loopback of the host.
    Localhost(NonZeroU16),
}

impl Request {
    /// The access, to decide it with a rule set or to classify it.
    #[must_use]
    pub fn as_access(&self) -> Access<'_> {
        match self {
            Self::File { kind, path } => Access::File { kind: *kind, path },
            Self::Domain(name) => Access::Domain(name),
            Self::UnixSocket(path) => Access::UnixSocket(path),
            Self::Localhost(port) => Access::Localhost(*port),
        }
    }
}

/// Who holds pentd with a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Hold {
    /// One run of `pent run`.
    Run {
        /// The key of the run: the file name of the root program.
        key: RuleKey,
        /// The command line, for the judge and for `pent monitor`. The
        /// program chose it, so it is untrusted text.
        command: Vec<String>,
    },
    /// `pent daemon` in the foreground.
    Daemon,
    /// The systemd user unit. It never ends its hold.
    Unit,
}

/// An access that no rule answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    /// The number of the question. `pent run` sends 0, and pentd gives the
    /// real number.
    pub id: QuestionId,
    /// The session of the access.
    pub session: SessionId,
    /// The key of the session.
    pub key: RuleKey,
    /// The program that makes the access, as text. It is untrusted.
    pub program: String,
    /// The access.
    pub request: Request,
    /// The class of the access.
    pub class: Class,
    /// The targets that an answer can name, from the narrowest to the
    /// widest.
    pub menu: Vec<Target>,
    /// When `pent run` asked.
    pub asked: SystemTime,
    /// How long the access waits for an answer.
    pub deadline: Duration,
}

/// How long an answer lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Only this run.
    Run,
    /// This run and each later run: pentd writes a rule.
    Remember,
}

/// The answer to a question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    /// The question.
    pub id: QuestionId,
    /// Allow or deny.
    pub decision: Decision,
    /// The target of the answer, as a place in the menu of the question.
    pub width: MenuIndex,
    /// How long the answer lasts.
    pub scope: Scope,
    /// Who answered.
    pub source: Source,
}

/// What decided an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    /// A flag of `pent run` (an answer in advance).
    Flag(Decision),
    /// A rule of the key.
    Rule(Decision),
    /// An answer to a question.
    Answer {
        /// The question.
        question: QuestionId,
        /// The decision of the answer.
        decision: Decision,
    },
    /// The deadline of a question: the access got the error of a refusal,
    /// and the question stays open.
    Deadline {
        /// The question.
        question: QuestionId,
    },
    /// The access was in the pent class: the program got `ENOENT`.
    Hidden,
}

/// A decision of `pent run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// The session.
    pub session: SessionId,
    /// When `pent run` decided.
    pub time: SystemTime,
    /// The program that made the access, as text. It is untrusted.
    pub program: String,
    /// The access.
    pub request: Request,
    /// What decided it.
    pub outcome: Outcome,
}

/// One message of the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    /// See [`Hold`].
    Hold(Hold),
    /// See [`Question`].
    Question(Question),
    /// See [`Answer`].
    Answer(Answer),
    /// See [`Event`].
    Event(Event),
}

/// The frame of one line, for the encoder.
#[derive(Serialize)]
struct FrameOut<'a> {
    v: u32,
    msg: &'a Message,
}

/// The frame of one line, for the decoder. The message stays raw until the
/// version is known.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameIn<'a> {
    v: u64,
    #[serde(borrow)]
    msg: &'a serde_json::value::RawValue,
}

impl Message {
    /// Encode the message as one line, with its `\n`.
    ///
    /// # Errors
    /// Returns `ProtocolError::Json` when a value cannot be JSON (a path
    /// that is not valid UTF-8), and `ProtocolError::TooLong` when the line
    /// is longer than [`MAX_LINE_LEN`].
    pub fn encode_line(&self) -> Result<String, ProtocolError> {
        let mut line = serde_json::to_string(&FrameOut {
            v: PROTOCOL_VERSION,
            msg: self,
        })?;
        if line.len() > MAX_LINE_LEN {
            return Err(ProtocolError::TooLong(line.len()));
        }
        line.push('\n');
        Ok(line)
    }

    /// Decode one line. A final `\n` (or `\r\n`) is optional.
    ///
    /// # Errors
    /// Returns `ProtocolError::TooLong` for a line above the limit,
    /// `ProtocolError::EmbeddedNewline` for a `\n` before the end,
    /// `ProtocolError::Version` for an unknown version, and
    /// `ProtocolError::Json` for a frame or a message that is not valid.
    pub fn decode_line(line: &str) -> Result<Self, ProtocolError> {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.len() > MAX_LINE_LEN {
            return Err(ProtocolError::TooLong(line.len()));
        }
        if line.contains('\n') {
            return Err(ProtocolError::EmbeddedNewline);
        }
        let frame: FrameIn<'_> = serde_json::from_str(line)?;
        if frame.v != u64::from(PROTOCOL_VERSION) {
            return Err(ProtocolError::Version(frame.v));
        }
        Ok(serde_json::from_str(frame.msg.get())?)
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // a test that reaches a branch it must not reach fails
mod tests {
    use super::*;
    use crate::class::Sensitive;
    use crate::rule::{DomainWidth, PathWidth};

    fn path(p: &str) -> RulePath {
        RulePath::new(p).unwrap_or_else(|e| panic!("{e}"))
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn question() -> Question {
        let p = path("/home/u/.cargo/registry/x");
        Question {
            id: QuestionId(7),
            session: SessionId(3),
            key: "claude".parse().unwrap_or_else(|e| panic!("{e}")),
            program: "/usr/bin/cargo \u{1b}[31m".to_string(),
            request: Request::File {
                kind: FileKind::Read,
                path: p.clone(),
            },
            class: Class::Normal,
            menu: vec![
                Target::File {
                    kind: FileKind::Read,
                    width: PathWidth::Exact(p),
                },
                Target::File {
                    kind: FileKind::Read,
                    width: PathWidth::Subtree(path("/home/u/.cargo/registry")),
                },
            ],
            asked: SystemTime::UNIX_EPOCH + Duration::new(1_795_348_800, 123),
            deadline: Duration::from_secs(120),
        }
    }

    fn all_messages() -> Vec<Message> {
        let name: DomainName = "api.example.com".parse().unwrap_or_else(|e| panic!("{e}"));
        let port = NonZeroU16::new(5432).unwrap_or(NonZeroU16::MIN);
        let mut sensitive = question();
        sensitive.class = Class::Sensitive(Sensitive::Credential);
        sensitive.request = Request::UnixSocket(path("/run/docker.sock"));
        sensitive.menu = vec![
            Target::UnixSocket(path("/run/docker.sock")),
            Target::Domain(
                DomainWidth::wildcard(name.clone(), true).unwrap_or_else(|e| panic!("{e}")),
            ),
            Target::Localhost(port),
        ];
        vec![
            Message::Hold(Hold::Run {
                key: "cargo".parse().unwrap_or_else(|e| panic!("{e}")),
                command: vec!["cargo".into(), "build".into(), "\n".into()],
            }),
            Message::Hold(Hold::Daemon),
            Message::Hold(Hold::Unit),
            Message::Question(question()),
            Message::Question(sensitive),
            Message::Answer(Answer {
                id: QuestionId(7),
                decision: Decision::Allow,
                width: MenuIndex(1),
                scope: Scope::Remember,
                source: Source::Human,
            }),
            Message::Event(Event {
                session: SessionId(3),
                time: at(5),
                program: "node".into(),
                request: Request::Domain(name),
                outcome: Outcome::Answer {
                    question: QuestionId(7),
                    decision: Decision::Deny,
                },
            }),
            Message::Event(Event {
                session: SessionId(3),
                time: at(6),
                program: "node".into(),
                request: Request::Localhost(port),
                outcome: Outcome::Deadline {
                    question: QuestionId(8),
                },
            }),
            Message::Event(Event {
                session: SessionId(3),
                time: at(7),
                program: "sh".into(),
                request: Request::File {
                    kind: FileKind::Write,
                    path: path("/home/u/.config/pent/pent.toml"),
                },
                outcome: Outcome::Hidden,
            }),
            Message::Event(Event {
                session: SessionId(3),
                time: at(8),
                program: "sh".into(),
                request: Request::Domain("x.org".parse().unwrap_or_else(|e| panic!("{e}"))),
                outcome: Outcome::Rule(Decision::Allow),
            }),
            Message::Event(Event {
                session: SessionId(3),
                time: at(9),
                program: "sh".into(),
                request: Request::Domain("y.org".parse().unwrap_or_else(|e| panic!("{e}"))),
                outcome: Outcome::Flag(Decision::Allow),
            }),
        ]
    }

    #[test]
    fn each_message_survives_a_round_trip_on_one_line() -> Result<(), ProtocolError> {
        for message in all_messages() {
            let line = message.encode_line()?;
            assert!(line.ends_with('\n'), "{line}");
            assert_eq!(line.matches('\n').count(), 1, "{line}");
            assert!(line.starts_with("{\"v\":1,"), "{line}");
            assert_eq!(Message::decode_line(&line)?, message);
            assert_eq!(Message::decode_line(line.trim_end())?, message);
        }
        Ok(())
    }

    #[test]
    fn the_form_of_a_line_is_stable() -> Result<(), ProtocolError> {
        let answer = Message::Answer(Answer {
            id: QuestionId(7),
            decision: Decision::Allow,
            width: MenuIndex(1),
            scope: Scope::Remember,
            source: Source::Human,
        });
        assert_eq!(
            answer.encode_line()?,
            "{\"v\":1,\"msg\":{\"answer\":{\"id\":7,\"decision\":\"allow\",\"width\":1,\
             \"scope\":\"remember\",\"source\":\"human\"}}}\n"
        );
        let hold = Message::Hold(Hold::Daemon);
        assert_eq!(
            hold.encode_line()?,
            "{\"v\":1,\"msg\":{\"hold\":\"daemon\"}}\n"
        );
        Ok(())
    }

    #[test]
    fn the_version_comes_before_the_message() {
        // A newer pent can send a message that this pent does not know.
        let newer = "{\"v\":2,\"msg\":{\"stream\":{\"x\":1}}}";
        assert!(matches!(
            Message::decode_line(newer),
            Err(ProtocolError::Version(2))
        ));
        assert!(matches!(
            Message::decode_line("{\"msg\":{\"hold\":\"daemon\"}}"),
            Err(ProtocolError::Json(_))
        ));
    }

    #[test]
    fn a_line_with_a_bad_value_is_refused() {
        let line = |msg: &str| format!("{{\"v\":1,\"msg\":{msg}}}");
        for bad in [
            // A relative path and a `..` component.
            r#"{"event":{"session":1,"time":{"secs_since_epoch":0,"nanos_since_epoch":0},"program":"x","request":{"unix_socket":"run/x"},"outcome":"hidden"}}"#,
            r#"{"event":{"session":1,"time":{"secs_since_epoch":0,"nanos_since_epoch":0},"program":"x","request":{"unix_socket":"/run/../x"},"outcome":"hidden"}}"#,
            // A key that is not a safe file name.
            r#"{"hold":{"run":{"key":"../x","command":[]}}}"#,
            r#"{"hold":{"run":{"key":".hidden","command":[]}}}"#,
            // Port 0, an unknown field, an unknown message.
            r#"{"event":{"session":1,"time":{"secs_since_epoch":0,"nanos_since_epoch":0},"program":"x","request":{"localhost":0},"outcome":"hidden"}}"#,
            r#"{"answer":{"id":1,"decision":"allow","width":0,"scope":"run","source":"human","extra":1}}"#,
            r#"{"grant":{"id":1}}"#,
            r#"{"answer":{"id":1,"decision":"maybe","width":0,"scope":"run","source":"human"}}"#,
        ] {
            assert!(
                matches!(
                    Message::decode_line(&line(bad)),
                    Err(ProtocolError::Json(_))
                ),
                "{bad}"
            );
        }
        let mut wide = question();
        wide.menu.clear();
        let Ok(text) = Message::Question(wide).encode_line() else {
            panic!("encode");
        };
        let text = text.replace("\"menu\":[]", "\"menu\":[{\"domain\":\"*.co.uk\"}]");
        assert!(matches!(
            Message::decode_line(&text),
            Err(ProtocolError::Json(_))
        ));
    }

    #[test]
    fn a_long_line_or_an_inner_newline_is_refused() -> Result<(), ProtocolError> {
        let long = format!(
            "{{\"v\":1,\"msg\":{{\"hold\":{{\"run\":{{\"key\":\"x\",\"command\":[\"{}\"]}}}}}}}}",
            "a".repeat(MAX_LINE_LEN)
        );
        assert!(matches!(
            Message::decode_line(&long),
            Err(ProtocolError::TooLong(_))
        ));
        let mut big = question();
        big.program = "a".repeat(MAX_LINE_LEN);
        assert!(matches!(
            Message::Question(big).encode_line(),
            Err(ProtocolError::TooLong(_))
        ));
        let line = Message::Hold(Hold::Daemon).encode_line()?;
        let two = format!("{line}{line}");
        assert!(matches!(
            Message::decode_line(&two),
            Err(ProtocolError::EmbeddedNewline)
        ));
        // A newline inside a string is escaped, so it stays on one line.
        let mut odd = question();
        odd.program = "a\nb\r\n".into();
        let line = Message::Question(odd.clone()).encode_line()?;
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(Message::decode_line(&line)?, Message::Question(odd));
        Ok(())
    }

    #[test]
    fn a_request_gives_its_access() {
        let q = question();
        let Access::File { kind, path } = q.request.as_access() else {
            panic!("a file request gives a file access");
        };
        assert_eq!(kind, FileKind::Read);
        assert_eq!(
            path.as_path(),
            std::path::Path::new("/home/u/.cargo/registry/x")
        );
    }
}
