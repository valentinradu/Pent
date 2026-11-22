//! The protocol of `pentd.sock`: JSON lines.
//!
//! Each line is one frame, `{"v":1,"msg":{...}}`, and ends with `\n`. The
//! decoder reads only the version first, so a frame of a newer pent gives
//! [`ProtocolError::Version`], also when the frame has new fields. A line
//! has at most [`MAX_LINE_LEN`] bytes.
//!
//! The decoder checks each value with the types of the rules: a path is
//! absolute and normal, a domain is valid, a wildcard does not cover a public
//! suffix, a key is a safe file name. Thus a frame cannot carry a target
//! that a rule file refuses. A deadline has a limit. An unknown field is an
//! error.
//!
//! The messages (`docs/design/pent.md`, sections 7 and 10):
//!
//! - [`Hold`]: the first message of a connection that keeps pentd alive.
//! - [`Ask`]: an access that no rule answers, from `pent run` to pentd.
//! - [`Question`]: an [`Ask`] with the number that pentd gives it, from
//!   pentd to `pent monitor`.
//! - [`Answer`]: the answer to a question, from `pent monitor` or
//!   `pent allow` to pentd, and from pentd to `pent run`.
//! - [`Event`]: a decision of `pent run`, for `pent denials` and for the
//!   events of a session in `pent monitor`.

use std::num::NonZeroU16;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::class::Class;
use crate::render::safe;
use crate::rule::{Access, Decision, DomainName, FileKind, RuleKey, RulePath, Source, Target};

/// The version of the protocol that this code speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// The longest line, in bytes, without the `\n`. A question with a long
/// path and its menu fits many times.
pub const MAX_LINE_LEN: usize = 64 * 1024;

/// The longest deadline of a question. The longest deadline of the design is
/// 120 s (section 7), so this limit leaves room and stays far from an
/// overflow of `Instant`.
pub const MAX_DEADLINE: Duration = Duration::from_secs(600);

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
    /// The line is not a valid frame or message. The message of the error
    /// can quote the line, so its text escapes each control character.
    #[error("the line is not a valid message: {}", safe(&.0.to_string()))]
    Json(#[from] serde_json::Error),
}

/// A deadline is longer than [`MAX_DEADLINE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the deadline of {0} ms is longer than the limit of {limit} s", limit = MAX_DEADLINE.as_secs())]
pub struct DeadlineTooLong(u64);

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

/// A time as milliseconds since 1970-01-01 UTC. A time before 1970 is
/// negative, so a host with a wrong clock can still send each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The time of `time`, in whole milliseconds. A time out of the range of
    /// `i64` gives the nearest limit.
    #[must_use]
    pub fn from_system_time(time: SystemTime) -> Self {
        let millis = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => Self(millis(after)),
            Err(before) => Self(millis(before.duration()).saturating_neg()),
        }
    }

    /// The time now.
    #[must_use]
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// The time as a `SystemTime`, or `None` when the platform cannot hold
    /// it.
    #[must_use]
    pub fn to_system_time(self) -> Option<SystemTime> {
        let offset = Duration::from_millis(self.0.unsigned_abs());
        if self.0 >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(offset)
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(offset)
        }
    }
}

/// How long an access waits for an answer: at most [`MAX_DEADLINE`], in
/// whole milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct Deadline(Duration);

impl Deadline {
    /// Check and wrap `duration`. Pent drops a fraction of a millisecond.
    ///
    /// # Errors
    /// Returns an error if `duration` is longer than [`MAX_DEADLINE`].
    pub fn new(duration: Duration) -> Result<Self, DeadlineTooLong> {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self::try_from(millis)
    }

    /// The deadline.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

impl TryFrom<u64> for Deadline {
    type Error = DeadlineTooLong;

    fn try_from(millis: u64) -> Result<Self, Self::Error> {
        let duration = Duration::from_millis(millis);
        if duration > MAX_DEADLINE {
            return Err(DeadlineTooLong(millis));
        }
        Ok(Self(duration))
    }
}

impl From<Deadline> for u64 {
    fn from(deadline: Deadline) -> Self {
        // The limit is 600,000 ms, so the value fits.
        u64::try_from(deadline.0.as_millis()).unwrap_or(u64::MAX)
    }
}

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

/// The two mappings between [`Access`] and [`Request`] are exhaustive, so a
/// new kind of access does not compile until the protocol can carry it.
impl From<Access<'_>> for Request {
    fn from(access: Access<'_>) -> Self {
        match access {
            Access::File { kind, path } => Self::File {
                kind,
                path: path.clone(),
            },
            Access::Domain(name) => Self::Domain(name.clone()),
            Access::UnixSocket(path) => Self::UnixSocket(path.clone()),
            Access::Localhost(port) => Self::Localhost(port),
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

/// An access that no rule answers, as `pent run` sends it. It has no
/// number: pentd gives the number in a [`Question`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ask {
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
    pub asked: Timestamp,
    /// How long the access waits for an answer.
    pub deadline: Deadline,
}

/// An [`Ask`] with the number that pentd gave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    /// The number of the question.
    pub id: QuestionId,
    /// The access that waits.
    pub ask: Ask,
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
pub enum DecidedBy {
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
    pub time: Timestamp,
    /// The program that made the access, as text. It is untrusted.
    pub program: String,
    /// The access.
    pub request: Request,
    /// What decided it.
    pub decided_by: DecidedBy,
}

/// One message of the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    /// See [`Hold`].
    Hold(Hold),
    /// See [`Ask`].
    Ask(Ask),
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

/// Only the version of a frame. This parse ignores each other field, so a
/// frame of a newer version with new fields still gives its version.
#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

/// The frame of one line of this version, for the decoder.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameIn {
    /// The decoder read the version already. The field only keeps `v` out
    /// of the unknown fields.
    #[serde(rename = "v")]
    _version: u64,
    msg: Message,
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
        let VersionOnly { v } = serde_json::from_str(line)?;
        if v != u64::from(PROTOCOL_VERSION) {
            return Err(ProtocolError::Version(v));
        }
        let frame: FrameIn = serde_json::from_str(line)?;
        Ok(frame.msg)
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

    fn deadline(secs: u64) -> Deadline {
        Deadline::new(Duration::from_secs(secs)).unwrap_or_else(|e| panic!("{e}"))
    }

    fn ask() -> Ask {
        let p = path("/home/u/.cargo/registry/x");
        Ask {
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
            asked: Timestamp(1_795_348_800_123),
            deadline: deadline(120),
        }
    }

    fn event(time: i64, request: Request, decided_by: DecidedBy) -> Message {
        Message::Event(Event {
            session: SessionId(3),
            time: Timestamp(time),
            program: "node".into(),
            request,
            decided_by,
        })
    }

    fn all_messages() -> Vec<Message> {
        let name: DomainName = "api.example.com".parse().unwrap_or_else(|e| panic!("{e}"));
        let port = NonZeroU16::new(5432).unwrap_or(NonZeroU16::MIN);
        let mut sensitive = ask();
        sensitive.class = Class::Sensitive(Sensitive::Credential);
        sensitive.request = Request::UnixSocket(path("/run/docker.sock"));
        sensitive.menu = vec![
            Target::UnixSocket(path("/run/docker.sock")),
            Target::Domain(
                DomainWidth::wildcard(name.clone(), true).unwrap_or_else(|e| panic!("{e}")),
            ),
            Target::Localhost(port),
        ];
        let domain =
            |s: &str| -> Request { Request::Domain(s.parse().unwrap_or_else(|e| panic!("{e}"))) };
        vec![
            Message::Hold(Hold::Run {
                key: "cargo".parse().unwrap_or_else(|e| panic!("{e}")),
                command: vec!["cargo".into(), "build".into(), "\n".into()],
            }),
            Message::Hold(Hold::Daemon),
            Message::Hold(Hold::Unit),
            Message::Ask(ask()),
            Message::Question(Question {
                id: QuestionId(0),
                ask: sensitive,
            }),
            Message::Answer(Answer {
                id: QuestionId(7),
                decision: Decision::Allow,
                width: MenuIndex(1),
                scope: Scope::Remember,
                source: Source::Human,
            }),
            event(
                5,
                Request::Domain(name),
                DecidedBy::Answer {
                    question: QuestionId(7),
                    decision: Decision::Deny,
                },
            ),
            event(
                -6,
                Request::Localhost(port),
                DecidedBy::Deadline {
                    question: QuestionId(8),
                },
            ),
            event(
                7,
                Request::File {
                    kind: FileKind::Write,
                    path: path("/home/u/.config/pent/pent.toml"),
                },
                DecidedBy::Hidden,
            ),
            event(8, domain("x.org"), DecidedBy::Rule(Decision::Allow)),
            event(9, domain("y.org"), DecidedBy::Flag(Decision::Allow)),
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
        let line = Message::Ask(ask()).encode_line()?;
        assert!(line.contains("\"asked\":1795348800123,"), "{line}");
        assert!(line.contains("\"deadline\":120000}"), "{line}");
        Ok(())
    }

    #[test]
    fn the_version_comes_before_the_frame_and_the_message() {
        // A newer pent can send a message that this pent does not know, a
        // new field in the frame, or no `msg`.
        for newer in [
            "{\"v\":2,\"msg\":{\"stream\":{\"x\":1}}}",
            "{\"v\":2,\"id\":5,\"msg\":{\"hold\":\"daemon\"}}",
            "{\"v\":2,\"body\":[1,2]}",
        ] {
            assert!(
                matches!(Message::decode_line(newer), Err(ProtocolError::Version(2))),
                "{newer}"
            );
        }
        for bad in [
            "{\"msg\":{\"hold\":\"daemon\"}}",
            "{\"v\":1,\"id\":5,\"msg\":{\"hold\":\"daemon\"}}",
            "{\"v\":1}",
            "[1]",
        ] {
            assert!(
                matches!(Message::decode_line(bad), Err(ProtocolError::Json(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_line_with_a_bad_value_is_refused() {
        let line = |msg: &str| format!("{{\"v\":1,\"msg\":{msg}}}");
        let event = |request: &str| {
            line(&format!(
                r#"{{"event":{{"session":1,"time":0,"program":"x","request":{request},"decided_by":"hidden"}}}}"#
            ))
        };
        let mut bad = vec![
            // A relative path, a `..` component and a NUL byte.
            event(r#"{"unix_socket":"run/x"}"#),
            event(r#"{"unix_socket":"/run/../x"}"#),
            event(r#"{"unix_socket":"/run/x\u0000y"}"#),
            // Port 0.
            event(r#"{"localhost":0}"#),
            // A key that is not a safe file name.
            line(r#"{"hold":{"run":{"key":"../x","command":[]}}}"#),
            line(r#"{"hold":{"run":{"key":".hidden","command":[]}}}"#),
            // An unknown field, an unknown message, an unknown value.
            line(
                r#"{"answer":{"id":1,"decision":"allow","width":0,"scope":"run","source":"human","extra":1}}"#,
            ),
            line(r#"{"grant":{"id":1}}"#),
            line(
                r#"{"answer":{"id":1,"decision":"maybe","width":0,"scope":"run","source":"human"}}"#,
            ),
        ];
        // A menu entry with a wildcard at a public suffix, with an unknown
        // field, and a deadline above the limit.
        let Ok(text) = Message::Ask(Ask {
            menu: Vec::new(),
            ..ask()
        })
        .encode_line() else {
            panic!("encode");
        };
        for menu in [
            r#"[{"domain":"*.co.uk"}]"#,
            r#"[{"file":{"kind":"read","width":{"exact":"/x"},"recursive":true}}]"#,
        ] {
            bad.push(text.replace("\"menu\":[]", &format!("\"menu\":{menu}")));
        }
        bad.push(text.replace("\"deadline\":120000", "\"deadline\":18446744073709551615"));
        bad.push(text.replace("\"deadline\":120000", "\"deadline\":600001"));
        for line in &bad {
            assert!(
                matches!(Message::decode_line(line), Err(ProtocolError::Json(_))),
                "{line}"
            );
        }
        // The limit itself is valid.
        let at_limit = text.replace("\"deadline\":120000", "\"deadline\":600000");
        assert!(Message::decode_line(&at_limit).is_ok(), "{at_limit}");
    }

    #[test]
    fn the_text_of_an_error_escapes_control_characters() {
        let line = "{\"v\":1,\"msg\":{\"\\u001b]0;pwned\\u0007\":{}}}";
        let Err(e) = Message::decode_line(line) else {
            panic!("the line must be refused");
        };
        let text = e.to_string();
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(text.contains("\\u{1b}]0;pwned\\u{7}"), "{text}");
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
        let mut big = ask();
        big.program = "a".repeat(MAX_LINE_LEN);
        assert!(matches!(
            Message::Ask(big).encode_line(),
            Err(ProtocolError::TooLong(_))
        ));
        let line = Message::Hold(Hold::Daemon).encode_line()?;
        let two = format!("{line}{line}");
        assert!(matches!(
            Message::decode_line(&two),
            Err(ProtocolError::EmbeddedNewline)
        ));
        // The encoder escapes a newline inside a string, so the message
        // stays on one line.
        let mut odd = ask();
        odd.program = "a\nb\r\n".into();
        let line = Message::Ask(odd.clone()).encode_line()?;
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(Message::decode_line(&line)?, Message::Ask(odd));
        Ok(())
    }

    #[test]
    fn a_time_before_1970_is_negative_and_survives() {
        let before = SystemTime::UNIX_EPOCH - Duration::from_millis(1500);
        let t = Timestamp::from_system_time(before);
        assert_eq!(t, Timestamp(-1500));
        assert_eq!(t.to_system_time(), Some(before));
        let after = SystemTime::UNIX_EPOCH + Duration::new(5, 999_999);
        assert_eq!(Timestamp::from_system_time(after), Timestamp(5000));
        assert!(Timestamp::now().0 > 0);
    }

    #[test]
    fn a_deadline_has_a_limit() {
        assert_eq!(deadline(120).duration(), Duration::from_secs(120));
        assert_eq!(
            Deadline::new(MAX_DEADLINE).map(Deadline::duration),
            Ok(MAX_DEADLINE)
        );
        assert!(Deadline::new(MAX_DEADLINE + Duration::from_millis(1)).is_err());
        assert!(Deadline::new(Duration::MAX).is_err());
    }

    #[test]
    fn a_request_and_an_access_map_both_ways() {
        let port = NonZeroU16::MIN;
        let name: DomainName = "a.example".parse().unwrap_or_else(|e| panic!("{e}"));
        let requests = [
            ask().request,
            Request::Domain(name),
            Request::UnixSocket(path("/run/a")),
            Request::Localhost(port),
        ];
        for request in requests {
            assert_eq!(Request::from(request.as_access()), request);
        }
    }
}
