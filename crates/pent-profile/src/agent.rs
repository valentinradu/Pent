//! The protocol of `agent.sock`: JSON lines between the agent in the
//! sandbox and `pent run` (`docs/design/pent.md`, section 9).
//!
//! Each line is one frame, `{"v":1,"msg":{...}}`, and ends with `\n`, as on
//! `pentd.sock`. A line has at most [`MAX_LINE_LEN`] bytes. The agent sends
//! an [`AgentRequest`], and `pent run` answers with [`AgentReply`] lines.
//!
//! The agent can only read the refusals of its run, deny a question of its
//! run, and send a question of its run up to the human. No request allows
//! an access: [`AgentRequest`] has no such variant, so a line with any other
//! message does not decode.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::protocol::{
    DecidedBy, ProtocolError, QuestionId, RejectReason, Request, Skip, Timestamp, MAX_LINE_LEN,
};

/// The version of the protocol of `agent.sock`.
pub const AGENT_PROTOCOL_VERSION: u32 = 1;

/// A request of the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentRequest {
    /// Send each refusal of the run, then [`AgentReply::End`].
    Denials,
    /// Deny one open question of the run, for this run and for the exact
    /// target.
    Deny(QuestionId),
    /// Send one open question of the run up to the human, with a reason.
    Skip(Skip),
}

/// One refusal of the run. The same access of the same program is one
/// entry, with a count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDenial {
    /// The program that made the access, as text. It is untrusted.
    pub program: String,
    /// The access.
    pub request: Request,
    /// What refused it the last time. A deadline names its question.
    pub decided_by: DecidedBy,
    /// When the last refusal came.
    pub last: Timestamp,
    /// How many times the access got a refusal.
    pub count: u64,
}

/// Why `pent run` could not do a request of the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentFailure {
    /// pentd is not reachable, so no question is open.
    NoPentd,
    /// pentd refused the request (for example, no open question of the run
    /// has this code).
    Rejected(RejectReason),
    /// pentd gave no reply in time.
    NoReply,
}

impl std::fmt::Display for AgentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPentd => f.write_str("pentd does not run, so no question is open"),
            Self::Rejected(reason) => write!(f, "pentd refused the request: {reason}"),
            Self::NoReply => f.write_str("pentd gave no reply in time"),
        }
    }
}

/// A reply of `pent run` to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentReply {
    /// One refusal of the run.
    Denial(AgentDenial),
    /// The end of the refusals. `dropped` older refusals left the list, so
    /// it is not complete when the number is above zero.
    End {
        /// The number of refusals that left the list.
        dropped: u64,
    },
    /// pentd did the request.
    Done,
    /// The request failed.
    Failed(AgentFailure),
}

/// The frame of one line, for the encoder.
#[derive(Serialize)]
struct FrameOut<'a, T> {
    v: u32,
    msg: &'a T,
}

/// Only the version of a frame.
#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

/// The frame of one line of this version, for the decoder.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameIn<T> {
    #[serde(rename = "v")]
    _version: u64,
    msg: T,
}

fn encode<T: Serialize>(msg: &T) -> Result<String, ProtocolError> {
    let mut line = serde_json::to_string(&FrameOut {
        v: AGENT_PROTOCOL_VERSION,
        msg,
    })?;
    if line.len() > MAX_LINE_LEN {
        return Err(ProtocolError::TooLong(line.len()));
    }
    line.push('\n');
    Ok(line)
}

fn decode<T: DeserializeOwned>(line: &str) -> Result<T, ProtocolError> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.len() > MAX_LINE_LEN {
        return Err(ProtocolError::TooLong(line.len()));
    }
    if line.contains('\n') {
        return Err(ProtocolError::EmbeddedNewline);
    }
    let VersionOnly { v } = serde_json::from_str(line)?;
    if v != u64::from(AGENT_PROTOCOL_VERSION) {
        return Err(ProtocolError::Version(v));
    }
    let frame: FrameIn<T> = serde_json::from_str(line)?;
    Ok(frame.msg)
}

impl AgentRequest {
    /// Encode the request as one line, with its `\n`.
    ///
    /// # Errors
    /// Returns `ProtocolError::TooLong` when the line is longer than
    /// [`MAX_LINE_LEN`].
    pub fn encode_line(&self) -> Result<String, ProtocolError> {
        encode(self)
    }

    /// Decode one line. A final `\n` (or `\r\n`) is optional.
    ///
    /// # Errors
    /// Returns a `ProtocolError` for a line that is not one request of
    /// this version: also for each message of `pentd.sock`.
    pub fn decode_line(line: &str) -> Result<Self, ProtocolError> {
        decode(line)
    }
}

impl AgentReply {
    /// Encode the reply as one line, with its `\n`.
    ///
    /// # Errors
    /// Returns `ProtocolError::Json` for a value that cannot be JSON, and
    /// `ProtocolError::TooLong` when the line is longer than
    /// [`MAX_LINE_LEN`].
    pub fn encode_line(&self) -> Result<String, ProtocolError> {
        encode(self)
    }

    /// Decode one line. A final `\n` (or `\r\n`) is optional.
    ///
    /// # Errors
    /// Returns a `ProtocolError` for a line that is not one reply of this
    /// version.
    pub fn decode_line(line: &str) -> Result<Self, ProtocolError> {
        decode(line)
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // a test that reaches a branch it must not reach fails
mod tests {
    use super::*;
    use crate::protocol::{AgentReason, Answer, MenuIndex, Message, Scope};
    use crate::rule::{Decision, FileKind, RulePath, Source};

    fn id(text: &str) -> QuestionId {
        text.parse().unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn each_request_and_reply_goes_through_one_line() {
        let reason = AgentReason::try_from("the build needs it".to_string())
            .unwrap_or_else(|e| panic!("{e}"));
        let requests = [
            AgentRequest::Denials,
            AgentRequest::Deny(id("k3m9tx")),
            AgentRequest::Skip(Skip {
                id: id("k3m9tx"),
                reason,
            }),
        ];
        for request in requests {
            let line = request.encode_line().unwrap_or_else(|e| panic!("{e}"));
            assert!(line.ends_with('\n') && !line.trim_end().contains('\n'));
            assert_eq!(AgentRequest::decode_line(&line).ok(), Some(request));
        }
        let denial = AgentDenial {
            program: "cat".to_string(),
            request: Request::File {
                kind: FileKind::Read,
                path: RulePath::new("/home/u/x").unwrap_or_else(|e| panic!("{e}")),
            },
            decided_by: DecidedBy::Deadline {
                question: id("k3m9tx"),
            },
            last: Timestamp(5),
            count: 3,
        };
        let replies = [
            AgentReply::Denial(denial),
            AgentReply::End { dropped: 2 },
            AgentReply::Done,
            AgentReply::Failed(AgentFailure::Rejected(RejectReason::UnknownQuestion)),
        ];
        for reply in replies {
            let line = reply.encode_line().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(AgentReply::decode_line(&line).ok(), Some(reply));
        }
    }

    /// No line of `pentd.sock` is a request of the agent that changes a
    /// question: an allow cannot reach pentd through `agent.sock`. Only
    /// `Message::Denials(None)` reads as the request `Denials`, which only
    /// reads the refusals of the run.
    #[test]
    fn no_message_of_pentd_decodes_as_a_request_of_the_agent() {
        let answer = |decision| {
            Message::Answer(Answer {
                id: id("k3m9tx"),
                decision,
                width: MenuIndex(0),
                scope: Scope::Remember,
                source: Source::Human,
            })
        };
        for message in [
            answer(Decision::Allow),
            answer(Decision::Deny),
            Message::Watch,
            Message::Questions,
            Message::Denials(Some("k3m9tx".parse().unwrap_or_else(|e| panic!("{e}")))),
            Message::AgentDeny(id("k3m9tx")),
        ] {
            let line = message.encode_line().unwrap_or_else(|e| panic!("{e}"));
            assert!(AgentRequest::decode_line(&line).is_err(), "{line}");
        }
        let line = Message::Denials(None)
            .encode_line()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            AgentRequest::decode_line(&line).ok(),
            Some(AgentRequest::Denials)
        );
        // A request with an extra field or an unknown verb fails too.
        for line in [
            r#"{"v":1,"msg":"allow"}"#,
            r#"{"v":1,"msg":{"allow":"k3m9tx"}}"#,
            r#"{"v":1,"msg":{"deny":"k3m9tx"},"allow":true}"#,
            r#"{"v":2,"msg":"denials"}"#,
        ] {
            assert!(AgentRequest::decode_line(line).is_err(), "{line}");
        }
    }

    #[test]
    fn a_reason_is_not_empty_and_has_a_limit() {
        assert!(AgentReason::try_from(String::new()).is_err());
        let long = "x".repeat(crate::protocol::MAX_REASON_LEN + 1);
        assert!(AgentReason::try_from(long).is_err());
        let line = format!(
            r#"{{"v":1,"msg":{{"skip":{{"id":"k3m9tx","reason":"{}"}}}}}}"#,
            "x".repeat(crate::protocol::MAX_REASON_LEN + 1)
        );
        assert!(AgentRequest::decode_line(&line).is_err());
    }
}
