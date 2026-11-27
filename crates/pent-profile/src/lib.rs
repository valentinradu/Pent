//! Recorded access events, profile files, grouping and review for pent.
//!
//! This crate holds the parts of watch mode that do not depend on the
//! platform:
//!
//! - [`event`]: the event type that each recorder emits (the seccomp
//!   recorder, the proxy).
//! - [`name`]: the name of a profile.
//! - [`doc`]: the profile file (`~/.config/pent/profiles/<name>.toml`).
//! - [`guard`]: the dangerous paths that watch mode blocks.
//! - [`summary`]: the step that groups raw events into a short list of rules.
//! - [`review`](mod@review): the interactive review at the end of watch mode.
//! - [`render`]: the text of the summary, the draft file and a profile.
//! - [`psl`]: a compact subset of the public suffix list.
//! - [`rule`]: the rules, the answers that pent keeps for the next run (see
//!   `docs/design/pent.md`).
//! - [`rule_file`]: the TOML form of the rules of one program.
//! - [`class`]: the class of an access (normal, sensitive, pent) and the
//!   width menu of a question.
//! - [`protocol`]: the messages of `pentd.sock` and their JSON lines codec.
//!
//! See `docs/design/watch.md` for the full design.

pub mod agent;
pub mod class;
pub mod doc;
pub mod event;
pub mod guard;
pub mod localhost;
pub mod name;
pub mod protocol;
pub mod psl;
pub mod render;
pub mod review;
pub mod rule;
pub mod rule_file;
pub mod summary;

pub use agent::{AgentDenial, AgentFailure, AgentReply, AgentRequest, AGENT_PROTOCOL_VERSION};
pub use class::{
    exact_target, Class, Classifier, GuardSpot, Sensitive, ESCAPE_SOCKETS, HOME_AGENT_SOCKETS,
    PENT_HOME_DIRS, RESOLVER_SOCKETS,
};
pub use doc::{DocError, FilesystemRules, NetworkRules, ProfileDoc};
pub use event::{FsOp, GuardClass, NetProtocol, Outcome, ProcessInfo, WatchEvent};
pub use guard::{
    classify, guard_rules, guard_rules_with, name_matches, GuardAccess, GuardRule, GuardTarget,
};
pub use localhost::{control_port, is_localhost_name, is_loopback, CONTROL_PORTS};
pub use name::{ProfileName, ProfileNameError};
pub use protocol::{
    AgentReason, Answer, Ask, BadCode, BadReason, Deadline, DeadlineTooLong, DecidedBy, Denial,
    Event, EventsDropped, Forget, Forgotten, Hold, MenuIndex, Message, ProtocolError, Question,
    QuestionId, RejectReason, Rejected, Request, Scope, SessionId, SessionInfo, Skip, Timestamp,
    Verdict, CODE_ALPHABET, CODE_LEN, CODE_SPACE, DNS_DEADLINE, FILE_DEADLINE, MAX_DEADLINE,
    MAX_LINE_LEN, MAX_REASON_LEN, PROTOCOL_VERSION, PROXY_DEADLINE,
};
pub use render::{
    render_draft, render_draft_with, render_header, render_profile, render_terminal, safe,
    safe_lines, DraftSource, Reasons, Warnings, WatchHeader,
};
pub use review::{review, Selection};
pub use rule::{
    Access, Decision, Depth, DomainName, DomainWidth, FileKind, PathWidth, Rule, RuleError,
    RuleKey, RulePath, RuleSet, Source, Target,
};
pub use rule_file::{format_date, EntryError, Kind as RuleFileKind, RuleFileError};
pub use summary::{
    summarize, FsAccess, Grant, Item, ItemNote, Section, Stats, Summary, SummaryContext,
};

#[cfg(test)]
mod fixture;
