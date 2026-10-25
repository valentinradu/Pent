//! Recorded access events, profile files, grouping and review for pent.
//!
//! This crate holds the parts of watch mode that do not depend on the
//! platform:
//!
//! - [`event`]: the event type that each recorder emits (Linux seccomp
//!   recorder, macOS Seatbelt recorder, the proxy).
//! - [`name`]: the name of a profile.
//! - [`doc`]: the profile file (`~/.config/pent/profiles/<name>.toml`).
//! - [`guard`]: the dangerous paths that watch mode blocks on all platforms.
//! - [`summary`]: the step that groups raw events into a short list of rules.
//! - [`review`](mod@review): the interactive review at the end of watch mode.
//! - [`render`]: the text of the summary, the draft file and a profile.
//! - [`psl`]: a compact subset of the public suffix list.
//!
//! See `docs/design/watch.md` for the full design.

pub mod doc;
pub mod event;
pub mod guard;
pub mod name;
pub mod psl;
pub mod render;
pub mod review;
pub mod summary;

pub use doc::{DocError, FilesystemRules, NetworkRules, ProfileDoc};
pub use event::{FsOp, GuardClass, NetProtocol, Outcome, ProcessInfo, WatchEvent};
pub use guard::{classify, guard_rules, GuardAccess, GuardRule, GuardTarget};
pub use name::{ProfileName, ProfileNameError};
pub use render::{render_draft, render_profile, render_terminal, Reasons, WatchHeader};
pub use summary::{
    summarize, FsAccess, Grant, Item, ItemNote, Section, Stats, Summary, SummaryContext,
};

#[cfg(test)]
mod fixture;
