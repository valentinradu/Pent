//! The summary step: group raw events into a short list of rules.
//!
//! The user never sees raw events. The summary has at most one rule for each
//! directory or domain that the program needs, and one short reason for each
//! rule. See `docs/design/watch.md` for the grouping rules.

use std::path::PathBuf;

use crate::{GuardClass, ProfileDoc, WatchEvent};

/// The access that a filesystem rule gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FsAccess {
    /// Read access.
    Read,
    /// Read and write access.
    ReadWrite,
    /// Read and execute access.
    Execute,
}

/// The rule that an item adds to the profile when the user accepts it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Grant {
    /// A filesystem rule. `path` uses `~/` for the home directory.
    Fs {
        /// The access.
        access: FsAccess,
        /// The path (a file, or a directory and all below it).
        path: String,
    },
    /// A domain for the proxy allowlist (can start with `*.`).
    Domain(String),
}

/// A note that the summary shows next to an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemNote {
    /// The program created this file in the session and then executed it.
    CreatedThenExecuted,
    /// The path is outside the home directory and outside the workspace.
    OutsideHome,
    /// The path is in another directory that looks like a source repository.
    OtherRepository,
}

/// One proposed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The rule that the item adds.
    pub grant: Grant,
    /// One short reason, for example `creates and edits files (37 new)` or
    /// `read by git`.
    pub reason: String,
    /// The guard class, when the watch guard blocked this access. The review
    /// shows these items in their own section, and does not select them by
    /// default.
    pub blocked: Option<GuardClass>,
    /// Extra notes for the user.
    pub notes: Vec<ItemNote>,
}

/// A section of the summary and of the review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Section {
    /// Read-write filesystem rules.
    ReadWrite,
    /// Read filesystem rules.
    Read,
    /// Execute filesystem rules.
    Execute,
    /// Domains.
    Network,
    /// Accesses that the watch guard blocked.
    Blocked,
}

impl Item {
    /// Return the section of the item.
    #[must_use]
    pub const fn section(&self) -> Section {
        if self.blocked.is_some() {
            return Section::Blocked;
        }
        match &self.grant {
            Grant::Fs { access, .. } => match access {
                FsAccess::ReadWrite => Section::ReadWrite,
                FsAccess::Read => Section::Read,
                FsAccess::Execute => Section::Execute,
            },
            Grant::Domain(_) => Section::Network,
        }
    }
}

/// Counts for the header of the summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// The number of filesystem events.
    pub fs_events: usize,
    /// The number of network events.
    pub net_events: usize,
    /// The distinct process names, in order of first appearance.
    pub processes: Vec<String>,
}

/// The input of the summary step that does not come from the events.
#[derive(Debug, Clone)]
pub struct SummaryContext {
    /// The home directory.
    pub home: PathBuf,
    /// The workspace. The sandbox always allows it, so the summary omits it.
    pub workspace: PathBuf,
    /// Directories that the sandbox defaults already allow (system paths,
    /// `/tmp`, `/proc`, `/dev`, `/nix/store`, ...). The summary omits paths
    /// below them.
    pub covered: Vec<PathBuf>,
    /// The current trusted profile, if one exists. The summary omits the
    /// rules that it already has.
    pub existing: Option<ProfileDoc>,
}

/// The result of the summary step.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// The proposed rules, sorted by section, then by rule.
    pub items: Vec<Item>,
    /// Counts for the header.
    pub stats: Stats,
}

impl Summary {
    /// Make a profile from the items at the selected indices.
    #[must_use]
    pub fn to_doc(&self, selected: &[usize]) -> ProfileDoc {
        let mut doc = ProfileDoc::default();
        for item in selected.iter().filter_map(|&i| self.items.get(i)) {
            let list = match &item.grant {
                Grant::Fs { access, path } => {
                    let list = match access {
                        FsAccess::Read => &mut doc.filesystem.read,
                        FsAccess::ReadWrite => &mut doc.filesystem.read_write,
                        FsAccess::Execute => &mut doc.filesystem.execute,
                    };
                    (list, path)
                }
                Grant::Domain(d) => (&mut doc.network.domains, d),
            };
            if !list.0.contains(list.1) {
                list.0.push(list.1.clone());
            }
        }
        doc
    }
}

/// Group raw events into a summary.
///
/// CONTRACT STUB: the full grouping is not implemented yet. This version
/// returns an empty summary.
#[must_use]
pub fn summarize<'a, I>(events: I, ctx: &SummaryContext) -> Summary
where
    I: IntoIterator<Item = &'a WatchEvent>,
{
    let _ = (events.into_iter().count(), ctx);
    Summary::default()
}
