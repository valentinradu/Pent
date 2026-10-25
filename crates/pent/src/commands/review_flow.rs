//! The steps after the events are on disk, for `pent watch` and for
//! `pent trust NAME --review`: summary, interactive review, draft, trust.

use std::path::{Path, PathBuf};

use pent_profile::review::{review, Selection};
use pent_profile::summary::{summarize, Summary, SummaryContext};
use pent_profile::{
    render_draft_with, render_header, render_terminal, DraftSource, ProfileDoc, ProfileName,
    Reasons, Warnings, WatchEvent, WatchHeader,
};
use pent_settings::ProfileStore;

use crate::commands::tty::Tty;
use crate::error::CliError;
use crate::ui;

/// The home directory of the user.
///
/// # Errors
/// Returns an error when `$HOME` is not known.
pub(crate) fn home_dir() -> Result<PathBuf, CliError> {
    dirs::home_dir()
        .ok_or_else(|| CliError::Other("the home directory is not available".to_string()))
}

/// The directories that the sandbox already allows without a rule. The
/// summary omits paths below them.
///
/// The traversal list is not in the result: a traversal grant on `/` gives
/// no read access.
pub(crate) fn covered_paths() -> Vec<PathBuf> {
    let path_env = std::env::var("PATH").unwrap_or_default();
    pent_sandbox::implicit_allowed_paths(&path_env)
}

/// What to do when the review needs the user and pent has no terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustAnswer {
    /// Ask on the terminal. Without a terminal, do not trust.
    Ask,
    /// Trust without a question (`--yes`).
    Yes,
}

/// The input of [`summarize_review_and_draft`].
pub(crate) struct ReviewInput<'a> {
    pub store: &'a ProfileStore,
    pub name: &'a ProfileName,
    pub workspace: &'a Path,
    pub events: &'a [WatchEvent],
    /// The trusted profile. The summary omits its rules, and the draft
    /// keeps them.
    pub existing: Option<ProfileDoc>,
    /// Rules that the draft keeps in addition (the current draft for
    /// `pent watch --append`).
    pub keep: Option<ProfileDoc>,
    pub origin: DraftSource,
    pub trust: TrustAnswer,
}

/// The result of [`summarize_review_and_draft`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewOutcome {
    /// The user selected no new rule. Pent wrote no draft.
    NothingSelected,
    /// Pent wrote the draft and the user did not trust it.
    DraftWritten,
    /// Pent wrote the draft and trusted it.
    Trusted,
}

/// Summarize `events`, run the review, write the draft and ask to trust it.
///
/// The review runs on `/dev/tty`. Without a terminal, pent selects all items
/// that the guard did not block.
///
/// # Errors
/// Returns terminal and store errors.
pub(crate) fn summarize_review_and_draft(
    input: ReviewInput<'_>,
) -> Result<ReviewOutcome, CliError> {
    let ReviewInput {
        store,
        name,
        workspace,
        events,
        existing,
        keep,
        origin,
        trust,
    } = input;
    let ctx = SummaryContext {
        home: home_dir()?,
        workspace: workspace.to_path_buf(),
        covered: covered_paths(),
        existing: existing.clone(),
    };
    let summary = summarize(events, &ctx);
    let header = WatchHeader {
        name,
        source: origin,
    };

    // With a terminal, the review shows the items itself, so pent prints only
    // the header first. Without a terminal, pent prints the full summary.
    // The warning lines come after the header, so a user who presses Enter
    // quickly still sees the important facts.
    let mut tty = Tty::open();
    let facts = Warnings::of(&summary);
    let selection = match &tty {
        Some(t) => {
            eprint!("{}", render_header(&summary, &header));
            for line in facts.lines() {
                ui::warn(line);
            }
            eprintln!();
            let (input, output) = t.split()?;
            review(&summary, input, output)?
        }
        None => {
            eprint!("{}", render_terminal(&summary, &header));
            for line in facts.lines() {
                ui::warn(line);
            }
            select_by_default(&summary)
        }
    };
    let added = summary.to_doc(&selection.indices);

    let mut doc = existing.unwrap_or_default();
    if let Some(keep) = &keep {
        doc.extend(keep);
    }
    // A watch run always writes a draft: `pent run` needs a trusted profile,
    // also an empty one. A review of denied accesses that adds nothing
    // leaves the profile as it is.
    if added.is_empty() && origin == DraftSource::DeniedReview {
        ui::ok(format!(
            "no new rules; the profile \"{name}\" does not change"
        ));
        return Ok(ReviewOutcome::NothingSelected);
    }
    doc.extend(&added);

    // The draft keeps the rules of the earlier draft and profile, so it also
    // keeps their reasons.
    let mut reasons = Reasons::from_summary(&summary);
    for earlier in [store.read_draft_text(name), store.read_profile_text(name)] {
        if let Ok(Some(text)) = earlier {
            reasons.merge_missing(Reasons::from_draft(&text));
        }
    }
    let text = render_draft_with(name, origin, &doc, &reasons, facts);
    let path = store.write_draft(name, &text)?;
    ui::ok(format!("draft written: {}", path.display()));

    let trusted = match (trust, tty.as_mut()) {
        (TrustAnswer::Yes, _) => true,
        (TrustAnswer::Ask, Some(t)) => t.confirm("Trust this profile now?")?,
        (TrustAnswer::Ask, None) => false,
    };
    if trusted {
        let profile = store.trust(name)?;
        ui::ok(format!("trusted \"{name}\" ({})", profile.display()));
        Ok(ReviewOutcome::Trusted)
    } else {
        ui::status("next", format!("review and trust it: pent trust {name}"));
        Ok(ReviewOutcome::DraftWritten)
    }
}

/// Select the items of each section that the review selects by default
/// (the review without a terminal).
///
/// The blocked accesses and the Unix sockets stay out: both are strong
/// grants, and only the user can accept them.
fn select_by_default(summary: &Summary) -> Selection {
    Selection {
        indices: summary
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.section().selects_by_default())
            .map(|(i, _)| i)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pent_profile::summary::{Grant, Item};
    use pent_profile::GuardClass;

    #[test]
    fn without_terminal_all_but_the_strong_grants() {
        let item = |grant, blocked| Item {
            grant,
            reason: String::new(),
            blocked,
            notes: vec![],
        };
        let domain = || Grant::Domain("a.com".to_string());
        let summary = Summary {
            items: vec![
                item(domain(), None),
                item(domain(), Some(GuardClass::Credential)),
                item(Grant::UnixSocket("~/a.sock".to_string()), None),
                item(domain(), None),
            ],
            stats: pent_profile::summary::Stats::default(),
        };
        assert_eq!(select_by_default(&summary).indices, vec![0, 3]);
    }

    /// The warning lines show only the counts that are not zero.
    #[test]
    fn warning_lines_name_each_count() {
        assert!(Warnings::default().lines().is_empty());
        let facts = Warnings {
            outside_home: 2,
            other_repository: 1,
            refused_unix_sockets: 3,
        };
        assert_eq!(
            facts.lines(),
            vec![
                "2 rules read outside the home directory",
                "1 rule reads in another repository",
                "pent refused 3 connections to a Unix socket",
            ]
        );
    }

    #[test]
    fn covered_paths_do_not_include_root() {
        let covered = covered_paths();
        assert!(!covered.contains(&PathBuf::from("/")));
        assert!(covered.contains(&PathBuf::from("/tmp")));
    }
}
