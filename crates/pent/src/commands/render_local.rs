//! LOCAL RENDERERS (temporary).
//!
//! `pent_profile::render` will provide the terminal summary and the draft
//! file. Until it lands, these two small functions do the work. The
//! integrator replaces the body of each function with a call to
//! `pent_profile::render`, or replaces the callers and deletes this module.

use pent_profile::summary::{FsAccess, Grant, Section, Summary};
use pent_profile::{ProfileDoc, ProfileName};

/// Append `text` and a newline to `out`.
fn push_line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

/// Where the rules of a draft come from. The draft header names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DraftOrigin {
    /// One or more `pent watch` runs.
    WatchRuns(usize),
    /// The review of the accesses that `pent run` denied.
    DeniedReview,
}

/// The title of a summary section.
const fn section_title(section: Section) -> &'static str {
    match section {
        Section::ReadWrite => "Read-write",
        Section::Read => "Read",
        Section::Execute => "Execute",
        Section::Network => "Network",
        Section::Blocked => "Blocked by the guard",
    }
}

/// The text of a grant, as the summary shows it.
fn grant_text(grant: &Grant) -> &str {
    match grant {
        Grant::Fs { path, .. } => path,
        Grant::Domain(domain) => domain,
    }
}

/// LOCAL RENDERER: replace with `pent_profile::render` when it lands.
///
/// Render the summary for the terminal: a header with the counts, then one
/// block for each section with the item numbers that the review uses.
pub(crate) fn render_terminal_summary(summary: &Summary) -> String {
    let mut out = String::new();
    let stats = &summary.stats;
    push_line(
        &mut out,
        &format!(
            "Recorded {} filesystem and {} network events{}.",
            stats.fs_events,
            stats.net_events,
            if stats.processes.is_empty() {
                String::new()
            } else {
                format!(" from {}", stats.processes.join(", "))
            }
        ),
    );
    if summary.items.is_empty() {
        out.push_str("No new rules.\n");
        return out;
    }
    let mut current: Option<Section> = None;
    let mut number = 0_usize;
    for item in &summary.items {
        let section = item.section();
        if current != Some(section) {
            current = Some(section);
            number = 0;
            let count = summary
                .items
                .iter()
                .filter(|i| i.section() == section)
                .count();
            push_line(&mut out, &format!("\n{} ({count})", section_title(section)));
        }
        number = number.saturating_add(1);
        push_line(
            &mut out,
            &format!(
                "  {number:<2} {:<28} {}",
                grant_text(&item.grant),
                item.reason
            ),
        );
    }
    out
}

/// LOCAL RENDERER: replace with `pent_profile::render` when it lands.
///
/// Render the draft file of `doc`. Each rule that is in `summary` gets the
/// reason of its item as a comment. The result is a valid profile file.
pub(crate) fn render_draft(
    name: &ProfileName,
    doc: &ProfileDoc,
    summary: &Summary,
    origin: DraftOrigin,
) -> String {
    let mut out = String::new();
    let made = match origin {
        DraftOrigin::WatchRuns(1) => "Pent made it from 1 watch run.".to_string(),
        DraftOrigin::WatchRuns(n) => format!("Pent made it from {n} watch runs."),
        DraftOrigin::DeniedReview => "Pent updated it from the denied accesses.".to_string(),
    };
    push_line(&mut out, &format!("# Profile for \"{name}\". {made}"));
    out.push_str("# Each comment tells why the rule exists. Remove a line to remove the rule.\n");

    let reason = |grant: &Grant| -> Option<&str> {
        summary
            .items
            .iter()
            .find(|i| i.blocked.is_none() && &i.grant == grant)
            .map(|i| i.reason.as_str())
    };
    let fs = &doc.filesystem;
    out.push_str("\n[filesystem]\n");
    for (key, list, access) in [
        ("read_write", &fs.read_write, FsAccess::ReadWrite),
        ("read", &fs.read, FsAccess::Read),
        ("execute", &fs.execute, FsAccess::Execute),
    ] {
        write_list(&mut out, key, list, |entry| {
            reason(&Grant::Fs {
                access,
                path: entry.to_string(),
            })
        });
    }
    out.push_str("\n[network]\n");
    write_list(&mut out, "domains", &doc.network.domains, |entry| {
        reason(&Grant::Domain(entry.to_string()))
    });
    out
}

/// Write one TOML array with one entry for each line and an optional
/// comment after each entry.
fn write_list<'a>(
    out: &mut String,
    key: &str,
    list: &[String],
    comment: impl Fn(&str) -> Option<&'a str>,
) {
    if list.is_empty() {
        push_line(out, &format!("{key} = []"));
        return;
    }
    push_line(out, &format!("{key} = ["));
    for entry in list {
        let quoted = toml_string(entry);
        match comment(entry) {
            Some(reason) => {
                push_line(
                    out,
                    &format!("  {:<30} # {}", format!("{quoted},"), one_line(reason)),
                );
            }
            None => {
                push_line(out, &format!("  {quoted},"));
            }
        }
    }
    out.push_str("]\n");
}

/// Quote a string for TOML. A JSON string is a valid TOML basic string.
fn toml_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("{s:?}"))
}

/// Make a comment one line long.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pent_profile::summary::Item;

    fn summary() -> Summary {
        Summary {
            items: vec![
                Item {
                    grant: Grant::Fs {
                        access: FsAccess::ReadWrite,
                        path: "~/.claude".to_string(),
                    },
                    reason: "creates and edits files (37 new)".to_string(),
                    blocked: None,
                    notes: vec![],
                },
                Item {
                    grant: Grant::Domain("api.anthropic.com".to_string()),
                    reason: "claude".to_string(),
                    blocked: None,
                    notes: vec![],
                },
            ],
            stats: pent_profile::summary::Stats::default(),
        }
    }

    #[test]
    fn draft_is_a_valid_profile_with_reasons() {
        let s = summary();
        let mut doc = s.to_doc(&[0, 1]);
        doc.filesystem.read.push("~/odd \"name\"\n".to_string());
        let name: Result<ProfileName, _> = "claude".parse();
        let Ok(name) = name else {
            return assert!(name.is_ok());
        };
        let text = render_draft(&name, &doc, &s, DraftOrigin::WatchRuns(3));
        assert!(text.starts_with("# Profile for \"claude\". Pent made it from 3 watch runs."));
        assert!(
            text.contains("# creates and edits files (37 new)"),
            "{text}"
        );
        let parsed = ProfileDoc::parse(&text);
        assert!(
            parsed.as_ref().is_ok_and(|p| *p == doc),
            "{parsed:?}\n{text}"
        );
    }

    #[test]
    fn summary_numbers_items_per_section() {
        let text = render_terminal_summary(&summary());
        assert!(text.contains("Read-write (1)\n  1  ~/.claude"), "{text}");
        assert!(
            text.contains("Network (1)\n  1  api.anthropic.com"),
            "{text}"
        );
        assert!(render_terminal_summary(&Summary::default()).contains("No new rules."));
    }
}
