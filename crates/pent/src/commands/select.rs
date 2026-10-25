//! Profile selection for `pent run` and `pent watch`, and the conversion of
//! a profile into sandbox paths.

use pent_profile::{ProfileDoc, ProfileName};
use pent_settings::{LoadedProfile, ProfileStatus, ProfileStore, SandboxPaths};

use crate::error::CliError;

/// The profile that a command uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Selected {
    /// The profile name.
    pub name: ProfileName,
    /// How pent found the name.
    pub source: NameSource,
}

/// How pent found the profile name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameSource {
    /// The user gave `--profile`.
    Flag,
    /// Pent made the name from the command.
    Command,
}

/// Select the profile: `--profile NAME`, else the file name of the command.
///
/// # Errors
/// Returns an error if the name is not a valid profile name.
pub(crate) fn select_profile(flag: Option<&str>, command: &[String]) -> Result<Selected, CliError> {
    if let Some(name) = flag {
        return Ok(Selected {
            name: name.parse()?,
            source: NameSource::Flag,
        });
    }
    let cmd = command
        .first()
        .ok_or_else(|| CliError::Other("command list is empty".to_string()))?;
    Ok(Selected {
        name: ProfileName::from_command(cmd)?,
        source: NameSource::Command,
    })
}

/// The warning for a generic command name (a shell or an interpreter) when
/// the user did not give `--profile`.
pub(crate) fn generic_warning(selected: &Selected) -> Option<String> {
    (selected.source == NameSource::Command && selected.name.is_generic()).then(|| {
        format!(
            "the profile name \"{0}\" comes from a generic command: all programs that \
             run through {0} share this profile. Give each program its own profile \
             with --profile NAME",
            selected.name
        )
    })
}

/// The `pent watch` command that records the profile of this selection.
pub(crate) fn watch_command(selected: &Selected, command: &[String]) -> String {
    let words: Vec<String> = command.iter().map(|w| shell_quote(w)).collect();
    match selected.source {
        NameSource::Flag => format!(
            "pent watch --profile {} -- {}",
            selected.name,
            words.join(" ")
        ),
        NameSource::Command => format!("pent watch -- {}", words.join(" ")),
    }
}

/// Quote a word for a POSIX shell when it has special characters.
fn shell_quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@%+,~".contains(&b));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// The error message when `pent run` cannot apply the profile, or `None`
/// when the profile is trusted.
pub(crate) fn not_trusted_message(
    status: ProfileStatus,
    name: &ProfileName,
    watch: &str,
) -> Option<String> {
    match status {
        ProfileStatus::Trusted => None,
        ProfileStatus::Missing => Some(format!(
            "no trusted profile for \"{name}\"\n  record one: {watch}"
        )),
        ProfileStatus::DraftOnly => Some(format!(
            "no trusted profile for \"{name}\": the draft is not trusted\n  \
             review and trust it: pent trust {name}"
        )),
        ProfileStatus::NotTrusted => Some(format!(
            "the profile \"{name}\" is not trusted\n  review and trust it: pent trust {name}"
        )),
        ProfileStatus::Changed => Some(format!(
            "the profile \"{name}\" changed after you trusted it; pent does not apply it\n  \
             review and trust it again: pent trust {name}"
        )),
    }
}

/// Load the trusted profile of `selected`.
///
/// # Errors
/// Returns the messages of [`not_trusted_message`] when the profile is not
/// trusted, and store errors.
pub(crate) fn load_trusted(
    store: &ProfileStore,
    selected: &Selected,
    command: &[String],
) -> Result<ProfileDoc, CliError> {
    let LoadedProfile { status, doc, .. } = store.load(&selected.name)?;
    if let Some(message) =
        not_trusted_message(status, &selected.name, &watch_command(selected, command))
    {
        return Err(CliError::Other(message));
    }
    // A trusted profile always has a document; the store parses it.
    doc.ok_or_else(|| CliError::Other(format!("cannot read the profile \"{}\"", selected.name)))
}

/// Convert a profile into sandbox paths.
///
/// The lists keep their entries as written (`~/` expands later). The
/// traversal list gets each parent directory of each entry, so that the
/// program can resolve the path (`realpath` reads the metadata of each
/// component). Traversal gives no read access to files.
pub(crate) fn profile_paths(doc: &ProfileDoc) -> SandboxPaths {
    let fs = &doc.filesystem;
    let mut traversal: Vec<String> = Vec::new();
    for entry in fs.read.iter().chain(&fs.read_write).chain(&fs.execute) {
        for parent in parents(entry) {
            if !traversal.contains(&parent) {
                traversal.push(parent);
            }
        }
    }
    SandboxPaths {
        traversal,
        read: fs.read.clone(),
        execute: fs.execute.clone(),
        read_write: fs.read_write.clone(),
    }
}

/// The parent directories of a profile entry, from the top down.
///
/// `~/.cache/claude` gives `~` and `~/.cache`. `/opt/a/b` gives `/opt` and
/// `/opt/a`; `/` is in the sandbox defaults. A relative entry gives nothing.
fn parents(entry: &str) -> Vec<String> {
    let entry = entry.strip_suffix('*').unwrap_or(entry);
    let (root, rest) = if entry == "~" {
        return Vec::new();
    } else if let Some(rest) = entry.strip_prefix("~/") {
        ("~", rest)
    } else if let Some(rest) = entry.strip_prefix('/') {
        ("", rest)
    } else {
        return Vec::new();
    };
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    let mut out = Vec::new();
    if !root.is_empty() {
        out.push(root.to_string());
    }
    let mut current = root.to_string();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        current = format!("{current}/{part}");
        out.push(current.clone());
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cmd(words: &[&str]) -> Vec<String> {
        words.iter().map(ToString::to_string).collect()
    }

    fn name(s: &str) -> ProfileName {
        s.parse().unwrap()
    }

    #[test]
    fn selects_the_command_basename() {
        let s = select_profile(None, &cmd(&["/home/u/.local/bin/claude", "--resume"]));
        assert!(
            matches!(&s, Ok(Selected { name: n, source: NameSource::Command }) if n.as_str() == "claude"),
            "{s:?}"
        );
    }

    #[test]
    fn flag_wins_and_suppresses_the_generic_warning() {
        let s = select_profile(Some("train"), &cmd(&["python3", "train.py"]));
        let Ok(s) = s else {
            return assert!(s.is_ok(), "{s:?}");
        };
        assert_eq!(s.name.as_str(), "train");
        assert_eq!(s.source, NameSource::Flag);
        assert!(generic_warning(&s).is_none());
    }

    #[test]
    fn warns_for_a_generic_command() {
        let s = select_profile(None, &cmd(&["bash", "-c", "npm test"]));
        let Ok(s) = s else {
            return assert!(s.is_ok(), "{s:?}");
        };
        let warning = generic_warning(&s).unwrap_or_default();
        assert!(warning.contains("\"bash\""), "{warning}");
        assert!(warning.contains("--profile NAME"), "{warning}");
        let claude = select_profile(None, &cmd(&["claude"]));
        assert!(claude.is_ok_and(|c| generic_warning(&c).is_none()));
    }

    #[test]
    fn invalid_flag_name_fails() {
        assert!(select_profile(Some("a/b"), &cmd(&["x"])).is_err());
    }

    #[test]
    fn watch_command_quotes_words() {
        let by_cmd = Selected {
            name: name("claude"),
            source: NameSource::Command,
        };
        assert_eq!(
            watch_command(&by_cmd, &cmd(&["claude"])),
            "pent watch -- claude"
        );
        let by_flag = Selected {
            name: name("npm-test"),
            source: NameSource::Flag,
        };
        assert_eq!(
            watch_command(&by_flag, &cmd(&["bash", "-c", "npm test"])),
            "pent watch --profile npm-test -- bash -c 'npm test'"
        );
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn messages_for_each_status() {
        let n = name("claude");
        let w = "pent watch -- claude";
        assert_eq!(not_trusted_message(ProfileStatus::Trusted, &n, w), None);
        assert_eq!(
            not_trusted_message(ProfileStatus::Missing, &n, w).as_deref(),
            Some("no trusted profile for \"claude\"\n  record one: pent watch -- claude")
        );
        let draft = not_trusted_message(ProfileStatus::DraftOnly, &n, w).unwrap_or_default();
        assert!(draft.contains("pent trust claude"), "{draft}");
        assert!(!draft.contains("pent watch"), "{draft}");
        let changed = not_trusted_message(ProfileStatus::Changed, &n, w).unwrap_or_default();
        assert!(
            changed.contains("changed after you trusted it"),
            "{changed}"
        );
        assert!(changed.contains("pent trust claude"), "{changed}");
        let not = not_trusted_message(ProfileStatus::NotTrusted, &n, w).unwrap_or_default();
        assert!(not.contains("is not trusted"), "{not}");
    }

    #[test]
    fn profile_to_paths() {
        let doc = ProfileDoc::parse(
            "[filesystem]\nread = [\"~/.gitconfig\", \"/opt/a/b\"]\n\
             read_write = [\"~/.cache/claude\", \"rel/dir\"]\nexecute = [\"~/.local/bin\"]\n",
        );
        let Ok(doc) = doc else {
            return assert!(doc.is_ok(), "{doc:?}");
        };
        let paths = profile_paths(&doc);
        assert_eq!(paths.read, vec!["~/.gitconfig", "/opt/a/b"]);
        assert_eq!(paths.read_write, vec!["~/.cache/claude", "rel/dir"]);
        assert_eq!(paths.execute, vec!["~/.local/bin"]);
        assert_eq!(
            paths.traversal,
            vec!["~", "/opt", "/opt/a", "~/.cache", "~/.local"]
        );
    }

    #[test]
    fn parents_of_entries() {
        assert!(parents("~").is_empty());
        assert_eq!(parents("~/.claude.json*"), vec!["~"]);
        assert!(parents("/opt").is_empty());
        assert!(parents("relative").is_empty());
    }
}
