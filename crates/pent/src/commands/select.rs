//! Profile selection for `pent watch`, and the message of `pent trust` for
//! a profile that is not trusted.

use pent_profile::ProfileName;
use pent_settings::ProfileStatus;

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

/// The error message for a profile that is not trusted, or `None` when the
/// profile is trusted.
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
}
