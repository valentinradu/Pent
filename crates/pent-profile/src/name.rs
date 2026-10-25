//! The name of a profile.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The maximum length of a profile name.
const MAX_LEN: usize = 64;

/// Commands whose basename is a bad profile name, because many different
/// programs run through them. Pent shows a warning when one of these names
/// selects a profile and the user did not give `--profile`.
const GENERIC_COMMANDS: &[&str] = &[
    "bash", "sh", "zsh", "fish", "dash", "env", "python", "python3", "node", "deno", "bun", "ruby",
    "perl", "php", "java", "npx", "uvx", "pipx", "sudo", "nix", "xargs",
];

/// The name of a profile, for example `claude`.
///
/// A name has 1 to 64 characters from `[A-Za-z0-9._-]`, and it does not start
/// with `.`. Thus a name is always a safe file name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProfileName(String);

/// An invalid profile name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileNameError {
    /// The name is empty.
    #[error("the profile name is empty")]
    Empty,
    /// The name is too long.
    #[error("the profile name {0:?} has more than 64 characters")]
    TooLong(String),
    /// The name has a character that is not permitted.
    #[error("the profile name {0:?} can contain only letters, digits, '.', '_' and '-', and it cannot start with '.'")]
    InvalidCharacter(String),
    /// The command has no file name, so pent cannot make a profile name.
    #[error("cannot make a profile name from the command {0:?}; use --profile")]
    NoBasename(String),
}

impl ProfileName {
    /// Make a profile name from the command that the user gave, for example
    /// `claude` from `~/.local/bin/claude`. Pent uses the basename as typed,
    /// not the resolved path, so a new version directory of the program does
    /// not change the name.
    ///
    /// # Errors
    /// Returns an error if the basename is not a valid profile name.
    pub fn from_command(command: &str) -> Result<Self, ProfileNameError> {
        let base = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ProfileNameError::NoBasename(command.to_string()))?;
        base.parse()
    }

    /// Return true if the name is a generic interpreter or shell, for which
    /// the user should give `--profile`.
    #[must_use]
    pub fn is_generic(&self) -> bool {
        GENERIC_COMMANDS.contains(&self.0.as_str())
    }

    /// Return the name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the file name of the profile (`<name>.toml`).
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}.toml", self.0)
    }
}

impl FromStr for ProfileName {
    type Err = ProfileNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ProfileNameError::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(ProfileNameError::TooLong(s.to_string()));
        }
        let valid = !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid {
            return Err(ProfileNameError::InvalidCharacter(s.to_string()));
        }
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<String> for ProfileName {
    type Error = ProfileNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<ProfileName> for String {
    fn from(n: ProfileName) -> Self {
        n.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_command_uses_the_basename() {
        assert_eq!(
            ProfileName::from_command("/home/u/.local/bin/claude").map(String::from),
            Ok("claude".to_string())
        );
        assert_eq!(
            ProfileName::from_command("claude").map(String::from),
            Ok("claude".to_string())
        );
    }

    #[test]
    fn rejects_unsafe_names() {
        for bad in ["", ".hidden", "a/b", "..", "a b", "x\0"] {
            assert!(bad.parse::<ProfileName>().is_err(), "{bad:?}");
        }
        assert!("a".repeat(65).parse::<ProfileName>().is_err());
    }

    /// The limit is 64 characters: a name of 64 characters is valid, and a
    /// name of 65 characters is not.
    #[test]
    fn the_length_limit_is_64_characters() {
        assert!("a".repeat(MAX_LEN).parse::<ProfileName>().is_ok());
        assert!("a"
            .repeat(MAX_LEN.saturating_add(1))
            .parse::<ProfileName>()
            .is_err());
    }

    /// `as_str` and `file_name` give the name that the store uses for the
    /// file of the profile. A wrong value here reads or writes another
    /// profile.
    #[test]
    fn the_name_gives_the_text_and_the_file_name() {
        let parsed = "claude".parse::<ProfileName>();
        assert_eq!(parsed.as_ref().map(ProfileName::as_str), Ok("claude"));
        assert_eq!(
            parsed.as_ref().map(ProfileName::file_name),
            Ok("claude.toml".to_string())
        );
        let other = "other".parse::<ProfileName>();
        assert_eq!(other.as_ref().map(ProfileName::as_str), Ok("other"));
        assert_eq!(
            other.as_ref().map(ProfileName::file_name),
            Ok("other.toml".to_string())
        );
    }

    #[test]
    fn generic_names() {
        assert_eq!(
            "bash".parse::<ProfileName>().map(|n| n.is_generic()),
            Ok(true)
        );
        assert_eq!(
            "claude".parse::<ProfileName>().map(|n| n.is_generic()),
            Ok(false)
        );
    }
}
