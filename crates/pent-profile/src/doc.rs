//! The profile file.
//!
//! A trusted profile is at `~/.config/pent/profiles/<name>.toml`. A draft is
//! at `~/.local/state/pent/drafts/<name>.toml`. Both use this format:
//!
//! ```toml
//! [filesystem]
//! read = ["~/.gitconfig"]
//! read_write = ["~/.claude"]
//! execute = ["~/.local/share/claude"]
//!
//! [network]
//! domains = ["api.anthropic.com", "*.npmjs.org"]
//! ```
//!
//! Paths can start with `~/`. Pent expands `~` when it applies the profile.
//! The draft writer adds comments. The parser ignores them.

use serde::{Deserialize, Serialize};

/// The filesystem rules of a profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRules {
    /// Paths with read access (a file, or a directory and all below it).
    #[serde(default)]
    pub read: Vec<String>,
    /// Paths with read and write access.
    #[serde(default)]
    pub read_write: Vec<String>,
    /// Paths with read and execute access.
    #[serde(default)]
    pub execute: Vec<String>,
}

/// The network rules of a profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRules {
    /// Domains that the proxy allows. A leading `*.` matches one or more
    /// labels below the domain, but not the domain itself.
    #[serde(default)]
    pub domains: Vec<String>,
}

/// A profile: the access that one program gets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDoc {
    /// The filesystem rules.
    #[serde(default)]
    pub filesystem: FilesystemRules,
    /// The network rules.
    #[serde(default)]
    pub network: NetworkRules,
}

/// An error in a profile file.
#[derive(Debug, thiserror::Error)]
pub enum DocError {
    /// The file is not valid TOML, or it has an unknown key.
    #[error("invalid profile: {0}")]
    Parse(#[from] toml::de::Error),
}

impl ProfileDoc {
    /// Parse a profile file.
    ///
    /// # Errors
    /// Returns an error if the text is not valid TOML or has an unknown key.
    pub fn parse(text: &str) -> Result<Self, DocError> {
        Ok(toml::from_str(text)?)
    }

    /// Return true if the profile has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filesystem.read.is_empty()
            && self.filesystem.read_write.is_empty()
            && self.filesystem.execute.is_empty()
            && self.network.domains.is_empty()
    }

    /// Add the rules of `other` that this profile does not have. The order of
    /// the existing rules does not change.
    pub fn extend(&mut self, other: &Self) {
        fn add(dst: &mut Vec<String>, src: &[String]) {
            for s in src {
                if !dst.contains(s) {
                    dst.push(s.clone());
                }
            }
        }
        add(&mut self.filesystem.read, &other.filesystem.read);
        add(
            &mut self.filesystem.read_write,
            &other.filesystem.read_write,
        );
        add(&mut self.filesystem.execute, &other.filesystem.execute);
        add(&mut self.network.domains, &other.network.domains);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ignores_comments_and_rejects_unknown_keys() {
        let doc = ProfileDoc::parse(
            "[filesystem]\nread = [\"~/.gitconfig\"] # git\n[network]\ndomains = [\"a.com\"]\n",
        );
        assert!(doc.is_ok(), "{doc:?}");
        assert!(ProfileDoc::parse("[filesystem]\nwrite = []\n").is_err());
    }

    #[test]
    fn extend_adds_only_new_rules() {
        let mut a = ProfileDoc::default();
        a.network.domains.push("a.com".to_string());
        let mut b = ProfileDoc::default();
        b.network.domains = vec!["a.com".to_string(), "b.com".to_string()];
        a.extend(&b);
        assert_eq!(a.network.domains, vec!["a.com", "b.com"]);
    }
}
