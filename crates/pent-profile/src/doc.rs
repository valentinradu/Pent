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
//! localhost = [5432]
//! ```
//!
//! Paths can start with `~/`. Pent expands `~` when it applies the profile.
//! The draft writer adds comments. The parser ignores them.

use std::num::NonZeroU16;

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
    /// Unix socket paths that the program can connect to.
    ///
    /// Landlock cannot control a connection to a Unix socket, so pent makes
    /// each permitted connection itself. A socket that is not in this list
    /// is not reachable, also when a rule gives access to its directory.
    #[serde(default)]
    pub unix_sockets: Vec<String>,
}

/// The network rules of a profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRules {
    /// Domains that the proxy allows. A leading `*.` matches one or more
    /// labels below the domain, but not the domain itself.
    #[serde(default)]
    pub domains: Vec<String>,
    /// TCP ports on the loopback of the host that the program can connect
    /// to (`127.0.0.1`, `::1`).
    ///
    /// A port on the loopback of the host is a strong grant: a service there
    /// often has no authentication (the Docker API, the debug port of a
    /// browser). The program reaches only the ports in this list. A port that
    /// is not in the list stays inside the sandbox.
    #[serde(default)]
    pub localhost: Vec<NonZeroU16>,
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
            && self.filesystem.unix_sockets.is_empty()
            && self.network.domains.is_empty()
            && self.network.localhost.is_empty()
    }

    /// Add the rules of `other` that this profile does not have. The order of
    /// the existing rules does not change.
    pub fn extend(&mut self, other: &Self) {
        fn add<T: Clone + PartialEq>(dst: &mut Vec<T>, src: &[T]) {
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
        add(
            &mut self.filesystem.unix_sockets,
            &other.filesystem.unix_sockets,
        );
        add(&mut self.network.domains, &other.network.domains);
        add(&mut self.network.localhost, &other.network.localhost);
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

    #[test]
    fn localhost_takes_ports_and_rejects_port_zero() {
        let doc = ProfileDoc::parse("[network]\nlocalhost = [5432, 11434]\n");
        let ports: Option<Vec<u16>> = doc
            .ok()
            .map(|d| d.network.localhost.iter().map(|p| p.get()).collect());
        assert_eq!(ports, Some(vec![5432, 11434]));
        assert!(ProfileDoc::parse("[network]\nlocalhost = [0]\n").is_err());
        assert!(ProfileDoc::parse("[network]\nlocalhost = [65536]\n").is_err());
        assert!(ProfileDoc::parse("[network]\nlocalhost = [\"5432\"]\n").is_err());
    }

    #[test]
    fn a_profile_with_only_a_port_is_not_empty() {
        let doc = ProfileDoc::parse("[network]\nlocalhost = [5432]\n");
        assert!(doc.is_ok_and(|d| !d.is_empty()));
    }
}
