//! The rules: the answers that pent keeps for the next run.
//!
//! A rule is one answer of the human or of the model: a target (a file width,
//! a domain width, a Unix socket or a port on localhost) and a decision. The
//! rules of one root program form a [`RuleSet`], and [`RuleSet::decide`] tells
//! whether a rule answers one access.
//!
//! When more than one rule matches, the most specific rule wins: an exact
//! path before a subtree, a deeper subtree before a shallower one, an exact
//! domain before a wildcard. On a tie, `Deny` wins.
//!
//! See `docs/design/pent.md`, sections 5 to 7 and 12.

use std::fmt;
use std::num::NonZeroU16;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::psl;

/// The maximum length of a rule key.
const MAX_KEY_LEN: usize = 64;

/// The maximum length of a domain name.
const MAX_DOMAIN_LEN: usize = 253;

/// An invalid rule key, path or domain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// The key is empty.
    #[error("the key is empty")]
    EmptyKey,
    /// The key is too long.
    #[error("the key {0:?} has more than 64 characters")]
    KeyTooLong(String),
    /// The key has a character that is not permitted.
    #[error("the key {0:?} can contain only letters, digits, '.', '_' and '-', and it cannot start with '.'")]
    InvalidKey(String),
    /// The command has no file name, so pent cannot make a key.
    #[error("cannot make a key from the command {0:?}; use --key")]
    NoBasename(String),
    /// The path is not absolute.
    #[error("the path {0:?} is not absolute")]
    RelativePath(PathBuf),
    /// The path has a `.` or `..` component.
    #[error("the path {0:?} has a '.' or '..' component")]
    PathNotNormal(PathBuf),
    /// The path has a NUL byte, so no system call can take it.
    #[error("the path {0:?} has a NUL byte")]
    PathHasNul(PathBuf),
    /// The domain name is not valid.
    #[error("the domain name {0:?} is not valid")]
    InvalidDomain(String),
    /// A wildcard would cover a public suffix or a shared hosting domain.
    #[error("the wildcard {0:?} is too wide: it covers a public suffix")]
    WildcardTooWide(String),
}

// ── The key ─────────────────────────────────────────────────────────────────

/// The key of a set of rules: the file name of the root program, for example
/// `claude` for `pent run -- ~/.local/bin/claude`.
///
/// A key has 1 to 64 characters from `[A-Za-z0-9._-]`, and it does not start
/// with `.`. Thus a key is always a safe file name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RuleKey(String);

impl TryFrom<String> for RuleKey {
    type Error = RuleError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<RuleKey> for String {
    fn from(key: RuleKey) -> Self {
        key.0
    }
}

impl RuleKey {
    /// Make a key from the command that the user gave. Pent uses the file
    /// name as typed, not the resolved path, so a new version directory of
    /// the program does not change the key.
    ///
    /// # Errors
    /// Returns an error if the command has no file name, or if the file name
    /// is not a valid key.
    pub fn from_command(command: &str) -> Result<Self, RuleError> {
        Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RuleError::NoBasename(command.to_string()))?
            .parse()
    }

    /// The key as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RuleKey {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(RuleError::EmptyKey);
        }
        if s.len() > MAX_KEY_LEN {
            return Err(RuleError::KeyTooLong(s.to_string()));
        }
        let valid = !s.starts_with('.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !valid {
            return Err(RuleError::InvalidKey(s.to_string()));
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for RuleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Paths and domains ───────────────────────────────────────────────────────

/// An absolute path with no `.` and no `..` component and no NUL byte, in one
/// normal form: `//a//b/` becomes `/a/b`. Thus one path has one text, in a
/// question and in a rule file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "PathBuf", into = "PathBuf")]
pub struct RulePath(PathBuf);

impl TryFrom<PathBuf> for RulePath {
    type Error = RuleError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl From<RulePath> for PathBuf {
    fn from(path: RulePath) -> Self {
        path.0
    }
}

impl RulePath {
    /// Check `path` and give it the normal form.
    ///
    /// # Errors
    /// Returns an error if the path is relative, if it has a `..`
    /// component, or if it has a NUL byte. A `.` component in the middle
    /// is not an error: the normal form drops it, as the kernel does.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, RuleError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(RuleError::RelativePath(path));
        }
        if path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(RuleError::PathHasNul(path));
        }
        if path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        {
            return Err(RuleError::PathNotNormal(path));
        }
        // `components` drops a repeated `/`, a `.` in the middle and a final
        // `/`, so the collected path is the normal form.
        Ok(Self(path.components().collect()))
    }

    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The number of normal components, used to rank two subtrees.
    fn depth(&self) -> usize {
        self.0
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    }
}

/// A domain name in normal form: lowercase ASCII, no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

impl TryFrom<String> for DomainName {
    type Error = RuleError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<DomainName> for String {
    fn from(name: DomainName) -> Self {
        name.0
    }
}

impl DomainName {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The number of labels, used to rank two wildcards.
    fn labels(&self) -> usize {
        self.0.split('.').count()
    }
}

impl FromStr for DomainName {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        if name.is_empty() || name.len() > MAX_DOMAIN_LEN || !name.split('.').all(label_ok) {
            return Err(RuleError::InvalidDomain(s.to_string()));
        }
        Ok(Self(name))
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Accesses ────────────────────────────────────────────────────────────────

/// The kind of a file access. "See" (`stat`, an existence check) is free and
/// never needs a rule, so it is not in this list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    /// Learn the names in a directory (`readdir`).
    List,
    /// Read the content.
    Read,
    /// Create, write, make a directory, rename or delete.
    Write,
    /// Run a program.
    Exec,
}

impl FileKind {
    /// The name of the kind, as the rule file writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Read => "read",
            Self::Write => "write",
            Self::Exec => "exec",
        }
    }

    /// Return true if a rule of this kind also permits an access of the kind
    /// `access`. A read, write or exec rule includes the listings inside its
    /// width, and a write or exec rule includes reads.
    #[must_use]
    pub const fn covers(self, access: Self) -> bool {
        matches!(
            (self, access),
            (Self::List, Self::List)
                | (Self::Read, Self::List | Self::Read)
                | (Self::Write, Self::List | Self::Read | Self::Write)
                | (Self::Exec, Self::List | Self::Read | Self::Exec)
        )
    }
}

/// One access of the program that pent must decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access<'a> {
    /// A file access on an absolute, normal path.
    File {
        /// The kind of the access.
        kind: FileKind,
        /// The path.
        path: &'a RulePath,
    },
    /// A connection to a domain (a DNS query or a proxy request).
    Domain(&'a DomainName),
    /// A connection to a Unix socket with a path.
    UnixSocket(&'a RulePath),
    /// A TCP connection to a port on the loopback of the host.
    Localhost(NonZeroU16),
}

// ── Rules ───────────────────────────────────────────────────────────────────

/// The paths that a file rule covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathWidth {
    /// The path itself. For a listing, the names of this directory only.
    Exact(RulePath),
    /// The directory and everything below it.
    Subtree(RulePath),
}

/// The domains that a network rule covers. The forms follow the proxy:
/// `*.example.com` is exactly one more label, `**.example.com` is any depth.
/// Neither form covers `example.com` itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum DomainWidth {
    /// The name itself.
    Exact(DomainName),
    /// `*.base`: one more label.
    OneLabel(DomainName),
    /// `**.base`: one or more labels.
    AnyDepth(DomainName),
}

impl DomainWidth {
    /// Make a wildcard below `base`.
    ///
    /// # Errors
    /// Returns an error if the wildcard would cover a public suffix, for
    /// example `*.com` or `*.github.io`.
    pub fn wildcard(base: DomainName, any_depth: bool) -> Result<Self, RuleError> {
        if !psl::wildcard_allowed(base.as_str()) {
            return Err(RuleError::WildcardTooWide(base.0));
        }
        Ok(if any_depth {
            Self::AnyDepth(base)
        } else {
            Self::OneLabel(base)
        })
    }
}

impl TryFrom<String> for DomainWidth {
    type Error = RuleError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<DomainWidth> for String {
    fn from(width: DomainWidth) -> Self {
        width.to_string()
    }
}

impl FromStr for DomainWidth {
    type Err = RuleError;

    /// Parse the form of the proxy: `name`, `*.base` or `**.base`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(base) = s.strip_prefix("**.") {
            Self::wildcard(base.parse()?, true)
        } else if let Some(base) = s.strip_prefix("*.") {
            Self::wildcard(base.parse()?, false)
        } else {
            s.parse().map(Self::Exact)
        }
    }
}

impl fmt::Display for DomainWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => write!(f, "{name}"),
            Self::OneLabel(base) => write!(f, "*.{base}"),
            Self::AnyDepth(base) => write!(f, "**.{base}"),
        }
    }
}

/// What a rule covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// File accesses of one kind within a width.
    File {
        /// The kind that the rule permits or refuses.
        kind: FileKind,
        /// The paths.
        width: PathWidth,
    },
    /// Connections to domains.
    Domain(DomainWidth),
    /// Connections to one Unix socket. A socket rule is always exact.
    UnixSocket(RulePath),
    /// Connections to one port on the loopback of the host.
    Localhost(NonZeroU16),
}

/// The text of a target, as `read /home/u/.cargo/**`: a subtree ends with
/// `/**`. The text holds the path or the name as it is, so a caller that
/// prints it escapes it.
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { kind, width } => match width {
                PathWidth::Exact(p) => write!(f, "{} {}", kind.name(), p.as_path().display()),
                PathWidth::Subtree(base) => {
                    let base = base.as_path().display().to_string();
                    let sep = if base.ends_with('/') { "" } else { "/" };
                    write!(f, "{} {base}{sep}**", kind.name())
                }
            },
            Self::Domain(width) => write!(f, "domain {width}"),
            Self::UnixSocket(p) => write!(f, "unix-socket {}", p.as_path().display()),
            Self::Localhost(port) => write!(f, "localhost {port}"),
        }
    }
}

/// The decision of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Permit the access.
    Allow,
    /// Refuse the access.
    Deny,
}

impl Decision {
    /// The name of the decision, as the rule file writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Who made a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The human, in `pent monitor` or with `pent allow`.
    Human,
    /// The judge model.
    Model,
}

impl Source {
    /// The name of the source, as the rule file writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Model => "model",
        }
    }
}

/// One answer that pent keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// What the rule covers.
    pub target: Target,
    /// Allow or deny.
    pub decision: Decision,
    /// Who made the rule.
    pub source: Source,
    /// When the rule was made.
    pub created: SystemTime,
}

/// How specific a match is. A larger value wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    /// 1 for an exact match, 0 for a subtree or a wildcard.
    exact: u8,
    /// The depth of the subtree, or the number of labels of the wildcard.
    depth: usize,
}

impl Rule {
    /// Return the rank of the match if this rule covers `access`.
    fn matches(&self, access: &Access<'_>) -> Option<Rank> {
        match (&self.target, access) {
            (Target::File { kind, width }, Access::File { kind: want, path }) => {
                if !kind.covers(*want) {
                    return None;
                }
                match width {
                    PathWidth::Exact(p) => (p == *path).then_some(Rank {
                        exact: 1,
                        depth: p.depth(),
                    }),
                    PathWidth::Subtree(base) => {
                        path.as_path().starts_with(base.as_path()).then(|| Rank {
                            exact: 0,
                            depth: base.depth(),
                        })
                    }
                }
            }
            (Target::Domain(width), Access::Domain(name)) => domain_rank(width, name),
            (Target::UnixSocket(p), Access::UnixSocket(want)) => (p == *want).then_some(Rank {
                exact: 1,
                depth: p.depth(),
            }),
            (Target::Localhost(port), Access::Localhost(want)) => {
                (port == want).then_some(Rank { exact: 1, depth: 0 })
            }
            _ => None,
        }
    }
}

/// Return the rank if the domain width covers `name`.
fn domain_rank(width: &DomainWidth, name: &DomainName) -> Option<Rank> {
    match width {
        DomainWidth::Exact(d) => (d == name).then(|| Rank {
            exact: 1,
            depth: d.labels(),
        }),
        DomainWidth::OneLabel(base) | DomainWidth::AnyDepth(base) => {
            let prefix = name
                .as_str()
                .strip_suffix(base.as_str())?
                .strip_suffix('.')?;
            let one_label = !prefix.is_empty() && !prefix.contains('.');
            let fits = match width {
                DomainWidth::OneLabel(_) => one_label,
                _ => !prefix.is_empty(),
            };
            fits.then(|| Rank {
                exact: 0,
                depth: base.labels(),
            })
        }
    }
}

/// The rules of one root program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    /// The key: the file name of the root program.
    pub key: RuleKey,
    /// The rules, in no particular order.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// An empty set for `key`.
    #[must_use]
    pub const fn new(key: RuleKey) -> Self {
        Self {
            key,
            rules: Vec::new(),
        }
    }

    /// Return the decision of the most specific rule that covers `access`,
    /// or `None` when no rule covers it. On a tie, `Deny` wins.
    #[must_use]
    pub fn decide(&self, access: &Access<'_>) -> Option<Decision> {
        self.rules
            .iter()
            .filter_map(|rule| rule.matches(access).map(|rank| (rank, rule.decision)))
            .max_by(|(ra, da), (rb, db)| {
                ra.cmp(rb)
                    .then_with(|| (*da == Decision::Deny).cmp(&(*db == Decision::Deny)))
            })
            .map(|(_, decision)| decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), RuleError>;

    fn path(p: &str) -> Result<RulePath, RuleError> {
        RulePath::new(p)
    }

    fn rule(target: Target, decision: Decision) -> Rule {
        Rule {
            target,
            decision,
            source: Source::Human,
            created: SystemTime::UNIX_EPOCH,
        }
    }

    fn file(kind: FileKind, width: PathWidth, decision: Decision) -> Rule {
        rule(Target::File { kind, width }, decision)
    }

    fn read(path: &RulePath) -> Access<'_> {
        Access::File {
            kind: FileKind::Read,
            path,
        }
    }

    fn list(path: &RulePath) -> Access<'_> {
        Access::File {
            kind: FileKind::List,
            path,
        }
    }

    fn set(rules: Vec<Rule>) -> Result<RuleSet, RuleError> {
        Ok(RuleSet {
            key: "claude".parse()?,
            rules,
        })
    }

    #[test]
    fn a_key_comes_from_the_file_name_of_the_command() -> TestResult {
        assert_eq!(
            RuleKey::from_command("~/.local/bin/claude")?.as_str(),
            "claude"
        );
        assert_eq!(RuleKey::from_command("cargo")?.as_str(), "cargo");
        assert!(matches!(
            RuleKey::from_command("/"),
            Err(RuleError::NoBasename(_))
        ));
        assert!(matches!(
            ".hidden".parse::<RuleKey>(),
            Err(RuleError::InvalidKey(_))
        ));
        assert!(matches!(
            "a/b".parse::<RuleKey>(),
            Err(RuleError::InvalidKey(_))
        ));
        assert!(matches!("".parse::<RuleKey>(), Err(RuleError::EmptyKey)));
        assert!(matches!(
            "x".repeat(65).parse::<RuleKey>(),
            Err(RuleError::KeyTooLong(_))
        ));
        Ok(())
    }

    #[test]
    fn a_rule_path_has_one_normal_form_and_no_nul() -> TestResult {
        for (text, normal) in [
            ("//home//u/x/", "/home/u/x"),
            ("/home/./u", "/home/u"),
            ("/", "/"),
        ] {
            let p = RulePath::new(text)?;
            assert_eq!(p.as_path().as_os_str(), normal, "{text}");
        }
        assert_eq!(RulePath::new("//a//b/")?, RulePath::new("/a/b")?);
        assert!(matches!(
            RulePath::new("/run/x\0y"),
            Err(RuleError::PathHasNul(_))
        ));
        Ok(())
    }

    #[test]
    fn a_rule_path_is_absolute_and_normal() {
        assert!(RulePath::new("/home/u/x").is_ok());
        assert!(matches!(
            RulePath::new("home/u"),
            Err(RuleError::RelativePath(_))
        ));
        assert!(matches!(
            RulePath::new("/home/u/../v"),
            Err(RuleError::PathNotNormal(_))
        ));
    }

    #[test]
    fn a_domain_name_is_normalized_and_checked() -> TestResult {
        assert_eq!(
            "API.Example.COM.".parse::<DomainName>()?.as_str(),
            "api.example.com"
        );
        for bad in ["", "a..b", "-a.com", "a-.com", "a_b.com", "a b.com"] {
            assert!(
                bad.parse::<DomainName>().is_err(),
                "{bad:?} must be refused"
            );
        }
        Ok(())
    }

    #[test]
    fn each_file_kind_covers_the_expected_kinds() {
        use FileKind::{Exec, List, Read, Write};
        let all = [List, Read, Write, Exec];
        let expect = |rule: FileKind| -> Vec<FileKind> {
            all.into_iter().filter(|a| rule.covers(*a)).collect()
        };
        assert_eq!(expect(List), vec![List]);
        assert_eq!(expect(Read), vec![List, Read]);
        assert_eq!(expect(Write), vec![List, Read, Write]);
        assert_eq!(expect(Exec), vec![List, Read, Exec]);
    }

    #[test]
    fn a_subtree_covers_the_paths_below_it_and_not_its_siblings() -> TestResult {
        let rules = set(vec![file(
            FileKind::Read,
            PathWidth::Subtree(path("/home/u/.cargo/registry")?),
            Decision::Allow,
        )])?;
        let inside = path("/home/u/.cargo/registry/src/x.rs")?;
        let base = path("/home/u/.cargo/registry")?;
        let sibling = path("/home/u/.cargo/registry-old/x")?;
        let parent = path("/home/u/.cargo/config.toml")?;
        assert_eq!(rules.decide(&read(&inside)), Some(Decision::Allow));
        assert_eq!(rules.decide(&read(&base)), Some(Decision::Allow));
        assert_eq!(rules.decide(&read(&sibling)), None);
        assert_eq!(rules.decide(&read(&parent)), None);
        // A read rule does not permit a write.
        let write = Access::File {
            kind: FileKind::Write,
            path: &inside,
        };
        assert_eq!(rules.decide(&write), None);
        Ok(())
    }

    #[test]
    fn an_exact_list_rule_covers_only_that_directory() -> TestResult {
        let rules = set(vec![file(
            FileKind::List,
            PathWidth::Exact(path("/home/u")?),
            Decision::Allow,
        )])?;
        let home = path("/home/u")?;
        let below = path("/home/u/notes")?;
        assert_eq!(rules.decide(&list(&home)), Some(Decision::Allow));
        assert_eq!(rules.decide(&list(&below)), None);
        // A list rule gives the names, not the content.
        let read = Access::File {
            kind: FileKind::Read,
            path: &home,
        };
        assert_eq!(rules.decide(&read), None);
        Ok(())
    }

    #[test]
    fn the_most_specific_rule_wins() -> TestResult {
        let rules = set(vec![
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/x")?),
                Decision::Allow,
            ),
            file(
                FileKind::Read,
                PathWidth::Exact(path("/home/u/x/secret")?),
                Decision::Deny,
            ),
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u")?),
                Decision::Deny,
            ),
        ])?;
        assert_eq!(
            rules.decide(&read(&path("/home/u/x/secret")?)),
            Some(Decision::Deny)
        );
        assert_eq!(
            rules.decide(&read(&path("/home/u/x/a")?)),
            Some(Decision::Allow)
        );
        assert_eq!(
            rules.decide(&read(&path("/home/u/y")?)),
            Some(Decision::Deny)
        );
        Ok(())
    }

    #[test]
    fn deny_wins_a_tie() -> TestResult {
        let p = path("/home/u/x")?;
        let rules = set(vec![
            file(FileKind::Read, PathWidth::Exact(p.clone()), Decision::Allow),
            file(FileKind::Write, PathWidth::Exact(p.clone()), Decision::Deny),
        ])?;
        let read = Access::File {
            kind: FileKind::Read,
            path: &p,
        };
        assert_eq!(rules.decide(&read), Some(Decision::Deny));
        Ok(())
    }

    #[test]
    fn domain_widths_follow_the_proxy() -> TestResult {
        let name = |s: &str| s.parse::<DomainName>();
        let rules = set(vec![
            rule(
                Target::Domain(DomainWidth::Exact(name("api.example.com")?)),
                Decision::Allow,
            ),
            rule(
                Target::Domain(DomainWidth::wildcard(name("npmjs.org")?, false)?),
                Decision::Allow,
            ),
            rule(
                Target::Domain(DomainWidth::wildcard(name("cdn.net.example")?, true)?),
                Decision::Allow,
            ),
        ])?;
        let decide = |s: &str| -> Result<Option<Decision>, RuleError> {
            Ok(rules.decide(&Access::Domain(&name(s)?)))
        };
        assert_eq!(decide("api.example.com")?, Some(Decision::Allow));
        assert_eq!(decide("www.example.com")?, None);
        assert_eq!(decide("registry.npmjs.org")?, Some(Decision::Allow));
        assert_eq!(
            decide("npmjs.org")?,
            None,
            "a wildcard does not cover its base"
        );
        assert_eq!(decide("a.b.npmjs.org")?, None, "*. is one label");
        assert_eq!(
            decide("a.b.cdn.net.example")?,
            Some(Decision::Allow),
            "**. is any depth"
        );
        assert_eq!(decide("evilnpmjs.org")?, None);
        Ok(())
    }

    #[test]
    fn a_wildcard_cannot_cover_a_public_suffix() -> TestResult {
        for base in ["com", "co.uk", "github.io"] {
            let result = DomainWidth::wildcard(base.parse()?, false);
            assert!(
                matches!(result, Err(RuleError::WildcardTooWide(_))),
                "{base}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_domain_width_parses_the_form_of_the_proxy() -> TestResult {
        for text in ["api.example.com", "*.npmjs.org", "**.cdn.example"] {
            assert_eq!(text.parse::<DomainWidth>()?.to_string(), text);
        }
        assert!(matches!(
            "*.co.uk".parse::<DomainWidth>(),
            Err(RuleError::WildcardTooWide(_))
        ));
        assert!(matches!(
            "*.".parse::<DomainWidth>(),
            Err(RuleError::InvalidDomain(_))
        ));
        assert!(matches!(
            "a.*.com".parse::<DomainWidth>(),
            Err(RuleError::InvalidDomain(_))
        ));
        Ok(())
    }

    #[test]
    fn sockets_and_ports_match_exactly() -> TestResult {
        let sock = path("/run/user/1000/docker.sock")?;
        let other = path("/run/user/1000/other.sock")?;
        let port = NonZeroU16::new(5432).ok_or(RuleError::EmptyKey)?;
        let port2 = NonZeroU16::new(5433).ok_or(RuleError::EmptyKey)?;
        let rules = set(vec![
            rule(Target::UnixSocket(sock.clone()), Decision::Deny),
            rule(Target::Localhost(port), Decision::Allow),
        ])?;
        assert_eq!(
            rules.decide(&Access::UnixSocket(&sock)),
            Some(Decision::Deny)
        );
        assert_eq!(rules.decide(&Access::UnixSocket(&other)), None);
        assert_eq!(
            rules.decide(&Access::Localhost(port)),
            Some(Decision::Allow)
        );
        assert_eq!(rules.decide(&Access::Localhost(port2)), None);
        // A file rule never answers a socket access.
        let file_rules = set(vec![file(
            FileKind::Write,
            PathWidth::Subtree(path("/run/user/1000")?),
            Decision::Allow,
        )])?;
        assert_eq!(file_rules.decide(&Access::UnixSocket(&sock)), None);
        Ok(())
    }

    #[test]
    fn a_target_has_a_short_text() -> TestResult {
        let file = |kind, width| Target::File { kind, width };
        let port = NonZeroU16::new(8080).ok_or(RuleError::EmptyKey)?;
        for (target, text) in [
            (
                file(FileKind::Read, PathWidth::Exact(path("/etc/hosts")?)),
                "read /etc/hosts",
            ),
            (
                file(FileKind::Write, PathWidth::Subtree(path("/home/u/.cargo")?)),
                "write /home/u/.cargo/**",
            ),
            (
                file(FileKind::Exec, PathWidth::Subtree(path("/")?)),
                "exec /**",
            ),
            (
                file(FileKind::List, PathWidth::Exact(path("/tmp")?)),
                "list /tmp",
            ),
            (Target::Domain("*.npmjs.org".parse()?), "domain *.npmjs.org"),
            (
                Target::UnixSocket(path("/run/x.sock")?),
                "unix-socket /run/x.sock",
            ),
            (Target::Localhost(port), "localhost 8080"),
        ] {
            assert_eq!(target.to_string(), text);
        }
        Ok(())
    }
}
