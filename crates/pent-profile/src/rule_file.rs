//! The rule file: the TOML form of a [`RuleSet`].
//!
//! Pent keeps one file for each key, `~/.local/state/pent/rules/<key>.toml`.
//! A user can read and edit it:
//!
//! ```toml
//! version = 1
//!
//! [[rule]]
//! kind = "read"
//! width = "subtree"
//! path = "/home/u/.cargo/registry"
//! decision = "allow"
//! source = "human"
//! created = 2026-11-22T12:00:00Z
//!
//! # Why I allow this.
//! [[rule]]
//! kind = "domain"
//! domain = "*.npmjs.org"
//! decision = "allow"
//! source = "model"
//! created = 2026-11-22T12:00:05Z
//! ```
//!
//! The kinds are `list`, `read`, `write` and `exec` (with `width` and
//! `path`), `domain` (with `domain`), `unix-socket` (with `path`) and
//! `localhost` (with `port`). An unknown field, a missing field and a field
//! of another kind are errors. The date has whole seconds: pent drops a
//! fraction of a second when it reads the file.
//!
//! [`RuleSet::update_toml`] changes an existing file and keeps the comments
//! and the form of each rule that stays. The file does not hold the key: the
//! file name gives it.

use std::fmt;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use toml::value::{Date, Datetime, Offset, Time};
use toml_edit::{ArrayOfTables, DocumentMut, Item};

use crate::rule::{
    Decision, DomainWidth, FileKind, PathWidth, Rule, RuleError, RuleKey, RulePath, RuleSet,
    Source, Target,
};

/// The version of the format that this code reads and writes.
const VERSION: u32 = 1;

/// The last second that a TOML date can hold: 9999-12-31T23:59:59Z.
const MAX_SECS: u64 = 253_402_300_799;

/// The number of seconds in a day.
const DAY_SECS: u64 = 86_400;

/// The name of the array of rules in the file.
const RULE_TABLE: &str = "rule";

/// The text at the start of each new file that pent writes.
const HEADER: &str = "\
# The rules of pent for one program. Each rule is one answer.
# You can edit this file, and pent keeps your comments.
# Remove a rule and pent asks again.

";

/// An error in a rule file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleFileError {
    /// The file is not valid TOML, or it has an unknown field. The message
    /// names the field and its line.
    #[error("{0}")]
    Syntax(#[from] toml::de::Error),
    /// The file has a version that this pent does not know. Pent checks the
    /// version before the fields, so a file of a newer pent gives this
    /// error and not an unknown field.
    #[error("the version {0} is not known; this pent reads version {VERSION}")]
    Version(u32),
    /// One rule is not valid.
    #[error("rule {index}: {source}")]
    Entry {
        /// The number of the rule in the file, from 1.
        index: usize,
        /// The problem.
        source: EntryError,
    },
    /// A date is before 1970 or after 9999, so TOML cannot hold it.
    #[error("the date of a rule is before 1970 or after 9999")]
    TimeOutOfRange,
    /// Pent cannot encode the rules as TOML.
    #[error("cannot encode the rules: {0}")]
    Encode(#[from] toml::ser::Error),
    /// Pent cannot encode one rule as a TOML table.
    #[error("cannot encode a rule: {0}")]
    EncodeTable(#[from] toml_edit::ser::Error),
    /// The editor of the file cannot parse the text.
    #[error("{0}")]
    Edit(#[from] toml_edit::TomlError),
}

/// A problem in one rule of a file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    /// A field that the kind needs is missing.
    #[error("the field `{field}` is missing")]
    Missing {
        /// The name of the field.
        field: &'static str,
    },
    /// A field does not belong to the kind.
    #[error("the field `{field}` is not permitted in a rule of the kind \"{kind}\"")]
    NotPermitted {
        /// The name of the field.
        field: &'static str,
        /// The kind of the rule.
        kind: Kind,
    },
    /// A path or a domain is not valid.
    #[error(transparent)]
    Value(#[from] RuleError),
    /// The date has no date part, no time part or no offset, it does not
    /// exist, or it is not from 1970 to 9999 in UTC.
    #[error(
        "the date {0} is not a full date and time with an offset from 1970 to 9999, \
         for example 2026-11-22T12:00:00Z"
    )]
    Date(Datetime),
}

/// The kind of a rule in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A file rule of the kind [`FileKind::List`].
    List,
    /// A file rule of the kind [`FileKind::Read`].
    Read,
    /// A file rule of the kind [`FileKind::Write`].
    Write,
    /// A file rule of the kind [`FileKind::Exec`].
    Exec,
    /// A [`Target::Domain`] rule.
    Domain,
    /// A [`Target::UnixSocket`] rule.
    UnixSocket,
    /// A [`Target::Localhost`] rule.
    Localhost,
}

/// The group of a kind: the shape of its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    File(FileKind),
    Domain,
    UnixSocket,
    Localhost,
}

impl Kind {
    /// The kind of a rule with this target.
    const fn of_target(target: &Target) -> Self {
        match target {
            Target::File { kind, .. } => match kind {
                FileKind::List => Self::List,
                FileKind::Read => Self::Read,
                FileKind::Write => Self::Write,
                FileKind::Exec => Self::Exec,
            },
            Target::Domain(_) => Self::Domain,
            Target::UnixSocket(_) => Self::UnixSocket,
            Target::Localhost(_) => Self::Localhost,
        }
    }

    /// The group of this kind.
    const fn group(self) -> Group {
        match self {
            Self::List => Group::File(FileKind::List),
            Self::Read => Group::File(FileKind::Read),
            Self::Write => Group::File(FileKind::Write),
            Self::Exec => Group::File(FileKind::Exec),
            Self::Domain => Group::Domain,
            Self::UnixSocket => Group::UnixSocket,
            Self::Localhost => Group::Localhost,
        }
    }

    /// The name in the file.
    const fn name(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Read => "read",
            Self::Write => "write",
            Self::Exec => "exec",
            Self::Domain => "domain",
            Self::UnixSocket => "unix-socket",
            Self::Localhost => "localhost",
        }
    }

    /// The fields that a rule of this kind has, other than `kind`,
    /// `decision`, `source` and `created`.
    const fn fields(self) -> &'static [&'static str] {
        match self.group() {
            Group::File(_) => &["width", "path"],
            Group::Domain => &["domain"],
            Group::UnixSocket => &["path"],
            Group::Localhost => &["port"],
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The width of a file rule in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Width {
    Exact,
    Subtree,
}

/// The version alone. Pent reads it before the strict parse.
#[derive(Debug, Deserialize)]
struct VersionOnly {
    version: Option<u32>,
}

/// The whole file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDoc {
    version: u32,
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    rules: Vec<Entry>,
}

/// One `[[rule]]` table.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    width: Option<Width>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<NonZeroU16>,
    decision: Decision,
    source: Source,
    created: Datetime,
}

impl Entry {
    /// Make the entry of `rule`.
    fn from_rule(rule: &Rule) -> Result<Self, RuleFileError> {
        let mut entry = Self {
            kind: Kind::of_target(&rule.target),
            width: None,
            path: None,
            domain: None,
            port: None,
            decision: rule.decision,
            source: rule.source,
            created: to_datetime(rule.created)?,
        };
        match &rule.target {
            Target::File { width, .. } => {
                let (width, path) = match width {
                    PathWidth::Exact(p) => (Width::Exact, p),
                    PathWidth::Subtree(p) => (Width::Subtree, p),
                };
                entry.width = Some(width);
                entry.path = Some(path.as_path().to_path_buf());
            }
            Target::Domain(width) => entry.domain = Some(width.to_string()),
            Target::UnixSocket(p) => entry.path = Some(p.as_path().to_path_buf()),
            Target::Localhost(port) => entry.port = Some(*port),
        }
        Ok(entry)
    }

    /// Check the entry and make its rule.
    fn into_rule(self) -> Result<Rule, EntryError> {
        let kind = self.kind;
        let present = [
            ("width", self.width.is_some()),
            ("path", self.path.is_some()),
            ("domain", self.domain.is_some()),
            ("port", self.port.is_some()),
        ];
        if let Some((field, _)) = present
            .iter()
            .find(|(field, here)| *here && !kind.fields().contains(field))
        {
            return Err(EntryError::NotPermitted { field, kind });
        }
        let missing = |field| EntryError::Missing { field };
        let target = match kind.group() {
            Group::File(file_kind) => {
                let path = RulePath::new(self.path.ok_or_else(|| missing("path"))?)?;
                let width = match self.width.ok_or_else(|| missing("width"))? {
                    Width::Exact => PathWidth::Exact(path),
                    Width::Subtree => PathWidth::Subtree(path),
                };
                Target::File {
                    kind: file_kind,
                    width,
                }
            }
            Group::Domain => Target::Domain(
                self.domain
                    .ok_or_else(|| missing("domain"))?
                    .parse::<DomainWidth>()?,
            ),
            Group::UnixSocket => {
                Target::UnixSocket(RulePath::new(self.path.ok_or_else(|| missing("path"))?)?)
            }
            Group::Localhost => Target::Localhost(self.port.ok_or_else(|| missing("port"))?),
        };
        Ok(Rule {
            target,
            decision: self.decision,
            source: self.source,
            created: from_datetime(&self.created).ok_or(EntryError::Date(self.created))?,
        })
    }

    /// The entry as a TOML table for `[[rule]]`.
    fn to_table(&self) -> Result<toml_edit::Table, RuleFileError> {
        let doc = toml_edit::ser::to_document(self)?;
        let mut table = doc.as_table().clone();
        table.set_implicit(false);
        table.decor_mut().set_prefix("\n");
        Ok(table)
    }
}

impl RuleSet {
    /// Parse the text of the rule file of `key`.
    ///
    /// # Errors
    /// Returns an error if the text is not valid TOML, if it has an unknown
    /// version or an unknown field, or if a rule is not valid. The error
    /// names the field or the rule.
    pub fn from_toml(key: RuleKey, text: &str) -> Result<Self, RuleFileError> {
        // The version comes first: a newer file can have fields that this
        // pent does not know.
        let VersionOnly { version } = toml::from_str(text)?;
        if let Some(version) = version.filter(|v| *v != VERSION) {
            return Err(RuleFileError::Version(version));
        }
        let doc: FileDoc = toml::from_str(text)?;
        let rules = doc
            .rules
            .into_iter()
            .enumerate()
            .map(|(i, entry)| {
                entry.into_rule().map_err(|source| RuleFileError::Entry {
                    index: i.saturating_add(1),
                    source,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { key, rules })
    }

    /// The text of a new rule file, with a header comment. Pent keeps the
    /// order of the rules and drops the fractions of a second.
    ///
    /// # Errors
    /// Returns an error if a date is before 1970 or after 9999, or if a path
    /// is not valid UTF-8.
    pub fn to_toml(&self) -> Result<String, RuleFileError> {
        let doc = FileDoc {
            version: VERSION,
            rules: self
                .rules
                .iter()
                .map(Entry::from_rule)
                .collect::<Result<_, _>>()?,
        };
        Ok(format!("{HEADER}{}", toml::to_string(&doc)?))
    }

    /// The text of the rule file `old` after a change to these rules.
    ///
    /// A rule of `old` that is also in this set keeps its table, with its
    /// comments, its form and its place. A rule of `old` that is not in
    /// this set loses its table and the comment above it. A rule of this set
    /// that is not in `old` gets a new table at the end. The other comments
    /// of the file stay. When the file has equal rules, the first copies in
    /// the file keep their tables, so the order of the rules can change. The
    /// order has no effect on a decision.
    ///
    /// # Errors
    /// Returns an error if `old` is not a valid rule file: pent does not
    /// write over a file that it cannot read. Also returns the errors of
    /// [`RuleSet::to_toml`].
    pub fn update_toml(&self, old: &str) -> Result<String, RuleFileError> {
        let old_rules = Self::from_toml(self.key.clone(), old)?.rules;
        let mut doc: DocumentMut = old.parse()?;

        // Match each old rule with one equal new rule, in order.
        let mut used = vec![false; self.rules.len()];
        let keep: Vec<bool> = old_rules
            .iter()
            .map(|old_rule| {
                let found = self
                    .rules
                    .iter()
                    .zip(used.iter_mut())
                    .find(|(rule, taken)| !**taken && *rule == old_rule);
                found.map(|(_, taken)| *taken = true).is_some()
            })
            .collect();
        let added = self
            .rules
            .iter()
            .zip(&used)
            .filter(|(_, taken)| !**taken)
            .map(|(rule, _)| Entry::from_rule(rule)?.to_table())
            .collect::<Result<Vec<_>, _>>()?;

        let tables = match doc.remove(RULE_TABLE) {
            None => ArrayOfTables::new(),
            Some(Item::ArrayOfTables(mut tables)) => {
                let mut index = 0_usize;
                tables.retain(|_| {
                    let kept = keep.get(index).copied().unwrap_or(false);
                    index = index.saturating_add(1);
                    kept
                });
                tables
            }
            // An inline array (`rule = [...]`) has no tables to keep, so
            // pent writes each kept rule again as a table.
            Some(_) => {
                let mut tables = ArrayOfTables::new();
                for (rule, kept) in old_rules.iter().zip(&keep) {
                    if *kept {
                        tables.push(Entry::from_rule(rule)?.to_table()?);
                    }
                }
                tables
            }
        };
        let mut tables = tables;
        for table in added {
            tables.push(table);
        }
        if !tables.is_empty() {
            doc.insert(RULE_TABLE, Item::ArrayOfTables(tables));
        }
        Ok(doc.to_string())
    }
}

// ── Dates ───────────────────────────────────────────────────────────────────
//
// The functions below use the algorithms of Howard Hinnant ("chrono-Compatible
// Low-Level Date Algorithms"). The years stay from 1970 to 9999, so the
// arithmetic on `i64` cannot overflow.

/// The date in UTC of `time`, in whole seconds.
fn to_datetime(time: SystemTime) -> Result<Datetime, RuleFileError> {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| RuleFileError::TimeOutOfRange)?
        .as_secs();
    if secs > MAX_SECS {
        return Err(RuleFileError::TimeOutOfRange);
    }
    let days = i64::try_from(secs / DAY_SECS).map_err(|_| RuleFileError::TimeOutOfRange)?;
    let rest = secs % DAY_SECS;
    let (year, month, day) = civil_from_days(days);
    let narrow = |v: u64| u8::try_from(v).map_err(|_| RuleFileError::TimeOutOfRange);
    Ok(Datetime {
        date: Some(Date {
            year: u16::try_from(year).map_err(|_| RuleFileError::TimeOutOfRange)?,
            month,
            day,
        }),
        time: Some(Time {
            hour: narrow(rest / 3600)?,
            minute: narrow(rest % 3600 / 60)?,
            second: narrow(rest % 60)?,
            nanosecond: 0,
        }),
        offset: Some(Offset::Z),
    })
}

/// The time of a full TOML date with an offset, in whole seconds. Returns
/// `None` for a date that does not exist, a time before 1970 or after
/// [`MAX_SECS`] in UTC, or a value without a date, a time or an offset.
fn from_datetime(dt: &Datetime) -> Option<SystemTime> {
    let date = dt.date?;
    let time = dt.time?;
    let offset_minutes = match dt.offset? {
        Offset::Z => 0,
        Offset::Custom { minutes } => i64::from(minutes),
    };
    let days = days_from_civil(i64::from(date.year), date.month, date.day);
    if civil_from_days(days) != (i64::from(date.year), date.month, date.day)
        || time.hour > 23
        || time.minute > 59
        || time.second > 60
    {
        return None;
    }
    let secs = days * 86_400
        + i64::from(time.hour) * 3600
        + i64::from(time.minute) * 60
        + i64::from(time.second)
        - offset_minutes * 60;
    let secs = u64::try_from(secs).ok().filter(|s| *s <= MAX_SECS)?;
    // The fraction of a second is dropped, as in `to_datetime`, so a load
    // and a save give the same rule.
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// The number of days from 1970-01-01 to the date.
fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let (month, day) = (i64::from(month), i64::from(day));
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of the day `days` after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // The day is from 1 to 31 and the month from 1 to 12, so they fit.
    let narrow = |v: i64| u8::try_from(v).unwrap_or(0);
    (year, narrow(month), narrow(day))
}

#[cfg(test)]
#[allow(clippy::panic)] // a test that reaches a branch it must not reach fails
mod tests {
    use super::*;

    fn key() -> RuleKey {
        match "claude".parse() {
            Ok(key) => key,
            Err(e) => panic!("{e}"),
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn parse(text: &str) -> Result<RuleSet, RuleFileError> {
        RuleSet::from_toml(key(), text)
    }

    fn entry_error(text: &str) -> Option<EntryError> {
        match parse(text) {
            Err(RuleFileError::Entry { source, .. }) => Some(source),
            _ => None,
        }
    }

    const ONE_RULE: &str = "
version = 1
[[rule]]
kind = \"read\"
width = \"exact\"
path = \"/home/u/x\"
decision = \"allow\"
source = \"human\"
created = 2026-11-22T12:00:00Z
";

    #[test]
    fn each_kind_survives_a_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let path = |p: &str| RulePath::new(p);
        let rule = |target, decision, source, secs| Rule {
            target,
            decision,
            source,
            created: at(secs),
        };
        let set = RuleSet {
            key: key(),
            rules: vec![
                rule(
                    Target::File {
                        kind: FileKind::List,
                        width: PathWidth::Exact(path("/home/u")?),
                    },
                    Decision::Allow,
                    Source::Human,
                    0,
                ),
                rule(
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Subtree(path("/home/u/.cargo")?),
                    },
                    Decision::Allow,
                    Source::Model,
                    1_795_000_000,
                ),
                rule(
                    Target::File {
                        kind: FileKind::Write,
                        width: PathWidth::Exact(path("/home/u/a b \"c\"")?),
                    },
                    Decision::Deny,
                    Source::Human,
                    MAX_SECS,
                ),
                rule(
                    Target::File {
                        kind: FileKind::Exec,
                        width: PathWidth::Subtree(path("/opt/tool")?),
                    },
                    Decision::Allow,
                    Source::Human,
                    951_782_400, // 2000-02-29
                ),
                rule(
                    Target::Domain("**.cdn.example".parse()?),
                    Decision::Allow,
                    Source::Model,
                    5,
                ),
                rule(
                    Target::Domain("api.example.com".parse()?),
                    Decision::Deny,
                    Source::Human,
                    6,
                ),
                rule(
                    Target::UnixSocket(path("/run/user/1000/docker.sock")?),
                    Decision::Deny,
                    Source::Human,
                    7,
                ),
                rule(
                    Target::Localhost(NonZeroU16::new(5432).ok_or("port")?),
                    Decision::Allow,
                    Source::Human,
                    8,
                ),
            ],
        };
        let text = set.to_toml()?;
        assert!(text.starts_with("# The rules of pent"), "{text}");
        assert!(text.contains("created = 2026-11-18T11:06:40Z"), "{text}");
        assert_eq!(RuleSet::from_toml(key(), &text)?, set);
        Ok(())
    }

    #[test]
    fn an_empty_set_has_only_the_version() -> Result<(), RuleFileError> {
        let text = RuleSet::new(key()).to_toml()?;
        assert!(text.ends_with("version = 1\n"), "{text}");
        assert_eq!(parse(&text)?.rules, vec![]);
        Ok(())
    }

    #[test]
    fn a_hand_edit_with_an_offset_and_comments_is_read() -> Result<(), RuleFileError> {
        let text = "
# my notes
version = 1

[[rule]]
kind = \"domain\"
domain = \"*.NPMJS.org\"   # the case does not matter
decision = \"allow\"
source = \"human\"
created = 2026-11-22T14:00:00+02:00
";
        let set = parse(text)?;
        assert_eq!(set.rules.len(), 1);
        let rule = set.rules.first().ok_or(RuleFileError::TimeOutOfRange)?;
        assert_eq!(
            rule.target,
            Target::Domain(
                "*.npmjs.org"
                    .parse()
                    .map_err(|_| RuleFileError::TimeOutOfRange)?
            )
        );
        assert_eq!(rule.created, at(1_795_348_800));
        assert_eq!(parse(ONE_RULE)?.rules.len(), 1);
        Ok(())
    }

    #[test]
    fn an_unknown_field_is_an_error_that_names_it() {
        for (text, name) in [
            (format!("{ONE_RULE}colour = \"red\"\n"), "colour"),
            (format!("extra = 1\n{ONE_RULE}"), "extra"),
        ] {
            match parse(&text) {
                Err(e @ RuleFileError::Syntax(_)) => {
                    assert!(e.to_string().contains(name), "{e}");
                }
                other => panic!("{name}: {other:?}"),
            }
        }
        let bad_kind = ONE_RULE.replace("\"read\"", "\"delete\"");
        match parse(&bad_kind) {
            Err(e @ RuleFileError::Syntax(_)) => assert!(e.to_string().contains("delete"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_field_of_another_kind_or_a_missing_field_is_an_error() {
        let with_port = ONE_RULE.replace("width", "port = 22\nwidth");
        assert_eq!(
            entry_error(&with_port),
            Some(EntryError::NotPermitted {
                field: "port",
                kind: Kind::Read
            })
        );
        let no_width = ONE_RULE.replace("width = \"exact\"\n", "");
        assert_eq!(
            entry_error(&no_width),
            Some(EntryError::Missing { field: "width" })
        );
        let socket = ONE_RULE.replace("\"read\"", "\"unix-socket\"");
        assert_eq!(
            entry_error(&socket),
            Some(EntryError::NotPermitted {
                field: "width",
                kind: Kind::UnixSocket
            })
        );
    }

    #[test]
    fn bad_values_are_errors() {
        let relative = ONE_RULE.replace("/home/u/x", "home/u/x");
        assert!(matches!(
            entry_error(&relative),
            Some(EntryError::Value(RuleError::RelativePath(_)))
        ));
        let wide = "version = 1\n[[rule]]\nkind = \"domain\"\ndomain = \"*.com\"\n\
                    decision = \"allow\"\nsource = \"human\"\ncreated = 2026-11-22T12:00:00Z\n";
        assert!(matches!(
            entry_error(wide),
            Some(EntryError::Value(RuleError::WildcardTooWide(_)))
        ));
        for date in [
            "2026-11-22",
            "2026-11-22T12:00:00",
            "12:00:00",
            "2026-02-30T12:00:00Z",
            "1969-12-31T23:59:59Z",
            // 9999-12-31T23:59:59-01:00 is after the last second in UTC, so
            // a save could not write it.
            "9999-12-31T23:59:59-01:00",
        ] {
            let text = ONE_RULE.replace("2026-11-22T12:00:00Z", date);
            assert!(
                matches!(entry_error(&text), Some(EntryError::Date(_)))
                    || matches!(parse(&text), Err(RuleFileError::Syntax(_))),
                "{date}: {:?}",
                parse(&text)
            );
        }
        let zero_port = "version = 1\n[[rule]]\nkind = \"localhost\"\nport = 0\n\
                         decision = \"allow\"\nsource = \"human\"\ncreated = 2026-11-22T12:00:00Z\n";
        assert!(matches!(parse(zero_port), Err(RuleFileError::Syntax(_))));
        let decision = ONE_RULE.replace("\"allow\"", "\"maybe\"");
        assert!(matches!(parse(&decision), Err(RuleFileError::Syntax(_))));
    }

    #[test]
    fn the_version_must_be_known() {
        assert_eq!(
            parse(&ONE_RULE.replace("version = 1", "version = 2")),
            Err(RuleFileError::Version(2))
        );
        // A newer file with a new field gives the version error, not an
        // unknown field.
        let newer = format!("{}expires = 2027-01-01T00:00:00Z\n", ONE_RULE)
            .replace("version = 1", "version = 2");
        assert_eq!(parse(&newer), Err(RuleFileError::Version(2)));
        assert!(matches!(parse(""), Err(RuleFileError::Syntax(_))));
    }

    #[test]
    fn a_fraction_of_a_second_is_dropped_on_the_load() -> Result<(), RuleFileError> {
        let text = ONE_RULE.replace("12:00:00Z", "12:00:00.5Z");
        let set = parse(&text)?;
        let rule = set.rules.first().ok_or(RuleFileError::TimeOutOfRange)?;
        assert_eq!(rule.created, at(1_795_348_800));
        // A load, a save and a load give the same rules.
        assert_eq!(parse(&set.to_toml()?)?, set);
        assert_eq!(parse(&set.update_toml(&text)?)?, set);
        Ok(())
    }

    #[test]
    fn a_time_out_of_range_cannot_be_written() -> Result<(), RuleError> {
        let mut set = RuleSet::new(key());
        set.rules.push(Rule {
            target: Target::Localhost(NonZeroU16::MIN),
            decision: Decision::Allow,
            source: Source::Human,
            created: at(MAX_SECS + 1),
        });
        assert_eq!(set.to_toml(), Err(RuleFileError::TimeOutOfRange));
        Ok(())
    }

    /// A file that a user edited: a header, a comment above each rule, an
    /// inline comment, a domain in upper case and a trailing comment.
    const EDITED: &str = "\
# my header
version = 1

# keep me
[[rule]]
kind = \"localhost\"
port = 22 # ssh
decision = \"allow\"
source = \"human\"
created = 2026-11-22T12:00:00Z

# drop me
[[rule]]
kind = \"localhost\"
port = 23
decision = \"allow\"
source = \"human\"
created = 2026-11-22T12:00:00Z

# also keep me
[[rule]]
kind = \"domain\"
domain = \"API.Example.COM\"
decision = \"deny\"
source = \"human\"
created = 2026-11-22T12:00:00Z

# trailing note
";

    fn port_rule(port: u16, secs: u64) -> Rule {
        Rule {
            target: Target::Localhost(NonZeroU16::new(port).unwrap_or(NonZeroU16::MIN)),
            decision: Decision::Allow,
            source: Source::Model,
            created: at(secs),
        }
    }

    #[test]
    fn an_update_keeps_the_comments_and_the_form_of_each_kept_rule() -> Result<(), RuleFileError> {
        let mut set = parse(EDITED)?;
        set.rules.remove(1);
        set.rules.push(port_rule(5432, 7));
        let text = set.update_toml(EDITED)?;

        for kept in [
            "# my header",
            "# keep me",
            "port = 22 # ssh",
            "# also keep me",
            "domain = \"API.Example.COM\"",
            "# trailing note",
        ] {
            assert!(text.contains(kept), "{kept:?} is lost:\n{text}");
        }
        assert!(!text.contains("# drop me"), "{text}");
        assert!(!text.contains("port = 23"), "{text}");
        // The kept rules stay in their place, and the new rule comes last.
        let order: Vec<_> = ["port = 22", "API.Example.COM", "port = 5432"]
            .iter()
            .map(|s| text.find(s))
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
        assert_eq!(parse(&text)?, set);
        Ok(())
    }

    #[test]
    fn an_update_with_no_change_gives_the_same_text() -> Result<(), RuleFileError> {
        assert_eq!(parse(EDITED)?.update_toml(EDITED)?, EDITED);
        Ok(())
    }

    #[test]
    fn an_update_keeps_one_table_for_each_copy_of_a_rule() -> Result<(), RuleFileError> {
        // Two equal rules in the file and one in the set: one table stays.
        let twice = format!("{ONE_RULE}{}", &ONE_RULE["\nversion = 1".len()..]);
        let mut set = parse(&twice)?;
        assert_eq!(set.rules.len(), 2);
        set.rules.pop();
        let text = set.update_toml(&twice)?;
        assert_eq!(text.matches("[[rule]]").count(), 1, "{text}");
        assert_eq!(parse(&text)?, set);
        Ok(())
    }

    #[test]
    fn an_update_with_equal_rules_keeps_the_first_copies() -> Result<(), RuleFileError> {
        let a = port_rule(22, 1);
        let b = port_rule(80, 2);
        let mut set = RuleSet::new(key());
        set.rules = vec![a.clone(), b.clone(), a.clone(), b.clone()];
        let text = set.to_toml()?;
        // Remove the first copy of `a`: the file keeps the first copy and
        // drops the second, with the same rules in another order.
        set.rules.remove(0);
        let after = parse(&set.update_toml(&text)?)?;
        assert_eq!(after.rules, vec![a, b.clone(), b]);
        Ok(())
    }

    #[test]
    fn an_update_to_no_rules_keeps_the_other_comments() -> Result<(), RuleFileError> {
        let text = RuleSet::new(key()).update_toml(EDITED)?;
        assert_eq!(text, "# my header\nversion = 1\n\n# trailing note\n");
        assert!(parse(&text)?.rules.is_empty());
        Ok(())
    }

    #[test]
    fn an_update_of_an_inline_array_writes_tables() -> Result<(), RuleFileError> {
        let inline = "version = 1\nrule = [{kind = \"localhost\", port = 22, \
                      decision = \"allow\", source = \"human\", created = 2026-11-22T12:00:00Z}]\n";
        let mut set = parse(inline)?;
        set.rules.push(port_rule(80, 9));
        let text = set.update_toml(inline)?;
        assert_eq!(text.matches("[[rule]]").count(), 2, "{text}");
        assert_eq!(parse(&text)?, set);
        Ok(())
    }

    #[test]
    fn an_update_refuses_a_file_that_is_not_valid() {
        let set = RuleSet::new(key());
        assert!(matches!(
            set.update_toml("version = 1\ncolour = 1\n"),
            Err(RuleFileError::Syntax(_))
        ));
        assert!(matches!(
            set.update_toml(&ONE_RULE.replace("/home/u/x", "x")),
            Err(RuleFileError::Entry { .. })
        ));
    }

    #[test]
    fn each_kind_maps_to_its_group_and_back() {
        let kinds = [
            Kind::List,
            Kind::Read,
            Kind::Write,
            Kind::Exec,
            Kind::Domain,
            Kind::UnixSocket,
            Kind::Localhost,
        ];
        let path = RulePath::new("/x").unwrap_or_else(|e| panic!("{e}"));
        for kind in kinds {
            let target = match kind.group() {
                Group::File(file_kind) => Target::File {
                    kind: file_kind,
                    width: PathWidth::Exact(path.clone()),
                },
                Group::Domain => Target::Domain(DomainWidth::Exact(
                    "a.example".parse().unwrap_or_else(|e| panic!("{e}")),
                )),
                Group::UnixSocket => Target::UnixSocket(path.clone()),
                Group::Localhost => Target::Localhost(NonZeroU16::MIN),
            };
            assert_eq!(Kind::of_target(&target), kind);
        }
    }

    #[test]
    fn the_date_functions_agree() {
        for days in [0, 59, 60, 365, 10_957, 11_016, 20_414, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
