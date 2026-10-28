//! Text output for a summary and a profile.
//!
//! - [`render_terminal`]: the summary block at the end of `pent watch`.
//! - [`render_draft`]: the draft file, with one comment for each rule.
//! - [`render_profile`]: a profile for `pent trust` and `pent profile show`,
//!   with the reasons when they are known.
//!
//! The functions replace the control characters and the Unicode format
//! characters in paths, names and reasons with escapes, so the output cannot
//! change the state of the terminal and cannot change the order of the text.
//! [`safe_lines`] does the same for a whole file text: `pent trust` and
//! `pent profile show` print the draft or the profile file as it is.

use std::borrow::Cow;
use std::collections::HashMap;

use serde::Deserialize;

use crate::summary::{format_count, FsAccess, Grant, Item, ItemNote, Section, Summary};
use crate::{GuardClass, ProfileDoc, ProfileName};

/// The maximum width of the first column. A longer label pushes its reason
/// to the right, but the other lines keep their alignment.
const LABEL_CAP: usize = 40;

/// The sections in the order of the summary.
pub(crate) const SECTIONS: [Section; 7] = [
    Section::ReadWrite,
    Section::Read,
    Section::Execute,
    Section::UnixSockets,
    Section::Network,
    Section::Localhost,
    Section::Blocked,
];

/// The information for the first lines of [`render_terminal`].
#[derive(Debug, Clone, Copy)]
pub struct WatchHeader<'a> {
    /// The profile name.
    pub name: &'a ProfileName,
    /// Where the events come from. A review of denied accesses has
    /// [`DraftSource::DeniedReview`].
    pub source: DraftSource,
}

/// Return the title of a section.
#[must_use]
pub const fn section_title(section: Section) -> &'static str {
    match section {
        Section::ReadWrite => "Read-write",
        Section::Read => "Read",
        Section::Execute => "Execute",
        Section::UnixSockets => "Unix sockets",
        Section::Network => "Network",
        Section::Localhost => "Localhost ports",
        Section::Blocked => "Blocked by the guard",
    }
}

/// Return the text of a guard class for the user.
#[must_use]
pub const fn class_label(class: GuardClass) -> &'static str {
    match class {
        GuardClass::Credential => "credential",
        GuardClass::Persistence => "persistence",
        GuardClass::PentFiles => "pent files",
        GuardClass::PrivilegeEscalation => "privilege escalation",
        GuardClass::ControlPort => "control port",
    }
}

/// Return the text of a note for the user.
#[must_use]
pub const fn note_label(note: &ItemNote) -> &'static str {
    match note {
        ItemNote::CreatedThenExecuted => "created in the session, then run",
        ItemNote::OutsideHome => "outside the home directory",
        ItemNote::OtherRepository => "in another repository",
        ItemNote::ServedOutside => "a program outside the recording serves it",
    }
}

/// Return true for a Unicode format character (category Cf) or a line or
/// paragraph separator.
///
/// These characters are invisible, and some of them change the order of the
/// text: a path with `U+202E` shows `exe.txt` for the file `txt.exe`. The
/// output escapes them, as it escapes the control characters.
///
/// The list follows the Unicode character database (the ranges of the
/// category Cf), plus `U+2028` and `U+2029`, which move the cursor in some
/// programs.
pub(crate) const fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00ad}'                  // soft hyphen
        | '\u{0600}'..='\u{0605}'   // Arabic number signs
        | '\u{061c}'                // Arabic letter mark
        | '\u{06dd}' | '\u{070f}'
        | '\u{0890}'..='\u{0891}'
        | '\u{08e2}'
        | '\u{180e}'                // Mongolian vowel separator
        | '\u{200b}'..='\u{200f}'   // zero width space to right-to-left mark
        | '\u{2028}'..='\u{2029}'   // line and paragraph separator
        | '\u{202a}'..='\u{202e}'   // bidi embedding and override
        | '\u{2060}'..='\u{2064}'   // word joiner and invisible operators
        | '\u{2066}'..='\u{206f}'   // bidi isolate and deprecated formats
        | '\u{feff}'                // byte order mark
        | '\u{fff9}'..='\u{fffb}'   // interlinear annotation
        | '\u{110bd}' | '\u{110cd}'
        | '\u{13430}'..='\u{1343f}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0001}'
        | '\u{e0020}'..='\u{e007f}' // tag characters
    )
}

/// Return true for a character that the output must escape: a control
/// character (C0, DEL, C1) or a format character.
///
/// The function is not `const`: `char::is_control` became usable in a
/// constant only after the Rust that the end-to-end image pins, and each
/// caller gives the function to `escape_with`, where `const` buys nothing.
pub(crate) fn is_unsafe_char(c: char) -> bool {
    c.is_control() || is_format_char(c)
}

/// Replace with escapes (`\u{1b}`) each character that
/// [`is_unsafe_char`] names, the newline too. Use this function for one
/// field of one line.
pub(crate) fn safe(text: &str) -> Cow<'_, str> {
    escape_with(text, is_unsafe_char)
}

/// Replace with escapes (`\u{1b}`) each character that
/// `is_unsafe_char` names, but keep the newline. Use this function for a
/// text with more than one line, for example the text of a draft or of a
/// profile file.
///
/// `pent trust` and `pent profile show` print the file as it is. A file
/// that pent wrote has no such character, but a file that a person edited
/// can have one.
#[must_use]
pub fn safe_lines(text: &str) -> Cow<'_, str> {
    escape_with(text, |c| c != '\n' && is_unsafe_char(c))
}

/// Replace each character for which `unsafe_char` returns true with its
/// `\u{...}` escape.
fn escape_with(text: &str, unsafe_char: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !text.chars().any(&unsafe_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if unsafe_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Return the rule text of a grant (the path, the domain or the port).
fn grant_text(grant: &Grant) -> Cow<'_, str> {
    match grant {
        Grant::Fs { path, .. } | Grant::UnixSocket(path) => Cow::Borrowed(path),
        Grant::Domain(domain) => Cow::Borrowed(domain),
        Grant::Localhost(port) => Cow::Owned(port.to_string()),
    }
}

/// Return the first column of an item: the path or the domain. A blocked
/// item starts with the access (`read ~/.ssh/id_ed25519`).
pub(crate) fn item_label(item: &Item) -> String {
    let grant = grant_text(&item.grant);
    let text = safe(&grant);
    if item.blocked.is_none() {
        return text.into_owned();
    }
    let verb = match &item.grant {
        Grant::Fs { access, .. } => match access {
            FsAccess::Read => "read",
            FsAccess::ReadWrite => "write",
            FsAccess::Execute => "exec",
        },
        Grant::Domain(_) | Grant::UnixSocket(_) | Grant::Localhost(_) => "connect",
    };
    format!("{verb} {text}")
}

/// Return the second column of an item: the reason, the guard class and the
/// notes. The text is not escaped: use [`safe`] for the terminal and
/// [`comment_text`] for the draft.
pub(crate) fn item_comment(item: &Item) -> String {
    let mut text = item.reason.clone();
    if let Some(class) = item.blocked {
        if text.is_empty() {
            text.push_str(class_label(class));
        } else {
            text.push_str(&format!(" ({})", class_label(class)));
        }
    }
    for note in &item.notes {
        if !text.is_empty() {
            text.push_str("; ");
        }
        text.push_str(note_label(note));
    }
    text
}

/// Return the width of the first column for these labels.
pub(crate) fn column_width<'a>(labels: impl Iterator<Item = &'a str>) -> usize {
    labels
        .map(|l| l.chars().count())
        .filter(|&w| w <= LABEL_CAP)
        .max()
        .unwrap_or(0)
}

/// Write `label`, padded to `width`, then two spaces and `comment`.
pub(crate) fn push_row(out: &mut String, indent: &str, label: &str, width: usize, comment: &str) {
    out.push_str(indent);
    out.push_str(label);
    if !comment.is_empty() {
        let pad = width.saturating_sub(label.chars().count());
        out.extend(std::iter::repeat_n(' ', pad.saturating_add(2)));
        out.push_str(comment);
    }
    out.push('\n');
}

/// Return `1 rule` or `3 rules`.
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", format_count(n), if n == 1 { one } else { many })
}

/// Render only the first lines of the terminal summary: the profile name and
/// the counts. The interactive review shows the items itself, so pent prints
/// this header before the review instead of the full summary.
#[must_use]
pub fn render_header(summary: &Summary, header: &WatchHeader<'_>) -> String {
    let mut out = String::new();
    match header.source {
        DraftSource::WatchRuns(runs) => {
            out.push_str(&format!("pent watch: {}", header.name));
            if runs > 1 {
                out.push_str(&format!(" ({} runs)", format_count(runs)));
            }
        }
        DraftSource::DeniedReview => {
            out.push_str(&format!("pent trust --review: {}", header.name));
        }
    }
    out.push('\n');

    let blocked = summary.items.iter().filter(|i| i.blocked.is_some()).count();
    let rules = summary.items.len().saturating_sub(blocked);
    let stats = &summary.stats;
    let what = if rules == 0 {
        "No new rules".to_string()
    } else {
        plural(rules, "rule", "rules")
    };
    out.push_str(&format!(
        "  {what} from {}",
        plural(stats.total_events(), "access", "accesses")
    ));
    if !stats.processes.is_empty() {
        out.push_str(&format!(
            " by {}",
            plural(stats.processes.len(), "process", "processes")
        ));
    }
    out.push('.');
    if blocked > 0 {
        out.push_str(&format!(
            " The guard blocked {}.",
            plural(blocked, "access", "accesses")
        ));
    }
    out.push('\n');

    out
}

/// The facts of a run that the user must see without a careful read.
///
/// `pent watch` prints one warning line for each count that is not zero,
/// under the header, and writes the same lines into the first lines of the
/// draft.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Warnings {
    /// The number of rules outside the home directory.
    pub outside_home: usize,
    /// The number of rules in another repository.
    pub other_repository: usize,
    /// The number of connections to a Unix socket that pent refused.
    pub refused_unix_sockets: usize,
    /// The number of ports on localhost through which the command reached a
    /// program on the host. Pent does not record what such a program does.
    pub localhost_ports: usize,
}

impl Warnings {
    /// Count the facts of `summary`.
    #[must_use]
    pub fn of(summary: &Summary) -> Self {
        let count = |note: &ItemNote| {
            summary
                .items
                .iter()
                .filter(|item| item.notes.contains(note))
                .count()
        };
        Self {
            outside_home: count(&ItemNote::OutsideHome),
            other_repository: count(&ItemNote::OtherRepository),
            refused_unix_sockets: summary.stats.refused_unix_sockets,
            localhost_ports: count(&ItemNote::ServedOutside),
        }
    }

    /// Return true if each count is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.outside_home == 0
            && self.other_repository == 0
            && self.refused_unix_sockets == 0
            && self.localhost_ports == 0
    }

    /// One short line for each count that is not zero.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.outside_home > 0 {
            lines.push(format!(
                "{} outside the home directory",
                plural(self.outside_home, "rule reads", "rules read")
            ));
        }
        if self.other_repository > 0 {
            lines.push(format!(
                "{} in another repository",
                plural(self.other_repository, "rule reads", "rules read")
            ));
        }
        if self.refused_unix_sockets > 0 {
            lines.push(format!(
                "pent refused {}",
                plural(
                    self.refused_unix_sockets,
                    "connection to a Unix socket",
                    "connections to a Unix socket"
                )
            ));
        }
        if self.localhost_ports > 0 {
            lines.push(format!(
                "the command reached {}; pent does not record what the programs behind them do",
                plural(
                    self.localhost_ports,
                    "port on localhost",
                    "ports on localhost"
                )
            ));
        }
        lines
    }
}

/// Render the summary block that `pent watch` prints after the child exits.
///
/// Example:
///
/// ```text
/// pent watch: claude
///   13 rules from 1,834 accesses by 5 processes. The guard blocked 2 accesses.
///
///   Read-write
///     ~/.claude                creates and edits files (37 new)
///     ~/.claude.json           config file
///   Network
///     api.anthropic.com        HTTPS
///     *.npmjs.org              registry, www, cdn
///   Blocked by the guard
///     read ~/.ssh/id_ed25519   ssh (credential)
/// ```
#[must_use]
pub fn render_terminal(summary: &Summary, header: &WatchHeader<'_>) -> String {
    let mut out = render_header(summary, header);
    let stats = &summary.stats;
    let labels: Vec<String> = summary.items.iter().map(item_label).collect();
    let width = column_width(labels.iter().map(String::as_str));
    if !summary.items.is_empty() {
        out.push('\n');
    }
    for section in SECTIONS {
        let mut rows = summary
            .items
            .iter()
            .zip(&labels)
            .filter(|(item, _)| item.section() == section)
            .peekable();
        if rows.peek().is_none() {
            continue;
        }
        out.push_str(&format!("  {}\n", section_title(section)));
        for (item, label) in rows {
            push_row(&mut out, "    ", label, width, &safe(&item_comment(item)));
        }
    }

    if !stats.unreachable_sockets.is_empty() || !stats.ip_hosts.is_empty() {
        out.push_str("\n  Not in the rules\n");
        for socket in &stats.unreachable_sockets {
            out.push_str(&format!(
                "    Unix socket {}: a rule cannot name it, so it is not reachable\n",
                safe(socket)
            ));
        }
        for host in &stats.ip_hosts {
            out.push_str(&format!(
                "    {}: the proxy cannot allow an IP address\n",
                safe(host)
            ));
        }
    }
    out
}

// ── Reasons ──────────────────────────────────────────────────────────────────

/// The reason for each rule, from a summary or from the comments of a draft.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reasons(HashMap<Grant, String>);

impl Reasons {
    /// Collect the reasons of the items in `summary`. The text is the same as
    /// the comment in the draft (with the guard class and the notes).
    #[must_use]
    pub fn from_summary(summary: &Summary) -> Self {
        let mut map = HashMap::new();
        for item in &summary.items {
            map.entry(item.grant.clone())
                .or_insert_with(|| comment_text(&item_comment(item)));
        }
        Self(map)
    }

    /// Collect the reasons from the comments of a draft that
    /// [`render_draft`] wrote. Lines that the function does not know give no
    /// reason.
    #[must_use]
    pub fn from_draft(text: &str) -> Self {
        let mut map = HashMap::new();
        let mut list: Option<ListKind> = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(kind) = ListKind::from_line(trimmed) {
                list = Some(kind);
                continue;
            }
            if trimmed.starts_with('[') || trimmed == "]" {
                list = None;
                continue;
            }
            let Some(kind) = list else {
                continue;
            };
            let Some((grant, rest)) = kind.parse_entry(trimmed) else {
                continue;
            };
            let comment = rest
                .trim_start()
                .strip_prefix(',')
                .unwrap_or(rest)
                .trim_start()
                .strip_prefix('#')
                .map(str::trim);
            if let Some(comment) = comment.filter(|c| !c.is_empty()) {
                map.insert(grant, comment.to_string());
            }
        }
        Self(map)
    }

    /// Return the reason of a rule.
    #[must_use]
    pub fn get(&self, grant: &Grant) -> Option<&str> {
        self.0.get(grant).map(String::as_str)
    }

    /// Add the reasons of `other` for the rules that have no reason yet.
    pub fn merge_missing(&mut self, other: Self) {
        for (grant, reason) in other.0 {
            self.0.entry(grant).or_insert(reason);
        }
    }

    /// Return true if no rule has a reason.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The six lists of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    ReadWrite,
    Read,
    Execute,
    UnixSockets,
    Domains,
    Localhost,
}

impl ListKind {
    const ALL: [Self; 6] = [
        Self::ReadWrite,
        Self::Read,
        Self::Execute,
        Self::UnixSockets,
        Self::Domains,
        Self::Localhost,
    ];

    const fn key(self) -> &'static str {
        match self {
            Self::ReadWrite => "read_write",
            Self::Read => "read",
            Self::Execute => "execute",
            Self::UnixSockets => "unix_sockets",
            Self::Domains => "domains",
            Self::Localhost => "localhost",
        }
    }

    /// Return the table of the list in the profile file.
    const fn table(self) -> &'static str {
        match self {
            Self::ReadWrite | Self::Read | Self::Execute | Self::UnixSockets => "filesystem",
            Self::Domains | Self::Localhost => "network",
        }
    }

    const fn section(self) -> Section {
        match self {
            Self::ReadWrite => Section::ReadWrite,
            Self::Read => Section::Read,
            Self::Execute => Section::Execute,
            Self::UnixSockets => Section::UnixSockets,
            Self::Domains => Section::Network,
            Self::Localhost => Section::Localhost,
        }
    }

    /// Return the rules of the list, each with its grant.
    fn rules(self, doc: &ProfileDoc) -> Vec<Grant> {
        let fs = |list: &[String], access| {
            list.iter()
                .map(|path| Grant::Fs {
                    access,
                    path: path.clone(),
                })
                .collect()
        };
        match self {
            Self::ReadWrite => fs(&doc.filesystem.read_write, FsAccess::ReadWrite),
            Self::Read => fs(&doc.filesystem.read, FsAccess::Read),
            Self::Execute => fs(&doc.filesystem.execute, FsAccess::Execute),
            Self::UnixSockets => doc
                .filesystem
                .unix_sockets
                .iter()
                .cloned()
                .map(Grant::UnixSocket)
                .collect(),
            Self::Domains => doc
                .network
                .domains
                .iter()
                .cloned()
                .map(Grant::Domain)
                .collect(),
            Self::Localhost => doc
                .network
                .localhost
                .iter()
                .copied()
                .map(Grant::Localhost)
                .collect(),
        }
    }

    /// Return the grant of the value at the start of a line of a draft
    /// list, and the rest of the line. A port is a TOML integer, each other
    /// rule is a TOML string.
    fn parse_entry(self, line: &str) -> Option<(Grant, &str)> {
        let access = match self {
            Self::ReadWrite => FsAccess::ReadWrite,
            Self::Read => FsAccess::Read,
            Self::Execute => FsAccess::Execute,
            Self::UnixSockets => {
                let (value, rest) = split_string_literal(line)?;
                return Some((Grant::UnixSocket(value), rest));
            }
            Self::Domains => {
                let (value, rest) = split_string_literal(line)?;
                return Some((Grant::Domain(value), rest));
            }
            Self::Localhost => {
                let end = line
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(line.len());
                let port = line.get(..end)?.parse().ok()?;
                return Some((Grant::Localhost(port), line.get(end..)?));
            }
        };
        let (path, rest) = split_string_literal(line)?;
        Some((Grant::Fs { access, path }, rest))
    }

    /// Return the list that starts on this line (`read = [`).
    fn from_line(line: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| {
            line.strip_prefix(kind.key())
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
                .is_some_and(|rest| rest.trim_start().starts_with('['))
        })
    }
}

/// Split a line that starts with a TOML basic string into the value of the
/// string and the rest of the line.
fn split_string_literal(line: &str) -> Option<(String, &str)> {
    #[derive(Deserialize)]
    struct Literal {
        v: String,
    }
    let body = line.strip_prefix('"')?;
    let mut escaped = false;
    let mut end = None;
    for (i, c) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            end = Some(i);
            break;
        }
    }
    // The literal is `"` + body[..end] + `"`, so it ends at byte end + 2.
    let literal_end = end?.checked_add(2)?;
    let literal = line.get(..literal_end)?;
    let rest = line.get(literal_end..)?;
    let parsed: Literal = toml::from_str(&format!("v = {literal}")).ok()?;
    Some((parsed.v, rest))
}

// ── Draft ────────────────────────────────────────────────────────────────────

/// One entry of a draft list: the TOML string with the comma, and the
/// reason as a TOML comment ([`comment_text`]).
type DraftEntry = (String, Option<String>);

/// Encode `text` as a TOML basic string, with escapes.
///
/// The function escapes each control character and each format character
/// (see `safe`), so the text of the draft shows the true rule.
/// The string parses back to `text`.
#[must_use]
pub fn toml_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if is_unsafe_char(c) => {
                let code = u32::from(c);
                if code <= 0xFFFF {
                    out.push_str(&format!("\\u{code:04X}"));
                } else {
                    out.push_str(&format!("\\U{code:08X}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Make a reason safe for a TOML comment: a comment cannot have a control
/// character, and a format character can change the order of the text, so
/// the function replaces both with spaces.
pub(crate) fn comment_text(reason: &str) -> String {
    reason
        .chars()
        .map(|c| if is_unsafe_char(c) { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Render the draft file: the rules of `doc`, with the reasons from
/// `summary` as comments.
///
/// The result parses back to `doc` with [`ProfileDoc::parse`]. A rule that is
/// not in `summary` (for example from an earlier run with `--append`) has no
/// comment.
#[must_use]
pub fn render_draft(
    name: &ProfileName,
    runs: usize,
    doc: &ProfileDoc,
    summary: &Summary,
) -> String {
    render_draft_with(
        name,
        DraftSource::WatchRuns(runs),
        doc,
        &Reasons::from_summary(summary),
        Warnings::of(summary),
    )
}

/// Where the rules of a draft come from. The first line of the draft names
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftSource {
    /// One or more `pent watch` runs.
    WatchRuns(usize),
    /// The review of the accesses that `pent run` denied.
    DeniedReview,
}

/// Render a draft with the reasons in `reasons`. Use this function when the
/// draft keeps rules from an earlier draft or profile: merge their reasons
/// into `reasons` with [`Reasons::merge_missing`].
///
/// `facts` goes into the first lines, as a comment for each count that is
/// not zero. A user who reads the file later sees the same facts as the
/// user who saw the review.
#[must_use]
pub fn render_draft_with(
    name: &ProfileName,
    source: DraftSource,
    doc: &ProfileDoc,
    reasons: &Reasons,
    facts: Warnings,
) -> String {
    let mut out = String::new();
    match source {
        DraftSource::WatchRuns(runs) => out.push_str(&format!(
            "# Profile for \"{name}\". Pent made it from {}.\n",
            plural(runs, "watch run", "watch runs")
        )),
        DraftSource::DeniedReview => out.push_str(&format!(
            "# Profile for \"{name}\". Pent added the denied accesses that you accepted.\n"
        )),
    }
    out.push_str("# Each comment tells why the rule exists. Remove a line to remove the rule.\n");
    for line in facts.lines() {
        out.push_str(&format!("# {}.\n", comment_text(&line)));
    }
    if doc.is_empty() {
        out.push_str("# The profile has no rules.\n");
        return out;
    }

    // The entries, with the comma, and the comments. A reason can come from
    // the comments of an earlier draft, thus `comment_text` runs on each
    // reason: a bare CR or ESC in a hand-edited comment must not make the
    // new draft invalid.
    let mut lists: Vec<(ListKind, Vec<DraftEntry>)> = Vec::new();
    for kind in ListKind::ALL {
        let entries: Vec<DraftEntry> = kind
            .rules(doc)
            .iter()
            .map(|grant| {
                let comment = reasons
                    .get(grant)
                    .map(comment_text)
                    .filter(|c| !c.is_empty());
                let value = match grant {
                    Grant::Localhost(port) => port.to_string(),
                    other => toml_string(&grant_text(other)),
                };
                (format!("{value},"), comment)
            })
            .collect();
        if !entries.is_empty() {
            lists.push((kind, entries));
        }
    }
    let width = column_width(
        lists
            .iter()
            .flat_map(|(_, entries)| entries.iter().map(|(e, _)| e.as_str())),
    );

    let mut table = "";
    for (kind, entries) in &lists {
        let this_table = kind.table();
        if this_table != table {
            out.push_str(&format!("\n[{this_table}]\n"));
            table = this_table;
        }
        out.push_str(&format!("{} = [\n", kind.key()));
        for (entry, comment) in entries {
            let comment = comment
                .as_ref()
                .map(|c| format!("# {c}"))
                .unwrap_or_default();
            push_row(&mut out, "  ", entry, width, &comment);
        }
        out.push_str("]\n");
    }
    out
}

// ── Plain profile ────────────────────────────────────────────────────────────

/// Render a profile as plain text, one section for each list, with the
/// reasons that `reasons` has. `pent trust` and `pent profile show` print
/// this text.
#[must_use]
pub fn render_profile(doc: &ProfileDoc, reasons: &Reasons) -> String {
    if doc.is_empty() {
        return "The profile has no rules.\n".to_string();
    }
    let lists: Vec<(ListKind, Vec<Grant>)> = ListKind::ALL
        .into_iter()
        .map(|kind| (kind, kind.rules(doc)))
        .collect();
    let labels: Vec<String> = lists
        .iter()
        .flat_map(|(_, rules)| rules.iter().map(|g| safe(&grant_text(g)).into_owned()))
        .collect();
    let width = column_width(labels.iter().map(String::as_str));
    let mut out = String::new();
    for (kind, rules) in &lists {
        if rules.is_empty() {
            continue;
        }
        out.push_str(&format!("{}\n", section_title(kind.section())));
        for grant in rules {
            let reason = reasons.get(grant).map(safe).unwrap_or_default();
            push_row(&mut out, "  ", &safe(&grant_text(grant)), width, &reason);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{claude_session, ctx};
    use crate::summary::summarize;

    type TestResult = Result<(), crate::ProfileNameError>;

    fn name(text: &str) -> Result<ProfileName, crate::ProfileNameError> {
        text.parse()
    }

    fn claude_summary() -> Summary {
        summarize(&claude_session(), &ctx())
    }

    /// Select each item of a section that the review selects by default.
    fn default_selection(summary: &Summary) -> Vec<usize> {
        summary
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.section().selects_by_default())
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn terminal_summary_snapshot() -> TestResult {
        let summary = claude_summary();
        let profile = name("claude")?;
        let text = render_terminal(
            &summary,
            &WatchHeader {
                name: &profile,
                source: DraftSource::WatchRuns(1),
            },
        );
        let expected = "\
pent watch: claude
  14 rules from 1,835 accesses by 4 processes. The guard blocked 2 accesses.

  Read-write
    ~/.cache/claude         cache
    ~/.claude               creates and edits files (37 new)
    ~/.claude.json          config file
  Read
    ~/.config/git/ignore    read by git
    ~/.gitconfig            read by git
    ~/.ssh/config           read by ssh
    ~/.ssh/known_hosts      read by git, ssh
  Execute
    ~/.local/share/claude   runs claude
    ~/.nvm/versions/node    runs node
  Unix sockets
    /run/user/1000/bus      D-Bus
  Network
    api.anthropic.com       HTTPS
    github.com              port 22
    *.npmjs.org             registry, www, cdn
    statsig.anthropic.com   HTTPS
  Blocked by the guard
    write ~/.bashrc         node (persistence)
    read ~/.ssh/id_ed25519  ssh (credential)

  Not in the rules
    Unix socket @/tmp/.X11-unix/X0: a rule cannot name it, so it is not reachable
    140.82.112.3:443: the proxy cannot allow an IP address
";
        assert_eq!(text, expected, "\n{text}");
        Ok(())
    }

    #[test]
    fn terminal_summary_without_rules() -> TestResult {
        let profile = name("tool")?;
        let text = render_terminal(
            &Summary::default(),
            &WatchHeader {
                name: &profile,
                source: DraftSource::WatchRuns(3),
            },
        );
        assert_eq!(
            text,
            "pent watch: tool (3 runs)\n  No new rules from 0 accesses.\n"
        );
        Ok(())
    }

    #[test]
    fn draft_snapshot_parses_back() -> TestResult {
        let summary = claude_summary();
        let doc = summary.to_doc(&default_selection(&summary));
        let text = render_draft(&name("claude")?, 3, &doc, &summary);
        let expected = r#"# Profile for "claude". Pent made it from 3 watch runs.
# Each comment tells why the rule exists. Remove a line to remove the rule.
# pent refused 1 connection to a Unix socket.

[filesystem]
read_write = [
  "~/.cache/claude",        # cache
  "~/.claude",              # creates and edits files (37 new)
  "~/.claude.json",         # config file
]
read = [
  "~/.config/git/ignore",   # read by git
  "~/.gitconfig",           # read by git
  "~/.ssh/config",          # read by ssh
  "~/.ssh/known_hosts",     # read by git, ssh
]
execute = [
  "~/.local/share/claude",  # runs claude
  "~/.nvm/versions/node",   # runs node
]

[network]
domains = [
  "api.anthropic.com",      # HTTPS
  "github.com",             # port 22
  "*.npmjs.org",            # registry, www, cdn
  "statsig.anthropic.com",  # HTTPS
]
"#;
        assert_eq!(text, expected, "\n{text}");
        let parsed = ProfileDoc::parse(&text);
        assert!(matches!(&parsed, Ok(p) if *p == doc), "{parsed:?}");
        Ok(())
    }

    #[test]
    fn draft_with_accepted_blocked_item_names_the_class() -> TestResult {
        let summary = claude_summary();
        let all: Vec<usize> = (0..summary.items.len()).collect();
        let doc = summary.to_doc(&all);
        let text = render_draft(&name("claude")?, 1, &doc, &summary);
        assert!(text.contains("from 1 watch run."), "{text}");
        assert!(
            text.contains("  \"~/.ssh/id_ed25519\",      # ssh (credential)\n"),
            "{text}"
        );
        assert!(matches!(ProfileDoc::parse(&text), Ok(p) if p == doc));
        Ok(())
    }

    #[test]
    fn draft_round_trips_unusual_strings() -> TestResult {
        let mut doc = ProfileDoc::default();
        doc.filesystem.read = vec![
            "~/with \"quotes\"".to_string(),
            "C:\\Users\\back\\slash".to_string(),
            "~/ünïcödé/日本語/😀".to_string(),
            "~/control\u{1}\u{7f}\t\n\r\u{8}\u{c}end".to_string(),
            "~/# not a comment".to_string(),
            "~/trailing\\".to_string(),
        ];
        doc.filesystem.read_write = vec!["~/x".to_string()];
        doc.network.domains = vec!["*.example.com".to_string()];
        let mut summary = Summary::default();
        summary.items.push(Item {
            grant: Grant::Fs {
                access: FsAccess::Read,
                path: "~/with \"quotes\"".to_string(),
            },
            reason: "read by evil\nname # x".to_string(),
            blocked: None,
            notes: vec![ItemNote::OutsideHome],
        });
        let text = render_draft(&name("t")?, 1, &doc, &summary);
        let parsed = ProfileDoc::parse(&text);
        assert!(matches!(&parsed, Ok(p) if *p == doc), "{parsed:?}\n{text}");
        assert!(
            text.contains("# read by evil name # x; outside the home directory\n"),
            "{text}"
        );

        let reasons = Reasons::from_draft(&text);
        assert_eq!(
            reasons.get(&Grant::Fs {
                access: FsAccess::Read,
                path: "~/with \"quotes\"".to_string(),
            }),
            Some("read by evil name # x; outside the home directory")
        );
        assert_eq!(
            reasons.get(&Grant::Fs {
                access: FsAccess::Read,
                path: "~/# not a comment".to_string(),
            }),
            None
        );
        Ok(())
    }

    #[test]
    fn empty_draft_parses_to_an_empty_profile() -> TestResult {
        let text = render_draft(&name("t")?, 1, &ProfileDoc::default(), &Summary::default());
        assert!(matches!(ProfileDoc::parse(&text), Ok(p) if p.is_empty()));
        assert!(text.ends_with("# The profile has no rules.\n"));
        Ok(())
    }

    #[test]
    fn reasons_from_the_draft_match_the_summary() -> TestResult {
        let summary = claude_summary();
        let doc = summary.to_doc(&default_selection(&summary));
        let text = render_draft(&name("claude")?, 1, &doc, &summary);
        let from_draft = Reasons::from_draft(&text);
        let from_summary = Reasons::from_summary(&summary);
        for item in summary
            .items
            .iter()
            .filter(|i| i.section().selects_by_default())
        {
            assert_eq!(from_draft.get(&item.grant), from_summary.get(&item.grant));
            assert!(from_draft.get(&item.grant).is_some());
        }
        Ok(())
    }

    #[test]
    fn plain_profile_snapshot() {
        let summary = claude_summary();
        let doc = summary.to_doc(&default_selection(&summary));
        let mut text_doc = doc.clone();
        text_doc.filesystem.read.push("~/no-reason".to_string());
        let text = render_profile(&text_doc, &Reasons::from_summary(&summary));
        let expected = "\
Read-write
  ~/.cache/claude        cache
  ~/.claude              creates and edits files (37 new)
  ~/.claude.json         config file
Read
  ~/.config/git/ignore   read by git
  ~/.gitconfig           read by git
  ~/.ssh/config          read by ssh
  ~/.ssh/known_hosts     read by git, ssh
  ~/no-reason
Execute
  ~/.local/share/claude  runs claude
  ~/.nvm/versions/node   runs node
Network
  api.anthropic.com      HTTPS
  github.com             port 22
  *.npmjs.org            registry, www, cdn
  statsig.anthropic.com  HTTPS
";
        assert_eq!(text, expected, "\n{text}");
        assert_eq!(
            render_profile(&ProfileDoc::default(), &Reasons::default()),
            "The profile has no rules.\n"
        );
    }

    #[test]
    fn control_characters_are_escaped_for_the_terminal() {
        assert_eq!(safe("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(safe("plain"), "plain");
    }

    #[test]
    fn toml_strings_escape_special_characters() {
        assert_eq!(toml_string("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(toml_string("\u{1}\u{7f}"), r#""\u0001\u007F""#);
        assert_eq!(toml_string("\u{202e}\u{feff}"), r#""\u202E\uFEFF""#);
        assert_eq!(toml_string("\u{e0041}"), r#""\U000E0041""#);
    }

    #[test]
    fn format_characters_are_escaped_too() {
        assert_eq!(safe("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(safe("iso\u{2066}x\u{2069}"), "iso\\u{2066}x\\u{2069}");
        assert_eq!(safe_lines("a\nb"), "a\nb");
        assert_eq!(safe_lines("a\n\u{200f}b"), "a\n\\u{200f}b");
        assert_eq!(safe_lines("plain"), "plain");
        assert_eq!(comment_text("a\u{202e}b"), "a b");
    }

    /// A reason that comes back from an earlier draft can hold a bare CR or
    /// an ESC. The new draft must stay valid.
    #[test]
    fn comments_from_an_earlier_draft_stay_valid() -> TestResult {
        let mut doc = ProfileDoc::default();
        doc.filesystem.read.push("~/a".to_string());
        let earlier = "[filesystem]\nread = [\n  \"~/a\",  # one\rtwo\u{1b}[31m\n]\n";
        let text = render_draft_with(
            &name("tool")?,
            DraftSource::WatchRuns(1),
            &doc,
            &Reasons::from_draft(earlier),
            Warnings::default(),
        );
        assert!(
            matches!(ProfileDoc::parse(&text), Ok(p) if p == doc),
            "{text}"
        );
        assert!(text.contains("# one two [31m\n"), "{text}");
        Ok(())
    }

    // =================================================================    // The lines that the coverage run found open.
    // See docs/testing/fuzzing-and-coverage.md.
    // ========================================================================

    /// Each note has its own text, and no text is empty. The user reads
    /// the note beside the rule, so two notes with the same text hide the
    /// difference.
    #[test]
    fn each_note_has_its_own_text() {
        const ALL: [ItemNote; 3] = [
            ItemNote::CreatedThenExecuted,
            ItemNote::OutsideHome,
            ItemNote::OtherRepository,
        ];
        let texts: Vec<&str> = ALL.iter().map(note_label).collect();
        for text in &texts {
            assert!(!text.is_empty(), "a note has no text");
        }
        let mut sorted = texts.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), texts.len(), "two notes share one text");
    }

    /// A blocked item starts with the access. A domain and a Unix socket
    /// both use the verb `connect`.
    #[test]
    fn a_blocked_item_names_its_access() {
        let item = |grant: Grant| Item {
            grant,
            reason: String::new(),
            blocked: Some(GuardClass::Credential),
            notes: Vec::new(),
        };
        assert_eq!(
            item_label(&item(Grant::Domain("evil.example".to_string()))),
            "connect evil.example"
        );
        assert_eq!(
            item_label(&item(Grant::UnixSocket("~/.ssh/agent".to_string()))),
            "connect ~/.ssh/agent"
        );
        assert_eq!(
            item_label(&item(Grant::Fs {
                access: FsAccess::Read,
                path: "~/.ssh/id_ed25519".to_string(),
            })),
            "read ~/.ssh/id_ed25519"
        );
        // With no reason the comment is only the class of the guard.
        assert_eq!(
            item_comment(&item(Grant::Domain("evil.example".to_string()))),
            "credential"
        );
        // With a reason the class comes after it, in parentheses.
        let mut with_reason = item(Grant::Domain("evil.example".to_string()));
        with_reason.reason = "read by ssh".to_string();
        assert_eq!(item_comment(&with_reason), "read by ssh (credential)");
    }

    /// `Warnings::is_empty` and `Reasons::is_empty` answer for the empty
    /// value and for a value that holds one entry. `pent watch` uses them
    /// to decide whether to print the warning block.
    #[test]
    fn the_empty_checks_answer_for_both_cases() {
        assert!(Warnings::default().is_empty());
        let one_of_each = [
            Warnings {
                outside_home: 1,
                ..Warnings::default()
            },
            Warnings {
                other_repository: 1,
                ..Warnings::default()
            },
            Warnings {
                refused_unix_sockets: 1,
                ..Warnings::default()
            },
        ];
        for warnings in one_of_each {
            assert!(
                !warnings.is_empty(),
                "the warnings {warnings:?} are not empty"
            );
            assert_eq!(warnings.lines().len(), 1, "one count gives one line");
        }

        assert!(Reasons::default().is_empty());
        let reasons = Reasons::from_draft("domains = [\n\"a.example\", # why\n]\n");
        assert!(!reasons.is_empty(), "the draft holds one reason");
        assert_eq!(
            reasons.get(&Grant::Domain("a.example".to_string())),
            Some("why")
        );
    }
    // ── Warnings ────────────────────────────────────────────────────────────

    /// [`Warnings::is_empty`] is true only when each of the three counts is
    /// zero.
    #[test]
    fn warnings_are_empty_only_when_each_count_is_zero() {
        assert!(Warnings::default().is_empty());
        let counts = [
            Warnings {
                outside_home: 1,
                ..Warnings::default()
            },
            Warnings {
                other_repository: 1,
                ..Warnings::default()
            },
            Warnings {
                refused_unix_sockets: 1,
                ..Warnings::default()
            },
            Warnings {
                localhost_ports: 1,
                ..Warnings::default()
            },
        ];
        for warnings in counts {
            assert!(
                !warnings.is_empty(),
                "one count that is not zero makes a warning: {warnings:?}"
            );
        }
    }

    /// [`Warnings::lines`] writes one line for each count that is not zero,
    /// and nothing for a count that is zero.
    #[test]
    fn warning_lines_name_only_the_counts_that_are_not_zero() {
        assert!(Warnings::default().lines().is_empty());
        let warnings = Warnings {
            outside_home: 2,
            other_repository: 1,
            refused_unix_sockets: 3,
            localhost_ports: 2,
        };
        assert_eq!(
            warnings.lines(),
            vec![
                "2 rules read outside the home directory".to_string(),
                "1 rule reads in another repository".to_string(),
                "pent refused 3 connections to a Unix socket".to_string(),
                "the command reached 2 ports on localhost; pent does not record what the \
                 programs behind them do"
                    .to_string(),
            ]
        );
        let one = Warnings {
            refused_unix_sockets: 1,
            ..Warnings::default()
        };
        assert_eq!(
            one.lines(),
            vec!["pent refused 1 connection to a Unix socket".to_string()]
        );
    }

    /// The terminal summary shows the block "Not in the rules" also when
    /// only one of the two lists has a member.
    #[test]
    fn the_block_that_is_not_in_the_rules_needs_only_one_list() -> TestResult {
        let profile = name("tool")?;
        let header = WatchHeader {
            name: &profile,
            source: DraftSource::WatchRuns(1),
        };

        let mut only_socket = Summary::default();
        only_socket.stats.unreachable_sockets = vec!["@abstract".to_string()];
        let text = render_terminal(&only_socket, &header);
        assert!(text.contains("Not in the rules"), "{text}");
        assert!(text.contains("@abstract"), "{text}");

        let mut only_host = Summary::default();
        only_host.stats.ip_hosts = vec!["203.0.113.9:443".to_string()];
        let text = render_terminal(&only_host, &header);
        assert!(text.contains("Not in the rules"), "{text}");
        assert!(text.contains("203.0.113.9:443"), "{text}");

        let text = render_terminal(&Summary::default(), &header);
        assert!(!text.contains("Not in the rules"), "{text}");
        Ok(())
    }

    // ── Reasons ─────────────────────────────────────────────────────────────

    /// The end of a list and the start of a table both end the list, so a
    /// stray string between two lists gets no reason.
    #[test]
    fn a_string_between_two_lists_gets_no_reason() {
        let text = "\
[filesystem]
read = [
  \"~/a\",  # one
]
\"stray.example\",  # two

[network]
\"other.example\",  # three
domains = [
  \"x.example\",  # four
]
";
        let reasons = Reasons::from_draft(text);
        assert_eq!(
            reasons.get(&Grant::Fs {
                access: FsAccess::Read,
                path: "~/a".to_string(),
            }),
            Some("one")
        );
        for stray in ["stray.example", "other.example"] {
            assert_eq!(
                reasons.get(&Grant::Fs {
                    access: FsAccess::Read,
                    path: stray.to_string(),
                }),
                None,
                "the list ended before {stray}"
            );
        }
        assert_eq!(
            reasons.get(&Grant::Domain("x.example".to_string())),
            Some("four")
        );
    }

    /// A port is a TOML integer in the `[network]` table. The draft keeps
    /// the reason of the port as a comment, and the reader finds it again.
    #[test]
    fn a_port_rule_round_trips_with_its_reason() -> TestResult {
        let port = std::num::NonZeroU16::MIN.saturating_add(5431);
        let mut doc = ProfileDoc::default();
        doc.network.domains.push("a.example".to_string());
        doc.network.localhost.push(port);
        let summary = Summary {
            items: vec![Item {
                grant: Grant::Localhost(port),
                reason: "used by psql".to_string(),
                blocked: None,
                notes: Vec::new(),
            }],
            stats: crate::Stats::default(),
        };
        let text = render_draft(&name("db")?, 1, &doc, &summary);
        assert!(
            text.contains("[network]\ndomains = [\n  \"a.example\",\n]\nlocalhost = [\n  5432,"),
            "{text}"
        );
        assert!(
            ProfileDoc::parse(&text).is_ok_and(|parsed| parsed == doc),
            "{text}"
        );
        let reasons = Reasons::from_draft(&text);
        assert_eq!(reasons.get(&Grant::Localhost(port)), Some("used by psql"));
        let shown = render_profile(&doc, &reasons);
        assert!(shown.contains("Localhost ports\n  5432"), "{shown}");
        assert!(shown.contains("used by psql"), "{shown}");
        Ok(())
    }

    /// [`Reasons::is_empty`] is true only when no rule has a reason.
    #[test]
    fn reasons_are_empty_only_without_a_reason() {
        assert!(Reasons::default().is_empty());
        assert!(
            !Reasons::from_summary(&claude_summary()).is_empty(),
            "the fixture gives a reason to each rule"
        );
    }

    /// [`Reasons::merge_missing`] adds the reason of a rule that has none,
    /// and keeps the reason that the set already holds.
    #[test]
    fn merge_missing_keeps_the_reason_that_exists() {
        let kept = Grant::Domain("a.example".to_string());
        let added = Grant::Domain("b.example".to_string());
        let mut reasons = Reasons::from_draft("domains = [\n  \"a.example\",  # first\n]\n");
        let other = Reasons::from_draft(
            "domains = [\n  \"a.example\",  # second\n  \"b.example\",  # new\n]\n",
        );
        assert_eq!(reasons.get(&kept), Some("first"));
        assert_eq!(reasons.get(&added), None);

        reasons.merge_missing(other);
        assert_eq!(reasons.get(&kept), Some("first"), "the old reason stays");
        assert_eq!(reasons.get(&added), Some("new"), "the new reason comes in");
    }
}

/// Property tests of the draft writer and of the profile reader.
///
/// A rule holds a path or a domain that the watched program chose, so a
/// rule can hold any text. The same properties run as the `cargo fuzz`
/// targets in `crates/pent-profile/fuzz`; this module repeats them with a
/// fixed seed, so that the stable toolchain also checks them. See
/// `docs/testing/fuzzing-and-coverage.md`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod render_properties {
    use super::*;
    use crate::fixture::{rounds, Rng};

    /// The number of documents that each property test reads by default.
    const ROUNDS: usize = 20_000;

    /// The characters that a generated rule can hold. They cover the three
    /// groups that the writer must escape: the TOML syntax, the control
    /// characters and the Unicode format characters.
    const PIECES: [&str; 16] = [
        "a",
        "/home/u/work",
        "~/.ssh",
        "\"",
        "\\",
        "\n",
        "\r",
        "\t",
        "\u{0}",
        "\u{1b}",
        "\u{7f}",
        "\u{202e}",
        "\u{feff}",
        "\u{e0020}",
        "#",
        " ",
    ];

    /// Build one rule out of the pieces.
    fn gen_rule(rng: &mut Rng) -> String {
        let parts = rng.below(6);
        (0..parts)
            .map(|_| PIECES.get(rng.below(PIECES.len())).copied().unwrap_or("a"))
            .collect()
    }

    /// Build a list of rules.
    fn gen_rules(rng: &mut Rng) -> Vec<String> {
        let count = rng.below(4);
        (0..count).map(|_| gen_rule(rng)).collect()
    }

    /// Build a document.
    fn gen_doc(rng: &mut Rng) -> ProfileDoc {
        ProfileDoc {
            filesystem: crate::FilesystemRules {
                read: gen_rules(rng),
                read_write: gen_rules(rng),
                execute: gen_rules(rng),
                unix_sockets: gen_rules(rng),
            },
            network: crate::NetworkRules {
                domains: gen_rules(rng),
                localhost: gen_ports(rng),
            },
        }
    }

    /// Build a list of ports. A port can repeat, as in a file that a person
    /// edited.
    fn gen_ports(rng: &mut Rng) -> Vec<std::num::NonZeroU16> {
        let count = rng.below(4);
        #[allow(clippy::cast_possible_truncation, reason = "a port fits in 16 bits")]
        (0..count)
            .filter_map(|_| std::num::NonZeroU16::new(rng.next_u64() as u16))
            .collect()
    }

    /// A draft parses back to the document that it holds, and it holds no
    /// control character except the newline.
    #[test]
    fn a_draft_round_trips_and_is_safe_for_the_terminal() {
        let mut rng = Rng::new(0x5EED_0601);
        let total = rounds(ROUNDS);
        let Ok(name) = "fuzz".parse::<ProfileName>() else {
            panic!("the name \"fuzz\" must be valid");
        };
        let mut checked = 0usize;
        for _ in 0..total {
            let doc = gen_doc(&mut rng);
            let source = if rng.one_in(2) {
                DraftSource::WatchRuns(rng.below(5))
            } else {
                DraftSource::DeniedReview
            };
            let mut reasons = Reasons::default();
            reasons.merge_missing(Reasons::from_summary(&Summary::default()));
            let text = render_draft_with(&name, source, &doc, &reasons, Warnings::default());
            if let Some(c) = text.chars().find(|c| c.is_control() && *c != '\n') {
                panic!("the draft holds the control character {c:?}: {text:?}");
            }
            match ProfileDoc::parse(&text) {
                Ok(parsed) => assert_eq!(parsed, doc, "the draft does not round trip: {text:?}"),
                Err(e) => panic!("the draft does not parse: {e}: {text:?}"),
            }
            checked = checked.saturating_add(1);
        }
        assert!(
            checked == total,
            "the test read {checked} of {total} inputs"
        );
    }

    /// The plain profile text and the terminal summary hold no control
    /// character either. `pent trust` prints them to the terminal of the
    /// user, so an escape sequence in a path must never reach it.
    #[test]
    fn the_profile_text_is_safe_for_the_terminal() {
        let mut rng = Rng::new(0x5EED_0602);
        let total = rounds(ROUNDS);
        for _ in 0..total {
            let doc = gen_doc(&mut rng);
            let text = render_profile(&doc, &Reasons::default());
            if let Some(c) = text.chars().find(|c| c.is_control() && *c != '\n') {
                panic!("the profile text holds the control character {c:?}: {text:?}");
            }
            // `safe_lines` is the guard for a file that a person edited.
            let safe = safe_lines(&text);
            assert_eq!(safe, text, "safe_lines changed a text that pent wrote");
        }
    }

    /// `safe_lines` escapes every control character except the newline, and
    /// it changes nothing else.
    #[test]
    fn safe_lines_escapes_every_control_character() {
        let mut rng = Rng::new(0x5EED_0603);
        let total = rounds(ROUNDS);
        for _ in 0..total {
            let text = gen_rule(&mut rng);
            let safe = safe_lines(&text);
            if let Some(c) = safe.chars().find(|c| c.is_control() && *c != '\n') {
                panic!("safe_lines kept the control character {c:?} of {text:?}");
            }
            if !text.chars().any(|c| c.is_control() && c != '\n') {
                // The function must not change a text that is already safe,
                // apart from the format characters that it also escapes.
                assert!(safe.len() >= text.len(), "safe_lines made the text shorter");
            }
        }
    }

    /// A rule that `toml_string` writes parses back to the same rule.
    #[test]
    fn a_toml_string_parses_back_to_the_rule() {
        let mut rng = Rng::new(0x5EED_0604);
        let total = rounds(ROUNDS);
        for _ in 0..total {
            let rule = gen_rule(&mut rng);
            let literal = toml_string(&rule);
            assert!(
                !literal.chars().any(char::is_control),
                "the literal of {rule:?} holds a control character"
            );
            let document = format!("[filesystem]\nread = [{literal}]\n");
            match ProfileDoc::parse(&document) {
                Ok(doc) => assert_eq!(
                    doc.filesystem.read,
                    vec![rule.clone()],
                    "the literal {literal} does not parse back to {rule:?}"
                ),
                Err(e) => panic!("the literal {literal} does not parse: {e}"),
            }
        }
    }
}
