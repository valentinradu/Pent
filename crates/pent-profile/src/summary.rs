//! The summary step: group raw events into a short list of rules.
//!
//! The user never sees raw events. The summary has at most one rule for each
//! directory or domain that the program needs, and one short reason for each
//! rule. See `docs/design/watch.md` for the grouping rules.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use crate::guard::{classify, guard_rules, GuardAccess, GuardRule, GuardTarget};
use crate::psl;
use crate::{FsOp, GuardClass, Outcome, ProfileDoc, WatchEvent};

/// The number of entries in one directory that makes one rule on the
/// directory.
const DIR_THRESHOLD: usize = 4;

/// The number of written files in one directory that give one read-write
/// rule on the directory.
const WRITE_DIR_THRESHOLD: usize = 2;

/// The number of names below one registrable domain that makes one wildcard.
const WILDCARD_THRESHOLD: usize = 3;

/// The maximum number of names in a reason. The reason shows the rest as
/// `+N`.
const MAX_NAMES: usize = 3;

/// Directories below the home directory that are too broad for a rule. The
/// summary uses the child directory instead.
const BROAD_HOME_DIRS: &[&str] = &[
    ".config",
    ".local",
    ".local/share",
    ".local/state",
    ".cache",
    "Library",
    "Library/Application Support",
    "Library/Caches",
    "Library/Preferences",
];

/// Cache directories below the home directory.
const CACHE_DIRS: &[&str] = &[".cache", "Library/Caches"];

/// Directories with short-lived files. The summary omits all paths below
/// them.
const EPHEMERAL_DIRS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev",
    "/private/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// The access that a filesystem rule gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FsAccess {
    /// Read access.
    Read,
    /// Read and write access.
    ReadWrite,
    /// Read and execute access.
    Execute,
}

/// The rule that an item adds to the profile when the user accepts it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Grant {
    /// A filesystem rule. `path` uses `~/` for the home directory.
    Fs {
        /// The access.
        access: FsAccess,
        /// The path (a file, or a directory and all below it).
        path: String,
    },
    /// A domain for the proxy allowlist (can start with `*.`).
    Domain(String),
    /// A Unix socket that the program can connect to. The path uses `~/` for
    /// the home directory.
    ///
    /// This rule is a strong grant: a program that reaches the socket of an
    /// agent can use the key of that agent. The review does not select such
    /// an item by default.
    UnixSocket(String),
}

/// A note that the summary shows next to an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemNote {
    /// The program created this file in the session and then executed it.
    CreatedThenExecuted,
    /// The path is outside the home directory and outside the workspace.
    OutsideHome,
    /// The path is in another directory that looks like a source repository.
    OtherRepository,
}

/// One proposed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The rule that the item adds.
    pub grant: Grant,
    /// One short reason, for example `creates and edits files (37 new)` or
    /// `read by git`.
    pub reason: String,
    /// The guard class, when the watch guard blocked this access. The review
    /// shows these items in their own section, and does not select them by
    /// default.
    pub blocked: Option<GuardClass>,
    /// Extra notes for the user.
    pub notes: Vec<ItemNote>,
}

/// A section of the summary and of the review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Section {
    /// Read-write filesystem rules.
    ReadWrite,
    /// Read filesystem rules.
    Read,
    /// Execute filesystem rules.
    Execute,
    /// Unix sockets.
    UnixSockets,
    /// Domains.
    Network,
    /// Accesses that the watch guard blocked.
    Blocked,
}

impl Section {
    /// Return true if the review selects the items of this section by
    /// default.
    ///
    /// A blocked access and a Unix socket are strong grants, so the user
    /// must select them. The default of these two sections is `[n]`.
    #[must_use]
    pub const fn selects_by_default(self) -> bool {
        !matches!(self, Self::Blocked | Self::UnixSockets)
    }
}

impl Item {
    /// Return the section of the item.
    #[must_use]
    pub const fn section(&self) -> Section {
        if self.blocked.is_some() {
            return Section::Blocked;
        }
        match &self.grant {
            Grant::Fs { access, .. } => match access {
                FsAccess::ReadWrite => Section::ReadWrite,
                FsAccess::Read => Section::Read,
                FsAccess::Execute => Section::Execute,
            },
            Grant::Domain(_) => Section::Network,
            Grant::UnixSocket(_) => Section::UnixSockets,
        }
    }
}

/// Counts for the header of the summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// The number of filesystem events. This count includes the `connect()`
    /// calls to Unix sockets.
    pub fs_events: usize,
    /// The number of network events.
    pub net_events: usize,
    /// The distinct process names, in order of first appearance.
    pub processes: Vec<String>,
    /// The distinct Unix socket targets that a rule cannot name: an abstract
    /// address (`@name`) and a relative path. The sandbox cannot reach them,
    /// so the summary makes no item for them.
    pub unreachable_sockets: Vec<String>,
    /// The number of connections to a Unix socket that pent refused.
    pub refused_unix_sockets: usize,
    /// The distinct connections to an IP address without a name, as
    /// `address:port`. The proxy cannot allow an IP address, so the summary
    /// makes no item for them.
    pub ip_hosts: Vec<String>,
}

impl Stats {
    /// Return the number of all events.
    #[must_use]
    pub const fn total_events(&self) -> usize {
        self.fs_events.saturating_add(self.net_events)
    }
}

/// The input of the summary step that does not come from the events.
#[derive(Debug, Clone)]
pub struct SummaryContext {
    /// The home directory.
    pub home: PathBuf,
    /// The workspace. The sandbox always allows it, so the summary omits it.
    pub workspace: PathBuf,
    /// Directories that the sandbox defaults already allow (system paths,
    /// `/tmp`, `/proc`, `/dev`, `/nix/store`, ...). The summary omits paths
    /// below them.
    pub covered: Vec<PathBuf>,
    /// The current trusted profile, if one exists. The summary omits the
    /// rules that it already has.
    pub existing: Option<ProfileDoc>,
}

/// The result of the summary step.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// The proposed rules, sorted by section, then by rule.
    pub items: Vec<Item>,
    /// Counts for the header.
    pub stats: Stats,
}

impl Summary {
    /// Make a profile from the items at the selected indices.
    #[must_use]
    pub fn to_doc(&self, selected: &[usize]) -> ProfileDoc {
        let mut doc = ProfileDoc::default();
        for item in selected.iter().filter_map(|&i| self.items.get(i)) {
            let list = match &item.grant {
                Grant::Fs { access, path } => {
                    let list = match access {
                        FsAccess::Read => &mut doc.filesystem.read,
                        FsAccess::ReadWrite => &mut doc.filesystem.read_write,
                        FsAccess::Execute => &mut doc.filesystem.execute,
                    };
                    (list, path)
                }
                Grant::Domain(d) => (&mut doc.network.domains, d),
                Grant::UnixSocket(s) => (&mut doc.filesystem.unix_sockets, s),
            };
            if !list.0.contains(list.1) {
                list.0.push(list.1.clone());
            }
        }
        doc
    }
}

/// Group raw events into a summary.
///
/// The grouping follows `docs/design/watch.md`:
///
/// - The summary replaces the home directory with `~`. It omits the
///   workspace, the paths in [`SummaryContext::covered`] and the short-lived
///   paths (`/proc/<pid>`, `/proc/self`, `/tmp`, `/var/tmp`, `/dev`).
/// - A create or a delete in a directory gives read-write on the directory. A
///   write to an existing file gives read-write on the file.
/// - A directory with at least 4 entries that have rules of the same kind
///   gets one rule. The count includes subdirectories, so the grouping goes
///   up the tree. For read-write, only the directory rules count, not the
///   single written files.
/// - The summary never makes a rule on a top-level directory, on the home
///   directory or its parents, or on a broad home directory (`~/.config`,
///   `~/.local/share`, `~/.cache`, ...). It uses the child instead. The
///   summary makes no rule on the workspace or on a parent of the workspace.
///   This limit holds for each rule, also for a rule that comes from one
///   direct access: `open("~")` gives no rule, and `mkdir ~/.config` gives
///   no rule. A file directly in a broad directory (`~/.apprc`) keeps its
///   own rule.
/// - An exec gives execute on the directory of the binary. When the path has
///   a version directory (`versions/2.1.3`), the rule goes above it, so an
///   update of the program does not need a new rule.
/// - A wider rule hides a narrower one. Read-write and execute include read.
/// - The summary omits the rules that [`SummaryContext::existing`] has.
/// - Events with [`Outcome::Blocked`] become blocked items. Events with
///   [`Outcome::Denied`] become normal items.
/// - Three or more names below one registrable domain become `*.domain`,
///   except on a public suffix.
/// - A `connect()` to a Unix socket with a path gives one item with
///   [`Grant::UnixSocket`]. An abstract address (`@name`) and a relative
///   path give no item: a rule cannot name them. The summary lists them in
///   [`Stats::unreachable_sockets`].
/// - Connections to an IP address give no item. The summary lists them in
///   [`Stats::ip_hosts`].
#[must_use]
pub fn summarize<'a, I>(events: I, ctx: &SummaryContext) -> Summary
where
    I: IntoIterator<Item = &'a WatchEvent>,
{
    let env = Env::new(ctx);
    let mut stats = Stats::default();
    let mut fs = FsLog::default();
    let mut blocked: BTreeMap<(FsAccess, PathBuf), BlockedEntry> = BTreeMap::new();
    let mut net = NetLog::default();
    let mut unix = UnixLog::default();
    let mut ips = Names::default();

    for event in events {
        match event {
            WatchEvent::Fs {
                op,
                path,
                process,
                outcome,
            } => {
                stats.fs_events = stats.fs_events.saturating_add(1);
                add_name(&mut stats.processes, &process.name);
                let Some(path) = normalize(path) else {
                    continue;
                };
                // An access that matches a guard rule goes to the blocked
                // section, also when the guard did not block it (a denial of
                // `pent run`, or a path without a mount). The review does not
                // select these items by default.
                let class = match outcome {
                    Outcome::Blocked(class) => Some(*class),
                    Outcome::Allowed | Outcome::Denied => env.guard_class(*op, &path),
                };
                if let Some(class) = class {
                    add_blocked(&mut blocked, *op, path, class, &process.name, &env);
                } else if !env.is_omitted(&path) {
                    fs.record(*op, path, &process.name);
                }
            }
            WatchEvent::UnixConnect {
                target,
                process,
                outcome,
            } => {
                stats.fs_events = stats.fs_events.saturating_add(1);
                add_name(&mut stats.processes, &process.name);
                if *outcome == Outcome::Denied {
                    stats.refused_unix_sockets = stats.refused_unix_sockets.saturating_add(1);
                }
                // An abstract address and a relative path cannot be a rule.
                let path = (!target.starts_with('@'))
                    .then(|| normalize(Path::new(target)))
                    .flatten();
                match path.as_deref().and_then(|p| env.display(p)) {
                    Some(shown) => unix.add(&shown, &process.name),
                    None => unix.unreachable.add(target),
                }
            }
            WatchEvent::Dns { name, .. } => {
                stats.net_events = stats.net_events.saturating_add(1);
                net.add(name, None);
            }
            WatchEvent::Connect { host, port, .. } => {
                stats.net_events = stats.net_events.saturating_add(1);
                match parse_ip(host) {
                    Some(IpAddr::V4(ip)) => ips.add(&format!("{ip}:{port}")),
                    Some(IpAddr::V6(ip)) => ips.add(&format!("[{ip}]:{port}")),
                    None => net.add(host, Some(*port)),
                }
            }
        }
    }
    stats.unreachable_sockets = unix.unreachable.0.clone();
    stats.ip_hosts = ips.0;

    let mut items = fs_items(&fs, &env, &stats.processes);
    items.extend(blocked_items(blocked, &env));
    items.extend(net.items());
    items.extend(unix.items());
    if let Some(existing) = &ctx.existing {
        items.retain(|item| !doc_covers(existing, &item.grant, &env));
    }
    items.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    Summary { items, stats }
}

// ── Helpers: names ───────────────────────────────────────────────────────────

/// Distinct names in order of first appearance.
#[derive(Debug, Default, Clone)]
struct Names(Vec<String>);

impl Names {
    fn add(&mut self, name: &str) {
        add_name(&mut self.0, name);
    }

    fn extend(&mut self, other: &Self) {
        for name in &other.0 {
            self.add(name);
        }
    }
}

/// Add `name` to `names` if it is not empty and not in the list.
fn add_name(names: &mut Vec<String>, name: &str) {
    if !name.is_empty() && !names.iter().any(|n| n == name) {
        names.push(name.to_string());
    }
}

/// Join at most [`MAX_NAMES`] names, then `+N` for the rest.
fn list_names<S: AsRef<str>>(names: &[S]) -> String {
    let mut text = names
        .iter()
        .take(MAX_NAMES)
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(", ");
    let rest = names.len().saturating_sub(MAX_NAMES);
    if rest > 0 {
        text.push_str(&format!(" +{rest}"));
    }
    text
}

/// Sort process names by their first appearance in the session.
fn in_session_order(names: Names, order: &[String]) -> Vec<String> {
    let mut names = names.0;
    names.sort_by_key(|n| order.iter().position(|o| o == n).unwrap_or(usize::MAX));
    names
}

// ── Helpers: paths ───────────────────────────────────────────────────────────

/// Make an absolute path without `.` and `..` components. Return `None` for
/// a relative path, because a rule cannot use it.
fn normalize(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                // At the root, `pop` does nothing, like the kernel.
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    Some(out)
}

/// Return true for a short-lived path.
fn is_ephemeral(path: &Path) -> bool {
    if EPHEMERAL_DIRS.iter().any(|d| path.starts_with(d)) {
        return true;
    }
    let mut components = path.components();
    components.next() == Some(Component::RootDir)
        && components.next() == Some(Component::Normal(OsStr::new("proc")))
        && match components.next() {
            Some(Component::Normal(name)) => {
                name == "self"
                    || name == "thread-self"
                    || name
                        .to_str()
                        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            }
            _ => false,
        }
}

/// Return true if a directory name looks like a version (`2.1.3`,
/// `v22.1.0`, `1.80.0-x86_64-unknown-linux-gnu`).
fn is_version(name: &str) -> bool {
    let rest = name.strip_prefix('v').unwrap_or(name);
    rest.starts_with(|c: char| c.is_ascii_digit())
        && rest.contains('.')
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Return the path of the first `.git` directory in `path`, without `.git`.
fn repo_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|a| a.file_name() == Some(OsStr::new(".git")))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

/// The paths that the guard rules for `access` protect: the directories
/// (the root of a subtree, the directory of a file pattern) and the single
/// files.
fn guard_paths(home: &Path, access: GuardAccess) -> GuardPaths {
    let mut paths = GuardPaths::default();
    for rule in guard_rules(home) {
        if rule.access != access {
            continue;
        }
        match rule.target {
            GuardTarget::Exact(p) => paths.files.push(p),
            GuardTarget::Subtree(p) => paths.dirs.push(p),
            GuardTarget::FilesInDir { dir, .. } => paths.dirs.push(dir),
            GuardTarget::BinaryName(_) => {}
        }
    }
    paths
}

/// The paths that the guard rules of one access protect.
#[derive(Default)]
struct GuardPaths {
    /// The directories. A rule on such a directory, or on a parent of one,
    /// is too wide: it gives access to the files that the guard protects.
    dirs: Vec<PathBuf>,
    /// The single files. A rule on a parent of such a file is too wide. A
    /// rule on the file itself is not: it gives no more than the one file,
    /// and the guard still stops the access that it covers.
    files: Vec<PathBuf>,
}

impl GuardPaths {
    /// Return true if a rule on `path` would include a protected path.
    fn covered_by_a_rule_on(&self, path: &Path) -> bool {
        self.dirs.iter().any(|g| g.starts_with(path))
            || self.files.iter().any(|g| g.starts_with(path) && g != path)
    }
}

struct Env {
    home: Option<PathBuf>,
    workspace: Option<PathBuf>,
    covered: Vec<PathBuf>,
    /// The guard rules for the home directory.
    guard: Vec<GuardRule>,
    /// The paths of the read guard rules. No rule can include one of them.
    guarded_read: GuardPaths,
    /// The paths of the write guard rules. No read-write rule can include
    /// one of them.
    guarded_write: GuardPaths,
}

impl Env {
    fn new(ctx: &SummaryContext) -> Self {
        Self {
            // An empty or relative path is a prefix of each path, so the
            // summary ignores it.
            home: normalize(&ctx.home),
            workspace: normalize(&ctx.workspace),
            covered: ctx.covered.iter().filter_map(|p| normalize(p)).collect(),
            guard: guard_rules(&ctx.home),
            guarded_read: guard_paths(&ctx.home, GuardAccess::Read),
            guarded_write: guard_paths(&ctx.home, GuardAccess::Write),
        }
    }

    /// Return the guard class of an access, if a guard rule matches it.
    fn guard_class(&self, op: FsOp, path: &Path) -> Option<GuardClass> {
        let access = match op {
            FsOp::Read => GuardAccess::Read,
            FsOp::Exec => GuardAccess::ExecName,
            FsOp::Write | FsOp::Create | FsOp::Delete => GuardAccess::Write,
        };
        classify(&self.guard, path, access)
    }

    fn is_omitted(&self, path: &Path) -> bool {
        self.workspace.as_ref().is_some_and(|w| path.starts_with(w))
            || self.covered.iter().any(|c| path.starts_with(c))
            || is_ephemeral(path)
    }

    /// Return true if a directory is too broad for a rule.
    fn is_broad(&self, dir: &Path) -> bool {
        dir.components().count() <= 2
            || self.guarded_read.covered_by_a_rule_on(dir)
            || self.home.as_ref().is_some_and(|home| {
                home.starts_with(dir) || BROAD_HOME_DIRS.iter().any(|r| dir == home.join(r))
            })
    }

    /// Return true if grouping can make a rule on `dir`.
    fn can_group(&self, dir: &Path) -> bool {
        !self.is_broad(dir) && !self.workspace.as_ref().is_some_and(|w| w.starts_with(dir))
    }

    /// Return true if a directory is too broad for a read-write rule: it is
    /// broad, or it contains a path that the guard protects from writes.
    fn is_broad_for_write(&self, dir: &Path) -> bool {
        self.is_broad(dir) || self.guarded_write.covered_by_a_rule_on(dir)
    }

    /// Return true if grouping can make a read-write rule on `dir`.
    fn can_group_for_write(&self, dir: &Path) -> bool {
        self.can_group(dir) && !self.is_broad_for_write(dir)
    }

    /// Return true if a rule on `path` with `access` is too wide.
    ///
    /// The limit holds for every rule, not only for a rule that the grouping
    /// makes. One access on a broad directory (`open("~")`,
    /// `mkdir ~/.config`) must give no rule on it. The accesses below the
    /// directory keep their own rules.
    fn is_too_wide(&self, access: FsAccess, path: &Path) -> bool {
        match access {
            FsAccess::ReadWrite => self.is_broad_for_write(path),
            FsAccess::Read | FsAccess::Execute => self.is_broad(path),
        }
    }

    fn is_cache(&self, path: &Path) -> bool {
        self.home
            .as_ref()
            .is_some_and(|home| CACHE_DIRS.iter().any(|r| path.starts_with(home.join(r))))
    }

    /// Return the program directory in a cache (`~/.cache/<name>`) for a
    /// path below it. A program owns its cache directory, and the file
    /// names in it change, so the summary always makes one rule for it.
    fn cache_root(&self, path: &Path) -> Option<PathBuf> {
        let home = self.home.as_ref()?;
        CACHE_DIRS.iter().find_map(|r| {
            let cache = home.join(r);
            let rel = path.strip_prefix(&cache).ok()?;
            let first = rel.components().next()?;
            Some(cache.join(first))
        })
    }

    fn is_outside_home(&self, path: &Path) -> bool {
        !self
            .home
            .as_ref()
            .is_some_and(|home| path.starts_with(home))
    }

    /// Return the path as the profile writes it (`~/` for the home
    /// directory). Return `None` for a path that is not valid UTF-8: a rule
    /// cannot name it.
    fn display(&self, path: &Path) -> Option<String> {
        if let Some(rel) = self.home.as_ref().and_then(|h| path.strip_prefix(h).ok()) {
            if rel.as_os_str().is_empty() {
                return Some("~".to_string());
            }
            return rel.to_str().map(|r| format!("~/{r}"));
        }
        path.to_str().map(str::to_string)
    }

    /// Return a profile path in the form of [`Self::display`].
    fn rule_form(&self, rule: &str) -> PathBuf {
        normalize(Path::new(rule))
            .and_then(|p| self.display(&p))
            .map_or_else(|| PathBuf::from(rule), PathBuf::from)
    }

    /// Return the directory for the execute rule of `binary`.
    fn exec_dir(&self, binary: &Path) -> PathBuf {
        let Some(parent) = binary.parent() else {
            return binary.to_path_buf();
        };
        let mut dir = parent;
        let version = parent.ancestors().find(|a| {
            a.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(is_version)
        });
        if let Some(up) = version.and_then(Path::parent) {
            dir = up;
        }
        if dir.file_name() == Some(OsStr::new("versions")) {
            if let Some(up) = dir.parent() {
                dir = up;
            }
        }
        if !self.is_broad(dir) {
            return dir.to_path_buf();
        }
        if !self.is_broad(parent) {
            return parent.to_path_buf();
        }
        binary.to_path_buf()
    }
}

// ── Filesystem ───────────────────────────────────────────────────────────────

/// The filesystem events that the summary keeps, by path.
#[derive(Default)]
struct FsLog {
    reads: BTreeMap<PathBuf, Names>,
    writes: BTreeMap<PathBuf, Names>,
    execs: BTreeMap<PathBuf, Names>,
    created: BTreeSet<PathBuf>,
    deleted: BTreeSet<PathBuf>,
    /// True if the path exists after the last create or delete.
    exists_at_end: BTreeMap<PathBuf, bool>,
    /// The roots of the source repositories that the program touched.
    repos: BTreeSet<PathBuf>,
}

impl FsLog {
    fn record(&mut self, op: FsOp, path: PathBuf, process: &str) {
        if let Some(root) = repo_root(&path) {
            self.repos.insert(root);
        }
        match op {
            FsOp::Read => self.reads.entry(path).or_default().add(process),
            FsOp::Write => self.writes.entry(path).or_default().add(process),
            FsOp::Exec => self.execs.entry(path).or_default().add(process),
            FsOp::Create => {
                self.created.insert(path.clone());
                self.exists_at_end.insert(path, true);
            }
            FsOp::Delete => {
                self.deleted.insert(path.clone());
                self.exists_at_end.insert(path, false);
            }
        }
    }

    /// Return true if the program created `path` and deleted it again.
    fn is_transient(&self, path: &Path) -> bool {
        self.created.contains(path) && self.exists_at_end.get(path) == Some(&false)
    }
}

/// Return true if a rule with access `wide` includes access `narrow`.
fn includes(wide: FsAccess, narrow: FsAccess) -> bool {
    wide == narrow || (narrow == FsAccess::Read && wide != FsAccess::Read)
}

/// Replace each group of at least [`DIR_THRESHOLD`] entries in one directory
/// with one rule on the directory. Only the candidates for which `counts`
/// returns true make a directory an entry of its parent.
///
/// When grouping makes a rule on a directory, the entries of its parent do
/// not change: the new rule is below the same child. Thus one pass over the
/// tree gives the same result as repeated passes.
fn group(
    candidates: &BTreeSet<PathBuf>,
    counts: impl Fn(&Path) -> bool,
    allowed: impl Fn(&Path) -> bool,
) -> BTreeSet<PathBuf> {
    let mut entries: BTreeMap<&Path, BTreeSet<&Path>> = BTreeMap::new();
    for candidate in candidates.iter().filter(|c| counts(c)) {
        let mut child = candidate.as_path();
        while let Some(parent) = child.parent() {
            entries.entry(parent).or_default().insert(child);
            child = parent;
        }
    }
    let groups: BTreeSet<&Path> = entries
        .iter()
        .filter(|(dir, kids)| kids.len() >= DIR_THRESHOLD && allowed(dir))
        .map(|(dir, _)| *dir)
        .collect();
    candidates
        .iter()
        .map(|c| {
            c.ancestors()
                .filter(|a| groups.contains(a))
                .last()
                .unwrap_or(c)
                .to_path_buf()
        })
        .collect()
}

/// Make the filesystem items.
fn fs_items(fs: &FsLog, env: &Env, order: &[String]) -> Vec<Item> {
    // Read-write: a create or a delete gives the directory, a write to an
    // existing file gives the file.
    let mut rw_dirs = BTreeSet::new();
    let mut rw = BTreeSet::new();
    for path in fs.created.iter().chain(fs.deleted.iter()) {
        if let Some(cache) = env.cache_root(path) {
            rw_dirs.insert(cache.clone());
            rw.insert(cache);
            continue;
        }
        let Some(dir) = path.parent() else {
            continue;
        };
        if env.can_group_for_write(dir) {
            rw_dirs.insert(dir.to_path_buf());
            rw.insert(dir.to_path_buf());
        } else if !fs.is_transient(path) {
            // A directory that is too wide for a rule (a broad directory,
            // the workspace or a parent of it) gets no rule. The file keeps
            // its own rule. A temporary file gets no rule: its next name is
            // not known.
            rw.insert(path.clone());
        }
    }
    // Writes to existing files: two or more files in one directory give the
    // directory, because the program probably writes other files there too.
    let mut writes_in_dir: BTreeMap<&Path, usize> = BTreeMap::new();
    for path in fs.writes.keys().filter(|p| !fs.created.contains(*p)) {
        if let Some(cache) = env.cache_root(path) {
            rw_dirs.insert(cache.clone());
            rw.insert(cache);
            continue;
        }
        rw.insert(path.clone());
        if let Some(dir) = path.parent() {
            let n = writes_in_dir.entry(dir).or_default();
            *n = n.saturating_add(1);
        }
    }
    for (dir, n) in writes_in_dir {
        if n >= WRITE_DIR_THRESHOLD && env.can_group_for_write(dir) {
            rw_dirs.insert(dir.to_path_buf());
            rw.insert(dir.to_path_buf());
        }
    }
    // Every final rule keeps the limit of the grouping, also a rule that
    // comes from one direct access. A rule that is too wide goes away before
    // the next step, so it does not hide a narrower rule below it.
    let rw: BTreeSet<PathBuf> = group(&rw, |p| rw_dirs.contains(p), |d| env.can_group_for_write(d))
        .into_iter()
        .filter(|p| !env.is_too_wide(FsAccess::ReadWrite, p))
        .collect();

    let exec: BTreeSet<PathBuf> = fs
        .execs
        .keys()
        .map(|b| env.exec_dir(b))
        .filter(|p| !env.is_too_wide(FsAccess::Execute, p))
        .collect();

    let wider_exists = |path: &Path| path.ancestors().any(|a| rw.contains(a) || exec.contains(a));
    let read: BTreeSet<PathBuf> = fs
        .reads
        .keys()
        .map(|p| env.cache_root(p).unwrap_or_else(|| p.clone()))
        .filter(|p| !wider_exists(p))
        .collect();
    let read: BTreeSet<PathBuf> = group(&read, |_| true, |d| env.can_group(d))
        .into_iter()
        .filter(|p| !env.is_too_wide(FsAccess::Read, p))
        .collect();

    let mut rules: BTreeSet<(FsAccess, PathBuf)> = BTreeSet::new();
    rules.extend(rw.into_iter().map(|p| (FsAccess::ReadWrite, p)));
    rules.extend(exec.into_iter().map(|p| (FsAccess::Execute, p)));
    rules.extend(read.into_iter().map(|p| (FsAccess::Read, p)));

    let hidden = |access: FsAccess, path: &Path| {
        path.ancestors().any(|a| {
            [FsAccess::Read, FsAccess::ReadWrite, FsAccess::Execute]
                .into_iter()
                .filter(|&wide| includes(wide, access))
                .filter(|&wide| a != path || wide != access)
                .any(|wide| rules.contains(&(wide, a.to_path_buf())))
        })
    };

    let mut items = Vec::new();
    for (access, path) in &rules {
        if hidden(*access, path) {
            continue;
        }
        let Some(shown) = env.display(path) else {
            continue;
        };
        let mut notes = Vec::new();
        let reason = match access {
            FsAccess::ReadWrite => rw_reason(fs, env, path),
            FsAccess::Read => read_reason(fs, env, path, order),
            FsAccess::Execute => {
                let mut binaries = Names::default();
                for binary in fs.execs.keys().filter(|b| b.starts_with(path)) {
                    if let Some(name) = binary.file_name().and_then(OsStr::to_str) {
                        binaries.add(name);
                    }
                    if fs.created.contains(binary)
                        && !notes.contains(&ItemNote::CreatedThenExecuted)
                    {
                        notes.push(ItemNote::CreatedThenExecuted);
                    }
                }
                format!("runs {}", list_names(&binaries.0))
            }
        };
        if env.is_outside_home(path) {
            notes.push(ItemNote::OutsideHome);
        }
        let other_repo = fs.repos.iter().any(|root| {
            !env.workspace.as_ref().is_some_and(|w| w.starts_with(root))
                && (path.starts_with(root) || root.starts_with(path))
        });
        if other_repo {
            notes.push(ItemNote::OtherRepository);
        }
        items.push(Item {
            grant: Grant::Fs {
                access: *access,
                path: shown,
            },
            reason,
            blocked: None,
            notes,
        });
    }
    items
}

/// Return the reason of a read rule on `path`.
fn read_reason(fs: &FsLog, env: &Env, path: &Path, order: &[String]) -> String {
    if env.is_cache(path) {
        return "cache".to_string();
    }
    let mut names = Names::default();
    for (_, n) in fs.reads.iter().filter(|(p, _)| p.starts_with(path)) {
        names.extend(n);
    }
    let names = in_session_order(names, order);
    if names.is_empty() {
        "read".to_string()
    } else {
        format!("read by {}", list_names(&names))
    }
}

/// Return the reason of a read-write rule on `path`.
fn rw_reason(fs: &FsLog, env: &Env, path: &Path) -> String {
    if env.is_cache(path) {
        return "cache".to_string();
    }
    let below = |set: &mut dyn Iterator<Item = &PathBuf>| {
        set.filter(|p| p.starts_with(path) && p.as_path() != path)
            .count()
    };
    let new = below(&mut fs.created.iter());
    let deleted = below(&mut fs.deleted.iter());
    let written = below(&mut fs.writes.keys());
    if new > 0 {
        return format!("creates and edits files ({} new)", format_count(new));
    }
    if deleted > 0 && written == 0 {
        return "deletes files".to_string();
    }
    if written > 0 || deleted > 0 {
        return "edits files".to_string();
    }
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".lock") || name.ends_with(".pid") {
        "lock file".to_string()
    } else if name.ends_with(".log") {
        "log file".to_string()
    } else if name.contains("history") {
        "history file".to_string()
    } else {
        "config file".to_string()
    }
}

/// Format a count with a comma between groups of three digits (`1,834`).
#[must_use]
pub fn format_count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && digits.len().saturating_sub(i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// ── Blocked accesses ─────────────────────────────────────────────────────────

/// One blocked access, merged by grant.
struct BlockedEntry {
    class: GuardClass,
    processes: Names,
    binaries: Names,
}

fn add_blocked(
    blocked: &mut BTreeMap<(FsAccess, PathBuf), BlockedEntry>,
    op: FsOp,
    path: PathBuf,
    class: GuardClass,
    process: &str,
    env: &Env,
) {
    let binary = (op == FsOp::Exec)
        .then(|| path.file_name().and_then(OsStr::to_str).map(str::to_string))
        .flatten();
    let key = match op {
        FsOp::Read => (FsAccess::Read, path),
        FsOp::Exec => (FsAccess::Execute, env.exec_dir(&path)),
        FsOp::Write | FsOp::Create | FsOp::Delete => (FsAccess::ReadWrite, path),
    };
    let entry = blocked.entry(key).or_insert_with(|| BlockedEntry {
        class,
        processes: Names::default(),
        binaries: Names::default(),
    });
    entry.processes.add(process);
    if let Some(binary) = binary {
        entry.binaries.add(&binary);
    }
}

fn blocked_items(blocked: BTreeMap<(FsAccess, PathBuf), BlockedEntry>, env: &Env) -> Vec<Item> {
    blocked
        .into_iter()
        .filter_map(|((access, path), entry)| {
            let shown = env.display(&path)?;
            let reason = if access == FsAccess::Execute && !entry.binaries.0.is_empty() {
                format!("runs {}", list_names(&entry.binaries.0))
            } else if entry.processes.0.is_empty() {
                match access {
                    FsAccess::Read => "read",
                    FsAccess::ReadWrite => "write",
                    FsAccess::Execute => "exec",
                }
                .to_string()
            } else {
                list_names(&entry.processes.0)
            };
            Some(Item {
                grant: Grant::Fs {
                    access,
                    path: shown,
                },
                reason,
                blocked: Some(entry.class),
                notes: Vec::new(),
            })
        })
        .collect()
}

// ── Network ──────────────────────────────────────────────────────────────────

/// Parse a host as an IP address (`1.2.3.4`, `::1` or `[::1]`).
fn parse_ip(host: &str) -> Option<IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse().ok()
}

/// Normalize a domain name. Return `None` for a name that cannot be a rule:
/// an IP address, a name with one label, a local name (`localhost`,
/// `*.local`) or a reverse lookup (`*.arpa`).
fn normalize_domain(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.contains('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.split('.').any(str::is_empty);
    let local = name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.ends_with(".arpa");
    (valid && !local && parse_ip(&name).is_none()).then_some(name)
}

/// One domain, with the ports of its connections.
struct DomainEntry {
    order: usize,
    ports: BTreeSet<u16>,
}

#[derive(Default)]
struct NetLog {
    domains: BTreeMap<String, DomainEntry>,
}

impl NetLog {
    fn add(&mut self, raw: &str, port: Option<u16>) {
        let Some(name) = normalize_domain(raw) else {
            return;
        };
        let order = self.domains.len();
        let entry = self.domains.entry(name).or_insert_with(|| DomainEntry {
            order,
            ports: BTreeSet::new(),
        });
        if let Some(port) = port {
            entry.ports.insert(port);
        }
    }

    fn items(&self) -> Vec<Item> {
        let mut below: BTreeMap<&str, Vec<(&str, usize)>> = BTreeMap::new();
        for (name, entry) in &self.domains {
            if let Some(registrable) = psl::registrable_domain(name) {
                if registrable != name {
                    below
                        .entry(registrable)
                        .or_default()
                        .push((name.as_str(), entry.order));
                }
            }
        }
        let mut items = Vec::new();
        let mut grouped = BTreeSet::new();
        for (registrable, mut names) in below {
            if names.len() < WILDCARD_THRESHOLD || !psl::wildcard_allowed(registrable) {
                continue;
            }
            names.sort_by_key(|(_, order)| *order);
            let labels: Vec<&str> = names
                .iter()
                .map(|(name, _)| {
                    name.strip_suffix(registrable)
                        .map_or(*name, |rest| rest.trim_end_matches('.'))
                })
                .collect();
            items.push(Item {
                grant: Grant::Domain(format!("*.{registrable}")),
                reason: list_names(&labels),
                blocked: None,
                notes: Vec::new(),
            });
            grouped.extend(names.iter().map(|(name, _)| *name));
        }
        for (name, entry) in &self.domains {
            if grouped.contains(name.as_str()) {
                continue;
            }
            items.push(Item {
                grant: Grant::Domain(name.clone()),
                reason: port_reason(&entry.ports),
                blocked: None,
                notes: Vec::new(),
            });
        }
        items
    }
}

/// Return the reason of a domain from its ports.
fn port_reason(ports: &BTreeSet<u16>) -> String {
    if ports.is_empty() {
        return "DNS lookup only".to_string();
    }
    // HTTPS and HTTP first, then the other ports in order.
    let mut parts = Vec::new();
    if ports.contains(&443) {
        parts.push("HTTPS".to_string());
    }
    if ports.contains(&80) {
        parts.push("HTTP".to_string());
    }
    parts.extend(
        ports
            .iter()
            .filter(|p| !matches!(p, 80 | 443))
            .map(|p| format!("port {p}")),
    );
    list_names(&parts)
}

// ── Unix sockets ─────────────────────────────────────────────────────────────

/// Return the name of a common Unix socket, or `None` for a socket that
/// pent does not know.
///
/// The name tells the user what the rule gives. A program that reaches the
/// socket of an agent can use the key of that agent.
fn known_socket(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(lower.as_str());
    if lower.contains("ssh-agent")
        || name.starts_with("agent.")
        || lower.ends_with("/keyring/ssh")
        || lower.ends_with("/gcr/ssh")
    {
        return Some("ssh-agent");
    }
    if lower.contains("gpg-agent") {
        return Some("gpg-agent");
    }
    if name == "bus" || name.ends_with("_bus_socket") || lower.contains("dbus") {
        return Some("D-Bus");
    }
    if name == "docker.sock" || name == "podman.sock" {
        return Some("Docker");
    }
    None
}

/// The connections to a Unix socket that the summary keeps.
#[derive(Default)]
struct UnixLog {
    /// The processes of each socket, by the path in the form of the profile.
    sockets: BTreeMap<String, Names>,
    /// The targets that a rule cannot name.
    unreachable: Names,
}

impl UnixLog {
    fn add(&mut self, shown: &str, process: &str) {
        self.sockets
            .entry(shown.to_string())
            .or_default()
            .add(process);
    }

    /// One item for each socket path.
    fn items(&self) -> Vec<Item> {
        self.sockets
            .iter()
            .map(|(path, processes)| Item {
                grant: Grant::UnixSocket(path.clone()),
                reason: unix_reason(path, &processes.0),
                blocked: None,
                notes: Vec::new(),
            })
            .collect()
    }
}

/// Return the reason of a Unix socket rule: the name of the agent when pent
/// knows the socket, else the processes that connected to it.
fn unix_reason(path: &str, processes: &[String]) -> String {
    if let Some(known) = known_socket(path) {
        return known.to_string();
    }
    if processes.is_empty() {
        return "Unix socket".to_string();
    }
    format!("used by {}", list_names(processes))
}

// ── Existing profile and order ───────────────────────────────────────────────

/// Return true if the domain rule `rule` matches the domain or wildcard
/// `domain`.
fn domain_covers(rule: &str, domain: &str) -> bool {
    if rule == domain {
        return true;
    }
    let Some(base) = rule.strip_prefix("*.") else {
        return false;
    };
    let target = domain.strip_prefix("*.").unwrap_or(domain);
    target
        .strip_suffix(base)
        .is_some_and(|rest| rest.ends_with('.'))
        || (target == base && domain.starts_with("*."))
}

/// Return true if the profile `doc` already has a rule that includes
/// `grant`.
fn doc_covers(doc: &ProfileDoc, grant: &Grant, env: &Env) -> bool {
    match grant {
        Grant::Fs { access, path } => {
            let fs = &doc.filesystem;
            let lists: &[&Vec<String>] = match access {
                FsAccess::Read => &[&fs.read, &fs.read_write, &fs.execute],
                FsAccess::ReadWrite => &[&fs.read_write],
                FsAccess::Execute => &[&fs.execute],
            };
            let path = Path::new(path);
            lists
                .iter()
                .flat_map(|list| list.iter())
                .any(|rule| path.starts_with(env.rule_form(rule)))
        }
        Grant::Domain(domain) => doc
            .network
            .domains
            .iter()
            .any(|rule| domain_covers(rule, domain)),
        // A socket rule names one path, so only the same path covers it.
        Grant::UnixSocket(path) => doc
            .filesystem
            .unix_sockets
            .iter()
            .any(|rule| env.rule_form(rule) == Path::new(path)),
    }
}

/// The sort key of an item: the section, then the path or the domain. A
/// wildcard sorts next to its domain.
fn sort_key(item: &Item) -> (Section, &str, bool) {
    match &item.grant {
        Grant::Fs { path, .. } | Grant::UnixSocket(path) => (item.section(), path.as_str(), false),
        Grant::Domain(domain) => match domain.strip_prefix("*.") {
            Some(base) => (item.section(), base, true),
            None => (item.section(), domain.as_str(), false),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{blocked, claude_session, connect, ctx, dns, fs, fs_outcome};
    use FsOp::{Create, Delete, Exec, Read, Write};

    /// One line for each item: `<section> <rule> | <reason> [notes]`.
    fn lines(summary: &Summary) -> Vec<String> {
        summary
            .items
            .iter()
            .map(|item| {
                let section = match item.section() {
                    Section::ReadWrite => "rw",
                    Section::Read => "r",
                    Section::Execute => "x",
                    Section::UnixSockets => "unix",
                    Section::Network => "net",
                    Section::Blocked => "blocked",
                };
                let rule = match &item.grant {
                    Grant::Fs { access, path } if item.blocked.is_some() => {
                        format!("{access:?} {path}")
                    }
                    Grant::Fs { path, .. } | Grant::UnixSocket(path) => path.clone(),
                    Grant::Domain(d) => d.clone(),
                };
                let mut line = format!("{section} {rule} | {}", item.reason);
                if let Some(class) = item.blocked {
                    line.push_str(&format!(" ({class:?})"));
                }
                if !item.notes.is_empty() {
                    line.push_str(&format!(" {:?}", item.notes));
                }
                line
            })
            .collect()
    }

    fn run(events: &[WatchEvent]) -> Vec<String> {
        lines(&summarize(events, &ctx()))
    }

    #[test]
    fn claude_session_gives_a_short_list() {
        let events = claude_session();
        let summary = summarize(&events, &ctx());
        assert_eq!(
            lines(&summary),
            vec![
                "rw ~/.cache/claude | cache",
                "rw ~/.claude | creates and edits files (37 new)",
                "rw ~/.claude.json | config file",
                "r ~/.config/git/ignore | read by git",
                "r ~/.gitconfig | read by git",
                "r ~/.ssh/config | read by ssh",
                "r ~/.ssh/known_hosts | read by git, ssh",
                "x ~/.local/share/claude | runs claude",
                "x ~/.nvm/versions/node | runs node",
                "unix /run/user/1000/bus | D-Bus",
                "net api.anthropic.com | HTTPS",
                "net github.com | port 22",
                "net *.npmjs.org | registry, www, cdn",
                "net statsig.anthropic.com | HTTPS",
                "blocked ReadWrite ~/.bashrc | node (Persistence)",
                "blocked Read ~/.ssh/id_ed25519 | ssh (Credential)",
            ]
        );
        let stats = &summary.stats;
        assert_eq!(stats.processes, vec!["claude", "git", "ssh", "node"]);
        assert_eq!(stats.unreachable_sockets, vec!["@/tmp/.X11-unix/X0"]);
        assert_eq!(stats.refused_unix_sockets, 1);
        assert_eq!(stats.ip_hosts, vec!["140.82.112.3:443"]);
        assert_eq!(stats.net_events, 508);
        assert_eq!(stats.total_events(), events.len());
    }

    #[test]
    fn omits_workspace_covered_and_ephemeral_paths() {
        let events = [
            fs(Read, "/home/u/work/app/README.md", "a"),
            fs(Read, "/usr/lib/libz.so", "a"),
            fs(Read, "/proc/self/status", "a"),
            fs(Read, "/proc/77/cmdline", "a"),
            fs(Create, "/tmp/x", "a"),
            fs(Write, "/var/tmp/y", "a"),
            fs(Read, "/dev/tty", "a"),
            fs(Read, "relative/path", "a"),
        ];
        assert!(run(&events).is_empty());
    }

    #[test]
    fn four_reads_in_a_directory_give_one_rule() {
        let three: Vec<_> = (0..3)
            .map(|i| fs(Read, &format!("/home/u/.tool/f{i}"), "tool"))
            .collect();
        assert_eq!(run(&three).len(), 3);
        let four: Vec<_> = (0..4)
            .map(|i| fs(Read, &format!("/home/u/.tool/f{i}"), "tool"))
            .collect();
        assert_eq!(run(&four), vec!["r ~/.tool | read by tool"]);
    }

    #[test]
    fn grouping_goes_up_the_tree() {
        let events: Vec<_> = (0..4)
            .flat_map(|d| (0..2).map(move |f| (d, f)))
            .map(|(d, f)| fs(Read, &format!("/home/u/.tool/d{d}/f{f}"), "tool"))
            .collect();
        assert_eq!(run(&events), vec!["r ~/.tool | read by tool"]);
    }

    #[test]
    fn never_groups_on_broad_directories() {
        let events: Vec<_> = ["a.toml", "b.toml", "c.toml", "d.toml"]
            .iter()
            .map(|f| fs(Read, &format!("/home/u/.config/{f}"), "tool"))
            .chain((0..4).map(|i| fs(Read, &format!("/home/u/.f{i}"), "tool")))
            .collect();
        assert_eq!(
            run(&events),
            vec![
                "r ~/.config/a.toml | read by tool",
                "r ~/.config/b.toml | read by tool",
                "r ~/.config/c.toml | read by tool",
                "r ~/.config/d.toml | read by tool",
                "r ~/.f0 | read by tool",
                "r ~/.f1 | read by tool",
                "r ~/.f2 | read by tool",
                "r ~/.f3 | read by tool",
            ]
        );
        // Creates directly in ~/.cache give a rule on the child.
        let events = [
            fs(Create, "/home/u/.cache/tool", "tool"),
            fs(Create, "/home/u/.cache/tool/a", "tool"),
        ];
        assert_eq!(run(&events), vec!["rw ~/.cache/tool | cache"]);
        // A new broad directory gives a rule on the child, not on itself.
        let events = [
            fs(Create, "/home/u/.local/share", "tool"),
            fs(Create, "/home/u/.local/share/tool", "tool"),
            fs(Create, "/home/u/.local/share/tool/a", "tool"),
        ];
        assert_eq!(
            run(&events),
            vec!["rw ~/.local/share/tool | creates and edits files (1 new)"]
        );
    }

    #[test]
    fn never_groups_on_the_workspace_parent() {
        let events: Vec<_> = (0..4)
            .map(|i| fs(Read, &format!("/home/u/work/other{i}/README.md"), "tool"))
            .collect();
        assert_eq!(run(&events).len(), 4);
    }

    #[test]
    fn denied_credential_reads_are_blocked_items() {
        let events = [
            fs_outcome(Read, "/home/u/.ssh/id_ed25519", "ssh", Outcome::Denied),
            fs_outcome(Read, "/home/u/.ssh/id_rsa", "ssh", Outcome::Denied),
            fs_outcome(Read, "/home/u/.ssh/known_hosts", "ssh", Outcome::Denied),
            fs_outcome(Read, "/home/u/.ssh/config", "ssh", Outcome::Denied),
            fs_outcome(Read, "/home/u/.ssh/other", "ssh", Outcome::Denied),
        ];
        let lines = run(&events);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("blocked Read ~/.ssh/id_ed25519")),
            "{lines:?}"
        );
        // ~/.ssh holds guarded keys, so it never gets a directory rule.
        assert!(
            !lines.iter().any(|l| l.starts_with("r ~/.ssh |")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("r ~/.ssh/known_hosts")),
            "{lines:?}"
        );
    }

    #[test]
    fn cache_accesses_give_the_cache_directory() {
        let events = [
            fs(Write, "/home/u/.cache/app/a/f1", "app"),
            fs(Read, "/home/u/.cache/app/b/f2", "app"),
            fs(Read, "/home/u/.cache/other/x", "app"),
        ];
        let lines = run(&events);
        assert!(
            lines.iter().any(|l| l.starts_with("rw ~/.cache/app")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("r ~/.cache/other")),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("f1") || l.contains("f2")),
            "{lines:?}"
        );
    }

    #[test]
    fn two_written_files_give_the_directory() {
        let events = [
            fs(Write, "/home/u/.config/app/a.json", "app"),
            fs(Write, "/home/u/.config/app/b.json", "app"),
        ];
        let lines = run(&events);
        assert!(
            lines.iter().any(|l| l.starts_with("rw ~/.config/app")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("a.json")), "{lines:?}");
    }

    #[test]
    fn creates_give_the_directory_and_writes_give_the_file() {
        let events = [
            fs(Write, "/home/u/.tool/config.json", "tool"),
            fs(Write, "/home/u/.other/state.json", "tool"),
            fs(Create, "/home/u/.other/lock", "tool"),
        ];
        assert_eq!(
            run(&events),
            vec![
                "rw ~/.other | creates and edits files (1 new)",
                "rw ~/.tool/config.json | config file",
            ]
        );
    }

    #[test]
    fn deletes_count_as_writes_to_the_directory() {
        let events = [fs(Delete, "/home/u/.tool/old.log", "tool")];
        assert_eq!(run(&events), vec!["rw ~/.tool | deletes files"]);
    }

    #[test]
    fn temporary_files_in_home_give_no_rule() {
        let events = [
            fs(Create, "/home/u/.tool.json.tmp", "tool"),
            fs(Delete, "/home/u/.tool.json.tmp", "tool"),
            fs(Create, "/home/u/.tool.json", "tool"),
            fs(Write, "/home/u/.bash_history", "bash"),
        ];
        assert_eq!(
            run(&events),
            vec![
                "rw ~/.bash_history | history file",
                "rw ~/.tool.json | config file",
            ]
        );
    }

    #[test]
    fn wider_rules_hide_narrower_rules() {
        let events = [
            fs(Read, "/home/u/.tool/a", "tool"),
            fs(Write, "/home/u/.tool/b", "tool"),
            fs(Create, "/home/u/.tool/c", "tool"),
            fs(Exec, "/opt/tool/bin/tool", "tool"),
            fs(Read, "/opt/tool/lib/x.so", "tool"),
        ];
        assert_eq!(
            run(&events),
            vec![
                "rw ~/.tool | creates and edits files (1 new)",
                "r /opt/tool/lib/x.so | read by tool [OutsideHome]",
                "x /opt/tool/bin | runs tool [OutsideHome]",
            ]
        );
    }

    #[test]
    fn exec_rules_skip_version_directories() {
        let events = [
            fs(
                Exec,
                "/home/u/.rustup/toolchains/1.80.0-x86_64-unknown-linux-gnu/bin/cargo",
                "sh",
            ),
            fs(Exec, "/home/u/.local/share/claude/versions/2.1.4", "sh"),
            fs(Exec, "/home/u/.local/bin/tool", "sh"),
            fs(Exec, "/home/u/run.sh", "sh"),
        ];
        assert_eq!(
            run(&events),
            vec![
                "x ~/.local/bin | runs tool",
                "x ~/.local/share/claude | runs 2.1.4",
                "x ~/.rustup/toolchains | runs cargo",
                "x ~/run.sh | runs run.sh",
            ]
        );
    }

    #[test]
    fn created_then_executed_gets_a_note() {
        let events = [
            fs(Create, "/home/u/build/out/tool", "cc"),
            fs(Exec, "/home/u/build/out/tool", "make"),
        ];
        assert_eq!(
            run(&events),
            vec![
                "rw ~/build/out | creates and edits files (1 new)",
                "x ~/build/out | runs tool [CreatedThenExecuted]",
            ]
        );
    }

    #[test]
    fn other_repositories_get_a_note() {
        let events = [
            fs(Read, "/home/u/src/lib/.git/HEAD", "git"),
            fs(Read, "/home/u/work/app/.git/HEAD", "git"),
        ];
        assert_eq!(
            run(&events),
            vec!["r ~/src/lib/.git/HEAD | read by git [OtherRepository]"]
        );
    }

    #[test]
    fn existing_rules_are_omitted() {
        let mut ctx = ctx();
        let mut doc = ProfileDoc::default();
        doc.filesystem.read_write.push("~/.tool".to_string());
        doc.filesystem
            .execute
            .push("/home/u/.local/bin".to_string());
        doc.network.domains.push("*.npmjs.org".to_string());
        ctx.existing = Some(doc);
        let events = [
            fs(Read, "/home/u/.tool/a", "tool"),
            fs(Create, "/home/u/.tool/b/c", "tool"),
            fs(Exec, "/home/u/.local/bin/tool", "sh"),
            fs(Exec, "/home/u/.local/bin2/tool", "sh"),
            connect("registry.npmjs.org", 443),
            connect("npmjs.org", 443),
        ];
        assert_eq!(
            lines(&summarize(&events, &ctx)),
            vec!["x ~/.local/bin2 | runs tool", "net npmjs.org | HTTPS"]
        );
    }

    #[test]
    fn denied_events_are_normal_items() {
        let events = [
            fs_outcome(Read, "/home/u/.tool/a", "tool", Outcome::Denied),
            fs_outcome(Read, "/home/u/.ssh/id_rsa", "ssh", Outcome::Denied),
        ];
        // A denied read of a credential is a blocked item, so the review
        // does not select it by default.
        assert_eq!(
            run(&events),
            vec![
                "r ~/.tool/a | read by tool",
                "blocked Read ~/.ssh/id_rsa | ssh (Credential)"
            ]
        );
    }

    #[test]
    fn blocked_events_become_blocked_items() {
        let events = [
            blocked(
                Read,
                "/home/u/.aws/credentials",
                "aws",
                GuardClass::Credential,
            ),
            blocked(
                Read,
                "/home/u/.aws/credentials",
                "python3",
                GuardClass::Credential,
            ),
            blocked(
                Exec,
                "/run/wrappers/bin/sudo",
                "bash",
                GuardClass::PrivilegeEscalation,
            ),
            blocked(
                Create,
                "/home/u/.config/pent/profiles/x.toml",
                "x",
                GuardClass::PentFiles,
            ),
        ];
        assert_eq!(
            run(&events),
            vec![
                "blocked Execute /run/wrappers/bin | runs sudo (PrivilegeEscalation)",
                "blocked Read ~/.aws/credentials | aws, python3 (Credential)",
                "blocked ReadWrite ~/.config/pent/profiles/x.toml | x (PentFiles)",
            ]
        );
    }

    #[test]
    fn wildcards_need_three_names_and_never_use_a_public_suffix() {
        let events = [
            connect("a.example.co.uk", 443),
            connect("b.example.co.uk", 443),
            connect("c.example.co.uk", 443),
            connect("one.github.io", 443),
            connect("two.github.io", 443),
            connect("three.github.io", 443),
            connect("x.foo.dev", 443),
            connect("y.foo.dev", 80),
            connect("b1.s3.amazonaws.com", 443),
            connect("b2.s3.amazonaws.com", 443),
            connect("b3.s3.amazonaws.com", 443),
        ];
        assert_eq!(
            run(&events),
            vec![
                "net b1.s3.amazonaws.com | HTTPS",
                "net b2.s3.amazonaws.com | HTTPS",
                "net b3.s3.amazonaws.com | HTTPS",
                "net *.example.co.uk | a, b, c",
                "net one.github.io | HTTPS",
                "net three.github.io | HTTPS",
                "net two.github.io | HTTPS",
                "net x.foo.dev | HTTPS",
                "net y.foo.dev | HTTP",
            ]
        );
    }

    #[test]
    fn wildcard_reasons_list_at_most_three_names() {
        let events: Vec<_> = ["registry", "www", "cdn", "api", "a.b"]
            .iter()
            .map(|l| connect(&format!("{l}.npmjs.org"), 443))
            .collect();
        assert_eq!(
            run(&events),
            vec!["net *.npmjs.org | registry, www, cdn +2"]
        );
    }

    #[test]
    fn network_reasons_and_skipped_names() {
        let events = [
            dns("Example.COM."),
            dns("localhost"),
            dns("printer.local"),
            dns("1.0.0.127.in-addr.arpa"),
            dns("intranet"),
            connect("ssh.example.org", 22),
            connect("ssh.example.org", 443),
            connect("ssh.example.org", 80),
            connect("::1", 8080),
            connect("[2001:db8::1]", 443),
        ];
        let summary = summarize(&events, &ctx());
        assert_eq!(
            lines(&summary),
            vec![
                "net example.com | DNS lookup only",
                "net ssh.example.org | HTTPS, HTTP, port 22",
            ]
        );
        assert_eq!(
            summary.stats.ip_hosts,
            vec!["[::1]:8080", "[2001:db8::1]:443"]
        );
    }

    #[test]
    fn process_names_show_at_most_three() {
        let events: Vec<_> = ["a", "b", "c", "d", "e", "a"]
            .iter()
            .map(|p| fs(Read, "/home/u/.shared", p))
            .collect();
        assert_eq!(run(&events), vec!["r ~/.shared | read by a, b, c +2"]);
    }

    /// A `connect()` to a socket with a path.
    fn unix(target: &str, process: &str, outcome: Outcome) -> WatchEvent {
        WatchEvent::UnixConnect {
            target: target.to_string(),
            process: crate::ProcessInfo {
                pid: 1,
                name: process.to_string(),
            },
            outcome,
        }
    }

    #[test]
    fn unix_sockets_use_the_home_form_and_name_the_agent() {
        let events = [
            unix("/home/u/.gnupg/S.gpg-agent", "gpg", Outcome::Denied),
            unix("/home/u/.tool/tool.sock", "tool", Outcome::Denied),
            unix("/home/u/.tool/tool.sock", "other", Outcome::Denied),
        ];
        let summary = summarize(&events, &ctx());
        assert_eq!(
            lines(&summary),
            vec![
                "unix ~/.gnupg/S.gpg-agent | gpg-agent",
                "unix ~/.tool/tool.sock | used by tool, other",
            ]
        );
        assert!(summary.stats.unreachable_sockets.is_empty());
        assert_eq!(summary.stats.refused_unix_sockets, 3);
    }

    /// An abstract address and a relative path cannot be a rule.
    #[test]
    fn unreachable_sockets_give_no_rule() {
        let events = [
            unix("@/tmp/.X11-unix/X0", "x", Outcome::Denied),
            unix("relative.sock", "x", Outcome::Allowed),
        ];
        let summary = summarize(&events, &ctx());
        assert!(summary.items.is_empty());
        assert_eq!(
            summary.stats.unreachable_sockets,
            vec!["@/tmp/.X11-unix/X0", "relative.sock"]
        );
        assert_eq!(summary.stats.refused_unix_sockets, 1);
    }

    #[test]
    fn known_sockets_have_a_name() {
        for (path, name) in [
            ("/run/user/1000/bus", "D-Bus"),
            ("/run/dbus/system_bus_socket", "D-Bus"),
            ("~/.gnupg/S.gpg-agent.ssh", "gpg-agent"),
            ("/run/user/1000/gnupg/S.gpg-agent", "gpg-agent"),
            ("~/.ssh/agent.4242", "ssh-agent"),
            ("/tmp/ssh-XoP1/agent.900", "ssh-agent"),
            ("/run/user/1000/keyring/ssh", "ssh-agent"),
            ("/var/run/docker.sock", "Docker"),
        ] {
            assert_eq!(known_socket(path), Some(name), "{path}");
        }
        assert_eq!(known_socket("~/.tool/tool.sock"), None);
    }

    /// A Unix socket rule is a strong grant, so the review does not select
    /// it by default.
    #[test]
    fn unix_sockets_are_not_selected_by_default() {
        assert!(!Section::UnixSockets.selects_by_default());
        assert!(!Section::Blocked.selects_by_default());
        for section in [Section::ReadWrite, Section::Read, Section::Execute] {
            assert!(section.selects_by_default(), "{section:?}");
        }
    }

    #[test]
    fn a_socket_rule_of_the_profile_is_omitted() {
        let mut ctx = ctx();
        let mut doc = ProfileDoc::default();
        doc.filesystem
            .unix_sockets
            .push("/home/u/.gnupg/S.gpg-agent".to_string());
        ctx.existing = Some(doc);
        let events = [
            unix("/home/u/.gnupg/S.gpg-agent", "gpg", Outcome::Allowed),
            unix("/home/u/.other.sock", "gpg", Outcome::Allowed),
        ];
        assert_eq!(
            lines(&summarize(&events, &ctx)),
            vec!["unix ~/.other.sock | used by gpg"]
        );
    }

    #[test]
    fn to_doc_writes_the_socket_rules() {
        let events = [unix("/home/u/.gnupg/S.gpg-agent", "gpg", Outcome::Denied)];
        let summary = summarize(&events, &ctx());
        let doc = summary.to_doc(&[0]);
        assert_eq!(doc.filesystem.unix_sockets, vec!["~/.gnupg/S.gpg-agent"]);
    }

    #[test]
    fn to_doc_uses_the_selected_items() {
        let events = claude_session();
        let summary = summarize(&events, &ctx());
        let all: Vec<usize> = (0..summary.items.len()).collect();
        let doc = summary.to_doc(&all);
        assert_eq!(
            doc.filesystem.read_write,
            vec![
                "~/.cache/claude",
                "~/.claude",
                "~/.claude.json",
                "~/.bashrc"
            ]
        );
        assert_eq!(doc.network.domains.len(), 4);
    }

    #[test]
    fn counts_have_group_separators() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_834), "1,834");
        assert_eq!(format_count(1_234_567), "1,234,567");
    }

    #[test]
    fn empty_home_and_workspace_do_not_hide_everything() {
        let ctx = SummaryContext {
            home: PathBuf::new(),
            workspace: PathBuf::new(),
            covered: vec![PathBuf::new()],
            existing: None,
        };
        let events = [fs(Read, "/opt/tool/a", "tool")];
        assert_eq!(
            lines(&summarize(&events, &ctx)),
            vec!["r /opt/tool/a | read by tool [OutsideHome]"]
        );
    }
}
