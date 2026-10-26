//! Read the Seatbelt reports of a process tree from the macOS unified log.
//!
//! The kernel writes one log line for each operation that Seatbelt denies,
//! and for each operation that an `allow` rule with `(with report)` allows.
//! With `log stream --style syslog`, one report looks like this:
//!
//! ```text
//! 2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) Sandbox: cat(1234) deny(1) file-read-data /Users/x/.ssh/id_rsa
//! 2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) Sandbox: cat(1234) allow(1) file-read-data /Users/x/notes.txt
//! ```
//!
//! The deny form is known (the `pent run --trace` code reads it). The author
//! did not see the form of an allow report on a Mac. The parser thus accepts
//! the keywords `deny` and `allow`, with or without the `(<count>)` part.
//! Test this on a Mac.
//!
//! # Every process can write to the unified log
//!
//! The watched program can call `os_log` or run `/usr/bin/logger`, so the
//! text of a line proves nothing. The reader has four guards (see MAC-1 in
//! `docs/security/macos.md`):
//!
//! 1. The predicate takes only the messages of the kernel
//!    (`PREDICATE`: `processImagePath == "/kernel"`).
//!    A program cannot write a message with the image path of the kernel.
//! 2. [`parse_line`] takes only a line with the full kernel header that
//!    `log` writes itself (`kernel[0]: `), and it reads each field of the
//!    report at a fixed position. A program that gives its own executable a
//!    name which looks like the header cannot reach the fields, because
//!    `log` always writes `[<pid>]: ` after the name of the process.
//! 3. The reader keeps only the lines of the process tree of the run.
//! 4. The reader keeps only a line whose process name fits the program
//!    that the PID runs ([`ProcessTree::name_fits`]).
//!
//! # The name of the process (FUZZ-1)
//!
//! The kernel writes the name of the file that the program runs, and the
//! program chooses that name. A file named
//! `a(1234) deny(1) file-read-data /etc/shadow (b` puts a second `) deny`
//! marker in the line. [`parse_line`] reads the first marker, so each
//! field of the record comes from the name, and the program also chooses
//! the PID (fork, build the name with that PID, exec). The text alone
//! cannot tell this line from a real report of a path that holds the text
//! of a marker.
//!
//! Guard 4 uses three sources that the program does not choose:
//!
//! - Pent itself. It starts the root process, so it knows the two names of
//!   that process: `sandbox-exec` and the command
//!   ([`ProcessTree::with_names`]).
//! - The process tree in the kernel. Each poll walks the tree of the run
//!   and reads the path of the program of each member
//!   ([`crate::macos_proctable`]), so the reader knows the file that each
//!   PID runs.
//! - The parent of a `fork`. A `fork` copies the program of the parent, so
//!   a child takes each name of its parent until it runs a new file
//!   ([`ProcessTree::inherit_names`]).
//! - The exec reports. The kernel writes the path of the program in each
//!   `process-exec` report, and a process that runs a new file keeps its
//!   PID ([`ProcessTree::learn_name`]).
//!
//! A PID can thus have more than one name, and the reader drops a report
//! whose name fits none of them ([`names_agree`]).
//!
//! What the check holds:
//!
//! - A forged name is longer than the name in the record, because the
//!   payload of the forgery comes after the first marker. The two differ,
//!   so the record goes.
//! - A real report agrees, also when the kernel cuts a long name to the
//!   16 bytes of `p_comm`: the check accepts the cut form.
//! - A report of a PID whose program pent never read cannot be checked,
//!   so it goes too.
//!
//! What the check does not hold:
//!
//! - A descendant that forks, runs and exits between two polls never
//!   reaches a snapshot, and pent knows neither its PID nor a name of it,
//!   so its reports go. The root process is safe, because pent knows its
//!   names. macOS watch mode is a lower bound for this reason;
//!   `--append` merges more runs. See MAC-10 in `docs/security/macos.md`,
//!   which holds the measurement of the window that stays.
//! - A file name whose first 16 bytes are the whole name of the record and
//!   whose rest holds a marker is refused, also when it is honest. Such a
//!   name is a forgery or a name that nobody needs.
//!
//! [`LogReader`] starts `log stream` before the spawn of the child, keeps
//! only the lines of the PIDs of the child tree, and sends one
//! [`WatchEvent`] for each line. The parse, filter and map functions are
//! pure, so their unit tests also run on Linux.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use pent_profile::{classify, FsOp, GuardAccess, GuardRule, Outcome, ProcessInfo, WatchEvent};

/// The action in a Seatbelt log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// A rule with `(with report)` allowed the operation.
    Allow,
    /// A rule denied the operation.
    Deny,
}

/// One Seatbelt log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeatbeltRecord {
    /// The process name in the message.
    pub(crate) process: String,
    /// The process ID.
    pub(crate) pid: u32,
    /// Allowed or denied.
    pub(crate) action: Action,
    /// The Seatbelt operation (for example `file-read-data`).
    pub(crate) operation: String,
    /// The target of the operation: a path, an address, or empty.
    pub(crate) target: String,
}

/// The header that `log --style syslog` writes for a message of the
/// kernel. Only the kernel has the process ID 0, and `log` writes this
/// header itself, so a program cannot put it in its own message: after the
/// name of the process, `log` always writes `[<pid>]: ` with the real PID.
const KERNEL_HEADER: &str = " kernel[0]: ";

/// The prefix of each Seatbelt report in the message of the kernel.
const REPORT_PREFIX: &str = "Sandbox: ";

/// Find the first `) deny` or `) allow` marker in `line`.
///
/// Return the byte index of `)`, the action and the length of the marker.
fn find_marker(line: &str) -> Option<(usize, Action, usize)> {
    const DENY: &str = ") deny";
    const ALLOW: &str = ") allow";
    let deny = line.find(DENY).map(|i| (i, Action::Deny, DENY.len()));
    let allow = line.find(ALLOW).map(|i| (i, Action::Allow, ALLOW.len()));
    match (deny, allow) {
        (Some(d), Some(a)) => Some(if d.0 <= a.0 { d } else { a }),
        (d, a) => d.or(a),
    }
}

/// Remove the `(<sender>) ` group that `log --style syslog` writes between
/// the header and the message. Return `text` unchanged when the group is
/// not there.
fn strip_sender(text: &str) -> &str {
    let Some(rest) = text.strip_prefix('(') else {
        return text;
    };
    match rest.find(") ") {
        Some(close) => rest.get(close.saturating_add(2)..).unwrap_or(text),
        None => text,
    }
}

/// Return true if `name` can be the name of a process in a report.
///
/// A real name holds spaces and parentheses (`Code Helper (GPU)`). It does
/// not hold `[`, `]` or `:`. These three characters are the ones that `log`
/// writes around the PID of the process that sends a message, so this check
/// drops a line in which the name of the process holds a false header.
fn is_process_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['[', ']', ':'])
}

/// Return true if `text` is a Seatbelt operation name.
fn is_operation(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '*' | '_'))
}

/// Parse one line of `log stream` output.
///
/// Return `None` if the line is not a Seatbelt report of the kernel. The
/// line must have this shape:
///
/// ```text
/// <anything> kernel[0]: [(<sender>) ]Sandbox: <name>(<pid>) <action>[(<count>)] <operation>[ <target>]
/// ```
///
/// The function reads the first kernel header of the line, so text that a
/// program puts in a path cannot add a second report: such text stays in
/// the target of the real report.
///
/// The process name can contain spaces and parentheses
/// (`Code Helper (GPU)(77)`); the PID is the number in the last parentheses
/// before the action keyword.
pub(crate) fn parse_line(line: &str) -> Option<SeatbeltRecord> {
    // One report is one line. A control character belongs to no field.
    if line.contains(char::is_control) {
        return None;
    }
    let header = line.find(KERNEL_HEADER)?;
    let after_header = line.get(header.checked_add(KERNEL_HEADER.len())?..)?;
    let message = strip_sender(after_header).strip_prefix(REPORT_PREFIX)?;

    let (marker, action, marker_len) = find_marker(message)?;
    let head = message.get(..marker)?;
    let open = head.rfind('(')?;
    let digits = head.get(open.checked_add(1)?..)?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let pid: u32 = digits.parse().ok()?;
    let process = head.get(..open)?;
    if !is_process_name(process) {
        return None;
    }
    let mut rest = message.get(marker.checked_add(marker_len)?..)?;
    // The keyword must end here: "allowed" or "denying" is not a report.
    if !(rest.starts_with('(') || rest.starts_with(' ')) {
        return None;
    }
    // Skip the "(1)" count when it is present.
    if let Some(after_open) = rest.strip_prefix('(') {
        let close = after_open.find(')')?;
        let count = after_open.get(..close)?;
        if count.is_empty() || !count.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        rest = after_open.get(close.checked_add(1)?..)?;
    }
    let rest = rest.strip_prefix(' ')?;
    let (operation, target) = rest
        .split_once(' ')
        .map_or((rest, ""), |(op, tail)| (op, tail));
    if !is_operation(operation) {
        return None;
    }
    Some(SeatbeltRecord {
        process: process.to_string(),
        pid,
        action,
        operation: operation.to_string(),
        target: target.to_string(),
    })
}

/// The event kind of a Seatbelt operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationKind {
    /// A filesystem operation.
    Fs(FsOp),
    /// A `connect()` to a Unix socket.
    UnixConnect,
}

/// Map a Seatbelt operation and its target to an event kind.
///
/// Return `None` for the operations that a profile does not use (metadata
/// reads, Mach lookups, IP connections, signals, ...). The proxy records the
/// IP connections.
pub(crate) fn map_operation(operation: &str, target: &str) -> Option<OperationKind> {
    let kind = match operation {
        "file-read-data" | "file-read*" => OperationKind::Fs(FsOp::Read),
        "file-write-create" | "file-link" => OperationKind::Fs(FsOp::Create),
        "file-write-unlink" => OperationKind::Fs(FsOp::Delete),
        op if op.starts_with("file-write") => OperationKind::Fs(FsOp::Write),
        op if op.starts_with("process-exec") => OperationKind::Fs(FsOp::Exec),
        "network-outbound" if target.starts_with('/') => OperationKind::UnixConnect,
        _ => return None,
    };
    if matches!(kind, OperationKind::Fs(_)) && !target.starts_with('/') {
        return None;
    }
    Some(kind)
}

/// The mode of the recorder.
#[derive(Debug, Clone)]
pub(crate) enum RecordMode {
    /// `pent run --trace`: each denial comes from the sandbox policy.
    Run,
    /// `pent watch`: a denial of a file operation comes from the guard.
    Watch(Vec<GuardRule>),
}

/// Return the guard access that matches a filesystem operation.
const fn guard_access(op: FsOp) -> GuardAccess {
    match op {
        FsOp::Read => GuardAccess::Read,
        FsOp::Exec => GuardAccess::ExecName,
        FsOp::Write | FsOp::Create | FsOp::Delete => GuardAccess::Write,
    }
}

/// Convert a Seatbelt record into an event.
///
/// The outcome is [`Outcome::Allowed`] for an allow report. For a denial in
/// watch mode, it is [`Outcome::Blocked`] with the class of the guard rule
/// that matches the path, or [`Outcome::Denied`] if no rule matches (for
/// example a path through a symbolic link that the rule does not name). In
/// run mode, each denial is [`Outcome::Denied`].
///
/// Seatbelt reports the resolved path, so the event has only the target of
/// a symbolic link, not the link path.
pub(crate) fn to_event(record: &SeatbeltRecord, mode: &RecordMode) -> Option<WatchEvent> {
    let kind = map_operation(&record.operation, &record.target)?;
    let process = ProcessInfo {
        pid: record.pid,
        name: record.process.clone(),
    };
    let blocked_class = |op: FsOp| match mode {
        RecordMode::Watch(rules) => {
            classify(rules, Path::new(&record.target), guard_access(op)).map(Outcome::Blocked)
        }
        RecordMode::Run => None,
    };
    let event = match kind {
        OperationKind::Fs(op) => WatchEvent::Fs {
            op,
            path: PathBuf::from(&record.target),
            process,
            outcome: match record.action {
                Action::Allow => Outcome::Allowed,
                Action::Deny => blocked_class(op).unwrap_or(Outcome::Denied),
            },
        },
        OperationKind::UnixConnect => WatchEvent::UnixConnect {
            target: record.target.clone(),
            process,
            outcome: match record.action {
                Action::Allow => Outcome::Allowed,
                Action::Deny => Outcome::Denied,
            },
        },
    };
    Some(event)
}

/// One process of a snapshot of the process tree.
///
/// [`crate::macos_proctable::snapshot`] makes the rows on macOS. The tests
/// make them with [`parse_proc_table`], which reads the same fields from a
/// text table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcRow {
    /// The process ID.
    pub(crate) pid: u32,
    /// The parent process ID.
    pub(crate) ppid: u32,
    /// True if the process exited and its parent did not reap it yet.
    pub(crate) zombie: bool,
    /// The file name of the program that the process runs, without the
    /// directory. It is empty when the kernel gives no program.
    pub(crate) name: String,
}

/// Split the first field from `text`. Return the field and the rest
/// without its leading spaces.
#[cfg(test)]
fn next_field(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if text.is_empty() {
        return None;
    }
    match text.find(char::is_whitespace) {
        Some(end) => Some((text.get(..end)?, text.get(end..)?.trim_start())),
        None => Some((text, "")),
    }
}

/// The file name of `path`: the text after the last `/`.
fn file_name_of(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}

/// Read a process table in the form `<pid> <ppid> <state> <program>`.
///
/// This is how a test writes a snapshot. The form is the output of
/// `ps -A -o pid=,ppid=,stat=,comm=`, which the reader used before the
/// run 40246227819 measured that a fork of `ps` costs 35 ms (see
/// [`crate::macos_proctable`]). A row without a state column is a live
/// process. The program is the last column and it holds the whole path,
/// which can hold spaces
/// (`/Applications/X.app/Contents/MacOS/Code Helper (GPU)`), so the row
/// keeps the rest of the line as the program.
#[cfg(test)]
pub(crate) fn parse_proc_table(output: &str) -> Vec<ProcRow> {
    output
        .lines()
        .filter_map(|line| {
            let (pid, rest) = next_field(line)?;
            let (ppid, rest) = next_field(rest)?;
            let pid = pid.parse().ok()?;
            let ppid = ppid.parse().ok()?;
            let (stat, command) = next_field(rest).unwrap_or(("", ""));
            Some(ProcRow {
                pid,
                ppid,
                zombie: stat.starts_with('Z'),
                name: file_name_of(command).to_string(),
            })
        })
        .collect()
}

/// The number of bytes that `p_comm`, the accounting name of a process on
/// macOS, holds. The kernel cuts a longer file name to this length.
const COMM_LEN: usize = 16;

/// Return true when the name `record` of a Seatbelt report can be the name
/// of the program `known` that the process table gives.
///
/// The two agree when they are the same text. They also agree when
/// `record` is the first [`COMM_LEN`] bytes of `known`, because the kernel
/// cuts a long name to that length in `p_comm`.
///
/// The cut form is the one that a forged name uses: a program that runs a
/// file named `a(1234) deny(1) file-read-data /etc/shadow (b` makes the
/// kernel write a line in which the first marker is in the name, so
/// [`parse_line`] reads `a` as the name. Thus pent refuses the cut form
/// when the rest of the known name holds a marker: such a name is either a
/// forgery or a file name that nobody needs.
fn names_agree(record: &str, known: &str) -> bool {
    if known.is_empty() {
        // Pent knows no name for the process, so it cannot check.
        return false;
    }
    if record == known {
        return true;
    }
    let Some(rest) = known.strip_prefix(record) else {
        return false;
    };
    record.len() == COMM_LEN && find_marker(rest).is_none()
}

/// The PIDs of the child and its descendants.
///
/// The set of known PIDs only grows, so a report that the log delivers after
/// a process exits still matches. A process that leaves the process table
/// (or becomes a zombie) is dead and never counts as live again, so a later
/// reuse of its PID does not keep the tree alive.
#[derive(Debug)]
pub(crate) struct ProcessTree {
    known: HashSet<u32>,
    dead: HashSet<u32>,
    names: HashMap<u32, HashSet<String>>,
}

impl ProcessTree {
    /// Create a tree with only `root`, and with the names of the programs
    /// that `root` runs.
    ///
    /// The poll of the process tree is one source of the name of a
    /// process, and it misses a process that lives less than one poll
    /// interval. Pent itself is the second source: it starts the root
    /// process, so it knows the program of the root before the first
    /// poll. See MAC-8 in `docs/security/macos.md`.
    pub(crate) fn with_names(root: u32, names: &[String]) -> Self {
        let root_names: HashSet<String> = names.iter().filter(|n| !n.is_empty()).cloned().collect();
        let mut map = HashMap::new();
        if !root_names.is_empty() {
            map.insert(root, root_names);
        }
        Self {
            known: HashSet::from([root]),
            dead: HashSet::new(),
            names: map,
        }
    }

    /// Record that `pid` runs the program `name` from now on.
    ///
    /// The source is a `process-exec` report: the kernel writes the path
    /// of the program that the process runs, and a process that runs a new
    /// file keeps its PID. The kernel chooses that path, not the program,
    /// so the name is as good as the one of the process table. Pent adds
    /// the name, and does not remove the earlier one: a report of the same
    /// PID can arrive before or after the exec.
    ///
    /// A PID outside the tree learns nothing.
    pub(crate) fn learn_name(&mut self, pid: u32, name: &str) {
        if name.is_empty() || !self.known.contains(&pid) {
            return;
        }
        self.names.entry(pid).or_default().insert(name.to_string());
    }

    /// Return true if `pid` is in the tree (live or dead).
    pub(crate) fn contains(&self, pid: u32) -> bool {
        self.known.contains(&pid)
    }

    /// The members of the tree that the last snapshot found live.
    ///
    /// The walk of the next snapshot starts at these process IDs
    /// ([`crate::macos_proctable::snapshot`]). A dead member is never a
    /// start of the walk, so a process that takes the PID of a dead member
    /// brings none of its children into the tree.
    pub(crate) fn live_members(&self) -> Vec<u32> {
        self.known
            .iter()
            .copied()
            .filter(|pid| !self.dead.contains(pid))
            .collect()
    }

    /// Give `child` each name of `parent`.
    ///
    /// A `fork` copies the program of the parent, so the child runs that
    /// program until it runs a new file. The kernel gives the link between
    /// the two processes, and pent reads each name of the parent from the
    /// kernel too, so this name is a source that the program does not
    /// choose (FUZZ-1).
    ///
    /// Without this step, the reader drops each report of a child between
    /// the `fork` and the `process-exec` report of it, because the
    /// snapshot that found the child named the program of the parent and
    /// the report names it too.
    fn inherit_names(&mut self, parent: u32, child: u32) {
        let Some(names) = self.names.get(&parent).cloned() else {
            return;
        };
        self.names.entry(child).or_default().extend(names);
    }

    /// Return true when `name`, the process name of a Seatbelt report, is
    /// the name of the program that `pid` runs.
    ///
    /// The program chooses the text of its own name, so the name in a
    /// report proves nothing by itself. The kernel is the second source:
    /// it tells which file each PID runs. A report whose name does not fit
    /// that file is a forgery, and a report of a PID whose name pent never
    /// read cannot be checked. Both are dropped (FUZZ-1 in
    /// `docs/security/fuzzing.md`).
    pub(crate) fn name_fits(&self, pid: u32, name: &str) -> bool {
        self.names
            .get(&pid)
            .is_some_and(|known| known.iter().any(|known| names_agree(name, known.as_str())))
    }

    /// Update the tree from a snapshot of the process tree.
    ///
    /// Add the children of each live member, mark the members that are not
    /// in the snapshot (or are zombies) as dead, and return true if a
    /// member is still live.
    ///
    /// The snapshot also gives the name of the program of each member, and
    /// a new child takes each name of its parent
    /// ([`ProcessTree::inherit_names`]). A process that runs a new file
    /// keeps its PID, so each name of a PID stays (see
    /// [`ProcessTree::name_fits`]).
    pub(crate) fn update(&mut self, rows: &[ProcRow]) -> bool {
        let mut children: HashMap<u32, Vec<&ProcRow>> = HashMap::new();
        let mut present: HashMap<u32, &ProcRow> = HashMap::new();
        for row in rows {
            children.entry(row.ppid).or_default().push(row);
            present.insert(row.pid, row);
        }
        // The live members of the snapshot.
        let mut live: Vec<u32> = self
            .known
            .iter()
            .copied()
            .filter(|pid| !self.dead.contains(pid))
            .filter(|pid| present.get(pid).is_some_and(|row| !row.zombie))
            .collect();
        let mut queue = live.clone();
        while let Some(pid) = queue.pop() {
            for child in children.get(&pid).map_or(&[][..], Vec::as_slice) {
                if child.zombie {
                    // A short-lived child: record its PID for the filter.
                    if self.known.insert(child.pid) {
                        self.inherit_names(pid, child.pid);
                    }
                    continue;
                }
                if self.known.insert(child.pid) || self.dead.remove(&child.pid) {
                    self.inherit_names(pid, child.pid);
                    live.push(child.pid);
                    queue.push(child.pid);
                }
            }
        }
        let live: HashSet<u32> = live.into_iter().collect();
        for pid in &self.known {
            if !live.contains(pid) {
                self.dead.insert(*pid);
            }
            // The name of a member of the tree, for the check of a report.
            // A process that runs a new file keeps its PID, so a PID can
            // have more than one name over the run. Each name stays: a
            // report of the PID can arrive before or after the exec.
            if let Some(row) = present.get(pid) {
                if !row.name.is_empty() {
                    self.names.entry(*pid).or_default().insert(row.name.clone());
                }
            }
        }
        !live.is_empty()
    }
}

#[cfg(target_os = "macos")]
pub(crate) use runtime::LogReader;

#[cfg(target_os = "macos")]
mod runtime {
    use std::io::BufRead as _;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use pent_profile::WatchEvent;

    use super::{file_name_of, parse_line, to_event, ProcessTree, RecordMode};
    use crate::macos_proctable::snapshot;
    use crate::SandboxError;

    /// The time to wait for `log stream` to print its header.
    const READY_TIMEOUT: Duration = Duration::from_secs(3);
    /// The interval of the process-tree poll.
    ///
    /// The poll reads the tree in the process, so one snapshot costs tens
    /// of microseconds (see [`crate::macos_proctable`]). The limit is the
    /// clock of the machine and not the cost: the run 40246732816 on
    /// `macos-latest` measured that a sleep of one millisecond gives a
    /// real interval of about five milliseconds on that runner, with
    /// `nanosleep`, with `select` and with `mach_wait_until` alike. Pent
    /// asks for the shortest interval that it can use, and a machine with
    /// a finer clock then polls more often. See MAC-10 in
    /// `docs/security/macos.md`.
    const POLL_INTERVAL: Duration = Duration::from_millis(1);
    /// The minimum time between two process-tree refreshes on demand.
    const MIN_REFRESH_GAP: Duration = Duration::from_millis(1);
    /// The time to read late log lines after the last process of the tree
    /// exits.
    const DRAIN_GRACE: Duration = Duration::from_millis(500);

    /// The Seatbelt profile of the warm-up probe (MAC-12).
    ///
    /// The deny of `process-exec` stops the program of the probe before it
    /// runs, and the kernel writes one Seatbelt report with the process ID
    /// of the probe. The profile names no path, so it needs no escaping
    /// and it cannot hit the length limit of the reader (MAC-9).
    const PROBE_PROFILE: &str = "(version 1)(allow default)(deny process-exec)";
    /// The program of the warm-up probe. It never runs: the profile denies
    /// the `exec` of it. macOS has no `/bin/true`, so the path is this one
    /// (MAC-7).
    const PROBE_PROGRAM: &str = "/usr/bin/true";
    /// The time between two warm-up probes.
    const PROBE_GAP: Duration = Duration::from_millis(250);
    /// The time limit of the warm-up.
    const WARM_UP_LIMIT: Duration = Duration::from_secs(10);

    /// The `log stream` predicate.
    ///
    /// The kernel writes each Seatbelt report as
    /// "Sandbox: <name>(<pid>) <action>(<count>) <operation> <target>", and
    /// the sender of these messages is the `Sandbox` part of the kernel.
    ///
    /// The first term is the important one: every process can write to the
    /// unified log, but only the kernel has the process image path
    /// `/kernel`. A message of the watched program therefore never reaches
    /// the reader (MAC-1 in `docs/security/macos.md`). The second term
    /// keeps the stream small; it accepts the sender and also the text, so
    /// a change of one of the two does not lose all reports.
    ///
    /// The author did not run this predicate on a Mac. If a first run gives
    /// no event at all, the predicate is the first thing to check:
    /// `log stream --predicate 'processImagePath == "/kernel"' --style syslog`.
    const PREDICATE: &str = r#"processImagePath == "/kernel" AND (sender == "Sandbox" OR eventMessage BEGINSWITH "Sandbox: ")"#;

    /// The process tree and the time of its last refresh.
    struct Tree {
        tree: ProcessTree,
        last_refresh: Option<Instant>,
    }

    impl Tree {
        /// Walk the process tree in the kernel and update the tree of the
        /// run. Return true if a member is still live.
        fn refresh(&mut self) -> bool {
            self.last_refresh = Some(Instant::now());
            self.tree.update(&snapshot(&self.tree.live_members()))
        }

        /// Walk the tree again when the last walk is not too recent.
        ///
        /// A report of a process that the tree does not hold is the
        /// reason to look again at once: the process can be new, or it
        /// can have run a new file after the last poll. The walk costs
        /// tens of microseconds, so the gap only bounds the cost of a log
        /// that holds the reports of many other processes.
        fn refresh_on_demand(&mut self) {
            if self
                .last_refresh
                .is_none_or(|t| t.elapsed() >= MIN_REFRESH_GAP)
            {
                // The poll thread uses the result for the liveness check;
                // here only the new PIDs and the new names matter.
                let _alive = self.refresh();
            }
        }

        /// Return true if `pid` is in the tree and `name` is the name of
        /// the program that `pid` runs.
        fn accepts(&mut self, pid: u32, name: &str) -> bool {
            if self.tree.contains(pid) && self.tree.name_fits(pid, name) {
                return true;
            }
            self.refresh_on_demand();
            self.tree.contains(pid) && self.tree.name_fits(pid, name)
        }

        /// Return true if `pid` is a member of the tree, live or dead.
        fn member(&mut self, pid: u32) -> bool {
            if self.tree.contains(pid) {
                return true;
            }
            self.refresh_on_demand();
            self.tree.contains(pid)
        }
    }

    fn lock(tree: &Mutex<Tree>) -> MutexGuard<'_, Tree> {
        // A poisoned lock only means that a thread panicked during a
        // refresh; the set of PIDs is still valid.
        tree.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A running `log stream` process that reads Seatbelt reports.
    pub(crate) struct LogReader {
        log_proc: Option<Child>,
        lines: Option<Receiver<String>>,
    }

    /// The reason that a `log stream` which cannot run gives.
    fn unavailable(reason: String) -> SandboxError {
        SandboxError::SandboxUnavailable {
            reason,
            remediation: "Make sure that /usr/bin/log works (run `log stream` in a terminal)"
                .to_string(),
        }
    }

    /// Start `log stream` and read its output on a thread.
    ///
    /// # Errors
    /// Returns `SandboxUnavailable` if `log stream` cannot start or has no
    /// output pipe.
    fn spawn_stream() -> Result<(Child, Receiver<String>), SandboxError> {
        let mut log_proc = Command::new("/usr/bin/log")
            .args([
                "stream",
                "--predicate",
                PREDICATE,
                "--style",
                // syslog avoids the column-width truncation of the
                // "compact" style, which cuts off long paths.
                "syslog",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| unavailable(format!("could not start `log stream`: {e}")))?;
        let Some(stdout) = log_proc.stdout.take() else {
            stop_log_process(&mut log_proc);
            return Err(unavailable("`log stream` has no output pipe".to_string()));
        };
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    // The reader is gone; stop the read.
                    break;
                }
            }
        });
        Ok((log_proc, rx))
    }

    impl LogReader {
        /// Start `log stream` and wait until it delivers a report.
        ///
        /// Start the reader before the child, so that the log does not miss
        /// the first reports. The header of `log stream` proves nothing:
        /// `log` prints it before it connects to the log. The reader
        /// therefore makes a report of its own and waits for it
        /// ([`warm_up`], MAC-12).
        ///
        /// # Errors
        /// Returns `SandboxUnavailable` if `log stream` cannot start or stops
        /// before its header.
        pub(crate) fn start() -> Result<Self, SandboxError> {
            let (mut log_proc, rx) = spawn_stream()?;
            match rx.recv_timeout(READY_TIMEOUT) {
                // The first line is the header of `log stream`.
                Ok(_header) => {}
                Err(RecvTimeoutError::Timeout) => tracing::warn!(
                    "`log stream` did not start in time; the record can miss the first accesses"
                ),
                Err(RecvTimeoutError::Disconnected) => {
                    stop_log_process(&mut log_proc);
                    return Err(unavailable("`log stream` stopped".to_string()));
                }
            }
            let _warm = warm_up(&rx);
            Ok(Self {
                log_proc: Some(log_proc),
                lines: Some(rx),
            })
        }

        /// Start to filter the log for the process tree of `root_pid`.
        ///
        /// Return the channel of events. The channel closes when the last
        /// process of the tree exits, after a short drain time for late log
        /// lines.
        ///
        /// `root_names` holds the names of the programs that the root
        /// process runs: the front end `sandbox-exec` and the command of
        /// the user. A short-lived root never reaches the process table, so
        /// without these names the reader drops each report of it (MAC-8 in
        /// `docs/security/macos.md`).
        pub(crate) fn attach(
            mut self,
            root_pid: u32,
            root_names: &[String],
            mode: RecordMode,
        ) -> Receiver<WatchEvent> {
            let (tx, rx) = std::sync::mpsc::channel();
            let (Some(lines), Some(log_proc)) = (self.lines.take(), self.log_proc.take()) else {
                // `start` always sets both fields; with no input the channel
                // closes at once.
                return rx;
            };
            let tree = Arc::new(Mutex::new(Tree {
                tree: ProcessTree::with_names(root_pid, root_names),
                last_refresh: None,
            }));

            // Poll the process tree, so that short-lived descendants are
            // known before their reports arrive. When the tree is empty,
            // wait for late lines, then stop `log stream`. Its output then
            // ends, the filter thread ends, and the event channel closes.
            {
                let tree = Arc::clone(&tree);
                std::thread::spawn(move || {
                    let mut log_proc = log_proc;
                    while lock(&tree).refresh() {
                        std::thread::sleep(POLL_INTERVAL);
                    }
                    std::thread::sleep(DRAIN_GRACE);
                    stop_log_process(&mut log_proc);
                });
            }

            std::thread::spawn(move || filter_lines(&lines, &tree, &mode, &tx));
            rx
        }
    }

    /// The answer of the warm-up (MAC-12).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum WarmUp {
        /// A report of a probe came back through the stream. The stream
        /// delivers the reports of the kernel from now on.
        Ready,
        /// No report of a probe came back inside [`WARM_UP_LIMIT`].
        TimedOut,
    }

    /// Run one probe and return its process ID.
    ///
    /// The probe is a sandboxed program that the profile stops at its
    /// `exec`, so the kernel writes one Seatbelt report of it. Nothing
    /// else of the probe reaches the machine: the program never runs.
    ///
    /// # Errors
    /// Returns the error of the spawn or of the wait.
    fn run_probe() -> std::io::Result<u32> {
        let mut child = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", PROBE_PROFILE, PROBE_PROGRAM])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        // The profile denies the `exec`, so the probe exits at once.
        let _status = child.wait()?;
        Ok(pid)
    }

    /// Wait until the stream delivers a Seatbelt report of pent itself.
    ///
    /// MAC-12. `log stream` prints its header before it connects to the
    /// log, so the header proves nothing. The run 40246227819 on
    /// `macos-latest` measured what that costs: the **first** `log stream`
    /// of a machine lost a report that a probe made 17 ms after the
    /// header, and it lost it for the whole 30 s of the measurement. Each
    /// stream after the first one lost none. A watch run of a short
    /// command on a new machine thus recorded nothing, and the user read
    /// "No new rules from 0 accesses", which reads like a program that
    /// did nothing.
    ///
    /// The warm-up makes a report of its own and waits for it. One probe
    /// is not enough, because a probe that runs while the stream is still
    /// cold is lost with it; the warm-up therefore runs a new probe every
    /// [`PROBE_GAP`] until one of them comes back. The run 40246732816
    /// measured the cost: the first stream of a machine needed two probes
    /// and 316 ms, and each stream after it needed one probe and 46 ms.
    ///
    /// A warm-up that passes its limit gives a warning and no error: a
    /// run that records too little is better than a run that does not
    /// start. The lines that the warm-up reads come from before the
    /// child, so dropping them loses nothing.
    pub(crate) fn warm_up(lines: &Receiver<String>) -> WarmUp {
        let start = Instant::now();
        let mut probes: Vec<u32> = Vec::new();
        let mut next_probe = Instant::now();
        while start.elapsed() < WARM_UP_LIMIT {
            if Instant::now() >= next_probe {
                match run_probe() {
                    Ok(pid) => probes.push(pid),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "the warm-up probe of the log reader did not run; \
                             the record can miss the first accesses"
                        );
                        return WarmUp::TimedOut;
                    }
                }
                next_probe = Instant::now() + PROBE_GAP;
            }
            let left = WARM_UP_LIMIT.saturating_sub(start.elapsed());
            let wait = left.min(PROBE_GAP);
            match lines.recv_timeout(wait) {
                Ok(line) => {
                    let Some(record) = parse_line(&line) else {
                        continue;
                    };
                    if probes.contains(&record.pid) {
                        tracing::debug!(
                            probes = probes.len(),
                            took_ms = start.elapsed().as_millis(),
                            "the log stream delivers the reports of the kernel"
                        );
                        return WarmUp::Ready;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        tracing::warn!(
            probes = probes.len(),
            limit_s = WARM_UP_LIMIT.as_secs(),
            "`log stream` delivered no report of pent itself inside the limit; \
             this run can record no access at all (MAC-12)"
        );
        WarmUp::TimedOut
    }

    /// Send one event for each log line of the process tree.
    fn filter_lines(
        lines: &Receiver<String>,
        tree: &Mutex<Tree>,
        mode: &RecordMode,
        tx: &Sender<WatchEvent>,
    ) {
        for line in lines {
            let Some(record) = parse_line(&line) else {
                continue;
            };
            // The report of an exec names the program that the process
            // runs from now on. The kernel writes that path, so the name
            // is a source that the program does not choose, and it is as
            // good as the one of a snapshot. The reader takes it **before**
            // the check of the name below: a process that runs a new file
            // between two snapshots has a name that no snapshot holds yet,
            // and the check would drop the exec report itself and with it
            // every later report of that process (MAC-8 and MAC-10).
            //
            // The membership in the tree still comes from the kernel walk
            // alone. A name is not a process tree: two unrelated programs
            // of a machine have the same name, so a report whose PID the
            // tree does not hold teaches nothing
            // (`watch_keeps_only_the_processes_of_the_run`).
            if record.operation.starts_with("process-exec") && record.target.starts_with('/') {
                let mut guard = lock(tree);
                if guard.member(record.pid) {
                    guard
                        .tree
                        .learn_name(record.pid, file_name_of(&record.target));
                }
            }
            // The reports of other sandboxed processes on the system are
            // also in the log. Keep only our process tree, and only a
            // report whose process name fits the program that the PID
            // runs: the program chooses the text of its own name, so a
            // name that does not fit is a forgery (FUZZ-1).
            if !lock(tree).accepts(record.pid, &record.process) {
                continue;
            }
            let Some(event) = to_event(&record, mode) else {
                continue;
            };
            if tx.send(event).is_err() {
                // The receiver is gone; stop the filter.
                break;
            }
        }
    }

    impl Drop for LogReader {
        fn drop(&mut self) {
            if let Some(mut log_proc) = self.log_proc.take() {
                stop_log_process(&mut log_proc);
            }
        }
    }

    /// Kill and reap the `log stream` process.
    fn stop_log_process(log_proc: &mut Child) {
        if let Err(e) = log_proc.kill() {
            tracing::debug!(error = %e, "could not kill `log stream`");
        }
        if let Err(e) = log_proc.wait() {
            tracing::debug!(error = %e, "could not reap `log stream`");
        }
    }

    #[cfg(test)]
    #[allow(
        clippy::panic,
        reason = "a stream that gives no report must fail the test with its reason"
    )]
    mod tests {
        use super::{
            spawn_stream, stop_log_process, warm_up, LogReader, RecordMode, WarmUp, READY_TIMEOUT,
        };
        use std::time::Instant;

        /// MAC-12. A `log stream` that pent has just started must deliver
        /// a report of the kernel before pent starts the child.
        ///
        /// Before the warm-up, the **first** stream of a machine
        /// delivered no report at all, so the first watch run of a machine
        /// recorded nothing and the user saw an empty draft. The warm-up
        /// makes a report of its own and waits for it, so this test holds
        /// the property that MAC-12 broke.
        ///
        /// The test prints the time that the warm-up took. On a runner the
        /// first stream of the machine needs about 300 ms and each stream
        /// after it about 50 ms.
        #[test]
        fn the_warm_up_sees_a_report_of_its_own_probe() {
            let Ok((mut log_proc, lines)) = spawn_stream() else {
                panic!("`log stream` did not start");
            };
            // The header, as `LogReader::start` reads it.
            let _header = lines.recv_timeout(READY_TIMEOUT);
            let start = Instant::now();
            let answer = warm_up(&lines);
            stop_log_process(&mut log_proc);
            println!(
                "the warm-up of the log reader took {} ms",
                start.elapsed().as_millis()
            );
            assert_eq!(
                answer,
                WarmUp::Ready,
                "the stream delivered no report of the probe of pent inside \
                 the limit, so a watch run of this machine records nothing \
                 (MAC-12 in docs/security/macos.md)"
            );
        }

        /// The reader of a short command must see the accesses of that
        /// command.
        ///
        /// `LogReader::start` warms the stream up, so the reader is
        /// connected when the child starts. The test runs the reader over
        /// a sandboxed program that reads one file and asserts that the
        /// read reaches the event channel.
        #[test]
        fn the_reader_keeps_the_access_of_a_short_command() {
            let dir = match tempfile::tempdir() {
                Ok(dir) => dir,
                Err(e) => panic!("the test could not make a directory: {e}"),
            };
            let file = dir.path().join("known.txt");
            if let Err(e) = std::fs::write(&file, "KNOWN\n") {
                panic!("the test could not write its file: {e}");
            }
            // The kernel reports the resolved path, and on macOS the
            // temporary directory is below a symbolic link, so the rule
            // needs the resolved form too.
            let real = match std::fs::canonicalize(dir.path()) {
                Ok(path) => path,
                Err(e) => panic!("the test could not resolve its directory: {e}"),
            };
            let Ok(reader) = LogReader::start() else {
                panic!("the log reader did not start");
            };
            let profile = format!(
                "(version 1)\n(allow default)\n(allow file-read-data (subpath \"{}\") \
                 (with report))\n",
                real.display()
            );
            let child = std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "/bin/cat"])
                .arg(&file)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            let Ok(mut child) = child else {
                panic!("the test could not start sandbox-exec");
            };
            let names = vec!["sandbox-exec".to_string(), "cat".to_string()];
            let events = reader.attach(child.id(), &names, RecordMode::Run);
            let _status = child.wait();
            let seen: Vec<_> = events.iter().collect();
            assert!(
                seen.iter()
                    .any(|event| format!("{event:?}").contains("known.txt")),
                "the reader kept no event of the file that the program read; \
                 it saw {} events: {seen:?}",
                seen.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pent_profile::{guard_rules, GuardClass};

    /// The header that `log --style syslog` writes before the message of
    /// the kernel.
    const HEAD: &str = "2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) ";

    /// One log line of the kernel with the message `message`.
    fn kernel_line(message: &str) -> String {
        format!("{HEAD}{message}")
    }

    // A test helper: a line that does not parse must fail the test.
    #[allow(clippy::panic)]
    fn record(message: &str) -> SeatbeltRecord {
        let line = kernel_line(message);
        match parse_line(&line) {
            Some(r) => r,
            None => panic!("line did not parse: {line}"),
        }
    }

    #[test]
    fn parses_syslog_deny_line() {
        let r = record("Sandbox: cat(1234) deny(1) file-read-data /Users/x/.ssh/id_rsa");
        assert_eq!(r.process, "cat");
        assert_eq!(r.pid, 1234);
        assert_eq!(r.action, Action::Deny);
        assert_eq!(r.operation, "file-read-data");
        assert_eq!(r.target, "/Users/x/.ssh/id_rsa");
    }

    #[test]
    fn parses_allow_report_with_and_without_count() {
        let r = record("Sandbox: node(42) allow(1) file-write-create /w/a b.txt");
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.operation, "file-write-create");
        assert_eq!(r.target, "/w/a b.txt");
        let r = record("Sandbox: node(42) allow file-read-data /w/x");
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.target, "/w/x");
    }

    /// The sender group of the syslog style is not in every line, and the
    /// text before the header is not fixed.
    #[test]
    fn parses_a_line_without_the_sender_group() {
        let line = "2026-10-25 10:00:00.000000+0200  mac kernel[0]: \
                    Sandbox: cat(7) deny(1) file-read-data /a";
        assert_eq!(parse_line(line).map(|r| r.pid), Some(7));
    }

    #[test]
    fn parses_process_name_with_parens() {
        let r = record("Sandbox: Code Helper (GPU)(77) deny(1) network-outbound 1.1.1.1:443");
        assert_eq!(r.process, "Code Helper (GPU)");
        assert_eq!(r.pid, 77);
        assert_eq!(r.target, "1.1.1.1:443");
    }

    #[test]
    fn target_with_marker_text_stays_whole() {
        let r = record("Sandbox: sh(5) allow(1) file-read-data /w/x) deny(1) y");
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.target, "/w/x) deny(1) y");
    }

    /// A path can hold the text of a whole kernel header. The parser reads
    /// the first header of the line, so the text stays in the target of the
    /// real report and gives no second event.
    #[test]
    fn a_header_inside_a_path_gives_no_second_event() {
        let r = record(
            "Sandbox: cat(5) deny(1) file-read-data \
             /w/ kernel[0]: (Sandbox) Sandbox: evil(9) allow(1) file-read-data /etc/passwd",
        );
        assert_eq!(r.pid, 5);
        assert_eq!(r.action, Action::Deny);
        assert_eq!(
            r.target,
            "/w/ kernel[0]: (Sandbox) Sandbox: evil(9) allow(1) file-read-data /etc/passwd"
        );
    }

    /// MAC-1. Every process can write to the unified log. A line of
    /// another sender is not a report: it has no kernel header. The
    /// predicate of `log stream` already drops such a line; the parser is
    /// the second guard. See `docs/security/macos.md`.
    #[test]
    fn a_line_from_another_sender_is_not_a_report() {
        for line in [
            "2026-10-25 10:00:00.000000+0200  localhost logger[55]: (libsystem.dylib) \
             Sandbox: evil(1234) allow(1) file-read-data /etc/passwd",
            "logger[55]: Sandbox: evil(1234) allow(1) file-read-data /etc/passwd",
            "Sandbox: evil(1234) allow(1) file-read-data /etc/passwd",
            // The PID of the kernel is 0. Another PID is another process.
            "2026-10-25 10:00:00.000000+0200  localhost kernel[7]: (Sandbox) \
             Sandbox: evil(1234) allow(1) file-read-data /etc/passwd",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }

    /// MAC-1. A program can give its own executable a name that looks like
    /// a kernel header. `log` always writes `[<pid>]: ` after the name of
    /// the process, so the name of the forged report holds `[`, `]` and
    /// `:`, and the parser drops the line.
    #[test]
    fn a_process_name_that_looks_like_a_header_is_not_a_report() {
        let line = "2026-10-25 10:00:00.000000+0200  localhost \
                    kernel[0]: (Sandbox) Sandbox: evil(99[55]: (x) ) allow(1) \
                    file-read-data /etc/passwd";
        assert_eq!(parse_line(line), None, "{line}");
    }

    /// A line that the parser must drop, with the reason in the name of the
    /// case.
    #[test]
    fn rejects_other_lines() {
        for (reason, line) in [
            (
                "no report",
                "Filtering the log data using \"...\"".to_string(),
            ),
            (
                "no header",
                "Sandbox: cat(1) deny(1) file-read-data /a".to_string(),
            ),
            (
                "the PID is not a number",
                kernel_line("Sandbox: cat(x) deny(1) file-read-data /a"),
            ),
            (
                "another word",
                kernel_line("Sandbox: app(12) allowed something"),
            ),
            (
                "no process name",
                kernel_line("Sandbox: (12) deny(1) file-read-data /a"),
            ),
            (
                "no message prefix",
                kernel_line("cat(12) deny(1) file-read-data /a"),
            ),
            (
                "truncated after the action",
                kernel_line("Sandbox: cat(12) deny(1)"),
            ),
            ("truncated in the name", kernel_line("Sandbox: cat(12")),
            (
                "truncated after the count",
                kernel_line("Sandbox: cat(12) deny(1) "),
            ),
            (
                "the count is not a number",
                kernel_line("Sandbox: cat(12) deny(x) file-read-data /a"),
            ),
            (
                "the operation is not a name",
                kernel_line("Sandbox: cat(12) deny(1) FILE_READ /a"),
            ),
            (
                "a second line in one line",
                format!(
                    "{}\n{}",
                    kernel_line("Sandbox: cat(12) deny(1) file-read-data /a"),
                    kernel_line("Sandbox: evil(13) allow(1) file-read-data /etc/passwd")
                ),
            ),
        ] {
            assert_eq!(parse_line(&line), None, "{reason}: {line}");
        }
    }

    /// The reader keeps only the lines of the process tree of the run, so a
    /// report of another sandboxed process on the system is not an event.
    #[test]
    fn a_pid_outside_the_tree_is_not_in_the_record() {
        let r = record("Sandbox: other(1234) deny(1) file-read-data /etc/passwd");
        assert_eq!(r.pid, 1234);
        let mut tree = ProcessTree::with_names(10, &[]);
        assert!(tree.update(&parse_proc_table("10 1 S\n")));
        assert!(tree.contains(10));
        assert!(!tree.contains(r.pid));
    }

    #[test]
    fn maps_operations() {
        let fs = |op| Some(OperationKind::Fs(op));
        assert_eq!(map_operation("file-read-data", "/a"), fs(FsOp::Read));
        assert_eq!(map_operation("file-read*", "/a"), fs(FsOp::Read));
        assert_eq!(map_operation("file-read-metadata", "/a"), None);
        assert_eq!(map_operation("file-write-create", "/a"), fs(FsOp::Create));
        assert_eq!(map_operation("file-write-unlink", "/a"), fs(FsOp::Delete));
        assert_eq!(map_operation("file-write-data", "/a"), fs(FsOp::Write));
        assert_eq!(map_operation("file-write*", "/a"), fs(FsOp::Write));
        assert_eq!(map_operation("process-exec", "/bin/ls"), fs(FsOp::Exec));
        assert_eq!(map_operation("process-exec*", "/bin/ls"), fs(FsOp::Exec));
        assert_eq!(
            map_operation("network-outbound", "/private/var/run/mDNSResponder"),
            Some(OperationKind::UnixConnect)
        );
        assert_eq!(map_operation("network-outbound", "1.1.1.1:443"), None);
        assert_eq!(map_operation("mach-lookup", "com.apple.x"), None);
        // A file operation without an absolute path is not an event.
        assert_eq!(map_operation("file-read-data", ""), None);
    }

    #[test]
    fn outcome_of_watch_denial_is_guard_class() {
        let mode = RecordMode::Watch(guard_rules(Path::new("/Users/u")));
        let deny = record("Sandbox: ssh(9) deny(1) file-read-data /Users/u/.ssh/id_ed25519");
        let event = to_event(&deny, &mode);
        assert_eq!(
            event.map(|e| e.outcome()),
            Some(Outcome::Blocked(GuardClass::Credential))
        );
        let exec = record("Sandbox: sh(9) deny(1) process-exec /usr/bin/sudo");
        assert_eq!(
            to_event(&exec, &mode).map(|e| e.outcome()),
            Some(Outcome::Blocked(GuardClass::PrivilegeEscalation))
        );
        let write = record("Sandbox: sh(9) deny(1) file-write-create /Users/u/.zshrc");
        assert_eq!(
            to_event(&write, &mode).map(|e| e.outcome()),
            Some(Outcome::Blocked(GuardClass::Persistence))
        );
        let other = record("Sandbox: sh(9) deny(1) file-read-data /etc/master.passwd");
        assert_eq!(
            to_event(&other, &mode).map(|e| e.outcome()),
            Some(Outcome::Denied)
        );
    }

    #[test]
    fn outcome_of_allow_and_run_denial() {
        let mode = RecordMode::Watch(guard_rules(Path::new("/Users/u")));
        let allow = record("Sandbox: git(3) allow(1) file-read-data /Users/u/.gitconfig");
        assert_eq!(
            to_event(&allow, &mode),
            Some(WatchEvent::Fs {
                op: FsOp::Read,
                path: PathBuf::from("/Users/u/.gitconfig"),
                process: ProcessInfo {
                    pid: 3,
                    name: "git".to_string(),
                },
                outcome: Outcome::Allowed,
            })
        );
        let deny = record("Sandbox: ssh(9) deny(1) file-read-data /Users/u/.ssh/id_ed25519");
        assert_eq!(
            to_event(&deny, &RecordMode::Run).map(|e| e.outcome()),
            Some(Outcome::Denied)
        );
        let unix = record("Sandbox: ssh(9) deny(1) network-outbound /private/tmp/agent.sock");
        assert_eq!(
            to_event(&unix, &RecordMode::Run),
            Some(WatchEvent::UnixConnect {
                target: "/private/tmp/agent.sock".to_string(),
                process: ProcessInfo {
                    pid: 9,
                    name: "ssh".to_string(),
                },
                outcome: Outcome::Denied,
            })
        );
    }

    /// A row of [`ProcRow`] with the fields that the test names.
    fn proc_row(pid: u32, ppid: u32, zombie: bool, name: &str) -> ProcRow {
        ProcRow {
            pid,
            ppid,
            zombie,
            name: name.to_string(),
        }
    }

    #[test]
    fn parses_a_process_table() {
        let rows = parse_proc_table(
            "  1     0 Ss /sbin/launchd\n\
             10     1 S+ /bin/sh\n\
             11    10 Z+ /usr/bin/cat\n\
             bad\n\
             12 10\n\
             13 10 S /Applications/X.app/Contents/MacOS/Code Helper (GPU)\n",
        );
        assert_eq!(
            rows,
            vec![
                proc_row(1, 0, false, "launchd"),
                proc_row(10, 1, false, "sh"),
                proc_row(11, 10, true, "cat"),
                proc_row(12, 10, false, ""),
                proc_row(13, 10, false, "Code Helper (GPU)"),
            ]
        );
    }

    /// FUZZ-1. The name of a report must fit the program that the PID
    /// runs. The program chooses the text of its own name, so a name that
    /// does not fit is a forgery.
    #[test]
    fn the_name_of_a_report_must_fit_the_program() {
        let mut tree = ProcessTree::with_names(10, &[]);
        let _live = tree.update(&parse_proc_table(
            "10 1 S /bin/sh\n\
             11 10 S /usr/bin/cat\n\
             12 10 S /Applications/X.app/Contents/MacOS/Code Helper (GPU)\n",
        ));
        assert!(tree.name_fits(11, "cat"));
        assert!(!tree.name_fits(11, "sh"));
        // The kernel cuts a long name to the 16 bytes of `p_comm`.
        assert!(tree.name_fits(12, "Code Helper (GPU"));
        assert!(tree.name_fits(12, "Code Helper (GPU)"));
        assert!(!tree.name_fits(12, "Code Helper"));
        // A PID that the process table never held cannot be checked.
        assert!(!tree.name_fits(99, "cat"));
    }

    /// The forged name of FUZZ-1, in the two shapes that it can take.
    #[test]
    fn a_forged_name_never_fits_the_program() {
        let forged = "a(1234) deny(1) file-read-data /etc/shadow (b";
        // The parser reads `a` as the name; the real file is longer.
        assert!(!names_agree("a", forged));
        // A name whose first 16 bytes are the name of the record: the rest
        // holds a marker, so pent cannot tell it from a forgery.
        let padded = "aaaaaaaaaaaaaaaa(1234) deny(1) file-read-data /etc/shadow (b";
        assert!(!names_agree("aaaaaaaaaaaaaaaa", padded));
        // An empty known name means "pent cannot check".
        assert!(!names_agree("cat", ""));
    }

    /// MAC-8. A root process that lives less than one poll interval never
    /// reaches the process table. Pent starts that process, so it gives
    /// the two names of it to the tree, and the reports of the process
    /// reach the recorder.
    #[test]
    fn the_names_of_the_root_come_from_pent() {
        let names = ["sandbox-exec".to_string(), "cat".to_string()];
        let tree = ProcessTree::with_names(10, &names);
        assert!(tree.name_fits(10, "cat"));
        assert!(tree.name_fits(10, "sandbox-exec"));
        assert!(!tree.name_fits(10, "sh"));
        // Another PID gets nothing from the names of the root.
        assert!(!tree.name_fits(11, "cat"));
        // A tree without names keeps the old behaviour.
        let empty = ProcessTree::with_names(10, &[]);
        assert!(!empty.name_fits(10, "cat"));
    }

    /// MAC-8. A process that runs a new file keeps its PID, and the name
    /// of each later report is the name of the new file. The exec report
    /// gives that name, and the earlier name stays valid for a report that
    /// arrives late.
    #[test]
    fn an_exec_report_teaches_the_new_name_of_the_process() {
        let names = ["sh".to_string()];
        let mut tree = ProcessTree::with_names(10, &names);
        assert!(!tree.name_fits(10, "bash"));
        tree.learn_name(10, "bash");
        assert!(tree.name_fits(10, "bash"), "the new name must fit");
        assert!(tree.name_fits(10, "sh"), "the old name must stay");
        // A PID outside the tree learns nothing.
        tree.learn_name(99, "bash");
        assert!(!tree.name_fits(99, "bash"));
        // The process table adds a name, it does not replace one.
        let _live = tree.update(&parse_proc_table("10 1 S /bin/zsh\n"));
        assert!(tree.name_fits(10, "zsh"));
        assert!(tree.name_fits(10, "bash"));
    }

    #[test]
    fn tree_follows_descendants_and_ends() {
        let mut tree = ProcessTree::with_names(10, &[]);
        // 10 -> 11 -> 12; 20 is not ours.
        let rows = parse_proc_table("10 1 S\n11 10 S\n12 11 S\n20 1 S\n");
        assert!(tree.update(&rows));
        assert!(tree.contains(12));
        assert!(!tree.contains(20));

        // The root exits; 12 lives on, reparented to launchd.
        let rows = parse_proc_table("12 1 S\n20 1 S\n");
        assert!(tree.update(&rows));
        assert!(tree.contains(10), "dead PIDs stay known for late lines");

        // 12 becomes a zombie: the tree is empty.
        let rows = parse_proc_table("12 1 Z\n20 1 S\n");
        assert!(!tree.update(&rows));
    }

    /// MAC-10. A `fork` copies the program of the parent, so a child that
    /// a snapshot finds between the `fork` and the `exec` runs the program
    /// of its parent. The reports of that child then have the name of the
    /// parent, and the reader must keep them.
    #[test]
    fn a_forked_child_takes_the_names_of_its_parent() {
        let names = ["sandbox-exec".to_string(), "sh".to_string()];
        let mut tree = ProcessTree::with_names(10, &names);
        // The snapshot finds the child; the kernel still names the
        // program of the parent, because the child did not exec yet.
        let _live = tree.update(&parse_proc_table("10 1 S /bin/sh\n11 10 S /bin/sh\n"));
        assert!(tree.name_fits(11, "sh"), "the name of the parent must fit");
        assert!(
            tree.name_fits(11, "sandbox-exec"),
            "each name of the parent must fit"
        );
        assert!(!tree.name_fits(11, "cat"), "a name of nobody must not fit");
        // The child runs a new file. The kernel names it in the report.
        tree.learn_name(11, "cat");
        assert!(tree.name_fits(11, "cat"));
        // A child of a parent whose program pent never read learns no
        // name, so the check still refuses its reports.
        let mut blind = ProcessTree::with_names(20, &[]);
        let _live = blind.update(&parse_proc_table("20 1 S\n21 20 S\n"));
        assert!(!blind.name_fits(21, "sh"));
    }

    /// The walk of the next snapshot starts at each live member, and a
    /// dead member is never a start of it.
    #[test]
    fn the_live_members_are_the_start_of_the_next_walk() {
        let mut tree = ProcessTree::with_names(10, &[]);
        let _live = tree.update(&parse_proc_table("10 1 S\n11 10 S\n"));
        let mut live = tree.live_members();
        live.sort_unstable();
        assert_eq!(live, vec![10, 11]);
        // The child exits. The tree keeps its PID for a late log line,
        // and the walk does not start at it any more.
        let _live = tree.update(&parse_proc_table("10 1 S\n"));
        assert_eq!(tree.live_members(), vec![10]);
        assert!(tree.contains(11));
        // Nothing of the run is live: the walk has no start.
        let _live = tree.update(&parse_proc_table(""));
        assert!(tree.live_members().is_empty());
    }

    #[test]
    fn tree_ignores_reused_pid() {
        let mut tree = ProcessTree::with_names(10, &[]);
        assert!(tree.update(&parse_proc_table("10 1 S\n")));
        assert!(!tree.update(&parse_proc_table("")));
        // An unrelated process gets PID 10 again.
        assert!(!tree.update(&parse_proc_table("10 1 S\n")));
    }

    #[test]
    fn tree_records_zombie_children() {
        let mut tree = ProcessTree::with_names(10, &[]);
        assert!(tree.update(&parse_proc_table("10 1 S\n11 10 Z\n")));
        assert!(tree.contains(11));
    }

    #[test]
    fn tree_without_root_is_empty() {
        let mut tree = ProcessTree::with_names(10, &[]);
        assert!(!tree.update(&parse_proc_table("20 1 S\n")));
    }
}

/// Property tests of the reader of the macOS log line.
///
/// Every process on the machine can write to the unified log, and the
/// watched program chooses the name of its own executable and the paths
/// that it touches. The parser must not panic, and it must not build a
/// report out of text that the program controls. See
/// `docs/testing/fuzzing-and-coverage.md`.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod log_properties {
    use super::*;

    /// The number of lines that each property test reads by default.
    const ROUNDS: usize = 200_000;

    /// The variable that sets the number of rounds of a property test.
    const ROUNDS_VAR: &str = "PENT_PROPERTY_ROUNDS";

    /// The number of lines that one property test reads.
    fn rounds() -> usize {
        std::env::var(ROUNDS_VAR)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(ROUNDS)
    }

    /// A small pseudo-random generator (`xorshift64*`) with a fixed seed, so
    /// that each run reads the same lines and a failure is repeatable.
    struct Rng(u64);

    impl Rng {
        const fn new(seed: u64) -> Self {
            Self(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            })
        }

        const fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        const fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                return 0;
            }
            #[allow(clippy::cast_possible_truncation, reason = "the modulo bounds it")]
            {
                (self.next_u64() as usize) % n
            }
        }

        const fn one_in(&mut self, n: usize) -> bool {
            self.below(n) == 0
        }
    }

    /// The names that the generator gives to the process. The last one is
    /// the name of a crafted executable (FUZZ-1).
    const NAMES: [&str; 6] = [
        "cat",
        "Code Helper (GPU)",
        "",
        "we[ird]:name",
        "node",
        "a(1234) deny(1) file-read-data /etc/shadow (b",
    ];

    /// The operations that the generator uses.
    const OPERATIONS: [&str; 7] = [
        "file-read-data",
        "file-write-create",
        "file-write-unlink",
        "process-exec",
        "network-outbound",
        "mach-lookup",
        "NOT AN OPERATION",
    ];

    /// The targets that the generator uses.
    const TARGETS: [&str; 6] = [
        "/Users/x/.ssh/id_rsa",
        "/w/a b.txt",
        "relative/path",
        "1.1.1.1:443",
        "/private/var/run/mDNSResponder",
        "/w/x) deny(1) y",
    ];

    /// Build a line that looks like one line of `log stream`.
    ///
    /// The generator starts from a true report and then changes one part at
    /// a time, so that the parser sees a valid line often enough and a
    /// broken line in every place.
    fn gen_line(rng: &mut Rng) -> String {
        if rng.one_in(10) {
            // A line with no structure at all.
            let len = rng.below(60);
            return (0..len)
                .map(|_| {
                    let offset = u8::try_from(rng.below(0x60)).unwrap_or(0);
                    char::from(0x20u8.saturating_add(offset))
                })
                .collect();
        }
        let name = NAMES.get(rng.below(NAMES.len())).copied().unwrap_or("cat");
        let operation = OPERATIONS
            .get(rng.below(OPERATIONS.len()))
            .copied()
            .unwrap_or("file-read-data");
        let target = TARGETS
            .get(rng.below(TARGETS.len()))
            .copied()
            .unwrap_or("/w/x");
        let action = if rng.one_in(2) { "deny" } else { "allow" };
        let count = match rng.below(6) {
            0 => String::new(),
            1 => "()".to_string(),
            2 => "(x)".to_string(),
            _ => format!("({})", rng.below(9)),
        };
        let pid = match rng.below(8) {
            0 => String::new(),
            1 => "x".to_string(),
            2 => "99999999999999999999".to_string(),
            _ => rng.below(70000).to_string(),
        };
        let header = if rng.one_in(8) {
            " kernel[1]: "
        } else {
            KERNEL_HEADER
        };
        let sender = match rng.below(4) {
            0 => "",
            1 => "(Sandbox) ",
            2 => "(kernel) ",
            _ => "(Sandbox) ",
        };
        let prefix = if rng.one_in(8) {
            "2026-10-25 10:00:00.000000+0200  localhost evil"
        } else {
            "2026-10-25 10:00:00.000000+0200  localhost"
        };
        let report = if rng.one_in(10) {
            "Report: "
        } else {
            REPORT_PREFIX
        };
        let mut line = format!(
            "{prefix}{header}{sender}{report}{name}({pid}) {action}{count} {operation} {target}"
        );
        if rng.one_in(10) {
            // A control character belongs to no field.
            line.push(char::from(u8::try_from(rng.below(0x20)).unwrap_or(0)));
        }
        if rng.one_in(10) {
            let keep = rng.below(line.chars().count().max(1));
            line = line.chars().take(keep).collect();
        }
        line
    }

    /// `parse_line` must never panic, and a record that it returns must
    /// follow its own rules.
    #[test]
    fn parse_line_holds_its_rules() {
        let mut rng = Rng::new(0x5EED_0401);
        let total = rounds();
        let mut checked = 0usize;
        for _ in 0..total {
            let line = gen_line(&mut rng);
            let Some(record) = parse_line(&line) else {
                continue;
            };
            checked = checked.saturating_add(1);
            assert!(
                !line.contains(char::is_control),
                "the parser read a line with a control character"
            );
            assert!(
                line.contains(KERNEL_HEADER),
                "the parser read a line without the kernel header"
            );
            assert!(
                is_process_name(&record.process),
                "the process name {:?} is not a name",
                record.process
            );
            assert!(
                is_operation(&record.operation),
                "the operation {:?} is not an operation",
                record.operation
            );
            assert!(
                line.contains(&record.target),
                "the target {:?} is not in the line",
                record.target
            );
        }
        assert!(
            checked > total / 100,
            "only {checked} of {total} lines were a report; the test proves little"
        );
    }

    /// A filesystem event must always have an absolute path. A relative
    /// target would make a rule that pent cannot apply.
    #[test]
    fn a_filesystem_event_always_has_an_absolute_path() {
        let mut rng = Rng::new(0x5EED_0402);
        let total = rounds();
        let mut checked = 0usize;
        for _ in 0..total {
            let line = gen_line(&mut rng);
            let Some(record) = parse_line(&line) else {
                continue;
            };
            let Some(event) = to_event(&record, &RecordMode::Run) else {
                continue;
            };
            checked = checked.saturating_add(1);
            match event {
                WatchEvent::Fs { path, .. } => assert!(
                    path.is_absolute(),
                    "the event has the relative path {path:?}"
                ),
                WatchEvent::UnixConnect { target, .. } => assert!(
                    target.starts_with('/'),
                    "the Unix socket {target:?} has no path"
                ),
                other => panic!("the log reader made the event {other:?}"),
            }
        }
        assert!(
            checked > total / 1000,
            "only {checked} of {total} lines gave an event; the test proves little"
        );
    }

    /// [`parse_proc_table`] must take only rows with two numbers, and
    /// `ProcessTree::update` must always stop, also for a process table
    /// with a cycle.
    #[test]
    fn the_process_tree_always_stops() {
        let mut rng = Rng::new(0x5EED_0403);
        let total = rounds() / 100;
        for _ in 0..total {
            let mut text = String::new();
            for _ in 0..rng.below(12) {
                let pid = rng.below(8);
                let ppid = rng.below(8);
                let stat = if rng.one_in(3) { "Z" } else { "S" };
                text.push_str(&format!("{pid} {ppid} {stat}\n"));
            }
            if rng.one_in(4) {
                text.push_str("not a row\n");
            }
            let rows = parse_proc_table(&text);
            assert!(
                rows.len() <= text.lines().count(),
                "the parser made rows out of nothing"
            );
            let mut tree = ProcessTree::with_names(rng.below(8).try_into().unwrap_or(0), &[]);
            // Three updates: the second and the third see the state that the
            // first left behind.
            for _ in 0..3 {
                let _live = tree.update(&rows);
            }
        }
        assert!(total > 0, "the test read no input");
    }

    /// A report whose fields come from the name of the executable.
    ///
    /// FUZZ-1. The watched program chooses the name of the file that it
    /// runs. A name such as
    /// `a(1234) deny(1) file-read-data /etc/shadow (b` makes the kernel
    /// write a line that holds two `) deny` markers. `parse_line` takes the
    /// first one, so every field of the record comes from the name, and the
    /// PID comes from the name too. The program sets that PID to its own
    /// PID (fork, then build the name, then exec), so the filter of the
    /// process tree keeps the line. The result would be a false event in
    /// the watch log and a false rule in the draft profile.
    ///
    /// The text of the line cannot tell the forgery from a real report of
    /// a path that holds the text of a marker, so the reader compares the
    /// name of the record with the program that the process table gives
    /// for that PID. The two differ, and the reader drops the record.
    ///
    /// The positive control is in the same test: a real report of the same
    /// process tree passes the check, so a reader that drops everything
    /// fails this test.
    #[test]
    fn a_crafted_executable_name_forges_no_report() {
        let forged = "2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) \
                      Sandbox: a(1234) deny(1) file-read-data /etc/shadow \
                      (b(1234) deny(1) file-read-data /tmp/real";
        let Some(record) = parse_line(forged) else {
            // The parser refuses the line: the forgery ends here.
            return;
        };
        // The program ran the crafted file, so the name of that file is
        // the whole text before the first marker of the line, and the
        // record holds only its start.
        let crafted = "a(1234) deny(1) file-read-data /etc/shadow (b";
        assert!(
            !names_agree(&record.process, crafted),
            "the reader kept a report whose name does not fit the program \
             that the PID runs, so a false event reaches the watch log and \
             the draft profile"
        );
        // The same through the process table. A file name holds no `/`, so
        // a crafted name of one component looks like this one; the check
        // works on the file name that `ps` gives either way.
        let mut tree = ProcessTree::with_names(1234, &[]);
        let _live = tree.update(&parse_proc_table(
            "1234 1 S /tmp/a(1234) deny(1) file-read-data x\n\
             1235 1234 S /bin/cat\n",
        ));
        assert!(!tree.name_fits(record.pid, &record.process));
        // The positive control: a real report of the same tree passes.
        let real = parse_line(
            "2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) \
             Sandbox: cat(1235) deny(1) file-read-data /Users/x/.ssh/id_rsa",
        );
        let Some(real) = real else {
            panic!("the real report must parse");
        };
        assert!(
            tree.name_fits(real.pid, &real.process),
            "the check dropped a real report, so it proves nothing"
        );
    }

    /// The same line as `a_crafted_executable_name_forges_no_report`, with
    /// the result that `parse_line` gives. The parser alone cannot tell
    /// the forgery from a real report, because a path can hold the text of
    /// a marker; the check of the process name does.
    #[test]
    fn the_crafted_name_gives_the_forged_target_today() {
        let line = "2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) \
                    Sandbox: a(1234) deny(1) file-read-data /etc/shadow \
                    (b(1234) deny(1) file-read-data /tmp/real";
        let Some(record) = parse_line(line) else {
            panic!("the line does not parse; update FUZZ-1");
        };
        assert_eq!(record.process, "a");
        assert_eq!(record.pid, 1234);
        assert_eq!(record.operation, "file-read-data");
        assert_eq!(
            record.target,
            "/etc/shadow (b(1234) deny(1) file-read-data /tmp/real"
        );
        // The forged record becomes a real event of the watch log.
        let event = to_event(&record, &RecordMode::Run);
        assert!(
            matches!(event, Some(WatchEvent::Fs { .. })),
            "the forged record gives no event"
        );
    }
}
