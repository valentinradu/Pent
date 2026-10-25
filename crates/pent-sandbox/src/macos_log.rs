//! Read the Seatbelt reports of a process tree from the macOS unified log.
//!
//! The kernel writes one log line for each operation that Seatbelt denies,
//! and for each operation that an `allow` rule with `(with report)` allows:
//!
//! ```text
//! Sandbox: cat(1234) deny(1) file-read-data /Users/x/.ssh/id_rsa
//! Sandbox: cat(1234) allow(1) file-read-data /Users/x/notes.txt
//! ```
//!
//! The deny form is known (the `pent run --trace` code reads it). The author
//! did not see the form of an allow report on a Mac. The parser thus accepts
//! the keywords `deny` and `allow`, with or without the `(<count>)` part.
//! Test this on a Mac.
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

/// Parse one line of `log stream` output.
///
/// Return `None` if the line is not a Seatbelt report. The process name can
/// contain spaces and parentheses (`Code Helper (GPU)(77)`); the PID is the
/// number in the last parentheses before the action keyword.
pub(crate) fn parse_line(line: &str) -> Option<SeatbeltRecord> {
    const PREFIX: &str = "Sandbox: ";
    let (marker, action, marker_len) = find_marker(line)?;
    let head = line.get(..marker)?;
    let open = head.rfind('(')?;
    let pid: u32 = head.get(open.checked_add(1)?..)?.trim().parse().ok()?;
    let name_part = head.get(..open)?;
    let process = match name_part.rfind(PREFIX) {
        Some(i) => name_part.get(i.checked_add(PREFIX.len())?..)?,
        None => name_part.rsplit(char::is_whitespace).next()?,
    }
    .trim();
    if process.is_empty() {
        return None;
    }
    let mut rest = line.get(marker.checked_add(marker_len)?..)?;
    // The keyword must end here: "allowed" or "denying" is not a report.
    if !(rest.starts_with('(') || rest.starts_with(char::is_whitespace)) {
        return None;
    }
    // Skip the "(1)" count when it is present.
    if let Some(after_open) = rest.strip_prefix('(') {
        let close = after_open.find(')')?;
        rest = after_open.get(close.checked_add(1)?..)?;
    }
    let rest = rest.trim();
    let (operation, target) = rest
        .split_once(char::is_whitespace)
        .map_or((rest, ""), |(op, target)| (op, target.trim()));
    if operation.is_empty() {
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

/// One row of `ps -A -o pid=,ppid=,stat=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PsRow {
    /// The process ID.
    pub(crate) pid: u32,
    /// The parent process ID.
    pub(crate) ppid: u32,
    /// True if the process exited and its parent did not reap it yet.
    pub(crate) zombie: bool,
}

/// Parse the output of `ps -A -o pid=,ppid=,stat=`.
///
/// A row without a state column is a live process.
pub(crate) fn parse_ps_output(output: &str) -> Vec<PsRow> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse().ok()?;
            let ppid = fields.next()?.parse().ok()?;
            let zombie = fields.next().is_some_and(|stat| stat.starts_with('Z'));
            Some(PsRow { pid, ppid, zombie })
        })
        .collect()
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
}

impl ProcessTree {
    /// Create a tree with only `root`.
    pub(crate) fn new(root: u32) -> Self {
        Self {
            known: HashSet::from([root]),
            dead: HashSet::new(),
        }
    }

    /// Return true if `pid` is in the tree (live or dead).
    pub(crate) fn contains(&self, pid: u32) -> bool {
        self.known.contains(&pid)
    }

    /// Update the tree from a snapshot of the process table.
    ///
    /// Add the children of each live member, mark the members that are not
    /// in the table (or are zombies) as dead, and return true if a member is
    /// still live.
    pub(crate) fn update(&mut self, rows: &[PsRow]) -> bool {
        let mut children: HashMap<u32, Vec<&PsRow>> = HashMap::new();
        let mut present: HashMap<u32, &PsRow> = HashMap::new();
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
                    self.known.insert(child.pid);
                    continue;
                }
                if self.known.insert(child.pid) || self.dead.remove(&child.pid) {
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

    use super::{parse_line, parse_ps_output, to_event, ProcessTree, RecordMode};
    use crate::SandboxError;

    /// The time to wait for `log stream` to print its header.
    const READY_TIMEOUT: Duration = Duration::from_secs(3);
    /// The interval of the process-tree poll.
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    /// The minimum time between two process-tree refreshes on demand.
    const MIN_REFRESH_GAP: Duration = Duration::from_millis(50);
    /// The time to read late log lines after the last process of the tree
    /// exits.
    const DRAIN_GRACE: Duration = Duration::from_millis(500);

    /// The `log stream` predicate.
    ///
    /// The kernel writes each Seatbelt report as
    /// "Sandbox: <name>(<pid>) <action>(<count>) <operation> <target>". The
    /// sender of these messages is the `Sandbox` kernel extension. The
    /// predicate accepts both, so a change of one does not lose all reports.
    const PREDICATE: &str = r#"sender == "Sandbox" OR eventMessage CONTAINS ") deny(" OR eventMessage CONTAINS ") allow(""#;

    /// The process tree and the time of its last refresh.
    struct Tree {
        tree: ProcessTree,
        last_refresh: Option<Instant>,
    }

    impl Tree {
        /// Read the process table and update the tree. Return true if a
        /// member is still live.
        ///
        /// If `ps` fails, keep the tree and return true: the poll tries
        /// again, and the drain does not start too early.
        fn refresh(&mut self) -> bool {
            self.last_refresh = Some(Instant::now());
            match Command::new("/bin/ps")
                .args(["-A", "-o", "pid=,ppid=,stat="])
                .stderr(Stdio::null())
                .output()
            {
                Ok(out) => self
                    .tree
                    .update(&parse_ps_output(&String::from_utf8_lossy(&out.stdout))),
                Err(e) => {
                    tracing::debug!(error = %e, "ps failed");
                    true
                }
            }
        }

        /// Return true if `pid` is in the tree. Refresh first if the PID is
        /// not known and the last refresh is not too recent.
        fn contains(&mut self, pid: u32) -> bool {
            if self.tree.contains(pid) {
                return true;
            }
            if self
                .last_refresh
                .is_none_or(|t| t.elapsed() >= MIN_REFRESH_GAP)
            {
                // The poll thread uses the result for the liveness check;
                // here only the new PIDs matter.
                let _alive = self.refresh();
            }
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

    impl LogReader {
        /// Start `log stream` and wait until it prints its header.
        ///
        /// Start the reader before the child, so that the log does not miss
        /// the first reports. A small race stays: `log stream` prints its
        /// header just before it connects to the log.
        ///
        /// # Errors
        /// Returns `SandboxUnavailable` if `log stream` cannot start or stops
        /// before its header.
        pub(crate) fn start() -> Result<Self, SandboxError> {
            let unavailable = |reason: String| SandboxError::SandboxUnavailable {
                reason,
                remediation: "Make sure that /usr/bin/log works (run `log stream` in a terminal)"
                    .to_string(),
            };
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
        pub(crate) fn attach(mut self, root_pid: u32, mode: RecordMode) -> Receiver<WatchEvent> {
            let (tx, rx) = std::sync::mpsc::channel();
            let (Some(lines), Some(log_proc)) = (self.lines.take(), self.log_proc.take()) else {
                // `start` always sets both fields; with no input the channel
                // closes at once.
                return rx;
            };
            let tree = Arc::new(Mutex::new(Tree {
                tree: ProcessTree::new(root_pid),
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
            // The reports of other sandboxed processes on the system are
            // also in the log. Keep only our process tree.
            if !lock(tree).contains(record.pid) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use pent_profile::{guard_rules, GuardClass};

    // A test helper: a line that does not parse must fail the test.
    #[allow(clippy::panic)]
    fn record(line: &str) -> SeatbeltRecord {
        match parse_line(line) {
            Some(r) => r,
            None => panic!("line did not parse: {line}"),
        }
    }

    #[test]
    fn parses_syslog_deny_line() {
        let r = record(
            "2026-10-25 10:00:00.000000+0200  localhost kernel[0]: (Sandbox) \
             Sandbox: cat(1234) deny(1) file-read-data /Users/x/.ssh/id_rsa",
        );
        assert_eq!(r.process, "cat");
        assert_eq!(r.pid, 1234);
        assert_eq!(r.action, Action::Deny);
        assert_eq!(r.operation, "file-read-data");
        assert_eq!(r.target, "/Users/x/.ssh/id_rsa");
    }

    #[test]
    fn parses_allow_report_with_and_without_count() {
        let r = record("kernel: Sandbox: node(42) allow(1) file-write-create /w/a b.txt");
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.operation, "file-write-create");
        assert_eq!(r.target, "/w/a b.txt");
        let r = record("Sandbox: node(42) allow file-read-data /w/x");
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.target, "/w/x");
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

    #[test]
    fn rejects_other_lines() {
        assert_eq!(parse_line("Filtering the log data using \"...\""), None);
        assert_eq!(
            parse_line("Sandbox: cat(x) deny(1) file-read-data /a"),
            None
        );
        assert_eq!(parse_line("app(12) allowed something"), None);
        assert_eq!(parse_line("Sandbox: (12) deny(1) file-read-data /a"), None);
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

    #[test]
    fn parses_ps_rows() {
        let rows = parse_ps_output("  1     0 Ss\n 10     1 S+\n 11    10 Z+\nbad\n 12 10\n");
        assert_eq!(
            rows,
            vec![
                PsRow {
                    pid: 1,
                    ppid: 0,
                    zombie: false
                },
                PsRow {
                    pid: 10,
                    ppid: 1,
                    zombie: false
                },
                PsRow {
                    pid: 11,
                    ppid: 10,
                    zombie: true
                },
                PsRow {
                    pid: 12,
                    ppid: 10,
                    zombie: false
                },
            ]
        );
    }

    #[test]
    fn tree_follows_descendants_and_ends() {
        let mut tree = ProcessTree::new(10);
        // 10 -> 11 -> 12; 20 is not ours.
        let rows = parse_ps_output("10 1 S\n11 10 S\n12 11 S\n20 1 S\n");
        assert!(tree.update(&rows));
        assert!(tree.contains(12));
        assert!(!tree.contains(20));

        // The root exits; 12 lives on, reparented to launchd.
        let rows = parse_ps_output("12 1 S\n20 1 S\n");
        assert!(tree.update(&rows));
        assert!(tree.contains(10), "dead PIDs stay known for late lines");

        // 12 becomes a zombie: the tree is empty.
        let rows = parse_ps_output("12 1 Z\n20 1 S\n");
        assert!(!tree.update(&rows));
    }

    #[test]
    fn tree_ignores_reused_pid() {
        let mut tree = ProcessTree::new(10);
        assert!(tree.update(&parse_ps_output("10 1 S\n")));
        assert!(!tree.update(&parse_ps_output("")));
        // An unrelated process gets PID 10 again.
        assert!(!tree.update(&parse_ps_output("10 1 S\n")));
    }

    #[test]
    fn tree_records_zombie_children() {
        let mut tree = ProcessTree::new(10);
        assert!(tree.update(&parse_ps_output("10 1 S\n11 10 Z\n")));
        assert!(tree.contains(11));
    }

    #[test]
    fn tree_without_root_is_empty() {
        let mut tree = ProcessTree::new(10);
        assert!(!tree.update(&parse_ps_output("20 1 S\n")));
    }
}
