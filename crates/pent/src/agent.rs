//! `agent.sock`: the one channel of the agent in the sandbox
//! (`docs/design/pent.md`, section 9).
//!
//! `pent run` makes the socket in a new directory next to the runtime
//! directory of pentd (`$XDG_RUNTIME_DIR/pent-agent-XXXXXX/agent.sock`), and
//! the sandbox gets it as an allowed Unix socket, named in
//! [`AGENT_SOCK_VAR`]. The socket lives as long as the run, also when pentd
//! restarts. The protocol is [`pent_profile::agent`]:
//!
//! - `denials`: `pent run` answers from its own list of refusals
//!   ([`DenialLog`]), so it works also without pentd.
//! - `deny ID` and `skip ID REASON`: `pent run` relays them to pentd on the
//!   connection of its session. pentd checks that the question belongs to
//!   that session, and a deny holds for this run and for the exact target.
//!
//! No request allows an access. The list of refusals is only for the agent:
//! no decision reads it.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pent_profile::{
    AgentDenial, AgentReply, AgentRequest, DecidedBy, Request, Timestamp, MAX_LINE_LEN,
};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::commands::decide::Decider;

/// The variable that names `agent.sock` in the sandbox.
pub(crate) const AGENT_SOCK_VAR: &str = "PENT_AGENT_SOCK";

/// The most different refusals in the list of a run. A refusal of the same
/// access by the same program adds to the count of its entry.
pub(crate) const MAX_DENIALS: usize = 1024;

/// The most connections to `agent.sock` at one time. A later connection
/// closes at once, so the program cannot make `pent run` grow.
const MAX_CONNECTIONS: usize = 16;

/// One entry of the list.
struct Entry {
    denial: AgentDenial,
    /// The place of the entry in the order of the last refusal.
    seq: u64,
}

/// The refusals of one run, for the agent. The same access of the same
/// program is one entry with a count. When the list is full, the entry
/// with the oldest last refusal leaves it, and its count adds to
/// `dropped`.
#[derive(Default)]
pub(crate) struct DenialLog {
    entries: HashMap<(String, Request), Entry>,
    /// The key of each entry by its place, oldest first.
    order: BTreeMap<u64, (String, Request)>,
    next: u64,
    dropped: u64,
}

impl DenialLog {
    /// Add one decision. Only a refusal goes into the list.
    pub(crate) fn record(&mut self, program: &str, request: &Request, decided_by: DecidedBy) {
        if !decided_by.is_refusal() {
            return;
        }
        let seq = self.next;
        self.next = self.next.saturating_add(1);
        let key = (program.to_string(), request.clone());
        if let Some(entry) = self.entries.get_mut(&key) {
            self.order.remove(&entry.seq);
            entry.seq = seq;
            entry.denial.count = entry.denial.count.saturating_add(1);
            entry.denial.decided_by = decided_by;
            entry.denial.last = Timestamp::now();
            self.order.insert(seq, key);
            return;
        }
        if self.entries.len() >= MAX_DENIALS {
            if let Some((_, oldest)) = self.order.pop_first() {
                if let Some(gone) = self.entries.remove(&oldest) {
                    self.dropped = self.dropped.saturating_add(gone.denial.count);
                }
            }
        }
        self.order.insert(seq, key.clone());
        self.entries.insert(
            key,
            Entry {
                denial: AgentDenial {
                    program: program.to_string(),
                    request: request.clone(),
                    decided_by,
                    last: Timestamp::now(),
                    count: 1,
                },
                seq,
            },
        );
    }

    /// The entries, oldest last refusal first, and the number of refusals
    /// that left the list.
    pub(crate) fn list(&self) -> (Vec<AgentDenial>, u64) {
        let denials = self
            .order
            .values()
            .filter_map(|key| self.entries.get(key))
            .map(|e| e.denial.clone())
            .collect();
        (denials, self.dropped)
    }
}

/// The server of `agent.sock`. The socket and its directory go when the
/// value drops.
pub(crate) struct AgentServer {
    dir: PathBuf,
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AgentServer {
    fn drop(&mut self) {
        self.task.abort();
        // The run ends; a file that is gone already means nothing.
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Make a new directory `pent-agent-CODE` in `parent`, with the mode 0700.
fn new_dir(parent: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut tries = 0_u32;
    loop {
        let code = pent_profile::SessionId(crate::daemon::random::fresh(|_| false));
        let dir = parent.join(format!("pent-agent-{code}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 8 => {
                tries = tries.saturating_add(1);
            }
            Err(e) => return Err(e),
        }
    }
}

impl AgentServer {
    /// Make `agent.sock` in a new directory in `parent` (mode 0700), and
    /// serve it with `decider`.
    ///
    /// # Errors
    /// Returns the I/O error of the directory or of the socket.
    pub(crate) fn start(parent: &Path, decider: Arc<Decider>) -> std::io::Result<Self> {
        let dir = new_dir(parent)?;
        let path = dir.join("agent.sock");
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(e) => {
                // The directory is new and empty.
                let _ = std::fs::remove_dir(&dir);
                return Err(e);
            }
        };
        // SAFETY: getuid has no preconditions.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let own_uid = unsafe { libc::getuid() };
        let task = tokio::spawn(accept_loop(listener, decider, own_uid));
        Ok(Self { dir, path, task })
    }

    /// The path of the socket.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

async fn accept_loop(listener: UnixListener, decider: Arc<Decider>, own_uid: u32) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::debug!("agent.sock: no connection: {e}");
                continue;
            }
        };
        if !stream.peer_cred().is_ok_and(|c| c.uid() == own_uid) {
            tracing::debug!("agent.sock refuses a peer of another user");
            continue;
        }
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!("agent.sock has too many connections; one closes");
            continue;
        };
        let decider = Arc::clone(&decider);
        tokio::spawn(async move {
            connection(stream, &decider).await;
            drop(slot);
        });
    }
}

/// Serve one connection until it ends or sends a line that is not a
/// request.
async fn connection(stream: UnixStream, decider: &Decider) {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    // The limit counts the newline too: `MAX_LINE_LEN` bytes and `\r\n`.
    let limit = u64::try_from(MAX_LINE_LEN.saturating_add(2)).unwrap_or(u64::MAX);
    loop {
        let mut line = Vec::new();
        match (&mut reader).take(limit).read_until(b'\n', &mut line).await {
            Ok(0) => return,
            Ok(_) if line.last() == Some(&b'\n') => {}
            Ok(_) | Err(_) => return,
        }
        let Ok(text) = std::str::from_utf8(&line) else {
            return;
        };
        let request = match AgentRequest::decode_line(text) {
            Ok(request) => request,
            Err(e) => {
                tracing::debug!("agent.sock closes a connection: {e}");
                return;
            }
        };
        let mut out = String::new();
        for reply in replies(decider, request).await {
            match reply.encode_line() {
                Ok(line) => out.push_str(&line),
                Err(e) => tracing::debug!("agent.sock cannot send a reply: {e}"),
            }
        }
        if write.write_all(out.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// The replies to one request.
async fn replies(decider: &Decider, request: AgentRequest) -> Vec<AgentReply> {
    match request {
        AgentRequest::Denials => {
            let (denials, dropped) = decider.agent_denials();
            let mut replies: Vec<AgentReply> =
                denials.into_iter().map(AgentReply::Denial).collect();
            replies.push(AgentReply::End { dropped });
            replies
        }
        AgentRequest::Deny(id) => vec![done(decider.agent_deny(id).await)],
        AgentRequest::Skip(skip) => vec![done(decider.agent_skip(skip).await)],
    }
}

fn done(outcome: crate::daemon::client::AgentOutcome) -> AgentReply {
    match outcome {
        Ok(()) => AgentReply::Done,
        Err(failure) => AgentReply::Failed(failure),
    }
}

/// The path of `agent.sock` when this process runs in the sandbox of
/// `pent run`.
pub(crate) fn agent_socket() -> Option<PathBuf> {
    std::env::var_os(AGENT_SOCK_VAR)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Send `request` on `agent.sock` at `socket`, and read the replies until
/// the last one (`End`, `Done` or `Failed`).
///
/// # Errors
/// Returns `CliError::Other` when the socket is not reachable or a reply
/// is not valid.
pub(crate) async fn call(
    socket: &Path,
    request: &AgentRequest,
) -> Result<Vec<AgentReply>, crate::error::CliError> {
    use crate::error::CliError;
    let failed = |e: &dyn std::fmt::Display| {
        CliError::Other(format!("agent.sock ({}): {e}", socket.display()))
    };
    let line = request.encode_line().map_err(|e| failed(&e))?;
    let mut stream = UnixStream::connect(socket).await.map_err(|e| failed(&e))?;
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| failed(&e))?;
    let mut reader = BufReader::new(stream);
    let mut replies = Vec::new();
    loop {
        let mut text = String::new();
        let read = reader.read_line(&mut text).await.map_err(|e| failed(&e))?;
        if read == 0 {
            return Err(failed(&"the connection ended before the reply"));
        }
        let reply = AgentReply::decode_line(&text).map_err(|e| failed(&e))?;
        let last = matches!(
            reply,
            AgentReply::End { .. } | AgentReply::Done | AgentReply::Failed(_)
        );
        replies.push(reply);
        if last {
            return Ok(replies);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use super::*;
    use pent_profile::{Decision, FileKind, QuestionId, RulePath};

    fn read(path: &str) -> Request {
        Request::File {
            kind: FileKind::Read,
            path: RulePath::new(path).unwrap(),
        }
    }

    #[test]
    fn the_same_refusal_is_one_entry_with_a_count() {
        let mut log = DenialLog::default();
        let deny = DecidedBy::Rule(Decision::Deny);
        log.record("cat", &read("/home/u/a"), deny);
        log.record("cat", &read("/home/u/b"), deny);
        log.record("cat", &read("/home/u/a"), deny);
        // An allow is no refusal.
        log.record("cat", &read("/home/u/c"), DecidedBy::Rule(Decision::Allow));
        let (list, dropped) = log.list();
        assert_eq!(dropped, 0);
        let seen: Vec<(Request, u64)> = list.iter().map(|d| (d.request.clone(), d.count)).collect();
        // The order is the order of the last refusal.
        assert_eq!(seen, [(read("/home/u/b"), 1), (read("/home/u/a"), 2)]);
        // Another program is another entry.
        log.record("ls", &read("/home/u/a"), deny);
        assert_eq!(log.list().0.len(), 3);
    }

    #[test]
    fn a_full_list_drops_the_oldest_entry_and_counts_its_refusals() {
        let mut log = DenialLog::default();
        let deny = DecidedBy::Base(Decision::Deny);
        let q: QuestionId = "k3m9tx".parse().unwrap();
        // The first entry has three refusals, and its last one is a deadline.
        for _ in 0..2 {
            log.record("cat", &read("/home/u/first"), deny);
        }
        log.record(
            "cat",
            &read("/home/u/first"),
            DecidedBy::Deadline { question: q },
        );
        for i in 1..MAX_DENIALS {
            log.record("cat", &read(&format!("/home/u/{i}")), deny);
        }
        let (list, dropped) = log.list();
        assert_eq!((list.len(), dropped), (MAX_DENIALS, 0));
        assert!(matches!(
            list.first(),
            Some(d) if d.request == read("/home/u/first")
                && d.count == 3
                && d.decided_by == DecidedBy::Deadline { question: q }
        ));
        // A new refusal of the oldest entry moves it to the end.
        log.record("cat", &read("/home/u/first"), deny);
        log.record("cat", &read("/home/u/new"), deny);
        let (list, dropped) = log.list();
        assert_eq!((list.len(), dropped), (MAX_DENIALS, 1));
        assert!(!list.iter().any(|d| d.request == read("/home/u/1")));
        assert!(list.iter().any(|d| d.request == read("/home/u/first")));
        assert!(matches!(list.last(), Some(d) if d.request == read("/home/u/new")));
    }
}
