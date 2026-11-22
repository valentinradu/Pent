//! The client side of pentd for `pent run`: a [`Session`].
//!
//! A session holds pentd for the whole run, and it asks the questions of
//! the run. When no pentd answers, it starts one (`pent daemon --spawned`)
//! and connects again. When the connection ends during the run, it
//! connects again, a few times in a row; a connection that lasts
//! [`STABLE`] resets the count.
//!
//! [`Session::ask`] never waits longer than the deadline of the question.
//! At the deadline the access gets the error of a refusal, and the question
//! stays open in pentd. When pentd fails, each waiting question gets the
//! error of a refusal at once: without pentd, the rules still apply
//! (`docs/design/pent.md`, section 2).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pent_profile::{Ask, Hold, Message, QuestionId, Verdict};
use pent_settings::RuntimeDir;
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};

use super::{read_message, DaemonError};

/// How long the client waits for a pentd that it started.
const START_WAIT: Duration = Duration::from_secs(3);

/// The pause between two tries to connect.
const RETRY_PAUSE: Duration = Duration::from_millis(25);

/// How many times in a row the client holds again after a lost connection.
const MAX_RECONNECTS: u32 = 3;

/// A connection that lasts this long resets the count of reconnects.
const STABLE: Duration = Duration::from_secs(30);

/// The result of a question.
#[cfg_attr(not(test), allow(dead_code))] // `pent run` asks from phase 3 of PLAN.md; until then only the tests ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// pentd sent the verdict of an answer.
    Answered(Verdict),
    /// The deadline came first. The access gets the error of a refusal,
    /// and the question stays open in pentd.
    Deadline,
    /// pentd is not reachable, or it refused the question. The access gets
    /// the error of a refusal.
    Unavailable,
}

/// The answer that the task gives to one question.
type Reply = oneshot::Sender<Option<Verdict>>;

/// A command from [`Session`] to its task.
#[cfg_attr(not(test), allow(dead_code))] // `pent run` asks from phase 3 of PLAN.md; until then only the tests ask.
enum Command {
    Ask(Box<Ask>, Reply),
}

/// How the task connects again after a lost connection.
struct Reconnect {
    runtime: RuntimeDir,
    socket: PathBuf,
    hold_line: String,
}

/// One run of `pent run` in pentd. The hold ends when the value drops.
#[derive(Debug)]
pub(crate) struct Session {
    #[cfg_attr(not(test), allow(dead_code))]
    // `pent run` asks from phase 3 of PLAN.md; until then only the tests ask.
    commands: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Session {
    /// Hold pentd with `hold`, and start pentd when no pentd answers.
    ///
    /// # Errors
    /// Returns the errors of the runtime directory, `DaemonError::Unreachable`
    /// when no pentd answers after a start, and the errors of the first write.
    pub(crate) async fn connect(runtime: &RuntimeDir, hold: Hold) -> Result<Self, DaemonError> {
        let socket = runtime.pentd_socket();
        let hold_line = Message::Hold(hold).encode_line()?;
        let stream = connect_or_start(runtime, &socket, &hold_line).await?;
        let reconnect = Reconnect {
            runtime: runtime.clone(),
            socket,
            hold_line,
        };
        Ok(Self::over(stream, Some(reconnect)))
    }

    /// A session over `stream`, which sent its hold already. Without
    /// `reconnect`, a lost connection ends the session.
    fn over(stream: UnixStream, reconnect: Option<Reconnect>) -> Self {
        let (commands, inbox) = mpsc::unbounded_channel();
        let task = tokio::spawn(run(stream, reconnect, inbox));
        Self { commands, task }
    }

    /// Ask `ask` and wait for the verdict, at most until its deadline.
    #[cfg_attr(not(test), allow(dead_code))] // `pent run` asks from phase 3 of PLAN.md; until then only the tests ask.
    pub(crate) async fn ask(&self, ask: Ask) -> Outcome {
        let deadline = ask.deadline.duration();
        let (reply, verdict) = oneshot::channel();
        if self
            .commands
            .send(Command::Ask(Box::new(ask), reply))
            .is_err()
        {
            return Outcome::Unavailable;
        }
        match tokio::time::timeout(deadline, verdict).await {
            Ok(Ok(Some(verdict))) => Outcome::Answered(verdict),
            Ok(Ok(None) | Err(_)) => Outcome::Unavailable,
            Err(_) => Outcome::Deadline,
        }
    }
}

/// The questions that wait on one connection.
#[derive(Default)]
struct Waiting {
    /// The questions that pentd did not number yet, in the order of the
    /// asks. pentd numbers them in the same order.
    unnumbered: VecDeque<Reply>,
    /// The numbered questions. The same access asked twice has one number.
    numbered: HashMap<QuestionId, Vec<Reply>>,
}

impl Waiting {
    /// Give each waiting question the error of a refusal.
    fn fail_all(&mut self) {
        for reply in self.unnumbered.drain(..) {
            // The caller can be gone after its deadline.
            let _ = reply.send(None);
        }
        for reply in self.numbered.drain().flat_map(|(_, r)| r) {
            let _ = reply.send(None);
        }
    }

    /// Handle one message of pentd.
    fn take(&mut self, message: Message) {
        match message {
            Message::Question(question) => {
                if let Some(reply) = self.unnumbered.pop_front() {
                    self.numbered.entry(question.id).or_default().push(reply);
                }
            }
            Message::Verdict(verdict) => {
                for reply in self.numbered.remove(&verdict.id).unwrap_or_default() {
                    let _ = reply.send(Some(verdict.clone()));
                }
            }
            // pentd refused an ask in place of a number.
            Message::Rejected(_) => {
                if let Some(reply) = self.unnumbered.pop_front() {
                    let _ = reply.send(None);
                }
            }
            other => tracing::debug!("the session does not take {other:?}"),
        }
    }
}

/// The task of a session: it writes the asks, and it reads the numbers and
/// the verdicts.
async fn run(
    stream: UnixStream,
    reconnect: Option<Reconnect>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let mut stream = Some(stream);
    let mut reconnects = 0_u32;
    while let Some(current) = stream.take() {
        let since = tokio::time::Instant::now();
        let ended = serve(current, &mut commands).await;
        if ended == Served::SessionGone {
            return;
        }
        if since.elapsed() >= STABLE {
            reconnects = 0;
        }
        let Some(reconnect) = &reconnect else {
            break;
        };
        if reconnects >= MAX_RECONNECTS {
            tracing::debug!("the hold on pentd ended; no more tries");
            break;
        }
        reconnects = reconnects.saturating_add(1);
        match connect_or_start(&reconnect.runtime, &reconnect.socket, &reconnect.hold_line).await {
            Ok(next) => stream = Some(next),
            Err(e) => tracing::debug!("cannot hold pentd again: {e}"),
        }
    }
    // Without pentd, each later question gets the error of a refusal.
    while let Some(Command::Ask(_, reply)) = commands.recv().await {
        let _ = reply.send(None);
    }
}

/// Why [`serve`] returned.
#[derive(Debug, PartialEq, Eq)]
enum Served {
    /// The connection ended.
    Lost,
    /// The `Session` dropped.
    SessionGone,
}

/// Serve one connection until it ends.
async fn serve(stream: UnixStream, commands: &mut mpsc::UnboundedReceiver<Command>) -> Served {
    let (read, mut write) = stream.into_split();
    // A separate task reads, because a read of a line must not stop in the
    // middle when the other branch below wins.
    let (incoming_tx, mut incoming) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        let mut reader = BufReader::new(read);
        while let Ok(Some(message)) = read_message(&mut reader).await {
            if incoming_tx.send(message).is_err() {
                break;
            }
        }
    });
    let mut waiting = Waiting::default();
    let result = loop {
        tokio::select! {
            command = commands.recv() => match command {
                None => break Served::SessionGone,
                Some(Command::Ask(ask, reply)) => {
                    waiting.unnumbered.push_back(reply);
                    if send_ask(&mut write, *ask).await.is_err() {
                        break Served::Lost;
                    }
                }
            },
            message = incoming.recv() => match message {
                Some(message) => waiting.take(message),
                None => break Served::Lost,
            },
        }
    };
    reader.abort();
    waiting.fail_all();
    result
}

/// Write one ask.
async fn send_ask(write: &mut OwnedWriteHalf, ask: Ask) -> std::io::Result<()> {
    let line = Message::Ask(ask)
        .encode_line()
        .map_err(std::io::Error::other)?;
    write.write_all(line.as_bytes()).await
}

/// Connect and send the hold. When no pentd answers, start one and try
/// again until [`START_WAIT`]. When the started pentd stops before a
/// connection works, the client stops at once: pentd cannot start (for
/// example, a file is at the path of the socket), and the run must not wait
/// for nothing.
async fn connect_or_start(
    runtime: &RuntimeDir,
    socket: &Path,
    line: &str,
) -> Result<UnixStream, DaemonError> {
    if let Ok(stream) = connect_and_send(socket, line).await {
        return Ok(stream);
    }
    runtime.ensure()?;
    let started = start_pentd(socket)?;
    let deadline = tokio::time::Instant::now() + START_WAIT;
    loop {
        // Read the end of pentd before the connect, so a pentd that served
        // and then stopped still gets its last try.
        let ended = started.try_recv().is_ok();
        match connect_and_send(socket, line).await {
            Ok(stream) => return Ok(stream),
            Err(source) if ended || tokio::time::Instant::now() >= deadline => {
                return Err(DaemonError::Unreachable {
                    path: socket.to_path_buf(),
                    source,
                })
            }
            Err(_) => tokio::time::sleep(RETRY_PAUSE).await,
        }
    }
}

/// Connect to `socket` and send `line`.
async fn connect_and_send(socket: &Path, line: &str) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(line.as_bytes()).await?;
    Ok(stream)
}

/// Start `pent daemon --spawned` in its own process group, with no
/// terminal, so a Ctrl-C in the terminal of `pent run` does not stop it.
/// The receiver gets a message when that pentd ends.
fn start_pentd(socket: &Path) -> Result<std::sync::mpsc::Receiver<()>, DaemonError> {
    use std::os::unix::process::CommandExt as _;
    let io = |source| DaemonError::Io {
        path: socket.to_path_buf(),
        source,
    };
    let exe = std::env::current_exe().map_err(io)?;
    let mut child = std::process::Command::new(exe)
        .args(["daemon", "--spawned"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(io)?;
    // Reap the child when it ends, so it does not stay as a zombie while
    // `pent run` runs. pentd normally ends after `pent run`.
    let (ended, ended_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Err(e) = child.wait() {
            tracing::debug!("cannot wait for pentd: {e}");
        }
        // The client can be gone already; then nobody needs the message.
        let _ = ended.send(());
    });
    Ok(ended_rx)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // a test fails on a branch that it must not reach
mod tests {
    use pent_profile::{
        Class, Deadline, Decision, Question, RejectReason, Rejected, Request, Scope, SessionId,
        Source, Target, Timestamp, DNS_DEADLINE, FILE_DEADLINE, PROXY_DEADLINE,
    };
    use tokio::io::AsyncBufReadExt as _;

    use super::*;

    fn ask(deadline: Duration) -> Ask {
        let port = std::num::NonZeroU16::new(5432).unwrap();
        Ask {
            session: SessionId(0),
            key: "cargo".parse().unwrap(),
            program: "psql".into(),
            request: Request::Localhost(port),
            class: Class::Normal,
            menu: vec![Target::Localhost(port)],
            asked: Timestamp(0),
            deadline: Deadline::new(deadline).unwrap(),
        }
    }

    fn verdict(id: u64) -> Verdict {
        Verdict {
            id: QuestionId(id),
            decision: Decision::Allow,
            target: Target::Localhost(std::num::NonZeroU16::new(5432).unwrap()),
            scope: Scope::Run,
            source: Source::Human,
        }
    }

    /// A fake pentd on the other end of a pair: it gives each ask the next
    /// number, and then does what `reply` says.
    async fn fake_pentd<F>(stream: UnixStream, reply: F)
    where
        F: Fn(Question) -> Vec<Message>,
    {
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let mut next = 0;
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(Message::Ask(ask)) = Message::decode_line(&line) else {
                continue;
            };
            let question = Question {
                id: QuestionId(next),
                ask,
            };
            next += 1;
            for message in reply(question) {
                let line = message.encode_line().unwrap();
                if write.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
            }
        }
    }

    // The paused clock moves to the next timer when the runtime is idle,
    // also while socket data is on its way. Thus only this test, where
    // pentd never answers, uses it; the other tests use the real clock.
    #[tokio::test(start_paused = true)]
    async fn each_deadline_gives_a_refusal_at_its_time_and_not_before() {
        for deadline in [FILE_DEADLINE, PROXY_DEADLINE, DNS_DEADLINE] {
            let (ours, theirs) = UnixStream::pair().unwrap();
            // pentd numbers the question and never answers.
            tokio::spawn(fake_pentd(theirs, |q| vec![Message::Question(q)]));
            let session = Session::over(ours, None);
            let start = tokio::time::Instant::now();
            assert_eq!(session.ask(ask(deadline)).await, Outcome::Deadline);
            assert_eq!(start.elapsed(), deadline, "{deadline:?}");
        }
    }

    #[tokio::test]
    async fn a_verdict_answers_each_ask_of_the_same_question() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // pentd answers the second ask, and both asks have the number 0,
        // as for the same access asked twice.
        tokio::spawn(fake_pentd(theirs, |q| {
            let same = Question {
                id: QuestionId(0),
                ask: q.ask.clone(),
            };
            if q.id.0 == 1 {
                vec![Message::Question(same), Message::Verdict(verdict(0))]
            } else {
                vec![Message::Question(same)]
            }
        }));
        let session = Session::over(ours, None);
        let (a, b) = tokio::join!(
            session.ask(ask(FILE_DEADLINE)),
            session.ask(ask(FILE_DEADLINE))
        );
        assert_eq!(a, Outcome::Answered(verdict(0)));
        assert_eq!(b, Outcome::Answered(verdict(0)));
    }

    #[tokio::test]
    async fn a_failure_of_pentd_refuses_at_once() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let session = Session::over(ours, None);
        let start = tokio::time::Instant::now();
        // pentd numbers the question, then stops.
        let server = tokio::spawn(async move {
            let (read, mut write) = theirs.into_split();
            let mut lines = BufReader::new(read).lines();
            if let Ok(Some(line)) = lines.next_line().await {
                if let Ok(Message::Ask(ask)) = Message::decode_line(&line) {
                    let q = Message::Question(Question {
                        id: QuestionId(3),
                        ask,
                    });
                    write
                        .write_all(q.encode_line().unwrap().as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        assert_eq!(session.ask(ask(FILE_DEADLINE)).await, Outcome::Unavailable);
        assert!(start.elapsed() < FILE_DEADLINE);
        server.await.unwrap();
        // A later question gets the refusal too, at once.
        assert_eq!(session.ask(ask(FILE_DEADLINE)).await, Outcome::Unavailable);
    }

    #[tokio::test]
    async fn a_rejected_ask_is_a_refusal() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        tokio::spawn(fake_pentd(theirs, |_| {
            vec![Message::Rejected(Rejected {
                id: None,
                reason: RejectReason::NotPermitted,
            })]
        }));
        let session = Session::over(ours, None);
        assert_eq!(session.ask(ask(FILE_DEADLINE)).await, Outcome::Unavailable);
    }
}
