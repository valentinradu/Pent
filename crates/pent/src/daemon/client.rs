//! The client side of pentd for `pent run`: a [`Session`].
//!
//! A session holds pentd for the whole run, and it asks the questions of
//! the run. Its task connects in the background, so the program starts at
//! once; a question before the connection waits in the task, inside its
//! deadline. When no pentd answers, the task starts one
//! (`pent daemon --spawned`) and connects again. When the connection ends during the run, it
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

use pent_profile::{Ask, Event, Hold, Message, QuestionId, Verdict};
use pent_settings::RuntimeDir;
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::{read_message, DaemonError};

/// How long the client waits for a pentd that it started.
const START_WAIT: Duration = Duration::from_secs(3);

/// The pause between two tries to connect.
const RETRY_PAUSE: Duration = Duration::from_millis(25);

/// How many times in a row the client holds again after a lost connection.
const MAX_RECONNECTS: u32 = 3;

/// The most events that wait in the queue of a session. A later event goes
/// nowhere, so a pentd that reads slowly cannot make the queue grow without
/// a limit. The events are for the human; no decision depends on them.
const MAX_QUEUED_EVENTS: usize = 4096;

/// The longest wait of [`Session::flush`].
const FLUSH_WAIT: Duration = Duration::from_secs(2);

/// A connection that lasts this long resets the count of reconnects.
const STABLE: Duration = Duration::from_secs(30);

/// The result of a question.
#[cfg_attr(not(test), allow(dead_code))] // `pent run` asks from phase 3 of PLAN.md; until then only the tests ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// pentd sent the verdict of an answer.
    Answered(Verdict),
    /// The deadline came first. The access gets the error of a refusal,
    /// and the question stays open in pentd. The number is `None` when
    /// pentd gave no number before the deadline.
    Deadline(Option<QuestionId>),
    /// pentd is not reachable, or it refused the question. The access gets
    /// the error of a refusal.
    Unavailable,
}

/// A step of one question, from the task to [`Session::ask`].
#[derive(Debug)]
enum Step {
    /// pentd gave the question its number.
    Numbered(QuestionId),
    /// The verdict, or `None` for the error of a refusal.
    Done(Option<Verdict>),
}

/// The channel that the task gives the steps of one question to.
type Reply = mpsc::UnboundedSender<Step>;

/// A command from [`Session`] to its task.
enum Command {
    #[cfg_attr(not(test), allow(dead_code))]
    // `pent run` asks from step 3.2 of PLAN.md; until then only the tests ask.
    Ask(Box<Ask>, Reply),
    Event(Box<Event>, Queued),
    /// Reply when each command before this one left.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// The place of one event in the count of the queue. The drop leaves the
/// count, when the task takes the event or when the queue drops it.
struct Queued(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Queued {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
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
    commands: mpsc::UnboundedSender<Command>,
    /// The number of events in the queue of the task.
    queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Session {
    /// Hold pentd with `hold` from a task, and start pentd when no pentd
    /// answers. The call returns at once: the task connects in the
    /// background. When it cannot reach pentd, each question gets the error
    /// of a refusal.
    ///
    /// # Errors
    /// Returns `DaemonError::Protocol` when the hold cannot be one line.
    pub(crate) fn connect(runtime: &RuntimeDir, hold: Hold) -> Result<Self, DaemonError> {
        let reconnect = Reconnect {
            runtime: runtime.clone(),
            socket: runtime.pentd_socket(),
            hold_line: Message::Hold(hold).encode_line()?,
        };
        Ok(Self::spawn(None, Some(reconnect)))
    }

    /// A session over `stream`, which sent its hold already. Without
    /// `reconnect`, a lost connection ends the session.
    #[cfg(test)]
    fn over(stream: UnixStream, reconnect: Option<Reconnect>) -> Self {
        Self::spawn(Some(stream), reconnect)
    }

    /// A session over `stream`, which sent its hold already. A lost
    /// connection ends the session.
    #[cfg(test)]
    pub(crate) fn over_stream(stream: UnixStream) -> Self {
        Self::over(stream, None)
    }

    /// Start the task. With no `stream`, the task connects first.
    fn spawn(stream: Option<UnixStream>, reconnect: Option<Reconnect>) -> Self {
        let (commands, inbox) = mpsc::unbounded_channel();
        let task = tokio::spawn(run(stream, reconnect, inbox));
        Self {
            commands,
            queued: std::sync::Arc::default(),
            task,
        }
    }

    /// Send `event` to pentd. pentd puts the number of this session in
    /// it. Without pentd the event goes nowhere: the events are for the
    /// human, and the decision of the access does not depend on them.
    /// When [`MAX_QUEUED_EVENTS`] events wait already, the event goes
    /// nowhere too.
    pub(crate) fn send_event(&self, event: Event) {
        use std::sync::atomic::Ordering;
        let before = self.queued.fetch_add(1, Ordering::Relaxed);
        let place = Queued(std::sync::Arc::clone(&self.queued));
        if before >= MAX_QUEUED_EVENTS {
            tracing::debug!("the queue of events is full; an event goes nowhere");
            return;
        }
        if self
            .commands
            .send(Command::Event(Box::new(event), place))
            .is_err()
        {
            tracing::debug!("the session ended; an event goes nowhere");
        }
    }

    /// The number of events in the queue of the task.
    #[cfg(test)]
    fn queued(&self) -> usize {
        self.queued.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Wait until each event and each question before this call left for
    /// pentd, at most [`FLUSH_WAIT`]. Call it before the process exits:
    /// the exit ends the task, also with events in its queue.
    pub(crate) async fn flush(&self) {
        let (done, wait) = tokio::sync::oneshot::channel();
        if self.commands.send(Command::Flush(done)).is_err() {
            return;
        }
        if tokio::time::timeout(FLUSH_WAIT, wait).await.is_err() {
            tracing::debug!("the events did not leave for pentd in time");
        }
    }

    /// Ask `ask` and wait for the verdict, at most until its deadline.
    #[cfg_attr(not(test), allow(dead_code))] // `pent run` asks from step 3.2 of PLAN.md; until then only the tests ask.
    pub(crate) async fn ask(&self, ask: Ask) -> Outcome {
        let deadline = tokio::time::Instant::now() + ask.deadline.duration();
        let (reply, mut steps) = mpsc::unbounded_channel();
        if self
            .commands
            .send(Command::Ask(Box::new(ask), reply))
            .is_err()
        {
            return Outcome::Unavailable;
        }
        let mut number = None;
        loop {
            match tokio::time::timeout_at(deadline, steps.recv()).await {
                Ok(Some(Step::Numbered(id))) => number = Some(id),
                Ok(Some(Step::Done(Some(verdict)))) => return Outcome::Answered(verdict),
                Ok(Some(Step::Done(None)) | None) => return Outcome::Unavailable,
                Err(_) => return Outcome::Deadline(number),
            }
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
            let _ = reply.send(Step::Done(None));
        }
        for reply in self.numbered.drain().flat_map(|(_, r)| r) {
            // The caller can be gone after its deadline.
            let _ = reply.send(Step::Done(None));
        }
    }

    /// Forget each numbered question whose callers are gone: their deadline
    /// passed. Thus a long run with many unanswered questions does not
    /// grow. The unnumbered replies stay, because their order matters.
    fn forget_gone(&mut self) {
        self.numbered.retain(|_, replies| {
            replies.retain(|reply| !reply.is_closed());
            !replies.is_empty()
        });
    }

    /// Handle one message of pentd.
    fn take(&mut self, message: Message) {
        match message {
            Message::Question(question) => {
                if let Some(reply) = self.unnumbered.pop_front() {
                    // The caller can be gone after its deadline.
                    let _ = reply.send(Step::Numbered(question.id));
                    self.numbered.entry(question.id).or_default().push(reply);
                }
                self.forget_gone();
            }
            Message::Verdict(verdict) => {
                for reply in self.numbered.remove(&verdict.id).unwrap_or_default() {
                    // The caller can be gone after its deadline.
                    let _ = reply.send(Step::Done(Some(verdict.clone())));
                }
            }
            // pentd refused an ask in place of a number. A refusal with a
            // number is for an answer, and a session does not answer.
            Message::Rejected(rejected) if rejected.id.is_none() => {
                if let Some(reply) = self.unnumbered.pop_front() {
                    // The caller can be gone after its deadline.
                    let _ = reply.send(Step::Done(None));
                }
            }
            other => tracing::debug!("the session does not take {other:?}"),
        }
    }
}

/// The task of a session: it connects when it has no `stream`, it writes
/// the asks, and it reads the numbers and the verdicts.
async fn run(
    stream: Option<UnixStream>,
    reconnect: Option<Reconnect>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let mut stream = stream;
    if stream.is_none() {
        if let Some(r) = &reconnect {
            match connect_or_start(&r.runtime, &r.socket, &r.hold_line).await {
                Ok(first) => stream = Some(first),
                Err(e) => tracing::debug!("pent runs without pentd: {e}"),
            }
        }
    }
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
    // Without pentd, each later question gets the error of a refusal, and
    // each later event goes nowhere.
    while let Some(command) = commands.recv().await {
        match command {
            Command::Ask(_, reply) => {
                // The caller can be gone after its deadline.
                let _ = reply.send(Step::Done(None));
            }
            Command::Flush(done) => {
                // The caller can be gone after its wait.
                let _ = done.send(());
            }
            Command::Event(..) => {}
        }
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
                    // An ask that cannot be one line fails alone: it is no
                    // reason to fail the other questions of the run.
                    let line = match Message::Ask(*ask).encode_line() {
                        Ok(line) => line,
                        Err(e) => {
                            tracing::debug!("the session cannot send a question: {e}");
                            // The caller can be gone after its deadline.
                            let _ = reply.send(Step::Done(None));
                            continue;
                        }
                    };
                    waiting.unnumbered.push_back(reply);
                    if write.write_all(line.as_bytes()).await.is_err() {
                        break Served::Lost;
                    }
                }
                Some(Command::Event(event, _place)) => {
                    // An event that cannot be one line goes alone, as an
                    // ask does.
                    let line = match Message::Event(*event).encode_line() {
                        Ok(line) => line,
                        Err(e) => {
                            tracing::debug!("the session cannot send an event: {e}");
                            continue;
                        }
                    };
                    if write.write_all(line.as_bytes()).await.is_err() {
                        break Served::Lost;
                    }
                }
                Some(Command::Flush(done)) => {
                    // Each write before this one is in the socket now. The
                    // caller can be gone after its wait.
                    let _ = done.send(());
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
        Class, Deadline, Decision, Event, Question, RejectReason, Rejected, Request, Scope,
        SessionId, Source, Target, Timestamp, DNS_DEADLINE, FILE_DEADLINE, PROXY_DEADLINE,
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
            // The paused clock can pass the deadline before the number
            // arrives; the next test checks the number.
            assert!(matches!(
                session.ask(ask(deadline)).await,
                Outcome::Deadline(_)
            ));
            assert_eq!(start.elapsed(), deadline, "{deadline:?}");
        }
    }

    #[tokio::test]
    async fn a_deadline_names_the_number_of_its_question() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        tokio::spawn(fake_pentd(theirs, |q| vec![Message::Question(q)]));
        let session = Session::over(ours, None);
        assert_eq!(
            session.ask(ask(Duration::from_millis(300))).await,
            Outcome::Deadline(Some(QuestionId(0)))
        );
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
    async fn an_ask_that_cannot_be_one_line_fails_alone() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        tokio::spawn(fake_pentd(theirs, |q| {
            let id = q.id;
            vec![
                Message::Question(q),
                Message::Verdict(Verdict { id, ..verdict(0) }),
            ]
        }));
        let session = Session::over(ours, None);
        let mut long = ask(FILE_DEADLINE);
        long.program = "x".repeat(pent_profile::MAX_LINE_LEN);
        assert_eq!(session.ask(long).await, Outcome::Unavailable);
        // The connection is still good: the next question gets its verdict.
        assert_eq!(
            session.ask(ask(FILE_DEADLINE)).await,
            Outcome::Answered(verdict(0))
        );
    }

    #[tokio::test]
    async fn the_queue_of_events_has_a_limit() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // pentd never reads, so the socket fills and the task waits on a
        // write.
        let session = Session::over(ours, None);
        let event = Event {
            session: SessionId(0),
            time: Timestamp(0),
            program: "x".repeat(1000),
            request: Request::Localhost(std::num::NonZeroU16::new(1).unwrap()),
            decided_by: pent_profile::DecidedBy::Base(Decision::Deny),
        };
        for _ in 0..3 * MAX_QUEUED_EVENTS {
            session.send_event(event.clone());
        }
        assert!(
            session.queued() <= MAX_QUEUED_EVENTS,
            "{}",
            session.queued()
        );
        assert!(session.queued() > 0, "the socket took each event");
        drop(theirs);
    }

    #[test]
    fn the_replies_of_expired_questions_go() {
        let mut waiting = Waiting::default();
        for _ in 0..3 {
            let (reply, receiver) = mpsc::unbounded_channel();
            waiting.unnumbered.push_back(reply);
            drop(receiver);
        }
        for id in 0..3 {
            waiting.take(Message::Question(Question {
                id: QuestionId(id),
                ask: ask(FILE_DEADLINE),
            }));
        }
        assert!(waiting.numbered.is_empty(), "the dead replies stay");
    }

    #[test]
    fn a_refusal_with_a_number_does_not_take_the_place_of_a_number() {
        let mut waiting = Waiting::default();
        let (reply, mut receiver) = mpsc::unbounded_channel();
        waiting.unnumbered.push_back(reply);
        waiting.take(Message::Rejected(Rejected {
            id: Some(QuestionId(5)),
            reason: RejectReason::RuleNotKept,
        }));
        assert_eq!(waiting.unnumbered.len(), 1);
        assert!(receiver.try_recv().is_err());
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
