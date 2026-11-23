//! The shared state of pentd: the queue, the sessions, the watchers and
//! the count of connections and open questions.
//!
//! Each connection has a role, which its first `Hold` decides:
//!
//! | Role | May send | Gets |
//! |---|---|---|
//! | session (`Hold::Run`) | `Ask`, `Event` | `Question` (with its number), `Verdict` |
//! | holder (`Hold::Daemon`, `Hold::Unit`) | as a client | as a client |
//! | client (no hold) | `Answer`, `Watch`, `Questions`, `Denials`, `Forget` | `Verdict` for its answer, the replies, `Rejected` |
//!
//! A session cannot answer, watch, read the questions or the refusals, or
//! forget a rule, so a bug in `pent run` cannot allow its own access or mix
//! the questions of other runs into its own. Only a session sends events,
//! and pentd puts the number of that session in each event. pentd is the
//! only writer of the rules, one write at a time.
//!
//! Each connection has a bounded [`Outbox`]. A client that does not read
//! fills it, and pentd then closes that connection: a lost message would
//! break the order of the numbers, and an unbounded outbox would let a
//! client make pentd grow without a limit. One item of the outbox is a
//! [`Batch`] of encoded lines: a reply with a list (`Questions`, `Denials`,
//! the first questions of `Watch`) and the verdicts of one answer for one
//! connection take one item, so a long list does not fill the outbox.
//! pentd encodes each message one time, and the writer only writes.
//!
//! Each live connection keeps pentd alive, and so does each open question.
//! Thus pentd never stops between the accept of a connection and its first
//! message, and it stays while `pent monitor` is open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use pent_profile::{
    Answer, EventsDropped, Forget, Forgotten, Hold, Message, QuestionId, RejectReason, Rejected,
    RuleKey, Scope, SessionId, SessionInfo, Verdict,
};
use pent_profile::{Class, Classifier};
use pent_settings::RuleStore;
use tokio::sync::{mpsc, watch, Notify};

use super::denials::Denials;
use super::queue::{Plan, Queue};
use super::random;

/// How many messages wait for one connection before pentd closes it.
pub(crate) const OUTBOX_LEN: usize = 256;

/// How often pentd sends the new events to the watchers.
pub(crate) const FLUSH_EVERY: std::time::Duration = std::time::Duration::from_millis(200);

/// The free places that an outbox keeps for the questions and the verdicts.
/// pentd sends a batch of events only to an outbox with more free places,
/// so the events never close a connection.
const EVENT_RESERVE: usize = 64;

/// The most events that wait for the next flush. Above it, pentd counts the
/// events as dropped for each watcher.
const MAX_PENDING: usize = 4096;

/// One or more encoded lines, each with its `\n`, for one write.
#[derive(Debug, Clone, Default)]
pub(crate) struct Batch(String);

impl Batch {
    /// Encode `message` and add its line. A message that cannot be one line
    /// is not added: the hub checks the length of each question before it
    /// queues it, so this does not break the order of the numbers.
    fn push(&mut self, message: &Message) {
        match message.encode_line() {
            Ok(line) => self.0.push_str(&line),
            Err(e) => tracing::warn!("pentd cannot encode a message: {e}"),
        }
    }

    /// A batch of one message.
    fn of(message: &Message) -> Self {
        let mut batch = Self::default();
        batch.push(message);
        batch
    }

    /// Return true if the batch has no line.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The text of the lines.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The messages to one connection. When the client does not read and the
/// outbox is full, the outbox asks the connection to close.
#[derive(Debug, Clone)]
pub(crate) struct Outbox {
    tx: mpsc::Sender<Batch>,
    close: Arc<Notify>,
}

impl Outbox {
    /// A new outbox, the receiver for the writer of the connection, and the
    /// signal to close the connection.
    pub(crate) fn new() -> (Self, mpsc::Receiver<Batch>, Arc<Notify>) {
        let (tx, rx) = mpsc::channel(OUTBOX_LEN);
        let close = Arc::new(Notify::new());
        (
            Self {
                tx,
                close: Arc::clone(&close),
            },
            rx,
            close,
        )
    }

    /// Send `batch`. Returns false when the connection is gone or full;
    /// a full connection gets the signal to close. An empty batch is not
    /// sent.
    fn send(&self, batch: Batch) -> bool {
        if batch.is_empty() {
            return true;
        }
        match self.tx.try_send(batch) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close.notify_one();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Send `batch` only when the outbox keeps more than `reserve` free
    /// places. Returns false when pentd did not send it. A full outbox does
    /// not close the connection here: the caller counts what it dropped.
    fn send_spare(&self, batch: Batch, reserve: usize) -> bool {
        if self.tx.capacity() <= reserve {
            return false;
        }
        self.tx.try_send(batch).is_ok()
    }

    /// Return true if `self` and `other` reach the same connection.
    fn same(&self, other: &Self) -> bool {
        self.tx.same_channel(&other.tx)
    }
}

/// A connection that watches, and the events that it did not get.
#[derive(Debug)]
struct Watcher {
    outbox: Outbox,
    /// The events that pentd dropped for this watcher since its last batch
    /// of events.
    dropped: u64,
}

impl Watcher {
    /// Send `batch`, as [`Outbox::send`].
    fn send(&self, batch: Batch) -> bool {
        self.outbox.send(batch)
    }

    /// Return true if this watcher is the connection of `outbox`.
    fn same(&self, outbox: &Outbox) -> bool {
        self.outbox.same(outbox)
    }
}

/// What keeps pentd alive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Activity {
    /// The live connections.
    pub(crate) connections: usize,
    /// The open questions. A question of an ended session keeps pentd
    /// alive, so a late answer can still become a rule.
    pub(crate) questions: usize,
}

impl Activity {
    /// Return true when nothing keeps pentd alive.
    pub(crate) const fn is_idle(self) -> bool {
        self.connections == 0 && self.questions == 0
    }
}

/// The state behind the lock.
struct State {
    queue: Queue,
    denials: Denials,
    sessions: HashMap<SessionId, Outbox>,
    watchers: Vec<Watcher>,
    /// The events for the watchers since the last flush.
    pending: Vec<pent_profile::Event>,
    /// The events above [`MAX_PENDING`] since the last flush.
    pending_lost: u64,
}

impl State {
    /// Return true if `outbox` is a watcher.
    fn watches(&self, outbox: &Outbox) -> bool {
        self.watchers.iter().any(|w| w.same(outbox))
    }
}

/// The shared state of pentd.
pub(crate) struct Hub {
    state: Mutex<State>,
    activity: watch::Sender<Activity>,
    rules: Option<RuleStore>,
    /// The classes of the user. pentd computes the class and the menu of
    /// each question itself, so a faulty session cannot make a sensitive
    /// access look normal or offer a wide target for it.
    classes: Option<Classifier>,
    /// One answer at a time from the queue to the rule file, so the file
    /// gets the answers in the order of the queue.
    writes: tokio::sync::Mutex<()>,
    /// The count of new questions, for the notification hook.
    new_questions: watch::Sender<u64>,
}

/// The role of one connection.
#[derive(Debug)]
pub(crate) enum Role {
    /// No message yet.
    Client,
    /// A client that sent a message other than a hold first. It may not
    /// hold any more: a hold is only the first message, so a watcher never
    /// becomes a session.
    Plain,
    /// A holder that is not a session.
    Holder,
    /// A run of `pent run`.
    Session {
        /// The number that pentd gave the session.
        id: SessionId,
        /// The key of the run.
        key: RuleKey,
    },
}

/// One live connection. The count goes down when the value drops, also
/// when the task of the connection ends with an error.
pub(crate) struct ConnectionGuard(Arc<Hub>);

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectionGuard")
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0
            .activity
            .send_modify(|a| a.connections = a.connections.saturating_sub(1));
    }
}

impl Hub {
    /// A new hub. `rules` is `None` when pent cannot find the rule files;
    /// then an answer with the scope `remember` holds only for this run.
    /// `classes` is `None` when pent does not know the home directory; then
    /// pentd refuses each question with `NoAnswer`.
    pub(crate) fn new(rules: Option<RuleStore>, classes: Option<Classifier>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                queue: Queue::default(),
                denials: Denials::default(),
                sessions: HashMap::new(),
                watchers: Vec::new(),
                pending: Vec::new(),
                pending_lost: 0,
            }),
            activity: watch::Sender::new(Activity::default()),
            rules,
            classes,
            writes: tokio::sync::Mutex::new(()),
            new_questions: watch::Sender::new(0),
        })
    }

    /// Watch the activity.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Activity> {
        self.activity.subscribe()
    }

    /// Count a new connection until the guard drops. The accept loop takes
    /// the guard before it starts the task of the connection.
    pub(crate) fn connection(self: &Arc<Self>) -> ConnectionGuard {
        self.activity
            .send_modify(|a| a.connections = a.connections.saturating_add(1));
        ConnectionGuard(Arc::clone(self))
    }

    /// Watch the count of new questions. The receiver sees a change for
    /// each question since its last look.
    pub(crate) fn watch_new_questions(&self) -> watch::Receiver<u64> {
        self.new_questions.subscribe()
    }

    /// The number of open questions.
    pub(crate) fn open_questions(&self) -> usize {
        self.lock().queue.len()
    }

    /// The lock of the state. A panic in another task cannot leave the
    /// state half changed (each change is one call), so pentd takes the
    /// state also from a poisoned lock.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish the number of open questions.
    fn publish(&self, state: &State) {
        let questions = state.queue.len();
        self.activity.send_if_modified(|a| {
            let changed = a.questions != questions;
            a.questions = questions;
            changed
        });
    }

    /// Handle `message` from a connection with the role `role`, which
    /// `outbox` reaches.
    pub(crate) async fn handle(
        self: &Arc<Self>,
        role: &mut Role,
        outbox: &Outbox,
        message: Message,
    ) {
        if matches!(role, Role::Client) && !matches!(message, Message::Hold(_)) {
            *role = Role::Plain;
        }
        match message {
            Message::Hold(hold) => self.hold(role, outbox, hold),
            Message::Ask(ask) => {
                let Role::Session { id, key } = role else {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                };
                self.ask(*id, key, outbox, ask);
            }
            Message::Answer(answer) => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, Some(answer.id), RejectReason::NotPermitted);
                    return;
                }
                self.answer(outbox, &answer).await;
            }
            Message::Event(event) => {
                let Role::Session { id, .. } = role else {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                };
                let mut state = self.lock();
                if let Some(event) = state.denials.record(*id, event) {
                    if state.watchers.is_empty() {
                        // Nobody watches: the log of the session keeps it.
                    } else if state.pending.len() < MAX_PENDING {
                        state.pending.push(event);
                    } else {
                        state.pending_lost = state.pending_lost.saturating_add(1);
                    }
                }
            }
            Message::Questions => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                }
                let mut batch = Batch::default();
                for question in self.lock().queue.open() {
                    batch.push(&Message::Question(question.clone()));
                }
                batch.push(&Message::End);
                outbox.send(batch);
            }
            Message::Denials(session) => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                }
                let Some(denials) = self.lock().denials.list(session) else {
                    reject(outbox, None, RejectReason::UnknownSession);
                    return;
                };
                let mut batch = Batch::default();
                for denial in denials {
                    batch.push(&Message::Denial(denial));
                }
                batch.push(&Message::End);
                outbox.send(batch);
            }
            Message::Forget(forget) => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                }
                self.forget(outbox, forget).await;
            }
            Message::Watch => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                }
                let mut state = self.lock();
                // A second `Watch` changes nothing: one connection is one
                // watcher, so it gets each message one time.
                if state.watches(outbox) {
                    return;
                }
                // The other watchers get the waiting events first, so the new
                // watcher gets them only in the recent events below.
                flush(&mut state);
                let mut batch = Batch::default();
                for info in state.denials.sessions() {
                    batch.push(&Message::Session(info));
                }
                for question in state.queue.open() {
                    batch.push(&Message::Question(question.clone()));
                }
                for event in state.denials.recent() {
                    batch.push(&Message::Event(event));
                }
                if outbox.send(batch) {
                    state.watchers.push(Watcher {
                        outbox: outbox.clone(),
                        dropped: 0,
                    });
                }
            }
            other => tracing::debug!("pentd does not take {other:?} from a client"),
        }
    }

    /// Take the hold of a connection. Only the first message may hold; a
    /// later hold gets `NotPermitted`.
    fn hold(&self, role: &mut Role, outbox: &Outbox, hold: Hold) {
        if !matches!(role, Role::Client) {
            reject(outbox, None, RejectReason::NotPermitted);
            return;
        }
        *role = match hold {
            Hold::Run { key, command } => {
                let mut state = self.lock();
                // A code that no live session and no list of refusals has.
                let id = SessionId(random::fresh(|v| {
                    let id = SessionId(v);
                    state.sessions.contains_key(&id) || state.denials.knows(id)
                }));
                state.sessions.insert(id, outbox.clone());
                state.denials.start(id, key.clone(), command);
                if let Some(info) = state.denials.info(id) {
                    broadcast(&mut state.watchers, &Batch::of(&Message::Session(info)));
                }
                Role::Session { id, key }
            }
            Hold::Daemon | Hold::Unit => Role::Holder,
        };
    }

    /// Queue the question `ask` of the session `session`. pentd replaces
    /// the class and the menu of the ask with its own. An access in the pent
    /// class gets `NoAnswer`: nobody answers it.
    fn ask(&self, session: SessionId, key: &RuleKey, outbox: &Outbox, mut ask: pent_profile::Ask) {
        let Some(classes) = &self.classes else {
            reject(outbox, None, RejectReason::NoAnswer);
            return;
        };
        let access = ask.request.as_access();
        ask.class = classes.classify(&access);
        ask.menu = classes.widths(&access);
        if ask.class == Class::Pent {
            reject(outbox, None, RejectReason::NoAnswer);
            return;
        }
        let mut state = self.lock();
        let (question, new) = match state.queue.ask(session, key, ask) {
            Ok(asked) => asked,
            Err(reason) => {
                reject(outbox, None, reason);
                return;
            }
        };
        let id = question.id;
        // pentd adds the number and the key, so a question can be too long
        // for one line where its ask was not. The session then gets a
        // refusal in its place, and the order of the numbers stays true.
        let Ok(line) = Message::Question(question).encode_line() else {
            if new {
                state.queue.remove(id);
            }
            reject(outbox, None, RejectReason::TooLong);
            self.publish(&state);
            return;
        };
        let batch = Batch(line);
        outbox.send(batch.clone());
        if new {
            broadcast(&mut state.watchers, &batch);
            self.new_questions.send_modify(|n| *n = n.wrapping_add(1));
        }
        self.publish(&state);
    }

    /// Check `answer`, write the rule, then resolve the questions and send
    /// each verdict.
    ///
    /// One answer at a time takes this path, so the rule file gets the
    /// answers in the order of the queue. pentd resolves the questions only
    /// after the write: when the write fails, the answer holds only for the
    /// run of the question, as an answer with the scope `run` does, and the
    /// client that answered gets `RuleNotKept` before the verdicts. A
    /// question that came during the write is resolved too. When the
    /// answered question went during the write, see [`answer_end`].
    ///
    /// Each connection gets the verdicts of one answer as one batch, so a
    /// wide answer that resolves many questions does not fill an outbox.
    async fn answer(&self, outbox: &Outbox, answer: &Answer) {
        let _write = self.writes.lock().await;
        let plan = match self.lock().queue.check(answer) {
            Ok(plan) => plan,
            Err(reason) => {
                reject(outbox, Some(answer.id), reason);
                return;
            }
        };
        let scope = match plan.scope {
            Scope::Remember if self.write_rule(&plan).await => Scope::Remember,
            Scope::Remember | Scope::Run => Scope::Run,
        };
        let mut state = self.lock();
        let verdicts = state.queue.resolve(&plan, scope);
        self.publish(&state);
        let mut to_answerer = Batch::default();
        match answer_end(plan.id, &verdicts, plan.scope, scope) {
            AnswerEnd::Verdicts => {}
            AnswerEnd::NotKept => to_answerer.push(&rejected(answer.id, RejectReason::RuleNotKept)),
            AnswerEnd::Gone => {
                to_answerer.push(&rejected(answer.id, RejectReason::UnknownQuestion))
            }
            AnswerEnd::GoneButKept => to_answerer.push(&Message::Verdict(plan.verdict(scope))),
        }
        let mut to_sessions: HashMap<SessionId, Batch> = HashMap::new();
        let mut to_watchers = Batch::default();
        for (session, verdict) in verdicts {
            let message = Message::Verdict(verdict);
            let line = Batch::of(&message);
            to_sessions.entry(session).or_default().0.push_str(&line.0);
            to_watchers.0.push_str(&line.0);
        }
        for (session, batch) in to_sessions {
            if let Some(target) = state.sessions.get(&session) {
                target.send(batch);
            }
        }
        // A watcher gets the verdicts with the other watchers; one copy is
        // enough.
        if !state.watches(outbox) {
            to_answerer.0.push_str(&to_watchers.0);
        }
        // The answerer gets its batch first: when it watches, its
        // `RuleNotKept` must come before the verdicts of the broadcast.
        outbox.send(to_answerer);
        broadcast(&mut state.watchers, &to_watchers);
    }

    /// Remove the rules of `forget` from the rule file of its key, and send
    /// the count. One write at a time takes this path, as for an answer.
    async fn forget(&self, outbox: &Outbox, forget: Forget) {
        let _write = self.writes.lock().await;
        let Some(store) = self.rules.clone() else {
            tracing::warn!("pentd cannot find the rule files; nothing to forget");
            reject(outbox, None, RejectReason::RulesNotWritten);
            return;
        };
        let Forget { key, target } = forget;
        let file_key = key.clone();
        let write = tokio::task::spawn_blocking(move || {
            // A key with no rule needs no write, and pentd does not create
            // an empty file for it.
            if store.load(&file_key)?.rules.is_empty() {
                return Ok(0);
            }
            store.update(&file_key, |set| {
                let before = set.rules.len();
                match &target {
                    Some(target) => set.rules.retain(|r| r.target != *target),
                    None => set.rules.clear(),
                }
                before.saturating_sub(set.rules.len())
            })
        });
        match write.await {
            Ok(Ok(count)) => send(
                outbox,
                &Message::Forgotten(Forgotten {
                    key,
                    count: u32::try_from(count).unwrap_or(u32::MAX),
                }),
            ),
            Ok(Err(e)) => {
                tracing::warn!("pentd cannot change the rules of {key}: {e}");
                reject(outbox, None, RejectReason::RulesNotWritten);
            }
            Err(e) => {
                tracing::warn!("the change of the rules of {key} failed: {e}");
                reject(outbox, None, RejectReason::RulesNotWritten);
            }
        }
    }

    /// Write the rule of `plan` in the rule file of its key, outside the
    /// threads of the runtime. A rule for the same target takes the place of
    /// the old one. Returns true when the rule is in the file.
    async fn write_rule(&self, plan: &Plan) -> bool {
        let Some(store) = self.rules.clone() else {
            tracing::warn!("pentd cannot find the rule files; the answer is not kept");
            return false;
        };
        let key = plan.key.clone();
        let rule = plan.rule();
        let write = tokio::task::spawn_blocking(move || {
            store.update(&key, |set| {
                set.rules.retain(|r| r.target != rule.target);
                set.rules.push(rule);
            })
        });
        match write.await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::warn!("pentd cannot write the rule of {}: {e}", plan.key);
                false
            }
            Err(e) => {
                tracing::warn!("the write of the rule of {} failed: {e}", plan.key);
                false
            }
        }
    }

    /// The connection of `role`, which `outbox` reached, ended. Its
    /// watcher goes too, so the writer of the connection can end.
    pub(crate) fn end(&self, role: Role, outbox: &Outbox) {
        let mut state = self.lock();
        state.watchers.retain(|w| !w.same(outbox));
        if let Role::Session { id, .. } = role {
            let now = std::time::Instant::now();
            state.sessions.remove(&id);
            state.queue.end_session(id, now);
            // The watchers get the last events of the run before its end.
            flush(&mut state);
            let info = state.denials.info(id);
            state.denials.end(id, now);
            if let Some(info) = info {
                let ended = Message::Session(SessionInfo {
                    live: false,
                    ..info
                });
                broadcast(&mut state.watchers, &Batch::of(&ended));
            }
        }
        self.publish(&state);
    }

    /// Drop the orphans that are too old.
    pub(crate) fn expire(&self) {
        self.expire_at(std::time::Instant::now());
    }

    /// Drop what is too old at `now`. Each watcher gets `Gone` for each
    /// dropped question, so `pent monitor` does not keep it on the screen.
    fn expire_at(&self, now: std::time::Instant) {
        let mut state = self.lock();
        let dropped = state.queue.expire(now);
        state.denials.expire(now);
        if !dropped.is_empty() {
            tracing::debug!(
                "pentd drops {} old questions of ended sessions",
                dropped.len()
            );
            let mut batch = Batch::default();
            for id in dropped {
                batch.push(&Message::Gone(id));
            }
            broadcast(&mut state.watchers, &batch);
        }
        state.watchers.retain(|w| !w.outbox.tx.is_closed());
        self.publish(&state);
    }

    /// Send the new events to the watchers. The server calls this every
    /// [`FLUSH_EVERY`].
    pub(crate) fn flush_events(&self) {
        flush(&mut self.lock());
    }
}

/// Send the waiting events to each watcher in one batch. A watcher whose
/// outbox has no room above [`EVENT_RESERVE`] does not get the batch:
/// pentd counts its events as dropped and sends the count with the next
/// batch that fits, so a loss is never silent.
fn flush(state: &mut State) {
    let events = std::mem::take(&mut state.pending);
    let lost = std::mem::take(&mut state.pending_lost);
    let mut lines = Batch::default();
    for event in events.iter().cloned() {
        lines.push(&Message::Event(event));
    }
    let count = u64::try_from(events.len()).unwrap_or(u64::MAX);
    for watcher in &mut state.watchers {
        let missed = watcher.dropped.saturating_add(lost);
        let mut batch = Batch::default();
        if missed > 0 {
            batch.push(&Message::EventsDropped(EventsDropped { count: missed }));
        }
        batch.0.push_str(&lines.0);
        if batch.is_empty() {
            continue;
        }
        if watcher.outbox.send_spare(batch, EVENT_RESERVE) {
            watcher.dropped = 0;
        } else {
            watcher.dropped = missed.saturating_add(count);
        }
    }
}

/// What the client that answered gets besides the verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnswerEnd {
    /// The verdicts name the question, and the answer holds as asked.
    Verdicts,
    /// pentd did not keep the rule: `RuleNotKept` comes before the
    /// verdicts.
    NotKept,
    /// The question went during the write (its session ended long ago, and
    /// the queue dropped it), but pentd kept the rule: the client gets a
    /// verdict for its question, so it does not report a failure for a rule
    /// that holds.
    GoneButKept,
    /// The question went during the write, and nothing holds:
    /// `UnknownQuestion`, so the client does not wait for a verdict that
    /// never comes.
    Gone,
}

/// The end of the answer to `id`, from the verdicts of the queue, the scope
/// that the answer asked for and the scope that holds after the write.
fn answer_end(
    id: QuestionId,
    verdicts: &[(SessionId, Verdict)],
    asked: Scope,
    holds: Scope,
) -> AnswerEnd {
    let named = verdicts.iter().any(|(_, v)| v.id == id);
    match (named, holds) {
        (false, Scope::Remember) => AnswerEnd::GoneButKept,
        (false, Scope::Run) => AnswerEnd::Gone,
        (true, _) if asked != holds => AnswerEnd::NotKept,
        (true, _) => AnswerEnd::Verdicts,
    }
}

/// Send `message` to one connection. A closed or a full connection is not
/// an error here: its task ends soon.
fn send(outbox: &Outbox, message: &Message) {
    // A false result means that the connection ends; nothing else to do.
    let _ = outbox.send(Batch::of(message));
}

/// Send `batch` to each watcher, and forget each watcher that is gone or
/// full.
fn broadcast(watchers: &mut Vec<Watcher>, batch: &Batch) {
    if batch.is_empty() {
        return;
    }
    watchers.retain(|w| w.send(batch.clone()));
}

/// The refusal of the answer to `id`.
fn rejected(id: QuestionId, reason: RejectReason) -> Message {
    Message::Rejected(Rejected {
        id: Some(id),
        reason,
    })
}

/// Refuse a message of a client.
fn reject(outbox: &Outbox, id: Option<QuestionId>, reason: RejectReason) {
    send(outbox, &Message::Rejected(Rejected { id, reason }));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // a test fails on a value that it must not get
mod tests {
    use std::num::NonZeroU16;

    use pent_profile::{DecidedBy, Decision, Event, MenuIndex, Request, Source, Target, Timestamp};

    use super::*;

    /// The messages of each batch that waits in `rx`.
    fn drain(rx: &mut mpsc::Receiver<Batch>) -> Vec<Vec<Message>> {
        let mut batches = Vec::new();
        while let Ok(batch) = rx.try_recv() {
            let text = String::from_utf8(batch.as_bytes().to_vec()).unwrap();
            batches.push(
                text.lines()
                    .map(|l| Message::decode_line(l).unwrap())
                    .collect(),
            );
        }
        batches
    }

    fn event(time: i64) -> Message {
        Message::Event(Event {
            session: SessionId(0),
            time: Timestamp(time),
            program: "node".into(),
            request: Request::Localhost(NonZeroU16::MIN),
            decided_by: DecidedBy::Rule(Decision::Allow),
        })
    }

    #[tokio::test]
    async fn a_watcher_gets_the_sessions_and_the_events_in_batches_and_each_loss() {
        let hub = Hub::new(None, None);
        let (watcher, mut watched, _close) = Outbox::new();
        hub.handle(&mut Role::Client, &watcher, Message::Watch)
            .await;
        assert!(drain(&mut watched).is_empty(), "nothing to dump yet");

        let (session, _rx, _c) = Outbox::new();
        let mut role = Role::Client;
        let hold = Hold::Run {
            key: "cargo".parse().unwrap(),
            command: vec!["cargo".into()],
        };
        hub.handle(&mut role, &session, Message::Hold(hold)).await;
        let Role::Session { id, .. } = role else {
            panic!("no session");
        };
        let batches = drain(&mut watched);
        assert!(
            matches!(&batches[..], [b] if matches!(&b[..], [Message::Session(i)] if i.id == id && i.live))
        );

        // Three events wait for the flush, then come in one batch with the
        // code of the session.
        for t in 0..3 {
            hub.handle(&mut role, &session, event(t)).await;
        }
        assert!(drain(&mut watched).is_empty());
        hub.flush_events();
        let batches = drain(&mut watched);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 3);
        assert!(batches[0]
            .iter()
            .all(|m| matches!(m, Message::Event(e) if e.session == id)));

        // The outbox has no room above the reserve: the events are dropped
        // for this watcher, and the connection stays.
        for _ in 0..(OUTBOX_LEN - EVENT_RESERVE) {
            assert!(watcher.send(Batch::of(&Message::End)));
        }
        for t in 3..5 {
            hub.handle(&mut role, &session, event(t)).await;
        }
        hub.flush_events();
        assert_eq!(drain(&mut watched).len(), OUTBOX_LEN - EVENT_RESERVE);
        assert!(hub.lock().watches(&watcher), "the watcher must stay");
        // The next batch that fits names the loss first.
        hub.handle(&mut role, &session, event(5)).await;
        hub.flush_events();
        let batches = drain(&mut watched);
        assert!(matches!(
            &batches[..],
            [b] if matches!(&b[..], [Message::EventsDropped(d), Message::Event(e)] if d.count == 2 && e.time.0 == 5)
        ));

        // The end of the session reaches the watcher after its events.
        hub.handle(&mut role, &session, event(6)).await;
        hub.end(role, &session);
        let batches = drain(&mut watched);
        let all: Vec<&Message> = batches.iter().flatten().collect();
        assert!(
            matches!(&all[..], [Message::Event(e), Message::Session(i)] if e.time.0 == 6 && !i.live)
        );
    }

    /// A hub with the classes of the home `/home/u` and the rule store
    /// `rules`.
    fn hub_with(rules: Option<RuleStore>) -> Arc<Hub> {
        Hub::new(
            rules,
            Some(Classifier::new(std::path::Path::new("/home/u"), &[])),
        )
    }

    /// Hold a session of `cargo` and ask for the port `port`.
    async fn ask_port(hub: &Arc<Hub>, port: u16) -> (Role, Outbox, QuestionId) {
        let (session, mut rx, _c) = Outbox::new();
        let mut role = Role::Client;
        let hold = Hold::Run {
            key: "cargo".parse().unwrap(),
            command: vec![],
        };
        hub.handle(&mut role, &session, Message::Hold(hold)).await;
        let port = NonZeroU16::new(port).unwrap();
        let ask = pent_profile::Ask {
            session: SessionId(0),
            key: "cargo".parse().unwrap(),
            program: "psql".into(),
            request: Request::Localhost(port),
            class: Class::Normal,
            menu: vec![],
            asked: Timestamp(0),
            deadline: pent_profile::Deadline::new(pent_profile::FILE_DEADLINE).unwrap(),
        };
        hub.handle(&mut role, &session, Message::Ask(ask)).await;
        let id = drain(&mut rx)
            .into_iter()
            .flatten()
            .find_map(|m| match m {
                Message::Question(q) => Some(q.id),
                _ => None,
            })
            .unwrap();
        (role, session, id)
    }

    #[tokio::test]
    async fn each_watcher_learns_that_an_old_orphan_is_gone() {
        let hub = hub_with(None);
        let (watcher, mut watched, _c) = Outbox::new();
        hub.handle(&mut Role::Client, &watcher, Message::Watch)
            .await;
        let (role, session, id) = ask_port(&hub, 5432).await;
        let ended = std::time::Instant::now();
        hub.end(role, &session);
        drain(&mut watched);
        hub.expire_at(ended + super::super::queue::ORPHAN_TTL + std::time::Duration::from_secs(1));
        let all: Vec<Message> = drain(&mut watched).into_iter().flatten().collect();
        assert_eq!(all, [Message::Gone(id)]);
        assert_eq!(hub.open_questions(), 0);
    }

    #[tokio::test]
    async fn a_watcher_that_answers_gets_rule_not_kept_before_the_verdicts() {
        let state = tempfile::tempdir().unwrap();
        let dirs = pent_settings::PentDirs::from_vars(
            None,
            Some(state.path().into()),
            Some(state.path().into()),
        )
        .unwrap();
        std::fs::create_dir_all(dirs.rules_dir()).unwrap();
        std::fs::write(dirs.rules_dir().join("cargo.toml"), "not toml [").unwrap();
        let hub = hub_with(Some(RuleStore::new(&dirs)));
        let (_role, _session, id) = ask_port(&hub, 5432).await;
        let (monitor, mut rx, _c) = Outbox::new();
        let mut role = Role::Client;
        hub.handle(&mut role, &monitor, Message::Watch).await;
        drain(&mut rx);
        let answer = Answer {
            id,
            decision: Decision::Allow,
            width: MenuIndex(0),
            scope: Scope::Remember,
            source: Source::Human,
        };
        hub.handle(&mut role, &monitor, Message::Answer(answer))
            .await;
        let all: Vec<Message> = drain(&mut rx).into_iter().flatten().collect();
        assert!(
            matches!(
                &all[..],
                [Message::Rejected(r), Message::Verdict(v)]
                    if r.reason == RejectReason::RuleNotKept && v.id == id && v.scope == Scope::Run
            ),
            "{all:?}"
        );
    }

    #[tokio::test]
    async fn a_new_watcher_gets_the_sessions_the_questions_and_the_recent_events() {
        let hub = Hub::new(None, None);
        let (session, _rx, _c) = Outbox::new();
        let mut role = Role::Client;
        let hold = Hold::Run {
            key: "cargo".parse().unwrap(),
            command: vec![],
        };
        hub.handle(&mut role, &session, Message::Hold(hold)).await;
        let (first, mut first_rx, _c1) = Outbox::new();
        hub.handle(&mut Role::Client, &first, Message::Watch).await;
        drain(&mut first_rx);
        hub.handle(&mut role, &session, event(1)).await;
        // A second watcher before the flush: the first one gets the event
        // in a flush, the second one in its dump, and neither gets it two
        // times.
        let (second, mut second_rx, _c2) = Outbox::new();
        hub.handle(&mut Role::Client, &second, Message::Watch).await;
        hub.flush_events();
        let count = |rx: &mut mpsc::Receiver<Batch>| {
            drain(rx)
                .iter()
                .flatten()
                .filter(|m| matches!(m, Message::Event(_)))
                .count()
        };
        assert_eq!(count(&mut first_rx), 1);
        let dump = drain(&mut second_rx);
        assert!(matches!(dump[0][0], Message::Session(_)), "{dump:?}");
        assert_eq!(
            dump.iter()
                .flatten()
                .filter(|m| matches!(m, Message::Event(_)))
                .count(),
            1
        );
    }

    fn verdict(id: u64) -> (SessionId, Verdict) {
        (
            SessionId(0),
            Verdict {
                id: QuestionId(id),
                decision: Decision::Allow,
                target: Target::Localhost(NonZeroU16::MIN),
                scope: Scope::Run,
                source: Source::Human,
            },
        )
    }

    #[test]
    fn the_client_gets_an_end_when_its_question_went_or_its_rule_was_not_kept() {
        use Scope::{Remember, Run};
        let id = QuestionId(1);
        let with = [verdict(0), verdict(1)];
        let without = [verdict(0)];
        assert_eq!(answer_end(id, &with, Run, Run), AnswerEnd::Verdicts);
        assert_eq!(
            answer_end(id, &with, Remember, Remember),
            AnswerEnd::Verdicts
        );
        assert_eq!(answer_end(id, &with, Remember, Run), AnswerEnd::NotKept);
        assert_eq!(
            answer_end(id, &without, Remember, Remember),
            AnswerEnd::GoneButKept
        );
        assert_eq!(answer_end(id, &without, Remember, Run), AnswerEnd::Gone);
        assert_eq!(answer_end(id, &without, Run, Run), AnswerEnd::Gone);
        assert_eq!(answer_end(id, &[], Run, Run), AnswerEnd::Gone);
    }
}
