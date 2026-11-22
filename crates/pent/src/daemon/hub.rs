//! The shared state of pentd: the queue, the sessions, the watchers and
//! the count of holds and open questions.
//!
//! Each connection has a role, which its first `Hold` decides:
//!
//! | Role | May send | Gets |
//! |---|---|---|
//! | session (`Hold::Run`) | `Ask` | `Question` (with its number), `Verdict` |
//! | holder (`Hold::Daemon`, `Hold::Unit`) | `Answer`, `Watch` | as a client |
//! | client (no hold) | `Answer`, `Watch` | `Verdict` for its answer, `Rejected` |
//!
//! A session cannot answer or watch, so a bug in `pent run` cannot allow
//! its own access or mix the questions of other runs into its own. pentd is
//! the only writer of the rules, one write at a time.
//!
//! Each connection has a bounded [`Outbox`]. A client that does not read
//! fills it, and pentd then closes that connection: a lost message would
//! break the order of the numbers, and an unbounded outbox would let a
//! client make pentd grow without a limit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use pent_profile::{
    Answer, Hold, Message, QuestionId, RejectReason, Rejected, Rule, RuleKey, Scope, SessionId,
};
use pent_settings::RuleStore;
use tokio::sync::{mpsc, watch, Notify};

use super::queue::Queue;

/// How many messages wait for one connection before pentd closes it.
pub(crate) const OUTBOX_LEN: usize = 256;

/// The messages to one connection. When the client does not read and the
/// outbox is full, the outbox asks the connection to close.
#[derive(Debug, Clone)]
pub(crate) struct Outbox {
    tx: mpsc::Sender<Message>,
    close: Arc<Notify>,
}

impl Outbox {
    /// A new outbox, the receiver for the writer of the connection, and the
    /// signal to close the connection.
    pub(crate) fn new() -> (Self, mpsc::Receiver<Message>, Arc<Notify>) {
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

    /// Send `message`. Returns false when the connection is gone or full;
    /// a full connection gets the signal to close.
    fn send(&self, message: Message) -> bool {
        match self.tx.try_send(message) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close.notify_one();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Return true if `self` and `other` reach the same connection.
    fn same(&self, other: &Self) -> bool {
        self.tx.same_channel(&other.tx)
    }
}

/// What keeps pentd alive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Activity {
    /// The live holds.
    pub(crate) holds: usize,
    /// The open questions. A question of an ended session keeps pentd
    /// alive, so a late answer can still become a rule.
    pub(crate) questions: usize,
}

impl Activity {
    /// Return true when nothing keeps pentd alive.
    pub(crate) const fn is_idle(self) -> bool {
        self.holds == 0 && self.questions == 0
    }
}

/// The state behind the lock.
struct State {
    queue: Queue,
    next_session: u64,
    sessions: HashMap<SessionId, Outbox>,
    watchers: Vec<Outbox>,
}

/// The shared state of pentd.
pub(crate) struct Hub {
    state: Mutex<State>,
    activity: watch::Sender<Activity>,
    rules: Option<RuleStore>,
    /// One answer at a time from the queue to the rule file, so the file
    /// gets the answers in the order of the queue.
    writes: tokio::sync::Mutex<()>,
}

/// The role of one connection.
#[derive(Debug)]
pub(crate) enum Role {
    /// No hold yet.
    Client,
    /// A holder that is not a session.
    Holder {
        /// The hold, which ends when the role drops.
        _hold: HoldGuard,
    },
    /// A run of `pent run`.
    Session {
        /// The number that pentd gave the session.
        id: SessionId,
        /// The key of the run.
        key: RuleKey,
        /// The hold of the run.
        _hold: HoldGuard,
    },
}

/// One hold. The count goes down when the value drops, also when the task
/// of the connection ends with an error.
pub(crate) struct HoldGuard(Arc<Hub>);

impl std::fmt::Debug for HoldGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HoldGuard")
    }
}

impl HoldGuard {
    fn new(hub: &Arc<Hub>) -> Self {
        hub.activity
            .send_modify(|a| a.holds = a.holds.saturating_add(1));
        Self(Arc::clone(hub))
    }
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        self.0
            .activity
            .send_modify(|a| a.holds = a.holds.saturating_sub(1));
    }
}

impl Hub {
    /// A new hub. `rules` is `None` when pent cannot find the rule files;
    /// then an answer with the scope `remember` acts only on the open
    /// questions.
    pub(crate) fn new(rules: Option<RuleStore>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                queue: Queue::default(),
                next_session: 0,
                sessions: HashMap::new(),
                watchers: Vec::new(),
            }),
            activity: watch::Sender::new(Activity::default()),
            rules,
            writes: tokio::sync::Mutex::new(()),
        })
    }

    /// Watch the activity.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Activity> {
        self.activity.subscribe()
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
        match message {
            Message::Hold(hold) => self.hold(role, outbox, hold),
            Message::Ask(ask) => {
                let Role::Session { id, key, .. } = role else {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                };
                let mut state = self.lock();
                let (question, new) = state.queue.ask(*id, key, ask);
                let id = question.id;
                let message = Message::Question(question);
                // pentd adds the number and the key, so a question can be
                // too long for one line where its ask was not. The session
                // then gets a refusal in its place, and the order of the
                // numbers stays true.
                if message.encode_line().is_err() {
                    if new {
                        state.queue.remove(id);
                    }
                    reject(outbox, None, RejectReason::TooLong);
                    self.publish(&state);
                    return;
                }
                send(outbox, message.clone());
                if new {
                    broadcast(&mut state.watchers, &message);
                }
                self.publish(&state);
            }
            Message::Answer(answer) => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, Some(answer.id), RejectReason::NotPermitted);
                    return;
                }
                self.answer(outbox, &answer).await;
            }
            Message::Watch => {
                if matches!(role, Role::Session { .. }) {
                    reject(outbox, None, RejectReason::NotPermitted);
                    return;
                }
                let mut state = self.lock();
                for question in state.queue.open() {
                    send(outbox, Message::Question(question.clone()));
                }
                state.watchers.push(outbox.clone());
            }
            other => tracing::debug!("pentd does not take {other:?} from a client"),
        }
    }

    /// Take the first hold of a connection.
    fn hold(self: &Arc<Self>, role: &mut Role, outbox: &Outbox, hold: Hold) {
        if !matches!(role, Role::Client) {
            return;
        }
        *role = match hold {
            Hold::Run { key, .. } => {
                let mut state = self.lock();
                let id = SessionId(state.next_session);
                state.next_session = state.next_session.saturating_add(1);
                state.sessions.insert(id, outbox.clone());
                Role::Session {
                    id,
                    key,
                    _hold: HoldGuard::new(self),
                }
            }
            Hold::Daemon | Hold::Unit => Role::Holder {
                _hold: HoldGuard::new(self),
            },
        };
    }

    /// Check `answer`, write the rule, then send each verdict.
    ///
    /// One answer at a time takes this path, so the rule file gets the
    /// answers in the order of the queue. When the rule cannot be written,
    /// each verdict gets the scope `run`, and the client that answered gets
    /// `Rejected` with `RuleNotKept`.
    async fn answer(&self, outbox: &Outbox, answer: &Answer) {
        let _write = self.writes.lock().await;
        let resolution = {
            let mut state = self.lock();
            match state.queue.answer(answer) {
                Ok(resolution) => {
                    self.publish(&state);
                    resolution
                }
                Err(reason) => {
                    reject(outbox, Some(answer.id), reason);
                    return;
                }
            }
        };
        let kept = match resolution.rule {
            Some(rule) => self.write_rule(&resolution.key, rule).await,
            None => true,
        };
        let mut state = self.lock();
        for (session, mut verdict) in resolution.verdicts {
            if !kept {
                verdict.scope = Scope::Run;
            }
            let message = Message::Verdict(verdict);
            if let Some(target) = state.sessions.get(&session) {
                send(target, message.clone());
            }
            broadcast(&mut state.watchers, &message);
            send(outbox, message);
        }
        if !kept {
            reject(outbox, Some(answer.id), RejectReason::RuleNotKept);
        }
    }

    /// Write `rule` in the rule file of `key`, outside the threads of the
    /// runtime. A rule for the same target takes the place of the old one.
    /// Returns true when the rule is in the file.
    async fn write_rule(&self, key: &RuleKey, rule: Rule) -> bool {
        let Some(store) = self.rules.clone() else {
            tracing::warn!("pentd cannot find the rule files; the answer is not kept");
            return false;
        };
        let file_key = key.clone();
        let write = tokio::task::spawn_blocking(move || {
            store.update(&file_key, |set| {
                set.rules.retain(|r| r.target != rule.target);
                set.rules.push(rule);
            })
        });
        match write.await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::warn!("pentd cannot write the rule of {key}: {e}");
                false
            }
            Err(e) => {
                tracing::warn!("the write of the rule of {key} failed: {e}");
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
            state.sessions.remove(&id);
            state.queue.end_session(id, std::time::Instant::now());
        }
        self.publish(&state);
    }

    /// Drop the orphans that are too old.
    pub(crate) fn expire(&self) {
        let mut state = self.lock();
        let dropped = state.queue.expire(std::time::Instant::now());
        if dropped > 0 {
            tracing::debug!("pentd drops {dropped} old questions of ended sessions");
        }
        state.watchers.retain(|w| !w.tx.is_closed());
        self.publish(&state);
    }
}

/// Send `message` to one connection. A closed or a full connection is not
/// an error here: its task ends soon.
fn send(outbox: &Outbox, message: Message) {
    // A false result means that the connection ends; nothing else to do.
    let _ = outbox.send(message);
}

/// Send `message` to each watcher, and forget each watcher that is gone or
/// full.
fn broadcast(watchers: &mut Vec<Outbox>, message: &Message) {
    watchers.retain(|w| w.send(message.clone()));
}

/// Refuse a message of a client.
fn reject(outbox: &Outbox, id: Option<QuestionId>, reason: RejectReason) {
    send(outbox, Message::Rejected(Rejected { id, reason }));
}
