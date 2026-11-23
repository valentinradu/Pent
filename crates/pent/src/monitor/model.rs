//! The model of `pent monitor`: the state of the screen, without I/O.
//!
//! The model takes the messages of pentd ([`Model::apply`]) and the keys of
//! the user ([`Model::key`]), and it returns the [`Action`]s for the loop:
//! a message to send, a read of the rule files, or the end. Thus the tests
//! cover each rule of the screen without a terminal and without pentd.
//!
//! - **The questions** are grouped by root program (the key), in the order
//!   of the first question of each key, and then in the order of the asks.
//! - **An answer** names the selected place in the width menu and the
//!   scope. pentd checks it (`docs/security/pentd.md`, QU-3); the model only
//!   builds it. A sensitive question has only its exact target in its menu.
//! - **The events** keep the last [`MAX_EVENTS`], with a filter by session
//!   and by kind. pentd can drop events for a slow monitor; the model counts
//!   them, so the screen shows each loss.

use std::collections::{HashMap, VecDeque};

use pent_profile::{
    Answer, Decision, Event, MenuIndex, Message, Question, QuestionId, RejectReason, Rule, RuleKey,
    Scope, SessionId, SessionInfo, Source,
};

use crate::daemon::queue::Resolving;

/// The most events that the monitor keeps.
pub(crate) const MAX_EVENTS: usize = 2000;

/// A tab of the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// The open questions.
    Questions,
    /// The events of the sessions.
    Events,
    /// The saved rules.
    Rules,
}

impl Tab {
    /// The tabs, in the order of the screen.
    pub(crate) const ALL: [Self; 3] = [Self::Questions, Self::Events, Self::Rules];

    /// The tab after this one, or before it for `back`.
    fn next(self, back: bool) -> Self {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        let n = Self::ALL.len();
        let j = if back { (i + n - 1) % n } else { (i + 1) % n };
        Self::ALL.get(j).copied().unwrap_or(Self::Questions)
    }
}

/// A key of the user, without the terminal library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Left,
    Right,
    Tab,
    BackTab,
    Enter,
    Esc,
    Char(char),
}

/// What the loop must do after a message or a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Send this message to pentd.
    Send(Message),
    /// Read the rule files again, and give them to [`Model::set_rules`].
    LoadRules,
    /// End the monitor.
    Quit,
}

/// Which events the events tab shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KindFilter {
    /// Each event.
    All,
    /// Only the refusals.
    Refusals,
}

/// The rules of one key, or the error of its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyRules {
    /// The key.
    pub(crate) key: RuleKey,
    /// The rules in the order of the file, or the text of the error.
    pub(crate) rules: Result<Vec<Rule>, String>,
}

/// The state of the screen.
#[derive(Debug)]
pub(crate) struct Model {
    questions: Vec<Question>,
    /// The selected place in the menu of each question.
    widths: HashMap<QuestionId, u16>,
    selected: Option<QuestionId>,
    scope: Scope,
    details: bool,
    sessions: Vec<SessionInfo>,
    events: VecDeque<Event>,
    dropped: u64,
    tab: Tab,
    session_filter: Option<SessionId>,
    kind_filter: KindFilter,
    rules: Vec<KeyRules>,
    rules_selected: usize,
    status: Option<String>,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            questions: Vec::new(),
            widths: HashMap::new(),
            selected: None,
            scope: Scope::Run,
            details: false,
            sessions: Vec::new(),
            events: VecDeque::new(),
            dropped: 0,
            tab: Tab::Questions,
            session_filter: None,
            kind_filter: KindFilter::All,
            rules: Vec::new(),
            rules_selected: 0,
            status: None,
        }
    }
}

impl Model {
    // ── What the view reads ─────────────────────────────────────────────

    /// The tab on the screen.
    pub(crate) const fn tab(&self) -> Tab {
        self.tab
    }

    /// The last status line: the result of an answer or an error.
    pub(crate) fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// The scope of the next answer.
    pub(crate) const fn scope(&self) -> Scope {
        self.scope
    }

    /// True when the details of the selected question show.
    pub(crate) const fn details(&self) -> bool {
        self.details
    }

    /// The number of open questions.
    pub(crate) fn open(&self) -> usize {
        self.questions.len()
    }

    /// The questions grouped by key: each key in the order of its first
    /// question, and its questions in the order of the asks.
    pub(crate) fn groups(&self) -> Vec<(&RuleKey, Vec<&Question>)> {
        let mut groups: Vec<(&RuleKey, Vec<&Question>)> = Vec::new();
        for question in &self.questions {
            match groups.iter_mut().find(|(k, _)| **k == question.ask.key) {
                Some((_, list)) => list.push(question),
                None => groups.push((&question.ask.key, vec![question])),
            }
        }
        groups
    }

    /// The questions in the order of the screen.
    fn ordered(&self) -> Vec<&Question> {
        self.groups()
            .into_iter()
            .flat_map(|(_, list)| list)
            .collect()
    }

    /// The selected question.
    pub(crate) fn selected(&self) -> Option<&Question> {
        let id = self.selected?;
        self.questions.iter().find(|q| q.id == id)
    }

    /// The selected place in the menu of `question`.
    pub(crate) fn width_of(&self, question: &Question) -> u16 {
        self.widths.get(&question.id).copied().unwrap_or(0)
    }

    /// The number of open questions that an answer with `decision`, the
    /// selected target and the selected scope resolves, also the selected
    /// one. The rule is the one of pentd (`queue::Resolving`).
    pub(crate) fn covered(&self, decision: Decision) -> usize {
        let Some(question) = self.selected() else {
            return 0;
        };
        let Some(target) = question.ask.menu.get(usize::from(self.width_of(question))) else {
            return 0;
        };
        let answer = Resolving::new(
            &question.ask.key,
            question.ask.session,
            target,
            decision,
            self.scope,
        );
        self.questions
            .iter()
            .filter(|q| q.id == question.id || answer.resolves(&q.ask))
            .count()
    }

    /// The session `id`, when the monitor knows it.
    pub(crate) fn session(&self, id: SessionId) -> Option<&SessionInfo> {
        self.sessions.iter().find(|s| s.id == id)
    }

    /// The events that the filters keep, from the oldest to the newest.
    pub(crate) fn events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|e| self.session_filter.is_none_or(|s| e.session == s))
            .filter(|e| match self.kind_filter {
                KindFilter::All => true,
                KindFilter::Refusals => e.decided_by.is_refusal(),
            })
            .collect()
    }

    /// The events that pentd dropped for this monitor.
    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The session filter of the events tab.
    pub(crate) const fn session_filter(&self) -> Option<SessionId> {
        self.session_filter
    }

    /// The kind filter of the events tab.
    pub(crate) const fn kind_filter(&self) -> KindFilter {
        self.kind_filter
    }

    /// The rules of each key, and the selected key.
    pub(crate) fn rules(&self) -> (&[KeyRules], usize) {
        (&self.rules, self.rules_selected)
    }

    // ── What changes the model ──────────────────────────────────────────

    /// Take a message of pentd.
    pub(crate) fn apply(&mut self, message: Message) -> Vec<Action> {
        match message {
            Message::Question(question) => {
                let id = question.id;
                match self.questions.iter_mut().find(|q| q.id == id) {
                    Some(old) => *old = question,
                    None => self.questions.push(question),
                }
                if self.selected.is_none() {
                    self.selected = Some(id);
                }
            }
            Message::Verdict(verdict) => {
                self.remove(verdict.id);
                self.status = Some(crate::commands::answer::verdict_text(&verdict));
                if verdict.scope == Scope::Remember && self.tab == Tab::Rules {
                    return vec![Action::LoadRules];
                }
            }
            Message::Rejected(rejected) => {
                // A question that pentd does not know any more leaves the
                // screen.
                if let (Some(id), RejectReason::UnknownQuestion) = (rejected.id, rejected.reason) {
                    self.remove(id);
                }
                let id = rejected.id.map(|id| format!("{id}: ")).unwrap_or_default();
                self.status = Some(format!("{id}{}", rejected.reason));
            }
            Message::Gone(id) => {
                self.remove(id);
                self.status = Some(format!("{id}: pentd dropped the question of an ended run"));
            }
            Message::Session(info) => match self.sessions.iter_mut().find(|s| s.id == info.id) {
                Some(old) => *old = info,
                None => self.sessions.push(info),
            },
            Message::Event(event) => {
                if self.events.len() >= MAX_EVENTS {
                    self.events.pop_front();
                }
                self.events.push_back(event);
            }
            Message::EventsDropped(dropped) => {
                self.dropped = self.dropped.saturating_add(dropped.count);
            }
            _ => {}
        }
        Vec::new()
    }

    /// Take the rule files that the loop read.
    pub(crate) fn set_rules(&mut self, rules: Vec<KeyRules>) {
        self.rules = rules;
        self.rules_selected = self.rules_selected.min(self.rules.len().saturating_sub(1));
    }

    /// Take a key of the user.
    pub(crate) fn key(&mut self, key: Key) -> Vec<Action> {
        match key {
            Key::Char('q') | Key::Esc => return vec![Action::Quit],
            Key::Tab | Key::BackTab => {
                self.tab = self.tab.next(key == Key::BackTab);
                if self.tab == Tab::Rules {
                    return vec![Action::LoadRules];
                }
                return Vec::new();
            }
            _ => {}
        }
        match self.tab {
            Tab::Questions => self.question_key(key),
            Tab::Events => {
                self.event_key(key);
                Vec::new()
            }
            Tab::Rules => {
                self.rules_key(key);
                Vec::new()
            }
        }
    }

    /// A key on the questions tab.
    fn question_key(&mut self, key: Key) -> Vec<Action> {
        match key {
            Key::Up | Key::Char('k') => self.move_selection(false),
            Key::Down | Key::Char('j') => self.move_selection(true),
            Key::Left | Key::Char('h') => self.move_width(false),
            Key::Right | Key::Char('l' | 'w') => self.move_width(true),
            Key::Char(c @ '0'..='9') => {
                if let (Some(digit), Some(question)) = (c.to_digit(10), self.selected()) {
                    let len = question.ask.menu.len();
                    let id = question.id;
                    if usize::try_from(digit).is_ok_and(|d| d < len) {
                        self.widths
                            .insert(id, u16::try_from(digit).unwrap_or_default());
                    }
                }
            }
            Key::Char('s') => {
                self.scope = match self.scope {
                    Scope::Run => Scope::Remember,
                    Scope::Remember => Scope::Run,
                };
            }
            Key::Enter | Key::Char('i') => self.details = !self.details,
            Key::Char('a') => return self.answer(Decision::Allow),
            Key::Char('d') => return self.answer(Decision::Deny),
            _ => {}
        }
        Vec::new()
    }

    /// The answer to the selected question.
    fn answer(&mut self, decision: Decision) -> Vec<Action> {
        let Some(question) = self.selected() else {
            return Vec::new();
        };
        let answer = Answer {
            id: question.id,
            decision,
            width: MenuIndex(self.width_of(question)),
            scope: self.scope,
            source: Source::Human,
        };
        self.status = Some(format!("{}: {} sent", answer.id, decision.name()));
        vec![Action::Send(Message::Answer(answer))]
    }

    /// Select the next question, or the previous one.
    fn move_selection(&mut self, down: bool) {
        let ids: Vec<QuestionId> = self.ordered().iter().map(|q| q.id).collect();
        let Some(current) = self
            .selected
            .and_then(|id| ids.iter().position(|i| *i == id))
        else {
            self.selected = ids.first().copied();
            return;
        };
        let next = if down {
            current.saturating_add(1).min(ids.len().saturating_sub(1))
        } else {
            current.saturating_sub(1)
        };
        self.selected = ids.get(next).copied();
    }

    /// Select a wider place in the menu, or a narrower one.
    fn move_width(&mut self, wider: bool) {
        let Some(question) = self.selected() else {
            return;
        };
        let last = u16::try_from(question.ask.menu.len().saturating_sub(1)).unwrap_or(0);
        let id = question.id;
        let now = self.width_of(question);
        let next = if wider {
            now.saturating_add(1).min(last)
        } else {
            now.saturating_sub(1)
        };
        self.widths.insert(id, next);
    }

    /// Remove the question `id`. When it was the selected one, the next
    /// question on the screen takes its place, or else the one before.
    fn remove(&mut self, id: QuestionId) {
        let ordered: Vec<QuestionId> = self.ordered().iter().map(|q| q.id).collect();
        self.questions.retain(|q| q.id != id);
        self.widths.remove(&id);
        if self.selected != Some(id) {
            return;
        }
        let place = ordered.iter().position(|i| *i == id).unwrap_or(0);
        self.selected = ordered
            .get(place.saturating_add(1))
            .or_else(|| place.checked_sub(1).and_then(|p| ordered.get(p)))
            .copied();
    }

    /// A key on the events tab: `f` steps through the sessions, `r` shows
    /// only the refusals or each event.
    fn event_key(&mut self, key: Key) {
        match key {
            Key::Char('f') => {
                let ids: Vec<SessionId> = self.sessions.iter().map(|s| s.id).collect();
                self.session_filter = match self.session_filter {
                    None => ids.first().copied(),
                    Some(now) => ids
                        .iter()
                        .position(|i| *i == now)
                        .and_then(|p| ids.get(p.saturating_add(1)))
                        .copied(),
                };
            }
            Key::Char('r') => {
                self.kind_filter = match self.kind_filter {
                    KindFilter::All => KindFilter::Refusals,
                    KindFilter::Refusals => KindFilter::All,
                };
            }
            _ => {}
        }
    }

    /// A key on the rules tab: select another key.
    fn rules_key(&mut self, key: Key) {
        match key {
            Key::Up | Key::Char('k') => self.rules_selected = self.rules_selected.saturating_sub(1),
            Key::Down | Key::Char('j') => {
                self.rules_selected = self
                    .rules_selected
                    .saturating_add(1)
                    .min(self.rules.len().saturating_sub(1));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // a test fails on a value that it must not get
pub(crate) mod tests {
    use std::num::NonZeroU16;

    use pent_profile::{
        Ask, Class, Deadline, DecidedBy, EventsDropped, FileKind, PathWidth, RejectReason,
        Rejected, Request, RulePath, Sensitive, Target, Timestamp, Verdict, FILE_DEADLINE,
    };

    use super::*;

    pub(crate) fn path(p: &str) -> RulePath {
        RulePath::new(p).unwrap()
    }

    /// A read question of `key` for `file` below `dir`, with the exact
    /// target and the subtree of `dir` in its menu.
    pub(crate) fn read(id: u64, key: &str, file: &str, dir: &str) -> Question {
        Question {
            id: QuestionId(id),
            ask: Ask {
                session: SessionId(1),
                key: key.parse().unwrap(),
                program: "/usr/bin/cargo".into(),
                request: Request::File {
                    kind: FileKind::Read,
                    path: path(file),
                },
                class: Class::Normal,
                menu: vec![
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Exact(path(file)),
                    },
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Subtree(path(dir)),
                    },
                ],
                asked: Timestamp(1_795_348_800_000),
                deadline: Deadline::new(FILE_DEADLINE).unwrap(),
            },
        }
    }

    fn sent(actions: &[Action]) -> &Answer {
        match actions {
            [Action::Send(Message::Answer(a))] => a,
            other => panic!("no answer: {other:?}"),
        }
    }

    fn verdict(id: u64, scope: Scope) -> Message {
        Message::Verdict(Verdict {
            id: QuestionId(id),
            decision: Decision::Allow,
            target: Target::Localhost(NonZeroU16::MIN),
            scope,
            source: Source::Human,
        })
    }

    fn model_with(questions: Vec<Question>) -> Model {
        let mut m = Model::default();
        for q in questions {
            m.apply(Message::Question(q));
        }
        m
    }

    #[test]
    fn the_questions_are_grouped_by_key_in_the_order_of_the_asks() {
        let m = model_with(vec![
            read(1, "claude", "/h/a/1", "/h/a"),
            read(2, "psql", "/h/b/2", "/h/b"),
            read(3, "claude", "/h/a/3", "/h/a"),
        ]);
        let groups: Vec<(String, Vec<u64>)> = m
            .groups()
            .iter()
            .map(|(k, l)| (k.to_string(), l.iter().map(|q| q.id.0).collect()))
            .collect();
        assert_eq!(
            groups,
            [
                ("claude".to_string(), vec![1, 3]),
                ("psql".to_string(), vec![2])
            ]
        );
        // The first question is selected, and the keys follow the screen.
        assert_eq!(m.selected().map(|q| q.id.0), Some(1));
        let mut m = m;
        m.key(Key::Down);
        assert_eq!(m.selected().map(|q| q.id.0), Some(3));
        m.key(Key::Down);
        assert_eq!(m.selected().map(|q| q.id.0), Some(2));
        m.key(Key::Down);
        assert_eq!(m.selected().map(|q| q.id.0), Some(2), "the end stays");
        m.key(Key::Up);
        assert_eq!(m.selected().map(|q| q.id.0), Some(3));
    }

    #[test]
    fn an_answer_names_the_selected_width_and_scope() {
        let mut m = model_with(vec![read(1, "cargo", "/h/r/a", "/h/r")]);
        assert_eq!(sent(&m.key(Key::Char('a'))).width, MenuIndex(0));
        m.key(Key::Right);
        m.key(Key::Right);
        assert_eq!(
            m.width_of(m.selected().unwrap()),
            1,
            "the menu has two places"
        );
        m.key(Key::Char('s'));
        let answer = sent(&m.key(Key::Char('d'))).clone();
        assert_eq!(answer.width, MenuIndex(1));
        assert_eq!(answer.scope, Scope::Remember);
        assert_eq!(answer.decision, Decision::Deny);
        assert_eq!(answer.source, Source::Human);
        // A digit picks a place, and a digit out of the menu changes
        // nothing.
        m.key(Key::Char('0'));
        assert_eq!(m.width_of(m.selected().unwrap()), 0);
        m.key(Key::Char('7'));
        assert_eq!(m.width_of(m.selected().unwrap()), 0);
        // No question, no answer.
        let mut empty = Model::default();
        assert!(empty.key(Key::Char('a')).is_empty());
    }

    #[test]
    fn a_sensitive_question_keeps_its_exact_target() {
        let mut q = read(1, "claude", "/h/.ssh/id", "/h/.ssh");
        q.ask.class = Class::Sensitive(Sensitive::Credential);
        q.ask.menu.truncate(1);
        let mut m = model_with(vec![q]);
        m.key(Key::Right);
        m.key(Key::Char('1'));
        assert_eq!(sent(&m.key(Key::Char('a'))).width, MenuIndex(0));
    }

    #[test]
    fn a_verdict_removes_its_question_and_selects_the_next_one() {
        let mut m = model_with(vec![
            read(1, "cargo", "/h/r/a", "/h/r"),
            read(2, "cargo", "/h/r/b", "/h/r"),
            read(3, "cargo", "/h/r/c", "/h/r"),
        ]);
        m.key(Key::Down);
        m.apply(verdict(2, Scope::Run));
        assert_eq!(m.selected().map(|q| q.id.0), Some(3));
        assert_eq!(m.open(), 2);
        assert!(m
            .status()
            .is_some_and(|s| s.contains("allow localhost 1 (this run)")));
        m.apply(verdict(3, Scope::Run));
        assert_eq!(m.selected().map(|q| q.id.0), Some(1), "the one before");
        m.apply(verdict(1, Scope::Run));
        assert!(m.selected().is_none());
    }

    #[test]
    fn a_gone_or_unknown_question_leaves_the_screen() {
        let mut m = model_with(vec![
            read(1, "cargo", "/h/r/a", "/h/r"),
            read(2, "cargo", "/h/r/b", "/h/r"),
        ]);
        m.apply(Message::Gone(QuestionId(1)));
        assert_eq!(m.open(), 1);
        assert_eq!(m.selected().map(|q| q.id.0), Some(2));
        m.apply(Message::Rejected(Rejected {
            id: Some(QuestionId(2)),
            reason: RejectReason::UnknownQuestion,
        }));
        assert_eq!(m.open(), 0);
        // Another refusal keeps the question.
        let mut m = model_with(vec![read(3, "cargo", "/h/r/c", "/h/r")]);
        m.apply(Message::Rejected(Rejected {
            id: Some(QuestionId(3)),
            reason: RejectReason::BadWidth,
        }));
        assert_eq!(m.open(), 1);
    }

    #[test]
    fn the_cover_count_follows_the_width() {
        let mut m = model_with(vec![
            read(1, "cargo", "/h/r/a", "/h/r"),
            read(2, "cargo", "/h/r/b", "/h/r"),
            read(3, "node", "/h/r/c", "/h/r"),
        ]);
        assert_eq!(m.covered(Decision::Allow), 1);
        m.key(Key::Right);
        // The subtree covers the two questions of `cargo`, not the one of
        // `node`.
        assert_eq!(m.covered(Decision::Allow), 2);

        // With the scope `run`, a question of another run of `cargo` does
        // not count; with `remember`, it does.
        let mut other = read(4, "cargo", "/h/r/d", "/h/r");
        other.ask.session = SessionId(9);
        m.apply(Message::Question(other));
        assert_eq!(m.covered(Decision::Allow), 2);
        m.key(Key::Char('s'));
        assert_eq!(m.covered(Decision::Allow), 3);

        // A deny of a read also resolves a write question; an allow does
        // not.
        let mut write = read(5, "cargo", "/h/r/e", "/h/r");
        write.ask.request = Request::File {
            kind: FileKind::Write,
            path: path("/h/r/e"),
        };
        m.apply(Message::Question(write));
        assert_eq!(m.covered(Decision::Allow), 3);
        assert_eq!(m.covered(Decision::Deny), 4);
    }

    #[test]
    fn a_refusal_of_pentd_shows_in_the_status() {
        let mut m = Model::default();
        m.apply(Message::Rejected(Rejected {
            id: Some(QuestionId(0)),
            reason: RejectReason::BadWidth,
        }));
        assert_eq!(
            m.status(),
            Some("222222: the width is not in the menu of the question, or it does not fit")
        );
    }

    fn event(session: u64, time: i64, decided_by: DecidedBy) -> Message {
        Message::Event(Event {
            session: SessionId(session),
            time: Timestamp(time),
            program: "node".into(),
            request: Request::Localhost(NonZeroU16::MIN),
            decided_by,
        })
    }

    fn info(id: u64, key: &str) -> Message {
        Message::Session(SessionInfo {
            id: SessionId(id),
            key: key.parse().unwrap(),
            command: vec![key.to_string()],
            live: true,
        })
    }

    #[test]
    fn the_events_have_a_limit_filters_and_a_drop_count() {
        let mut m = Model::default();
        m.apply(info(1, "cargo"));
        m.apply(info(2, "node"));
        m.apply(event(1, 1, DecidedBy::Rule(Decision::Allow)));
        m.apply(event(2, 2, DecidedBy::Rule(Decision::Deny)));
        m.apply(event(1, 3, DecidedBy::Hidden));
        m.apply(Message::EventsDropped(EventsDropped { count: 4 }));
        m.apply(Message::EventsDropped(EventsDropped { count: 1 }));
        assert_eq!(m.dropped(), 5);
        m.key(Key::Tab);
        assert_eq!(m.tab(), Tab::Events);
        let times = |m: &Model| m.events().iter().map(|e| e.time.0).collect::<Vec<_>>();
        assert_eq!(times(&m), [1, 2, 3]);
        m.key(Key::Char('f'));
        assert_eq!(m.session_filter(), Some(SessionId(1)));
        assert_eq!(times(&m), [1, 3]);
        m.key(Key::Char('r'));
        assert_eq!(times(&m), [3]);
        m.key(Key::Char('f'));
        assert_eq!(times(&m), [2], "the refusal of session 2");
        m.key(Key::Char('f'));
        assert_eq!(m.session_filter(), None);
        assert_eq!(times(&m), [2, 3]);

        let mut m = Model::default();
        for t in 0..i64::try_from(MAX_EVENTS).unwrap() + 3 {
            m.apply(event(1, t, DecidedBy::Hidden));
        }
        assert_eq!(m.events().len(), MAX_EVENTS);
        assert_eq!(m.events().first().map(|e| e.time.0), Some(3));
    }

    #[test]
    fn the_rules_tab_loads_the_rules_when_it_opens_and_after_a_kept_answer() {
        let mut m = Model::default();
        assert!(m.key(Key::Tab).is_empty());
        assert_eq!(m.key(Key::Tab), [Action::LoadRules]);
        assert_eq!(m.tab(), Tab::Rules);
        assert_eq!(m.apply(verdict(1, Scope::Remember)), [Action::LoadRules]);
        assert!(m.apply(verdict(2, Scope::Run)).is_empty());
        m.set_rules(vec![
            KeyRules {
                key: "a".parse().unwrap(),
                rules: Ok(vec![]),
            },
            KeyRules {
                key: "b".parse().unwrap(),
                rules: Err("bad".into()),
            },
        ]);
        m.key(Key::Down);
        m.key(Key::Down);
        assert_eq!(m.rules().1, 1);
        // Fewer keys after a load keep the selection in the list.
        m.set_rules(vec![]);
        assert_eq!(m.rules().1, 0);
        assert_eq!(m.key(Key::BackTab), []);
        assert_eq!(m.tab(), Tab::Events);
        assert_eq!(m.key(Key::Char('q')), [Action::Quit]);
    }
}
