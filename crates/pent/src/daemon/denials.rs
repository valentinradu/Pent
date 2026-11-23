//! The log of each session: its command, its refusals for `pent denials`,
//! and its last events for `pent monitor`. The module has no I/O, so the
//! tests cover each limit without a socket.
//!
//! pentd keeps the logs in memory only, with these limits:
//!
//! - at most [`MAX_PER_SESSION`] refusals for each session; a new refusal
//!   pushes out the oldest one;
//! - at most [`MAX_RECENT`] events of each kind for each session; a new
//!   event pushes out the oldest one. The refusals have their own list, so
//!   a flood of allowed accesses cannot push them out;
//! - the refusals of an ended session stay for [`ENDED_TTL`], so a client
//!   can read them just after the run;
//! - at most [`MAX_ENDED`] ended sessions; a new end pushes out the oldest
//!   ended session.
//!
//! pentd takes only the events of a session, and it puts the number of
//! that session in each event, so a session cannot put an event in the
//! list of another session.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use pent_profile::{Denial, Event, Message, RuleKey, SessionId, SessionInfo};

/// The most refusals that pentd keeps for one session.
pub(crate) const MAX_PER_SESSION: usize = 128;

/// How long the refusals of an ended session stay.
pub(crate) const ENDED_TTL: Duration = Duration::from_secs(5 * 60);

/// The most ended sessions that pentd keeps.
pub(crate) const MAX_ENDED: usize = 64;

/// The most recent events that pentd keeps for one session.
pub(crate) const MAX_RECENT: usize = 256;

/// The log of one session.
#[derive(Debug)]
struct Log {
    key: RuleKey,
    /// The command line of the run. It is untrusted text.
    command: Vec<String>,
    /// The refusals.
    events: VecDeque<Event>,
    /// The last events of each kind.
    recent: VecDeque<Event>,
    /// When the session ended, or `None` while it runs.
    ended: Option<Instant>,
}

/// The refusals of each session that pentd knows, in the order of the
/// starts. The list is short (the live sessions and at most [`MAX_ENDED`]
/// ended ones), so a search is a scan.
#[derive(Debug, Default)]
pub(crate) struct Denials {
    logs: Vec<(SessionId, Log)>,
}

impl Denials {
    /// Start the log of the session `session` with the key `key` and the
    /// command line `command`.
    pub(crate) fn start(&mut self, session: SessionId, key: RuleKey, command: Vec<String>) {
        self.logs.retain(|(id, _)| *id != session);
        self.logs.push((
            session,
            Log {
                key,
                command,
                events: VecDeque::new(),
                recent: VecDeque::new(),
                ended: None,
            },
        ));
    }

    /// The session `session`, as pentd tells it to a watcher.
    pub(crate) fn info(&self, session: SessionId) -> Option<SessionInfo> {
        self.log(session).map(|log| info(session, log))
    }

    /// Each session that pentd knows, in the order of the starts.
    pub(crate) fn sessions(&self) -> Vec<SessionInfo> {
        self.logs.iter().map(|(id, log)| info(*id, log)).collect()
    }

    /// The recent events of each session, in the order of the starts and
    /// then of the events.
    pub(crate) fn recent(&self) -> Vec<Event> {
        self.logs
            .iter()
            .flat_map(|(_, log)| log.recent.iter().cloned())
            .collect()
    }

    /// Return true if pentd knows the session `session`.
    pub(crate) fn knows(&self, session: SessionId) -> bool {
        self.log(session).is_some()
    }

    /// The list of `session`.
    fn log(&self, session: SessionId) -> Option<&Log> {
        self.logs
            .iter()
            .find(|(id, _)| *id == session)
            .map(|(_, log)| log)
    }

    /// The list of `session`, to change it.
    fn log_mut(&mut self, session: SessionId) -> Option<&mut Log> {
        self.logs
            .iter_mut()
            .find(|(id, _)| *id == session)
            .map(|(_, log)| log)
    }

    /// Keep `event` of the session `session` in its recent events, and in
    /// its refusals when it is a refusal. pentd gives the code of the
    /// session, so the code in `event` does not count. Returns the event
    /// with that code, for the watchers, or `None` when pentd does not keep
    /// it.
    pub(crate) fn record(&mut self, session: SessionId, mut event: Event) -> Option<Event> {
        let log = self.log_mut(session)?;
        event.session = session;
        // An event that cannot go on one line with its key could never
        // reach a client, so pentd does not keep it.
        let denial = Message::Denial(Denial {
            key: log.key.clone(),
            event,
        });
        if denial.encode_line().is_err() {
            return None;
        }
        let Message::Denial(Denial { event, .. }) = denial else {
            return None;
        };
        push_bounded(&mut log.recent, event.clone(), MAX_RECENT);
        if event.decided_by.is_refusal() {
            push_bounded(&mut log.events, event.clone(), MAX_PER_SESSION);
        }
        Some(event)
    }

    /// The session `session` ended at `now`. When more than [`MAX_ENDED`]
    /// sessions ended, the oldest end goes.
    pub(crate) fn end(&mut self, session: SessionId, now: Instant) {
        if let Some(log) = self.log_mut(session) {
            log.ended = Some(now);
        }
        let mut ended: Vec<(Instant, SessionId)> = self
            .logs
            .iter()
            .filter_map(|(id, log)| log.ended.map(|at| (at, *id)))
            .collect();
        if ended.len() <= MAX_ENDED {
            return;
        }
        ended.sort();
        let extra = ended.len().saturating_sub(MAX_ENDED);
        for (_, gone) in ended.into_iter().take(extra) {
            self.logs.retain(|(id, _)| *id != gone);
        }
    }

    /// Drop each ended session older than [`ENDED_TTL`] at `now`.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.logs.retain(|(_, log)| {
            log.ended
                .is_none_or(|at| now.saturating_duration_since(at) < ENDED_TTL)
        });
    }

    /// The refusals of `session`, or of each session for `None`, in the
    /// order of the starts of the sessions and then of the events. Returns `None` when
    /// pentd does not know the session.
    pub(crate) fn list(&self, session: Option<SessionId>) -> Option<Vec<Denial>> {
        let denials = |log: &Log| {
            log.events
                .iter()
                .map(|event| Denial {
                    key: log.key.clone(),
                    event: event.clone(),
                })
                .collect::<Vec<_>>()
        };
        match session {
            Some(id) => self.log(id).map(denials),
            None => Some(self.logs.iter().flat_map(|(_, log)| denials(log)).collect()),
        }
    }
}

/// Push `event` at the end of `list`, and drop the oldest event above
/// `limit`.
fn push_bounded(list: &mut VecDeque<Event>, event: Event, limit: usize) {
    if list.len() >= limit {
        list.pop_front();
    }
    list.push_back(event);
}

/// The [`SessionInfo`] of `log`.
fn info(id: SessionId, log: &Log) -> SessionInfo {
    SessionInfo {
        id,
        key: log.key.clone(),
        command: log.command.clone(),
        live: log.ended.is_none(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use pent_profile::{DecidedBy, Decision, Request, Timestamp};

    use super::*;

    fn key(name: &str) -> RuleKey {
        name.parse().unwrap()
    }

    fn event(time: i64, decided_by: DecidedBy) -> Event {
        Event {
            // A false number: pentd puts the number of the session.
            session: SessionId(999),
            time: Timestamp(time),
            program: "node".into(),
            request: Request::Domain("x.org".parse().unwrap()),
            decided_by,
        }
    }

    fn times(denials: &[Denial]) -> Vec<i64> {
        denials.iter().map(|d| d.event.time.0).collect()
    }

    #[test]
    fn only_a_refusal_is_kept_with_the_number_of_its_session() {
        let mut d = Denials::default();
        d.start(SessionId(1), key("cargo"), vec![]);
        d.record(SessionId(1), event(1, DecidedBy::Rule(Decision::Allow)));
        d.record(SessionId(1), event(2, DecidedBy::Rule(Decision::Deny)));
        d.record(SessionId(1), event(3, DecidedBy::Hidden));
        let list = d.list(Some(SessionId(1))).unwrap();
        assert_eq!(times(&list), [2, 3]);
        assert!(list.iter().all(|x| x.event.session == SessionId(1)));
        assert!(list.iter().all(|x| x.key == key("cargo")));
    }

    #[test]
    fn an_unknown_session_gives_none_and_keeps_nothing() {
        let mut d = Denials::default();
        d.record(SessionId(4), event(1, DecidedBy::Hidden));
        assert!(d.list(Some(SessionId(4))).is_none());
        assert_eq!(d.list(None).map(|l| l.len()), Some(0));
    }

    #[test]
    fn a_session_keeps_its_newest_refusals() {
        let mut d = Denials::default();
        d.start(SessionId(1), key("cargo"), vec![]);
        let total = i64::try_from(MAX_PER_SESSION).unwrap() + 5;
        for t in 0..total {
            d.record(SessionId(1), event(t, DecidedBy::Hidden));
        }
        let list = d.list(Some(SessionId(1))).unwrap();
        assert_eq!(list.len(), MAX_PER_SESSION);
        assert_eq!(list.first().map(|x| x.event.time.0), Some(5));
        assert_eq!(list.last().map(|x| x.event.time.0), Some(total - 1));
    }

    #[test]
    fn an_ended_session_stays_for_its_time() {
        let mut d = Denials::default();
        let start = Instant::now();
        d.start(SessionId(1), key("cargo"), vec![]);
        d.start(SessionId(2), key("node"), vec![]);
        d.record(SessionId(1), event(1, DecidedBy::Hidden));
        d.end(SessionId(1), start);
        d.expire(start + ENDED_TTL - Duration::from_secs(1));
        assert!(d.list(Some(SessionId(1))).is_some());
        d.expire(start + ENDED_TTL);
        assert!(d.list(Some(SessionId(1))).is_none());
        // A live session never expires.
        assert!(d.list(Some(SessionId(2))).is_some());
    }

    #[test]
    fn the_oldest_ended_session_goes_above_the_limit() {
        let mut d = Denials::default();
        let start = Instant::now();
        let total = u64::try_from(MAX_ENDED).unwrap() + 2;
        d.start(SessionId(1000), key("live"), vec![]);
        for id in 0..total {
            d.start(SessionId(id), key("cargo"), vec![]);
            d.end(SessionId(id), start + Duration::from_secs(id));
        }
        assert!(d.list(Some(SessionId(0))).is_none());
        assert!(d.list(Some(SessionId(1))).is_none());
        assert!(d.list(Some(SessionId(2))).is_some());
        assert!(d.list(Some(SessionId(total - 1))).is_some());
        assert!(d.list(Some(SessionId(1000))).is_some());
    }

    #[test]
    fn the_list_of_each_session_follows_the_starts_not_the_codes() {
        let mut d = Denials::default();
        d.start(SessionId(2), key("node"), vec![]);
        d.start(SessionId(1), key("cargo"), vec![]);
        d.record(SessionId(1), event(10, DecidedBy::Hidden));
        d.record(SessionId(2), event(20, DecidedBy::Hidden));
        d.record(SessionId(1), event(11, DecidedBy::Hidden));
        assert_eq!(times(&d.list(None).unwrap()), [20, 10, 11]);
    }

    #[test]
    fn the_recent_events_keep_each_kind_and_the_refusals_survive_a_flood() {
        let mut d = Denials::default();
        d.start(
            SessionId(1),
            key("cargo"),
            vec!["cargo".into(), "build".into()],
        );
        d.record(SessionId(1), event(1, DecidedBy::Rule(Decision::Deny)));
        let total = i64::try_from(MAX_RECENT).unwrap() + 10;
        for t in 2..total {
            let kept = d.record(SessionId(1), event(t, DecidedBy::Rule(Decision::Allow)));
            assert_eq!(kept.map(|e| e.session), Some(SessionId(1)));
        }
        let recent = d.recent();
        assert_eq!(recent.len(), MAX_RECENT);
        assert_eq!(recent.last().map(|e| e.time.0), Some(total - 1));
        // The flood pushed the refusal out of the recent events, not out
        // of the refusals.
        assert!(recent.iter().all(|e| !e.decided_by.is_refusal()));
        assert_eq!(times(&d.list(Some(SessionId(1))).unwrap()), [1]);
        // An unknown session keeps nothing.
        assert!(d
            .record(SessionId(9), event(1, DecidedBy::Hidden))
            .is_none());
    }

    #[test]
    fn a_session_info_names_its_key_command_and_state() {
        let mut d = Denials::default();
        d.start(SessionId(1), key("cargo"), vec!["cargo".into()]);
        d.start(SessionId(2), key("node"), vec![]);
        d.end(SessionId(1), Instant::now());
        let infos = d.sessions();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].id, SessionId(1));
        assert_eq!(infos[0].command, ["cargo"]);
        assert!(!infos[0].live);
        assert!(infos[1].live);
        assert_eq!(d.info(SessionId(2)).map(|i| i.key), Some(key("node")));
    }
}
