//! The refusals of each session, for `pent denials`. The module has no I/O,
//! so the tests cover each limit without a socket.
//!
//! pentd keeps them in memory only, with three limits:
//!
//! - at most [`MAX_PER_SESSION`] refusals for each session; a new refusal
//!   pushes out the oldest one;
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

use pent_profile::{Denial, Event, Message, RuleKey, SessionId};

/// The most refusals that pentd keeps for one session.
pub(crate) const MAX_PER_SESSION: usize = 128;

/// How long the refusals of an ended session stay.
pub(crate) const ENDED_TTL: Duration = Duration::from_secs(5 * 60);

/// The most ended sessions that pentd keeps.
pub(crate) const MAX_ENDED: usize = 64;

/// The refusals of one session.
#[derive(Debug)]
struct Log {
    key: RuleKey,
    events: VecDeque<Event>,
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
    /// Start the list of the session `session` with the key `key`.
    pub(crate) fn start(&mut self, session: SessionId, key: RuleKey) {
        self.logs.retain(|(id, _)| *id != session);
        self.logs.push((
            session,
            Log {
                key,
                events: VecDeque::new(),
                ended: None,
            },
        ));
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

    /// Keep `event` of the session `session` when it is a refusal. pentd
    /// gives the number of the session, so the number in `event` does not
    /// count.
    pub(crate) fn record(&mut self, session: SessionId, mut event: Event) {
        if !event.decided_by.is_refusal() {
            return;
        }
        let Some(log) = self.log_mut(session) else {
            return;
        };
        event.session = session;
        // A refusal that cannot go on one line with its key could never
        // reach a client, so pentd does not keep it.
        let denial = Message::Denial(Denial {
            key: log.key.clone(),
            event,
        });
        if denial.encode_line().is_err() {
            return;
        }
        let Message::Denial(Denial { event, .. }) = denial else {
            return;
        };
        if log.events.len() >= MAX_PER_SESSION {
            log.events.pop_front();
        }
        log.events.push_back(event);
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
        d.start(SessionId(1), key("cargo"));
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
        d.start(SessionId(1), key("cargo"));
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
        d.start(SessionId(1), key("cargo"));
        d.start(SessionId(2), key("node"));
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
        d.start(SessionId(1000), key("live"));
        for id in 0..total {
            d.start(SessionId(id), key("cargo"));
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
        d.start(SessionId(2), key("node"));
        d.start(SessionId(1), key("cargo"));
        d.record(SessionId(1), event(10, DecidedBy::Hidden));
        d.record(SessionId(2), event(20, DecidedBy::Hidden));
        d.record(SessionId(1), event(11, DecidedBy::Hidden));
        assert_eq!(times(&d.list(None).unwrap()), [20, 10, 11]);
    }
}
