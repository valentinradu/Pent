//! The queue of questions in pentd. The module has no I/O, so the tests
//! cover each rule without a socket.
//!
//! - **One question for a group.** The same access of the same session is
//!   one question. An answer resolves each open question of the same key
//!   that its target covers: with the scope `remember` in each session,
//!   with the scope `run` only in the session of the question.
//! - **A sensitive question** is resolved only by an answer that names its
//!   exact target. A wider answer to another question never resolves it.
//! - **pentd checks each answer:** the question exists, the `MenuIndex` is
//!   in its menu, and the source is the human (the judge runs in pentd).
//! - **The deadline is the work of `pent run`:** the access gets the error
//!   of a refusal there, and the question stays open here. A late answer
//!   with the scope `remember` becomes a rule.
//! - **A question of a session that ended** stays open for [`ORPHAN_TTL`],
//!   so a late answer still becomes a rule. Then the queue drops it.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use pent_profile::{
    Answer, Ask, Class, Decision, Question, QuestionId, RejectReason, Rule, RuleKey, RuleSet,
    Scope, SessionId, Source, Target, Verdict,
};

/// How long a question of a session that ended stays open.
pub(crate) const ORPHAN_TTL: Duration = Duration::from_secs(15 * 60);

/// One open question.
#[derive(Debug, Clone)]
struct Entry {
    question: Question,
    /// When the session of the question ended, or `None` while it runs.
    orphaned: Option<std::time::Instant>,
}

/// The result of an accepted answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolution {
    /// The key of the answered question.
    pub(crate) key: RuleKey,
    /// The rule to write, for the scope `remember`.
    pub(crate) rule: Option<Rule>,
    /// Each resolved question, its session and its verdict.
    pub(crate) verdicts: Vec<(SessionId, Verdict)>,
}

/// The queue.
#[derive(Debug, Default)]
pub(crate) struct Queue {
    next_id: u64,
    open: BTreeMap<QuestionId, Entry>,
}

impl Queue {
    /// Add the question `ask` of `session`, with the key of that session.
    /// pentd gives the session and the key, so the values in `ask` do not
    /// count. Returns the question and `true` when it is new; the same
    /// access of the same session gives the open question again.
    pub(crate) fn ask(
        &mut self,
        session: SessionId,
        key: &RuleKey,
        mut ask: Ask,
    ) -> (Question, bool) {
        ask.session = session;
        ask.key = key.clone();
        if let Some(entry) = self
            .open
            .values()
            .find(|e| e.question.ask.session == session && e.question.ask.request == ask.request)
        {
            return (entry.question.clone(), false);
        }
        let id = QuestionId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let question = Question { id, ask };
        self.open.insert(
            id,
            Entry {
                question: question.clone(),
                orphaned: None,
            },
        );
        (question, true)
    }

    /// Check `answer` and resolve each question that it covers.
    ///
    /// # Errors
    /// Returns the reason when the question is not open, when the
    /// `MenuIndex` is not in its menu, or when the source is not the human.
    pub(crate) fn answer(&mut self, answer: &Answer) -> Result<Resolution, RejectReason> {
        if answer.source != Source::Human {
            return Err(RejectReason::NotHuman);
        }
        let entry = self
            .open
            .get(&answer.id)
            .ok_or(RejectReason::UnknownQuestion)?;
        let ask = &entry.question.ask;
        let target = ask
            .menu
            .get(usize::from(answer.width.0))
            .cloned()
            .ok_or(RejectReason::BadWidth)?;
        let key = ask.key.clone();
        let session = ask.session;
        let scope = answer.scope;

        let covers = covering_set(&key, &target, answer.decision);
        let resolved: Vec<QuestionId> = self
            .open
            .iter()
            .filter(|(id, e)| {
                let q = &e.question.ask;
                if **id == answer.id {
                    return true;
                }
                let same_group = q.key == key && (scope == Scope::Remember || q.session == session);
                let access = q.request.as_access();
                let covered = covers.decide(&access).is_some();
                // A sensitive question needs its own exact answer.
                let allowed =
                    !matches!(q.class, Class::Sensitive(_)) || q.menu.first() == Some(&target);
                same_group && covered && allowed
            })
            .map(|(id, _)| *id)
            .collect();

        let mut verdicts = Vec::with_capacity(resolved.len());
        for id in resolved {
            if let Some(entry) = self.open.remove(&id) {
                verdicts.push((
                    entry.question.ask.session,
                    Verdict {
                        id,
                        decision: answer.decision,
                        target: target.clone(),
                        scope,
                        source: answer.source,
                    },
                ));
            }
        }
        let rule = (scope == Scope::Remember).then(|| Rule {
            target,
            decision: answer.decision,
            source: answer.source,
            created: SystemTime::now(),
        });
        Ok(Resolution {
            key,
            rule,
            verdicts,
        })
    }

    /// Mark the questions of `session` as orphans: the session ended.
    pub(crate) fn end_session(&mut self, session: SessionId, now: std::time::Instant) {
        for entry in self.open.values_mut() {
            if entry.question.ask.session == session && entry.orphaned.is_none() {
                entry.orphaned = Some(now);
            }
        }
    }

    /// Drop each orphan older than [`ORPHAN_TTL`]. Returns how many it
    /// dropped.
    pub(crate) fn expire(&mut self, now: std::time::Instant) -> usize {
        let before = self.open.len();
        self.open.retain(|_, e| {
            e.orphaned
                .is_none_or(|t| now.saturating_duration_since(t) < ORPHAN_TTL)
        });
        before.saturating_sub(self.open.len())
    }

    /// The open questions, in the order of their numbers.
    pub(crate) fn open(&self) -> impl Iterator<Item = &Question> {
        self.open.values().map(|e| &e.question)
    }

    /// The number of open questions.
    pub(crate) fn len(&self) -> usize {
        self.open.len()
    }
}

/// A rule set with one rule, to ask if the answer covers an access with the
/// same decision.
fn covering_set(key: &RuleKey, target: &Target, decision: Decision) -> RuleSet {
    RuleSet {
        key: key.clone(),
        rules: vec![Rule {
            target: target.clone(),
            decision,
            source: Source::Human,
            created: SystemTime::UNIX_EPOCH,
        }],
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // a test fails on a branch that it must not reach
mod tests {
    use std::time::Instant;

    use pent_profile::{
        Deadline, FileKind, MenuIndex, PathWidth, Request, RulePath, Sensitive, Timestamp,
        FILE_DEADLINE,
    };

    use super::*;

    fn key(k: &str) -> RuleKey {
        k.parse().unwrap()
    }

    fn path(p: &str) -> RulePath {
        RulePath::new(p).unwrap()
    }

    /// A read of `p` with the menu: the exact path, then the subtree of
    /// each parent below `/home`.
    fn read(p: &str) -> Ask {
        let rp = path(p);
        let mut menu = vec![Target::File {
            kind: FileKind::Read,
            width: PathWidth::Exact(rp.clone()),
        }];
        for dir in rp.as_path().ancestors().skip(1) {
            if dir.components().count() <= 2 {
                break;
            }
            menu.push(Target::File {
                kind: FileKind::Read,
                width: PathWidth::Subtree(path(dir.to_str().unwrap())),
            });
        }
        Ask {
            // pentd replaces the session and the key.
            session: SessionId(999),
            key: key("ignored"),
            program: "cat".into(),
            request: Request::File {
                kind: FileKind::Read,
                path: rp,
            },
            class: Class::Normal,
            menu,
            asked: Timestamp(0),
            deadline: Deadline::new(FILE_DEADLINE).unwrap(),
        }
    }

    fn answer(id: QuestionId, decision: Decision, width: u16, scope: Scope) -> Answer {
        Answer {
            id,
            decision,
            width: MenuIndex(width),
            scope,
            source: Source::Human,
        }
    }

    const S1: SessionId = SessionId(1);
    const S2: SessionId = SessionId(2);

    #[test]
    fn pentd_gives_the_number_the_session_and_the_key() {
        let mut q = Queue::default();
        let (a, new_a) = q.ask(S1, &key("cargo"), read("/home/u/a"));
        let (b, new_b) = q.ask(S1, &key("cargo"), read("/home/u/b"));
        assert!(new_a && new_b);
        assert_eq!((a.id, b.id), (QuestionId(0), QuestionId(1)));
        assert_eq!(a.ask.session, S1);
        assert_eq!(a.ask.key, key("cargo"));
        // The same access of the same session is the same question.
        let (again, new) = q.ask(S1, &key("cargo"), read("/home/u/a"));
        assert!(!new);
        assert_eq!(again.id, a.id);
        // Another session gets its own question.
        let (other, new) = q.ask(S2, &key("cargo"), read("/home/u/a"));
        assert!(new);
        assert_ne!(other.id, a.id);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn an_answer_is_checked() {
        let mut q = Queue::default();
        let (a, _) = q.ask(S1, &key("cargo"), read("/home/u/x/a"));
        assert_eq!(
            q.answer(&answer(QuestionId(42), Decision::Allow, 0, Scope::Run)),
            Err(RejectReason::UnknownQuestion)
        );
        assert_eq!(
            q.answer(&answer(a.id, Decision::Allow, 9, Scope::Run)),
            Err(RejectReason::BadWidth)
        );
        let mut model = answer(a.id, Decision::Allow, 0, Scope::Run);
        model.source = Source::Model;
        assert_eq!(q.answer(&model), Err(RejectReason::NotHuman));
        // A refused answer leaves the question open.
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn a_wide_answer_resolves_each_question_inside_its_width() {
        let mut q = Queue::default();
        let (a, _) = q.ask(S1, &key("cargo"), read("/home/u/reg/src/a.rs"));
        let (b, _) = q.ask(S1, &key("cargo"), read("/home/u/reg/src/b.rs"));
        let (c, _) = q.ask(S1, &key("cargo"), read("/home/u/other/c"));
        // Width 2: the subtree `/home/u/reg`.
        let res = q
            .answer(&answer(a.id, Decision::Allow, 2, Scope::Run))
            .unwrap();
        let ids: Vec<QuestionId> = res.verdicts.iter().map(|(_, v)| v.id).collect();
        assert_eq!(ids, vec![a.id, b.id]);
        assert!(res.rule.is_none(), "the scope run writes no rule");
        assert_eq!(q.open().map(|x| x.id).collect::<Vec<_>>(), vec![c.id]);
        for (_, v) in &res.verdicts {
            assert_eq!(
                v.target,
                Target::File {
                    kind: FileKind::Read,
                    width: PathWidth::Subtree(path("/home/u/reg")),
                }
            );
        }
    }

    #[test]
    fn the_scope_decides_which_sessions_share_the_answer() {
        let mut q = Queue::default();
        let (a1, _) = q.ask(S1, &key("cargo"), read("/home/u/reg/a"));
        let (a2, _) = q.ask(S2, &key("cargo"), read("/home/u/reg/b"));
        let (other_key, _) = q.ask(S2, &key("npm"), read("/home/u/reg/c"));
        let res = q
            .answer(&answer(a1.id, Decision::Allow, 1, Scope::Run))
            .unwrap();
        assert_eq!(
            res.verdicts.len(),
            1,
            "run: only the session of the question"
        );
        assert_eq!(res.verdicts[0].0, S1);

        let (a1b, _) = q.ask(S1, &key("cargo"), read("/home/u/reg/d"));
        let res = q
            .answer(&answer(a1b.id, Decision::Deny, 1, Scope::Remember))
            .unwrap();
        let mut got: Vec<(SessionId, QuestionId)> =
            res.verdicts.iter().map(|(s, v)| (*s, v.id)).collect();
        got.sort();
        assert_eq!(got, vec![(S1, a1b.id), (S2, a2.id)]);
        assert!(res
            .verdicts
            .iter()
            .all(|(_, v)| v.decision == Decision::Deny));
        let rule = res.rule.unwrap();
        assert_eq!(rule.decision, Decision::Deny);
        assert_eq!(rule.source, Source::Human);
        assert_eq!(res.key, key("cargo"));
        // Another key never shares an answer.
        assert_eq!(
            q.open().map(|x| x.id).collect::<Vec<_>>(),
            vec![other_key.id]
        );
    }

    #[test]
    fn a_wide_answer_does_not_resolve_a_sensitive_question() {
        let mut q = Queue::default();
        let (normal, _) = q.ask(S1, &key("sh"), read("/home/u/.ssh/known_hosts"));
        let mut secret = read("/home/u/.ssh/id_ed25519");
        secret.class = Class::Sensitive(Sensitive::Credential);
        secret.menu.truncate(1);
        let (secret, _) = q.ask(S1, &key("sh"), secret);
        // The subtree `/home/u/.ssh` covers both paths.
        let res = q
            .answer(&answer(normal.id, Decision::Allow, 1, Scope::Remember))
            .unwrap();
        assert_eq!(res.verdicts.len(), 1);
        assert_eq!(q.open().map(|x| x.id).collect::<Vec<_>>(), vec![secret.id]);
        // Its own exact answer resolves it.
        let res = q
            .answer(&answer(secret.id, Decision::Deny, 0, Scope::Remember))
            .unwrap();
        assert_eq!(res.verdicts.len(), 1);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn a_deny_does_not_resolve_a_question_with_another_kind() {
        let mut q = Queue::default();
        let (r, _) = q.ask(S1, &key("sh"), read("/home/u/x/a"));
        let mut write = read("/home/u/x/b");
        write.request = Request::File {
            kind: FileKind::Write,
            path: path("/home/u/x/b"),
        };
        let (w, _) = q.ask(S1, &key("sh"), write);
        // A read rule on the subtree does not cover a write.
        let res = q
            .answer(&answer(r.id, Decision::Allow, 1, Scope::Run))
            .unwrap();
        assert_eq!(res.verdicts.len(), 1);
        assert_eq!(q.open().map(|x| x.id).collect::<Vec<_>>(), vec![w.id]);
    }

    #[test]
    fn a_question_of_an_ended_session_stays_for_a_late_answer_then_goes() {
        let mut q = Queue::default();
        let (a, _) = q.ask(S1, &key("cargo"), read("/home/u/a"));
        let (b, _) = q.ask(S1, &key("cargo"), read("/home/u/b"));
        let (live, _) = q.ask(S2, &key("cargo"), read("/home/u/c"));
        let t0 = Instant::now();
        q.end_session(S1, t0);
        assert_eq!(q.expire(t0 + ORPHAN_TTL - Duration::from_secs(1)), 0);
        // A late answer becomes a rule.
        let res = q
            .answer(&answer(a.id, Decision::Allow, 0, Scope::Remember))
            .unwrap();
        assert!(res.rule.is_some());
        assert_eq!(q.expire(t0 + ORPHAN_TTL), 1, "the other orphan goes");
        assert_eq!(q.open().map(|x| x.id).collect::<Vec<_>>(), vec![live.id]);
        assert!(!q.open().any(|x| x.id == b.id));
    }
}
