//! The chain of deciders of `pent run` (`docs/design/pent.md`, section 7),
//! and the grants that the rules give to the static layers.
//!
//! The order of the chain: the pent class, the flags of `pent run` (the
//! answers in advance), the rules of the key, the answers of this run, and
//! last a question to pentd. The flags come before the rules: the user gave
//! them for this run.
//!
//! Until each hook asks (steps 3.2 to 3.4 of PLAN.md, and phase 5 for the
//! files), the rules go into the static layers at the start: Landlock, the
//! list of the proxy, the list of the Unix sockets and the list of the
//! ports. A static layer cannot make a hole in a grant, so an allow rule
//! with a deny rule inside its width does not go into a static layer
//! (`RuleSet::whole_allows`).

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use pent_profile::{
    Access, Ask, Class, Deadline, DecidedBy, Decision, DomainWidth, Event, FileKind, FsOp, Outcome,
    PathWidth, QuestionId, Request, Rule, RuleKey, RulePath, RuleSet, SessionId, Source, Target,
    Timestamp, WatchEvent,
};
use pent_settings::SandboxPaths;

use crate::daemon::classes::Classes;
use crate::daemon::client::{self, Session};

/// The answers of one run: the rules of the verdicts, and the question of
/// each rule at the same place.
struct Answers {
    rules: RuleSet,
    questions: Vec<QuestionId>,
}

impl Answers {
    /// Keep the verdict `verdict`, one time for each question.
    fn keep(&mut self, verdict: &pent_profile::Verdict) {
        if self.questions.contains(&verdict.id) {
            return;
        }
        self.rules.rules.push(Rule {
            target: verdict.target.clone(),
            decision: verdict.decision,
            source: verdict.source,
            created: SystemTime::now(),
        });
        self.questions.push(verdict.id);
    }
}

/// The chain of deciders of one run.
pub(crate) struct Decider {
    /// The answers in advance: the flags of `pent run`.
    flags: RuleSet,
    /// The rules of the key, as `pent run` read them at the start.
    rules: RuleSet,
    /// The answers of this run, of each scope, with their questions. pentd
    /// writes the rules of the scope "remember"; this list applies them at
    /// once.
    answers: Mutex<Answers>,
    /// The classes of the user, or `None` when the home directory is not
    /// known.
    classes: Option<Classes>,
    /// The hold on pentd, or `None` when the run has no key.
    session: Option<Session>,
    /// The recent decisions of the hooks, oldest first, at most
    /// [`MAX_HOOKED`]. The event of a hook comes later from the static
    /// layer (the proxy), and it takes its cause from here: an answer or a
    /// deadline has a question that the chain alone cannot know again.
    hooked: Mutex<std::collections::VecDeque<Hooked>>,
    /// The refusals of the run, for `agent.sock`. No decision reads them.
    refusals: Mutex<crate::agent::DenialLog>,
}

/// The most hook decisions that wait for their event.
const MAX_HOOKED: usize = 1024;

/// How long a hook decision waits for its event. The event comes at once
/// after the decision; an entry that waits longer has no event (for
/// example a TLS SNI name, whose event names the request), and a later
/// event must not take its cause.
const HOOKED_LIFE: Duration = Duration::from_secs(10);

/// One hook decision that waits for its event.
struct Hooked {
    request: Request,
    decided_by: DecidedBy,
    at: std::time::Instant,
}

impl Decider {
    /// A chain with the flags `flags` and the rules `rules`.
    pub(crate) fn new(
        flags: RuleSet,
        rules: RuleSet,
        classes: Option<Classes>,
        session: Option<Session>,
    ) -> Self {
        let answers = RuleSet::new(rules.key.clone());
        Self {
            flags,
            rules,
            answers: Mutex::new(Answers {
                rules: answers,
                questions: Vec::new(),
            }),
            classes,
            session,
            hooked: Mutex::new(std::collections::VecDeque::new()),
            refusals: Mutex::new(crate::agent::DenialLog::default()),
        }
    }

    /// The refusals of the run for the agent, and the number of refusals
    /// that left the list (see [`crate::agent::DenialLog`]).
    pub(crate) fn agent_denials(&self) -> (Vec<pent_profile::AgentDenial>, u64) {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .list()
    }

    /// Relay a deny of the agent to pentd (see [`Session::agent_deny`]).
    pub(crate) async fn agent_deny(&self, id: QuestionId) -> crate::daemon::client::AgentOutcome {
        match &self.session {
            Some(session) => session.agent_deny(id).await,
            None => Err(pent_profile::AgentFailure::NoPentd),
        }
    }

    /// Relay a skip of the agent to pentd (see [`Session::agent_skip`]).
    pub(crate) async fn agent_skip(
        &self,
        skip: pent_profile::Skip,
    ) -> crate::daemon::client::AgentOutcome {
        match &self.session {
            Some(session) => session.agent_skip(skip).await,
            None => Err(pent_profile::AgentFailure::NoPentd),
        }
    }

    /// The key of the run.
    pub(crate) const fn key(&self) -> &RuleKey {
        &self.rules.key
    }

    /// Wait until the events of the run left for pentd. See
    /// [`Session::flush`].
    pub(crate) async fn flush(&self) {
        if let Some(session) = &self.session {
            session.flush().await;
        }
    }

    /// What decides `request` with no question, or `None` when only a
    /// question can decide it.
    ///
    /// Only an exact rule or an exact answer allows a sensitive access; a
    /// wider one that contains it does not. A deny of any width refuses
    /// it. A flag allows it: the user named the path for this run.
    pub(crate) fn known(&self, request: &Request) -> Option<DecidedBy> {
        let class = self.class(request);
        if class == Some(Class::Pent) {
            return Some(match request {
                Request::File { .. } => DecidedBy::Hidden,
                _ => DecidedBy::Base(Decision::Deny),
            });
        }
        let sensitive = matches!(class, Some(Class::Sensitive(_)));
        let access = request.as_access();
        if let Some(decision) = self.flags.decide(&access) {
            return Some(DecidedBy::Flag(decision));
        }
        if let Some(decision) = decide_in(&self.rules, &access, sensitive) {
            return Some(DecidedBy::Rule(decision));
        }
        let mut answers = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A late verdict (its access stopped the wait at the deadline)
        // applies now, so a later try gets the answer with no new question.
        if let Some(session) = &self.session {
            for verdict in session.take_verdicts() {
                answers.keep(&verdict);
            }
        }
        let decision = decide_in(&answers.rules, &access, sensitive)?;
        // The event names one answer that alone gives the same decision.
        // For a sensitive access, only an exact answer allows, but a deny
        // of any width refuses (see `decide_in`).
        answers
            .rules
            .rules
            .iter()
            .zip(&answers.questions)
            .find(|(rule, _)| {
                (decision == Decision::Deny || !sensitive || is_exact(&rule.target))
                    && answers
                        .rules
                        .decide_where(&access, |r| std::ptr::eq(r, *rule))
                        == Some(decision)
            })
            .map(|(_, question)| DecidedBy::Answer {
                question: *question,
                decision,
            })
    }

    /// Decide `request` of `program` for a hook: with the chain when it
    /// knows the answer, else with a question to pentd that waits at most
    /// `deadline`. The hook sends no event itself: its static layer sends
    /// one, and [`Decider::report_watch`] gives it this cause.
    pub(crate) async fn decide(
        &self,
        program: &str,
        request: Request,
        deadline: Duration,
    ) -> DecidedBy {
        let decided_by = match self.known(&request) {
            Some(known) => known,
            None => self.ask(program, &request, deadline).await,
        };
        let mut hooked = self
            .hooked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if hooked.len() >= MAX_HOOKED {
            hooked.pop_front();
        }
        hooked.push_back(Hooked {
            request,
            decided_by,
            at: std::time::Instant::now(),
        });
        decided_by
    }

    /// Take the oldest hook decision of `request` with the decision
    /// `decision`.
    fn take_hooked(&self, request: &Request, decision: Decision) -> Option<DecidedBy> {
        let mut hooked = self
            .hooked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooked.retain(|h| h.at.elapsed() < HOOKED_LIFE);
        let refusal = decision == Decision::Deny;
        let place = hooked
            .iter()
            .position(|h| h.request == *request && h.decided_by.is_refusal() == refusal)?;
        hooked.remove(place).map(|h| h.decided_by)
    }

    /// Ask pentd, and keep the verdict for the rest of the run.
    async fn ask(&self, program: &str, request: &Request, deadline: Duration) -> DecidedBy {
        let (Some(session), Ok(deadline)) = (&self.session, Deadline::new(deadline)) else {
            return DecidedBy::Base(Decision::Deny);
        };
        // pentd replaces the class and the menu with its own; these are
        // only for a reader of the line.
        let (class, menu) = self.classes.as_ref().map_or_else(
            || {
                (
                    Class::Normal,
                    vec![pent_profile::exact_target(&request.as_access())],
                )
            },
            |classes| classes.decide(request),
        );
        let ask = Ask {
            session: SessionId(0),
            key: self.rules.key.clone(),
            program: program.to_string(),
            request: request.clone(),
            class,
            menu,
            asked: Timestamp::now(),
            deadline,
        };
        match session.ask(ask).await {
            client::Outcome::Answered(verdict) => {
                self.answers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .keep(&verdict);
                DecidedBy::Answer {
                    question: verdict.id,
                    decision: verdict.decision,
                }
            }
            client::Outcome::Deadline(Some(question)) => DecidedBy::Deadline { question },
            // No number and no verdict: no question covers the access.
            client::Outcome::Deadline(None) | client::Outcome::Unavailable => {
                DecidedBy::Base(Decision::Deny)
            }
        }
    }

    /// Send the event of a decision to pentd. pentd puts the number of the
    /// session in it.
    fn report(&self, program: &str, request: Request, decided_by: DecidedBy) {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(program, &request, decided_by);
        let Some(session) = &self.session else {
            return;
        };
        session.send_event(Event {
            session: SessionId(0),
            time: Timestamp::now(),
            program: program.to_string(),
            request,
            decided_by,
        });
    }

    /// Send the event of an access that a static layer decided: the proxy,
    /// the supervisor or Landlock. The cause is the hook decision of the
    /// same request and decision, when one waits, else the chain. An access that the program cannot name as
    /// a request (an IP address, an abstract socket) gives no event.
    pub(crate) fn report_watch(&self, event: &WatchEvent) {
        let Some((program, request, decision)) = request_of(event, self.key()) else {
            tracing::debug!("no event for {event:?}: it is not a request");
            return;
        };
        let decided_by = self
            .take_hooked(&request, decision)
            .unwrap_or_else(|| self.static_cause(&request, decision));
        self.report(&program, request, decided_by);
    }

    /// What made a static layer give `decision` to `request`: the layer of
    /// the chain with the same decision, else the base.
    fn static_cause(&self, request: &Request, decision: Decision) -> DecidedBy {
        match self.known(request) {
            Some(known) if known.is_refusal() == (decision == Decision::Deny) => known,
            _ => DecidedBy::Base(decision),
        }
    }

    /// The plan of a graft of `target` (see
    /// `pent_sandbox::AccessDecider::graft_plan`): `None` for no graft, or
    /// the holes of the graft. A graft needs a subtree of files that is in
    /// the normal class, with no deny rule of a flag, a rule or an answer
    /// inside it and no file of pent inside it. Each existing sensitive
    /// directory inside it becomes a hole; another sensitive location
    /// keeps the width with FUSE (`Classes::graft_holes`). Without the
    /// classes of the user no graft is safe.
    pub(crate) fn graft_plan(&self, target: &Target) -> Option<Vec<PathBuf>> {
        let Target::File { kind, width } = target else {
            return None;
        };
        let PathWidth::Subtree(base) = width else {
            return None;
        };
        let classes = self.classes.as_ref()?;
        let answers = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for set in [&self.flags, &self.rules, &answers.rules] {
            match file_held_back(set, *kind, width, Some(classes), Path::is_dir) {
                None | Some(HeldBack::Sensitive) => {}
                Some(_) => return None,
            }
        }
        drop(answers);
        let mut holes = Vec::new();
        for &given in static_kinds(*kind) {
            let request = Request::File {
                kind: given,
                path: base.clone(),
            };
            if classes.decide(&request).0 != Class::Normal {
                return None;
            }
            holes.extend(classes.graft_holes(base.as_path(), given)?);
        }
        holes.sort();
        holes.dedup();
        Some(holes)
    }

    /// The target of the flag, the rule or the answer that allowed
    /// `request` with the cause `decided`, or `None` for another cause.
    pub(crate) fn target_of(&self, request: &Request, decided: DecidedBy) -> Option<Target> {
        let access = request.as_access();
        let find = |set: &RuleSet| {
            set.rules
                .iter()
                .find(|r| {
                    r.decision == Decision::Allow
                        && set.decide_where(&access, |x| std::ptr::eq(x, *r))
                            == Some(Decision::Allow)
                })
                .map(|r| r.target.clone())
        };
        match decided {
            DecidedBy::Flag(Decision::Allow) => find(&self.flags),
            DecidedBy::Rule(Decision::Allow) => find(&self.rules),
            DecidedBy::Answer {
                question,
                decision: Decision::Allow,
            } => {
                let answers = self
                    .answers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let at = answers.questions.iter().position(|q| *q == question)?;
                answers.rules.rules.get(at).map(|r| r.target.clone())
            }
            _ => None,
        }
    }

    /// Return true if `path` is in the pent class: the FUSE server gives
    /// `ENOENT` for it. The server asks this for each request, with a path
    /// that has no link in it (see `Classes::is_pent_unlinked`).
    pub(crate) fn hidden(&self, path: &Path) -> bool {
        let Ok(path) = RulePath::new(path.to_path_buf()) else {
            return false;
        };
        let request = Request::File {
            kind: FileKind::Read,
            path,
        };
        self.classes
            .as_ref()
            .is_some_and(|c| c.is_pent_unlinked(&request))
    }

    /// The class of `request`, or `None` when the home directory is not
    /// known.
    fn class(&self, request: &Request) -> Option<Class> {
        self.classes.as_ref().map(|c| c.decide(request).0)
    }
}

/// The chain of deciders as the decider of the proxy. The proxy does not
/// know the process of a connection, so a question names the key as the
/// program.
pub(crate) struct ProxyDecider(pub std::sync::Arc<Decider>);

impl std::fmt::Debug for ProxyDecider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ProxyDecider").field(self.0.key()).finish()
    }
}

impl pent_proxy::DomainDecider for ProxyDecider {
    fn known(&self, name: &pent_profile::DomainName) -> Option<pent_proxy::DomainVerdict> {
        self.0
            .known(&Request::Domain(name.clone()))
            .map(|decided_by| match decided_by.decision() {
                Decision::Allow => pent_proxy::DomainVerdict::Allow,
                Decision::Deny => pent_proxy::DomainVerdict::Deny,
            })
    }

    fn decide<'a>(
        &'a self,
        name: &'a pent_profile::DomainName,
        deadline: Duration,
    ) -> pent_proxy::DecisionFuture<'a> {
        Box::pin(async move {
            let key = self.0.key().to_string();
            let decided_by = self
                .0
                .decide(&key, Request::Domain(name.clone()), deadline)
                .await;
            match decided_by {
                DecidedBy::Deadline { .. } => pent_proxy::DomainVerdict::Deadline,
                d => match d.decision() {
                    Decision::Allow => pent_proxy::DomainVerdict::Allow,
                    Decision::Deny => pent_proxy::DomainVerdict::Deny,
                },
            }
        })
    }
}

/// The chain of deciders as the decider of the supervisor (Unix sockets
/// and ports). The supervisor calls it in a worker thread, which waits on
/// the runtime of `pent run` for the decision.
pub(crate) struct SandboxDecider {
    /// The chain of the run.
    pub decider: std::sync::Arc<Decider>,
    /// The runtime of `pent run`, where the worker thread waits.
    pub runtime: tokio::runtime::Handle,
    /// The longest wait of a file question (see [`file_deadline`]).
    pub file_deadline: Duration,
}

/// The variable that shortens the deadline of a file question, in
/// milliseconds. The tests set it: since step 5.4 a refused file asks, and
/// a test that only probes a refusal must not wait 120 s for an answer that
/// nobody gives.
pub(crate) const FILE_DEADLINE_VAR: &str = "PENT_FILE_DEADLINE_MS";

/// The longest wait of a file question: [`pent_profile::FILE_DEADLINE`],
/// or a shorter time from [`FILE_DEADLINE_VAR`].
pub(crate) fn file_deadline() -> Duration {
    std::env::var(FILE_DEADLINE_VAR)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .map_or(pent_profile::FILE_DEADLINE, |d| {
            d.min(pent_profile::FILE_DEADLINE)
        })
}

impl std::fmt::Debug for SandboxDecider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SandboxDecider")
            .field(self.decider.key())
            .finish()
    }
}

impl pent_sandbox::AccessDecider for SandboxDecider {
    fn known(&self, request: &Request) -> Option<Decision> {
        self.decider.known(request).map(DecidedBy::decision)
    }

    /// A runtime that stops while the question waits (an error path of
    /// `pent run`) ends the task of the session, and the question ends
    /// with a deny.
    fn decide(&self, program: &str, request: Request, deadline: Duration) -> Decision {
        self.decide_target(program, request, deadline).0
    }

    fn hidden(&self, path: &Path) -> bool {
        self.decider.hidden(path)
    }

    fn graft_plan(&self, target: &Target) -> Option<Vec<PathBuf>> {
        self.decider.graft_plan(target)
    }

    fn decide_target(
        &self,
        program: &str,
        request: Request,
        deadline: Duration,
    ) -> (Decision, Option<Target>) {
        let deadline = match request {
            Request::File { .. } => deadline.min(self.file_deadline),
            _ => deadline,
        };
        let decided =
            self.runtime
                .block_on(self.decider.decide(program, request.clone(), deadline));
        (
            decided.decision(),
            self.decider.target_of(&request, decided),
        )
    }
}

/// The decision of `rules` for `access`. For a sensitive access, an allow
/// counts only when an exact rule gives it.
fn decide_in(rules: &RuleSet, access: &Access<'_>, sensitive: bool) -> Option<Decision> {
    let decision = rules.decide(access)?;
    if decision == Decision::Deny || !sensitive {
        return Some(decision);
    }
    rules.decide_where(access, |rule| is_exact(&rule.target))
}

/// Return true if `target` names one path, one name, one socket or one
/// port.
const fn is_exact(target: &Target) -> bool {
    match target {
        Target::File { width, .. } => matches!(width, PathWidth::Exact(_)),
        Target::Domain(width) => matches!(width, DomainWidth::Exact(_)),
        Target::UnixSocket(_) | Target::Localhost(_) => true,
    }
}

/// The program, the request and the decision of a static event. The proxy
/// does not know the process, so a network event names the key.
fn request_of(event: &WatchEvent, key: &RuleKey) -> Option<(String, Request, Decision)> {
    let decision = |outcome: Outcome| match outcome {
        Outcome::Allowed => Decision::Allow,
        Outcome::Blocked(_) | Outcome::Denied => Decision::Deny,
    };
    match event {
        WatchEvent::Fs {
            op,
            path,
            process,
            outcome,
        } => {
            let kind = match op {
                FsOp::List => FileKind::List,
                FsOp::Read => FileKind::Read,
                FsOp::Write | FsOp::Create | FsOp::Delete => FileKind::Write,
                FsOp::Exec => FileKind::Exec,
            };
            let path = RulePath::new(path.clone()).ok()?;
            Some((
                process.name.clone(),
                Request::File { kind, path },
                decision(*outcome),
            ))
        }
        WatchEvent::UnixConnect {
            target,
            process,
            outcome,
        } => Some((
            process.name.clone(),
            Request::UnixSocket(RulePath::new(target.as_str()).ok()?),
            decision(*outcome),
        )),
        WatchEvent::Dns { name, outcome, .. } => Some((
            key.to_string(),
            Request::Domain(name.parse().ok()?),
            decision(*outcome),
        )),
        WatchEvent::LocalhostConnect {
            port,
            process,
            outcome,
        } => Some((
            process.name.clone(),
            Request::Localhost(NonZeroU16::new(*port)?),
            decision(*outcome),
        )),
        WatchEvent::Connect {
            host,
            port,
            outcome,
            ..
        } => {
            let address = host.parse::<std::net::IpAddr>().ok();
            let request = if host == "localhost" || address.is_some_and(|ip| ip.is_loopback()) {
                Request::Localhost(NonZeroU16::new(*port)?)
            } else if address.is_some() {
                // A rule names a domain, never an address.
                return None;
            } else {
                Request::Domain(host.parse().ok()?)
            };
            Some((key.to_string(), request, decision(*outcome)))
        }
    }
}

// ── The flags ───────────────────────────────────────────────────────────────

/// The flags of `pent run` that give an access, as the rules of the flag
/// layer. A path flag covers its subtree, as Landlock does. A relative path
/// resolves against `workspace`, and a leading `~` against the home
/// directory. A flag that is not a valid target stays out of the chain;
/// the static layer still gets it.
pub(crate) struct FlagLists<'a> {
    /// The workspace of `-w`, as the user wrote it: list, read, write and
    /// exec in its subtree. Exec goes when phase 5 makes exec ask.
    pub workspace: Option<&'a Path>,
    /// `--read`.
    pub read: &'a [PathBuf],
    /// `--write`.
    pub write: &'a [PathBuf],
    /// `--execute`.
    pub execute: &'a [PathBuf],
    /// `--allow`.
    pub allow: &'a [String],
    /// `--unix-socket`.
    pub unix_sockets: &'a [PathBuf],
    /// `--localhost`.
    pub localhost: &'a [NonZeroU16],
}

impl FlagLists<'_> {
    /// The rules of the flags for the key `key`. A relative path resolves
    /// against `workspace`.
    ///
    /// Each path gives a rule for the path as the user wrote it, and one
    /// more for its canonical form when the two differ, so a request in
    /// either form finds the flag (a link such as `/home` to `/var/home`).
    pub(crate) fn rules(&self, key: RuleKey, workspace: &Path) -> RuleSet {
        let now = SystemTime::now();
        let rule = |target| Rule {
            target,
            decision: Decision::Allow,
            source: Source::Human,
            created: now,
        };
        let paths = |p: &Path| -> Vec<RulePath> {
            let p = pent_settings::expand_home(p);
            let written = if p.is_absolute() {
                p
            } else {
                workspace.join(p)
            };
            let real = std::fs::canonicalize(&written)
                .ok()
                .filter(|real| *real != written);
            std::iter::once(written)
                .chain(real)
                .filter_map(|p| RulePath::new(p).ok())
                .collect()
        };
        let mut rules = Vec::new();
        for dir in self.workspace.map(paths).unwrap_or_default() {
            rules.extend(
                [
                    FileKind::List,
                    FileKind::Read,
                    FileKind::Write,
                    FileKind::Exec,
                ]
                .map(|kind| {
                    rule(Target::File {
                        kind,
                        width: PathWidth::Subtree(dir.clone()),
                    })
                }),
            );
        }
        for (kind, list) in [
            (FileKind::Read, self.read),
            (FileKind::Write, self.write),
            (FileKind::Exec, self.execute),
        ] {
            rules.extend(list.iter().flat_map(|p| paths(p)).map(|p| {
                rule(Target::File {
                    kind,
                    width: PathWidth::Subtree(p),
                })
            }));
        }
        rules.extend(
            self.allow
                .iter()
                .filter_map(|d| d.parse::<DomainWidth>().ok())
                .map(|w| rule(Target::Domain(w))),
        );
        rules.extend(
            self.unix_sockets
                .iter()
                .flat_map(|p| paths(p))
                .map(|p| rule(Target::UnixSocket(p))),
        );
        rules.extend(
            self.localhost
                .iter()
                .map(|port| rule(Target::Localhost(*port))),
        );
        RuleSet { key, rules }
    }
}

// ── The grants of the rules ─────────────────────────────────────────────────

/// What the rules of the key give to the static layers at the start.
#[derive(Debug, Default)]
pub(crate) struct Grants {
    /// The paths for Landlock.
    pub paths: SandboxPaths,
    /// The domains for the list of the proxy, in its form.
    pub domains: Vec<String>,
    /// The Unix sockets for the supervisor.
    pub unix_sockets: Vec<PathBuf>,
    /// The ports on the loopback of the host.
    pub ports: Vec<NonZeroU16>,
    /// The allow rules that the static layers cannot hold, and why.
    pub held_back: Vec<(Target, HeldBack)>,
}

/// Why an allow rule does not go into a static layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldBack {
    /// A deny rule is inside its width.
    Hole,
    /// The rule names one directory, and Landlock gives a whole tree.
    Directory,
    /// The rule names a file of pent.
    PentFiles,
    /// A subtree covers a sensitive path or a file of pent: only an exact
    /// rule gives such a path.
    Sensitive,
    /// The sandbox cannot take the path as it is: the path is not UTF-8,
    /// or it ends with `*`, which the sandbox reads as a pattern.
    PathForm,
}

impl HeldBack {
    /// The reason as text, for a warning.
    pub(crate) const fn text(self) -> &'static str {
        match self {
            Self::Hole => "a deny rule is inside it",
            Self::Directory => "it names one directory, and the sandbox gives only whole trees",
            Self::PentFiles => "it names the files of pent",
            Self::PathForm => {
                "the sandbox cannot take this path as it is (a name that is not UTF-8, or a trailing *)"
            }
            Self::Sensitive => {
                "a sensitive path or a file of pent is inside it, and only an exact rule gives such a path"
            }
        }
    }
}

/// The warnings of the flags `flags`: each flag on a subtree that covers a
/// sensitive location or a location of the guard list. Such a flag still
/// applies, because the user gives it for this run, but the user must know.
/// A flag that covers the files of pent gets a note: they stay hidden (the
/// pent class comes first in the chain, and the sandbox masks them).
pub(crate) fn flag_warnings(flags: &RuleSet, classes: &Classes) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for rule in &flags.rules {
        let Target::File { kind, width } = &rule.target else {
            continue;
        };
        let (PathWidth::Exact(base) | PathWidth::Subtree(base)) = width;
        // One line for each path: `-w` gives four kinds on one path.
        let text = base.as_path().to_string_lossy();
        let shown = pent_profile::safe(&text);
        let line = match file_held_back(flags, *kind, width, Some(classes), Path::is_dir) {
            Some(HeldBack::Sensitive) => {
                format!("a flag gives {shown} for this run, and a sensitive location is inside it")
            }
            Some(HeldBack::PentFiles) => {
                format!("a flag gives {shown}, but the files of pent there stay hidden")
            }
            _ => continue,
        };
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines
}

impl Grants {
    /// The grants of `rules`. `classes` holds the classes of the user, or
    /// `None` when the home directory is not known: then no subtree goes
    /// into Landlock. `is_dir` tells if a path is a directory now.
    pub(crate) fn of(
        rules: &RuleSet,
        classes: Option<&Classes>,
        is_dir: impl Fn(&Path) -> bool,
    ) -> Self {
        let mut grants = Self::default();
        for rule in rules.rules.iter().filter(|r| r.decision == Decision::Allow) {
            if !rules.is_whole(rule) {
                grants.held_back.push((rule.target.clone(), HeldBack::Hole));
                continue;
            }
            match &rule.target {
                Target::File { kind, width } => {
                    if let Some(why) = file_held_back(rules, *kind, width, classes, &is_dir) {
                        grants.held_back.push((rule.target.clone(), why));
                        continue;
                    }
                    let (PathWidth::Exact(base) | PathWidth::Subtree(base)) = width;
                    let path = base.as_path();
                    let lists = &mut grants.paths;
                    match kind {
                        FileKind::List => push_new(&mut lists.traversal, path),
                        FileKind::Read => push_new(&mut lists.read, path),
                        FileKind::Write => push_new(&mut lists.read_write, path),
                        // The execute list of the sandbox gives no read of
                        // a file, and an exec rule includes the read.
                        FileKind::Exec => {
                            push_new(&mut lists.read, path);
                            push_new(&mut lists.execute, path);
                        }
                    }
                    // The program must reach the path: each parent below
                    // `/` gets the traversal. `/` is in the defaults.
                    for parent in path.ancestors().skip(1) {
                        if parent.parent().is_some() {
                            push_new(&mut lists.traversal, parent);
                        }
                    }
                }
                Target::Domain(width) => grants.domains.push(width.to_string()),
                Target::UnixSocket(path) => grants.unix_sockets.push(path.as_path().to_path_buf()),
                Target::Localhost(port) => grants.ports.push(*port),
            }
        }
        grants
    }
}

/// The kinds that the sandbox gives for a file rule of the kind `kind`. A
/// write grant of Landlock also gives the right to run a file, so a write
/// rule must hold as an exec rule too.
const fn static_kinds(kind: FileKind) -> &'static [FileKind] {
    match kind {
        FileKind::List => &[FileKind::List],
        FileKind::Read => &[FileKind::Read],
        FileKind::Write => &[FileKind::Write, FileKind::Exec],
        FileKind::Exec => &[FileKind::Exec],
    }
}

/// Why a whole file rule of the kind `kind` on `width` cannot go into
/// Landlock, or `None` when it can.
fn file_held_back(
    rules: &RuleSet,
    kind: FileKind,
    width: &PathWidth,
    classes: Option<&Classes>,
    is_dir: impl Fn(&Path) -> bool,
) -> Option<HeldBack> {
    let (PathWidth::Exact(base) | PathWidth::Subtree(base)) = width;
    let path = base.as_path();
    if path.to_str().is_none_or(|text| text.ends_with('*')) {
        return Some(HeldBack::PathForm);
    }
    let subtree = matches!(width, PathWidth::Subtree(_));
    for &given in static_kinds(kind) {
        let same_width = Rule {
            target: Target::File {
                kind: given,
                width: width.clone(),
            },
            decision: Decision::Allow,
            source: Source::Human,
            created: SystemTime::UNIX_EPOCH,
        };
        if !rules.is_whole(&same_width) {
            return Some(HeldBack::Hole);
        }
        let class = classes.map(|c| {
            c.decide(&Request::File {
                kind: given,
                path: base.clone(),
            })
            .0
        });
        match class {
            Some(Class::Pent) => return Some(HeldBack::PentFiles),
            Some(Class::Sensitive(_)) if subtree => return Some(HeldBack::Sensitive),
            _ if subtree && classes.is_none_or(|c| c.subtree_holds_guard(path, given)) => {
                return Some(HeldBack::Sensitive)
            }
            _ => {}
        }
    }
    (!subtree && is_dir(path)).then_some(HeldBack::Directory)
}

/// Add the text of `path` to `list` when it is not there. The caller
/// checked that the path is UTF-8.
fn push_new(list: &mut Vec<String>, path: &Path) {
    let text = path.to_string_lossy().into_owned();
    if !list.contains(&text) {
        list.push(text);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use pent_profile::{Message, NetProtocol, ProcessInfo, Question, Scope, Verdict};
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::UnixStream;
    use tokio::sync::mpsc;

    use std::os::unix::ffi::OsStrExt as _;

    use super::*;

    fn key() -> RuleKey {
        "cargo".parse().unwrap()
    }

    fn path(p: &str) -> RulePath {
        RulePath::new(p).unwrap()
    }

    fn rule(target: Target, decision: Decision) -> Rule {
        Rule {
            target,
            decision,
            source: Source::Human,
            created: SystemTime::UNIX_EPOCH,
        }
    }

    fn file(kind: FileKind, width: PathWidth, decision: Decision) -> Rule {
        rule(Target::File { kind, width }, decision)
    }

    fn set(rules: Vec<Rule>) -> RuleSet {
        RuleSet { key: key(), rules }
    }

    fn domain(name: &str) -> Request {
        Request::Domain(name.parse().unwrap())
    }

    fn read(p: &str) -> Request {
        Request::File {
            kind: FileKind::Read,
            path: path(p),
        }
    }

    fn classes() -> Option<Classes> {
        Some(Classes::new(Path::new("/home/u"), &[]))
    }

    #[test]
    fn a_graft_needs_a_clean_subtree() {
        let sub = |p: &str| PathWidth::Subtree(path(p));
        let target = |p: &str| Target::File {
            kind: FileKind::Read,
            width: sub(p),
        };
        let rules = set(vec![
            file(FileKind::Read, sub("/home/u/src"), Decision::Allow),
            file(FileKind::Read, sub("/home/u/src/secret"), Decision::Deny),
        ]);
        let decider = Decider::new(set(vec![]), rules, classes(), None);
        // A clean subtree may be a graft.
        assert!(decider.graft_plan(&target("/home/u/projects")).is_some());
        // A deny rule inside, a sensitive location inside, an exact width.
        assert!(decider.graft_plan(&target("/home/u/src")).is_none());
        assert!(decider.graft_plan(&target("/home/u")).is_none());
        assert!(decider.graft_plan(&target("/home/u/.ssh")).is_none());
        // The children of a width with a directory of pent (step 5.13):
        // pent and a missing credential stay with FUSE, a clean child may
        // be a graft.
        assert!(decider.graft_plan(&target("/home/u/.config")).is_none());
        assert!(decider
            .graft_plan(&target("/home/u/.config/pent"))
            .is_none());
        assert!(decider.graft_plan(&target("/home/u/.config/gh")).is_none());
        assert!(decider
            .graft_plan(&target("/home/u/.config/nvim"))
            .is_some());
        assert!(decider
            .graft_plan(&Target::File {
                kind: FileKind::Read,
                width: PathWidth::Exact(path("/home/u/projects")),
            })
            .is_none());
        // A graft gives more than its kind: a write graft reads and lists,
        // a read graft lists. A deny rule of such a kind inside the width
        // stops the graft too.
        let kinds = set(vec![
            file(FileKind::Write, sub("/home/u/w"), Decision::Allow),
            file(FileKind::Read, sub("/home/u/w/secret"), Decision::Deny),
            file(FileKind::Read, sub("/home/u/r"), Decision::Allow),
            file(FileKind::List, sub("/home/u/r/private"), Decision::Deny),
        ]);
        let decider = Decider::new(set(vec![]), kinds, classes(), None);
        let of = |kind, p: &str| Target::File {
            kind,
            width: sub(p),
        };
        assert!(decider
            .graft_plan(&of(FileKind::Write, "/home/u/w"))
            .is_none());
        assert!(decider
            .graft_plan(&of(FileKind::Read, "/home/u/r"))
            .is_none());
        // Without the classes of the user no graft is safe.
        let blind = Decider::new(set(vec![]), set(vec![]), None, None);
        assert!(blind.graft_plan(&target("/home/u/projects")).is_none());
    }

    #[test]
    fn the_target_of_a_decision_is_the_rule_that_allowed_it() {
        let wide = file(
            FileKind::Read,
            PathWidth::Subtree(path("/home/u/projects")),
            Decision::Allow,
        );
        let flag = file(
            FileKind::Read,
            PathWidth::Subtree(path("/home/u/notes")),
            Decision::Allow,
        );
        let decider = Decider::new(
            set(vec![flag.clone()]),
            set(vec![wide.clone()]),
            classes(),
            None,
        );
        let request = read("/home/u/projects/a/b");
        assert_eq!(
            decider.target_of(&request, DecidedBy::Rule(Decision::Allow)),
            Some(wide.target)
        );
        assert_eq!(
            decider.target_of(&read("/home/u/notes/x"), DecidedBy::Flag(Decision::Allow)),
            Some(flag.target)
        );
        // A refusal and the base have no target.
        assert_eq!(
            decider.target_of(&request, DecidedBy::Rule(Decision::Deny)),
            None
        );
        assert_eq!(
            decider.target_of(&request, DecidedBy::Base(Decision::Allow)),
            None
        );
    }

    #[test]
    fn the_grants_hold_back_what_a_static_layer_cannot_hold() {
        let port = NonZeroU16::new(5432).unwrap();
        let rules = set(vec![
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.cargo/registry")),
                Decision::Allow,
            ),
            file(
                FileKind::Write,
                PathWidth::Exact(path("/home/u/notes.txt")),
                Decision::Allow,
            ),
            file(
                FileKind::Exec,
                PathWidth::Subtree(path("/opt/tool")),
                Decision::Allow,
            ),
            // A directory with an exact width: Landlock gives the tree.
            file(
                FileKind::Read,
                PathWidth::Exact(path("/srv/data")),
                Decision::Allow,
            ),
            // A hole: the deny is inside the allow.
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/src")),
                Decision::Allow,
            ),
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/src/secret")),
                Decision::Deny,
            ),
            // The files of pent, below and above.
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.config/pent")),
                Decision::Allow,
            ),
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.config")),
                Decision::Allow,
            ),
            // A subtree on a credential, and an exact rule on one.
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.ssh")),
                Decision::Allow,
            ),
            file(
                FileKind::Read,
                PathWidth::Exact(path("/home/u/.ssh/id_ed25519")),
                Decision::Allow,
            ),
            // The guard stops only a write in `~/bin`: a read rule applies,
            // and a write rule does not.
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/bin")),
                Decision::Allow,
            ),
            file(
                FileKind::Write,
                PathWidth::Subtree(path("/home/u/bin")),
                Decision::Allow,
            ),
            rule(
                Target::Domain("*.crates.io".parse().unwrap()),
                Decision::Allow,
            ),
            rule(Target::Domain("evil.org".parse().unwrap()), Decision::Deny),
            rule(Target::UnixSocket(path("/run/x.sock")), Decision::Allow),
            rule(Target::Localhost(port), Decision::Allow),
        ]);
        let classes = classes();
        let grants = Grants::of(&rules, classes.as_ref(), |p| p == Path::new("/srv/data"));
        assert_eq!(
            grants.paths.read,
            vec![
                "/home/u/.cargo/registry",
                "/opt/tool",
                "/home/u/.ssh/id_ed25519",
                "/home/u/bin"
            ]
        );
        assert_eq!(grants.paths.read_write, vec!["/home/u/notes.txt"]);
        assert_eq!(grants.paths.execute, vec!["/opt/tool"]);
        assert_eq!(
            grants.paths.traversal,
            vec!["/home/u/.cargo", "/home/u", "/home", "/opt", "/home/u/.ssh"]
        );
        assert_eq!(grants.domains, vec!["*.crates.io"]);
        assert_eq!(grants.unix_sockets, vec![PathBuf::from("/run/x.sock")]);
        assert_eq!(grants.ports, vec![port]);
        let held: Vec<(String, HeldBack)> = grants
            .held_back
            .iter()
            .map(|(t, why)| (t.to_string(), *why))
            .collect();
        assert_eq!(
            held,
            vec![
                ("read /srv/data".to_string(), HeldBack::Directory),
                ("read /home/u/src/**".to_string(), HeldBack::Hole),
                (
                    "read /home/u/.config/pent/**".to_string(),
                    HeldBack::PentFiles
                ),
                ("read /home/u/.config/**".to_string(), HeldBack::Sensitive),
                ("read /home/u/.ssh/**".to_string(), HeldBack::Sensitive),
                ("write /home/u/bin/**".to_string(), HeldBack::Sensitive),
            ]
        );
        // Without the classes, no subtree goes into Landlock; an exact rule
        // does.
        let blind = Grants::of(&rules, None, |_| false);
        assert_eq!(
            blind.paths.read,
            vec!["/srv/data", "/home/u/.ssh/id_ed25519"]
        );
        assert!(blind.paths.execute.is_empty());
        assert_eq!(blind.paths.read_write, vec!["/home/u/notes.txt"]);
    }

    #[test]
    fn a_static_grant_holds_each_kind_that_the_sandbox_gives() {
        let rules = set(vec![
            // An exec rule includes the read, so it goes into both lists.
            file(
                FileKind::Exec,
                PathWidth::Subtree(path("/opt/tool")),
                Decision::Allow,
            ),
            // Landlock gives a write grant the right to run a file, so an
            // exec deny inside a write allow makes a hole.
            file(
                FileKind::Write,
                PathWidth::Subtree(path("/srv/proj")),
                Decision::Allow,
            ),
            file(
                FileKind::Exec,
                PathWidth::Subtree(path("/srv/proj/bin")),
                Decision::Deny,
            ),
            // The sandbox reads a trailing `*` as a pattern.
            file(
                FileKind::Read,
                PathWidth::Exact(path("/home/u/.ssh*")),
                Decision::Allow,
            ),
        ]);
        let classes = classes();
        let grants = Grants::of(&rules, classes.as_ref(), |_| false);
        assert_eq!(grants.paths.read, vec!["/opt/tool"]);
        assert_eq!(grants.paths.execute, vec!["/opt/tool"]);
        assert!(grants.paths.read_write.is_empty());
        let held: Vec<(String, HeldBack)> = grants
            .held_back
            .iter()
            .map(|(t, why)| (t.to_string(), *why))
            .collect();
        assert_eq!(
            held,
            vec![
                ("write /srv/proj/**".to_string(), HeldBack::Hole),
                ("read /home/u/.ssh*".to_string(), HeldBack::PathForm),
            ]
        );
        // A path that is not UTF-8.
        let latin = std::ffi::OsStr::from_bytes(b"/srv/caf\xe9");
        let rules = set(vec![file(
            FileKind::Read,
            PathWidth::Exact(RulePath::new(latin).unwrap()),
            Decision::Allow,
        )]);
        let grants = Grants::of(&rules, classes.as_ref(), |_| false);
        assert!(grants.paths.read.is_empty());
        assert_eq!(grants.held_back.len(), 1);
        assert_eq!(
            grants.held_back.first().map(|h| h.1),
            Some(HeldBack::PathForm)
        );
    }

    #[test]
    fn a_sensitive_access_names_its_exact_answer() {
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), None);
        {
            let mut answers = chain.answers.lock().unwrap();
            answers.rules.rules.push(file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.ssh")),
                Decision::Allow,
            ));
            answers.questions.push(QuestionId(3));
            answers.rules.rules.push(file(
                FileKind::Read,
                PathWidth::Exact(path("/home/u/.ssh/id_ed25519")),
                Decision::Allow,
            ));
            answers.questions.push(QuestionId(5));
        }
        assert_eq!(
            chain.known(&read("/home/u/.ssh/id_ed25519")),
            Some(DecidedBy::Answer {
                question: QuestionId(5),
                decision: Decision::Allow
            })
        );
        // A normal path names the wide answer.
        assert_eq!(
            chain.known(&read("/home/u/.ssh/known_hosts.d/x")),
            Some(DecidedBy::Answer {
                question: QuestionId(3),
                decision: Decision::Allow
            })
        );
    }

    /// A question of the supervisor gets a deny, not a panic, when the
    /// runtime of `pent run` stops while the question waits.
    #[test]
    fn a_question_of_the_supervisor_ends_with_a_deny_when_the_runtime_stops() {
        use pent_sandbox::AccessDecider as _;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        // A pentd that takes the question and never answers.
        let (session, theirs) = runtime.block_on(async {
            let (ours, theirs) = UnixStream::pair().unwrap();
            (Session::over_stream(ours), theirs)
        });
        let sandbox = SandboxDecider {
            decider: std::sync::Arc::new(Decider::new(
                set(vec![]),
                set(vec![]),
                classes(),
                Some(session),
            )),
            runtime: runtime.handle().clone(),
            file_deadline: pent_profile::FILE_DEADLINE,
        };
        let worker = std::thread::spawn(move || {
            sandbox.decide(
                "cargo",
                Request::UnixSocket(path("/run/x.sock")),
                Duration::from_secs(60),
            )
        });
        std::thread::sleep(Duration::from_millis(300));
        runtime.shutdown_timeout(Duration::from_secs(1));
        let decision = worker.join();
        drop(theirs);
        assert!(
            matches!(decision, Ok(Decision::Deny)),
            "the worker must end with a deny: {decision:?}"
        );
    }

    /// A deny answer of any width refuses a sensitive access at once and
    /// names its question: the user refused it already.
    #[test]
    fn a_wide_deny_answer_decides_a_sensitive_access() {
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), None);
        {
            let mut answers = chain.answers.lock().unwrap();
            answers.rules.rules.push(file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.ssh")),
                Decision::Deny,
            ));
            answers.questions.push(QuestionId(7));
        }
        assert_eq!(
            chain.known(&read("/home/u/.ssh/id_ed25519")),
            Some(DecidedBy::Answer {
                question: QuestionId(7),
                decision: Decision::Deny
            })
        );
    }

    #[test]
    fn only_an_exact_rule_allows_a_sensitive_access() {
        let key_file = "/home/u/.ssh/id_ed25519";
        let wide = set(vec![file(
            FileKind::Read,
            PathWidth::Subtree(path("/home/u/.ssh")),
            Decision::Allow,
        )]);
        let chain = Decider::new(set(vec![]), wide, classes(), None);
        assert_eq!(chain.known(&read(key_file)), None);
        // A normal path below the same subtree needs no exact rule.
        assert_eq!(
            chain.known(&read("/home/u/.ssh/known_hosts.d/x")),
            Some(DecidedBy::Rule(Decision::Allow))
        );
        let exact = set(vec![
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u/.ssh")),
                Decision::Allow,
            ),
            file(
                FileKind::Read,
                PathWidth::Exact(path(key_file)),
                Decision::Allow,
            ),
        ]);
        let chain = Decider::new(set(vec![]), exact, classes(), None);
        assert_eq!(
            chain.known(&read(key_file)),
            Some(DecidedBy::Rule(Decision::Allow))
        );
        // A wide deny refuses a sensitive access.
        let deny = set(vec![file(
            FileKind::Read,
            PathWidth::Subtree(path("/home/u/.ssh")),
            Decision::Deny,
        )]);
        let chain = Decider::new(set(vec![]), deny, classes(), None);
        assert_eq!(
            chain.known(&read(key_file)),
            Some(DecidedBy::Rule(Decision::Deny))
        );
    }

    /// `-w` is an answer in advance for the whole workspace: list, read,
    /// write and exec in its subtree, for this run only.
    #[test]
    fn the_workspace_flag_gives_each_kind_in_its_subtree() {
        let flags = FlagLists {
            workspace: Some(Path::new("/srv/ws")),
            read: &[],
            write: &[],
            execute: &[],
            allow: &[],
            unix_sockets: &[],
            localhost: &[],
        }
        .rules(key(), Path::new("/home/u"));
        let texts: Vec<String> = flags.rules.iter().map(|r| r.target.to_string()).collect();
        assert_eq!(
            texts,
            vec![
                "list /srv/ws/**",
                "read /srv/ws/**",
                "write /srv/ws/**",
                "exec /srv/ws/**",
            ]
        );
        let chain = Decider::new(flags, set(vec![]), classes(), None);
        assert_eq!(
            chain.known(&read("/srv/ws/src/main.rs")),
            Some(DecidedBy::Flag(Decision::Allow))
        );
        assert_eq!(chain.known(&read("/srv/other")), None);
    }

    /// A flag path that goes through a link gives a rule for each form, so
    /// a request in either form finds the flag.
    #[test]
    fn a_flag_through_a_link_gives_both_forms() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let read = [root.join("link")];
        let flags = FlagLists {
            workspace: Some(&root.join("link")),
            read: &read,
            write: &[],
            execute: &[],
            allow: &[],
            unix_sockets: &[],
            localhost: &[],
        }
        .rules(key(), &root);
        let texts: Vec<String> = flags.rules.iter().map(|r| r.target.to_string()).collect();
        for form in ["link", "real"] {
            let want = format!("read {}/**", root.join(form).display());
            assert_eq!(
                texts.iter().filter(|t| **t == want).count(),
                2,
                "{want}: {texts:?}"
            );
            let want = format!("write {}/**", root.join(form).display());
            assert!(texts.contains(&want), "{want}: {texts:?}");
        }
    }

    /// A flag over a sensitive location applies, with a warning; a flag
    /// over the files of pent gets a note that they stay hidden.
    #[test]
    fn a_flag_over_a_guard_location_gives_a_warning() {
        let classes = Classes::new(
            Path::new("/home/u"),
            &[PathBuf::from("/home/u/.config/pent")],
        );
        let lines = |write: &[PathBuf]| {
            let flags = FlagLists {
                workspace: None,
                read: &[],
                write,
                execute: &[],
                allow: &[],
                unix_sockets: &[],
                localhost: &[],
            }
            .rules(key(), Path::new("/home/u"));
            flag_warnings(&flags, &classes)
        };
        let config = lines(&[PathBuf::from("/home/u/.config")]);
        assert_eq!(config.len(), 1, "{config:?}");
        assert!(config[0].contains("a sensitive location"), "{config:?}");
        let pent = lines(&[PathBuf::from("/home/u/.config/pent")]);
        assert_eq!(pent.len(), 1, "{pent:?}");
        assert!(pent[0].contains("stay hidden"), "{pent:?}");
        assert!(lines(&[PathBuf::from("/home/u/src/app")]).is_empty());
    }

    #[test]
    fn the_flags_become_rules_of_the_flag_layer() {
        let read = [PathBuf::from("data"), PathBuf::from("/etc/x")];
        let allow = ["api.example.com".to_string(), "*.com".to_string()];
        let port = [NonZeroU16::new(8080).unwrap()];
        let flags = FlagLists {
            workspace: None,
            read: &read,
            write: &[],
            execute: &[],
            allow: &allow,
            unix_sockets: &[PathBuf::from("/run/y.sock")],
            localhost: &port,
        }
        .rules(key(), Path::new("/ws"));
        let texts: Vec<String> = flags.rules.iter().map(|r| r.target.to_string()).collect();
        // `*.com` covers a public suffix: it stays out of the chain.
        assert_eq!(
            texts,
            vec![
                "read /ws/data/**",
                "read /etc/x/**",
                "domain api.example.com",
                "unix-socket /run/y.sock",
                "localhost 8080",
            ]
        );
    }

    /// The list of refusals for the agent is only information: a full
    /// list, far past its limit, changes no decision of the chain, and the
    /// list counts the refusals that left it.
    #[test]
    fn a_full_list_of_refusals_changes_no_decision() {
        let rules = set(vec![
            rule(Target::Domain("a.org".parse().unwrap()), Decision::Allow),
            rule(Target::Domain("b.org".parse().unwrap()), Decision::Deny),
        ]);
        let chain = Decider::new(set(vec![]), rules, classes(), None);
        let probes = [
            domain("a.org"),
            domain("b.org"),
            domain("c.org"),
            read("/home/u/x"),
            read("/home/u/.config/pent/pent.toml"),
        ];
        let before: Vec<Option<DecidedBy>> = probes.iter().map(|r| chain.known(r)).collect();
        let total = crate::agent::MAX_DENIALS * 2;
        for i in 0..total {
            chain.report(
                "cat",
                read(&format!("/home/u/{i}")),
                DecidedBy::Base(Decision::Deny),
            );
        }
        // The refusals of the probes themselves go into the list too.
        for probe in &probes {
            chain.report("cat", probe.clone(), DecidedBy::Base(Decision::Deny));
        }
        let after: Vec<Option<DecidedBy>> = probes.iter().map(|r| chain.known(r)).collect();
        assert_eq!(before, after);
        let (list, dropped) = chain.agent_denials();
        assert_eq!(list.len(), crate::agent::MAX_DENIALS);
        let added = u64::try_from(total + probes.len()).unwrap();
        let kept = u64::try_from(list.len()).unwrap();
        assert_eq!(dropped, added - kept);
    }

    #[test]
    fn the_chain_asks_the_pent_class_then_the_flags_then_the_rules() {
        let flags = set(vec![
            file(
                FileKind::Read,
                PathWidth::Subtree(path("/home/u")),
                Decision::Allow,
            ),
            rule(Target::Domain("a.org".parse().unwrap()), Decision::Allow),
        ]);
        let rules = set(vec![
            rule(Target::Domain("a.org".parse().unwrap()), Decision::Deny),
            rule(Target::Domain("b.org".parse().unwrap()), Decision::Deny),
        ]);
        let chain = Decider::new(flags, rules, classes(), None);
        assert_eq!(
            chain.known(&read("/home/u/.local/state/pent/rules/cargo.toml")),
            Some(DecidedBy::Hidden)
        );
        assert_eq!(
            chain.known(&Request::UnixSocket(path("/home/u/.config/pent/x.sock"))),
            Some(DecidedBy::Base(Decision::Deny))
        );
        assert_eq!(
            chain.known(&read("/home/u/a.txt")),
            Some(DecidedBy::Flag(Decision::Allow))
        );
        assert_eq!(
            chain.known(&domain("a.org")),
            Some(DecidedBy::Flag(Decision::Allow))
        );
        assert_eq!(
            chain.known(&domain("b.org")),
            Some(DecidedBy::Rule(Decision::Deny))
        );
        assert_eq!(chain.known(&domain("c.org")), None);
    }

    #[tokio::test]
    async fn without_pentd_an_open_access_is_a_refusal_of_the_base() {
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), None);
        assert_eq!(
            chain
                .decide("curl", domain("c.org"), pent_profile::PROXY_DEADLINE)
                .await,
            DecidedBy::Base(Decision::Deny)
        );
    }

    /// A fake pentd: it numbers each ask, answers it with `answer`, and
    /// sends each event that it gets to the returned channel.
    fn fake_pentd(
        stream: UnixStream,
        answer: Option<(Decision, Target, Scope)>,
    ) -> (
        mpsc::UnboundedReceiver<Message>,
        tokio::task::JoinHandle<()>,
    ) {
        let (seen, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let mut next = 10;
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(message) = Message::decode_line(&line) else {
                    continue;
                };
                let _ = seen.send(message.clone());
                let Message::Ask(ask) = message else {
                    continue;
                };
                let id = pent_profile::QuestionId(next);
                next += 1;
                let mut out = vec![Message::Question(Question { id, ask })];
                if let Some((decision, target, scope)) = answer.clone() {
                    out.push(Message::Verdict(Verdict {
                        id,
                        decision,
                        target,
                        scope,
                        source: Source::Human,
                    }));
                }
                for m in out {
                    if write
                        .write_all(m.encode_line().unwrap().as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        (rx, task)
    }

    #[tokio::test]
    async fn an_answer_decides_and_covers_the_rest_of_its_width() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let wide = Target::Domain("**.example.com".parse().unwrap());
        let (mut seen, _task) = fake_pentd(theirs, Some((Decision::Allow, wide, Scope::Run)));
        let session = Session::over_stream(ours);
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), Some(session));
        let first = chain
            .decide(
                "curl",
                domain("api.example.com"),
                pent_profile::PROXY_DEADLINE,
            )
            .await;
        let answer = DecidedBy::Answer {
            question: pent_profile::QuestionId(10),
            decision: Decision::Allow,
        };
        assert_eq!(first, answer);
        // The same width needs no new question.
        let second = chain
            .decide(
                "curl",
                domain("cdn.example.com"),
                pent_profile::PROXY_DEADLINE,
            )
            .await;
        assert_eq!(second, answer);
        // The hook sends no event: the proxy sends one for each
        // connection, and it takes the cause of the hook.
        let dns = |name: &str| WatchEvent::Dns {
            name: name.to_string(),
            qtype: "A".to_string(),
            outcome: Outcome::Allowed,
        };
        chain.report_watch(&dns("api.example.com"));
        chain.report_watch(&dns("cdn.example.com"));
        chain.flush().await;
        drop(chain);
        let mut asks = 0;
        let mut events = Vec::new();
        while let Some(message) = seen.recv().await {
            match message {
                Message::Ask(ask) => {
                    asks += 1;
                    assert_eq!(ask.key, key());
                    assert_eq!(ask.program, "curl");
                }
                Message::Event(event) => events.push(event),
                other => panic!("pentd must not get {other:?}"),
            }
        }
        assert_eq!(asks, 1);
        let got: Vec<(Request, DecidedBy)> = events
            .into_iter()
            .map(|e| (e.request, e.decided_by))
            .collect();
        assert_eq!(
            got,
            vec![
                (domain("api.example.com"), answer),
                (domain("cdn.example.com"), answer),
            ]
        );
    }

    #[tokio::test]
    async fn a_deadline_names_its_question() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let (mut seen, _task) = fake_pentd(theirs, None);
        let session = Session::over_stream(ours);
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), Some(session));
        let deadline = DecidedBy::Deadline {
            question: pent_profile::QuestionId(10),
        };
        assert_eq!(
            chain
                .decide("curl", domain("slow.org"), Duration::from_millis(300))
                .await,
            deadline
        );
        // No answer came, so the next access asks again.
        assert_eq!(chain.known(&domain("slow.org")), None);
        // The refusal of the proxy names the question. A second refusal
        // with no hook decision names the base.
        let refused = WatchEvent::Dns {
            name: "slow.org".to_string(),
            qtype: "A".to_string(),
            outcome: Outcome::Denied,
        };
        chain.report_watch(&refused);
        chain.report_watch(&refused);
        chain.flush().await;
        drop(chain);
        let mut causes = Vec::new();
        while let Some(message) = seen.recv().await {
            if let Message::Event(e) = message {
                causes.push(e.decided_by);
            }
        }
        assert_eq!(causes, vec![deadline, DecidedBy::Base(Decision::Deny)]);
    }

    /// The verdict of a question comes after the deadline of its access
    /// (as at the 4 s of DNS). The next access of the same width gets the
    /// answer, and pentd gets no new question.
    #[tokio::test]
    async fn a_late_answer_applies_to_the_next_access() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let (read, mut write) = theirs.into_split();
        let asks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&asks);
        tokio::spawn(async move {
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(Message::Ask(ask)) = Message::decode_line(&line) else {
                    continue;
                };
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let id = QuestionId(7);
                let numbered = Message::Question(Question { id, ask });
                let line = numbered.encode_line().unwrap();
                write.write_all(line.as_bytes()).await.unwrap();
                // The human answers after the deadline of the access.
                tokio::time::sleep(Duration::from_millis(400)).await;
                let verdict = Message::Verdict(Verdict {
                    id,
                    decision: Decision::Allow,
                    target: Target::Domain("**.late.example".parse().unwrap()),
                    scope: Scope::Run,
                    source: Source::Human,
                });
                write
                    .write_all(verdict.encode_line().unwrap().as_bytes())
                    .await
                    .unwrap();
            }
        });
        let session = Session::over_stream(ours);
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), Some(session));
        assert_eq!(
            chain
                .decide("dig", domain("a.late.example"), Duration::from_millis(100))
                .await,
            DecidedBy::Deadline {
                question: QuestionId(7)
            }
        );
        tokio::time::sleep(Duration::from_millis(700)).await;
        let answer = DecidedBy::Answer {
            question: QuestionId(7),
            decision: Decision::Allow,
        };
        assert_eq!(
            chain
                .decide("dig", domain("b.late.example"), Duration::from_millis(100))
                .await,
            answer
        );
        assert_eq!(asks.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A hook decision that waits longer than its life has no event any
    /// more, so a later event does not take its cause.
    #[test]
    fn an_old_hook_decision_names_no_later_event() {
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), None);
        let deadline = DecidedBy::Deadline {
            question: QuestionId(4),
        };
        let old = std::time::Instant::now()
            .checked_sub(HOOKED_LIFE + Duration::from_secs(1))
            .unwrap();
        chain.hooked.lock().unwrap().push_back(Hooked {
            request: domain("b.example"),
            decided_by: deadline,
            at: old,
        });
        assert_eq!(
            chain.take_hooked(&domain("b.example"), Decision::Deny),
            None
        );
        assert!(chain.hooked.lock().unwrap().is_empty());
        chain.hooked.lock().unwrap().push_back(Hooked {
            request: domain("b.example"),
            decided_by: deadline,
            at: std::time::Instant::now(),
        });
        assert_eq!(
            chain.take_hooked(&domain("b.example"), Decision::Deny),
            Some(deadline)
        );
    }

    #[tokio::test]
    async fn a_static_event_names_its_cause() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let (mut seen, _task) = fake_pentd(theirs, None);
        let session = Session::over_stream(ours);
        let rules = set(vec![
            rule(Target::Domain("bad.org".parse().unwrap()), Decision::Deny),
            rule(Target::Domain("good.org".parse().unwrap()), Decision::Allow),
        ]);
        let chain = Decider::new(set(vec![]), rules, classes(), Some(session));
        let dns = |name: &str, outcome| WatchEvent::Dns {
            name: name.to_string(),
            qtype: "A".to_string(),
            outcome,
        };
        let connect = |host: &str, outcome| WatchEvent::Connect {
            host: host.to_string(),
            port: 5432,
            protocol: NetProtocol::Socks5,
            outcome,
        };
        let process = ProcessInfo {
            pid: 3,
            name: "cat".to_string(),
        };
        for event in [
            dns("bad.org", Outcome::Denied),
            dns("good.org", Outcome::Allowed),
            dns("new.org", Outcome::Denied),
            // The rule allows it, but a static layer refused it.
            dns("good.org", Outcome::Denied),
            // An address is not a request: no event.
            connect("10.0.0.1", Outcome::Denied),
            connect("127.0.0.1", Outcome::Denied),
            WatchEvent::Fs {
                op: FsOp::Create,
                path: PathBuf::from("/srv/out"),
                process: process.clone(),
                outcome: Outcome::Blocked(pent_profile::GuardClass::Persistence),
            },
            // An abstract socket is not a request: no event.
            WatchEvent::UnixConnect {
                target: "@bus".to_string(),
                process,
                outcome: Outcome::Denied,
            },
        ] {
            chain.report_watch(&event);
        }
        chain.flush().await;
        drop(chain);
        let mut got = Vec::new();
        while let Some(message) = seen.recv().await {
            if let Message::Event(e) = message {
                got.push((e.program, e.request, e.decided_by));
            }
        }
        let port = NonZeroU16::new(5432).unwrap();
        let deny = DecidedBy::Base(Decision::Deny);
        assert_eq!(
            got,
            vec![
                (
                    "cargo".into(),
                    domain("bad.org"),
                    DecidedBy::Rule(Decision::Deny)
                ),
                (
                    "cargo".into(),
                    domain("good.org"),
                    DecidedBy::Rule(Decision::Allow)
                ),
                ("cargo".into(), domain("new.org"), deny),
                ("cargo".into(), domain("good.org"), deny),
                ("cargo".into(), Request::Localhost(port), deny),
                (
                    "cat".into(),
                    Request::File {
                        kind: FileKind::Write,
                        path: path("/srv/out")
                    },
                    deny
                ),
            ]
        );
    }
}
