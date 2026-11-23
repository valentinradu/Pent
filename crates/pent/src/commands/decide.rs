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
        let answers = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let decision = decide_in(&answers.rules, &access, sensitive)?;
        // The event names one answer that alone gives the same decision.
        // For a sensitive access, only an exact answer counts.
        answers
            .rules
            .rules
            .iter()
            .zip(&answers.questions)
            .find(|(rule, _)| {
                (!sensitive || is_exact(&rule.target))
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

    /// Decide `request` of `program`: with the chain when it knows the
    /// answer, else with a question to pentd that waits at most `deadline`.
    /// Send the event of the decision to pentd.
    #[cfg_attr(not(test), allow(dead_code))] // the hooks ask from step 3.2 of PLAN.md.
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
        self.report(program, request, decided_by);
        decided_by
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
                let mut answers = self
                    .answers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                answers.rules.rules.push(Rule {
                    target: verdict.target.clone(),
                    decision: verdict.decision,
                    source: verdict.source,
                    created: SystemTime::now(),
                });
                answers.questions.push(verdict.id);
                drop(answers);
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
    pub(crate) fn report(&self, program: &str, request: Request, decided_by: DecidedBy) {
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
    /// the supervisor or Landlock. An access that the program cannot name as
    /// a request (an IP address, an abstract socket) gives no event.
    pub(crate) fn report_watch(&self, event: &WatchEvent) {
        let Some((program, request, decision)) = request_of(event, self.key()) else {
            tracing::debug!("no event for {event:?}: it is not a request");
            return;
        };
        let decided_by = self.static_cause(&request, decision);
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

    /// The class of `request`, or `None` when the home directory is not
    /// known.
    fn class(&self, request: &Request) -> Option<Class> {
        self.classes.as_ref().map(|c| c.decide(request).0)
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
    pub traverse: &'a [PathBuf],
    pub read: &'a [PathBuf],
    pub write: &'a [PathBuf],
    pub execute: &'a [PathBuf],
    pub allow: &'a [String],
    pub unix_sockets: &'a [PathBuf],
    pub localhost: &'a [NonZeroU16],
}

impl FlagLists<'_> {
    /// The rules of the flags for the key `key`.
    pub(crate) fn rules(&self, key: RuleKey, workspace: &Path) -> RuleSet {
        let now = SystemTime::now();
        let rule = |target| Rule {
            target,
            decision: Decision::Allow,
            source: Source::Human,
            created: now,
        };
        let path = |p: &Path| {
            let p = pent_settings::expand_home(p);
            RulePath::new(if p.is_absolute() {
                p
            } else {
                workspace.join(p)
            })
            .ok()
        };
        let mut rules = Vec::new();
        for (kind, list) in [
            (FileKind::List, self.traverse),
            (FileKind::Read, self.read),
            (FileKind::Write, self.write),
            (FileKind::Exec, self.execute),
        ] {
            rules.extend(list.iter().filter_map(|p| path(p)).map(|p| {
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
                .filter_map(|p| path(p))
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

    #[test]
    fn the_flags_become_rules_of_the_flag_layer() {
        let read = [PathBuf::from("data"), PathBuf::from("/etc/x")];
        let allow = ["api.example.com".to_string(), "*.com".to_string()];
        let port = [NonZeroU16::new(8080).unwrap()];
        let flags = FlagLists {
            traverse: &[],
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
        let (_seen, _task) = fake_pentd(theirs, None);
        let session = Session::over_stream(ours);
        let chain = Decider::new(set(vec![]), set(vec![]), classes(), Some(session));
        assert_eq!(
            chain
                .decide("curl", domain("slow.org"), Duration::from_millis(300))
                .await,
            DecidedBy::Deadline {
                question: pent_profile::QuestionId(10)
            }
        );
        // No answer came, so the next access asks again.
        assert_eq!(chain.known(&domain("slow.org")), None);
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
