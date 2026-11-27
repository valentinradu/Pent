//! `pent allow`, `pent deny`, `pent questions` and `pent denials`: the
//! clients of pentd for a script or a terminal.
//!
//! Inside the sandbox of `pent run` ([`crate::agent::AGENT_SOCK_VAR`] is
//! set), `pent denials`, `pent deny` and `pent skip` use `agent.sock`, and
//! `pent allow` fails: the agent cannot allow.
//!
//! Each command sends one request to pentd (see [`Call`]). The data goes to
//! stdout, and the status goes to stderr. Each text that a program chose (a
//! path, a name, a command) goes through [`safe`], so it cannot hold a
//! control character for the terminal.

use pent_profile::{
    format_date, safe, AgentDenial, AgentReason, AgentReply, AgentRequest, Answer, Class,
    DecidedBy, Decision, Denial, MenuIndex, Message, Question, QuestionId, RejectReason, Rejected,
    Scope, SessionId, Skip, Source, Timestamp, Verdict,
};
use pent_settings::RuntimeDir;

use crate::cli::{AnswerArgs, DenialsArgs, QuestionsArgs, SkipArgs};
use crate::daemon::call::Call;
use crate::daemon::DaemonError;
use crate::error::CliError;
use crate::ui;

/// `pent allow ID` and `pent deny ID`: answer one question.
pub(crate) async fn answer(args: &AnswerArgs, decision: Decision) -> Result<(), CliError> {
    let id: QuestionId = args.id.parse()?;
    if let Some(socket) = crate::agent::agent_socket() {
        return agent_deny(&socket, args, id, decision).await;
    }
    let scope = if args.remember {
        Scope::Remember
    } else {
        Scope::Run
    };
    let request = Message::Answer(Answer {
        id,
        decision,
        width: MenuIndex(args.width),
        scope,
        source: Source::Human,
    });
    let mut call = Call::send(&RuntimeDir::from_env(), &request).await?;
    // pentd sends `RuleNotKept` before the verdicts, and the verdict of the
    // question always comes. The verdicts of other questions that the
    // answer covers can come before it.
    let mut kept = true;
    loop {
        match call.next().await? {
            Message::Rejected(Rejected {
                id: Some(r),
                reason: RejectReason::RuleNotKept,
            }) if r == id => kept = false,
            Message::Rejected(Rejected { id: None, reason }) => {
                return Err(DaemonError::Rejected(reason).into())
            }
            Message::Rejected(Rejected {
                id: Some(r),
                reason,
            }) if r == id => return Err(DaemonError::Rejected(reason).into()),
            Message::Verdict(verdict) if verdict.id == id => {
                ui::ok(verdict_text(&verdict));
                if !kept {
                    ui::warn(RejectReason::RuleNotKept);
                }
                return Ok(());
            }
            _ => {}
        }
    }
}

/// The text of a verdict: `question 7: allow read /x/** (this run)`.
pub(crate) fn verdict_text(verdict: &Verdict) -> String {
    let scope = match verdict.scope {
        Scope::Run => "this run",
        Scope::Remember => "remembered",
    };
    format!(
        "question {}: {} {} ({scope})",
        verdict.id,
        verdict.decision.name(),
        safe(&verdict.target.to_string()),
    )
}

/// `pent questions`: list the open questions. A question that the agent
/// skipped shows its reason as untrusted text; with `--json`, each skip is
/// one more line of JSON after the questions.
pub(crate) async fn questions(args: &QuestionsArgs) -> Result<(), CliError> {
    let mut call = Call::send(&RuntimeDir::from_env(), &Message::Questions).await?;
    let mut questions = Vec::new();
    let mut skips = Vec::new();
    loop {
        match call.next().await? {
            Message::Question(question) => questions.push(question),
            Message::Skip(skip) => skips.push(skip),
            Message::Rejected(Rejected { reason, .. }) => {
                return Err(DaemonError::Rejected(reason).into())
            }
            Message::End => break,
            _ => {}
        }
    }
    if args.json {
        let failed = |e: serde_json::Error| CliError::Other(e.to_string());
        for question in &questions {
            println!("{}", serde_json::to_string(question).map_err(failed)?);
        }
        for skip in &skips {
            println!("{}", serde_json::to_string(skip).map_err(failed)?);
        }
        return Ok(());
    }
    for question in &questions {
        print!("{}", question_text(question));
        if let Some(skip) = skips.iter().find(|s| s.id == question.id) {
            println!(
                "    the agent says (untrusted): {}",
                safe(skip.reason.as_str())
            );
        }
    }
    if questions.is_empty() {
        ui::status("questions", "none");
    }
    Ok(())
}

/// The text of one question, with its menu, on more than one line.
fn question_text(question: &Question) -> String {
    let ask = &question.ask;
    let mut text = format!(
        "{}  {}  {}\n    program {}, session {}, asked {}\n",
        question.id,
        ask.key,
        safe(&ask.request.to_string()),
        safe(&ask.program),
        ask.session,
        time_text(ask.asked),
    );
    if let Class::Sensitive(sensitive) = ask.class {
        text.push_str(&format!(
            "    warning: {}; only the exact target (--width 0)\n",
            sensitive.warning()
        ));
    }
    for (i, target) in ask.menu.iter().enumerate() {
        text.push_str(&format!("    --width {i}  {}\n", safe(&target.to_string())));
    }
    text
}

/// The deny of the agent, inside the sandbox: for this run and for the
/// exact target only.
async fn agent_deny(
    socket: &std::path::Path,
    args: &AnswerArgs,
    id: QuestionId,
    decision: Decision,
) -> Result<(), CliError> {
    if decision == Decision::Allow {
        return Err(CliError::Other(
            "inside the sandbox of pent run, the agent cannot allow; the human answers in \
             pent monitor"
                .to_string(),
        ));
    }
    if args.width != 0 || args.remember {
        return Err(CliError::Other(
            "inside the sandbox of pent run, a deny holds for this run and for the exact \
             target; --width and --remember are not possible"
                .to_string(),
        ));
    }
    agent_done(
        socket,
        &AgentRequest::Deny(id),
        &format!("question {id}: deny (this run)"),
    )
    .await
}

/// `pent skip ID REASON`: send a question up to the human, inside the
/// sandbox.
pub(crate) async fn skip(args: &SkipArgs) -> Result<(), CliError> {
    let Some(socket) = crate::agent::agent_socket() else {
        return Err(CliError::Other(
            "pent skip works only inside the sandbox of pent run".to_string(),
        ));
    };
    let id: QuestionId = args.id.parse()?;
    let reason =
        AgentReason::try_from(args.reason.clone()).map_err(|e| CliError::Other(e.to_string()))?;
    agent_done(
        &socket,
        &AgentRequest::Skip(Skip { id, reason }),
        &format!("question {id}: sent to the human"),
    )
    .await
}

/// Send one request that ends with `Done` or `Failed`.
async fn agent_done(
    socket: &std::path::Path,
    request: &AgentRequest,
    done: &str,
) -> Result<(), CliError> {
    for reply in crate::agent::call(socket, request).await? {
        match reply {
            AgentReply::Done => {
                ui::ok(done);
                return Ok(());
            }
            AgentReply::Failed(failure) => return Err(CliError::Other(failure.to_string())),
            AgentReply::Denial(_) | AgentReply::End { .. } => {}
        }
    }
    Err(CliError::Other("agent.sock gave no result".to_string()))
}

/// `pent denials` inside the sandbox: the refusals of this run.
async fn agent_denials(socket: &std::path::Path) -> Result<(), CliError> {
    let mut any = false;
    for reply in crate::agent::call(socket, &AgentRequest::Denials).await? {
        match reply {
            AgentReply::Denial(denial) => {
                any = true;
                println!("{}", agent_denial_text(&denial));
            }
            AgentReply::End { dropped } if dropped > 0 => {
                ui::warn(format!("{dropped} older refusals are not in the list"));
            }
            AgentReply::End { .. } | AgentReply::Done | AgentReply::Failed(_) => {}
        }
    }
    if !any {
        ui::status("denials", "none");
    }
    Ok(())
}

/// The text of one refusal of the run, on one line.
fn agent_denial_text(denial: &AgentDenial) -> String {
    let count = if denial.count > 1 {
        format!(", {} times", denial.count)
    } else {
        String::new()
    };
    format!(
        "  {}  {}  by {}  ({}{count})",
        time_text(denial.last),
        safe(&denial.request.to_string()),
        safe(&denial.program),
        why_text(denial.decided_by),
    )
}

/// `pent denials [SESSION]`: show the refusals of a session.
pub(crate) async fn denials(args: &DenialsArgs) -> Result<(), CliError> {
    if let Some(socket) = crate::agent::agent_socket() {
        if args.session.is_some() {
            return Err(CliError::Other(
                "inside the sandbox of pent run, pent denials shows only this run".to_string(),
            ));
        }
        return agent_denials(&socket).await;
    }
    let session: Option<SessionId> = args.session.as_deref().map(str::parse).transpose()?;
    let request = Message::Denials(session);
    let mut call = Call::send(&RuntimeDir::from_env(), &request).await?;
    let mut last: Option<SessionId> = None;
    loop {
        match call.next().await? {
            Message::Denial(denial) => {
                if last != Some(denial.event.session) {
                    println!("session {}  {}", denial.event.session, denial.key);
                    last = Some(denial.event.session);
                }
                println!("{}", denial_text(&denial));
            }
            Message::Rejected(Rejected { reason, .. }) => {
                return Err(DaemonError::Rejected(reason).into())
            }
            Message::End => break,
            _ => {}
        }
    }
    if last.is_none() {
        ui::status("denials", "none");
    }
    Ok(())
}

/// The text of one refusal, on one line.
fn denial_text(denial: &Denial) -> String {
    let event = &denial.event;
    let why = why_text(event.decided_by);
    format!(
        "  {}  {}  by {}  ({why})",
        time_text(event.time),
        safe(&event.request.to_string()),
        safe(&event.program),
    )
}

/// What decided an access, as text: `a rule`, `the deadline of question
/// k3m9tx`.
pub(crate) fn why_text(decided_by: DecidedBy) -> String {
    match decided_by {
        DecidedBy::Flag(_) => "a flag of pent run".to_string(),
        DecidedBy::Rule(_) => "a rule".to_string(),
        DecidedBy::Answer { question, .. } => format!("the answer to question {question}"),
        DecidedBy::Deadline { question } => format!("the deadline of question {question}"),
        DecidedBy::Hidden => "a file of pent (ENOENT)".to_string(),
        DecidedBy::Base(_) => "the base".to_string(),
    }
}

/// The text of a time, in UTC, or the milliseconds when the time is out of
/// the range of a date.
pub(crate) fn time_text(time: Timestamp) -> String {
    time.to_system_time()
        .and_then(format_date)
        .unwrap_or_else(|| format!("{} ms", time.0))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use std::num::NonZeroU16;

    use pent_profile::{
        Ask, Deadline, Event, FileKind, PathWidth, Request, RulePath, Sensitive, Target,
        FILE_DEADLINE,
    };

    use super::*;

    fn path(p: &str) -> RulePath {
        RulePath::new(p).unwrap()
    }

    fn question(class: Class) -> Question {
        let p = path("/home/u/.ssh/id_ed25519");
        Question {
            id: QuestionId(7),
            ask: Ask {
                session: SessionId(3),
                key: "claude".parse().unwrap(),
                program: "/usr/bin/ssh\u{1b}[2J".into(),
                request: Request::File {
                    kind: FileKind::Read,
                    path: p.clone(),
                },
                class,
                menu: vec![
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Exact(p),
                    },
                    Target::File {
                        kind: FileKind::Read,
                        width: PathWidth::Subtree(path("/home/u/.ssh")),
                    },
                ],
                asked: Timestamp(1_795_348_800_000),
                deadline: Deadline::new(FILE_DEADLINE).unwrap(),
            },
        }
    }

    #[test]
    fn a_question_shows_its_menu_and_escapes_the_program() {
        let text = question_text(&question(Class::Normal));
        assert_eq!(
            text,
            "222229  claude  read /home/u/.ssh/id_ed25519\n    \
             program /usr/bin/ssh\\u{1b}[2J, session 222225, asked 2026-11-22T12:00:00Z\n    \
             --width 0  read /home/u/.ssh/id_ed25519\n    \
             --width 1  read /home/u/.ssh/**\n"
        );
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn a_sensitive_question_shows_its_warning() {
        let text = question_text(&question(Class::Sensitive(Sensitive::Credential)));
        assert!(
            text.contains("    warning: a credential file; only the exact target (--width 0)\n"),
            "{text}"
        );
    }

    #[test]
    fn a_denial_names_what_refused_it() {
        let port = NonZeroU16::new(5432).unwrap();
        let denial = |decided_by| Denial {
            key: "psql".parse().unwrap(),
            event: Event {
                session: SessionId(2),
                time: Timestamp(-5),
                program: "psql\n".into(),
                request: Request::Localhost(port),
                decided_by,
            },
        };
        assert_eq!(
            denial_text(&denial(DecidedBy::Deadline {
                question: QuestionId(9)
            })),
            "  -5 ms  localhost 5432  by psql\\u{a}  (the deadline of question 22222b)"
        );
        assert!(denial_text(&denial(DecidedBy::Rule(Decision::Deny))).ends_with("(a rule)"));
        assert!(denial_text(&denial(DecidedBy::Hidden)).ends_with("(a file of pent (ENOENT))"));
    }

    #[test]
    fn a_verdict_names_its_target_and_its_scope() {
        let verdict = Verdict {
            id: QuestionId(7),
            decision: Decision::Deny,
            target: Target::Domain("*.npmjs.org".parse().unwrap()),
            scope: Scope::Remember,
            source: Source::Human,
        };
        assert_eq!(
            verdict_text(&verdict),
            "question 222229: deny domain *.npmjs.org (remembered)"
        );
    }
}
