//! `pent allow`, `pent deny`, `pent questions` and `pent denials`: the
//! clients of pentd for a script or a terminal.
//!
//! Each command sends one request to pentd (see [`Call`]). The data goes to
//! stdout, and the status goes to stderr. Each text that a program chose (a
//! path, a name, a command) goes through [`safe`], so it cannot hold a
//! control character for the terminal.

use pent_profile::{
    format_date, safe, Answer, Class, DecidedBy, Decision, Denial, MenuIndex, Message, Question,
    QuestionId, RejectReason, Rejected, Scope, SessionId, Source, Timestamp, Verdict,
};
use pent_settings::RuntimeDir;

use crate::cli::{AnswerArgs, DenialsArgs, QuestionsArgs};
use crate::daemon::call::Call;
use crate::daemon::DaemonError;
use crate::error::CliError;
use crate::ui;

/// `pent allow ID` and `pent deny ID`: answer one question.
pub(crate) async fn answer(args: &AnswerArgs, decision: Decision) -> Result<(), CliError> {
    let id = QuestionId(args.id);
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
fn verdict_text(verdict: &Verdict) -> String {
    let scope = match verdict.scope {
        Scope::Run => "this run",
        Scope::Remember => "remembered",
    };
    format!(
        "question {}: {} {} ({scope})",
        verdict.id.0,
        verdict.decision.name(),
        safe(&verdict.target.to_string()),
    )
}

/// `pent questions`: list the open questions.
pub(crate) async fn questions(args: &QuestionsArgs) -> Result<(), CliError> {
    let mut call = Call::send(&RuntimeDir::from_env(), &Message::Questions).await?;
    let mut count = 0_usize;
    loop {
        match call.next().await? {
            Message::Question(question) => {
                count = count.saturating_add(1);
                if args.json {
                    let line = serde_json::to_string(&question)
                        .map_err(|e| CliError::Other(e.to_string()))?;
                    println!("{line}");
                } else {
                    print!("{}", question_text(&question));
                }
            }
            Message::Rejected(Rejected { reason, .. }) => {
                return Err(DaemonError::Rejected(reason).into())
            }
            Message::End => break,
            _ => {}
        }
    }
    if count == 0 && !args.json {
        ui::status("questions", "none");
    }
    Ok(())
}

/// The text of one question, with its menu, on more than one line.
fn question_text(question: &Question) -> String {
    let ask = &question.ask;
    let mut text = format!(
        "{}  {}  {}\n    program {}, session {}, asked {}\n",
        question.id.0,
        ask.key,
        safe(&ask.request.to_string()),
        safe(&ask.program),
        ask.session.0,
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

/// `pent denials [SESSION]`: show the refusals of a session.
pub(crate) async fn denials(args: &DenialsArgs) -> Result<(), CliError> {
    let request = Message::Denials(args.session.map(SessionId));
    let mut call = Call::send(&RuntimeDir::from_env(), &request).await?;
    let mut last: Option<SessionId> = None;
    loop {
        match call.next().await? {
            Message::Denial(denial) => {
                if last != Some(denial.event.session) {
                    println!("session {}  {}", denial.event.session.0, denial.key);
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
    let why = match event.decided_by {
        DecidedBy::Flag(_) => "a flag of pent run".to_string(),
        DecidedBy::Rule(_) => "a rule".to_string(),
        DecidedBy::Answer { question, .. } => format!("the answer to question {}", question.0),
        DecidedBy::Deadline { question } => format!("the deadline of question {}", question.0),
        DecidedBy::Hidden => "a file of pent (ENOENT)".to_string(),
    };
    format!(
        "  {}  {}  by {}  ({why})",
        time_text(event.time),
        safe(&event.request.to_string()),
        safe(&event.program),
    )
}

/// The text of a time, in UTC, or the milliseconds when the time is out of
/// the range of a date.
fn time_text(time: Timestamp) -> String {
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
            "7  claude  read /home/u/.ssh/id_ed25519\n    \
             program /usr/bin/ssh\\u{1b}[2J, session 3, asked 2026-11-22T12:00:00Z\n    \
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
            "  -5 ms  localhost 5432  by psql\\u{a}  (the deadline of question 9)"
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
            "question 7: deny domain *.npmjs.org (remembered)"
        );
    }
}
