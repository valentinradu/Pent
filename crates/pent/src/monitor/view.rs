//! The view of `pent monitor`: it draws a [`Model`] into a frame.
//!
//! Each text that a program chose (a path, a name, a command line) goes
//! through [`safe`], so it cannot hold a control sequence for the terminal.

use pent_profile::{safe, Class, Decision, Question, Scope};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use super::model::{KindFilter, Model, Tab};
use crate::commands::answer::{time_text, why_text};
use crate::commands::rules::{count_text, rule_text};

/// The style of a warning.
const WARN: Style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);

/// The style of the selected line.
const SELECTED: Style = Style::new().add_modifier(Modifier::REVERSED);

/// The style of a title of a group.
const GROUP: Style = Style::new().add_modifier(Modifier::BOLD);

/// Draw `model` into `frame`.
pub(crate) fn draw(frame: &mut Frame<'_>, model: &Model) {
    let [top, body, status, help] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_tabs(frame, top, model);
    match model.tab() {
        Tab::Questions => draw_questions(frame, body, model),
        Tab::Events => draw_events(frame, body, model),
        Tab::Rules => draw_rules(frame, body, model),
    }
    let text = model.status().unwrap_or_default();
    frame.render_widget(Paragraph::new(text.to_string()), status);
    let keys = match model.tab() {
        Tab::Questions => {
            "a allow  d deny  ←→ width  s scope  enter details  ↑↓ select  tab next  q quit"
        }
        Tab::Events => "f session  r refusals  tab next  q quit",
        Tab::Rules => "↑↓ key  tab next  q quit",
    };
    frame.render_widget(
        Paragraph::new(keys).style(Style::new().add_modifier(Modifier::DIM)),
        help,
    );
}

/// The line of the tabs.
fn draw_tabs(frame: &mut Frame<'_>, area: Rect, model: &Model) {
    let titles = Tab::ALL.iter().map(|tab| match tab {
        Tab::Questions => format!("Questions ({})", model.open()),
        Tab::Events => "Events".to_string(),
        Tab::Rules => "Rules".to_string(),
    });
    let selected = Tab::ALL.iter().position(|t| *t == model.tab()).unwrap_or(0);
    frame.render_widget(
        Tabs::new(titles).select(selected).highlight_style(SELECTED),
        area,
    );
}

/// The questions tab: the list, then the details of the selected question.
fn draw_questions(frame: &mut Frame<'_>, area: Rect, model: &Model) {
    let details = detail_lines(model);
    let height = u16::try_from(details.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let [list, detail] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(height)]).areas(area);
    let selected = model.selected().map(|q| q.id);
    let mut lines = Vec::new();
    let mut selected_line = 0_usize;
    for (key, questions) in model.groups() {
        lines.push(Line::styled(key.to_string(), GROUP));
        for question in questions {
            if Some(question.id) == selected {
                selected_line = lines.len();
            }
            let mut spans = vec![Span::raw(format!(
                "  {}  {}",
                question.id,
                safe(&question.ask.request.to_string())
            ))];
            if let Class::Sensitive(sensitive) = question.ask.class {
                spans.push(Span::styled(format!("  ! {}", sensitive.warning()), WARN));
            }
            let line = Line::from(spans);
            lines.push(if Some(question.id) == selected {
                line.style(SELECTED)
            } else {
                line
            });
        }
    }
    if lines.is_empty() {
        lines.push(Line::raw("No open question."));
    }
    // Keep the selected line in view.
    let inner = list.height.saturating_sub(2);
    let scroll = u16::try_from(selected_line)
        .unwrap_or(u16::MAX)
        .saturating_sub(inner.saturating_sub(1));
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("Open questions"))
            .scroll((scroll, 0)),
        list,
    );
    let title = model
        .selected()
        .map_or_else(|| "Details".to_string(), |q| q.id.to_string());
    frame.render_widget(
        Paragraph::new(details)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: false }),
        detail,
    );
}

/// The lines of the details of the selected question.
fn detail_lines(model: &Model) -> Vec<Line<'static>> {
    let Some(question) = model.selected() else {
        return vec![Line::raw("Select a question.")];
    };
    let ask = &question.ask;
    let session = model
        .session(ask.session)
        .map(|s| format!(" ({})", safe(&s.command.join(" "))))
        .unwrap_or_default();
    let mut lines = vec![
        Line::raw(format!(
            "{} wants: {}",
            ask.key,
            safe(&ask.request.to_string())
        )),
        Line::raw(format!(
            "program {}  session {}{session}",
            safe(&ask.program),
            ask.session
        )),
    ];
    if let Class::Sensitive(sensitive) = ask.class {
        lines.push(Line::styled(
            format!(
                "warning: {}; only the exact target, and only you can answer",
                sensitive.warning()
            ),
            WARN,
        ));
    }
    lines.extend(width_lines(model, question));
    let scope = match model.scope() {
        Scope::Run => "[this run]  remember",
        Scope::Remember => " this run  [remember]",
    };
    lines.push(Line::raw(format!("scope  {scope}")));
    lines.push(Line::raw(format!(
        "resolves: allow {}, deny {} of the open questions of {}",
        model.covered(Decision::Allow),
        model.covered(Decision::Deny),
        ask.key
    )));
    if model.details() {
        lines.push(Line::raw(format!("asked {}", time_text(ask.asked))));
        lines.push(Line::raw(format!(
            "waits {} s in the run, then the access gets a refusal",
            ask.deadline.duration().as_secs()
        )));
    }
    lines
}

/// The lines of the width menu of `question`, with the selected place.
fn width_lines(model: &Model, question: &Question) -> Vec<Line<'static>> {
    let width = usize::from(model.width_of(question));
    question
        .ask
        .menu
        .iter()
        .enumerate()
        .map(|(i, target)| {
            let label = if i == 0 { "width" } else { "     " };
            let mark = if i == width { "(•)" } else { "( )" };
            Line::raw(format!("{label}  {mark} {i} {}", safe(&target.to_string())))
        })
        .collect()
}

/// The events tab.
fn draw_events(frame: &mut Frame<'_>, area: Rect, model: &Model) {
    let session = model.session_filter().map_or_else(
        || "each session".to_string(),
        |id| {
            model
                .session(id)
                .map_or_else(|| id.to_string(), |s| format!("{id} {}", s.key))
        },
    );
    let kind = match model.kind_filter() {
        KindFilter::All => "each event",
        KindFilter::Refusals => "refusals",
    };
    let mut title = format!("Events: {session}, {kind}");
    if model.dropped() > 0 {
        title.push_str(&format!(
            "; pentd dropped {} events for this screen",
            model.dropped()
        ));
    }
    let events = model.events();
    let room = usize::from(area.height.saturating_sub(2));
    let start = events.len().saturating_sub(room);
    let lines: Vec<Line<'_>> = events
        .get(start..)
        .unwrap_or_default()
        .iter()
        .map(|event| {
            let key = model
                .session(event.session)
                .map_or_else(|| event.session.to_string(), |s| s.key.to_string());
            let refusal = event.decided_by.is_refusal();
            let text = format!(
                "{}  {key}  {}  {}  by {}  ({})",
                time_text(event.time),
                if refusal { "deny " } else { "allow" },
                safe(&event.request.to_string()),
                safe(&event.program),
                why_text(event.decided_by),
            );
            if refusal {
                Line::styled(text, Style::new().fg(Color::Red))
            } else {
                Line::raw(text)
            }
        })
        .collect();
    let lines = if lines.is_empty() {
        vec![Line::raw("No event.")]
    } else {
        lines
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title)),
        area,
    );
}

/// The rules tab: the keys, then the rules of the selected key.
fn draw_rules(frame: &mut Frame<'_>, area: Rect, model: &Model) {
    let (keys, selected) = model.rules();
    let [left, right] =
        Layout::horizontal([Constraint::Length(30), Constraint::Min(10)]).areas(area);
    let mut lines: Vec<Line<'_>> = keys
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let count = match &entry.rules {
                Ok(rules) => count_text(rules.len()),
                Err(_) => "not valid".to_string(),
            };
            let line = Line::raw(format!("{:<16} {count}", entry.key.as_str()));
            if i == selected {
                line.style(SELECTED)
            } else {
                line
            }
        })
        .collect();
    if lines.is_empty() {
        lines.push(Line::raw("No rules."));
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title("Keys")),
        left,
    );
    let (title, body) = match keys.get(selected) {
        None => ("Rules".to_string(), vec![Line::raw("")]),
        Some(entry) => (
            entry.key.to_string(),
            match &entry.rules {
                Ok(rules) if rules.is_empty() => vec![Line::raw("No rules.")],
                Ok(rules) => rules
                    .iter()
                    .enumerate()
                    .map(|(i, rule)| Line::raw(rule_text(i.saturating_add(1), rule)))
                    .collect(),
                Err(e) => vec![Line::styled(safe(e).into_owned(), WARN)],
            },
        ),
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: false }),
        right,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use pent_profile::{Message, Sensitive, SessionId, SessionInfo};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::super::model::tests::read;
    use super::super::model::{Key, KeyRules};
    use super::*;

    /// The text of the screen after a draw of `model`, one row on each line.
    fn screen(model: &Model, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, model)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn the_questions_show_by_key_with_the_menu_of_the_selected_one() {
        let mut model = Model::default();
        model.apply(Message::Session(SessionInfo {
            id: SessionId(1),
            key: "claude".parse().unwrap(),
            command: vec!["claude".into(), "\u{1b}[2J".into()],
            live: true,
        }));
        model.apply(Message::Question(read(1, "claude", "/h/r/a", "/h/r")));
        let mut sensitive = read(2, "psql", "/h/.ssh/id", "/h/.ssh");
        sensitive.ask.class = Class::Sensitive(Sensitive::Credential);
        sensitive.ask.menu.truncate(1);
        model.apply(Message::Question(sensitive));
        model.key(Key::Right);
        let text = screen(&model, 100, 24);
        assert!(text.contains("Questions (2)"), "{text}");
        assert!(text.contains("claude"), "{text}");
        assert!(text.contains("  222223  read /h/r/a"), "{text}");
        assert!(
            text.contains("  222224  read /h/.ssh/id  ! a credential file"),
            "{text}"
        );
        assert!(text.contains("width  ( ) 0 read /h/r/a"), "{text}");
        assert!(text.contains("       (•) 1 read /h/r/**"), "{text}");
        assert!(text.contains("scope  [this run]  remember"), "{text}");
        assert!(
            text.contains("resolves: allow 1, deny 1 of the open questions of claude"),
            "{text}"
        );
        // The command line of the session is escaped.
        assert!(text.contains("(claude \\u{1b}[2J)"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[test]
    fn a_sensitive_question_shows_its_warning_in_the_details() {
        let mut model = Model::default();
        let mut q = read(2, "psql", "/h/.ssh/id", "/h/.ssh");
        q.ask.class = Class::Sensitive(Sensitive::Credential);
        q.ask.menu.truncate(1);
        model.apply(Message::Question(q));
        let text = screen(&model, 100, 24);
        assert!(
            text.contains(
                "warning: a credential file; only the exact target, and only you can answer"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_events_tab_names_each_loss_and_escapes_the_program() {
        let mut model = Model::default();
        model.apply(Message::Event(pent_profile::Event {
            session: SessionId(1),
            time: pent_profile::Timestamp(1_795_348_800_000),
            program: "evil\u{7}".into(),
            request: pent_profile::Request::Localhost(std::num::NonZeroU16::MIN),
            decided_by: pent_profile::DecidedBy::Hidden,
        }));
        model.apply(Message::EventsDropped(pent_profile::EventsDropped {
            count: 9,
        }));
        model.key(Key::Tab);
        let text = screen(&model, 120, 12);
        assert!(
            text.contains("pentd dropped 9 events for this screen"),
            "{text}"
        );
        assert!(text.contains("deny   localhost 1  by evil\\u{7}"), "{text}");
        assert!(!text.contains('\u{7}'), "{text}");
    }

    #[test]
    fn the_rules_tab_shows_the_rules_of_the_selected_key() {
        let mut model = Model::default();
        model.key(Key::Tab);
        model.key(Key::Tab);
        model.set_rules(vec![KeyRules {
            key: "cargo".parse().unwrap(),
            rules: Ok(vec![pent_profile::Rule {
                target: pent_profile::Target::Localhost(std::num::NonZeroU16::MIN),
                decision: pent_profile::Decision::Deny,
                source: pent_profile::Source::Human,
                created: std::time::SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(1_795_348_800),
            }]),
        }]);
        let text = screen(&model, 120, 12);
        assert!(text.contains("cargo            1 rule"), "{text}");
        assert!(
            text.contains("  1  deny   localhost 1  human  2026-11-22T12:00:00Z"),
            "{text}"
        );
    }

    #[test]
    fn a_small_terminal_does_not_panic() {
        let mut model = Model::default();
        for i in 0..50 {
            model.apply(Message::Question(read(
                i,
                "cargo",
                &format!("/h/r/{i}"),
                "/h/r",
            )));
        }
        for _ in 0..40 {
            model.key(Key::Down);
        }
        for (w, h) in [(1, 1), (10, 3), (40, 8), (200, 60)] {
            // The text does not matter here: only that the draw ends.
            let _ = screen(&model, w, h);
        }
    }
}
