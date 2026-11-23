//! `pent monitor`: a terminal screen for the questions, the events and the
//! rules (`docs/design/pent.md`, section 11).
//!
//! - [`model`]: the state of the screen, without I/O.
//! - [`view`]: it draws the model.
//! - This module: the loop. It connects to pentd and sends `Watch`, it
//!   reads the keys in a thread, and it reads the rule files for the rules
//!   tab. It never starts pentd: without pentd, no question waits.

pub(crate) mod model;
pub(crate) mod view;

use std::io::IsTerminal as _;

use pent_profile::Message;
use pent_settings::{RuleStore, RuntimeDir};
use ratatui::crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::sync::mpsc;

use crate::daemon::{call, read_message, DaemonError};
use crate::error::CliError;
use model::{Action, Key, KeyRules, Model};

/// An input of the terminal.
enum Input {
    /// A key.
    Key(Key),
    /// A new size: draw again.
    Resize,
}

/// `pent monitor`.
pub(crate) async fn monitor() -> Result<(), CliError> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        return Err(CliError::Other("pent monitor needs a terminal".into()));
    }
    let runtime = RuntimeDir::from_env();
    let socket = runtime.pentd_socket();
    let stream = call::connect(&socket).await?;
    let (read, mut write) = stream.into_split();
    let io = |source| DaemonError::Io {
        path: socket.clone(),
        source,
    };
    let watch = Message::Watch.encode_line().map_err(DaemonError::from)?;
    write.write_all(watch.as_bytes()).await.map_err(io)?;

    // A task reads the lines, so a line never stops in the middle when the
    // other branch of the loop wins.
    let (lines_tx, mut lines) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut reader = BufReader::new(read);
        loop {
            let next = read_message(&mut reader).await;
            let end = !matches!(next, Ok(Some(_)));
            if lines_tx.send(next).is_err() || end {
                break;
            }
        }
    });
    let mut keys = spawn_keys();
    let store = RuleStore::open_default().ok();

    let mut terminal = Screen::enter()?;
    let mut model = Model::default();
    loop {
        terminal
            .0
            .draw(|frame| view::draw(frame, &model))
            .map_err(CliError::Io)?;
        let actions = tokio::select! {
            line = lines.recv() => match line {
                Some(Ok(Some(message))) => model.apply(message),
                Some(Ok(None)) | None => return Err(DaemonError::Closed.into()),
                Some(Err(e)) => return Err(DaemonError::Read(e).into()),
            },
            input = keys.recv() => match input {
                Some(Input::Key(key)) => model.key(key),
                Some(Input::Resize) => Vec::new(),
                None => return Ok(()),
            },
        };
        for action in actions {
            match action {
                Action::Send(message) => {
                    let line = message.encode_line().map_err(DaemonError::from)?;
                    write.write_all(line.as_bytes()).await.map_err(io)?;
                }
                Action::LoadRules => model.set_rules(load_rules(store.as_ref())),
                Action::Quit => return Ok(()),
            }
        }
    }
}

/// The terminal in raw mode on the alternate screen. The drop gives the
/// terminal back, also after an error.
struct Screen(ratatui::DefaultTerminal);

impl Screen {
    /// Enter the screen. `ratatui::try_init` also gives the terminal back
    /// before a panic message.
    fn enter() -> Result<Self, CliError> {
        ratatui::try_init().map(Self).map_err(CliError::Io)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

/// Read the keys in a thread: the read of crossterm blocks. The thread ends
/// when the loop drops the receiver and the next key comes, or when the
/// process ends.
fn spawn_keys() -> mpsc::UnboundedReceiver<Input> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || loop {
        let input = match event::read() {
            Ok(TermEvent::Key(key)) if key.kind != KeyEventKind::Release => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    Some(Input::Key(Key::Esc))
                } else {
                    map_key(key.code).map(Input::Key)
                }
            }
            Ok(TermEvent::Resize(..)) => Some(Input::Resize),
            Ok(_) => None,
            Err(_) => break,
        };
        if let Some(input) = input {
            if tx.send(input).is_err() {
                break;
            }
        }
    });
    rx
}

/// The key of the model for a key of crossterm.
const fn map_key(code: KeyCode) -> Option<Key> {
    Some(match code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Char(c) => Key::Char(c),
        _ => return None,
    })
}

/// The rules of each key, as `pent rules show` reads them. A file that pent
/// cannot read gives its error, and the list goes on.
fn load_rules(store: Option<&RuleStore>) -> Vec<KeyRules> {
    let Some(store) = store else {
        return Vec::new();
    };
    let keys = match store.keys() {
        Ok(keys) => keys,
        Err(e) => {
            tracing::debug!("cannot list the rules: {e}");
            return Vec::new();
        }
    };
    keys.into_iter()
        .map(|key| {
            let rules = store
                .load(&key)
                .map(|set| set.rules)
                .map_err(|e| e.to_string());
            KeyRules { key, rules }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use super::*;

    #[test]
    fn the_keys_of_crossterm_map_to_the_keys_of_the_model() {
        assert_eq!(map_key(KeyCode::Char('a')), Some(Key::Char('a')));
        assert_eq!(map_key(KeyCode::BackTab), Some(Key::BackTab));
        assert_eq!(map_key(KeyCode::F(1)), None);
    }

    #[test]
    fn the_rules_of_each_key_load_and_a_bad_file_keeps_its_error() {
        let state = tempfile::tempdir().unwrap();
        let dirs = pent_settings::PentDirs::from_vars(
            None,
            Some(state.path().into()),
            Some(state.path().into()),
        )
        .unwrap();
        let store = RuleStore::new(&dirs);
        std::fs::create_dir_all(dirs.rules_dir()).unwrap();
        std::fs::write(dirs.rules_dir().join("bad.toml"), "not toml [").unwrap();
        std::fs::write(dirs.rules_dir().join("good.toml"), "version = 1\n").unwrap();
        let rules = load_rules(Some(&store));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].key.as_str(), "bad");
        assert!(rules[0].rules.is_err());
        assert_eq!(rules[1].rules, Ok(vec![]));
        assert!(load_rules(None).is_empty());
    }
}
