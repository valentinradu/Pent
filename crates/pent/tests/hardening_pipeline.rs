//! Hardening tests for the CLI output of the profile pipeline.
//!
//! `pent trust` and `pent profile show` print the text of the draft or the
//! profile file. `pent trust NAME --review` without a terminal prints the
//! full summary. These outputs contain paths and names from the recorded
//! program. The tests write crafted events and drafts, run the `pent` binary
//! and check its output.
//!
//! Each test uses its own `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME`
//! below `CARGO_TARGET_TMPDIR`. The home directory is not below `/tmp`,
//! because the summary omits paths below `/tmp`. Each pent process starts in
//! a new session (`setsid`), so it cannot open `/dev/tty`.
//!
//! A test with `#[ignore = "OPEN H-<n>: ..."]` shows a property that does not
//! hold now. See `docs/security/watch-and-profiles.md`.

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use pent_profile::{
    render_draft, summarize, FsOp, GuardClass, Outcome, ProcessInfo, SummaryContext, WatchEvent,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PENT: &str = env!("CARGO_BIN_EXE_pent");

/// The dangerous text in the crafted events.
const PAYLOADS: &[&str] = &[
    "esc\u{1b}[2J\u{1b}]0;pwned\u{7}",
    "cr\rover",
    "c1\u{9b}31m",
    "bidi\u{202e}exe.txt",
    "iso\u{2066}x\u{2069}",
];

/// An isolated home and XDG directories for one test.
struct Env {
    _root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    config: PathBuf,
    state: PathBuf,
}

impl Env {
    fn new() -> std::io::Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("hardening-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
        let home = root.path().join("home");
        let workspace = home.join("work/app");
        fs::create_dir_all(&workspace)?;
        Ok(Self {
            config: root.path().join("config"),
            state: root.path().join("state"),
            home,
            workspace,
            _root: root,
        })
    }

    fn pent(&self, args: &[&str]) -> std::io::Result<Output> {
        let mut cmd = Command::new(PENT);
        cmd.args(args)
            .current_dir(&self.workspace)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("CLICOLOR", "0")
            .env("NO_COLOR", "1")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("PENT_LOG")
            .stdin(Stdio::null());
        // SAFETY: setsid() is async-signal-safe and has no memory-safety
        // preconditions. The child gets a new session without a controlling
        // terminal, so pent cannot open /dev/tty and never waits for input.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.output()
    }

    fn draft_path(&self, name: &str) -> PathBuf {
        self.state.join("pent/drafts").join(format!("{name}.toml"))
    }

    fn profile_path(&self, name: &str) -> PathBuf {
        self.config
            .join("pent/profiles")
            .join(format!("{name}.toml"))
    }

    fn denied_path(&self, name: &str) -> PathBuf {
        self.state.join("pent/denied").join(format!("{name}.jsonl"))
    }

    fn write(path: &Path, text: &str) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(path, text)
    }

    /// Write `text` as the draft of `name` and trust it.
    fn install(&self, name: &str, text: &str) -> TestResult {
        Self::write(&self.draft_path(name), text)?;
        let out = self.pent(&["trust", name, "--yes"])?;
        assert!(out.status.success(), "{}", stderr(&out));
        Ok(())
    }

    /// The crafted events, with paths below the test home.
    fn crafted_events(&self) -> Vec<WatchEvent> {
        let home = self.home.display().to_string();
        let mut events = Vec::new();
        for (i, p) in PAYLOADS.iter().enumerate() {
            let process = ProcessInfo {
                pid: 9,
                name: (*p).to_string(),
            };
            events.push(WatchEvent::Fs {
                op: FsOp::Create,
                path: PathBuf::from(format!("{home}/.t{i}{p}/new")),
                process: process.clone(),
                outcome: Outcome::Denied,
            });
            events.push(WatchEvent::Fs {
                op: FsOp::Read,
                path: PathBuf::from(format!("{home}/.r{i}/{p}")),
                process: process.clone(),
                outcome: Outcome::Denied,
            });
            events.push(WatchEvent::Fs {
                op: FsOp::Read,
                path: PathBuf::from(format!("{home}/.ssh/id_{i}{p}")),
                process: process.clone(),
                outcome: Outcome::Blocked(GuardClass::Credential),
            });
            events.push(WatchEvent::UnixConnect {
                target: format!("@{p}"),
                process,
                outcome: Outcome::Denied,
            });
        }
        events
    }

    /// A draft that `render_draft` makes from the crafted events, with all
    /// items selected.
    fn crafted_draft(&self) -> Result<String, Box<dyn std::error::Error>> {
        let events = self.crafted_events();
        let ctx = SummaryContext {
            home: self.home.clone(),
            workspace: self.workspace.clone(),
            covered: Vec::new(),
            existing: None,
        };
        let summary = summarize(&events, &ctx);
        let all: Vec<usize> = (0..summary.items.len()).collect();
        let doc = summary.to_doc(&all);
        assert!(!doc.is_empty());
        Ok(render_draft(&"tool".parse()?, 1, &doc, &summary))
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[track_caller]
fn assert_no_control(what: &str, text: &str) {
    let found: Vec<char> = text
        .chars()
        .filter(|&c| c.is_control() && c != '\n')
        .collect();
    assert!(
        found.is_empty(),
        "{what}: control characters {found:?} in:\n{}",
        text.escape_debug()
    );
}

#[track_caller]
fn assert_no_bidi(what: &str, text: &str) {
    let found: Vec<char> = text.chars().filter(|&c| is_bidi(c)).collect();
    assert!(
        found.is_empty(),
        "{what}: bidi characters {found:?} in:\n{}",
        text.escape_debug()
    );
}

/// Run `pent trust tool --review --yes` on a denied log with the crafted
/// events. Without a terminal, pent prints the full summary on stderr.
fn review_output(env: &Env) -> Result<Output, Box<dyn std::error::Error>> {
    env.install("tool", "[network]\ndomains = [\"a.example.com\"]\n")?;
    let lines: Result<Vec<String>, _> = env
        .crafted_events()
        .iter()
        .map(WatchEvent::to_json_line)
        .collect();
    Env::write(&env.denied_path("tool"), &(lines?.join("\n") + "\n"))?;
    let out = env.pent(&["trust", "tool", "--review", "--yes"])?;
    assert!(out.status.success(), "{}", stderr(&out));
    Ok(out)
}

#[test]
fn p1_cli_review_summary_has_no_control_characters() -> TestResult {
    let env = Env::new()?;
    let out = review_output(&env)?;
    let err = stderr(&out);
    // The crafted rules must reach the output, else the check proves nothing.
    assert!(err.contains("Read-write"), "{err}");
    assert!(err.contains("Unix socket @esc"), "{err}");
    assert_no_control("pent trust --review", &err);
    Ok(())
}

#[test]
#[ignore = "OPEN H-1: pent trust --review prints bidi override characters from events"]
fn p1_cli_review_summary_has_no_bidi_characters() -> TestResult {
    let env = Env::new()?;
    let out = review_output(&env)?;
    assert_no_bidi("pent trust --review", &stderr(&out));
    Ok(())
}

#[test]
fn p1_cli_trust_and_show_have_no_control_characters() -> TestResult {
    let env = Env::new()?;
    Env::write(&env.draft_path("tool"), &env.crafted_draft()?)?;
    let shown = env.pent(&["profile", "show", "tool"])?;
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert_no_control("pent profile show (draft)", &stdout(&shown));
    assert_no_control("pent profile show (draft)", &stderr(&shown));

    let trust = env.pent(&["trust", "tool", "--yes"])?;
    assert!(trust.status.success(), "{}", stderr(&trust));
    assert!(
        stderr(&trust).contains("[filesystem]"),
        "{}",
        stderr(&trust)
    );
    assert_no_control("pent trust", &stderr(&trust));

    let shown = env.pent(&["profile", "show", "tool"])?;
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert_no_control("pent profile show", &stdout(&shown));
    Ok(())
}

#[test]
#[ignore = "OPEN H-1: pent trust and pent profile show print bidi override characters from the draft"]
fn p1_cli_trust_and_show_have_no_bidi_characters() -> TestResult {
    let env = Env::new()?;
    Env::write(&env.draft_path("tool"), &env.crafted_draft()?)?;
    let trust = env.pent(&["trust", "tool", "--yes"])?;
    assert!(trust.status.success(), "{}", stderr(&trust));
    assert_no_bidi("pent trust", &stderr(&trust));
    let shown = env.pent(&["profile", "show", "tool"])?;
    assert_no_bidi("pent profile show", &stdout(&shown));
    Ok(())
}

/// The review without a terminal never selects a blocked item: the draft
/// after `pent trust --review --yes` has no rule for the blocked reads.
#[test]
fn p6_cli_review_without_terminal_keeps_blocked_items_out() -> TestResult {
    let env = Env::new()?;
    review_output(&env)?;
    let profile = fs::read_to_string(env.profile_path("tool"))?;
    assert!(!profile.contains(".ssh/id_"), "{profile}");
    assert!(profile.contains("~/.r0/"), "{profile}");
    Ok(())
}

/// `pent run` refuses a profile when one byte changed after the trust. The
/// check runs before the sandbox starts, so this test needs no privilege.
#[test]
fn p5_cli_run_refuses_a_profile_that_changed_after_trust() -> TestResult {
    let env = Env::new()?;
    let text = "[network]\ndomains = [\"a.example.com\"]\n";
    env.install("tool", text)?;
    let profile = env.profile_path("tool");
    for changed in [
        format!("{text} "),
        format!("{text}# c\n"),
        text.replace("a.example.com", "*.example.com"),
    ] {
        fs::write(&profile, &changed)?;
        let out = env.pent(&["run", "--", "tool"])?;
        assert!(!out.status.success(), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("changed after you trusted it"),
            "{}",
            stderr(&out)
        );
    }
    Ok(())
}
