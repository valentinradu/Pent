//! Hardening tests for the profile pipeline of watch mode.
//!
//! The recorded program controls the paths, the domains, the process names
//! and the socket targets in the events. These tests feed crafted events into
//! the public API (`summarize`, the renderers, `review`, the guard list and
//! the public suffix subset) and check the properties in
//! `docs/security/watch-and-profiles.md`.
//!
//! A test with `#[ignore = "OPEN H-<n>: ..."]` or `#[ignore = "GAP G-<n>: ..."]`
//! shows a property that does not hold now. Its assertion fails. Run it with
//! `cargo test -p pent-profile --test hardening_profile -- --include-ignored`.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use pent_profile::psl;
use pent_profile::{
    classify, guard_rules, render_draft, render_draft_with, render_header, render_profile,
    render_terminal, review, summarize, DraftSource, FsAccess, FsOp, Grant, GuardAccess,
    GuardClass, NetProtocol, Outcome, ProcessInfo, ProfileDoc, ProfileName, Reasons, Summary,
    SummaryContext, WatchEvent, WatchHeader,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HOME: &str = "/home/u";
const WORKSPACE: &str = "/home/u/work/app";

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn ctx() -> SummaryContext {
    SummaryContext {
        home: PathBuf::from(HOME),
        workspace: PathBuf::from(WORKSPACE),
        covered: ["/usr", "/nix/store", "/etc", "/proc", "/sys"]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        existing: None,
    }
}

fn fs_ev(op: FsOp, path: impl Into<PathBuf>, process: &str, outcome: Outcome) -> WatchEvent {
    WatchEvent::Fs {
        op,
        path: path.into(),
        process: ProcessInfo {
            pid: 7,
            name: process.to_string(),
        },
        outcome,
    }
}

fn allowed(op: FsOp, path: impl Into<PathBuf>) -> WatchEvent {
    fs_ev(op, path, "tool", Outcome::Allowed)
}

fn connect(host: &str) -> WatchEvent {
    WatchEvent::Connect {
        host: host.to_string(),
        port: 443,
        protocol: NetProtocol::HttpConnect,
        outcome: Outcome::Allowed,
    }
}

fn dns(name: &str) -> WatchEvent {
    WatchEvent::Dns {
        name: name.to_string(),
        qtype: "A".to_string(),
        outcome: Outcome::Allowed,
    }
}

fn unix(target: &str, process: &str) -> WatchEvent {
    WatchEvent::UnixConnect {
        target: target.to_string(),
        process: ProcessInfo {
            pid: 8,
            name: process.to_string(),
        },
        outcome: Outcome::Allowed,
    }
}

fn name(text: &str) -> Result<ProfileName, pent_profile::ProfileNameError> {
    text.parse()
}

fn all_indices(summary: &Summary) -> Vec<usize> {
    (0..summary.items.len()).collect()
}

// ── Property 1: output safety ────────────────────────────────────────────────

/// Text that the recorded program can put into an event. Each entry has one
/// class of dangerous character.
const PAYLOADS: &[&str] = &[
    "esc\u{1b}[2J\u{1b}]0;title\u{7}",
    "cr\rover",
    "bel\u{7}",
    "nul\u{0}x",
    "bs\u{8}\u{8}",
    "del\u{7f}",
    "c1csi\u{9b}31m",
    "c1osc\u{9d}0;x\u{9c}",
    "bidi\u{202e}txt.exe",
    "bidi\u{202a}\u{202b}\u{202c}\u{202d}",
    "isolate\u{2066}\u{2067}\u{2068}\u{2069}",
    "newline\nnext",
    "tab\there",
];

/// The class of character that a check looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Danger {
    /// C0 (except the newline that the renderer writes), DEL and C1.
    Control,
    /// The Unicode bidi embedding, override and isolate characters.
    Bidi,
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Return the dangerous characters in `text`. The renderers write `\n`
/// themselves, so a newline is not a finding.
fn dangerous(text: &str, danger: Danger) -> Vec<(usize, char)> {
    text.char_indices()
        .filter(|&(_, c)| match danger {
            Danger::Control => c.is_control() && c != '\n',
            Danger::Bidi => is_bidi(c),
        })
        .collect()
}

#[track_caller]
fn assert_clean(what: &str, text: &str, danger: Danger) {
    let found = dangerous(text, danger);
    assert!(
        found.is_empty(),
        "{what}: {danger:?} characters {found:?} in output:\n{}",
        text.escape_debug()
    );
}

/// Events that carry each payload in each event field that reaches the
/// output: the path of a normal and of a blocked item, the process name,
/// the Unix socket target, the DNS name and the TCP host.
fn crafted_events() -> Vec<WatchEvent> {
    let mut events = Vec::new();
    for (i, p) in PAYLOADS.iter().enumerate() {
        // A created file gives a read-write rule on the directory.
        events.push(fs_ev(
            FsOp::Create,
            format!("{HOME}/.t{i}{p}/new"),
            p,
            Outcome::Allowed,
        ));
        // A read of one file gives a read rule on the file.
        events.push(fs_ev(
            FsOp::Read,
            format!("{HOME}/.r{i}/{p}.conf"),
            p,
            Outcome::Allowed,
        ));
        // An exec gives an execute rule.
        events.push(fs_ev(
            FsOp::Exec,
            format!("/opt/x{i}{p}/bin/{p}"),
            p,
            Outcome::Allowed,
        ));
        // A blocked access gives a blocked item.
        events.push(fs_ev(
            FsOp::Read,
            format!("{HOME}/.ssh/id_{i}{p}"),
            p,
            Outcome::Blocked(GuardClass::Credential),
        ));
        events.push(fs_ev(
            FsOp::Exec,
            format!("/run/wrappers/bin{i}{p}/sudo"),
            p,
            Outcome::Blocked(GuardClass::PrivilegeEscalation),
        ));
        events.push(unix(&format!("@{p}"), p));
        events.push(unix(&format!("{HOME}/.sock{i}{p}"), p));
        events.push(unix(&format!("relative{p}"), p));
        events.push(dns(&format!("{p}.example.com")));
        events.push(connect(&format!("{p}.example.org")));
        events.push(connect(&format!("a{i}.{p}")));
    }
    events.push(connect("1.2.3.4"));
    events.push(connect("[::1]"));
    events
}

fn crafted_summary() -> Summary {
    summarize(&crafted_events(), &ctx())
}

/// The crafted events must reach each section, else the checks below prove
/// nothing.
#[test]
fn p1_crafted_events_reach_each_output_field() {
    let summary = crafted_summary();
    let has_payload = |text: &str| PAYLOADS.iter().any(|p| text.contains(p));
    assert!(summary.items.iter().any(|i| match &i.grant {
        Grant::Fs { path, .. } => has_payload(path),
        Grant::Domain(_) => false,
    }));
    assert!(summary
        .items
        .iter()
        .any(|i| i.blocked.is_some() && has_payload(&i.reason)));
    assert!(summary.stats.unix_sockets.iter().any(|s| has_payload(s)));
}

fn terminal_text(summary: &Summary) -> Result<String, pent_profile::ProfileNameError> {
    let profile = name("tool")?;
    let header = WatchHeader {
        name: &profile,
        source: DraftSource::WatchRuns(1),
    };
    Ok(format!(
        "{}{}",
        render_header(summary, &header),
        render_terminal(summary, &header)
    ))
}

fn review_text(summary: &Summary) -> Result<String, std::io::Error> {
    let mut out = Vec::new();
    review(summary, "a\na\na\na\na\n".as_bytes(), &mut out)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn draft_text(summary: &Summary) -> Result<String, pent_profile::ProfileNameError> {
    let doc = summary.to_doc(&all_indices(summary));
    Ok(render_draft(&name("tool")?, 1, &doc, summary))
}

fn profile_text(summary: &Summary) -> String {
    let doc = summary.to_doc(&all_indices(summary));
    render_profile(&doc, &Reasons::from_summary(summary))
}

#[test]
fn p1_terminal_summary_has_no_control_characters() -> TestResult {
    assert_clean(
        "render_terminal",
        &terminal_text(&crafted_summary())?,
        Danger::Control,
    );
    Ok(())
}

#[test]
fn p1_terminal_summary_has_no_bidi_characters() -> TestResult {
    assert_clean(
        "render_terminal",
        &terminal_text(&crafted_summary())?,
        Danger::Bidi,
    );
    Ok(())
}

#[test]
fn p1_review_prompts_have_no_control_characters() -> TestResult {
    assert_clean("review", &review_text(&crafted_summary())?, Danger::Control);
    Ok(())
}

#[test]
fn p1_review_prompts_have_no_bidi_characters() -> TestResult {
    assert_clean("review", &review_text(&crafted_summary())?, Danger::Bidi);
    Ok(())
}

#[test]
fn p1_draft_has_no_control_characters() -> TestResult {
    assert_clean("draft", &draft_text(&crafted_summary())?, Danger::Control);
    Ok(())
}

#[test]
fn p1_draft_has_no_bidi_characters() -> TestResult {
    assert_clean("draft", &draft_text(&crafted_summary())?, Danger::Bidi);
    Ok(())
}

#[test]
fn p1_render_profile_has_no_control_characters() {
    assert_clean(
        "render_profile",
        &profile_text(&crafted_summary()),
        Danger::Control,
    );
}

#[test]
fn p1_render_profile_has_no_bidi_characters() {
    assert_clean(
        "render_profile",
        &profile_text(&crafted_summary()),
        Danger::Bidi,
    );
}

/// Domain names and IP hosts never carry a payload: the summary drops a name
/// with a character outside `[a-z0-9._-]`, and it lists only parsed IP
/// addresses.
#[test]
fn p1_domains_and_ip_hosts_drop_payloads() {
    let summary = crafted_summary();
    for item in &summary.items {
        if let Grant::Domain(d) = &item.grant {
            assert!(
                d.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*')),
                "{d:?}"
            );
        }
    }
    assert_eq!(summary.stats.ip_hosts, vec!["1.2.3.4:443", "[::1]:443"]);
}

// ── Property 2: draft integrity ──────────────────────────────────────────────

/// Path parts that try to break out of a TOML string or a list.
const TOML_PAYLOADS: &[&str] = &[
    "\"]\n[network]\ndomains = [\"*\"]",
    "\"]\r\n[network]\r\ndomains = [\"*\"]\r\n#",
    "x\", \"/\", \"",
    "back\\slash\\",
    "\\\"",
    "\\u0022]",
    "quote\"",
    "]",
    "]]\n[[filesystem]]",
    "# not a comment",
    "[filesystem]",
    "read_write = [\"/\"]",
    "'''",
    "\"\"\"",
    "uni ü 日本 🦀",
    "\u{feff}bom",
    "\u{2028}line\u{2029}para",
    "nul\u{0}",
    "\u{1b}[31m",
    "\u{7f}\u{9b}",
    "\u{202e}bidi",
    "lossy \u{fffd}\u{fffd}",
    "trailing\\",
    "tab\tsep",
];

/// Render the draft of all items in `summary` and check that it parses back
/// to the selected doc, with no extra rule.
#[track_caller]
fn assert_draft_round_trip(summary: &Summary, what: &str) -> TestResult {
    let doc = summary.to_doc(&all_indices(summary));
    let text = render_draft(&name("tool")?, 2, &doc, summary);
    let parsed = ProfileDoc::parse(&text);
    assert!(parsed.is_ok(), "{what}: {parsed:?}\n{text}");
    if let Ok(parsed) = parsed {
        assert_eq!(parsed, doc, "{what}:\n{text}");
    }
    Ok(())
}

#[test]
fn p2_crafted_paths_round_trip_through_the_draft() -> TestResult {
    for (i, p) in TOML_PAYLOADS.iter().enumerate() {
        let events = [
            fs_ev(
                FsOp::Create,
                format!("{HOME}/.c{i}{p}/f"),
                p,
                Outcome::Allowed,
            ),
            fs_ev(
                FsOp::Write,
                format!("{HOME}/.w{i}/{p}"),
                p,
                Outcome::Allowed,
            ),
            fs_ev(FsOp::Read, format!("{HOME}/.r{i}/{p}"), p, Outcome::Allowed),
            fs_ev(
                FsOp::Exec,
                format!("/opt/e{i}{p}/bin/x"),
                p,
                Outcome::Allowed,
            ),
            fs_ev(
                FsOp::Write,
                format!("{HOME}/.bashrc{p}"),
                p,
                Outcome::Blocked(GuardClass::Persistence),
            ),
        ];
        let summary = summarize(&events, &ctx());
        assert!(!summary.items.is_empty(), "{p:?}");
        assert_draft_round_trip(&summary, p)?;
        // No payload can add a domain: the events have no network event.
        let doc = summary.to_doc(&all_indices(&summary));
        let text = render_draft(&name("tool")?, 1, &doc, &summary);
        let parsed = ProfileDoc::parse(&text)?;
        assert!(parsed.network.domains.is_empty(), "{p:?}:\n{text}");
    }
    Ok(())
}

#[test]
fn p2_all_payloads_in_one_draft_round_trip() -> TestResult {
    let events: Vec<WatchEvent> = TOML_PAYLOADS
        .iter()
        .enumerate()
        .flat_map(|(i, p)| {
            [
                allowed(FsOp::Create, format!("{HOME}/.c{i}{p}/f")),
                allowed(FsOp::Read, format!("{HOME}/.r{i}{p}")),
                connect(&format!("h{i}.example.com")),
            ]
        })
        .collect();
    assert_draft_round_trip(&summarize(&events, &ctx()), "all payloads")
}

/// `render_draft_with` gets rules that the summary did not make (from an
/// earlier draft) and reasons from the comments of an earlier draft.
#[test]
fn p2_render_draft_with_arbitrary_rules_round_trips() -> TestResult {
    let mut doc = ProfileDoc::default();
    for p in TOML_PAYLOADS {
        doc.filesystem.read.push(format!("~/r{p}"));
        doc.filesystem.read_write.push(format!("/rw{p}"));
        doc.filesystem.execute.push(format!("~/x{p}"));
        doc.network.domains.push(format!("d{p}.example"));
    }
    let profile = name("tool")?;
    for source in [DraftSource::WatchRuns(3), DraftSource::DeniedReview] {
        let text = render_draft_with(&profile, source, &doc, &Reasons::default());
        assert_eq!(ProfileDoc::parse(&text)?, doc, "\n{text}");
        // A second pass reads the reasons back from the comments.
        let again = render_draft_with(&profile, source, &doc, &Reasons::from_draft(&text));
        assert_eq!(ProfileDoc::parse(&again)?, doc, "\n{again}");
    }
    Ok(())
}

/// Reasons that come back from an earlier draft keep their text. A bare CR
/// in a comment of the earlier draft must not break the new draft.
#[test]
fn p2_reasons_from_an_earlier_draft_keep_the_draft_valid() -> TestResult {
    let mut doc = ProfileDoc::default();
    doc.filesystem.read.push("~/a".to_string());
    doc.filesystem.read.push("~/b".to_string());
    let earlier =
        "[filesystem]\nread = [\n  \"~/a\",  # one\rtwo\n  \"~/b\",  # \u{1b}[31mred\n]\n";
    let reasons = Reasons::from_draft(earlier);
    let text = render_draft_with(&name("tool")?, DraftSource::WatchRuns(1), &doc, &reasons);
    let parsed = ProfileDoc::parse(&text);
    assert!(parsed.is_ok(), "{parsed:?}\n{}", text.escape_debug());
    Ok(())
}

/// A path that is not valid UTF-8 gives no rule: a rule cannot name it. The
/// summary must not panic and must not write a lossy rule that names
/// another path.
#[test]
fn p2_non_utf8_paths_give_no_rule() -> TestResult {
    let mut bytes = format!("{HOME}/.tool/").into_bytes();
    bytes.extend([0xff, 0xfe, b'x']);
    let bad = PathBuf::from(OsString::from_vec(bytes));
    let events = [
        allowed(FsOp::Create, bad.join("f")),
        allowed(FsOp::Read, bad.clone()),
        allowed(FsOp::Write, bad.clone()),
    ];
    let summary = summarize(&events, &ctx());
    for item in &summary.items {
        if let Grant::Fs { path, .. } = &item.grant {
            assert!(!path.contains('\u{fffd}'), "{path:?}");
        }
    }
    assert_draft_round_trip(&summary, "non-UTF-8")
}

// ── Property 3: grouping limits ──────────────────────────────────────────────

/// The directories that must never get a rule, in the form of the draft.
fn forbidden_rules() -> BTreeSet<String> {
    [
        "/",
        "/home",
        "~",
        "~/.config",
        "~/.local",
        "~/.local/share",
        "~/.local/state",
        "~/.cache",
        "~/.ssh",
        "~/Library",
        "~/Library/Application Support",
        "~/Library/Caches",
        "~/Library/Preferences",
        // The parent of the workspace.
        "~/work",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Return the rules of `summary` that are forbidden or that have a `..`
/// component.
fn bad_rules(summary: &Summary) -> Vec<String> {
    let forbidden = forbidden_rules();
    summary
        .items
        .iter()
        .filter_map(|item| match &item.grant {
            Grant::Fs { access, path } => {
                let dotdot = Path::new(path)
                    .components()
                    .any(|c| c == Component::ParentDir);
                (forbidden.contains(path) || dotdot).then(|| format!("{access:?} {path}"))
            }
            Grant::Domain(_) => None,
        })
        .collect()
}

/// The absolute forms of the broad directories that the generators use.
const BROAD_DIRS: &[&str] = &[
    "/home/u",
    "/home/u/.config",
    "/home/u/.local",
    "/home/u/.local/share",
    "/home/u/.local/state",
    "/home/u/.cache",
    "/home/u/Library",
    "/home/u/Library/Caches",
];

const ALL_OPS: [FsOp; 5] = [
    FsOp::Read,
    FsOp::Write,
    FsOp::Create,
    FsOp::Delete,
    FsOp::Exec,
];

/// Many files and directories below the broad directories, with each
/// operation. Grouping must use the child directory, never the broad one.
#[test]
fn p3_many_entries_below_broad_dirs_do_not_widen() {
    for dir in BROAD_DIRS {
        for op in ALL_OPS {
            let events: Vec<WatchEvent> = (0..300)
                .flat_map(|i| {
                    [
                        allowed(op, format!("{dir}/f{i}")),
                        allowed(op, format!("{dir}/d{i}/f")),
                        allowed(op, format!("{dir}/d{i}/sub/f")),
                    ]
                })
                .collect();
            let summary = summarize(&events, &ctx());
            let bad = bad_rules(&summary);
            assert!(bad.is_empty(), "{dir} {op:?}: {bad:?}");
        }
    }
}

/// Mixed operations in one session, many runs with different seeds.
#[test]
fn p3_mixed_generated_sessions_do_not_widen() {
    let names = ["a", "b", "c", "lock", ".tmp", "x.json"];
    for seed in 0..64usize {
        let mut events = Vec::new();
        for i in 0..200usize {
            let k = seed.wrapping_mul(31).wrapping_add(i.wrapping_mul(17));
            let dir = BROAD_DIRS[k % BROAD_DIRS.len()];
            let op = ALL_OPS[(k / 3) % ALL_OPS.len()];
            let leaf = names[(k / 7) % names.len()];
            let path = match k % 3 {
                0 => format!("{dir}/{leaf}{i}"),
                1 => format!("{dir}/p{}/{leaf}", i % 9),
                _ => format!("{dir}/p{}/q{}/{leaf}", i % 5, i % 4),
            };
            events.push(allowed(op, path));
        }
        let summary = summarize(&events, &ctx());
        let bad = bad_rules(&summary);
        assert!(bad.is_empty(), "seed {seed}: {bad:?}");
    }
}

/// One access on the broad directory itself: `opendir(~)`, `mkdir -p
/// ~/.config/x` (which also tries `mkdir ~/.config`), a delete, and a path
/// with `..` that normalizes to a broad directory.
#[test]
fn p3_one_access_on_a_broad_dir_gives_no_rule() {
    let mut failures = Vec::new();
    for dir in BROAD_DIRS.iter().chain(["/", "/home"].iter()) {
        for op in ALL_OPS {
            for path in [dir.to_string(), format!("{dir}/x/.."), format!("{dir}/.")] {
                let summary = summarize(&[allowed(op, path.clone())], &ctx());
                let bad = bad_rules(&summary);
                if !bad.is_empty() {
                    failures.push(format!("{op:?} {path} -> {bad:?}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The files in `~/.ssh` that a normal ssh or git session reads. Four of
/// them in one directory start the grouping, and a read rule on `~/.ssh`
/// includes the private keys.
#[test]
fn p3_reads_in_ssh_dir_do_not_widen_to_the_dir() {
    let events: Vec<WatchEvent> = [
        "config",
        "known_hosts",
        "known_hosts.old",
        "id_ed25519.pub",
        "authorized_keys",
    ]
    .iter()
    .map(|f| {
        fs_ev(
            FsOp::Read,
            format!("{HOME}/.ssh/{f}"),
            "ssh",
            Outcome::Allowed,
        )
    })
    .collect();
    let summary = summarize(&events, &ctx());
    let bad = bad_rules(&summary);
    assert!(bad.is_empty(), "{bad:?}");
}

/// Hundreds of entries in `~/.ssh`, with each operation.
#[test]
fn p3_many_entries_in_ssh_dir_do_not_widen() {
    let mut failures = Vec::new();
    for op in ALL_OPS {
        let events: Vec<WatchEvent> = (0..300)
            .flat_map(|i| {
                [
                    allowed(op, format!("{HOME}/.ssh/k{i}")),
                    allowed(op, format!("{HOME}/.ssh/config.d/h{i}")),
                ]
            })
            .collect();
        let bad = bad_rules(&summarize(&events, &ctx()));
        if !bad.is_empty() {
            failures.push(format!("{op:?}: {bad:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A file that the program creates next to the workspace (for example
/// `../app.orig` or a lock file in the parent) must not give read-write on
/// the parent of the workspace: that rule includes the workspace and each
/// sibling repository.
#[test]
fn p3_create_in_workspace_parent_gives_no_parent_rule() {
    let mut failures = Vec::new();
    for op in [FsOp::Create, FsOp::Delete] {
        let summary = summarize(&[allowed(op, format!("{HOME}/work/app.orig"))], &ctx());
        let bad = bad_rules(&summary);
        if !bad.is_empty() {
            failures.push(format!("{op:?}: {bad:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Reads and writes in the workspace parent do not group on it (regression
/// test for the existing check).
#[test]
fn p3_reads_and_writes_in_workspace_parent_do_not_group() {
    for op in [FsOp::Read, FsOp::Write] {
        let events: Vec<WatchEvent> = (0..50)
            .map(|i| allowed(op, format!("{HOME}/work/other{i}/README.md")))
            .chain((0..50).map(|i| allowed(op, format!("{HOME}/work/f{i}"))))
            .collect();
        let bad = bad_rules(&summarize(&events, &ctx()));
        assert!(bad.is_empty(), "{op:?}: {bad:?}");
    }
}

/// No rule keeps a `..` component, and `..` cannot climb above `/`.
#[test]
fn p3_rules_never_have_parent_components() {
    let events: Vec<WatchEvent> = [
        "/home/u/.tool/../../../../../etc/shadow",
        "/home/u/.tool/a/../b/../../.tool2/x",
        "/../../home/u/.tool3/y",
        "/home/u/.tool4/./././z",
        "/home/u/.tool5/..hidden/f",
    ]
    .iter()
    .flat_map(|p| ALL_OPS.map(|op| allowed(op, *p)))
    .collect();
    let summary = summarize(&events, &ctx());
    for item in &summary.items {
        if let Grant::Fs { path, .. } = &item.grant {
            assert!(
                !Path::new(path)
                    .components()
                    .any(|c| c == Component::ParentDir),
                "{path}"
            );
        }
    }
}

/// Return the wildcards that the summary makes for three or more names
/// below `suffix`.
fn wildcards_below(suffix: &str) -> Vec<String> {
    let events: Vec<WatchEvent> = (0..5)
        .flat_map(|i| {
            [
                connect(&format!("tenant{i}.{suffix}")),
                connect(&format!("api.tenant{i}.{suffix}")),
            ]
        })
        .collect();
    summarize(&events, &ctx())
        .items
        .into_iter()
        .filter_map(|item| match item.grant {
            Grant::Domain(d) if d.starts_with("*.") => Some(d),
            _ => None,
        })
        .filter(|d| {
            let base = d.trim_start_matches("*.");
            // A wildcard on the suffix or on a parent of the suffix covers
            // other owners. `*.tenantN.suffix` is fine.
            suffix == base || suffix.ends_with(&format!(".{base}"))
        })
        .collect()
}

/// The multi-label suffixes that the subset has: no wildcard on them.
#[test]
fn p3_no_wildcard_on_public_suffixes_in_the_subset() {
    for suffix in [
        "co.uk",
        "com.au",
        "github.io",
        "githubusercontent.com",
        "gitlab.io",
        "herokuapp.com",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "workers.dev",
        "appspot.com",
        "web.app",
        "firebaseapp.com",
        "run.app",
        "fly.dev",
        "onrender.com",
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "readthedocs.io",
        "blob.core.windows.net",
        "azurewebsites.net",
        "cloudfront.net",
        "s3.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "elb.amazonaws.com",
        "glitch.me",
        "repl.co",
        "deno.dev",
    ] {
        assert!(!psl::wildcard_allowed(suffix), "{suffix}");
        let w = wildcards_below(suffix);
        assert!(w.is_empty(), "{suffix}: {w:?}");
    }
}

/// The single-label suffixes: no wildcard on a TLD.
#[test]
fn p3_no_wildcard_on_a_tld() {
    for tld in ["com", "org", "io", "dev", "app", "xyz", "uk"] {
        assert!(!psl::wildcard_allowed(tld), "{tld}");
        assert!(psl::registrable_domain(tld).is_none(), "{tld}");
    }
}

/// Public suffixes from <https://publicsuffix.org> (private section) that
/// give one name to each customer and that the subset does not have. For
/// each one, the summary makes `*.<registrable>` from three tenants, and
/// that wildcard allows all other customers of the service.
const MISSING_PUBLIC_SUFFIXES: &[&str] = &[
    "trycloudflare.com",
    "loca.lt",
    "ngrok.dev",
    "ngrok-free.dev",
    "duckdns.org",
    "ddns.net",
    "hopto.org",
    "dynv6.net",
    "mooo.com",
    "gitpod.io",
    "app.github.dev",
    "githubpreview.dev",
    "csb.app",
    "webcontainer.io",
    "replit.dev",
    "hf.space",
    "streamlit.app",
    "myshopify.com",
    "ts.net",
    "supabase.co",
    "amplifyapp.com",
    "on.aws",
    "azurecontainer.io",
    "freetls.fastly.net",
    "edgecompute.app",
    "neocities.org",
    "codeberg.page",
    "srht.site",
    "gitbook.io",
    "translate.goog",
];

#[test]
fn p3_no_wildcard_on_common_public_suffix_services() {
    let widened: Vec<(&str, Vec<String>)> = MISSING_PUBLIC_SUFFIXES
        .iter()
        .map(|s| (*s, wildcards_below(s)))
        .filter(|(_, w)| !w.is_empty())
        .collect();
    assert!(widened.is_empty(), "{widened:#?}");
}

// ── Property 4: guard coverage ───────────────────────────────────────────────

/// One row of the guard table: a path below the home directory (or an
/// absolute binary path for `ExecName`), the access, and the class that the
/// guard must give.
type GuardRow = (&'static str, GuardAccess, Option<GuardClass>);

fn guard_class(rel: &str, access: GuardAccess) -> Option<GuardClass> {
    let home = Path::new(HOME);
    let path = if rel.starts_with('/') {
        PathBuf::from(rel)
    } else {
        home.join(rel)
    };
    classify(&guard_rules(home), &path, access)
}

/// Return the rows whose class is not the expected class.
fn guard_mismatches(rows: &[GuardRow]) -> Vec<String> {
    rows.iter()
        .filter_map(|&(rel, access, expected)| {
            let got = guard_class(rel, access);
            (got != expected)
                .then(|| format!("{rel} {access:?}: expected {expected:?}, got {got:?}"))
        })
        .collect()
}

#[track_caller]
fn assert_guard(rows: &[GuardRow]) {
    let bad = guard_mismatches(rows);
    assert!(bad.is_empty(), "{bad:#?}");
}

use GuardAccess::{ExecName, Read as R, Write as W};
use GuardClass::{Credential as Cred, PentFiles as Pent, Persistence as Pers};

/// The locations that the design and the guard list name. This is a
/// regression test: each row holds now.
#[test]
fn p4_guard_covers_the_named_locations() {
    assert_guard(&[
        // Credentials (read).
        (".ssh/id_ed25519", R, Some(Cred)),
        (".ssh/id_rsa", R, Some(Cred)),
        (".ssh/id_ecdsa_sk", R, Some(Cred)),
        (".ssh/id_ed25519.pub", R, None),
        (".ssh/known_hosts", R, None),
        (".aws/credentials", R, Some(Cred)),
        (".aws/sso/cache/x.json", R, Some(Cred)),
        (".netrc", R, Some(Cred)),
        (".git-credentials", R, Some(Cred)),
        (".config/gh/hosts.yml", R, Some(Cred)),
        (".kube/config", R, Some(Cred)),
        (".docker/config.json", R, Some(Cred)),
        (".npmrc", R, Some(Cred)),
        (".pypirc", R, Some(Cred)),
        (".cargo/credentials.toml", R, Some(Cred)),
        (".cargo/credentials", R, Some(Cred)),
        (".gem/credentials", R, Some(Cred)),
        (
            ".config/gcloud/application_default_credentials.json",
            R,
            Some(Cred),
        ),
        (".azure/msal_token_cache.json", R, Some(Cred)),
        (".gnupg/private-keys-v1.d/x.key", R, Some(Cred)),
        (".password-store/x.gpg", R, Some(Cred)),
        (".local/share/keyrings/login.keyring", R, Some(Cred)),
        (".local/share/kwalletd/kdewallet.kwl", R, Some(Cred)),
        (".mozilla/firefox/x.default/logins.json", R, Some(Cred)),
        (".config/google-chrome/Default/Login Data", R, Some(Cred)),
        (".config/chromium/Default/Cookies", R, Some(Cred)),
        (
            ".config/BraveSoftware/Brave-Browser/Default/Login Data",
            R,
            Some(Cred),
        ),
        ("Library/Keychains/login.keychain-db", R, Some(Cred)),
        ("Library/Cookies/Cookies.binarycookies", R, Some(Cred)),
        ("Library/Safari/History.db", R, Some(Cred)),
        (
            "Library/Application Support/Google/Chrome/Default/Login Data",
            R,
            Some(Cred),
        ),
        (
            "Library/Application Support/Firefox/Profiles/x/logins.json",
            R,
            Some(Cred),
        ),
        // Persistence (write).
        (".bashrc", W, Some(Pers)),
        (".bash_profile", W, Some(Pers)),
        (".bash_login", W, Some(Pers)),
        (".bash_logout", W, Some(Pers)),
        (".profile", W, Some(Pers)),
        (".zshrc", W, Some(Pers)),
        (".zprofile", W, Some(Pers)),
        (".zshenv", W, Some(Pers)),
        (".zlogin", W, Some(Pers)),
        (".ssh/authorized_keys", W, Some(Pers)),
        (".ssh/config", W, Some(Pers)),
        (".ssh/rc", W, Some(Pers)),
        (".gitconfig", W, Some(Pers)),
        (".config/git/config", W, Some(Pers)),
        (".config/fish/config.fish", W, Some(Pers)),
        (".config/autostart/x.desktop", W, Some(Pers)),
        (".config/systemd/user/x.service", W, Some(Pers)),
        (".config/environment.d/x.conf", W, Some(Pers)),
        (".local/bin/git", W, Some(Pers)),
        ("Library/LaunchAgents/x.plist", W, Some(Pers)),
        // Persistence is write only: a read of an rc file is normal.
        (".bashrc", R, None),
        // Pent's own files (write), at the default locations.
        (".config/pent/trusted.toml", W, Some(Pent)),
        (".config/pent/profiles/x.toml", W, Some(Pent)),
        (".local/state/pent/drafts/x.toml", W, Some(Pent)),
        // Privilege escalation (exec by name, anywhere).
        (
            "/usr/bin/sudo",
            ExecName,
            Some(GuardClass::PrivilegeEscalation),
        ),
        (
            "/run/wrappers/bin/su",
            ExecName,
            Some(GuardClass::PrivilegeEscalation),
        ),
        (
            "/usr/bin/pkexec",
            ExecName,
            Some(GuardClass::PrivilegeEscalation),
        ),
        (
            "/usr/bin/doas",
            ExecName,
            Some(GuardClass::PrivilegeEscalation),
        ),
        (
            "/usr/bin/run0",
            ExecName,
            Some(GuardClass::PrivilegeEscalation),
        ),
    ]);
}

#[test]
fn p4_gap_xdg_git_credentials() {
    assert_guard(&[(".config/git/credentials", R, Some(Cred))]);
}

#[test]
fn p4_gap_terraform_and_vault_tokens() {
    assert_guard(&[
        (".terraform.d/credentials.tfrc.json", R, Some(Cred)),
        (".vault-token", R, Some(Cred)),
    ]);
}

#[test]
fn p4_gap_ssh_keys_with_other_names() {
    assert_guard(&[
        (".ssh/github_rsa", R, Some(Cred)),
        (".ssh/work.pem", R, Some(Cred)),
        (".ssh/deploy_key", R, Some(Cred)),
        (".ssh/keys/id_ed25519", R, Some(Cred)),
    ]);
}

#[test]
fn p4_gap_other_credential_stores() {
    assert_guard(&[
        (".config/op/config", R, Some(Cred)),
        (".config/containers/auth.json", R, Some(Cred)),
        (".config/rclone/rclone.conf", R, Some(Cred)),
        (".pgpass", R, Some(Cred)),
        (".my.cnf", R, Some(Cred)),
        (".s3cfg", R, Some(Cred)),
        (".oci/config", R, Some(Cred)),
        (".config/sops/age/keys.txt", R, Some(Cred)),
        (".config/hub", R, Some(Cred)),
        (".config/glab-cli/config.yml", R, Some(Cred)),
    ]);
}

#[test]
fn p4_gap_shell_history() {
    assert_guard(&[
        (".bash_history", R, Some(Cred)),
        (".zsh_history", R, Some(Cred)),
        (".local/share/fish/fish_history", R, Some(Cred)),
        (".python_history", R, Some(Cred)),
        (".psql_history", R, Some(Cred)),
    ]);
}

#[test]
fn p4_gap_other_shell_rc_files() {
    assert_guard(&[
        (".bash_aliases", W, Some(Pers)),
        (".zlogout", W, Some(Pers)),
        (".config/nushell/config.nu", W, Some(Pers)),
        (".xonshrc", W, Some(Pers)),
        (".kshrc", W, Some(Pers)),
        (".mkshrc", W, Some(Pers)),
        (".tcshrc", W, Some(Pers)),
        (".cshrc", W, Some(Pers)),
        (".config/zsh/.zshrc", W, Some(Pers)),
    ]);
}

#[test]
fn p4_gap_session_startup_files() {
    assert_guard(&[
        (".pam_environment", W, Some(Pers)),
        (".xprofile", W, Some(Pers)),
        (".xinitrc", W, Some(Pers)),
        (".xsession", W, Some(Pers)),
        (".xsessionrc", W, Some(Pers)),
        (".ssh/environment", W, Some(Pers)),
    ]);
}

#[test]
fn p4_gap_other_path_directories() {
    assert_guard(&[
        ("bin/git", W, Some(Pers)),
        (".cargo/bin/git", W, Some(Pers)),
        ("go/bin/git", W, Some(Pers)),
        (".npm-global/bin/git", W, Some(Pers)),
    ]);
}

#[test]
fn p4_gap_tool_configs_that_run_code() {
    assert_guard(&[
        (
            ".local/lib/python3.12/site-packages/usercustomize.py",
            W,
            Some(Pers),
        ),
        (
            ".local/lib/python3.12/site-packages/evil.pth",
            W,
            Some(Pers),
        ),
        (".vimrc", W, Some(Pers)),
        (".config/nvim/init.lua", W, Some(Pers)),
        (".emacs.d/init.el", W, Some(Pers)),
        (".cargo/config.toml", W, Some(Pers)),
        (".npmrc", W, Some(Pers)),
        (".git-templates/hooks/post-checkout", W, Some(Pers)),
        (".config/git/hooks/pre-commit", W, Some(Pers)),
        (".config/direnv/direnvrc", W, Some(Pers)),
    ]);
}

#[test]
fn p4_gap_schedulers() {
    assert_guard(&[
        ("/usr/bin/crontab", ExecName, Some(Pers)),
        ("/usr/bin/at", ExecName, Some(Pers)),
        ("/usr/bin/systemd-run", ExecName, Some(Pers)),
        (".config/cron/x", W, Some(Pers)),
    ]);
}

// ── Property 5 (part): profile names ─────────────────────────────────────────

#[test]
fn p5_profile_names_reject_unsafe_text() {
    let long = "a".repeat(65);
    for bad in [
        "",
        ".",
        "..",
        ".hidden",
        "../x",
        "a/b",
        "/abs",
        "a\\b",
        "a\0b",
        "a\nb",
        "a\rb",
        "a\u{1b}b",
        "a\u{7f}",
        "a\u{9b}",
        "a\u{202e}b",
        "ü",
        "a b",
        "a:b",
        "a*",
        long.as_str(),
    ] {
        assert!(bad.parse::<ProfileName>().is_err(), "{:?}", bad);
    }
    for good in ["claude", "npm-test", "a.b_c-1", "x"] {
        assert!(good.parse::<ProfileName>().is_ok(), "{good:?}");
    }
    // The basename of a command cannot climb out of the store.
    for command in ["..", "/", "a/..", "x/\u{1b}"] {
        assert!(ProfileName::from_command(command).is_err(), "{command:?}");
    }
    assert_eq!(
        ProfileName::from_command("../../bin/claude").map(String::from),
        Ok("claude".to_string())
    );
}

// ── Property 6: review input handling ────────────────────────────────────────

/// A summary with one item in each normal section and two blocked items.
fn review_summary() -> Summary {
    let events = [
        allowed(FsOp::Create, format!("{HOME}/.tool/a")),
        allowed(FsOp::Read, format!("{HOME}/.toolrc")),
        allowed(FsOp::Exec, "/opt/tool/bin/tool"),
        connect("api.example.com"),
        fs_ev(
            FsOp::Read,
            format!("{HOME}/.ssh/id_ed25519"),
            "ssh",
            Outcome::Blocked(GuardClass::Credential),
        ),
        fs_ev(
            FsOp::Write,
            format!("{HOME}/.bashrc"),
            "sh",
            Outcome::Blocked(GuardClass::Persistence),
        ),
    ];
    summarize(&events, &ctx())
}

fn blocked_indices(summary: &Summary) -> Vec<usize> {
    summary
        .items
        .iter()
        .enumerate()
        .filter(|(_, i)| i.blocked.is_some())
        .map(|(i, _)| i)
        .collect()
}

fn selected_blocked(summary: &Summary, input: &[u8]) -> Result<Vec<usize>, std::io::Error> {
    let mut out = Vec::new();
    let selection = review(summary, input, &mut out)?;
    let blocked = blocked_indices(summary);
    Ok(selection
        .indices
        .into_iter()
        .filter(|i| blocked.contains(i))
        .collect())
}

#[test]
fn p6_fixture_has_blocked_items() {
    let summary = review_summary();
    assert_eq!(blocked_indices(&summary).len(), 2);
    assert_eq!(summary.items.len(), 6);
}

#[test]
fn p6_eof_and_empty_lines_keep_blocked_items_unselected() -> TestResult {
    let summary = review_summary();
    for input in [
        &b""[..],
        b"\n",
        b"\n\n\n\n\n",
        b"a\na\na\na\n",
        b"a\na\na\na\n\n",
    ] {
        let got = selected_blocked(&summary, input)?;
        assert!(
            got.is_empty(),
            "{:?}: {got:?}",
            String::from_utf8_lossy(input)
        );
    }
    Ok(())
}

#[test]
fn p6_invalid_input_keeps_blocked_items_unselected() -> TestResult {
    let summary = review_summary();
    let garbage: &[&[u8]] = &[
        b"yes\n",
        b"y\n",
        b"0\n",
        b"-1\n",
        b"1-\n",
        b"-\n",
        b"1--2\n",
        b"2-1\n",
        b"3\n",
        b"1,3\n",
        b",,,\n",
        b"1-999999999\n",
        b"999999999-1000000000\n",
        b"18446744073709551615\n",
        b"18446744073709551616\n",
        b"1-18446744073709551615\n",
        b"99999999999999999999999999999999\n",
        b"\xff\xfe\n",
        b"\0\n",
        b"a\x1b\n",
        b"all of them\n",
    ];
    for g in garbage {
        // The four normal sections get "a", then the blocked section gets
        // the garbage line, then EOF.
        let mut input = b"a\na\na\na\n".to_vec();
        input.extend_from_slice(g);
        let got = selected_blocked(&summary, &input)?;
        assert!(got.is_empty(), "{:?}: {got:?}", String::from_utf8_lossy(g));
    }
    Ok(())
}

#[test]
fn p6_explicit_selection_selects_blocked_items() -> TestResult {
    let summary = review_summary();
    let blocked = blocked_indices(&summary);
    assert_eq!(selected_blocked(&summary, b"a\na\na\na\na\n")?, blocked);
    assert_eq!(selected_blocked(&summary, b"a\na\na\na\n1-2\n")?, blocked);
    assert_eq!(selected_blocked(&summary, b"n\nn\nn\nn\n2\n")?.len(), 1);
    Ok(())
}

/// Huge numbers and ranges, and a long line, must not allocate much memory
/// or take long. The parser rejects a range above the item count before it
/// makes the range.
#[test]
fn p6_huge_ranges_are_fast_and_rejected() -> TestResult {
    let summary = review_summary();
    let mut input = Vec::new();
    for _ in 0..4 {
        input.extend_from_slice(b"1-999999999\n1-18446744073709551615\n");
    }
    // One long line with many numbers.
    input.extend_from_slice("1,".repeat(200_000).as_bytes());
    input.push(b'\n');
    let start = Instant::now();
    let mut out = Vec::new();
    let selection = review(&summary, &input[..], &mut out)?;
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    // The long line selects item 1 of the first section. Each other section
    // gets its default at EOF; the blocked section stays unselected.
    let blocked = blocked_indices(&summary);
    assert!(selection.indices.iter().all(|i| !blocked.contains(i)));
    Ok(())
}

/// A wide read rule from the review is still a normal item: `FsAccess` is
/// part of the public result. This keeps the import of `FsAccess` used and
/// checks that the blocked read item keeps its access.
#[test]
fn p6_blocked_items_keep_their_access() {
    let summary = review_summary();
    let accesses: Vec<FsAccess> = summary
        .items
        .iter()
        .filter(|i| i.blocked.is_some())
        .filter_map(|i| match &i.grant {
            Grant::Fs { access, .. } => Some(*access),
            Grant::Domain(_) => None,
        })
        .collect();
    assert!(accesses.contains(&FsAccess::Read));
    assert!(accesses.contains(&FsAccess::ReadWrite));
}
