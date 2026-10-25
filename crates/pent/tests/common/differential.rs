//! The tables of the differential tests.
//!
//! Pent describes one policy three times: the profile (a TOML document),
//! the summary and the review (the text that pent shows), and the kernel
//! (Landlock, the mounts, the network namespace and the proxy). The three
//! descriptions can disagree. A disagreement is dangerous in both
//! directions: a kernel that allows more than the profile says gives the
//! user a limit that does not exist, and a summary that reports a block
//! that the kernel does not make gives the user a protection that is not
//! there.
//!
//! The tables below are data. One row is one case. To add a case, add one
//! line.
//!
//! The tests that use the tables:
//!
//! | File | Table | Compares |
//! |---|---|---|
//! | `differential_profile_kernel.rs` | [`FS_CASES`] | the profile against the kernel |
//! | `differential_watch_round_trip.rs` | [`WATCH_CASES`] | the summary against the kernel |
//! | `differential_guard.rs` | [`GUARD_CASES`] | `classify` against the kernel |
//! | `differential_network.rs` | [`NET_CASES`] | the DNS answer, the proxy and the profile |
//!
//! A row with `open = Some("DIFF-n")` states a disagreement that pent has
//! today. The normal test skips such a row, and one `#[ignore]` test for
//! each identifier runs it. `docs/security/differential.md` holds the
//! severity, the wrong description and the fix of each identifier.
//!
//! A test file includes this module with
//! `#[path = "common/differential.rs"] mod differential;`, so the module
//! holds no reference to the other test helpers.
#![allow(dead_code)] // each test binary uses a different subset of the tables

use std::path::{Path, PathBuf};

/// The marker that a probe prints first. A test that asserts a denial also
/// needs the proof that the child ran: without this marker, a child that
/// never started passes the test.
pub const RAN: &str = "PENT_CHILD_RAN";

/// The content of each file that a probe reads. The test asserts that this
/// text is in the output, or that it is not.
pub const MARKER: &str = "PENT-SECRET-CONTENT";

/// The text that a probe appends when it writes.
pub const WROTE: &str = "PENT-WROTE";

/// The text that an executable probe prints.
pub const EXECUTED: &str = "PENT-EXECUTED";

/// The text that a Unix socket server sends.
pub const GREETING: &str = "PENT-SOCKET-HELLO";

/// What the program does with the path of a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read the content of the file.
    Read,
    /// Append to the file. The test reads the file on the host after the
    /// run: a write that the overlay discards is not a write.
    Write,
    /// Run the file.
    Execute,
    /// Connect to the Unix socket at the path.
    UnixSocket,
}

/// What a description says about one access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The access works.
    Allow,
    /// The access does not work.
    Deny,
}

impl Verdict {
    /// The word for a message.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// One row of [`FS_CASES`]: a profile, a path and an access.
#[derive(Debug, Clone, Copy)]
pub struct FsCase {
    /// The name of the row. It is in each failure message.
    pub id: &'static str,
    /// The profile text. The test writes it as the draft and trusts it.
    pub profile: &'static str,
    /// The path of the access. A path that starts with `ws/` is below the
    /// workspace; every other path is below the home directory.
    pub target: &'static str,
    /// What the program does with the path.
    pub access: Access,
    /// What the profile says. The test compares it with the kernel.
    pub verdict: Verdict,
    /// True when the path must not exist before the run. The program then
    /// makes it.
    pub make_in_run: bool,
    /// A symbolic link to make before the run: the link and its target,
    /// both below the home directory.
    pub symlink: Option<(&'static str, &'static str)>,
    /// The identifier of the disagreement, when pent has one here.
    pub open: Option<&'static str>,
}

/// The default row. Each row of the table changes only the fields that it
/// needs.
const FS: FsCase = FsCase {
    id: "",
    profile: "",
    target: "",
    access: Access::Read,
    verdict: Verdict::Allow,
    make_in_run: false,
    symlink: None,
    open: None,
};

// ── The profiles of the filesystem table ─────────────────────────────────

/// A rule on one file.
const P_FILE: &str = "[filesystem]\nread = [\"~/data/one.txt\"]\n";
/// A rule on one directory.
const P_DIR: &str = "[filesystem]\nread = [\"~/data\"]\n";
/// A path with a space.
const P_SPACE: &str = "[filesystem]\nread = [\"~/a b.txt\"]\n";
/// A path with a quotation mark.
const P_QUOTE: &str = "[filesystem]\nread = [\"~/q\\\"uote.txt\"]\n";
/// A path with a newline.
const P_NEWLINE: &str = "[filesystem]\nread = [\"~/nl\\nline.txt\"]\n";
/// A path that is not ASCII.
const P_UNICODE: &str = "[filesystem]\nread = [\"~/héllo-日本.txt\"]\n";
/// A rule on a symbolic link.
const P_SYMLINK: &str = "[filesystem]\nread = [\"~/link.txt\"]\n";
/// A relative entry. It resolves against the workspace.
const P_RELATIVE: &str = "[filesystem]\nread = [\"rel.txt\"]\n";
/// The whole home directory.
const P_TILDE: &str = "[filesystem]\nread = [\"~\"]\n";
/// A read-only directory.
const P_RO: &str = "[filesystem]\nread = [\"~/ro\"]\n";
/// A read-write directory.
const P_RW: &str = "[filesystem]\nread_write = [\"~/rw\"]\n";
/// A read-write directory that does not exist when the run starts.
const P_MADE: &str = "[filesystem]\nread_write = [\"~/made\"]\n";
/// A directory of executables.
const P_EXEC: &str = "[filesystem]\nexecute = [\"~/bin\"]\n";
/// The same directory with a read rule only.
const P_EXEC_READ_ONLY: &str = "[filesystem]\nread = [\"~/bin\"]\n";
/// One Unix socket of a directory.
const P_SOCKET: &str =
    "[filesystem]\nread = [\"~/sock\"]\nunix_sockets = [\"~/sock/allowed.sock\"]\n";
/// A rule that covers another rule.
const P_COVER: &str = "[filesystem]\nread_write = [\"~/cov\"]\nread = [\"~/cov/f.txt\"]\n";
/// A profile with no rule.
const P_EMPTY: &str = "";
/// A profile with a network rule only.
const P_NET_ONLY: &str = "[network]\ndomains = [\"example.com\"]\n";

/// The profile against the kernel: one row for each profile shape and each
/// access kind.
///
/// Each shape has a row that the profile allows and a row that the profile
/// denies, so each denial has its positive control in the same table.
pub const FS_CASES: &[FsCase] = &[
    // A rule on one file.
    FsCase {
        id: "file-rule-the-named-file",
        profile: P_FILE,
        target: "data/one.txt",
        ..FS
    },
    FsCase {
        id: "file-rule-a-sibling",
        profile: P_FILE,
        target: "data/two.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A rule on one directory.
    FsCase {
        id: "dir-rule-a-child",
        profile: P_DIR,
        target: "data/one.txt",
        ..FS
    },
    FsCase {
        id: "dir-rule-a-deep-child",
        profile: P_DIR,
        target: "data/x/y/z.txt",
        ..FS
    },
    FsCase {
        id: "dir-rule-another-directory",
        profile: P_DIR,
        target: "other/one.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A path with a space.
    FsCase {
        id: "space-the-named-file",
        profile: P_SPACE,
        target: "a b.txt",
        ..FS
    },
    FsCase {
        id: "space-a-sibling",
        profile: P_SPACE,
        target: "a c.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A path with a quotation mark.
    FsCase {
        id: "quote-the-named-file",
        profile: P_QUOTE,
        target: "q\"uote.txt",
        ..FS
    },
    FsCase {
        id: "quote-a-sibling",
        profile: P_QUOTE,
        target: "quiet.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A path with a newline.
    FsCase {
        id: "newline-the-named-file",
        profile: P_NEWLINE,
        target: "nl\nline.txt",
        ..FS
    },
    FsCase {
        id: "newline-a-sibling",
        profile: P_NEWLINE,
        target: "nlXline.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A path that is not ASCII.
    FsCase {
        id: "unicode-the-named-file",
        profile: P_UNICODE,
        target: "héllo-日本.txt",
        ..FS
    },
    FsCase {
        id: "unicode-a-sibling",
        profile: P_UNICODE,
        target: "hello-nippon.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A symbolic link.
    FsCase {
        id: "symlink-the-named-link",
        profile: P_SYMLINK,
        target: "link.txt",
        symlink: Some(("link.txt", "real.txt")),
        open: Some("DIFF-2"),
        ..FS
    },
    FsCase {
        id: "symlink-the-target-by-its-own-name",
        profile: P_SYMLINK,
        target: "real.txt",
        verdict: Verdict::Deny,
        symlink: Some(("link.txt", "real.txt")),
        ..FS
    },
    // A relative entry.
    FsCase {
        id: "relative-the-named-file-in-the-workspace",
        profile: P_RELATIVE,
        target: "ws/rel.txt",
        ..FS
    },
    FsCase {
        id: "relative-the-same-name-in-the-home-directory",
        profile: P_RELATIVE,
        target: "rel.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // The whole home directory.
    FsCase {
        id: "tilde-a-file-of-the-home-directory",
        profile: P_TILDE,
        target: "secret.txt",
        ..FS
    },
    FsCase {
        id: "tilde-does-not-reach-the-root",
        profile: P_TILDE,
        target: "../outside.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    // A path that the program makes.
    FsCase {
        id: "made-in-the-run-write",
        profile: P_MADE,
        target: "made/sub/n.txt",
        access: Access::Write,
        make_in_run: true,
        ..FS
    },
    FsCase {
        id: "made-in-the-run-outside-the-rule",
        profile: P_MADE,
        target: "unmade/sub/n.txt",
        access: Access::Write,
        verdict: Verdict::Deny,
        make_in_run: true,
        ..FS
    },
    // Read.
    FsCase {
        id: "read-rule-read",
        profile: P_RO,
        target: "ro/f.txt",
        ..FS
    },
    FsCase {
        id: "read-rule-write",
        profile: P_RO,
        target: "ro/f.txt",
        access: Access::Write,
        verdict: Verdict::Deny,
        ..FS
    },
    // Read and write.
    FsCase {
        id: "read-write-rule-read",
        profile: P_RW,
        target: "rw/f.txt",
        ..FS
    },
    FsCase {
        id: "read-write-rule-write",
        profile: P_RW,
        target: "rw/f.txt",
        access: Access::Write,
        ..FS
    },
    // A `read_write` rule on a directory keeps the right to run a file of
    // that directory. Only a `read` rule loses it (DIFF-4).
    FsCase {
        id: "read-write-rule-run",
        profile: P_RW,
        target: "rw/f.txt",
        access: Access::Execute,
        ..FS
    },
    // Execute.
    FsCase {
        id: "execute-rule-run",
        profile: P_EXEC,
        target: "bin/tool",
        access: Access::Execute,
        ..FS
    },
    FsCase {
        id: "execute-rule-read",
        profile: P_EXEC,
        target: "bin/tool",
        ..FS
    },
    FsCase {
        id: "execute-rule-write",
        profile: P_EXEC,
        target: "bin/tool",
        access: Access::Write,
        verdict: Verdict::Deny,
        ..FS
    },
    FsCase {
        id: "read-rule-does-not-run",
        profile: P_EXEC_READ_ONLY,
        target: "bin/tool",
        access: Access::Execute,
        verdict: Verdict::Deny,
        ..FS
    },
    // A Unix socket.
    FsCase {
        id: "unix-socket-the-named-socket",
        profile: P_SOCKET,
        target: "sock/allowed.sock",
        access: Access::UnixSocket,
        ..FS
    },
    FsCase {
        id: "unix-socket-another-socket-of-the-same-directory",
        profile: P_SOCKET,
        target: "sock/other.sock",
        access: Access::UnixSocket,
        verdict: Verdict::Deny,
        ..FS
    },
    // A rule that covers another rule.
    FsCase {
        id: "cover-the-inner-file-reads",
        profile: P_COVER,
        target: "cov/f.txt",
        ..FS
    },
    FsCase {
        id: "cover-the-wider-rule-wins-for-the-write",
        profile: P_COVER,
        target: "cov/f.txt",
        access: Access::Write,
        ..FS
    },
    FsCase {
        id: "cover-a-sibling-of-the-inner-file-writes",
        profile: P_COVER,
        target: "cov/other.txt",
        access: Access::Write,
        ..FS
    },
    // A profile with no rule.
    FsCase {
        id: "empty-profile-the-home-directory",
        profile: P_EMPTY,
        target: "secret.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    FsCase {
        id: "empty-profile-the-workspace-stays-read-write",
        profile: P_EMPTY,
        target: "ws/w.txt",
        access: Access::Write,
        ..FS
    },
    // A profile with a network rule only.
    FsCase {
        id: "network-only-profile-the-home-directory",
        profile: P_NET_ONLY,
        target: "secret.txt",
        verdict: Verdict::Deny,
        ..FS
    },
    FsCase {
        id: "network-only-profile-the-workspace-stays-read-write",
        profile: P_NET_ONLY,
        target: "ws/w.txt",
        access: Access::Write,
        ..FS
    },
];

// ── The summary against the kernel ───────────────────────────────────────

/// One row of [`WATCH_CASES`]: a program, the rules that it needs, and the
/// rules that the pipeline may add.
#[derive(Debug, Clone, Copy)]
pub struct WatchCase {
    /// The name of the row.
    pub id: &'static str,
    /// The files that exist before the run: the path below the home
    /// directory, and the content. A path that ends with `/x` and the mode
    /// `exec` becomes an executable file; see [`WatchCase::executables`].
    pub setup: &'static [(&'static str, &'static str)],
    /// The files of `setup` that get the mode 0755.
    pub executables: &'static [&'static str],
    /// The symbolic links that exist before the run: the link and its
    /// target, both below the home directory.
    pub links: &'static [(&'static str, &'static str)],
    /// The shell script of the program. `$1` is the home directory.
    pub script: &'static str,
    /// The rules that the draft must have. The program really needs each
    /// one of them.
    pub needs: &'static [&'static str],
    /// The rule prefixes that the draft may have. A shell reads its own
    /// start files, and that is not a defect of the pipeline. Keep this
    /// list short: each entry hides a difference.
    pub allowed_extra: &'static [&'static str],
    /// The identifier of the disagreement, when pent has one here.
    pub open: Option<&'static str>,
}

/// The rule prefixes that a shell and the system tools add to every draft.
pub const SHELL_NOISE: &[&str] = &[
    "~/.bash",
    "~/.cache",
    "~/.CFUserTextEncoding",
    "~/.config/fish",
    "~/.local/share",
    "~/.profile",
    "~/.terminfo",
    "~/.zsh",
    "~/Library",
];

/// The default row.
const WATCH: WatchCase = WatchCase {
    id: "",
    setup: &[],
    executables: &[],
    links: &[],
    script: "true",
    needs: &[],
    allowed_extra: SHELL_NOISE,
    open: None,
};

/// The round trip of the whole flow: watch, trust, run, and no denial.
pub const WATCH_CASES: &[WatchCase] = &[
    WatchCase {
        id: "read-one-file",
        setup: &[(".apprc", "cfg\n")],
        script: r#"cat "$1/.apprc" > /dev/null"#,
        needs: &["~/.apprc"],
        ..WATCH
    },
    WatchCase {
        id: "create-and-edit-in-one-directory",
        setup: &[(".appdata/f.txt", "d\n")],
        script: r#"echo more >> "$1/.appdata/f.txt"; echo new > "$1/.appdata/n.txt""#,
        needs: &["~/.appdata"],
        ..WATCH
    },
    WatchCase {
        id: "write-with-an-atomic-rename",
        setup: &[(".appstate/cur.json", "{}\n")],
        script: r#"echo '{"a":1}' > "$1/.appstate/new"; mv "$1/.appstate/new" "$1/.appstate/cur.json""#,
        needs: &["~/.appstate"],
        ..WATCH
    },
    WatchCase {
        id: "delete-a-file",
        setup: &[(".appdel/old.txt", "x\n"), (".appdel/keep.txt", "k\n")],
        script: r#"rm "$1/.appdel/old.txt""#,
        needs: &["~/.appdel"],
        ..WATCH
    },
    WatchCase {
        id: "four-reads-become-one-directory-rule",
        setup: &[
            (".appcfg/a", "1\n"),
            (".appcfg/b", "2\n"),
            (".appcfg/c", "3\n"),
            (".appcfg/d", "4\n"),
        ],
        script: r#"cat "$1"/.appcfg/a "$1"/.appcfg/b "$1"/.appcfg/c "$1"/.appcfg/d > /dev/null"#,
        needs: &["~/.appcfg"],
        ..WATCH
    },
    WatchCase {
        id: "run-a-tool",
        setup: &[("tools/t", "#!/bin/sh\necho TOOLRAN\n")],
        executables: &["tools/t"],
        script: r#""$1/tools/t" > /dev/null"#,
        needs: &["~/tools"],
        ..WATCH
    },
    WatchCase {
        id: "odd-names",
        setup: &[
            ("a b.txt", "s\n"),
            ("q\"uote.txt", "q\n"),
            ("nl\nline.txt", "n\n"),
            ("héllo-日本.txt", "u\n"),
        ],
        script: r#"cat "$1/a b.txt" "$1/q\"uote.txt" "$1/nl
line.txt" "$1/héllo-日本.txt" > /dev/null"#,
        needs: &[
            "~/a b.txt",
            "~/q\"uote.txt",
            "~/nl\nline.txt",
            "~/héllo-日本.txt",
        ],
        ..WATCH
    },
    WatchCase {
        id: "read-through-a-symbolic-link",
        setup: &[("real.txt", "r\n")],
        links: &[("link.txt", "real.txt")],
        script: r#"cat "$1/link.txt" > /dev/null"#,
        // The recorder sees the link and the target, so the draft needs
        // both: a rule on the link alone gives no access (DIFF-2).
        needs: &["~/link.txt", "~/real.txt"],
        ..WATCH
    },
    WatchCase {
        id: "a-program-that-touches-nothing",
        script: "true",
        needs: &[],
        ..WATCH
    },
];

// ── `classify` against the kernel ────────────────────────────────────────

/// The access of a guard row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardKind {
    /// The program reads the file.
    Read,
    /// The program writes to the file.
    Write,
}

/// One row of [`GUARD_CASES`]: a path, an access and the verdict of
/// `pent_profile::classify`.
#[derive(Debug, Clone, Copy)]
pub struct GuardCase {
    /// The name of the row.
    pub id: &'static str,
    /// The path below the home directory.
    pub path: &'static str,
    /// What the program does with the path.
    pub kind: GuardKind,
    /// The class that `classify` must answer: `credential`, `persistence`,
    /// `pent-files`, or the empty text for "no rule matches".
    pub class: &'static str,
    /// A symbolic link to make before the run: the link and its target,
    /// both below the home directory. The test makes the target as a
    /// directory.
    pub link_dir: Option<(&'static str, &'static str)>,
    /// True when the file must not exist before the run.
    pub make_in_run: bool,
    /// The identifier of the disagreement on Linux, when pent has one.
    pub open_linux: Option<&'static str>,
    /// The identifier of the disagreement on macOS, when pent has one.
    pub open_macos: Option<&'static str>,
}

impl GuardCase {
    /// The word for the access, for a message.
    #[must_use]
    pub fn kind_word(&self) -> &'static str {
        match self.kind {
            GuardKind::Read => "read",
            GuardKind::Write => "write",
        }
    }

    /// The identifier of the disagreement on this platform.
    #[must_use]
    pub fn open_here(&self) -> Option<&'static str> {
        if cfg!(target_os = "macos") {
            self.open_macos
        } else {
            self.open_linux
        }
    }
}

/// The default row.
const GUARD: GuardCase = GuardCase {
    id: "",
    path: "",
    kind: GuardKind::Read,
    class: "credential",
    link_dir: None,
    make_in_run: false,
    open_linux: None,
    open_macos: None,
};

/// The guard against the summary. The table runs on Linux and on macOS.
///
/// A row with the empty class is a positive control: the guard must not
/// block it, so a run that blocks everything fails the table.
pub const GUARD_CASES: &[GuardCase] = &[
    // The name shapes of a private key.
    GuardCase {
        id: "key-prefix-id",
        path: ".ssh/id_ed25519",
        ..GUARD
    },
    // A pattern with a leading `*` is a file name suffix. The macOS
    // backend builds a regular expression from the prefix form only, so
    // these rules have no effect there (H-13 of
    // `docs/security/watch-and-profiles.md`).
    GuardCase {
        id: "key-suffix-rsa",
        path: ".ssh/github_rsa",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    GuardCase {
        id: "key-suffix-pem",
        path: ".ssh/work.pem",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    GuardCase {
        id: "key-suffix-key",
        path: ".ssh/deploy_key",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    // Names that hold a character of a regular expression.
    GuardCase {
        id: "key-name-with-a-dot",
        path: ".ssh/a.b.key",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    GuardCase {
        id: "key-name-with-a-plus",
        path: ".ssh/x+y_rsa",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    GuardCase {
        id: "key-name-with-brackets",
        path: ".ssh/k[1].key",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    GuardCase {
        id: "key-name-with-a-star",
        path: ".ssh/all*_rsa",
        open_macos: Some("DIFF-9"),
        ..GUARD
    },
    // Depth.
    GuardCase {
        id: "key-one-level-below",
        path: ".ssh/keys/id_rsa",
        ..GUARD
    },
    GuardCase {
        id: "key-two-levels-below",
        path: ".ssh/old/more/id_rsa",
        ..GUARD
    },
    // Through a symbolic link. The Linux supervisor refuses the read,
    // because no mask covers the name that the program uses; the macOS
    // profile holds a deny rule for the real directory of the link,
    // because Seatbelt matches the path that the kernel resolves.
    GuardCase {
        id: "key-through-a-symbolic-link",
        path: ".ssh/linked/id_rsa",
        link_dir: Some((".ssh/linked", "keystore")),
        ..GUARD
    },
    // A key that the program makes during the run. The Linux backend
    // masks only the children that exist when the child starts, so the
    // supervisor refuses the read; Seatbelt decides at the time of the
    // access.
    GuardCase {
        id: "key-made-during-the-run",
        path: ".ssh/id_new",
        make_in_run: true,
        ..GUARD
    },
    // The other credential shapes.
    GuardCase {
        id: "credential-exact-file",
        path: ".aws/credentials",
        ..GUARD
    },
    GuardCase {
        id: "credential-subtree",
        path: ".config/gcloud/creds.json",
        ..GUARD
    },
    // Positive controls: the guard must not block these reads.
    GuardCase {
        id: "public-key-is-not-a-credential",
        path: ".ssh/id_ed25519.pub",
        class: "",
        ..GUARD
    },
    GuardCase {
        id: "known-hosts-is-not-a-credential",
        path: ".ssh/known_hosts",
        class: "",
        ..GUARD
    },
    GuardCase {
        id: "a-plain-file-is-not-a-credential",
        path: "notes.txt",
        class: "",
        ..GUARD
    },
    // Persistence writes.
    GuardCase {
        id: "write-the-shell-start-file",
        path: ".bashrc",
        kind: GuardKind::Write,
        class: "persistence",
        ..GUARD
    },
    GuardCase {
        id: "write-the-git-config",
        path: ".gitconfig",
        kind: GuardKind::Write,
        class: "persistence",
        ..GUARD
    },
    GuardCase {
        id: "write-a-directory-of-the-path",
        path: ".local/bin/evil",
        kind: GuardKind::Write,
        class: "persistence",
        ..GUARD
    },
    GuardCase {
        id: "write-the-autostart-directory",
        path: ".config/autostart/x.desktop",
        kind: GuardKind::Write,
        class: "persistence",
        ..GUARD
    },
    GuardCase {
        id: "write-the-python-user-site",
        path: ".local/lib/python3.11/site-packages/usercustomize.py",
        kind: GuardKind::Write,
        class: "persistence",
        ..GUARD
    },
    GuardCase {
        id: "write-the-files-of-pent",
        path: ".config/pent/evil.toml",
        kind: GuardKind::Write,
        class: "pent-files",
        ..GUARD
    },
    // Positive controls for the writes.
    GuardCase {
        id: "write-a-plain-file",
        path: "notes.txt",
        kind: GuardKind::Write,
        class: "",
        ..GUARD
    },
    GuardCase {
        id: "read-the-shell-start-file-is-allowed",
        path: ".bashrc",
        kind: GuardKind::Read,
        class: "",
        ..GUARD
    },
];

// ── The three layers of the network ──────────────────────────────────────

/// One row of [`NET_CASES`]: a profile, a host, and the verdict of the DNS
/// layer and of the proxy.
#[derive(Debug, Clone, Copy)]
pub struct NetCase {
    /// The name of the row.
    pub id: &'static str,
    /// The domains of the profile.
    pub domains: &'static [&'static str],
    /// The name or the address that the program uses.
    pub host: &'static str,
    /// The scheme and the port of the connection, for `curl`.
    pub url: &'static str,
    /// What the DNS layer must answer. `Deny` means: no address.
    pub dns: Verdict,
    /// What the proxy must do with the connection.
    pub connect: Verdict,
    /// True when the row needs a resolver and the internet.
    pub needs_internet: bool,
    /// The identifier of the disagreement, when pent has one here.
    pub open: Option<&'static str>,
}

/// The default row.
const NET: NetCase = NetCase {
    id: "",
    domains: &[],
    host: "",
    url: "",
    dns: Verdict::Allow,
    connect: Verdict::Allow,
    needs_internet: true,
    open: None,
};

/// The domains of the profile that most network rows use.
const D_MAIN: &[&str] = &["example.com", "*.github.com"];

/// The domains of the rows that test a destination that is not public.
const D_PRIVATE: &[&str] = &["localtest.me", "10-0-0-1.sslip.io"];

/// The DNS answer, the decision of the proxy and the rule of the profile
/// must agree.
pub const NET_CASES: &[NetCase] = &[
    NetCase {
        id: "a-domain-that-the-profile-names",
        domains: D_MAIN,
        host: "example.com",
        url: "https://example.com/",
        ..NET
    },
    NetCase {
        id: "a-domain-that-the-profile-does-not-name",
        domains: D_MAIN,
        host: "www.iana.org",
        url: "https://www.iana.org/",
        dns: Verdict::Deny,
        connect: Verdict::Deny,
        ..NET
    },
    NetCase {
        id: "a-name-below-a-wildcard",
        domains: D_MAIN,
        host: "api.github.com",
        url: "https://api.github.com/",
        ..NET
    },
    NetCase {
        id: "the-domain-of-a-wildcard-itself",
        domains: D_MAIN,
        host: "github.com",
        url: "https://github.com/",
        dns: Verdict::Deny,
        connect: Verdict::Deny,
        ..NET
    },
    NetCase {
        id: "an-address-written-as-a-number",
        domains: D_MAIN,
        host: "93.184.215.14",
        url: "http://93.184.215.14/",
        // The program uses no name, so the DNS layer of pent has nothing
        // to answer and the reverse lookup of `getent` finds nothing.
        dns: Verdict::Deny,
        connect: Verdict::Deny,
        needs_internet: false,
        ..NET
    },
    NetCase {
        id: "a-name-that-resolves-to-a-loopback-address",
        domains: D_PRIVATE,
        host: "localtest.me",
        url: "http://localtest.me/",
        dns: Verdict::Allow,
        connect: Verdict::Deny,
        ..NET
    },
    NetCase {
        id: "a-name-that-resolves-to-a-private-address",
        domains: D_PRIVATE,
        host: "10-0-0-1.sslip.io",
        url: "http://10-0-0-1.sslip.io/",
        dns: Verdict::Allow,
        connect: Verdict::Deny,
        ..NET
    },
];

// ── Helpers ──────────────────────────────────────────────────────────────

/// The absolute path of a table entry.
///
/// A path that starts with `ws/` is below `ws`; every other path is below
/// `home`.
#[must_use]
pub fn resolve(home: &Path, ws: &Path, rel: &str) -> PathBuf {
    rel.strip_prefix("ws/")
        .map_or_else(|| home.join(rel), |rest| ws.join(rest))
}

/// The rows of `cases` that have no open disagreement.
#[must_use]
pub fn fs_closed() -> Vec<&'static FsCase> {
    FS_CASES.iter().filter(|c| c.open.is_none()).collect()
}

/// The rows of [`FS_CASES`] that state the disagreement `id`.
#[must_use]
pub fn fs_open(id: &str) -> Vec<&'static FsCase> {
    FS_CASES.iter().filter(|c| c.open == Some(id)).collect()
}

/// The rows of [`FS_CASES`] with these names.
///
/// A test of a closed finding names its rows, so the test keeps its rows
/// after the fix moves them out of [`fs_open`].
///
/// # Panics
/// Panics when a name is not in the table.
#[must_use]
pub fn fs_rows(ids: &[&str]) -> Vec<&'static FsCase> {
    let rows: Vec<&'static FsCase> = FS_CASES.iter().filter(|c| ids.contains(&c.id)).collect();
    assert_eq!(
        rows.len(),
        ids.len(),
        "FS_CASES does not hold each row of {ids:?}"
    );
    rows
}

/// The rows of [`GUARD_CASES`] that have no open disagreement on this
/// platform.
#[must_use]
pub fn guard_closed() -> Vec<&'static GuardCase> {
    GUARD_CASES
        .iter()
        .filter(|c| c.open_here().is_none())
        .collect()
}

/// The rows of [`GUARD_CASES`] that state the disagreement `id` on this
/// platform.
#[must_use]
pub fn guard_open(id: &str) -> Vec<&'static GuardCase> {
    GUARD_CASES
        .iter()
        .filter(|c| c.open_here() == Some(id))
        .collect()
}

/// The rows of [`GUARD_CASES`] with these names.
///
/// A test of a closed finding names its rows, so the test keeps its rows
/// after the fix moves them out of [`guard_open`].
///
/// # Panics
/// Panics when a name is not in the table.
#[must_use]
pub fn guard_rows(ids: &[&str]) -> Vec<&'static GuardCase> {
    let rows: Vec<&'static GuardCase> =
        GUARD_CASES.iter().filter(|c| ids.contains(&c.id)).collect();
    assert_eq!(
        rows.len(),
        ids.len(),
        "GUARD_CASES does not hold each row of {ids:?}"
    );
    rows
}

/// Every disagreement that [`GUARD_CASES`] states on this platform, sorted
/// and without a repeat.
#[must_use]
pub fn guard_open_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = GUARD_CASES
        .iter()
        .filter_map(GuardCase::open_here)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The rows of [`NET_CASES`] that have no open disagreement.
#[must_use]
pub fn net_closed() -> Vec<&'static NetCase> {
    NET_CASES.iter().filter(|c| c.open.is_none()).collect()
}

/// The rows of [`NET_CASES`] that state the disagreement `id`.
#[must_use]
pub fn net_open(id: &str) -> Vec<&'static NetCase> {
    NET_CASES.iter().filter(|c| c.open == Some(id)).collect()
}

/// The rows of [`WATCH_CASES`] that have no open disagreement.
#[must_use]
pub fn watch_closed() -> Vec<&'static WatchCase> {
    WATCH_CASES.iter().filter(|c| c.open.is_none()).collect()
}
