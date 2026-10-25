//! Test fixtures: event lists that look like real watch runs.

use std::path::PathBuf;

use crate::{FsOp, GuardClass, NetProtocol, Outcome, ProcessInfo, SummaryContext, WatchEvent};

/// The context of the fixtures: home `/home/u`, workspace `/home/u/work/app`.
pub(crate) fn ctx() -> SummaryContext {
    SummaryContext {
        home: PathBuf::from("/home/u"),
        workspace: PathBuf::from("/home/u/work/app"),
        covered: [
            "/usr",
            "/nix/store",
            "/etc",
            "/proc",
            "/sys",
            "/run/current-system",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect(),
        existing: None,
    }
}

/// A filesystem event that went through.
pub(crate) fn fs(op: FsOp, path: &str, process: &str) -> WatchEvent {
    fs_outcome(op, path, process, Outcome::Allowed)
}

/// A filesystem event with an outcome.
pub(crate) fn fs_outcome(op: FsOp, path: &str, process: &str, outcome: Outcome) -> WatchEvent {
    WatchEvent::Fs {
        op,
        path: PathBuf::from(path),
        process: ProcessInfo {
            pid: 4242,
            name: process.to_string(),
        },
        outcome,
    }
}

/// A filesystem event that the guard blocked.
pub(crate) fn blocked(op: FsOp, path: &str, process: &str, class: GuardClass) -> WatchEvent {
    fs_outcome(op, path, process, Outcome::Blocked(class))
}

/// A TCP connection through the proxy.
pub(crate) fn connect(host: &str, port: u16) -> WatchEvent {
    WatchEvent::Connect {
        host: host.to_string(),
        port,
        protocol: NetProtocol::HttpConnect,
        outcome: Outcome::Allowed,
    }
}

/// A DNS query.
pub(crate) fn dns(name: &str) -> WatchEvent {
    WatchEvent::Dns {
        name: name.to_string(),
        qtype: "A".to_string(),
        outcome: Outcome::Allowed,
    }
}

/// A session of `claude` in `/home/u/work/app`: about 1,900 events from
/// claude, git, ssh and node.
pub(crate) fn claude_session() -> Vec<WatchEvent> {
    use FsOp::{Create, Delete, Exec, Read, Write};
    let mut e = Vec::new();
    let home = |rel: &str| format!("/home/u/{rel}");

    e.push(fs(
        Exec,
        "/home/u/.local/share/claude/versions/2.1.3/claude",
        "claude",
    ));
    // The system paths and the short-lived paths.
    for lib in ["libc.so.6", "libm.so.6", "libstdc++.so.6", "libgcc_s.so.1"] {
        e.push(fs(
            Read,
            &format!("/nix/store/abc-glibc-2.40/lib/{lib}"),
            "claude",
        ));
    }
    for path in [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/ssl/certs/ca-bundle.crt",
        "/usr/share/zoneinfo/UTC",
        "/proc/self/maps",
        "/proc/4242/status",
        "/proc/cpuinfo",
        "/sys/devices/system/cpu/online",
        "/dev/null",
        "/dev/urandom",
    ] {
        e.push(fs(Read, path, "claude"));
    }
    e.push(fs(Create, "/tmp/claude-1000/cwd-abcd", "claude"));
    e.push(fs(Delete, "/tmp/claude-1000/cwd-abcd", "claude"));

    // Hundreds of reads below ~/.claude.
    for path in ["settings.json", "CLAUDE.md", "agents/reviewer.md"] {
        e.push(fs(Read, &home(&format!(".claude/{path}")), "claude"));
    }
    for i in 0..300 {
        e.push(fs(
            Read,
            &home(&format!(
                ".claude/plugins/marketplaces/official/plugins/p{}/file{i}.md",
                i % 30
            )),
            "claude",
        ));
    }

    // The config file: claude writes a new copy and renames it.
    e.push(fs(Read, &home(".claude.json"), "claude"));
    e.push(fs(Create, &home(".claude.json.tmp.4242.1"), "claude"));
    e.push(fs(Delete, &home(".claude.json.tmp.4242.1"), "claude"));
    e.push(fs(Create, &home(".claude.json"), "claude"));

    // 37 new files in 4 directories below ~/.claude.
    let session = ".claude/projects/-home-u-work-app/0f6c2d1e.jsonl";
    e.push(fs(Create, &home(session), "claude"));
    for _ in 0..200 {
        e.push(fs(Write, &home(session), "claude"));
    }
    for i in 0..20 {
        e.push(fs(
            Create,
            &home(&format!(".claude/todos/t{i}.json")),
            "claude",
        ));
    }
    for i in 0..10 {
        e.push(fs(
            Create,
            &home(&format!(".claude/shell-snapshots/snapshot-bash-{i}.sh")),
            "claude",
        ));
    }
    for i in 0..6 {
        e.push(fs(
            Create,
            &home(&format!(".claude/statsig/s{i}")),
            "claude",
        ));
    }

    // The cache.
    e.push(fs(Create, &home(".cache/claude/cli.lock"), "claude"));
    e.push(fs(
        Create,
        &home(".cache/claude/version-check.json"),
        "claude",
    ));
    e.push(fs(Delete, &home(".cache/claude/cli.lock"), "claude"));

    // The workspace: the summary omits all of it.
    for i in 0..400 {
        e.push(fs(Read, &format!("/home/u/work/app/src/m{i}.rs"), "claude"));
    }
    for i in 0..50 {
        e.push(fs(
            Write,
            &format!("/home/u/work/app/src/m{i}.rs"),
            "claude",
        ));
    }
    e.push(fs(Create, "/home/u/work/app/src/new.rs", "claude"));

    // git and ssh.
    e.push(fs(Exec, "/usr/bin/git", "claude"));
    e.push(fs(Read, &home(".gitconfig"), "git"));
    e.push(fs(Read, &home(".config/git/ignore"), "git"));
    for i in 0..100 {
        e.push(fs(
            Read,
            &format!("/home/u/work/app/.git/objects/{i:02x}"),
            "git",
        ));
    }
    e.push(fs(Exec, "/usr/bin/ssh", "git"));
    e.push(fs(Read, &home(".ssh/known_hosts"), "ssh"));
    e.push(fs(Read, &home(".ssh/known_hosts"), "git"));
    e.push(fs(Read, &home(".ssh/config"), "ssh"));
    e.push(blocked(
        Read,
        &home(".ssh/id_ed25519"),
        "ssh",
        GuardClass::Credential,
    ));

    // node.
    e.push(fs(
        Exec,
        &home(".nvm/versions/node/v22.1.0/bin/node"),
        "claude",
    ));
    for i in 0..200 {
        e.push(fs(
            Read,
            &home(&format!(
                ".nvm/versions/node/v22.1.0/lib/node_modules/npm/lib/f{i}.js"
            )),
            "node",
        ));
    }
    e.push(blocked(
        Write,
        &home(".bashrc"),
        "node",
        GuardClass::Persistence,
    ));

    // The Unix sockets: one with a path, and one abstract address that pent
    // refused.
    e.push(WatchEvent::UnixConnect {
        target: "/run/user/1000/bus".to_string(),
        process: ProcessInfo {
            pid: 4242,
            name: "claude".to_string(),
        },
        outcome: Outcome::Allowed,
    });
    e.push(WatchEvent::UnixConnect {
        target: "@/tmp/.X11-unix/X0".to_string(),
        process: ProcessInfo {
            pid: 4242,
            name: "claude".to_string(),
        },
        outcome: Outcome::Denied,
    });

    // The network.
    e.push(dns("api.anthropic.com"));
    for _ in 0..500 {
        e.push(connect("api.anthropic.com", 443));
    }
    e.push(connect("statsig.anthropic.com", 443));
    e.push(dns("registry.npmjs.org"));
    for host in ["registry.npmjs.org", "www.npmjs.org", "cdn.npmjs.org"] {
        e.push(connect(host, 443));
    }
    e.push(connect("github.com", 22));
    e.push(connect("140.82.112.3", 443));
    e
}
