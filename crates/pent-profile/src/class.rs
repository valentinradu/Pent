//! The classes of an access and the width menu of a question.
//!
//! Each access has one class (`docs/design/pent.md`, section 5.3):
//!
//! - **Pent:** the files of pent. Nobody answers, and the program gets
//!   `ENOENT`.
//! - **Sensitive:** a credential, a file that runs code later, a socket that
//!   gives a way out, a control port. Only the human answers, and the only
//!   width is the exact target.
//! - **Normal:** everything else.
//!
//! The width menu lists the targets that an answer can name, from the
//! narrowest to the widest. The human or the model picks one by its number,
//! so nobody writes a path or a domain by hand.
//!
//! The sensitive data is here, in one place: the guard list
//! ([`guard_rules_with`]), [`ESCAPE_SOCKETS`], [`RESOLVER_SOCKETS`],
//! [`HOME_AGENT_SOCKETS`] and [`CONTROL_PORTS`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::guard::{guard_rules_with, GuardAccess, GuardRule};
use crate::localhost::CONTROL_PORTS;
use crate::psl;
use crate::rule::{Access, DomainName, DomainWidth, FileKind, PathWidth, RulePath, Target};
use crate::GuardClass;

/// Unix sockets that give a way out of the sandbox: a container engine runs
/// a program on the host, and the system bus reaches `systemd-resolved`,
/// NetworkManager and polkit.
///
/// A fixed list can never be complete: each daemon that keeps a control
/// socket and offers a dial or an exec operation is an escape. The sandbox
/// hides every socket under `/run`, `/tmp` and `/var/tmp`, so this list is a
/// second layer. It is also the list that a user setting can extend later.
pub const ESCAPE_SOCKETS: &[&str] = &[
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
    "/run/dbus/system_bus_socket",
    "/var/run/dbus/system_bus_socket",
];

/// Unix sockets of host resolvers and of host network agents. A query or a
/// connection through them goes to the network of the host, past the proxy.
pub const RESOLVER_SOCKETS: &[&str] = &[
    "/run/nscd/socket",
    "/var/run/nscd/socket",
    "/run/systemd/resolve/io.systemd.Resolve",
    // The Tailscale daemon. Its LocalAPI has a "ts-dial" upgrade that opens
    // a TCP stream to any host of the tailnet, and through an exit node or a
    // subnet route to the public internet.
    "/run/tailscale/tailscaled.sock",
    "/var/run/tailscale/tailscaled.sock",
];

/// Unix sockets of an agent in the home directory, as a directory and a name
/// prefix. The agent signs a challenge or decrypts a secret for any program
/// that reaches its socket.
///
/// The sockets under `/run/user/<uid>` need no entry here: the sandbox hides
/// all of `/run`.
pub const HOME_AGENT_SOCKETS: &[(&str, &str)] = &[
    (".gnupg", "S.gpg-agent"),
    (".gnupg", "S.dirmngr"),
    (".ssh", "agent."),
];

/// The directories of pent below the home directory. The program never sees
/// them.
pub const PENT_HOME_DIRS: &[&str] = &[".config/pent", ".local/state/pent", ".local/share/pent"];

/// Why an access is sensitive. The text of the warning comes from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitive {
    /// A credential: a key, a token, a password store, a browser profile.
    /// A write is sensitive too: it can create or replace a token.
    Credential,
    /// A file that runs code later: a shell start file, an autostart entry,
    /// a directory of `PATH`.
    Persistence,
    /// A program that gives more privilege (`sudo`, `pkexec`).
    PrivilegeEscalation,
    /// A socket of [`ESCAPE_SOCKETS`].
    EscapeSocket,
    /// A socket of [`RESOLVER_SOCKETS`].
    ResolverSocket,
    /// A socket of [`HOME_AGENT_SOCKETS`].
    AgentSocket,
    /// A port of [`CONTROL_PORTS`].
    ControlPort,
}

impl Sensitive {
    /// The warning of a question, as a short phrase: "a credential file".
    #[must_use]
    pub const fn warning(self) -> &'static str {
        match self {
            Self::Credential => "a credential file",
            Self::Persistence => "a file that runs code later",
            Self::PrivilegeEscalation => "a program that gives more privilege",
            Self::EscapeSocket => "a socket that can run programs outside the sandbox",
            Self::ResolverSocket => "a socket that reaches the network past the proxy",
            Self::AgentSocket => "the socket of a key agent",
            Self::ControlPort => "a control port that can run programs outside the sandbox",
        }
    }
}

/// The class of an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// The model or the human answers, with any width of the menu.
    Normal,
    /// Only the human answers, with the exact target.
    Sensitive(Sensitive),
    /// The files of pent: nobody answers.
    Pent,
}

/// The classes of the accesses of one user.
#[derive(Debug, Clone)]
pub struct Classifier {
    home: PathBuf,
    guard: Vec<GuardRule>,
    pent: Vec<PathBuf>,
}

impl Classifier {
    /// The classes for the home directory `home`.
    ///
    /// `pent_dirs` holds the real directories of pent when they differ from
    /// [`PENT_HOME_DIRS`]: the config and state directories under
    /// `$XDG_CONFIG_HOME` and `$XDG_STATE_HOME`, and the directory of
    /// `pentd.sock`. The directories of [`PENT_HOME_DIRS`] stay in the list.
    #[must_use]
    pub fn new(home: &Path, pent_dirs: &[PathBuf]) -> Self {
        let mut pent: Vec<PathBuf> = PENT_HOME_DIRS.iter().map(|d| home.join(d)).collect();
        for dir in pent_dirs {
            if !pent.contains(dir) {
                pent.push(dir.clone());
            }
        }
        Self {
            home: home.to_path_buf(),
            guard: guard_rules_with(home, pent_dirs),
            pent,
        }
    }

    /// The class of `access`.
    #[must_use]
    pub fn classify(&self, access: &Access<'_>) -> Class {
        match access {
            Access::File { kind, path } => self.file(*kind, path.as_path()),
            Access::Domain(_) => Class::Normal,
            Access::UnixSocket(path) => self.unix_socket(path.as_path()),
            Access::Localhost(port) => {
                if CONTROL_PORTS.iter().any(|(p, _)| *p == port.get()) {
                    Class::Sensitive(Sensitive::ControlPort)
                } else {
                    Class::Normal
                }
            }
        }
    }

    /// The class of a file access.
    fn file(&self, kind: FileKind, path: &Path) -> Class {
        if self.is_pent(path) {
            return Class::Pent;
        }
        // The guard accesses that can make this access sensitive. A list
        // shows the names in a credential directory (the entries of a
        // password store name the sites). A write can create or replace a
        // credential. An exec reads the file.
        let checks: &[GuardAccess] = match kind {
            FileKind::List | FileKind::Read => &[GuardAccess::Read],
            FileKind::Write => &[GuardAccess::Read, GuardAccess::Write],
            FileKind::Exec => &[GuardAccess::Read, GuardAccess::ExecName],
        };
        checks
            .iter()
            .find_map(|access| self.guard.iter().find(|r| r.matches(path, *access)))
            .map_or(Class::Normal, |rule| match rule.class {
                GuardClass::Credential => Class::Sensitive(Sensitive::Credential),
                GuardClass::Persistence => Class::Sensitive(Sensitive::Persistence),
                GuardClass::PrivilegeEscalation => Class::Sensitive(Sensitive::PrivilegeEscalation),
                GuardClass::ControlPort => Class::Sensitive(Sensitive::ControlPort),
                GuardClass::PentFiles => Class::Pent,
            })
    }

    /// The class of a connection to a Unix socket.
    fn unix_socket(&self, path: &Path) -> Class {
        if self.is_pent(path) {
            return Class::Pent;
        }
        let listed = |list: &[&str]| list.iter().any(|s| path == Path::new(s));
        if listed(ESCAPE_SOCKETS) {
            return Class::Sensitive(Sensitive::EscapeSocket);
        }
        if listed(RESOLVER_SOCKETS) {
            return Class::Sensitive(Sensitive::ResolverSocket);
        }
        let agent = HOME_AGENT_SOCKETS.iter().any(|(dir, prefix)| {
            path.parent() == Some(self.home.join(dir).as_path())
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix))
        });
        if agent {
            Class::Sensitive(Sensitive::AgentSocket)
        } else {
            Class::Normal
        }
    }

    /// Return true if `path` is a directory of pent or below one.
    fn is_pent(&self, path: &Path) -> bool {
        self.pent.iter().any(|dir| path.starts_with(dir))
    }

    /// The width menu of `access`, from the narrowest target to the widest.
    ///
    /// - A file: the exact path, then a subtree for each parent directory.
    ///   A list also gets the subtree of the directory itself. No subtree is
    ///   `/`, a directory directly below `/`, the home directory or a parent
    ///   of it.
    /// - A domain: the exact name, then `*.parent` and `**.parent`, then
    ///   `**.base` for each wider base up to the registrable domain. No
    ///   wildcard covers a public suffix.
    /// - A Unix socket or a port: the exact target.
    ///
    /// A sensitive access gets only the exact target. A pent access gets an
    /// empty menu: nobody answers it.
    #[must_use]
    pub fn widths(&self, access: &Access<'_>) -> Vec<Target> {
        match self.classify(access) {
            Class::Pent => return Vec::new(),
            Class::Sensitive(_) => return vec![exact(access)],
            Class::Normal => {}
        }
        match access {
            Access::File { kind, path } => self.file_widths(*kind, path),
            Access::Domain(name) => domain_widths(name),
            Access::UnixSocket(_) | Access::Localhost(_) => vec![exact(access)],
        }
    }

    /// The width menu of a normal file access.
    fn file_widths(&self, kind: FileKind, path: &RulePath) -> Vec<Target> {
        let target = |width| Target::File { kind, width };
        let mut menu = vec![target(PathWidth::Exact(path.clone()))];
        let first = if kind == FileKind::List {
            Some(path.as_path())
        } else {
            path.as_path().parent()
        };
        for dir in first.into_iter().flat_map(Path::ancestors) {
            if !self.subtree_allowed(dir) {
                break;
            }
            if let Ok(dir) = RulePath::new(dir) {
                menu.push(target(PathWidth::Subtree(dir)));
            }
        }
        menu
    }

    /// Return true if a subtree rule on `dir` is narrow enough for the menu.
    fn subtree_allowed(&self, dir: &Path) -> bool {
        dir.components().count() > 2 && !self.home.starts_with(dir)
    }
}

/// The exact target of `access`.
fn exact(access: &Access<'_>) -> Target {
    match access {
        Access::File { kind, path } => Target::File {
            kind: *kind,
            width: PathWidth::Exact((*path).clone()),
        },
        Access::Domain(name) => Target::Domain(DomainWidth::Exact((*name).clone())),
        Access::UnixSocket(path) => Target::UnixSocket((*path).clone()),
        Access::Localhost(port) => Target::Localhost(*port),
    }
}

/// The width menu of a domain.
fn domain_widths(name: &DomainName) -> Vec<Target> {
    let mut menu = vec![Target::Domain(DomainWidth::Exact(name.clone()))];
    let Some(registrable) = psl::registrable_domain(name.as_str()) else {
        return menu;
    };
    // Each base from the parent of the name up to the registrable domain.
    let bases = name
        .as_str()
        .match_indices('.')
        .filter_map(|(i, _)| name.as_str().get(i.saturating_add(1)..))
        .take_while(|base| base.len() >= registrable.len());
    for (n, base) in bases.enumerate() {
        let Ok(base) = base.parse::<DomainName>() else {
            continue;
        };
        if n == 0 {
            if let Ok(width) = DomainWidth::wildcard(base.clone(), false) {
                menu.push(Target::Domain(width));
            }
        }
        if let Ok(width) = DomainWidth::wildcard(base, true) {
            menu.push(Target::Domain(width));
        }
    }
    menu
}

#[cfg(test)]
#[allow(clippy::panic)] // a test that reaches a branch it must not reach fails
mod tests {
    use std::num::NonZeroU16;

    use super::*;

    const HOME: &str = "/home/u";

    fn classifier() -> Classifier {
        Classifier::new(
            Path::new(HOME),
            &[
                PathBuf::from("/xdg/config/pent"),
                PathBuf::from("/run/user/1000/pent"),
            ],
        )
    }

    fn path(p: &str) -> RulePath {
        RulePath::new(p).unwrap_or_else(|e| panic!("{e}"))
    }

    fn file_class(kind: FileKind, p: &str) -> Class {
        classifier().classify(&Access::File {
            kind,
            path: &path(p),
        })
    }

    fn socket_class(p: &str) -> Class {
        classifier().classify(&Access::UnixSocket(&path(p)))
    }

    fn port(n: u16) -> NonZeroU16 {
        NonZeroU16::new(n).unwrap_or_else(|| panic!("port 0"))
    }

    fn domain(s: &str) -> DomainName {
        s.parse().unwrap_or_else(|e| panic!("{e}"))
    }

    /// The menu as text: `read =/a`, `read /a/**`, `*.x.com`.
    fn menu(access: &Access<'_>) -> Vec<String> {
        classifier()
            .widths(access)
            .iter()
            .map(|t| match t {
                Target::File { kind, width } => match width {
                    PathWidth::Exact(p) => format!("{kind:?} ={}", p.as_path().display()),
                    PathWidth::Subtree(p) => format!("{kind:?} {}/**", p.as_path().display()),
                },
                Target::Domain(width) => width.to_string(),
                Target::UnixSocket(p) => format!("unix {}", p.as_path().display()),
                Target::Localhost(port) => format!("localhost:{port}"),
            })
            .collect()
    }

    #[test]
    fn the_files_of_pent_are_in_the_pent_class_for_each_kind() {
        let kinds = [
            FileKind::List,
            FileKind::Read,
            FileKind::Write,
            FileKind::Exec,
        ];
        for p in [
            "/home/u/.config/pent",
            "/home/u/.config/pent/pent.toml",
            "/home/u/.local/state/pent/rules/claude.toml",
            "/home/u/.local/share/pent/models/m.gguf",
            "/xdg/config/pent/pent.toml",
        ] {
            for kind in kinds {
                assert_eq!(file_class(kind, p), Class::Pent, "{kind:?} {p}");
            }
        }
        assert_eq!(socket_class("/run/user/1000/pent/pentd.sock"), Class::Pent);
        // A sibling with a longer name is not pent.
        assert_eq!(
            file_class(FileKind::Read, "/home/u/.config/pentagon"),
            Class::Normal
        );
        // The parent is not pent: listing it shows only the name.
        assert_eq!(file_class(FileKind::List, "/home/u/.config"), Class::Normal);
    }

    #[test]
    fn a_credential_is_sensitive_to_read_list_write_and_exec() {
        let credential = Class::Sensitive(Sensitive::Credential);
        assert_eq!(
            file_class(FileKind::Read, "/home/u/.ssh/id_ed25519"),
            credential
        );
        assert_eq!(
            file_class(FileKind::Read, "/home/u/.ssh/work.pem"),
            credential
        );
        assert_eq!(
            file_class(FileKind::Exec, "/home/u/.ssh/id_rsa"),
            credential
        );
        // `gh auth login` creates the token: the write is sensitive.
        assert_eq!(
            file_class(FileKind::Write, "/home/u/.config/gh/hosts.yml"),
            credential
        );
        // The names in a password store name the sites.
        assert_eq!(
            file_class(FileKind::List, "/home/u/.password-store"),
            credential
        );
        assert_eq!(
            file_class(FileKind::Read, "/home/u/.ssh/id_ed25519.pub"),
            Class::Normal
        );
        assert_eq!(
            file_class(FileKind::Read, "/home/u/.ssh/known_hosts"),
            Class::Normal
        );
        assert_eq!(file_class(FileKind::List, "/home/u/.ssh"), Class::Normal);
    }

    #[test]
    fn a_start_file_is_sensitive_to_write_only() {
        let persistence = Class::Sensitive(Sensitive::Persistence);
        assert_eq!(file_class(FileKind::Write, "/home/u/.bashrc"), persistence);
        assert_eq!(
            file_class(FileKind::Write, "/home/u/.local/bin/git"),
            persistence
        );
        assert_eq!(file_class(FileKind::Read, "/home/u/.bashrc"), Class::Normal);
        assert_eq!(
            file_class(FileKind::Exec, "/home/u/.local/bin/git"),
            Class::Normal
        );
        assert_eq!(
            file_class(FileKind::Exec, "/usr/bin/sudo"),
            Class::Sensitive(Sensitive::PrivilegeEscalation)
        );
        assert_eq!(
            file_class(FileKind::Write, "/home/u/.cargo/registry/x"),
            Class::Normal
        );
    }

    #[test]
    fn the_sockets_of_the_lists_are_sensitive() {
        for s in ESCAPE_SOCKETS {
            assert_eq!(
                socket_class(s),
                Class::Sensitive(Sensitive::EscapeSocket),
                "{s}"
            );
        }
        for s in RESOLVER_SOCKETS {
            assert_eq!(
                socket_class(s),
                Class::Sensitive(Sensitive::ResolverSocket),
                "{s}"
            );
        }
        let agent = Class::Sensitive(Sensitive::AgentSocket);
        assert_eq!(socket_class("/home/u/.gnupg/S.gpg-agent"), agent);
        assert_eq!(socket_class("/home/u/.gnupg/S.gpg-agent.ssh"), agent);
        assert_eq!(socket_class("/home/u/.ssh/agent.1234"), agent);
        // The prefix must be in the named directory itself.
        assert_eq!(socket_class("/home/u/.ssh/x/agent.1234"), Class::Normal);
        assert_eq!(socket_class("/run/user/1000/wayland-0"), Class::Normal);
    }

    #[test]
    fn a_control_port_is_sensitive_and_a_domain_is_normal() {
        let c = classifier();
        for (p, _) in CONTROL_PORTS {
            assert_eq!(
                c.classify(&Access::Localhost(port(*p))),
                Class::Sensitive(Sensitive::ControlPort)
            );
        }
        assert_eq!(c.classify(&Access::Localhost(port(5432))), Class::Normal);
        assert_eq!(
            c.classify(&Access::Domain(&domain("api.example.com"))),
            Class::Normal
        );
    }

    #[test]
    fn each_sensitive_reason_has_a_warning() {
        for reason in [
            Sensitive::Credential,
            Sensitive::Persistence,
            Sensitive::PrivilegeEscalation,
            Sensitive::EscapeSocket,
            Sensitive::ResolverSocket,
            Sensitive::AgentSocket,
            Sensitive::ControlPort,
        ] {
            assert!(reason.warning().starts_with("a ") || reason.warning().starts_with("the "));
        }
    }

    #[test]
    fn a_file_menu_goes_up_to_the_home_directory() {
        let p = path("/home/u/.cargo/registry/src/x.rs");
        let read = Access::File {
            kind: FileKind::Read,
            path: &p,
        };
        assert_eq!(
            menu(&read),
            [
                "Read =/home/u/.cargo/registry/src/x.rs",
                "Read /home/u/.cargo/registry/src/**",
                "Read /home/u/.cargo/registry/**",
                "Read /home/u/.cargo/**",
            ]
        );
        // A file in the home root gets only the exact path.
        let p = path("/home/u/.claude.json");
        let write = Access::File {
            kind: FileKind::Write,
            path: &p,
        };
        assert_eq!(menu(&write), ["Write =/home/u/.claude.json"]);
    }

    #[test]
    fn a_file_menu_outside_home_stops_below_the_root() {
        let p = path("/opt/tool/bin/run");
        let exec = Access::File {
            kind: FileKind::Exec,
            path: &p,
        };
        assert_eq!(
            menu(&exec),
            [
                "Exec =/opt/tool/bin/run",
                "Exec /opt/tool/bin/**",
                "Exec /opt/tool/**",
            ]
        );
    }

    #[test]
    fn a_list_menu_starts_with_the_directory_itself() {
        let p = path("/home/u/notes/2026");
        let list = Access::File {
            kind: FileKind::List,
            path: &p,
        };
        assert_eq!(
            menu(&list),
            [
                "List =/home/u/notes/2026",
                "List /home/u/notes/2026/**",
                "List /home/u/notes/**",
            ]
        );
        let home = path("/home/u");
        let list_home = Access::File {
            kind: FileKind::List,
            path: &home,
        };
        assert_eq!(menu(&list_home), ["List =/home/u"]);
    }

    #[test]
    fn a_sensitive_access_gets_only_the_exact_target_and_pent_gets_none() {
        let key = path("/home/u/.ssh/id_ed25519");
        assert_eq!(
            menu(&Access::File {
                kind: FileKind::Read,
                path: &key
            }),
            ["Read =/home/u/.ssh/id_ed25519"]
        );
        let docker = path("/run/docker.sock");
        assert_eq!(
            menu(&Access::UnixSocket(&docker)),
            ["unix /run/docker.sock"]
        );
        assert_eq!(menu(&Access::Localhost(port(9222))), ["localhost:9222"]);
        let rules = path("/home/u/.local/state/pent/rules/claude.toml");
        assert!(menu(&Access::File {
            kind: FileKind::Write,
            path: &rules
        })
        .is_empty());
    }

    #[test]
    fn a_domain_menu_stops_at_the_registrable_domain() {
        let name = domain("a.b.example.com");
        assert_eq!(
            menu(&Access::Domain(&name)),
            [
                "a.b.example.com",
                "*.b.example.com",
                "**.b.example.com",
                "**.example.com",
            ]
        );
        let name = domain("registry.npmjs.org");
        assert_eq!(
            menu(&Access::Domain(&name)),
            ["registry.npmjs.org", "*.npmjs.org", "**.npmjs.org"]
        );
        // The registrable domain itself has no wildcard below a suffix.
        let name = domain("example.co.uk");
        assert_eq!(menu(&Access::Domain(&name)), ["example.co.uk"]);
        // A site on a shared host gets no wildcard over the other sites.
        let name = domain("user.github.io");
        assert_eq!(menu(&Access::Domain(&name)), ["user.github.io"]);
        let name = domain("com");
        assert_eq!(menu(&Access::Domain(&name)), ["com"]);
    }

    #[test]
    fn each_menu_entry_covers_the_access() {
        use crate::rule::{Decision, Rule, RuleKey, RuleSet, Source};
        let p = path("/home/u/.cargo/registry/src/x.rs");
        let name = domain("a.b.example.com");
        let accesses = [
            Access::File {
                kind: FileKind::Read,
                path: &p,
            },
            Access::File {
                kind: FileKind::List,
                path: &p,
            },
            Access::Domain(&name),
            Access::Localhost(port(5432)),
        ];
        let key: RuleKey = "k".parse().unwrap_or_else(|e| panic!("{e}"));
        for access in accesses {
            for target in classifier().widths(&access) {
                let set = RuleSet {
                    key: key.clone(),
                    rules: vec![Rule {
                        target: target.clone(),
                        decision: Decision::Allow,
                        source: Source::Human,
                        created: std::time::SystemTime::UNIX_EPOCH,
                    }],
                };
                assert_eq!(
                    set.decide(&access),
                    Some(Decision::Allow),
                    "{target:?} must cover {access:?}"
                );
            }
        }
    }
}
