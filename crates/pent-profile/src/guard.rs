//! The dangerous accesses that watch mode blocks.
//!
//! Watch mode does not sandbox the program, but it blocks a small set of
//! dangerous accesses. The kernel enforces the guard, so a program cannot race
//! it: on Linux with masks in the private mount namespace of the child, on
//! macOS with Seatbelt deny rules. The recorder still sees each attempt and
//! emits it with [`Outcome::Blocked`](crate::Outcome::Blocked). The user
//! decides about these items at the end of watch mode.
//!
//! Both platforms use the same list, so a recorded profile does not depend on
//! the platform.

use std::path::{Path, PathBuf};

use crate::GuardClass;

/// The access that a guard rule blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAccess {
    /// Block reads of the content. Linux: bind-mount `/dev/null` over a file
    /// or an empty tmpfs over a directory. macOS: `(deny file-read-data)`.
    Read,
    /// Block writes, creation and deletion. Linux: a read-only bind mount.
    /// macOS: `(deny file-write*)`.
    Write,
    /// Block execution of a binary with this file name, wherever it is. The
    /// `NO_NEW_PRIVS` flag already makes setuid binaries fail; the recorder
    /// marks the attempt as blocked.
    ExecName,
}

/// The paths that a guard rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardTarget {
    /// One file or directory (only the path itself).
    Exact(PathBuf),
    /// A directory and all paths below it.
    Subtree(PathBuf),
    /// The files in `dir` whose name starts with `prefix` and does not end
    /// with `exclude_suffix` (for example SSH private keys: prefix `id_`,
    /// exclude `.pub`). Linux masks the files that exist when the child
    /// starts.
    FilesInDir {
        /// The directory.
        dir: PathBuf,
        /// The file name prefix.
        prefix: String,
        /// A file name suffix that the rule does not match.
        exclude_suffix: Option<String>,
    },
    /// A binary with this file name (for [`GuardAccess::ExecName`]).
    BinaryName(String),
}

/// One guard rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRule {
    /// The class that the summary shows.
    pub class: GuardClass,
    /// The blocked access.
    pub access: GuardAccess,
    /// The matched paths.
    pub target: GuardTarget,
}

impl GuardRule {
    /// Return true if the rule matches `path` for an access of kind `access`.
    #[must_use]
    pub fn matches(&self, path: &Path, access: GuardAccess) -> bool {
        if access != self.access {
            return false;
        }
        match &self.target {
            GuardTarget::Exact(p) => path == p,
            GuardTarget::Subtree(p) => path.starts_with(p),
            GuardTarget::FilesInDir {
                dir,
                prefix,
                exclude_suffix,
            } => {
                path.parent() == Some(dir.as_path())
                    && path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                        n.starts_with(prefix.as_str())
                            && !exclude_suffix
                                .as_deref()
                                .is_some_and(|suffix| n.ends_with(suffix))
                    })
            }
            GuardTarget::BinaryName(name) => path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == name),
        }
    }
}

/// Return the guard class of `path` for `access`, if a rule matches.
#[must_use]
pub fn classify(rules: &[GuardRule], path: &Path, access: GuardAccess) -> Option<GuardClass> {
    rules
        .iter()
        .find(|r| r.matches(path, access))
        .map(|r| r.class)
}

/// Return the guard rules for the home directory `home`.
///
/// The list uses the default locations (`~/.config`, `~/.local/share`). The
/// list has the Linux and the macOS paths. A path that does not exist on a
/// platform has no effect there.
#[must_use]
pub fn guard_rules(home: &Path) -> Vec<GuardRule> {
    use GuardAccess::{ExecName, Read, Write};
    use GuardClass::{Credential, PentFiles, Persistence, PrivilegeEscalation};

    let h = |rel: &str| home.join(rel);
    let mut rules = Vec::new();
    let mut add = |class, access, target| {
        rules.push(GuardRule {
            class,
            access,
            target,
        });
    };

    // ── Credential reads ─────────────────────────────────────────────────────
    add(
        Credential,
        Read,
        GuardTarget::FilesInDir {
            dir: h(".ssh"),
            prefix: "id_".to_string(),
            exclude_suffix: Some(".pub".to_string()),
        },
    );
    for exact in [
        ".aws/credentials",
        ".netrc",
        ".git-credentials",
        ".config/gh/hosts.yml",
        ".kube/config",
        ".docker/config.json",
        ".npmrc",
        ".pypirc",
        ".cargo/credentials.toml",
        ".cargo/credentials",
        ".gem/credentials",
    ] {
        add(Credential, Read, GuardTarget::Exact(h(exact)));
    }
    for subtree in [
        ".aws/sso/cache",
        ".config/gcloud",
        ".azure",
        ".gnupg",
        ".password-store",
        ".local/share/keyrings",
        ".local/share/kwalletd",
        ".mozilla",
        ".config/google-chrome",
        ".config/chromium",
        ".config/BraveSoftware",
        "Library/Keychains",
        "Library/Cookies",
        "Library/Safari",
        "Library/Application Support/Google/Chrome",
        "Library/Application Support/Firefox",
    ] {
        add(Credential, Read, GuardTarget::Subtree(h(subtree)));
    }

    // ── Persistence writes ───────────────────────────────────────────────────
    for exact in [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".ssh/authorized_keys",
        ".ssh/config",
        ".ssh/rc",
        ".gitconfig",
        ".config/git/config",
    ] {
        add(Persistence, Write, GuardTarget::Exact(h(exact)));
    }
    for subtree in [
        ".config/fish",
        ".config/autostart",
        ".config/systemd/user",
        ".config/environment.d",
        ".local/bin",
        "Library/LaunchAgents",
    ] {
        add(Persistence, Write, GuardTarget::Subtree(h(subtree)));
    }

    // ── Pent's own files ─────────────────────────────────────────────────────
    for subtree in [".config/pent", ".local/state/pent"] {
        add(PentFiles, Write, GuardTarget::Subtree(h(subtree)));
    }

    // ── Privilege escalation ─────────────────────────────────────────────────
    for name in ["sudo", "su", "pkexec", "doas", "run0"] {
        add(
            PrivilegeEscalation,
            ExecName,
            GuardTarget::BinaryName(name.to_string()),
        );
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_private_keys_match_but_public_keys_do_not() {
        let home = Path::new("/home/u");
        let rules = guard_rules(home);
        let read = GuardAccess::Read;
        assert_eq!(
            classify(&rules, &home.join(".ssh/id_ed25519"), read),
            Some(GuardClass::Credential)
        );
        assert_eq!(
            classify(&rules, &home.join(".ssh/id_ed25519.pub"), read),
            None
        );
        assert_eq!(classify(&rules, &home.join(".ssh/known_hosts"), read), None);
    }

    #[test]
    fn persistence_is_write_only() {
        let home = Path::new("/home/u");
        let rules = guard_rules(home);
        let rc = home.join(".bashrc");
        assert_eq!(classify(&rules, &rc, GuardAccess::Read), None);
        assert_eq!(
            classify(&rules, &rc, GuardAccess::Write),
            Some(GuardClass::Persistence)
        );
    }

    #[test]
    fn sudo_anywhere_is_escalation() {
        let rules = guard_rules(Path::new("/home/u"));
        assert_eq!(
            classify(
                &rules,
                Path::new("/run/wrappers/bin/sudo"),
                GuardAccess::ExecName
            ),
            Some(GuardClass::PrivilegeEscalation)
        );
    }
}
