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
    /// The files below `dir` whose name matches `prefix` and does not end
    /// with `exclude_suffix` (for example SSH private keys: prefix `id_`,
    /// exclude `.pub`).
    ///
    /// `prefix` is a file name prefix. A `prefix` that starts with `*` is a
    /// file name suffix instead: `*_rsa` matches `github_rsa`. See
    /// [`name_matches`].
    ///
    /// The rule matches a file at any depth below `dir`. The two kernel
    /// backends mask only the direct children of `dir` that exist when the
    /// child starts, and the macOS backend knows only the prefix form, so
    /// the kernel enforces less than this rule says. The summary and the
    /// review use the full rule, so a matched read always goes to the
    /// blocked section. See `docs/security/watch-and-profiles.md`.
    FilesInDir {
        /// The directory.
        dir: PathBuf,
        /// The file name prefix, or `*` and a file name suffix.
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
                path.starts_with(dir)
                    && path != dir
                    && path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                        name_matches(prefix, n)
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

/// Return true if the file name `name` matches the pattern `pattern` of
/// [`GuardTarget::FilesInDir`].
///
/// A pattern without a leading `*` is a file name prefix: `id_` matches
/// `id_ed25519`. A pattern with a leading `*` is a file name suffix:
/// `*_rsa` matches `github_rsa`, and `*.pem` matches `work.pem`.
#[must_use]
pub fn name_matches(pattern: &str, name: &str) -> bool {
    pattern.strip_prefix('*').map_or_else(
        || name.starts_with(pattern),
        |suffix| name.ends_with(suffix),
    )
}

/// Return the guard class of `path` for `access`, if a rule matches.
#[must_use]
pub fn classify(rules: &[GuardRule], path: &Path, access: GuardAccess) -> Option<GuardClass> {
    rules
        .iter()
        .find(|r| r.matches(path, access))
        .map(|r| r.class)
}

/// The file name patterns of an SSH private key. A key file has no fixed
/// name: `ssh-keygen -f github_rsa` and a downloaded `work.pem` are private
/// keys too. The public key has the suffix `.pub`, which the rule excludes.
const SSH_KEY_PATTERNS: &[&str] = &[
    "id_", "*_rsa", "*_dsa", "*_ecdsa", "*_ed25519", "*_key", "*.pem", "*.key",
];

/// The directories of the Python user site. A `.pth` file and
/// `usercustomize.py` run at the start of each Python process.
const PYTHON_USER_SITE_DIRS: &[&str] = &[".local/lib", "Library/Python"];

/// The file name patterns that run code at the start of a Python process.
const PYTHON_STARTUP_PATTERNS: &[&str] = &["*.pth", "usercustomize.py", "sitecustomize.py"];

/// Return the guard rules for the home directory `home`.
///
/// The rules use the default locations (`~/.config/pent`,
/// `~/.local/state/pent`) for the files of pent. A caller that knows the
/// real directories must use [`guard_rules_with`]: with `$XDG_CONFIG_HOME`
/// or `$XDG_STATE_HOME`, the files of pent are in another place.
///
/// The list has the Linux and the macOS paths. A path that does not exist
/// on a platform has no effect there.
#[must_use]
pub fn guard_rules(home: &Path) -> Vec<GuardRule> {
    guard_rules_with(home, &[])
}

/// Return the guard rules for the home directory `home`, with one
/// `PentFiles` rule for each directory in `pent_dirs`.
///
/// Give the real pent directories (`PentDirs::config` and
/// `PentDirs::state` of `pent-settings`). The default locations stay in the
/// list, so a duplicate directory is not a problem.
///
/// The other rules below `~/.config` (fish, autostart, systemd, git) still
/// use the default location. `$XDG_CONFIG_HOME` does not move them.
#[must_use]
pub fn guard_rules_with(home: &Path, pent_dirs: &[PathBuf]) -> Vec<GuardRule> {
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
    for pattern in SSH_KEY_PATTERNS {
        add(
            Credential,
            Read,
            GuardTarget::FilesInDir {
                dir: h(".ssh"),
                prefix: (*pattern).to_string(),
                exclude_suffix: Some(".pub".to_string()),
            },
        );
    }
    for exact in [
        ".aws/credentials",
        ".netrc",
        ".git-credentials",
        ".config/git/credentials",
        ".config/gh/hosts.yml",
        ".config/hub",
        ".config/glab-cli/config.yml",
        ".kube/config",
        ".docker/config.json",
        ".config/containers/auth.json",
        ".config/rclone/rclone.conf",
        ".config/sops/age/keys.txt",
        ".npmrc",
        ".pypirc",
        ".cargo/credentials.toml",
        ".cargo/credentials",
        ".gem/credentials",
        ".terraform.d/credentials.tfrc.json",
        ".vault-token",
        ".oci/config",
        ".pgpass",
        ".my.cnf",
        ".s3cfg",
        // The shell history often holds a token that the user typed. A
        // program that reads it gets the token without a prompt. The guard
        // hides the file, thus a shell in watch mode starts without its
        // history.
        ".bash_history",
        ".zsh_history",
        ".python_history",
        ".psql_history",
        ".local/share/fish/fish_history",
    ] {
        add(Credential, Read, GuardTarget::Exact(h(exact)));
    }
    for subtree in [
        ".aws/sso/cache",
        ".config/gcloud",
        ".config/op",
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
        // Shell start files.
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".bash_aliases",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".zlogout",
        ".kshrc",
        ".mkshrc",
        ".tcshrc",
        ".cshrc",
        ".xonshrc",
        // Session start files.
        ".pam_environment",
        ".xprofile",
        ".xinitrc",
        ".xsession",
        ".xsessionrc",
        ".ssh/environment",
        ".ssh/authorized_keys",
        ".ssh/config",
        ".ssh/rc",
        // Files that run code at the next start of a tool.
        ".gitconfig",
        ".config/git/config",
        ".vimrc",
        ".cargo/config.toml",
        ".cargo/config",
        ".npmrc",
        ".direnvrc",
        ".config/direnv/direnvrc",
    ] {
        add(Persistence, Write, GuardTarget::Exact(h(exact)));
    }
    for subtree in [
        // Shell and session configuration.
        ".config/fish",
        ".config/nushell",
        // The common `$ZDOTDIR`. Another `$ZDOTDIR` is not in the list.
        ".config/zsh",
        ".config/autostart",
        ".config/systemd/user",
        ".config/environment.d",
        ".config/cron",
        "Library/LaunchAgents",
        // Directories of the `PATH`. A binary here (for example `git`) runs
        // later outside of the sandbox.
        "bin",
        ".local/bin",
        ".cargo/bin",
        "go/bin",
        ".npm-global/bin",
        ".yarn/bin",
        // Editor and tool configuration that runs code.
        ".config/nvim",
        ".emacs.d",
        ".git-templates",
        ".config/git/hooks",
    ] {
        add(Persistence, Write, GuardTarget::Subtree(h(subtree)));
    }
    for dir in PYTHON_USER_SITE_DIRS {
        for pattern in PYTHON_STARTUP_PATTERNS {
            add(
                Persistence,
                Write,
                GuardTarget::FilesInDir {
                    dir: h(dir),
                    prefix: (*pattern).to_string(),
                    exclude_suffix: None,
                },
            );
        }
    }
    // Schedulers that keep their state outside of the home directory.
    for name in ["crontab", "at", "batch", "systemd-run"] {
        add(
            Persistence,
            ExecName,
            GuardTarget::BinaryName(name.to_string()),
        );
    }

    // ── Pent's own files ─────────────────────────────────────────────────────
    for subtree in [".config/pent", ".local/state/pent"] {
        add(PentFiles, Write, GuardTarget::Subtree(h(subtree)));
    }
    for dir in pent_dirs {
        add(PentFiles, Write, GuardTarget::Subtree(dir.clone()));
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
    fn ssh_private_keys_with_other_names_match() {
        let home = Path::new("/home/u");
        let rules = guard_rules(home);
        let read = GuardAccess::Read;
        for key in [
            ".ssh/github_rsa",
            ".ssh/work.pem",
            ".ssh/deploy_key",
            ".ssh/keys/id_ed25519",
            ".ssh/old/server_ed25519",
        ] {
            assert_eq!(
                classify(&rules, &home.join(key), read),
                Some(GuardClass::Credential),
                "{key}"
            );
        }
        for other in [
            ".ssh/known_hosts",
            ".ssh/authorized_keys",
            ".ssh/config",
            ".ssh/github_rsa.pub",
        ] {
            assert_eq!(classify(&rules, &home.join(other), read), None, "{other}");
        }
    }

    #[test]
    fn name_patterns_are_a_prefix_or_a_suffix() {
        assert!(name_matches("id_", "id_rsa"));
        assert!(!name_matches("id_", "my_id_rsa"));
        assert!(name_matches("*_rsa", "github_rsa"));
        assert!(!name_matches("*_rsa", "rsa_github"));
        assert!(name_matches("*", "anything"));
    }

    #[test]
    fn pent_files_follow_the_xdg_directories() {
        let home = Path::new("/home/u");
        let dirs = [
            PathBuf::from("/home/u/dotfiles/config/pent"),
            PathBuf::from("/home/u/dotfiles/state/pent"),
        ];
        let rules = guard_rules_with(home, &dirs);
        for path in [
            "/home/u/dotfiles/config/pent/trusted.toml",
            "/home/u/dotfiles/state/pent/drafts/x.toml",
            // The default locations stay in the list.
            "/home/u/.config/pent/profiles/x.toml",
        ] {
            assert_eq!(
                classify(&rules, Path::new(path), GuardAccess::Write),
                Some(GuardClass::PentFiles),
                "{path}"
            );
        }
        // Without the directories, the rules cover only the defaults.
        assert_eq!(
            classify(
                &guard_rules(home),
                Path::new("/home/u/dotfiles/config/pent/trusted.toml"),
                GuardAccess::Write,
            ),
            None
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
