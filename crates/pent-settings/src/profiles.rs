//! Named configuration profiles for common development tools.
//!
//! Profiles produce additions to `[proxy] domain_allowlist` and
//! `[sandbox.paths.*]`. They are a command-level abstraction only;
//! the `PentConfig` struct and TOML format are unchanged.

use std::fmt;
use std::str::FromStr;

use crate::{PentConfig, ProxySettings, SandboxPaths, SandboxSettings};

/// A named configuration profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Base,
    Npm,
    Cargo,
    Pip,
    Gem,
    Go,
    Brew,
    Node,
    Gh,
    Git,
    Ssh,
    Keychain,
    Claude,
    Codex,
    Gemini,
}

/// Single source of truth mapping each variant to its `@name` string.
/// `Display`, `FromStr`, and `all()` are all derived from this table.
const PROFILES: &[(Profile, &str)] = &[
    (Profile::Base, "@base"),
    (Profile::Npm, "@npm"),
    (Profile::Cargo, "@cargo"),
    (Profile::Pip, "@pip"),
    (Profile::Gem, "@gem"),
    (Profile::Go, "@go"),
    (Profile::Brew, "@brew"),
    (Profile::Node, "@node"),
    (Profile::Gh, "@gh"),
    (Profile::Git, "@git"),
    (Profile::Ssh, "@ssh"),
    (Profile::Keychain, "@keychain"),
    (Profile::Claude, "@claude"),
    (Profile::Codex, "@codex"),
    (Profile::Gemini, "@gemini"),
];

impl Profile {
    /// Returns an iterator over every defined profile variant.
    pub fn all() -> impl Iterator<Item = Profile> {
        PROFILES.iter().map(|(p, _)| *p)
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = PROFILES
            .iter()
            .find(|(p, _)| p == self)
            .map(|(_, s)| *s)
            .expect("all Profile variants are in PROFILES");
        write!(f, "{name}")
    }
}

impl FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PROFILES
            .iter()
            .find(|(_, name)| *name == s)
            .map(|(p, _)| *p)
            .ok_or_else(|| {
                let valid: Vec<&str> = PROFILES.iter().map(|(_, n)| *n).collect();
                format!("unknown profile '{}'; valid profiles: {}", s, valid.join(" "))
            })
    }
}

/// Returns the direct dependencies of a profile.
pub fn profile_requires(p: Profile) -> &'static [Profile] {
    static NODE_DEP: [Profile; 1] = [Profile::Node];
    static SSH_DEP: [Profile; 1] = [Profile::Ssh];
    static KEYCHAIN_DEP: [Profile; 1] = [Profile::Keychain];
    static NODE_BASE_DEP: [Profile; 2] = [Profile::Node, Profile::Base];
    static NPM_SSH_GIT_DEP: [Profile; 3] = [Profile::Npm, Profile::Ssh, Profile::Git];
    static NPM_DEP: [Profile; 1] = [Profile::Npm];
    match p {
        Profile::Claude => &NPM_SSH_GIT_DEP,
        Profile::Codex => &NPM_DEP,
        Profile::Gemini => &NODE_DEP,
        Profile::Npm => &NODE_BASE_DEP,
        Profile::Gh => &SSH_DEP,
        Profile::Git => &KEYCHAIN_DEP,
        _ => &[],
    }
}

/// Returns the full transitive dependency closure, deduplicated, deps-first.
pub fn profile_deps_transitive(profiles: &[Profile]) -> Vec<Profile> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for &p in profiles {
        expand_deps(p, &mut result, &mut seen);
    }
    result
}

fn expand_deps(
    p: Profile,
    result: &mut Vec<Profile>,
    seen: &mut std::collections::HashSet<Profile>,
) {
    if seen.contains(&p) {
        return;
    }
    for dep in profile_requires(p) {
        expand_deps(*dep, result, seen);
    }
    if seen.insert(p) {
        result.push(p);
    }
}

/// Returns the `PentConfig` fragment for a single profile (platform-aware).
fn profile_config(p: Profile) -> PentConfig {
    let macos = std::env::consts::OS == "macos";

    match p {
        // ── @base ─────────────────────────────────────────────────────────────
        // Shell init files, user-local binaries, and PATH helpers.
        // Any profile that spawns subprocesses or shells should depend on this.
        Profile::Base => PentConfig {
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    traversal: vec!["~/.local".to_string()],
                    read: if macos {
                        vec![
                            // zsh init files (non-interactive, login, interactive)
                            "~/.zshenv".to_string(),
                            "~/.zprofile".to_string(),
                            "~/.zshrc".to_string(),
                            // bash init files (used by some tools and scripts)
                            "~/.bashrc".to_string(),
                            "~/.bash_profile".to_string(),
                            // POSIX shell profile
                            "~/.profile".to_string(),
                        ]
                    } else {
                        vec![
                            "~/.bashrc".to_string(),
                            "~/.bash_profile".to_string(),
                            "~/.profile".to_string(),
                        ]
                    },
                    execute: if macos {
                        vec![
                            // macOS PATH helper — reads /etc/paths and /etc/paths.d
                            "/usr/libexec/path_helper".to_string(),
                            // user-local binaries (e.g. pipx, mise, custom env shims)
                            "~/.local/bin".to_string(),
                        ]
                    } else {
                        vec![
                            // user-local binaries (e.g. pipx, mise, custom env shims)
                            "~/.local/bin".to_string(),
                        ]
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },

        // ── @npm ──────────────────────────────────────────────────────────────
        Profile::Npm => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "registry.npmjs.org".to_string(),
                    "*.npmjs.org".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: vec!["~/.npm".to_string()],
                    // Per-user npm config (registry overrides, auth tokens, etc.)
                    read: vec!["~/.npmrc".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @cargo ────────────────────────────────────────────────────────────
        Profile::Cargo => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "crates.io".to_string(),
                    "static.crates.io".to_string(),
                    "index.crates.io".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    // ~/.cargo — registry cache, installed binaries, build artifacts.
                    // ~/.rustup — toolchain binaries (rustc, std libs) managed by rustup.
                    read_write: vec!["~/.cargo".to_string(), "~/.rustup".to_string()],
                    // ~/.cargo/env is sourced by shell init to add ~/.cargo/bin to $PATH.
                    read: vec!["~/.cargo/env".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @pip ──────────────────────────────────────────────────────────────
        Profile::Pip => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "pypi.org".to_string(),
                    "files.pythonhosted.org".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: if macos {
                        vec![
                            "~/Library/Caches/pip".to_string(),
                            // pipx and venv home
                            "~/.local/share/pipx".to_string(),
                        ]
                    } else {
                        vec![
                            "~/.cache/pip".to_string(),
                            "~/.local/share/pipx".to_string(),
                        ]
                    },
                    // pip config files (index URL, trusted hosts, etc.)
                    read: vec![
                        "~/.pip".to_string(),
                        "~/.config/pip".to_string(),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @gem ──────────────────────────────────────────────────────────────
        Profile::Gem => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "rubygems.org".to_string(),
                    "*.rubygems.org".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: if macos {
                        vec!["~/.gem".to_string()]
                    } else {
                        vec!["~/.gem".to_string(), "~/.local/share/gem".to_string()]
                    },
                    // Per-user gem config (custom sources, credentials)
                    read: vec!["~/.gemrc".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @go ───────────────────────────────────────────────────────────────
        Profile::Go => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "proxy.golang.org".to_string(),
                    "sum.golang.org".to_string(),
                    "storage.googleapis.com".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: vec!["~/go".to_string()],
                    // Go user config (GOPATH overrides, telemetry opt-out, etc.)
                    read: vec!["~/.config/go".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @brew ─────────────────────────────────────────────────────────────
        Profile::Brew => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "formulae.brew.sh".to_string(),
                    "ghcr.io".to_string(),
                    "raw.githubusercontent.com".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: if macos {
                        vec!["/opt/homebrew".to_string(), "/usr/local".to_string()]
                    } else {
                        vec!["/home/linuxbrew/.linuxbrew".to_string()]
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @node ─────────────────────────────────────────────────────────────
        Profile::Node => PentConfig {
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    traversal: vec!["~".to_string()],
                    read: if macos {
                        vec![
                            "~/.CFUserTextEncoding".to_string(),
                            "~/Library/Preferences".to_string(),
                            "~/Library/Application Support/com.apple.TCC".to_string(),
                        ]
                    } else {
                        vec![]
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },

        // ── @gh ───────────────────────────────────────────────────────────────
        Profile::Gh => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "github.com".to_string(),
                    "*.github.com".to_string(),
                    "raw.githubusercontent.com".to_string(),
                    "objects.githubusercontent.com".to_string(),
                    "codeload.github.com".to_string(),
                    "api.github.com".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: vec!["~/.config/gh".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        // ── @git ──────────────────────────────────────────────────────────────
        Profile::Git => PentConfig {
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read: vec![
                        "~/.gitconfig".to_string(),
                        // XDG git config directory (config, ignore, attributes)
                        "~/.config/git".to_string(),
                        // Common machine-local include (often referenced from .gitconfig)
                        "~/.gitconfig_local".to_string(),
                        // GitHub CLI config (read for auth; @gh adds read_write if needed)
                        "~/.config/gh".to_string(),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },

        // ── @ssh ──────────────────────────────────────────────────────────────
        Profile::Ssh => PentConfig {
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    // ~/.ssh/config.d — included configs (Include directive)
                    traversal: vec!["~/.ssh".to_string()],
                    // Read access to SSH client config files.
                    // Private keys (~/.ssh/id_*) are intentionally excluded — grant
                    // those explicitly if the sandboxed process needs to authenticate.
                    read: vec![
                        "~/.ssh/known_hosts".to_string(),
                        "~/.ssh/config".to_string(),
                        "~/.ssh/config.d".to_string(),
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },

        Profile::Keychain => PentConfig {
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: if macos {
                        vec!["~/Library/Keychains".to_string()]
                    } else {
                        vec![
                            "~/.local/share/keyrings".to_string(),
                            "~/.local/share/kwalletd".to_string(),
                        ]
                    },
                    read: if macos {
                        vec![]
                    } else {
                        vec!["~/.password-store".to_string()]
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },

        Profile::Claude => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "api.anthropic.com".to_string(),
                    "statsig.anthropic.com".to_string(),
                    "sentry.io".to_string(),
                    // Claude Code marketplace fetches plugin indices and files from GitHub.
                    "github.com".to_string(),
                    "api.github.com".to_string(),
                    "raw.githubusercontent.com".to_string(),
                    "objects.githubusercontent.com".to_string(),
                    "codeload.github.com".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    // ~/.claude — credentials, sessions, and conversation history.
                    // Without read-write access the CLI cannot authenticate.
                    // ~/.local/share/claude — the Claude Code binary reads its own
                    // version/runtime files from here (installed via npm/bun).
                    read_write: if macos {
                        vec![
                            "~/.claude".to_string(),
                            "~/.claude.json".to_string(),
                            "~/.claude.lock".to_string(),
                            "~/.local/share/claude".to_string(),
                            // macOS user app data — Claude Code stores runtime
                            // state here (e.g. "Application Support/claude/...").
                            "~/Library/Application Support/claude".to_string(),
                            // Marketplace staging cache.
                            "~/.cache/claude".to_string(),
                        ]
                    } else {
                        vec![
                            "~/.claude".to_string(),
                            "~/.claude.json".to_string(),
                            "~/.claude.lock".to_string(),
                            "~/.local/share/claude".to_string(),
                            "~/.cache/claude".to_string(),
                        ]
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        Profile::Codex => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "api.openai.com".to_string(),
                    "*.openai.com".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    read_write: vec!["~/.codex".to_string()],
                    traversal: vec!["~/.agents".to_string()],
                    // ~/.agents/skills is the built-in user-level skills directory
                    // where Codex discovers custom automation plugins.
                    read: vec!["~/.agents/skills".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        },

        Profile::Gemini => PentConfig {
            proxy: ProxySettings {
                domain_allowlist: vec![
                    "generativelanguage.googleapis.com".to_string(),
                    "aiplatform.googleapis.com".to_string(),
                    "cloudresourcemanager.googleapis.com".to_string(),
                    "oauth2.googleapis.com".to_string(),
                    "accounts.google.com".to_string(),
                    "cloudcode-pa.googleapis.com".to_string(),
                    "play.googleapis.com".to_string(),
                ],
                ..Default::default()
            },
            sandbox: SandboxSettings {
                paths: SandboxPaths {
                    // Execute access to npm global install directory so Node can
                    // resolve modules from ~/.npm-global/lib/node_modules/ and
                    // run the binary at ~/.npm-global/bin/gemini.
                    execute: vec!["~/.npm-global".to_string()],
                    read_write: if macos {
                        vec![
                            "~/Library/Application Support/gemini-cli".to_string(),
                            "~/.gemini".to_string(),
                        ]
                    } else {
                        vec!["~/.gemini".to_string()]
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        },
    }
}

/// Merges the config fragments for all given profiles into a single `PentConfig`.
pub fn build_profiles_config(profiles: &[Profile]) -> PentConfig {
    profiles
        .iter()
        .fold(PentConfig::default(), |acc, &p| acc.merge(profile_config(p)))
}

/// Returns `true` if a profile appears to be active in the given config.
///
/// For profiles with domains: active when ≥1 domain is in `domain_allowlist`.
/// For path-only profiles (node, git, keychain): active when ≥1 path from the
/// profile's fragment is present in the config's path lists.
pub fn is_profile_likely_active(config: &PentConfig, p: Profile) -> bool {
    let fragment = profile_config(p);

    if !fragment.proxy.domain_allowlist.is_empty() {
        return fragment
            .proxy
            .domain_allowlist
            .iter()
            .any(|d| config.proxy.domain_allowlist.contains(d));
    }

    // Path-only profile: check all path categories
    let paths = &fragment.sandbox.paths;
    for path in &paths.traversal {
        if config.sandbox.paths.traversal.contains(path) {
            return true;
        }
    }
    for path in &paths.read {
        if config.sandbox.paths.read.contains(path) {
            return true;
        }
    }
    for path in &paths.execute {
        if config.sandbox.paths.execute.contains(path) {
            return true;
        }
    }
    for path in &paths.read_write {
        if config.sandbox.paths.read_write.contains(path) {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_from_str_valid() {
        assert_eq!("@npm".parse::<Profile>().unwrap(), Profile::Npm);
        assert_eq!("@cargo".parse::<Profile>().unwrap(), Profile::Cargo);
        assert_eq!("@codex".parse::<Profile>().unwrap(), Profile::Codex);
        assert_eq!("@gemini".parse::<Profile>().unwrap(), Profile::Gemini);
    }

    #[test]
    fn test_profile_from_str_invalid() {
        let err = "@unknown-profile".parse::<Profile>().unwrap_err();
        assert!(err.contains("unknown profile"));
        assert!(err.contains("@unknown-profile"));
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(Profile::Npm.to_string(), "@npm");
        assert_eq!(Profile::Codex.to_string(), "@codex");
        assert_eq!(Profile::Gemini.to_string(), "@gemini");
    }

    #[test]
    fn test_profile_requires_npm() {
        let deps = profile_requires(Profile::Npm);
        assert_eq!(deps, &[Profile::Node, Profile::Base]);
    }

    #[test]
    fn test_profile_requires_node_has_no_deps() {
        let deps = profile_requires(Profile::Node);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_profile_deps_transitive_npm() {
        let expanded = profile_deps_transitive(&[Profile::Npm]);
        assert_eq!(expanded, vec![Profile::Node, Profile::Base, Profile::Npm]);
    }

    #[test]
    fn test_profile_deps_transitive_node_not_duplicated() {
        // Both npm and claude depend on node; node should appear once
        let expanded = profile_deps_transitive(&[Profile::Npm, Profile::Claude]);
        assert_eq!(expanded.iter().filter(|p| **p == Profile::Node).count(), 1);
    }

    #[test]
    fn test_profile_deps_transitive_no_deps() {
        let expanded = profile_deps_transitive(&[Profile::Cargo]);
        assert_eq!(expanded, vec![Profile::Cargo]);
    }

    #[test]
    fn test_build_profiles_config_npm_has_domains() {
        let config = build_profiles_config(&[Profile::Npm]);
        assert!(config
            .proxy
            .domain_allowlist
            .contains(&"registry.npmjs.org".to_string()));
    }

    #[test]
    fn test_is_profile_likely_active_domain() {
        let config = PentConfig {
            proxy: crate::ProxySettings {
                domain_allowlist: vec!["registry.npmjs.org".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(is_profile_likely_active(&config, Profile::Npm));
        assert!(!is_profile_likely_active(&config, Profile::Cargo));
    }

    #[test]
    fn test_is_profile_likely_active_path_only() {
        let config = PentConfig {
            sandbox: crate::SandboxSettings {
                paths: crate::SandboxPaths {
                    traversal: vec!["~".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(is_profile_likely_active(&config, Profile::Node));
        assert!(!is_profile_likely_active(&config, Profile::Git));
    }
}
