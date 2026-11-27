use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "pent",
    version,
    about = "Run processes under filesystem and network containment"
)]
pub(crate) struct Cli {
    /// Increase log verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Run a command in the sandbox with the rules of its key
    Run(RunArgs),
    /// Record what a command does and make a draft profile from it.
    /// Watch mode does not sandbox the command
    Watch(WatchArgs),
    /// Show the draft of a profile, then trust it.
    /// With --review, review the accesses that `pent run` denied
    Trust(TrustArgs),
    /// Remove the trust of a profile. `pent run` then does not apply it
    Untrust(UntrustArgs),
    /// List, show or remove profiles
    Profile(ProfileArgs),
    /// Check that sandboxing and proxy are available on this system
    Check,
    /// Manage the global settings (pent.toml)
    Config(ConfigArgs),
    /// Run pentd, the daemon that holds the questions, in the foreground
    Daemon(DaemonArgs),
    /// Allow one open question. `pent questions` shows the codes
    Allow(AnswerArgs),
    /// Deny one open question. `pent questions` shows the codes. Inside
    /// the sandbox of `pent run`, the deny holds for this run and for the
    /// exact target
    Deny(AnswerArgs),
    /// Inside the sandbox of `pent run`: send one open question of the run
    /// up to the human, with a reason
    Skip(SkipArgs),
    /// List the open questions with their width menus
    Questions(QuestionsArgs),
    /// Answer the questions, and see the events and the rules, on a
    /// terminal screen. pentd must run
    Monitor,
    /// Show the accesses that pent refused in a session, or in each session
    Denials(DenialsArgs),
    /// List, show or forget the rules
    Rules(RulesArgs),
}

#[derive(Args)]
pub(crate) struct AnswerArgs {
    /// The code of the question, for example k3m9tx
    pub id: String,

    /// The place of the target in the width menu of the question. 0 is
    /// the exact target. `pent questions` shows the menu
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub width: u16,

    /// Keep the answer as a rule for the next runs. Without this flag, the
    /// answer holds only for the runs that wait now
    #[arg(long)]
    pub remember: bool,
}

#[derive(Args)]
pub(crate) struct SkipArgs {
    /// The code of the question, for example k3m9tx. `pent denials` shows
    /// it
    pub id: String,

    /// Why the human must answer it, in at most 512 bytes. The human sees
    /// it as untrusted text
    pub reason: String,
}

#[derive(Args)]
pub(crate) struct QuestionsArgs {
    /// Print each question as one line of JSON (for scripts). Each skip of
    /// the agent is one more line {"skip":{"id":..,"reason":..}}, and its
    /// reason is untrusted text
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub(crate) struct DenialsArgs {
    /// The code of the session, for example k3m9tx. Without it, pent shows
    /// each session
    pub session: Option<String>,
}

#[derive(Args)]
pub(crate) struct RulesArgs {
    #[command(subcommand)]
    pub subcommand: RulesSubcommand,
}

#[derive(Subcommand)]
pub(crate) enum RulesSubcommand {
    /// List the keys that have rules
    List,
    /// Show the rules of a key, with their numbers
    Show {
        /// The key: the file name of the root program
        key: String,
    },
    /// Remove one rule of a key, or each rule of the key. pentd must run
    Forget {
        /// The key: the file name of the root program
        key: String,
        /// The number of the rule in `pent rules show KEY`. Without it,
        /// pent removes each rule of the key
        rule: Option<usize>,
    },
}

#[derive(Args)]
pub(crate) struct DaemonArgs {
    /// `pent run` starts pentd with this flag: pentd stops a few seconds
    /// after the last hold, and it stops in silence when another pentd runs
    #[arg(long, hide = true)]
    pub spawned: bool,
}

#[derive(Args)]
pub(crate) struct RunArgs {
    /// The key of the rules. The default is the file name of the command
    /// (for example `claude` for `~/.local/bin/claude`)
    #[arg(long, value_name = "NAME")]
    pub key: Option<String>,

    /// Give the workspace read, write and exec access for this run: the
    /// current directory, or DIR with -w=DIR. Without this flag the
    /// workspace is not in the base, and pent does not keep the flag as a
    /// rule
    #[arg(
        short = 'w',
        long,
        value_name = "DIR",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "."
    )]
    pub workspace: Option<PathBuf>,

    /// Network containment mode. Without it, DNS, the proxy, the Unix
    /// sockets and the ports ask a question for each access that no rule
    /// answers. `blocked` refuses each such access with no question, and
    /// `unrestricted` gives the network of the host. This flag has
    /// precedence over --allow and over the rules
    #[arg(long, value_enum)]
    pub network: Option<NetworkModeArg>,

    /// Add a domain to the proxy allowlist for this run (repeatable)
    #[arg(long = "allow", value_name = "DOMAIN")]
    pub allow: Vec<String>,

    /// Add a read-only filesystem path for this run (repeatable)
    #[arg(long = "read", value_name = "PATH")]
    pub read: Vec<PathBuf>,

    /// Add a read-write filesystem path for this run (repeatable)
    #[arg(long = "write", value_name = "PATH")]
    pub write: Vec<PathBuf>,

    /// Add an executable filesystem path for this run. This gives read
    /// access too (repeatable)
    #[arg(long = "execute", value_name = "PATH")]
    pub execute: Vec<PathBuf>,

    /// Let the command connect to this Unix socket for this run. The rule
    /// is strong: a program that reaches the socket of an agent can use the
    /// key of that agent (repeatable)
    #[arg(long = "unix-socket", value_name = "PATH")]
    pub unix_socket: Vec<PathBuf>,

    /// Let the command connect to this TCP port on the loopback of the host
    /// (127.0.0.1, ::1) for this run. A server that the command itself runs
    /// needs no rule (repeatable)
    #[arg(long = "localhost", value_name = "PORT")]
    pub localhost: Vec<std::num::NonZeroU16>,

    /// Allow or set an environment variable (KEY or KEY=VALUE; repeatable)
    #[arg(long = "env", value_name = "KEY[=VALUE]")]
    pub env: Vec<String>,

    /// Write sandbox and proxy events to ~/.local/state/pent/trace/NAME.log,
    /// and record the
    /// filesystem accesses that the sandbox denies. The process continues
    /// after a denial. Tracing does not change the network mode
    #[arg(long)]
    pub trace: bool,

    /// Disable filesystem sandbox (no Landlock, no overlayfs).
    /// Network isolation is preserved unless --network unrestricted is also set.
    #[arg(long)]
    pub no_sandbox: bool,

    /// Command and arguments to run inside the sandbox
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkModeArg {
    Unrestricted,
    Blocked,
}

#[derive(Args)]
pub(crate) struct WatchArgs {
    /// The profile to record. The default is the file name of the command
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Merge this run into the current draft. Without this flag, the run
    /// starts a new draft
    #[arg(long)]
    pub append: bool,

    /// Do not ask before the start (for scripts)
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Network containment mode. This flag has precedence over --allow.
    /// Without it and without --allow, the network is open: the proxy
    /// observes each request and allows each domain
    #[arg(long, value_enum)]
    pub network: Option<NetworkModeArg>,

    /// Add a domain to the proxy allowlist for this run. The proxy then
    /// enforces the allowlist and refuses each other domain (repeatable)
    #[arg(long = "allow", value_name = "DOMAIN")]
    pub allow: Vec<String>,

    /// Command and arguments to record
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Args)]
pub(crate) struct TrustArgs {
    /// The profile name
    pub name: String,

    /// Trust the profile without a question
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Review the accesses that `pent run` denied since the last trust, and
    /// add the selected rules to the profile
    #[arg(long)]
    pub review: bool,
}

#[derive(Args)]
pub(crate) struct UntrustArgs {
    /// The profile name
    pub name: String,
}

#[derive(Args)]
pub(crate) struct ProfileArgs {
    #[command(subcommand)]
    pub subcommand: ProfileSubcommand,
}

#[derive(Subcommand)]
pub(crate) enum ProfileSubcommand {
    /// List the profiles, their trust status and the drafts
    List,
    /// Print a profile (or its draft, if no profile exists)
    Show {
        /// The profile name
        name: String,
    },
    /// Remove a profile, its draft, its trust entry and its logs
    #[command(name = "rm")]
    Remove {
        /// The profile name
        name: String,
    },
}

#[derive(Args)]
pub(crate) struct ConfigArgs {
    #[command(subcommand)]
    pub subcommand: ConfigSubcommand,
}

#[derive(Subcommand)]
pub(crate) enum ConfigSubcommand {
    /// Write a starter global settings file
    Init,
    /// Print the global settings
    Show {
        #[arg(long, value_enum, default_value = "toml")]
        format: OutputFormat,
    },
    /// Open the global settings file in $EDITOR
    Edit,
}

#[derive(ValueEnum, Clone, Copy)]
pub(crate) enum OutputFormat {
    Toml,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The run arguments of `argv`, or `None` when clap refuses them.
    fn run_args(argv: &[&str]) -> Option<RunArgs> {
        match Cli::try_parse_from(argv).ok()?.command {
            Command::Run(args) => Some(args),
            _ => None,
        }
    }

    #[test]
    fn the_workspace_flag_takes_its_directory_only_after_an_equals_sign() {
        let plain = run_args(&["pent", "run", "-w", "cargo", "build"]);
        assert_eq!(
            plain
                .as_ref()
                .map(|a| (a.workspace.clone(), a.command.clone())),
            Some((
                Some(PathBuf::from(".")),
                vec!["cargo".to_string(), "build".to_string()]
            ))
        );
        let other = run_args(&["pent", "run", "-w=../x", "--", "make"]);
        assert_eq!(other.and_then(|a| a.workspace), Some(PathBuf::from("../x")));
        let long = run_args(&["pent", "run", "--workspace=/srv/a", "true"]);
        assert_eq!(
            long.and_then(|a| a.workspace),
            Some(PathBuf::from("/srv/a"))
        );
        let none = run_args(&["pent", "run", "true"]);
        assert_eq!(none.map(|a| a.workspace), Some(None));
    }

    #[test]
    fn the_old_flags_of_run_are_gone() {
        assert!(run_args(&["pent", "run", "--data-dir", "/x", "true"]).is_none());
        assert!(run_args(&["pent", "run", "--traverse", "/x", "true"]).is_none());
    }
}
