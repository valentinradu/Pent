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
    /// Run a command in the sandbox with its trusted profile
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
}

#[derive(Args)]
pub(crate) struct RunArgs {
    /// The profile to apply. The default is the file name of the command
    /// (for example `claude` for `~/.local/bin/claude`)
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Network containment mode. This flag has precedence over --allow and
    /// over the profile. Without it, the mode is proxy when the profile or
    /// --allow gives domains, else blocked
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

    /// Add a traversal-only filesystem path for this run (repeatable)
    #[arg(long = "traverse", value_name = "PATH")]
    pub traverse: Vec<PathBuf>,

    /// Allow or set an environment variable (KEY or KEY=VALUE; repeatable)
    #[arg(long = "env", value_name = "KEY[=VALUE]")]
    pub env: Vec<String>,

    /// Override the sandbox data directory
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Write sandbox and proxy events to .pent/trace.log, and record the
    /// filesystem accesses that the sandbox denies. The process continues
    /// after a denial. Tracing does not change the network mode
    #[arg(long)]
    pub trace: bool,

    /// Disable filesystem sandbox (no Landlock, no overlayfs). Linux only.
    /// Network isolation is preserved unless --network unrestricted is also set.
    #[arg(long, hide = cfg!(target_os = "macos"))]
    pub no_sandbox: bool,

    /// Command and arguments to run inside the sandbox
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkModeArg {
    Unrestricted,
    Localhost,
    Proxy,
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
