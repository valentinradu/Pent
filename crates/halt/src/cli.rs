use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "halt",
    about = "Run processes under filesystem and network containment"
)]
pub struct Cli {
    /// Increase log verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a command inside the sandbox
    Run(RunArgs),
    /// Check that sandboxing and proxy are available on this system
    Check,
    /// Manage halt configuration
    Config(ConfigArgs),
}

#[derive(Args)]
pub struct RunArgs {
    /// Network containment mode
    #[arg(long, value_enum)]
    pub network: Option<NetworkModeArg>,

    /// Add domain to proxy allowlist (implies --network proxy; repeatable)
    #[arg(long = "allow", value_name = "DOMAIN")]
    pub allow: Vec<String>,

    /// Add read-only filesystem path (repeatable)
    #[arg(long = "read", value_name = "PATH")]
    pub read: Vec<PathBuf>,

    /// Add read-write filesystem path (repeatable)
    #[arg(long = "write", value_name = "PATH")]
    pub write: Vec<PathBuf>,

    /// Add traversal-only filesystem path (repeatable)
    #[arg(long = "traverse", value_name = "PATH")]
    pub traverse: Vec<PathBuf>,

    /// Allow or set an environment variable (KEY or KEY=VALUE; repeatable)
    #[arg(long = "env", value_name = "KEY[=VALUE]")]
    pub env: Vec<String>,

    /// Override the sandbox data directory
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Load an additional config file on top of defaults
    #[arg(long = "config", value_name = "PATH")]
    pub extra_config: Option<PathBuf>,

    /// Ignore all config files; use only CLI flags
    #[arg(long)]
    pub no_config: bool,

    /// Log every sandbox and proxy violation to .halt/trace.log without
    /// killing the process (useful for discovering which paths and domains to
    /// add to a profile)
    #[arg(long)]
    pub trace: bool,

    /// Command and arguments to run inside the sandbox
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum NetworkModeArg {
    Unrestricted,
    Localhost,
    Proxy,
    Blocked,
}

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub subcommand: ConfigSubcommand,
}

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    /// Write a starter config file
    Init {
        #[arg(long)]
        global: bool,
    },
    /// Print the effective merged configuration
    Show {
        #[arg(long, value_enum, default_value = "toml")]
        format: OutputFormat,
    },
    /// Open config in $EDITOR
    Edit {
        #[arg(long)]
        global: bool,
    },
    /// Add one or more profiles (e.g. @npm @cargo @gh)
    Add {
        #[arg(required = true, num_args = 1..)]
        profiles: Vec<String>,
        #[arg(long)]
        global: bool,
    },
    /// Remove one or more profiles
    #[command(name = "rm")]
    Remove {
        #[arg(required = true, num_args = 1..)]
        profiles: Vec<String>,
        #[arg(long)]
        global: bool,
    },
}

#[derive(ValueEnum, Clone, Copy)]
pub enum OutputFormat {
    Toml,
    Json,
}
