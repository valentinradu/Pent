//! `pent config init|show|edit`: the global settings (`pent.toml`).
//!
//! The global settings have only the proxy tunables and the mounts. The paths
//! and the domains are in the profiles.

use std::path::{Path, PathBuf};

use pent_settings::{ConfigLoader, PentConfig};

use crate::cli::{ConfigSubcommand, OutputFormat};
use crate::error::CliError;
use crate::ui;

/// The starter text of `pent config init`.
const STARTER: &str = "\
# The global settings of pent.
# The paths and the domains are in the profiles: record one with `pent watch`.

[proxy]
# upstream_dns = [\"1.1.1.1:53\"]
# dns_ttl_seconds = 300
# tcp_connect_timeout_secs = 30
# tcp_idle_timeout_secs = 300
# private_destinations = \"deny\"

# Linux only: more mount points in the sandbox.
# [[sandbox.mounts]]
# path = \"/opt/tools\"
# readonly = true
";

/// The path of the global settings file.
fn global_path() -> Result<PathBuf, CliError> {
    ConfigLoader::global_config_path(pent_settings::PentDirs::from_env().as_ref()).ok_or_else(
        || {
            CliError::Other(
                "Cannot determine the global config path: the home directory is not available"
                    .to_string(),
            )
        },
    )
}

pub(crate) fn config(args: crate::cli::ConfigArgs, cwd: &Path) -> Result<(), CliError> {
    match args.subcommand {
        ConfigSubcommand::Init => init(),
        ConfigSubcommand::Show { format } => show(format, cwd),
        ConfigSubcommand::Edit => edit(),
    }
}

fn init() -> Result<(), CliError> {
    let path = global_path()?;
    if path.exists() {
        return Err(CliError::Other(format!(
            "Config file already exists: {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, STARTER)?;
    ui::ok(format!("created {}", path.display()));
    Ok(())
}

fn show(format: OutputFormat, cwd: &Path) -> Result<(), CliError> {
    let config = ConfigLoader::load(cwd, pent_settings::PentDirs::from_env().as_ref())?;
    match format {
        OutputFormat::Toml => print!("{}", config.to_toml()?),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)
                .map_err(|e| CliError::Other(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        }
    }
    // The status line goes to stderr, thus stdout stays valid TOML or JSON.
    let path = global_path()?;
    let found = if path.exists() { "found" } else { "not found" };
    ui::status("global", format!("{} ({found})", path.display()));
    Ok(())
}

fn edit() -> Result<(), CliError> {
    let path = global_path()?;
    // Try $VISUAL, then $EDITOR, then fall back to vi.
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor).arg(&path).status()?;
    if !status.success() {
        return Err(CliError::Other(format!(
            "The editor {editor} failed ({status})"
        )));
    }
    if path.exists() {
        // Check the result now, so that the next `pent run` does not fail.
        PentConfig::load(&path)?;
        ui::ok(format!("{} is valid", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_is_a_valid_config() {
        let parsed = PentConfig::parse(STARTER);
        assert!(parsed.is_ok(), "{parsed:?}");
    }
}
