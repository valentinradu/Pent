use std::path::{Path, PathBuf};
use std::str::FromStr;

use halt_settings::{
    build_profiles_config, is_profile_likely_active, profile_deps_transitive, profile_requires,
    ConfigLoader, HaltConfig, Profile,
};

use crate::cli::{ConfigSubcommand, OutputFormat};
use crate::error::CliError;

/// Resolve the config file path for `--global` or project-local operations.
fn resolve_config_path(global: bool, cwd: &Path) -> Result<PathBuf, CliError> {
    if global {
        ConfigLoader::global_config_path().ok_or_else(|| {
            CliError::Other(
                "Cannot determine global config path: home directory not available".to_string(),
            )
        })
    } else {
        Ok(ConfigLoader::project_config_path(cwd))
    }
}

pub async fn config(args: crate::cli::ConfigArgs, cwd: PathBuf) -> Result<(), CliError> {
    match args.subcommand {
        ConfigSubcommand::Init { global } => init(global, &cwd),
        ConfigSubcommand::Show { format } => show(format, &cwd),
        ConfigSubcommand::Edit { global } => edit(global, &cwd),
        ConfigSubcommand::Add { profiles, global } => add_profile(global, profiles, &cwd),
        ConfigSubcommand::Remove { profiles, global } => rm_profile(global, profiles, &cwd),
    }
}

fn init(global: bool, cwd: &Path) -> Result<(), CliError> {
    let path = resolve_config_path(global, cwd)?;

    if path.exists() {
        return Err(CliError::Other(format!(
            "Config file already exists: {}",
            path.display()
        )));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    HaltConfig::default().save(&path)?;
    tracing::info!(path = %path.display(), "created config");
    Ok(())
}

fn show(format: OutputFormat, cwd: &Path) -> Result<(), CliError> {
    let config = ConfigLoader::load(cwd)?;
    match format {
        OutputFormat::Toml => {
            let toml = config.to_toml()?;
            print!("{toml}");
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)
                .map_err(|e| CliError::Other(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        }
    }
    Ok(())
}

fn edit(global: bool, cwd: &Path) -> Result<(), CliError> {
    let path = resolve_config_path(global, cwd)?;

    // Try $VISUAL, then $EDITOR, then fall back to vi.
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    std::process::Command::new(&editor).arg(&path).status()?;

    Ok(())
}

fn add_profile(global: bool, profiles: Vec<String>, cwd: &Path) -> Result<(), CliError> {
    let parsed: Vec<Profile> = profiles
        .iter()
        .map(|s| Profile::from_str(s).map_err(CliError::Other))
        .collect::<Result<_, _>>()?;

    let expanded = profile_deps_transitive(&parsed);

    let path = resolve_config_path(global, cwd)?;

    let existing = if path.exists() {
        HaltConfig::load(&path)?
    } else {
        HaltConfig::default()
    };

    let fragment = build_profiles_config(&expanded);
    let merged = existing.merge(fragment);
    merged.save(&path)?;

    let names: Vec<String> = expanded.iter().map(ToString::to_string).collect();
    tracing::info!(profiles = %names.join(" "), path = %path.display(), "added profiles");
    Ok(())
}

fn rm_profile(global: bool, profiles: Vec<String>, cwd: &Path) -> Result<(), CliError> {
    let parsed: Vec<Profile> = profiles
        .iter()
        .map(|s| Profile::from_str(s).map_err(CliError::Other))
        .collect::<Result<_, _>>()?;

    let removing_set: std::collections::HashSet<String> =
        parsed.iter().map(ToString::to_string).collect();

    let path = resolve_config_path(global, cwd)?;

    if !path.exists() {
        return Err(CliError::Other("No config file found".to_string()));
    }
    let mut config = HaltConfig::load(&path)?;

    // Check for active dependents not included in this removal
    for p in &parsed {
        let mut blocking: Vec<String> = Vec::new();
        for dependent in Profile::all() {
            if profile_requires(dependent).contains(p)
                && !removing_set.contains(&dependent.to_string())
                && is_profile_likely_active(&config, dependent)
            {
                blocking.push(dependent.to_string());
            }
        }
        if !blocking.is_empty() {
            let blocker = &blocking[0];
            let mut hint: Vec<String> = blocking.clone();
            hint.extend(parsed.iter().map(ToString::to_string));
            return Err(CliError::Other(format!(
                "cannot remove '{}': profile '{}' appears active and depends on it.\nRun: halt config rm {}",
                p,
                blocker,
                hint.join(" ")
            )));
        }
    }

    // Build removal fragment and remove matching values
    let removal = build_profiles_config(&parsed);
    let rm_domains: std::collections::HashSet<String> =
        removal.proxy.domain_allowlist.into_iter().collect();
    let rm_traversal: std::collections::HashSet<String> =
        removal.sandbox.paths.traversal.into_iter().collect();
    let rm_read: std::collections::HashSet<String> =
        removal.sandbox.paths.read.into_iter().collect();
    let rm_read_write: std::collections::HashSet<String> =
        removal.sandbox.paths.read_write.into_iter().collect();

    config
        .proxy
        .domain_allowlist
        .retain(|d| !rm_domains.contains(d));
    config
        .sandbox
        .paths
        .traversal
        .retain(|p| !rm_traversal.contains(p));
    config
        .sandbox
        .paths
        .read
        .retain(|p| !rm_read.contains(p));
    config
        .sandbox
        .paths
        .read_write
        .retain(|p| !rm_read_write.contains(p));

    config.save(&path)?;

    let names: Vec<String> = parsed.iter().map(ToString::to_string).collect();
    tracing::info!(profiles = %names.join(" "), path = %path.display(), "removed profiles");
    Ok(())
}
