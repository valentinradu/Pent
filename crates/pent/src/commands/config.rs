use std::collections::HashSet;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use pent_settings::{
    build_profiles_config, is_profile_likely_active, profile_deps_transitive, ConfigLoader,
    LoadedConfig, NetworkMode, PentConfig, PrivateDestinations, Profile, ProjectConfigStatus,
    TrustError, TrustStatus, TrustStore,
};

use crate::cli::{ConfigSubcommand, OutputFormat};
use crate::error::CliError;
use crate::ui;

/// The command that the user runs to trust a project config.
const TRUST_COMMAND: &str = "pent config trust";

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

#[allow(clippy::needless_pass_by_value)] // PathBuf taken for ergonomics
pub(crate) fn config(args: crate::cli::ConfigArgs, cwd: PathBuf) -> Result<(), CliError> {
    match args.subcommand {
        ConfigSubcommand::Init { global } => init(global, &cwd),
        ConfigSubcommand::Show { format } => show(format, &cwd),
        ConfigSubcommand::Edit { global } => edit(global, &cwd),
        ConfigSubcommand::Add { profiles, global } => add_profile(global, &profiles, &cwd),
        ConfigSubcommand::Remove { profiles, global } => rm_profile(global, &profiles, &cwd),
        ConfigSubcommand::Trust { yes } => trust(yes, &cwd),
        ConfigSubcommand::Untrust => untrust(&cwd),
    }
}

/// Print a warning when a project config exists but pent does not apply it.
pub(crate) fn warn_if_project_ignored(loaded: &LoadedConfig) {
    let reason = match loaded.project_status {
        ProjectConfigStatus::Untrusted => "is not trusted",
        ProjectConfigStatus::Changed => "changed after you trusted it",
        ProjectConfigStatus::Absent | ProjectConfigStatus::Trusted => return,
    };
    ui::warn(format!(
        "The project config {} {reason}. Pent ignores it and uses the global config only. \
         To review and apply it, run: {TRUST_COMMAND}",
        loaded.project_path.display()
    ));
}

// ── Trust after a write ──────────────────────────────────────────────────────

/// What to do with the trust of the project config after pent writes it.
enum Retrust {
    /// The file was trusted or did not exist. Trust the new content.
    Yes(TrustStore),
    /// The file was not trusted before the change. Keep it untrusted: the
    /// user did not review the content that was there before.
    No,
    /// Pent cannot use the trust store.
    Unavailable(TrustError),
}

/// Find out if pent may trust the project config at `path` after a write.
fn retrust_decision(path: &Path) -> Retrust {
    let store = match TrustStore::open_default() {
        Ok(store) => store,
        Err(e) => return Retrust::Unavailable(e),
    };
    match std::fs::read(path) {
        Ok(bytes) => match store.status(path, &bytes) {
            TrustStatus::Trusted => Retrust::Yes(store),
            TrustStatus::Untrusted | TrustStatus::Changed => Retrust::No,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Retrust::Yes(store),
        Err(source) => Retrust::Unavailable(TrustError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Update the trust of the project config at `path` after pent wrote it.
fn finish_project_write(path: &Path, decision: Retrust) {
    let result = match decision {
        Retrust::Yes(mut store) => std::fs::read(path)
            .map_err(|source| TrustError::Io {
                path: path.to_path_buf(),
                source,
            })
            .and_then(|bytes| {
                store.trust(path, &bytes);
                store.save()
            }),
        Retrust::No => {
            ui::warn(format!(
                "The project config {} was not trusted before this change. \
                 Pent does not apply it. To review and apply it, run: {TRUST_COMMAND}",
                path.display()
            ));
            return;
        }
        Retrust::Unavailable(e) => Err(e),
    };
    if let Err(e) = result {
        ui::warn(format!(
            "Cannot trust the project config: {e}. \
             Pent does not apply it until you run: {TRUST_COMMAND}"
        ));
    }
}

// ── Subcommands ──────────────────────────────────────────────────────────────

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

    let decision = (!global).then(|| retrust_decision(&path));
    PentConfig::default().save(&path)?;
    if let Some(decision) = decision {
        finish_project_write(&path, decision);
    }
    ui::ok(format!("created {}", path.display()));
    Ok(())
}

fn show(format: OutputFormat, cwd: &Path) -> Result<(), CliError> {
    let loaded = ConfigLoader::load_with_status(cwd)?;
    match format {
        OutputFormat::Toml => {
            let toml = loaded.config.to_toml()?;
            print!("{toml}");
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&loaded.config)
                .map_err(|e| CliError::Other(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        }
    }

    // Status lines go to stderr, thus stdout stays valid TOML or JSON.
    match ConfigLoader::global_config_path() {
        Some(path) => {
            let found = if path.exists() { "found" } else { "not found" };
            ui::status("global", format!("{} ({found})", path.display()));
        }
        None => ui::status("global", "n/a (home directory not available)"),
    }
    let state = match loaded.project_status {
        ProjectConfigStatus::Absent => "not found",
        ProjectConfigStatus::Trusted => "trusted, applied",
        ProjectConfigStatus::Untrusted => "not trusted, not applied",
        ProjectConfigStatus::Changed => "changed after trust, not applied",
    };
    ui::status(
        "project",
        format!("{} ({state})", loaded.project_path.display()),
    );
    warn_if_project_ignored(&loaded);
    Ok(())
}

fn edit(global: bool, cwd: &Path) -> Result<(), CliError> {
    let path = resolve_config_path(global, cwd)?;

    // Try $VISUAL, then $EDITOR, then fall back to vi.
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    let decision = (!global).then(|| retrust_decision(&path));
    let status = std::process::Command::new(&editor).arg(&path).status()?;
    if !status.success() {
        return Err(CliError::Other(format!(
            "The editor {editor} failed ({status}). Pent did not trust the result."
        )));
    }
    if let Some(decision) = decision {
        if path.exists() {
            finish_project_write(&path, decision);
        }
    }

    Ok(())
}

fn parse_profiles(profiles: &[String]) -> Result<Vec<Profile>, CliError> {
    Ok(profiles
        .iter()
        .map(|s| Profile::from_str(s))
        .collect::<Result<_, _>>()?)
}

fn add_profile(global: bool, profiles: &[String], cwd: &Path) -> Result<(), CliError> {
    let parsed = parse_profiles(profiles)?;
    let expanded = profile_deps_transitive(&parsed);

    let path = resolve_config_path(global, cwd)?;

    let existing = if path.exists() {
        PentConfig::load(&path)?
    } else {
        PentConfig::default()
    };

    let mut fragment = build_profiles_config(&expanded);
    // Record the profiles, so that `config rm` knows which entries they give.
    fragment.profiles.clone_from(&expanded);
    let merged = existing.merge(fragment);

    let decision = (!global).then(|| retrust_decision(&path));
    merged.save(&path)?;
    if let Some(decision) = decision {
        finish_project_write(&path, decision);
    }

    let names: Vec<String> = expanded.iter().map(ToString::to_string).collect();
    ui::ok(format!("added {} → {}", names.join(" "), path.display()));
    Ok(())
}

/// Remove from `list` each entry that is in `drop` and not in `keep`.
fn remove_entries(list: &mut Vec<String>, drop: &[String], keep: &[String]) {
    list.retain(|entry| !drop.contains(entry) || keep.contains(entry));
}

fn rm_profile(global: bool, profiles: &[String], cwd: &Path) -> Result<(), CliError> {
    let parsed = parse_profiles(profiles)?;

    let path = resolve_config_path(global, cwd)?;

    if !path.exists() {
        return Err(CliError::Other("No config file found".to_string()));
    }
    let mut config = PentConfig::load(&path)?;

    // The profiles that are in the config now, and the profiles to remove.
    let (present, removing): (Vec<Profile>, Vec<Profile>) = if config.profiles.is_empty() {
        // An older pent did not write the `profiles` list. Guess the present
        // profiles from the entries.
        ui::warn(format!(
            "{} has no `profiles` list. Pent guesses the present profiles from the entries.",
            path.display()
        ));
        let present = Profile::all()
            .filter(|p| is_profile_likely_active(&config, *p))
            .collect();
        (present, parsed.clone())
    } else {
        let mut removing = Vec::new();
        for p in &parsed {
            if config.profiles.contains(p) {
                removing.push(*p);
            } else {
                ui::warn(format!(
                    "{p} is not in the `profiles` list of {}. Pent removes nothing for it.",
                    path.display()
                ));
            }
        }
        (config.profiles.clone(), removing)
    };
    let remaining: Vec<Profile> = present
        .iter()
        .copied()
        .filter(|p| !parsed.contains(p))
        .collect();

    // A remaining profile must not depend on a removed profile.
    for p in &removing {
        let blocking: Vec<String> = remaining
            .iter()
            .filter(|d| profile_deps_transitive(&[**d]).contains(p))
            .map(ToString::to_string)
            .collect();
        if let Some(blocker) = blocking.first() {
            let mut hint = blocking.clone();
            hint.extend(parsed.iter().map(ToString::to_string));
            return Err(CliError::Other(format!(
                "cannot remove '{p}': profile '{blocker}' depends on it.\nRun: pent config rm {}",
                hint.join(" ")
            )));
        }
    }

    // Remove only the entries that the removed profiles give and that no
    // remaining profile gives. An entry that no profile gives stays: the user
    // added it.
    let drop = build_profiles_config(&removing);
    let keep = build_profiles_config(&profile_deps_transitive(&remaining));
    remove_entries(
        &mut config.proxy.domain_allowlist,
        &drop.proxy.domain_allowlist,
        &keep.proxy.domain_allowlist,
    );
    let (paths, drop_paths, keep_paths) = (
        &mut config.sandbox.paths,
        &drop.sandbox.paths,
        &keep.sandbox.paths,
    );
    remove_entries(
        &mut paths.traversal,
        &drop_paths.traversal,
        &keep_paths.traversal,
    );
    remove_entries(&mut paths.read, &drop_paths.read, &keep_paths.read);
    remove_entries(&mut paths.execute, &drop_paths.execute, &keep_paths.execute);
    remove_entries(
        &mut paths.read_write,
        &drop_paths.read_write,
        &keep_paths.read_write,
    );
    config.profiles.retain(|p| !removing.contains(p));

    let decision = (!global).then(|| retrust_decision(&path));
    config.save(&path)?;
    if let Some(decision) = decision {
        finish_project_write(&path, decision);
    }

    let names: Vec<String> = parsed.iter().map(ToString::to_string).collect();
    ui::ok(format!(
        "removed {} from {}",
        names.join(" "),
        path.display()
    ));
    Ok(())
}

/// The name of a network mode as it appears in the config file.
const fn network_name(mode: &NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Unrestricted => "unrestricted",
        NetworkMode::LocalhostOnly => "localhost_only",
        NetworkMode::ProxyOnly { .. } => "proxy_only",
        NetworkMode::Blocked => "blocked",
    }
}

/// Describe what `project` adds to `global`, one line for each change.
fn describe_additions(project: &PentConfig, global: &PentConfig) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(mode) = &project.sandbox.network {
        if global.sandbox.network.as_ref() != Some(mode) {
            lines.push(format!("sandbox.network = {}", network_name(mode)));
        }
    }
    let lists = [
        (
            "sandbox.paths.traversal",
            &project.sandbox.paths.traversal,
            &global.sandbox.paths.traversal,
        ),
        (
            "sandbox.paths.read",
            &project.sandbox.paths.read,
            &global.sandbox.paths.read,
        ),
        (
            "sandbox.paths.execute",
            &project.sandbox.paths.execute,
            &global.sandbox.paths.execute,
        ),
        (
            "sandbox.paths.read_write",
            &project.sandbox.paths.read_write,
            &global.sandbox.paths.read_write,
        ),
        (
            "proxy.domain_allowlist",
            &project.proxy.domain_allowlist,
            &global.proxy.domain_allowlist,
        ),
    ];
    for (key, ours, theirs) in lists {
        let theirs: HashSet<&String> = theirs.iter().collect();
        for entry in ours.iter().filter(|e| !theirs.contains(e)) {
            lines.push(format!("{key} += {entry:?}"));
        }
    }
    for mount in &project.sandbox.mounts {
        let known = global
            .sandbox
            .mounts
            .iter()
            .any(|m| m.path == mount.path && m.readonly == mount.readonly);
        if !known {
            let access = if mount.readonly {
                "read-only"
            } else {
                "read-write"
            };
            lines.push(format!(
                "sandbox.mounts += {:?} ({access})",
                mount.path.display().to_string()
            ));
        }
    }
    if let Some(dns) = &project.proxy.upstream_dns {
        if global.proxy.upstream_dns.as_ref() != Some(dns) {
            lines.push(format!("proxy.upstream_dns = {dns:?}"));
        }
    }
    if let Some(policy) = project.proxy.private_destinations {
        if policy == PrivateDestinations::Allow
            && global.proxy.private_destinations != Some(PrivateDestinations::Allow)
        {
            lines.push("proxy.private_destinations = \"allow\"".to_string());
        }
    }
    let scalars = [
        (
            "proxy.dns_ttl_seconds",
            project.proxy.dns_ttl_seconds.map(u64::from),
            global.proxy.dns_ttl_seconds.map(u64::from),
        ),
        (
            "proxy.tcp_connect_timeout_secs",
            project.proxy.tcp_connect_timeout_secs,
            global.proxy.tcp_connect_timeout_secs,
        ),
        (
            "proxy.tcp_idle_timeout_secs",
            project.proxy.tcp_idle_timeout_secs,
            global.proxy.tcp_idle_timeout_secs,
        ),
    ];
    for (key, ours, theirs) in scalars {
        if let Some(value) = ours {
            if theirs != Some(value) {
                lines.push(format!("{key} = {value}"));
            }
        }
    }
    lines
}

/// Ask the user a yes/no question on the terminal. The default is "no".
fn confirm(question: &str) -> Result<bool, CliError> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

fn trust(yes: bool, cwd: &Path) -> Result<(), CliError> {
    let path = ConfigLoader::project_config_path(cwd);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Other(format!(
                "No project config found at {}. Run `pent config init` to create one.",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    // Parse the bytes that pent trusts. Pent does not trust a file that it
    // cannot apply.
    let mut project = PentConfig::parse_file_contents(&path, &bytes)?;
    project.resolve_relative_paths(cwd);
    let mut global = match ConfigLoader::global_config_path() {
        Some(global_path) => ConfigLoader::load_file(&global_path)?.unwrap_or_default(),
        None => PentConfig::default(),
    };
    global.resolve_relative_paths(cwd);

    let mut store = TrustStore::open_default()?;
    if store.status(&path, &bytes) == TrustStatus::Trusted {
        ui::ok(format!("{} is already trusted", path.display()));
        return Ok(());
    }

    let additions = describe_additions(&project, &global);
    if additions.is_empty() {
        eprintln!(
            "The project config {} adds nothing to the global config.",
            path.display()
        );
    } else {
        eprintln!(
            "The project config {} adds these items to the global config:",
            path.display()
        );
        for line in &additions {
            eprintln!("  + {line}");
        }
    }

    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::Other(format!(
                "Cannot ask for confirmation: stdin is not a terminal. \
                 To trust the project config without a prompt, run: {TRUST_COMMAND} --yes"
            )));
        }
        if !confirm("Trust this project config?")? {
            ui::warn("Not trusted. Pent does not apply the project config.");
            return Ok(());
        }
    }

    store.trust(&path, &bytes);
    store.save()?;
    ui::ok(format!("trusted {}", path.display()));
    Ok(())
}

fn untrust(cwd: &Path) -> Result<(), CliError> {
    let path = ConfigLoader::project_config_path(cwd);
    let mut store = TrustStore::open_default()?;
    if store.untrust(&path) {
        store.save()?;
        ui::ok(format!(
            "untrusted {}. Pent does not apply it.",
            path.display()
        ));
    } else {
        ui::warn(format!("{} is not trusted.", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn test_remove_entries_keeps_shared_and_manual() {
        let mut list = s(&["shared", "only-removed", "manual"]);
        remove_entries(&mut list, &s(&["shared", "only-removed"]), &s(&["shared"]));
        assert_eq!(list, s(&["shared", "manual"]));
    }

    #[test]
    fn test_describe_additions() {
        let global =
            PentConfig::parse("[proxy]\ndomain_allowlist = [\"a.com\"]\n").unwrap_or_default();
        let project = PentConfig::parse(
            "[sandbox]\nnetwork = { mode = \"unrestricted\" }\n\
             [sandbox.paths]\nread_write = [\"~/.ssh\"]\n\
             [[sandbox.mounts]]\npath = \"/m\"\n\
             [proxy]\ndomain_allowlist = [\"a.com\", \"b.com\"]\n",
        )
        .unwrap_or_default();
        let lines = describe_additions(&project, &global);
        assert_eq!(
            lines,
            vec![
                "sandbox.network = unrestricted".to_string(),
                "sandbox.paths.read_write += \"~/.ssh\"".to_string(),
                "proxy.domain_allowlist += \"b.com\"".to_string(),
                "sandbox.mounts += \"/m\" (read-only)".to_string(),
            ]
        );
    }
}
