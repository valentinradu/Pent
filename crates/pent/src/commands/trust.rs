//! `pent trust`, `pent untrust` and `pent profile`.

use std::path::PathBuf;

use pent_profile::{safe_lines, ProfileName};
use pent_settings::{ProfileStatus, ProfileStore};

use crate::cli::{ProfileArgs, ProfileSubcommand, TrustArgs, UntrustArgs};
use crate::commands::review_flow::{summarize_review_and_draft, ReviewInput, TrustAnswer};
use crate::commands::select::not_trusted_message;
use crate::commands::tty::Tty;
use crate::error::CliError;
use crate::ui;
use pent_profile::DraftSource;

/// `pent trust NAME [--yes] [--review]`.
pub(crate) fn trust(args: &TrustArgs, cwd: PathBuf) -> Result<(), CliError> {
    let name: ProfileName = args.name.parse()?;
    let store = ProfileStore::open_default()?;
    let answer = if args.yes {
        TrustAnswer::Yes
    } else {
        TrustAnswer::Ask
    };
    if args.review {
        review_denied(&store, &name, cwd, answer)
    } else {
        trust_draft(&store, &name, answer)
    }
}

/// Show the draft (or the profile file), ask, then trust it.
fn trust_draft(
    store: &ProfileStore,
    name: &ProfileName,
    answer: TrustAnswer,
) -> Result<(), CliError> {
    let (label, path, text) = if let Some(text) = store.read_draft_text(name)? {
        ("draft", store.draft_path(name), text)
    } else {
        let loaded = store.load(name)?;
        match loaded.status {
            ProfileStatus::Trusted => {
                ui::ok(format!("the profile \"{name}\" is already trusted"));
                return Ok(());
            }
            ProfileStatus::Missing | ProfileStatus::DraftOnly => {
                return Err(CliError::Other(format!(
                    "no draft and no profile for \"{name}\"\n  record one: pent watch -- {name}"
                )));
            }
            ProfileStatus::NotTrusted | ProfileStatus::Changed => {
                let text = store.read_profile_text(name)?.unwrap_or_default();
                ("profile", loaded.path, text)
            }
        }
    };

    // The file can hold a control character or a format character from an
    // event or from a hand edit. The user must see the true text.
    let shown = safe_lines(&text);
    eprintln!("The {label} of \"{name}\" ({}):\n", path.display());
    eprint!("{shown}");
    if !shown.ends_with('\n') {
        eprintln!();
    }
    eprintln!();

    if answer == TrustAnswer::Ask {
        let Some(mut tty) = Tty::open() else {
            return Err(CliError::Other(format!(
                "cannot ask for confirmation: no terminal. \
                 To trust the profile without a question, run: pent trust {name} --yes"
            )));
        };
        if !tty.confirm("Trust this profile?")? {
            ui::warn(format!("not trusted; pent run does not apply \"{name}\""));
            return Ok(());
        }
    }
    // Trust the bytes that pent printed, not the bytes of a new read: the
    // file can change between the question and the answer.
    let profile = store.trust_exact(name, text.as_bytes())?;
    ui::ok(format!("trusted \"{name}\" ({})", profile.display()));
    Ok(())
}

/// Review the accesses that `pent run` denied, update the draft and ask to
/// trust it. Then delete the denied log.
fn review_denied(
    store: &ProfileStore,
    name: &ProfileName,
    cwd: PathBuf,
    answer: TrustAnswer,
) -> Result<(), CliError> {
    let loaded = store.load(name)?;
    if let Some(message) =
        not_trusted_message(loaded.status, name, &format!("pent watch -- {name}"))
    {
        return Err(CliError::Other(message));
    }
    let events = store.read_denied(name)?;
    if events.is_empty() {
        ui::ok(format!("no denied accesses for \"{name}\""));
        return Ok(());
    }
    summarize_review_and_draft(ReviewInput {
        store,
        name,
        workspace: &cwd,
        events: &events,
        existing: loaded.doc,
        keep: None,
        origin: DraftSource::DeniedReview,
        trust: answer,
    })?;
    // The selected rules are in the draft (or in the profile). The review
    // is done, so the denied accesses go away.
    store.clear_denied(name)?;
    Ok(())
}

/// `pent untrust NAME`.
pub(crate) fn untrust(args: &UntrustArgs) -> Result<(), CliError> {
    let name: ProfileName = args.name.parse()?;
    let store = ProfileStore::open_default()?;
    if store.untrust(&name)? {
        ui::ok(format!("untrusted \"{name}\"; pent run does not apply it"));
    } else {
        ui::warn(format!("the profile \"{name}\" is not trusted"));
    }
    Ok(())
}

/// `pent profile list|show|rm`.
pub(crate) fn profile(args: &ProfileArgs) -> Result<(), CliError> {
    let store = ProfileStore::open_default()?;
    match &args.subcommand {
        ProfileSubcommand::List => list(&store),
        ProfileSubcommand::Show { name } => show(&store, &name.parse()?),
        ProfileSubcommand::Remove { name } => remove(&store, &name.parse()?),
    }
}

fn list(store: &ProfileStore) -> Result<(), CliError> {
    let entries = store.list()?;
    if entries.is_empty() {
        ui::status("profiles", "none; record one: pent watch -- COMMAND");
        return Ok(());
    }
    for entry in entries {
        let draft = if entry.has_draft && entry.status != ProfileStatus::DraftOnly {
            ", draft"
        } else {
            ""
        };
        println!("{:<24} {}{draft}", entry.name.as_str(), entry.status);
    }
    Ok(())
}

fn show(store: &ProfileStore, name: &ProfileName) -> Result<(), CliError> {
    // The file can hold a control character or a format character from an
    // event or from a hand edit. `safe_lines` escapes them.
    if let Some(text) = store.read_profile_text(name)? {
        let loaded = store.load(name)?;
        ui::status(
            "profile",
            format!("{} ({})", loaded.path.display(), loaded.status),
        );
        print!("{}", safe_lines(&text));
        return Ok(());
    }
    if let Some(text) = store.read_draft_text(name)? {
        ui::status(
            "draft",
            format!("{} (not trusted)", store.draft_path(name).display()),
        );
        print!("{}", safe_lines(&text));
        return Ok(());
    }
    Err(CliError::Other(format!(
        "no profile for \"{name}\"\n  record one: pent watch -- {name}"
    )))
}

fn remove(store: &ProfileStore, name: &ProfileName) -> Result<(), CliError> {
    if store.remove(name)? {
        ui::ok(format!("removed the profile \"{name}\""));
    } else {
        ui::warn(format!("no profile for \"{name}\""));
    }
    Ok(())
}
