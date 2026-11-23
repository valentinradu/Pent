//! The notification hook: pentd runs the `[notify] command` of the global
//! `pent.toml` when new questions come.
//!
//! - **One run for each burst.** After a new question, pentd waits
//!   [`BURST_WINDOW`], so the questions of one burst share one run. While
//!   the command runs, pentd does not start it again; a question that came
//!   meanwhile starts the next burst when the command ends.
//! - **The environment** of pentd, and `PENT_PENDING` with the number of
//!   open questions. No shell: the first element is the program.
//! - **Only the global settings** set the command, and pentd reads them at
//!   each burst, so a change applies without a restart. The hook runs
//!   outside the sandbox, so no file of a workspace may set it.
//! - **A command that does not end** blocks the next run for at most
//!   [`HOOK_WAIT`]. pentd does not stop it: a notification can wait for the
//!   user.

use std::sync::Arc;
use std::time::Duration;

use pent_settings::{ConfigLoader, NotifyCommand, PentDirs};

use super::hub::Hub;

/// How long pentd collects the questions of one burst.
pub(crate) const BURST_WINDOW: Duration = Duration::from_millis(500);

/// How long pentd waits for the command before the next burst may run it.
const HOOK_WAIT: Duration = Duration::from_secs(5 * 60);

/// The variable with the number of open questions.
pub(crate) const PENDING_VAR: &str = "PENT_PENDING";

/// Run the hook for each burst of new questions, until the task stops.
pub(crate) async fn run(hub: Arc<Hub>) {
    let mut new_questions = hub.watch_new_questions();
    loop {
        if new_questions.changed().await.is_err() {
            return;
        }
        tokio::time::sleep(BURST_WINDOW).await;
        // Each question of the window belongs to this run. A question that
        // comes while the command runs starts the next burst.
        new_questions.mark_unchanged();
        let pending = hub.open_questions();
        if pending == 0 {
            continue;
        }
        // The read of `pent.toml` blocks; a slow home directory must not
        // stop a thread of the runtime.
        let command = match tokio::task::spawn_blocking(notify_command).await {
            Ok(Some(command)) => command,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("pentd cannot read the notify command: {e}");
                continue;
            }
        };
        match spawn(&command, pending) {
            Ok(mut child) => {
                match tokio::time::timeout(HOOK_WAIT, child.wait()).await {
                    Ok(Ok(status)) if !status.success() => {
                        tracing::debug!("the notify command ended with {status}");
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::debug!("cannot wait for the notify command: {e}"),
                    Err(_) => {
                        tracing::debug!("the notify command still runs; pentd goes on");
                        // Reap it when it ends, so it does not stay as a
                        // zombie.
                        tokio::spawn(async move {
                            // The status does not matter any more.
                            let _ = child.wait().await;
                        });
                    }
                }
            }
            Err(e) => tracing::warn!("pentd cannot run the notify command: {e}"),
        }
    }
}

/// The command of the global settings, or `None` when no command is set or
/// the settings cannot be read.
fn notify_command() -> Option<NotifyCommand> {
    let path = ConfigLoader::global_config_path(PentDirs::from_env().as_ref())?;
    match ConfigLoader::load_file(&path) {
        Ok(Some(config)) => config.notify.command,
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("pentd cannot read the notify command: {e}");
            None
        }
    }
}

/// Start `command` with `PENT_PENDING`, no terminal, and its own process
/// group, so a signal to the group of pentd does not reach it.
fn spawn(command: &NotifyCommand, pending: usize) -> std::io::Result<tokio::process::Child> {
    tokio::process::Command::new(command.program())
        .args(command.args())
        .env(PENDING_VAR, pending.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .kill_on_drop(false)
        .spawn()
}
