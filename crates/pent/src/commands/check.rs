use std::path::PathBuf;

use pent_proxy::{ProxyConfig, ProxyServer};
use pent_sandbox::check_availability;
use pent_settings::{ConfigLoader, ProfileStore};

use crate::error::CliError;
use crate::ui;

pub(crate) async fn check(cwd: PathBuf) -> Result<(), CliError> {
    let mut all_ok = true;

    // 1. Platform info
    ui::status(
        "platform",
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    );

    // 2. Sandbox availability
    match check_availability() {
        Ok(()) => ui::ok("sandbox"),
        Err(e) => {
            ui::error(format!("sandbox: {e}"));
            all_ok = false;
        }
    }

    // On Linux, the sandbox, the network containment and watch mode need
    // unprivileged user namespaces.
    #[cfg(target_os = "linux")]
    match pent_sandbox::check_user_namespaces() {
        Ok(()) => ui::ok("user namespaces"),
        Err(e) => {
            ui::error(format!("user namespaces: {e}"));
            all_ok = false;
        }
    }

    // The PID namespace and the private `/proc` go together, and a container
    // does not give them. Their absence is not a failure of the check: the
    // file rules and the network rules hold without them.
    #[cfg(target_os = "linux")]
    match pent_sandbox::proc_isolation() {
        pent_sandbox::ProcIsolation::Private => {
            ui::ok("pid namespace and private /proc");
            ui::status("processes", "the command sees only its own processes");
        }
        isolation @ pent_sandbox::ProcIsolation::Shared(_) => {
            for line in isolation.warning_lines() {
                ui::warn(line);
            }
        }
    }

    // 3. Proxy smoke-test
    let proxy_config = ProxyConfig::default();
    match ProxyServer::new(proxy_config) {
        Ok(server) => match server.start().await {
            Ok(handle) => match handle.shutdown().await {
                Ok(()) => ui::ok("proxy"),
                Err(e) => {
                    ui::error(format!("proxy shutdown: {e}"));
                    all_ok = false;
                }
            },
            Err(e) => {
                ui::error(format!("proxy start: {e}"));
                all_ok = false;
            }
        },
        Err(e) => {
            ui::error(format!("proxy init: {e}"));
            all_ok = false;
        }
    }

    // 4. Config and profile paths
    match ConfigLoader::global_config_path(pent_settings::PentDirs::from_env().as_ref()) {
        Some(path) => {
            let found = if path.exists() { "found" } else { "not found" };
            ui::status("global", format!("{} ({found})", path.display()));
        }
        None => ui::status("global", "n/a (home directory not available)"),
    }
    match ProfileStore::open_default() {
        Ok(store) => {
            ui::status("profiles", store.dirs().config.join("profiles").display());
            ui::status("state", store.dirs().state.display());
        }
        Err(e) => {
            ui::error(format!("profiles: {e}"));
            all_ok = false;
        }
    }

    match ConfigLoader::load(&cwd, pent_settings::PentDirs::from_env().as_ref()) {
        Ok(_) => ui::ok("config"),
        Err(e) => {
            ui::error(format!("config: {e}"));
            all_ok = false;
        }
    }

    if !all_ok {
        return Err(CliError::Other("one or more checks failed".to_string()));
    }

    Ok(())
}
