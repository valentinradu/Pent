#![allow(unreachable_pub)]
use std::path::PathBuf;

use pent_proxy::{ProxyConfig, ProxyServer};
use pent_sandbox::check_availability;
use pent_settings::ConfigLoader;

use crate::error::CliError;
use crate::ui;

pub async fn check(cwd: PathBuf) -> Result<(), CliError> {
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

    // 4. Config paths
    let global_path = ConfigLoader::global_config_path();
    let project_path = ConfigLoader::project_config_path(&cwd);

    if let Some(ref path) = global_path {
        let found = if path.exists() { "found" } else { "not found" };
        ui::status("global", format!("{} ({})", path.display(), found));
    } else {
        ui::status("global", "n/a (home directory not available)");
    }
    let found = if project_path.exists() { "found" } else { "not found" };
    ui::status("project", format!("{} ({})", project_path.display(), found));

    match ConfigLoader::load(&cwd) {
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
