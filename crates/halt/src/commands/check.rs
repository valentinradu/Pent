use std::path::PathBuf;

use halt_proxy::{ProxyConfig, ProxyServer};
use halt_sandbox::check_availability;
use halt_settings::ConfigLoader;

use crate::error::CliError;

pub async fn check(cwd: PathBuf) -> Result<(), CliError> {
    let mut all_ok = true;

    // 1. Platform info
    tracing::info!(os = std::env::consts::OS, arch = std::env::consts::ARCH, "platform");

    // 2. Sandbox availability
    match check_availability() {
        Ok(()) => tracing::info!("sandbox: OK"),
        Err(e) => {
            tracing::error!("sandbox: FAIL — {e}");
            all_ok = false;
        }
    }

    // 3. Proxy smoke-test
    let proxy_config = ProxyConfig::default();
    match ProxyServer::new(proxy_config) {
        Ok(server) => match server.start().await {
            Ok(handle) => match handle.shutdown().await {
                Ok(()) => tracing::info!("proxy: OK"),
                Err(e) => {
                    tracing::error!("proxy: FAIL (shutdown) — {e}");
                    all_ok = false;
                }
            },
            Err(e) => {
                tracing::error!("proxy: FAIL (start) — {e}");
                all_ok = false;
            }
        },
        Err(e) => {
            tracing::error!("proxy: FAIL (init) — {e}");
            all_ok = false;
        }
    }

    // 4. Config
    let global_path = ConfigLoader::global_config_path();
    let project_path = ConfigLoader::project_config_path(&cwd);

    if let Some(ref path) = global_path {
        let status = if path.exists() { "found" } else { "not found" };
        tracing::info!(path = %path.display(), status, "global config");
    } else {
        tracing::info!("global config: n/a (home directory not available)");
    }
    let status = if project_path.exists() { "found" } else { "not found" };
    tracing::info!(path = %project_path.display(), status, "project config");

    match ConfigLoader::load(&cwd) {
        Ok(_) => tracing::info!("config loaded: OK"),
        Err(e) => {
            tracing::error!("config loaded: FAIL — {e}");
            all_ok = false;
        }
    }

    if !all_ok {
        return Err(CliError::Other("One or more checks failed".to_string()));
    }

    Ok(())
}
