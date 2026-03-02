#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Sandbox(#[from] pent_sandbox::SandboxError),

    #[error("{0}")]
    Settings(#[from] pent_settings::SettingsError),

    #[error("{0}")]
    Proxy(#[from] pent_proxy::ProxyError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
