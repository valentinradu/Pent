#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Sandbox(#[from] pent_sandbox::SandboxError),

    #[error("{0}")]
    Settings(#[from] pent_settings::SettingsError),

    #[error("{0}")]
    Trust(#[from] pent_settings::TrustError),

    #[error("{0}")]
    Profile(#[from] pent_settings::ProfileParseError),

    #[error("{0}")]
    RwGlob(#[from] pent_settings::RwGlobError),

    #[error("{0}")]
    Proxy(#[from] pent_proxy::ProxyError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
