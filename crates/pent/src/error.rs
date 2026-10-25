#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Sandbox(#[from] pent_sandbox::SandboxError),

    #[error("{0}")]
    Settings(#[from] pent_settings::SettingsError),

    #[error("{0}")]
    Store(#[from] pent_settings::StoreError),

    #[error("{0}")]
    ProfileName(#[from] pent_profile::ProfileNameError),

    #[error("{0}")]
    RwGlob(#[from] pent_settings::RwGlobError),

    #[error("{0}")]
    Proxy(#[from] pent_proxy::ProxyError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
