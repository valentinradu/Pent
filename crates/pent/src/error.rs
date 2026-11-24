#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Sandbox(#[from] pent_sandbox::SandboxError),

    #[error("{0}")]
    Settings(#[from] pent_settings::SettingsError),

    #[error("{0}")]
    Store(#[from] pent_settings::StoreError),

    #[error("{0}")]
    Rule(#[from] pent_profile::RuleError),

    #[error("{0}")]
    Code(#[from] pent_profile::BadCode),

    #[error("{0}")]
    ProfileName(#[from] pent_profile::ProfileNameError),

    #[error("{0}")]
    RwGlob(#[from] pent_settings::RwGlobError),

    #[error("{0}")]
    Proxy(#[from] pent_proxy::ProxyError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Daemon(#[from] crate::daemon::DaemonError),

    #[error("the workspace {} is not usable: {source}", path.display())]
    Workspace {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[error("{0}")]
    Other(String),
}
