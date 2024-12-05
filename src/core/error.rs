use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForgeError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Environment error: {0}")]
    EnvironmentError(String),

    #[error("Resource allocation error: {0}")]
    ResourceError(String),

    #[error("Security error: {0}")]
    SecurityError(String),

    #[error("Plugin error: {0}")]
    PluginError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cloud provider error: {0}")]
    CloudError(String),
}

pub type DevEnvResult<T> = Result<T, ForgeError>;
