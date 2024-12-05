use std::sync::Arc;
use crate::config::{ForgeConfig, DatabaseConfig, CloudConfig, SecurityConfig};

pub fn mock_config() -> Arc<ForgeConfig> {
    Arc::new(ForgeConfig {
        base_directory: std::env::temp_dir().join("forge"),
        database: DatabaseConfig {
            url: "postgres://mock:mock@localhost:5432/forge".to_string(),
            max_connections: 5,
            ssl_mode: "prefer".to_string(),
        },
        cloud: CloudConfig {
            aws_access_key: "mock_aws_key".to_string(),
            aws_secret_key: "mock_aws_secret".to_string(),
            gcp_credentials_file: "/mock/path/to/gcp-creds.json".to_string(),
            azure_connection_string: "mock_azure_connection".to_string(),
            region: "us-west-2".to_string(),
        },
        security: SecurityConfig {
            encryption_key: "mock_encryption_key_32_bytes_long_key".to_string(),
            token_expiry_hours: 24,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            max_login_attempts: 3,
        },
        log_level: "info".to_string(),
        port: 8080,
        host: "127.0.0.1".to_string(),
    })
}
