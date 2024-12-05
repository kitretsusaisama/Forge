use std::sync::Arc;
use crate::config::{ForgeConfig, DatabaseConfig, SecurityConfig};

pub fn mock_config() -> Arc<ForgeConfig> {
    Arc::new(ForgeConfig {
        base_directory: std::env::temp_dir().join("forge"),
        database: DatabaseConfig {
            url: "postgres://mock:mock@localhost:5432/forge".to_string(),
            max_connections: 5,
            ssl_mode: "prefer".to_string(),
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
