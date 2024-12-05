use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub environment: EnvironmentConfig,
    pub security: SecurityConfig,
    pub resources: ResourceConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub default_type: String,
    pub cache_dir: PathBuf,
    pub templates_dir: PathBuf,
    pub max_concurrent_envs: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_vpn: bool,
    pub encryption_key_path: PathBuf,
    pub auth_provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub max_memory_per_env: usize,
    pub max_cpu_cores_per_env: usize,
    pub storage_limit: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub prometheus_endpoint: String,
    pub jaeger_endpoint: String,
    pub log_level: String,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
