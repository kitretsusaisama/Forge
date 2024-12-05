pub mod parser;
pub mod devcontainer;

pub use self::parser::*;
pub use self::devcontainer::*;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::path::PathBuf;
use directories::ProjectDirs;

pub use parser::{ConfigParser, ConfigSource, FileConfigSource, EnvConfigSource, ConfigParserOptions};
pub use devcontainer::DevContainerConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    pub base_directory: Option<String>,
    pub port_forwarding: PortForwardingConfig,
    pub monitoring_enabled: bool,
    pub database_url: Option<String>,
    pub container_runtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardingConfig {
    pub enabled: bool,
    pub host: String,
    pub start_port: u16,
    pub end_port: u16,
}

impl Default for PortForwardingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".to_string(),
            start_port: 8081,
            end_port: 65535,
        }
    }
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            base_directory: None,
            port_forwarding: PortForwardingConfig::default(),
            monitoring_enabled: true,
            database_url: None,
            container_runtime: None,
        }
    }
}

impl ForgeConfig {
    pub async fn load() -> Result<Self> {
        // For now return default config
        Ok(Self::default())
    }

    pub fn base_directory(&self) -> PathBuf {
        self.base_directory
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs::home_dir().unwrap().join(".forge"))
    }
}

// Removed the old ForgeConfig and PortForwardingConfig structs
// Removed the old implementation of ForgeConfig
