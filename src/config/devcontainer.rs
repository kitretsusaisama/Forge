use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

fn default_name() -> String {
    "default".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DevContainerConfig {
    #[serde(rename = "name", default = "default_name")]
    pub name: String,

    #[serde(rename = "image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(rename = "dockerFile", skip_serializing_if = "Option::is_none")]
    pub docker_file: Option<String>,

    #[serde(rename = "build", skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildConfig>,

    #[serde(rename = "features", default)]
    pub features: HashMap<String, serde_json::Value>,

    #[serde(rename = "customizations", skip_serializing_if = "Option::is_none")]
    pub customizations: Option<CustomizationsConfig>,

    #[serde(rename = "forwardPorts", skip_serializing_if = "Option::is_none")]
    pub forward_ports: Option<Vec<u16>>,

    #[serde(rename = "postCreateCommand", skip_serializing_if = "Option::is_none")]
    pub post_create_command: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BuildConfig {
    #[serde(rename = "context", skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,

    #[serde(rename = "dockerfile", skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,

    #[serde(rename = "args", default)]
    pub args: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomizationsConfig {
    #[serde(rename = "vscode", skip_serializing_if = "Option::is_none")]
    pub vscode: Option<VSCodeConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VSCodeConfig {
    #[serde(rename = "extensions", default)]
    pub extensions: Vec<String>,

    #[serde(rename = "settings", default)]
    pub settings: HashMap<String, serde_json::Value>,
}

impl DevContainerConfig {
    pub async fn from_file(path: &Path) -> Result<Self> {
        // Support both .json and .jsonc files
        let config_str = fs::read_to_string(path)
            .await
            .context("Failed to read DevContainer configuration file")?;

        // Handle JSON5 for more flexible parsing
        let config: DevContainerConfig = if path.extension()
            .map_or(false, |ext| ext == "jsonc" || ext == "json5")
        {
            json5::from_str(&config_str)
                .context("Failed to parse JSON5 DevContainer configuration")?
        } else {
            serde_json::from_str(&config_str)
                .context("Failed to parse JSON DevContainer configuration")?
        };

        Ok(config)
    }

    pub fn default_name() -> String {
        "dev-container".to_string()
    }

    pub fn detect_environment_type(&self) -> String {
        // Determine environment type based on configuration
        if self.docker_file.is_some() {
            "dockerfile".to_string()
        } else if let Some(image) = &self.image {
            format!("docker-image:{}", image)
        } else {
            "custom".to_string()
        }
    }
}

// Validation function for DevContainer configuration
pub fn validate_devcontainer_config(config: &DevContainerConfig) -> Result<()> {
    // Add basic validation rules
    if config.image.is_none() && config.docker_file.is_none() {
        return Err(anyhow::anyhow!(
            "DevContainer configuration must specify either an image or a Dockerfile"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_parse_devcontainer_config() {
        let config_json = r#"{
            "name": "Test Container",
            "image": "mcr.microsoft.com/devcontainers/rust:1-bullseye",
            "features": {
                "ghcr.io/devcontainers/features/rust:1": {}
            }
        }"#;

        let temp_file = NamedTempFile::new().unwrap();
        let mut temp_file_async = tokio::fs::File::create(temp_file.path()).await.unwrap();
        temp_file_async.write_all(config_json.as_bytes()).await.unwrap();

        let config = DevContainerConfig::from_file(temp_file.path()).await.unwrap();
        
        assert_eq!(config.name, "Test Container");
        assert_eq!(config.image, Some("mcr.microsoft.com/devcontainers/rust:1-bullseye".to_string()));
    }
}
