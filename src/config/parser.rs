use anyhow::{Context, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::fs;

/// Supported configuration file formats
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigFormat {
    Json,
    JsonC,  // JSON with comments
    Json5,
    Toml,
    Yaml,
}

/// Configuration parsing options
#[derive(Debug, Clone)]
pub struct ConfigParserOptions {
    pub format: ConfigFormat,
    pub allow_comments: bool,
    pub strict_mode: bool,
}

impl Default for ConfigParserOptions {
    fn default() -> Self {
        Self {
            format: ConfigFormat::Json,
            allow_comments: true,
            strict_mode: false,
        }
    }
}

/// Advanced configuration parser
pub struct ConfigParser;

impl ConfigParser {
    /// Parse configuration from a file
    pub fn parse_file<T>(
        path: &Path, 
        options: Option<ConfigParserOptions>
    ) -> Result<T> 
    where 
        T: for<'de> Deserialize<'de> 
    {
        let options = options.unwrap_or_default();
        let content = fs::read_to_string(path)
            .context("Failed to read configuration file")?;
        
        Self::parse_str(&content, options)
    }

    /// Parse configuration from a string
    pub fn parse_str<T>(
        content: &str, 
        options: ConfigParserOptions
    ) -> Result<T> 
    where 
        T: for<'de> Deserialize<'de> 
    {
        match options.format {
            ConfigFormat::Json => {
                if options.allow_comments {
                    // Handle JSON with comments using json5
                    let config: T = json5::from_str(content)
                        .context("Failed to parse JSON5 configuration")?;
                    Ok(config)
                } else {
                    let config: T = serde_json::from_str(content)
                        .context("Failed to parse JSON configuration")?;
                    Ok(config)
                }
            },
            ConfigFormat::Toml => {
                let config: T = toml::from_str(content)
                    .context("Failed to parse TOML configuration")?;
                Ok(config)
            },
            ConfigFormat::Yaml => {
                let config: T = serde_yaml::from_str(content)
                    .context("Failed to parse YAML configuration")?;
                Ok(config)
            },
            _ => Err(anyhow::anyhow!("Unsupported configuration format")),
        }
    }

    /// Validate configuration against a JSON schema
    pub fn validate_config<T>(
        config: &T, 
        schema_path: &Path
    ) -> Result<()> 
    where 
        T: Serialize 
    {
        // Read JSON schema
        let schema_content = fs::read_to_string(schema_path)
            .context("Failed to read JSON schema")?;
        
        let schema = jsonschema::JSONSchema::from_string(&schema_content)
            .context("Invalid JSON schema")?;
        
        // Convert config to JSON value
        let config_value = serde_json::to_value(config)
            .context("Failed to convert config to JSON")?;
        
        // Validate against schema
        schema.validate(&config_value)
            .map_err(|errors| {
                let error_messages: Vec<String> = errors
                    .map(|e| e.to_string())
                    .collect();
                
                anyhow::anyhow!(
                    "Configuration validation failed:\n{}",
                    error_messages.join("\n")
                )
            })?;
        
        Ok(())
    }

    /// Merge multiple configuration sources
    pub fn merge_configs<T>(
        base_config: Option<T>, 
        overlay_config: Option<T>
    ) -> Result<T> 
    where 
        T: Clone + Serialize + for<'de> Deserialize<'de>
    {
        match (base_config, overlay_config) {
            (Some(mut base), Some(overlay)) => {
                // Use serde_json for flexible merging
                let mut base_value = serde_json::to_value(&base)?;
                let overlay_value = serde_json::to_value(&overlay)?;

                json_patch::merge(&mut base_value, &overlay_value);
                
                let merged: T = serde_json::from_value(base_value)?;
                Ok(merged)
            },
            (Some(base), None) => Ok(base),
            (None, Some(overlay)) => Ok(overlay),
            (None, None) => Err(anyhow::anyhow!("No configuration provided")),
        }
    }
}

/// Trait for configuration sources
pub trait ConfigSource {
    type Output: DeserializeOwned;
    
    fn load_config(&self) -> Result<Option<Self::Output>>;
}

/// File-based configuration source
pub struct FileConfigSource {
    pub path: PathBuf,
    pub options: ConfigParserOptions,
}

impl ConfigSource for FileConfigSource {
    type Output = serde_json::Value;

    fn load_config(&self) -> Result<Option<Self::Output>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let contents = fs::read_to_string(&self.path)
            .with_context(|| format!("Failed to read config file: {}", self.path.display()))?;

        let config = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", self.path.display()))?;

        Ok(Some(config))
    }
}

/// Environment variable configuration source
pub struct EnvConfigSource {
    pub prefix: String,
}

impl ConfigSource for EnvConfigSource {
    type Output = serde_json::Value;

    fn load_config(&self) -> Result<Option<Self::Output>> {
        // Collect environment variables with the specified prefix
        let env_configs: Vec<(String, String)> = std::env::vars()
            .filter(|(key, _)| key.starts_with(&self.prefix))
            .collect();

        if env_configs.is_empty() {
            return Ok(None);
        }

        // Convert environment variables to a JSON object
        let mut config_json = serde_json::json!({});
        for (key, value) in env_configs {
            let json_key = key
                .trim_start_matches(&self.prefix)
                .to_lowercase()
                .replace('_', ".");
            
            config_json[json_key] = serde_json::Value::String(value);
        }

        Ok(Some(config_json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::NamedTempFile;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        name: String,
        version: u32,
        enabled: bool,
    }

    #[test]
    fn test_json_parsing() {
        let json_content = r#"{"name": "test", "version": 1, "enabled": true}"#;
        let config: TestConfig = ConfigParser::parse_str(
            json_content, 
            ConfigParserOptions::default()
        ).unwrap();

        assert_eq!(config, TestConfig {
            name: "test".to_string(),
            version: 1,
            enabled: true,
        });
    }

    #[test]
    fn test_config_merging() {
        let base_config = Some(TestConfig {
            name: "base".to_string(),
            version: 1,
            enabled: false,
        });

        let overlay_config = Some(TestConfig {
            name: "overlay".to_string(),
            version: 2,
            enabled: true,
        });

        let merged = ConfigParser::merge_configs(base_config, overlay_config).unwrap();

        assert_eq!(merged, TestConfig {
            name: "overlay".to_string(),
            version: 2,
            enabled: true,
        });
    }

    #[test]
    fn test_env_config_source() {
        std::env::set_var("FORGE_NAME", "test-env");
        std::env::set_var("FORGE_VERSION", "42");

        let env_source = EnvConfigSource {
            prefix: "FORGE_".to_string(),
        };

        let config: Option<serde_json::Value> = env_source.load_config().unwrap();
        assert!(config.is_some());

        let config = config.unwrap();
        assert_eq!(config["name"], serde_json::Value::String("test-env".to_string()));
        assert_eq!(config["version"], serde_json::Value::String("42".to_string()));

        // Clean up
        std::env::remove_var("FORGE_NAME");
        std::env::remove_var("FORGE_VERSION");
    }
}
