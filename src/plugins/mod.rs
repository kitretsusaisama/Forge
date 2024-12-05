use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Trait for environment detection plugins
#[async_trait]
pub trait EnvironmentDetectionPlugin: Send + Sync {
    /// Unique identifier for the plugin
    fn id(&self) -> &'static str;

    /// Human-readable name of the plugin
    fn name(&self) -> &'static str;

    /// Description of the plugin's detection capabilities
    fn description(&self) -> &'static str;

    /// Check if the plugin can detect an environment in the given path
    async fn can_detect(&self, path: &Path) -> Result<bool>;

    /// Detect the specific environment configuration
    async fn detect_configuration(&self, path: &Path) -> Result<Option<EnvironmentPluginConfig>>;

    /// Perform any necessary setup or initialization for the environment
    async fn setup_environment(&self, path: &Path) -> Result<()> {
        // Optional method for environment-specific setup
        Ok(())
    }
}

/// Standardized configuration structure for environment plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentPluginConfig {
    /// Type of environment (e.g., "devcontainer", "nix", "flox")
    pub env_type: String,

    /// Detected programming languages or frameworks
    pub languages: Vec<String>,

    /// Detected dependencies or requirements
    pub dependencies: Vec<String>,

    /// Additional metadata about the environment
    pub metadata: serde_json::Value,
}

/// Plugin type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginType {
    IDE,
    GitProvider,
    CloudProvider,
    BuildSystem,
    CustomTool,
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique plugin identifier
    pub id: Uuid,

    /// Plugin name
    pub name: String,

    /// Plugin type
    pub plugin_type: PluginType,

    /// Version
    pub version: String,

    /// Author
    pub author: String,

    /// Description
    pub description: String,

    /// Plugin file path
    pub path: PathBuf,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin-specific configuration
    pub config: HashMap<String, String>,
}

/// Plugin trait for dynamic loading and execution
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;

    /// Initialize plugin
    fn initialize(&mut self, config: &PluginConfig) -> Result<()>;

    /// Execute plugin-specific action
    fn execute(&self, action: &str, args: &[String]) -> Result<String>;

    /// Cleanup resources
    fn cleanup(&mut self) -> Result<()>;

    /// Convert to Any for dynamic type casting
    fn as_any(&self) -> &dyn Any;
}

/// Plugin manager for dynamic plugin management
pub struct PluginManager {
    /// Loaded plugins
    plugins: Arc<Mutex<HashMap<Uuid, Box<dyn Plugin>>>>,

    /// Plugin directory
    plugin_dir: PathBuf,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self {
            plugins: Arc::new(Mutex::new(HashMap::new())),
            plugin_dir,
        }
    }

    /// Load plugins from directory
    pub fn load_plugins(&mut self) -> Result<()> {
        // Ensure plugin directory exists
        std::fs::create_dir_all(&self.plugin_dir)?;

        // Scan for plugin files (e.g., .wasm, .so, .dll)
        for entry in std::fs::read_dir(&self.plugin_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Check for supported plugin file extensions
            if let Some(ext) = path.extension() {
                match ext.to_str() {
                    Some("wasm") => self.load_wasm_plugin(&path)?,
                    Some("so") | Some("dll") => self.load_native_plugin(&path)?,
                    _ => continue,
                }
            }
        }

        Ok(())
    }

    /// Load WebAssembly plugin
    fn load_wasm_plugin(&mut self, path: &Path) -> Result<()> {
        // WASM plugin loading logic
        // This would use a WASM runtime like wasmtime or wasmer
        unimplemented!("WASM plugin loading not yet implemented")
    }

    /// Load native plugin (shared library)
    fn load_native_plugin(&mut self, path: &Path) -> Result<()> {
        // Native plugin loading using dynamic library loading
        // This would use libloading or similar library
        unimplemented!("Native plugin loading not yet implemented")
    }

    /// Register a plugin
    pub fn register_plugin(&mut self, plugin: Box<dyn Plugin>) -> Result<()> {
        let mut plugins = self.plugins.lock().map_err(|_| 
            anyhow::anyhow!("Failed to acquire plugin lock")
        )?;

        let metadata = plugin.metadata();
        plugins.insert(metadata.id, plugin);

        Ok(())
    }

    /// Get a plugin by ID
    pub fn get_plugin(&self, plugin_id: &Uuid) -> Option<Arc<Box<dyn Plugin>>> {
        let plugins = self.plugins.lock().ok()?;
        plugins.get(plugin_id).cloned().map(Arc::new)
    }

    /// List all loaded plugins
    pub fn list_plugins(&self) -> Result<Vec<PluginMetadata>> {
        let plugins = self.plugins.lock().map_err(|_| 
            anyhow::anyhow!("Failed to acquire plugin lock")
        )?;

        Ok(plugins
            .values()
            .map(|plugin| plugin.metadata().clone())
            .collect())
    }

    /// Execute a plugin action
    pub fn execute_plugin(
        &self, 
        plugin_id: &Uuid, 
        action: &str, 
        args: &[String]
    ) -> Result<String> {
        let plugins = self.plugins.lock().map_err(|_| 
            anyhow::anyhow!("Failed to acquire plugin lock")
        )?;

        let plugin = plugins.get(plugin_id)
            .context("Plugin not found")?;

        plugin.execute(action, args)
    }

    /// Unload and cleanup plugins
    pub fn unload_plugins(&mut self) -> Result<()> {
        let mut plugins = self.plugins.lock().map_err(|_| 
            anyhow::anyhow!("Failed to acquire plugin lock")
        )?;

        for plugin in plugins.values_mut() {
            plugin.cleanup()?;
        }

        plugins.clear();
        Ok(())
    }
}

/// Plugin manager to handle environment detection plugins
pub struct EnvironmentPluginManager {
    plugins: Vec<Box<dyn EnvironmentDetectionPlugin>>,
    plugin_manager: PluginManager,
}

impl EnvironmentPluginManager {
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self { 
            plugins: Vec::new(), 
            plugin_manager: PluginManager::new(plugin_dir)
        }
    }

    /// Register a new detection plugin
    pub fn register_plugin(&mut self, plugin: Box<dyn EnvironmentDetectionPlugin>) {
        self.plugins.push(plugin);
    }

    /// Detect environment type for a given path
    pub async fn detect_environment(&self, path: &Path) -> Result<Option<EnvironmentPluginConfig>> {
        for plugin in &self.plugins {
            if plugin.can_detect(path).await? {
                let config = plugin.detect_configuration(path).await?;
                if let Some(config) = config {
                    // Optional: Setup the environment if detection is successful
                    plugin.setup_environment(path).await?;
                    return Ok(Some(config));
                }
            }
        }
        Ok(None)
    }

    /// List all registered plugins
    pub fn list_plugins(&self) -> Vec<(&'static str, &'static str)> {
        self.plugins
            .iter()
            .map(|p| (p.id(), p.name()))
            .collect()
    }

    /// Load plugins from directory
    pub fn load_plugins(&mut self) -> Result<()> {
        self.plugin_manager.load_plugins()
    }

    /// Register a plugin
    pub fn register_plugin_manager(&mut self, plugin: Box<dyn Plugin>) -> Result<()> {
        self.plugin_manager.register_plugin(plugin)
    }

    /// Get a plugin by ID
    pub fn get_plugin(&self, plugin_id: &Uuid) -> Option<Arc<Box<dyn Plugin>>> {
        self.plugin_manager.get_plugin(plugin_id)
    }

    /// List all loaded plugins
    pub fn list_plugins_manager(&self) -> Result<Vec<PluginMetadata>> {
        self.plugin_manager.list_plugins()
    }

    /// Execute a plugin action
    pub fn execute_plugin_manager(
        &self, 
        plugin_id: &Uuid, 
        action: &str, 
        args: &[String]
    ) -> Result<String> {
        self.plugin_manager.execute_plugin(plugin_id, action, args)
    }

    /// Unload and cleanup plugins
    pub fn unload_plugins_manager(&mut self) -> Result<()> {
        self.plugin_manager.unload_plugins()
    }
}

/// Example plugins for different environment types
pub mod plugins {
    use super::*;

    /// DevContainer Detection Plugin
    pub struct DevContainerPlugin;

    #[async_trait]
    impl EnvironmentDetectionPlugin for DevContainerPlugin {
        fn id(&self) -> &'static str { "devcontainer" }
        fn name(&self) -> &'static str { "DevContainer Detection Plugin" }
        fn description(&self) -> &'static str { "Detects DevContainer environments" }

        async fn can_detect(&self, path: &Path) -> Result<bool> {
            let config_paths = vec![
                path.join(".devcontainer").join("devcontainer.json"),
                path.join(".devcontainer.json"),
            ];

            Ok(config_paths.iter().any(|p| p.exists()))
        }

        async fn detect_configuration(&self, path: &Path) -> Result<Option<EnvironmentPluginConfig>> {
            let config_paths = vec![
                path.join(".devcontainer").join("devcontainer.json"),
                path.join(".devcontainer.json"),
            ];

            let config_path = config_paths.iter().find(|p| p.exists());

            match config_path {
                Some(path) => {
                    let config_content = std::fs::read_to_string(path)?;
                    let json: serde_json::Value = serde_json::from_str(&config_content)?;

                    Ok(Some(EnvironmentPluginConfig {
                        env_type: "devcontainer".to_string(),
                        languages: json["languages"]
                            .as_array()
                            .map(|langs| langs.iter().filter_map(|l| l.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        dependencies: json["features"]
                            .as_object()
                            .map(|features| features.keys().cloned().collect())
                            .unwrap_or_default(),
                        metadata: json,
                    }))
                }
                None => Ok(None)
            }
        }
    }

    /// Nix Environment Detection Plugin
    #[cfg(feature = "nix")]
    pub struct NixPlugin;

    #[cfg(feature = "nix")]
    #[async_trait]
    impl EnvironmentDetectionPlugin for NixPlugin {
        fn id(&self) -> &'static str { "nix" }
        fn name(&self) -> &'static str { "Nix Environment Detection Plugin" }
        fn description(&self) -> &'static str { "Detects Nix environments" }

        async fn can_detect(&self, path: &Path) -> Result<bool> {
            let nix_paths = vec![
                path.join("flake.nix"),
                path.join("default.nix"),
                path.join("shell.nix"),
            ];

            Ok(nix_paths.iter().any(|p| p.exists()))
        }

        async fn detect_configuration(&self, path: &Path) -> Result<Option<EnvironmentPluginConfig>> {
            let nix_paths = vec![
                path.join("flake.nix"),
                path.join("default.nix"),
                path.join("shell.nix"),
            ];

            let nix_path = nix_paths.iter().find(|p| p.exists());

            match nix_path {
                Some(path) => {
                    // Basic Nix configuration parsing
                    let content = std::fs::read_to_string(path)?;
                    
                    Ok(Some(EnvironmentPluginConfig {
                        env_type: "nix".to_string(),
                        languages: Vec::new(), // TODO: Parse languages from Nix file
                        dependencies: Vec::new(), // TODO: Parse dependencies
                        metadata: serde_json::json!({
                            "nix_file": path.to_string_lossy().to_string(),
                            "content_preview": content.chars().take(100).collect::<String>()
                        }),
                    }))
                }
                None => Ok(None)
            }
        }
    }

    /// Flox Environment Detection Plugin
    #[cfg(feature = "flox")]
    pub struct FloxPlugin;

    #[cfg(feature = "flox")]
    #[async_trait]
    impl EnvironmentDetectionPlugin for FloxPlugin {
        fn id(&self) -> &'static str { "flox" }
        fn name(&self) -> &'static str { "Flox Environment Detection Plugin" }
        fn description(&self) -> &'static str { "Detects Flox environments" }

        async fn can_detect(&self, path: &Path) -> Result<bool> {
            let flox_paths = vec![
                path.join(".flox"),
                path.join("flox.toml"),
            ];

            Ok(flox_paths.iter().any(|p| p.exists() && p.is_dir()))
        }

        async fn detect_configuration(&self, path: &Path) -> Result<Option<EnvironmentPluginConfig>> {
            let flox_paths = vec![
                path.join(".flox"),
                path.join("flox.toml"),
            ];

            let flox_path = flox_paths.iter().find(|p| p.exists());

            match flox_path {
                Some(path) => {
                    // Basic Flox configuration parsing
                    Ok(Some(EnvironmentPluginConfig {
                        env_type: "flox".to_string(),
                        languages: Vec::new(), // TODO: Parse languages
                        dependencies: Vec::new(), // TODO: Parse dependencies
                        metadata: serde_json::json!({
                            "flox_path": path.to_string_lossy().to_string()
                        }),
                    }))
                }
                None => Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_plugin_manager_registration() {
        let mut manager = EnvironmentPluginManager::new(tempdir().unwrap().path().to_path_buf());
        manager.register_plugin(Box::new(plugins::DevContainerPlugin));

        let plugins = manager.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].0, "devcontainer");
    }

    #[tokio::test]
    async fn test_devcontainer_plugin_detection() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path();

        // Create a mock DevContainer configuration
        std::fs::create_dir_all(path.join(".devcontainer")).unwrap();
        std::fs::write(
            path.join(".devcontainer/devcontainer.json"), 
            r#"{"languages": ["rust"], "features": {"golang": true}}"#
        ).unwrap();

        let mut manager = EnvironmentPluginManager::new(tempdir().unwrap().path().to_path_buf());
        manager.register_plugin(Box::new(plugins::DevContainerPlugin));

        let result = manager.detect_environment(path).await.unwrap();
        assert!(result.is_some());
        
        let config = result.unwrap();
        assert_eq!(config.env_type, "devcontainer");
        assert_eq!(config.languages, vec!["rust"]);
    }
}
