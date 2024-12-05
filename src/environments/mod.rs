use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fmt;
use tokio::fs;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{
    ForgeConfig,
    parser::ConfigParser,
    devcontainer::DevContainerConfig,
};

pub mod port_forward;
pub use port_forward::*;

mod devcontainer;

// Import detection and plugin modules
use crate::detection::EnvironmentDetector;
use crate::plugins::{EnvironmentPluginManager, EnvironmentPluginConfig};

// Import Docker client and storage
#[cfg(feature = "docker")]
use crate::docker::DockerClient;
use crate::storage::EnvironmentStorage;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Environment {
    pub name: String,
    pub env_type: String,
    pub path: PathBuf,
    pub status: EnvironmentStatus,
    pub config: Option<EnvironmentConfig>,
    
    // Optional Docker-related fields
    #[serde(skip)]
    pub container_id: Option<String>,

    // Port forwarding information
    #[serde(skip)]
    pub port_forwards: Vec<PortForward>,

    // Plugin-detected metadata
    pub plugin_metadata: Option<serde_json::Value>,
}

impl fmt::Display for EnvironmentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvironmentStatus::Created => write!(f, "Created"),
            EnvironmentStatus::Running => write!(f, "Running"),
            EnvironmentStatus::Stopped => write!(f, "Stopped"),
            EnvironmentStatus::Error => write!(f, "Error"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EnvironmentConfig {
    DevContainer(DevContainerConfig),
    Nix(NixConfig),
    Flox(FloxConfig),
    Conda(CondaConfig),
    Venv(VenvConfig),
    // Future: Add more environment configurations
}

// Placeholder configurations for different environment types
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NixConfig {
    pub flake_url: Option<String>,
    pub system: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FloxConfig {
    pub environment_name: Option<String>,
    pub system: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CondaConfig {
    pub environment_name: Option<String>,
    pub packages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VenvConfig {
    pub python_version: Option<String>,
    pub packages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum EnvironmentStatus {
    Created,
    Running,
    Stopped,
    Error,
}

pub struct EnvironmentManager {
    config: Arc<ForgeConfig>,
    detector: Arc<EnvironmentDetector>,
    plugin_manager: Arc<EnvironmentPluginManager>,
    storage: Arc<EnvironmentStorage>,
    port_forward: Arc<PortForwardManager>,
}

impl EnvironmentManager {
    pub async fn new(config: Arc<ForgeConfig>) -> Result<Self> {
        let base_dir = config.base_directory();
        let detector = Arc::new(EnvironmentDetector::new(base_dir.clone()));
        let plugin_manager = Arc::new(EnvironmentPluginManager::new(base_dir));
        let storage = Arc::new(EnvironmentStorage::new().await?);
        let port_forward = Arc::new(PortForwardManager::new(config.port_forwarding.clone()));

        Ok(Self {
            config,
            detector,
            plugin_manager,
            storage,
            port_forward,
        })
    }

    pub async fn create_environment(&self, name: &str, template: Option<&str>) -> Result<Environment> {
        // Get template configuration
        let template_config = if let Some(template_name) = template {
            self.config.templates.get(template_name)
                .context(format!("Template {} not found", template_name))?
        } else {
            self.config.templates.get(&self.config.environments.default_template)
                .context("Default template not found")?
        };

        // Create environment directory
        let env_path = self.config.environments.data_directory.join(name);
        fs::create_dir_all(&env_path).await?;

        // Create environment with template settings
        let mut env = Environment {
            name: name.to_string(),
            env_type: template_config.name.clone(),
            path: env_path.clone(),
            status: EnvironmentStatus::Created,
            config: None,
            container_id: None,
            port_forwards: Vec::new(),
            plugin_metadata: None,
        };

        // Create container with template settings
        #[cfg(feature = "docker")]
        if let Some(container_id) = self.port_forward.create_container(
            &env,
            &template_config.base_image,
            &template_config.exposed_ports,
            &template_config.env_vars,
        ).await? {
            env.container_id = Some(container_id);
        }

        // Save environment
        self.storage.save_environment(&env).await?;

        Ok(env)
    }

    pub async fn list_environments(&self) -> Result<Vec<Environment>> {
        self.storage.list_environments().await
    }

    pub async fn start_environment(&self, name: &str) -> Result<()> {
        let env = self.storage.get_environment(name).await?
            .context("Environment not found")?;

        // Start the environment using the plugin manager
        self.plugin_manager.start_environment(&env).await?;

        // Set up port forwarding if needed
        if let Some(ports) = env.exposed_ports {
            for port in ports {
                self.port_forward.create_forward(
                    &env.name,
                    port,
                    &self.config.port_forwarding,
                ).await?;
            }
        }

        Ok(())
    }

    pub async fn stop_environment(&self, name: &str) -> Result<()> {
        let env = self.storage.get_environment(name).await?
            .context("Environment not found")?;

        // Stop port forwarding
        self.port_forward.remove_forwards(&env.name).await?;

        // Stop the environment using the plugin manager
        self.plugin_manager.stop_environment(&env).await?;

        Ok(())
    }

    pub async fn delete_environment(&self, name: &str) -> Result<bool> {
        // First, stop the environment if it's running
        if let Some(mut env) = self.storage.get_environment(name).await? {
            #[cfg(feature = "docker")]
            {
                // Stop container if it exists
                if let Some(container_id) = &env.container_id {
                    self.port_forward.stop_container(container_id).await?;
                }
            }
            
            // Remove from filesystem
            if env.path.exists() {
                fs::remove_dir_all(&env.path).await
                    .context("Failed to remove environment directory")?;
            }
        }
        
        // Remove from database
        self.storage.delete_environment(name).await
    }

    pub async fn find_environments(&self) -> Result<Vec<Environment>> {
        // Use environment detector to find environments in base path
        let detector = EnvironmentDetector::new(self.config.environments.data_directory.clone());
        
        // Find potential environment paths
        let env_paths = detector.find_environments_in_directory()?;
        
        // Convert paths to environments
        let mut environments = Vec::new();
        
        for path in env_paths {
            // Extract environment name from path
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            
            // Create an environment from the path
            let env = self.create_environment(&name, Some("auto")).await?;
            environments.push(env);
        }
        
        Ok(environments)
    }

    pub async fn get_environment_url(&self, name: &str) -> Result<Option<String>> {
        let env = self.storage.get_environment(name).await?;
        
        if !env.port_forwards.is_empty() {
            // Return the URL of the first port forward
            Ok(Some(env.port_forwards[0].public_url.clone()))
        } else {
            Ok(None)
        }
    }

    pub async fn list_port_forwards(&self, name: &str) -> Result<Vec<PortForward>> {
        let env = self.storage.get_environment(name).await?;
        Ok(env.port_forwards.clone())
    }

    // List available plugins
    pub fn list_plugins(&self) -> Vec<(&'static str, &'static str)> {
        self.plugin_manager.list_plugins()
    }
}

// Implement Default for easier instantiation
impl Default for EnvironmentManager {
    fn default() -> Self {
        // Note: This will panic if async initialization fails
        // In practice, you'd want a different pattern for default initialization
        tokio::runtime::Runtime::new()
            .expect("Failed to create Tokio runtime")
            .block_on(Self::new(Arc::new(ForgeConfig::load().await.unwrap())))
            .expect("Failed to create default EnvironmentManager")
    }
}
