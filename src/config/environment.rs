use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Development Environment Configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevEnvironmentConfig {
    /// Unique environment identifier
    pub id: Uuid,

    /// Environment name
    pub name: String,

    /// Project root directory
    pub project_root: PathBuf,

    /// Supported programming languages
    pub languages: Vec<ProgrammingLanguage>,

    /// Environment dependencies
    pub dependencies: Vec<DependencyConfig>,

    /// Environment variables
    pub env_vars: HashMap<String, String>,

    /// IDE configurations
    pub ide_configs: Vec<IDEConfig>,

    /// Git repository configuration
    pub git_config: Option<GitConfig>,

    /// Resource allocation
    pub resources: ResourceConfig,

    /// Networking configuration
    pub network: NetworkConfig,
}

/// Programming Language Support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgrammingLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Other(String),
}

/// Dependency Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyConfig {
    /// Package manager
    pub manager: PackageManager,

    /// Package name
    pub name: String,

    /// Version constraint
    pub version: Option<String>,
}

/// Package Manager Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageManager {
    Cargo,
    Pip,
    Npm,
    Yarn,
    Maven,
    Gradle,
    Other(String),
}

/// IDE Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDEConfig {
    /// Supported IDEs
    pub ide: IDEType,

    /// Custom settings path
    pub settings_path: Option<PathBuf>,
}

/// Supported IDEs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IDEType {
    VSCode,
    JetBrainsSuite,
    IntelliJ,
    WebStorm,
    PyCharm,
    Other(String),
}

/// Git Repository Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitConfig {
    /// Repository URL
    pub repo_url: String,

    /// Branch to checkout
    pub branch: Option<String>,

    /// Commit hash (optional)
    pub commit: Option<String>,
}

/// Resource Allocation Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// CPU cores allocation
    pub cpu_cores: Option<u8>,

    /// Memory allocation in MB
    pub memory_mb: Option<u64>,

    /// Disk space allocation in GB
    pub disk_gb: Option<u64>,
}

/// Network Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Exposed ports
    pub exposed_ports: Vec<u16>,

    /// VPN configuration
    pub vpn: Option<VPNConfig>,
}

/// VPN Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VPNConfig {
    /// VPN provider
    pub provider: String,

    /// Connection details
    pub connection_details: HashMap<String, String>,
}

/// Environment Manager
pub struct EnvironmentManager {
    /// Base directory for environments
    base_dir: PathBuf,
}

impl EnvironmentManager {
    /// Create a new environment manager
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Create a new development environment
    pub fn create_environment(&self, config: &DevEnvironmentConfig) -> Result<()> {
        // Create environment directory
        let env_dir = self.base_dir.join(&config.name);
        fs::create_dir_all(&env_dir)?;

        // Save environment configuration
        let config_path = env_dir.join("dem_config.json");
        let config_json = serde_json::to_string_pretty(config)
            .context("Failed to serialize environment config")?;
        fs::write(config_path, config_json)?;

        // Setup project structure
        self.setup_project_structure(&env_dir, config)?;

        // Initialize dependencies
        self.initialize_dependencies(config)?;

        // Configure IDE
        self.configure_ide(config)?;

        Ok(())
    }

    /// Setup project directory structure
    fn setup_project_structure(&self, env_dir: &Path, config: &DevEnvironmentConfig) -> Result<()> {
        // Create source directories for supported languages
        for lang in &config.languages {
            let lang_dir = match lang {
                ProgrammingLanguage::Rust => env_dir.join("src"),
                ProgrammingLanguage::Python => env_dir.join("python"),
                ProgrammingLanguage::JavaScript | ProgrammingLanguage::TypeScript => {
                    env_dir.join("js")
                }
                ProgrammingLanguage::Go => env_dir.join("go"),
                ProgrammingLanguage::Java => env_dir.join("java"),
                ProgrammingLanguage::Other(name) => env_dir.join(name.to_lowercase()),
            };

            fs::create_dir_all(lang_dir)?;
        }

        Ok(())
    }

    /// Initialize project dependencies
    fn initialize_dependencies(&self, config: &DevEnvironmentConfig) -> Result<()> {
        for dep in &config.dependencies {
            match dep.manager {
                PackageManager::Cargo => {
                    // Initialize Rust project with Cargo
                    std::process::Command::new("cargo")
                        .arg("init")
                        .current_dir(&config.project_root)
                        .status()?;
                }
                PackageManager::Pip => {
                    // Create Python virtual environment
                    std::process::Command::new("python")
                        .args(&["-m", "venv", ".venv"])
                        .current_dir(&config.project_root)
                        .status()?;
                }
                // Add more package manager initializations
                _ => {}
            }
        }

        Ok(())
    }

    /// Configure IDE settings
    fn configure_ide(&self, config: &DevEnvironmentConfig) -> Result<()> {
        for ide_config in &config.ide_configs {
            if let IDEType::VSCode = ide_config.ide {
                // Generate VS Code workspace settings
                let vscode_dir = config.project_root.join(".vscode");
                fs::create_dir_all(&vscode_dir)?;

                // Example: Generate settings.json
                let settings = serde_json::json!({
                    "rust-analyzer.linkedProjects": [
                        "./Cargo.toml"
                    ]
                });

                fs::write(
                    vscode_dir.join("settings.json"),
                    serde_json::to_string_pretty(&settings)?,
                )?;
            }
        }

        Ok(())
    }

    /// List all existing environments
    pub fn list_environments(&self) -> Result<Vec<DevEnvironmentConfig>> {
        let mut environments = Vec::new();

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let config_path = entry.path().join("dem_config.json");

            if config_path.exists() {
                let config_json = fs::read_to_string(config_path)?;
                let config: DevEnvironmentConfig = serde_json::from_str(&config_json)?;
                environments.push(config);
            }
        }

        Ok(environments)
    }

    /// Delete an environment
    pub fn delete_environment(&self, env_name: &str) -> Result<()> {
        let env_dir = self.base_dir.join(env_name);

        if env_dir.exists() {
            fs::remove_dir_all(env_dir)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_environment() {
        let temp_dir = tempdir().unwrap();
        let env_manager = EnvironmentManager::new(temp_dir.path().to_path_buf());

        let config = DevEnvironmentConfig {
            id: Uuid::new_v4(),
            name: "test-project".to_string(),
            project_root: temp_dir.path().join("test-project"),
            languages: vec![ProgrammingLanguage::Rust, ProgrammingLanguage::Python],
            dependencies: vec![
                DependencyConfig {
                    manager: PackageManager::Cargo,
                    name: "serde".to_string(),
                    version: Some("1.0".to_string()),
                },
                DependencyConfig {
                    manager: PackageManager::Pip,
                    name: "requests".to_string(),
                    version: Some("2.26.0".to_string()),
                },
            ],
            env_vars: HashMap::new(),
            ide_configs: vec![IDEConfig {
                ide: IDEType::VSCode,
                settings_path: None,
            }],
            git_config: None,
            resources: ResourceConfig {
                cpu_cores: Some(2),
                memory_mb: Some(4096),
                disk_gb: Some(10),
            },
            network: NetworkConfig {
                exposed_ports: vec![8080, 3000],
                vpn: None,
            },
        };

        env_manager.create_environment(&config).unwrap();

        // Verify environment creation
        assert!(temp_dir.path().join("test-project").exists());
        assert!(temp_dir
            .path()
            .join("test-project/dem_config.json")
            .exists());
        assert!(temp_dir.path().join("test-project/src").exists());
        assert!(temp_dir.path().join("test-project/python").exists());
    }

    #[test]
    fn test_list_environments() {
        let temp_dir = tempdir().unwrap();
        let env_manager = EnvironmentManager::new(temp_dir.path().to_path_buf());

        // Create multiple test environments
        let config1 = DevEnvironmentConfig {
            id: Uuid::new_v4(),
            name: "project1".to_string(),
            project_root: temp_dir.path().join("project1"),
            languages: vec![ProgrammingLanguage::Rust],
            dependencies: vec![],
            env_vars: HashMap::new(),
            ide_configs: vec![],
            git_config: None,
            resources: ResourceConfig {
                cpu_cores: None,
                memory_mb: None,
                disk_gb: None,
            },
            network: NetworkConfig {
                exposed_ports: vec![],
                vpn: None,
            },
        };

        let config2 = DevEnvironmentConfig {
            id: Uuid::new_v4(),
            name: "project2".to_string(),
            project_root: temp_dir.path().join("project2"),
            languages: vec![ProgrammingLanguage::Python],
            dependencies: vec![],
            env_vars: HashMap::new(),
            ide_configs: vec![],
            git_config: None,
            resources: ResourceConfig {
                cpu_cores: None,
                memory_mb: None,
                disk_gb: None,
            },
            network: NetworkConfig {
                exposed_ports: vec![],
                vpn: None,
            },
        };

        env_manager.create_environment(&config1).unwrap();
        env_manager.create_environment(&config2).unwrap();

        // List environments
        let environments = env_manager.list_environments().unwrap();
        assert_eq!(environments.len(), 2);
        assert!(environments.iter().any(|e| e.name == "project1"));
        assert!(environments.iter().any(|e| e.name == "project2"));
    }
}
