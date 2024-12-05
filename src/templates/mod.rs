use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use tokio::fs;

/// Comprehensive template management system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentTemplate {
    pub id: String,
    pub name: String,
    pub language: String,
    pub version: String,
    pub template_type: TemplateType,
    pub dependencies: Vec<String>,
    pub configuration: TemplateConfiguration,
    pub recommended_resources: ResourceRecommendation,
}

/// Type of environment template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateType {
    Docker,
    Kubernetes,
    IDE,
    Development,
}

/// Configuration details for templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfiguration {
    pub environment_vars: HashMap<String, String>,
    pub ports: Vec<u16>,
    pub volumes: Vec<VolumeMount>,
    pub network_config: NetworkConfiguration,
}

/// Volume mounting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host_path: PathBuf,
    pub container_path: PathBuf,
    pub read_only: bool,
}

/// Network configuration for templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfiguration {
    pub network_mode: NetworkMode,
    pub dns_servers: Vec<String>,
    pub custom_networks: Vec<String>,
}

/// Network mode for containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode {
    Bridge,
    Host,
    None,
    Custom(String),
}

/// Resource recommendations for templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRecommendation {
    pub cpu_cores: f32,
    pub memory_mb: u32,
    pub storage_gb: u32,
    pub gpu_support: bool,
}

/// Template management service
pub struct TemplateManager {
    templates_dir: PathBuf,
    available_templates: Vec<EnvironmentTemplate>,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new(templates_dir: PathBuf) -> Self {
        Self {
            templates_dir,
            available_templates: Vec::new(),
        }
    }

    /// Load templates from directory
    pub async fn load_templates(&mut self) -> Result<()> {
        let mut templates = Vec::new();
        let mut dir = fs::read_dir(&self.templates_dir).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                let template_content = fs::read_to_string(&path).await?;
                let template: EnvironmentTemplate = serde_json::from_str(&template_content)
                    .context("Failed to parse template")?;
                templates.push(template);
            }
        }

        self.available_templates = templates;
        Ok(())
    }

    /// Get template by ID
    pub fn get_template(&self, template_id: &str) -> Option<&EnvironmentTemplate> {
        self.available_templates
            .iter()
            .find(|t| t.id == template_id)
    }

    /// Generate template based on workload type
    pub fn generate_template(
        language: &str, 
        version: &str, 
        workload_type: &str
    ) -> Result<EnvironmentTemplate> {
        let template = match (language, version, workload_type) {
            ("rust", "latest", "web") => Self::rust_web_template(),
            ("python", "3.9", "ml") => Self::python_ml_template(),
            ("nodejs", "16", "api") => Self::nodejs_api_template(),
            _ => return Err(anyhow::anyhow!("Unsupported template configuration")),
        };

        Ok(template)
    }

    /// Rust web service template
    fn rust_web_template() -> EnvironmentTemplate {
        EnvironmentTemplate {
            id: "rust-web-template".to_string(),
            name: "Rust Web Service".to_string(),
            language: "rust".to_string(),
            version: "latest".to_string(),
            template_type: TemplateType::Docker,
            dependencies: vec![
                "actix-web".to_string(),
                "serde".to_string(),
                "tokio".to_string(),
            ],
            configuration: TemplateConfiguration {
                environment_vars: HashMap::from([
                    ("RUST_LOG".to_string(), "info".to_string()),
                    ("SERVER_PORT".to_string(), "8080".to_string()),
                ]),
                ports: vec![8080],
                volumes: vec![],
                network_config: NetworkConfiguration {
                    network_mode: NetworkMode::Bridge,
                    dns_servers: vec![],
                    custom_networks: vec![],
                },
            },
            recommended_resources: ResourceRecommendation {
                cpu_cores: 2.0,
                memory_mb: 512,
                storage_gb: 10,
                gpu_support: false,
            },
        }
    }

    /// Python machine learning template
    fn python_ml_template() -> EnvironmentTemplate {
        EnvironmentTemplate {
            id: "python-ml-template".to_string(),
            name: "Python Machine Learning".to_string(),
            language: "python".to_string(),
            version: "3.9".to_string(),
            template_type: TemplateType::Docker,
            dependencies: vec![
                "tensorflow".to_string(),
                "numpy".to_string(),
                "pandas".to_string(),
                "scikit-learn".to_string(),
            ],
            configuration: TemplateConfiguration {
                environment_vars: HashMap::from([
                    ("PYTHONPATH".to_string(), "/app".to_string()),
                    ("JUPYTER_PORT".to_string(), "8888".to_string()),
                ]),
                ports: vec![8888],
                volumes: vec![],
                network_config: NetworkConfiguration {
                    network_mode: NetworkMode::Bridge,
                    dns_servers: vec![],
                    custom_networks: vec![],
                },
            },
            recommended_resources: ResourceRecommendation {
                cpu_cores: 4.0,
                memory_mb: 16384,  // 16GB
                storage_gb: 50,
                gpu_support: true,
            },
        }
    }

    /// Node.js API template
    fn nodejs_api_template() -> EnvironmentTemplate {
        EnvironmentTemplate {
            id: "nodejs-api-template".to_string(),
            name: "Node.js API Service".to_string(),
            language: "nodejs".to_string(),
            version: "16".to_string(),
            template_type: TemplateType::Docker,
            dependencies: vec![
                "express".to_string(),
                "mongoose".to_string(),
                "dotenv".to_string(),
                "winston".to_string(),
            ],
            configuration: TemplateConfiguration {
                environment_vars: HashMap::from([
                    ("NODE_ENV".to_string(), "production".to_string()),
                    ("API_PORT".to_string(), "3000".to_string()),
                ]),
                ports: vec![3000],
                volumes: vec![],
                network_config: NetworkConfiguration {
                    network_mode: NetworkMode::Bridge,
                    dns_servers: vec![],
                    custom_networks: vec![],
                },
            },
            recommended_resources: ResourceRecommendation {
                cpu_cores: 2.0,
                memory_mb: 1024,
                storage_gb: 20,
                gpu_support: false,
            },
        }
    }

    /// Save template to file
    pub async fn save_template(&self, template: &EnvironmentTemplate) -> Result<()> {
        let file_path = self.templates_dir.join(format!("{}.json", template.id));
        let template_json = serde_json::to_string_pretty(template)?;
        fs::write(file_path, template_json).await?;
        Ok(())
    }

    /// AI-powered template optimization
    pub fn optimize_template(
        &self, 
        template: &mut EnvironmentTemplate, 
        workload_metrics: &HashMap<String, f64>
    ) -> Result<()> {
        // Simple optimization logic - can be expanded with ML model
        if let Some(&cpu_usage) = workload_metrics.get("cpu_usage") {
            if cpu_usage > 0.8 {
                template.recommended_resources.cpu_cores *= 1.5;
            }
        }

        if let Some(&memory_usage) = workload_metrics.get("memory_usage") {
            if memory_usage > 0.9 {
                template.recommended_resources.memory_mb = 
                    (template.recommended_resources.memory_mb as f64 * 1.5) as u32;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_template_generation() {
        let rust_web_template = TemplateManager::generate_template("rust", "latest", "web")
            .expect("Failed to generate Rust web template");
        
        assert_eq!(rust_web_template.language, "rust");
        assert_eq!(rust_web_template.template_type, TemplateType::Docker);
    }

    #[tokio::test]
    async fn test_template_optimization() {
        let mut template = TemplateManager::generate_template("rust", "latest", "web")
            .expect("Failed to generate template");
        
        let metrics = HashMap::from([
            ("cpu_usage".to_string(), 0.9),
            ("memory_usage".to_string(), 0.95)
        ]);

        TemplateManager::optimize_template(&mut template, &metrics)
            .expect("Failed to optimize template");

        assert!(template.recommended_resources.cpu_cores > 2.0);
        assert!(template.recommended_resources.memory_mb > 512);
    }
}
