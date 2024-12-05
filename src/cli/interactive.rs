use std::io::{self, Write};
use std::path::PathBuf;
use dialoguer::{
    theme::ColorfulTheme, 
    Input, 
    Select, 
    Confirm, 
    MultiSelect
};
use anyhow::{Result, Context};

use crate::config::environment::{
    DevEnvironmentConfig, 
    ProgrammingLanguage, 
    ProjectType, 
    DependencyConfig
};
use crate::plugins::{PluginType, PluginInstallParams};

/// Interactive configuration wizard for development environments
pub struct InteractiveConfigWizard;

impl InteractiveConfigWizard {
    /// Launch interactive environment creation wizard
    pub fn create_environment_wizard() -> Result<DevEnvironmentConfig> {
        println!("🚀 Forge Development Environment Wizard");
        
        // Project name
        let name: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter project name")
            .validate_with(|input: &String| {
                if input.len() >= 3 { Ok(()) } 
                else { Err("Project name must be at least 3 characters") }
            })
            .interact_text()?;

        // Language selection
        let language = Self::select_programming_language()?;

        // Project type
        let project_type = Self::select_project_type()?;

        // Dependency management
        let dependencies = Self::configure_dependencies()?;

        // Advanced configuration
        let advanced_config = Self::advanced_configuration()?;

        Ok(DevEnvironmentConfig {
            name,
            languages: vec![language],
            project_type,
            dependencies,
            advanced_config,
            ..Default::default()
        })
    }

    /// Interactive programming language selection
    fn select_programming_language() -> Result<ProgrammingLanguage> {
        let languages = vec![
            ProgrammingLanguage::Rust,
            ProgrammingLanguage::Python,
            ProgrammingLanguage::JavaScript,
            ProgrammingLanguage::Go,
            ProgrammingLanguage::TypeScript,
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select primary programming language")
            .items(&languages)
            .default(0)
            .interact()?;

        Ok(languages[selection])
    }

    /// Interactive project type selection
    fn select_project_type() -> Result<ProjectType> {
        let project_types = vec![
            ProjectType::WebApplication,
            ProjectType::CLI,
            ProjectType::Library,
            ProjectType::Microservice,
            ProjectType::DesktopApplication,
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select project type")
            .items(&project_types)
            .default(0)
            .interact()?;

        Ok(project_types[selection])
    }

    /// Interactive dependency configuration
    fn configure_dependencies() -> Result<Vec<DependencyConfig>> {
        let mut dependencies = Vec::new();

        loop {
            let add_dependency = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Would you like to add a dependency?")
                .interact()?;

            if !add_dependency {
                break;
            }

            let name: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Dependency name")
                .interact_text()?;

            let version: Option<String> = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Dependency version (optional)")
                .allow_empty(true)
                .interact_text()?;

            dependencies.push(DependencyConfig {
                name,
                version,
                ..Default::default()
            });
        }

        Ok(dependencies)
    }

    /// Advanced environment configuration
    fn advanced_configuration() -> Result<serde_json::Value> {
        let features = vec![
            "Code Formatting",
            "Linting",
            "Testing Framework",
            "Custom Configuration"
        ];

        let selected_features = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select additional features")
            .items(&features)
            .interact()?;

        let mut advanced_config = serde_json::json!({});

        for index in selected_features {
            match features[index] {
                "Code Formatting" => {
                    advanced_config["code_formatting"] = serde_json::json!({
                        "enabled": true,
                        "tools": ["rustfmt", "prettier"]
                    });
                },
                "Linting" => {
                    advanced_config["linting"] = serde_json::json!({
                        "enabled": true,
                        "tools": ["clippy", "eslint"]
                    });
                },
                "Testing Framework" => {
                    advanced_config["testing"] = serde_json::json!({
                        "enabled": true,
                        "frameworks": ["cargo test", "pytest"]
                    });
                },
                "Custom Configuration" => {
                    let custom_config: String = Input::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter custom configuration (JSON)")
                        .interact_text()?;

                    advanced_config["custom"] = serde_json::from_str(&custom_config)
                        .unwrap_or(serde_json::json!({}));
                },
                _ => {}
            }
        }

        Ok(advanced_config)
    }

    /// Interactive plugin installation wizard
    pub fn plugin_installation_wizard() -> Result<PluginInstallParams> {
        let plugin_types = vec![
            PluginType::IDE,
            PluginType::BuildSystem,
            PluginType::CustomTool
        ];

        let type_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select plugin type")
            .items(&plugin_types)
            .default(0)
            .interact()?;

        let name: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter plugin name")
            .interact_text()?;

        let source: PathBuf = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter plugin source path")
            .validate_with(|input: &String| {
                let path = PathBuf::from(input);
                if path.exists() { Ok(()) } 
                else { Err("Plugin source path does not exist") }
            })
            .interact_text()?
            .into();

        Ok(PluginInstallParams {
            name,
            plugin_type: plugin_types[type_selection],
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_environment_creation_wizard() {
        // Mock test for environment creation
        // Note: This is a basic test and might need user interaction
        let result = InteractiveConfigWizard::create_environment_wizard();
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_installation_wizard() {
        // Mock test for plugin installation
        let temp_dir = tempdir().unwrap();
        let plugin_path = temp_dir.path().join("test_plugin");
        std::fs::write(&plugin_path, "test content").unwrap();

        let result = InteractiveConfigWizard::plugin_installation_wizard();
        assert!(result.is_ok());
    }
}
