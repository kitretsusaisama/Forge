use anyhow::{Context, Result};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EnvironmentType {
    DevContainer,
    Nix,
    Flox,
    Docker,
    Conda,
    Venv,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvironmentDetector {
    pub base_path: PathBuf,
}

impl EnvironmentDetector {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    pub fn detect_environment_type(&self) -> Result<EnvironmentType> {
        // Check for DevContainer configuration
        if self.has_devcontainer_config()? {
            return Ok(EnvironmentType::DevContainer);
        }

        // Check for Nix configuration
        #[cfg(feature = "nix")]
        if self.has_nix_config()? {
            return Ok(EnvironmentType::Nix);
        }

        // Check for Flox configuration
        #[cfg(feature = "flox")]
        if self.has_flox_config()? {
            return Ok(EnvironmentType::Flox);
        }

        // Check for Docker configuration
        #[cfg(feature = "docker")]
        if self.has_dockerfile()? {
            return Ok(EnvironmentType::Docker);
        }

        // Check for Python virtual environments
        if self.has_python_venv()? {
            return Ok(EnvironmentType::Venv);
        }

        // Check for Conda environments
        if self.has_conda_config()? {
            return Ok(EnvironmentType::Conda);
        }

        Ok(EnvironmentType::Unknown)
    }

    fn has_devcontainer_config(&self) -> Result<bool> {
        let config_paths = vec![
            self.base_path.join(".devcontainer").join("devcontainer.json"),
            self.base_path.join(".devcontainer.json"),
        ];

        Ok(config_paths.iter().any(|p| p.exists()))
    }

    #[cfg(feature = "nix")]
    fn has_nix_config(&self) -> Result<bool> {
        let nix_paths = vec![
            self.base_path.join("flake.nix"),
            self.base_path.join("default.nix"),
            self.base_path.join("shell.nix"),
        ];

        Ok(nix_paths.iter().any(|p| p.exists()))
    }

    #[cfg(feature = "flox")]
    fn has_flox_config(&self) -> Result<bool> {
        let flox_paths = vec![
            self.base_path.join(".flox"),
            self.base_path.join("flox.toml"),
        ];

        Ok(flox_paths.iter().any(|p| p.exists() && p.is_dir()))
    }

    #[cfg(feature = "docker")]
    fn has_dockerfile(&self) -> Result<bool> {
        let dockerfile_paths = vec![
            self.base_path.join("Dockerfile"),
            self.base_path.join(".dockerfile"),
        ];

        Ok(dockerfile_paths.iter().any(|p| p.exists()))
    }

    fn has_python_venv(&self) -> Result<bool> {
        // Look for typical Python virtual environment markers
        let venv_markers = vec![
            self.base_path.join("venv"),
            self.base_path.join(".venv"),
            self.base_path.join("env"),
        ];

        // Check for presence of activation scripts
        let activation_scripts = vec![
            "bin/activate",     // Unix-like
            "Scripts/activate", // Windows
        ];

        Ok(venv_markers.iter().any(|p| p.exists() && p.is_dir()) ||
           venv_markers.iter().any(|base| 
               activation_scripts.iter().any(|script| base.join(script).exists())
           ))
    }

    fn has_conda_config(&self) -> Result<bool> {
        // Look for Conda environment markers
        let conda_markers = vec![
            self.base_path.join("environment.yml"),
            self.base_path.join("conda-meta"),
        ];

        Ok(conda_markers.iter().any(|p| p.exists()))
    }

    pub fn find_environments_in_directory(&self) -> Result<Vec<PathBuf>> {
        let mut environments = Vec::new();

        // Use ignore crate for efficient directory traversal
        let walker = WalkBuilder::new(&self.base_path)
            .max_depth(Some(3))  // Limit depth to avoid deep scanning
            .build();

        for result in walker {
            let entry = result.context("Error walking directory")?;
            let path = entry.path().to_path_buf();

            // Create a temporary detector for each potential environment
            let detector = EnvironmentDetector::new(path.clone());
            
            // Check if this path represents an environment
            if let Ok(env_type) = detector.detect_environment_type() {
                if !matches!(env_type, EnvironmentType::Unknown) {
                    environments.push(path);
                }
            }
        }

        Ok(environments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_devcontainer_detection() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Create a DevContainer configuration
        fs::create_dir_all(path.join(".devcontainer")).unwrap();
        fs::write(path.join(".devcontainer/devcontainer.json"), "{}").unwrap();

        let detector = EnvironmentDetector::new(path);
        assert!(matches!(detector.detect_environment_type().unwrap(), EnvironmentType::DevContainer));
    }

    #[test]
    fn test_python_venv_detection() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Create a Python virtual environment marker
        fs::create_dir_all(path.join(".venv/bin")).unwrap();
        fs::write(path.join(".venv/bin/activate"), "").unwrap();

        let detector = EnvironmentDetector::new(path);
        assert!(matches!(detector.detect_environment_type().unwrap(), EnvironmentType::Venv));
    }
}
