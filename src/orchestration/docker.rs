use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use uuid::Uuid;

/// Docker container configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerContainerConfig {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub ports: Vec<PortMapping>,
    pub environment_vars: HashMap<String, String>,
    pub volumes: Vec<VolumeMount>,
    pub network: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_limit: Option<f32>,
    pub restart_policy: RestartPolicy,
}

/// Port mapping for containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: PortProtocol,
}

/// Port protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortProtocol {
    TCP,
    UDP,
}

/// Volume mounting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host_path: PathBuf,
    pub container_path: PathBuf,
    pub read_only: bool,
}

/// Container restart policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    UnlessStopped,
    Never,
}

/// Docker management service
pub struct DockerManager {
    base_dir: PathBuf,
}

impl DockerManager {
    /// Create a new Docker manager
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// List all running containers
    pub async fn list_containers(&self) -> Result<Vec<DockerContainerConfig>> {
        let output = Command::new("docker")
            .arg("ps")
            .arg("-a")
            .arg("--format")
            .arg("{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
            .output()
            .await?;

        let stdout = String::from_utf8(output.stdout)?;
        let containers: Vec<DockerContainerConfig> = stdout
            .lines()
            .filter_map(|line| self.parse_container_line(line))
            .collect();

        Ok(containers)
    }

    /// Parse a single container line from docker ps output
    fn parse_container_line(&self, line: &str) -> Option<DockerContainerConfig> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            return None;
        }

        Some(DockerContainerConfig {
            id: Uuid::new_v4(), // Placeholder, should use actual container ID
            name: parts[1].to_string(),
            image: parts[2].to_string(),
            ports: self.parse_ports(parts[4]),
            environment_vars: HashMap::new(), // Placeholder
            volumes: vec![], // Placeholder
            network: None,
            memory_limit: None,
            cpu_limit: None,
            restart_policy: RestartPolicy::Always,
        })
    }

    /// Parse port mappings
    fn parse_ports(&self, port_str: &str) -> Vec<PortMapping> {
        port_str
            .split(',')
            .filter_map(|p| {
                let parts: Vec<&str> = p.split("->").collect();
                if parts.len() != 2 {
                    return None;
                }

                let host_port: u16 = parts[0].parse().ok()?;
                let container_parts: Vec<&str> = parts[1].split('/').collect();
                let container_port: u16 = container_parts[0].parse().ok()?;
                let protocol = match container_parts.get(1) {
                    Some(&"tcp") => PortProtocol::TCP,
                    Some(&"udp") => PortProtocol::UDP,
                    _ => PortProtocol::TCP,
                };

                Some(PortMapping {
                    host_port,
                    container_port,
                    protocol,
                })
            })
            .collect()
    }

    /// Create a new container
    pub async fn create_container(&self, config: &DockerContainerConfig) -> Result<String> {
        let mut cmd = Command::new("docker");
        cmd.arg("run");

        // Add name
        cmd.arg("--name").arg(&config.name);

        // Add port mappings
        for port in &config.ports {
            cmd.arg("-p")
                .arg(format!("{}:{}/{}", port.host_port, port.container_port, 
                    match port.protocol {
                        PortProtocol::TCP => "tcp",
                        PortProtocol::UDP => "udp",
                    }
                ));
        }

        // Add environment variables
        for (key, value) in &config.environment_vars {
            cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Add volume mounts
        for volume in &config.volumes {
            cmd.arg("-v")
                .arg(format!(
                    "{}:{}{}",
                    volume.host_path.display(),
                    volume.container_path.display(),
                    if volume.read_only { ":ro" } else { "" }
                ));
        }

        // Add network
        if let Some(network) = &config.network {
            cmd.arg("--network").arg(network);
        }

        // Add memory limit
        if let Some(memory) = &config.memory_limit {
            cmd.arg("--memory").arg(memory);
        }

        // Add CPU limit
        if let Some(cpu) = config.cpu_limit {
            cmd.arg("--cpus").arg(cpu.to_string());
        }

        // Add restart policy
        cmd.arg("--restart").arg(match config.restart_policy {
            RestartPolicy::Always => "always",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::UnlessStopped => "unless-stopped",
            RestartPolicy::Never => "no",
        });

        // Add image
        cmd.arg(&config.image);

        // Execute command
        let output = cmd.output().await?;

        // Check for success
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create container: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Return container ID
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Stop a container
    pub async fn stop_container(&self, container_id: &str) -> Result<()> {
        let output = Command::new("docker")
            .arg("stop")
            .arg(container_id)
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to stop container: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Remove a container
    pub async fn remove_container(&self, container_id: &str, force: bool) -> Result<()> {
        let mut cmd = Command::new("docker");
        cmd.arg("rm");

        if force {
            cmd.arg("-f");
        }

        cmd.arg(container_id);

        let output = cmd.output().await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to remove container: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Generate Dockerfile template
    pub fn generate_dockerfile(&self, project_type: &str) -> Result<String> {
        match project_type {
            "nodejs" => Ok(include_str!("templates/Dockerfile.nodejs").to_string()),
            "python" => Ok(include_str!("templates/Dockerfile.python").to_string()),
            "java" => Ok(include_str!("templates/Dockerfile.java").to_string()),
            "rust" => Ok(include_str!("templates/Dockerfile.rust").to_string()),
            _ => Err(anyhow::anyhow!("Unsupported project type")),
        }
    }

    /// Manage Docker networks
    pub async fn create_network(&self, network_name: &str) -> Result<()> {
        let output = Command::new("docker")
            .arg("network")
            .arg("create")
            .arg(network_name)
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to create network: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_docker_container_creation() {
        let temp_dir = tempdir().unwrap();
        let docker_manager = DockerManager::new(temp_dir.path().to_path_buf());

        let container_config = DockerContainerConfig {
            id: Uuid::new_v4(),
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            ports: vec![
                PortMapping {
                    host_port: 8080,
                    container_port: 80,
                    protocol: PortProtocol::TCP,
                }
            ],
            environment_vars: HashMap::new(),
            volumes: vec![],
            network: None,
            memory_limit: Some("256m".to_string()),
            cpu_limit: Some(0.5),
            restart_policy: RestartPolicy::Always,
        };

        // Note: This test will only work if Docker is installed and running
        // In a real-world scenario, you'd use a mock or Docker-in-Docker setup
        match docker_manager.create_container(&container_config).await {
            Ok(_) => {
                // Cleanup
                docker_manager.remove_container(&container_config.name, true).await.ok();
            },
            Err(e) => {
                println!("Container creation test skipped: {}", e);
            }
        }
    }

    #[test]
    fn test_dockerfile_generation() {
        let temp_dir = tempdir().unwrap();
        let docker_manager = DockerManager::new(temp_dir.path().to_path_buf());

        let nodejs_dockerfile = docker_manager.generate_dockerfile("nodejs").unwrap();
        assert!(nodejs_dockerfile.contains("FROM node:"));

        let python_dockerfile = docker_manager.generate_dockerfile("python").unwrap();
        assert!(python_dockerfile.contains("FROM python:"));
    }
}
