use crate::config::devcontainer::DevContainerConfig;
use anyhow::{Context, Result};
use bollard::{
    container::{Config, CreateContainerOptions, StartContainerOptions},
    Docker,
    image::{BuildImageOptions, CreateImageOptions},
};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

use crate::environments::Environment;

pub struct DockerClient {
    client: Docker,
}

impl DockerClient {
    pub fn new() -> Result<Self> {
        let client = Docker::connect_with_local_defaults()
            .context("Failed to connect to Docker daemon")?;
        
        Ok(Self { client })
    }

    pub async fn build_devcontainer(&self, env: &Environment) -> Result<String> {
        // Ensure we have a DevContainer configuration
        let config = match &env.config {
            Some(config) => match config {
                crate::environments::EnvironmentConfig::DevContainer(dc) => dc,
            },
            None => return Err(anyhow::anyhow!("No DevContainer configuration found")),
        };

        // Determine build context
        let build_context = if let Some(build) = &config.build {
            build.context.clone().unwrap_or_else(|| ".".to_string())
        } else {
            ".".to_string()
        };

        // Determine Dockerfile
        let dockerfile = config.docker_file.clone()
            .or_else(|| config.build.as_ref().and_then(|b| b.dockerfile.clone()))
            .unwrap_or_else(|| "Dockerfile".to_string());

        // Prepare build options
        let build_options = BuildImageOptions {
            dockerfile: dockerfile.clone(),
            t: config.name.clone(),
            rm: true,
            pull: true,
            ..Default::default()
        };

        // Stream build output
        let mut build_stream = self.client.build_image(
            build_options, 
            None, 
            Some(env.path.clone())
        );

        // Process build stream
        while let Some(build_result) = build_stream.next().await {
            let build_info = build_result?;
            if let Some(error) = build_info.error {
                return Err(anyhow::anyhow!("Docker build error: {}", error));
            }
            // Optionally log build progress
            // tracing::info!("Build progress: {:?}", build_info);
        }

        Ok(config.name.clone())
    }

    pub async fn create_devcontainer(&self, env: &Environment) -> Result<String> {
        // Ensure we have a DevContainer configuration
        let config = match &env.config {
            Some(config) => match config {
                crate::environments::EnvironmentConfig::DevContainer(dc) => dc,
            },
            None => return Err(anyhow::anyhow!("No DevContainer configuration found")),
        };

        // Prepare container configuration
        let mut container_config = Config::<String>::default();
        
        // Set image or use the recently built image
        container_config.image = Some(config.name.clone());

        // Forward ports if specified
        if let Some(ports) = &config.forward_ports {
            let mut port_bindings = HashMap::new();
            for &port in ports {
                port_bindings.insert(
                    format!("{}/tcp", port),
                    Some(vec![bollard::service::PortBinding {
                        host_ip: Some("0.0.0.0".to_string()),
                        host_port: Some(port.to_string()),
                    }])
                );
            }
            container_config.host_config = Some(bollard::service::HostConfig {
                port_bindings: Some(port_bindings),
                ..Default::default()
            });
        }

        // Create container
        let container_name = format!("forge-{}", config.name);
        let create_options = CreateContainerOptions {
            name: &container_name,
            ..Default::default()
        };

        let container = self.client
            .create_container(Some(create_options), container_config)
            .await
            .context("Failed to create container")?;

        // Start the container
        self.client
            .start_container(&container.id, None::<StartContainerOptions<String>>)
            .await
            .context("Failed to start container")?;

        Ok(container.id)
    }

    pub async fn list_containers(&self) -> Result<Vec<String>> {
        let containers = self.client.list_containers::<String>(None)
            .await
            .context("Failed to list containers")?;

        Ok(containers.into_iter()
            .map(|c| c.id.unwrap_or_default())
            .collect())
    }

    pub async fn stop_container(&self, container_id: &str) -> Result<()> {
        self.client.stop_container(container_id, None)
            .await
            .context("Failed to stop container")?;

        Ok(())
    }

    // Check Docker availability
    pub fn is_docker_available() -> bool {
        Docker::connect_with_local_defaults().is_ok()
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DockerClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_docker_client_initialization() {
        let docker_client = DockerClient::new();
        assert!(docker_client.is_ok(), "Docker client should initialize");
    }

    #[tokio::test]
    async fn test_list_containers() {
        let docker_client = DockerClient::new().unwrap();
        let containers = docker_client.list_containers().await;
        assert!(containers.is_ok(), "Should be able to list containers");
    }
}
