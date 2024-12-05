use anyhow::Result;
use bollard::Docker;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerStats {
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub network_rx: u64,
    pub network_tx: u64,
}

pub struct ContainerManager {
    docker: Docker,
}

impl ContainerManager {
    pub fn new() -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        Ok(Self { docker })
    }

    pub async fn list_containers(&self) -> Result<Vec<String>> {
        let containers = self.docker.list_containers::<String>(None).await?;
        Ok(containers.into_iter().filter_map(|c| c.names).flatten().collect())
    }

    pub async fn create_container(&self, config: &crate::cli::ContainerConfig) -> Result<String> {
        use bollard::container::Config;
        use bollard::service::HostConfig;

        let mut env = Vec::new();
        for e in &config.environment {
            env.push(e.as_str());
        }

        let host_config = HostConfig {
            binds: Some(config.volumes.clone()),
            ..Default::default()
        };

        let container_config = Config {
            image: Some(config.image.clone()),
            env: Some(env),
            host_config: Some(host_config),
            ..Default::default()
        };

        let container = self.docker
            .create_container(None, container_config)
            .await?;

        Ok(container.id)
    }

    pub async fn start_container(&self, container_id: &str) -> Result<()> {
        self.docker.start_container(container_id, None).await?;
        Ok(())
    }

    pub async fn stop_container(&self, container_id: &str) -> Result<()> {
        self.docker.stop_container(container_id, None).await?;
        Ok(())
    }

    pub async fn get_container_logs(&self, container_id: &str) -> Result<String> {
        use bollard::container::LogsOptions;
        use std::time::SystemTime;

        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            since: 0, // Get all logs
            until: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as i64,
            timestamps: true,
            ..Default::default()
        };

        let logs = self.docker.logs(container_id, Some(options)).try_collect().await?;
        Ok(logs.join("\n"))
    }

    pub async fn get_container_stats(&self, container_id: &str) -> Result<ContainerStats> {
        use bollard::container::StatsOptions;

        let mut stats = self.docker.stats(container_id, Some(StatsOptions {
            stream: false,
            ..Default::default()
        }));

        if let Some(stat) = stats.next().await {
            let stat = stat?;
            
            // Calculate CPU usage percentage
            let cpu_delta = stat.cpu_stats.cpu_usage.total_usage as f64 
                - stat.precpu_stats.cpu_usage.total_usage as f64;
            let system_delta = stat.cpu_stats.system_cpu_usage.unwrap_or(0) as f64 
                - stat.precpu_stats.system_cpu_usage.unwrap_or(0) as f64;
            let cpu_usage = if system_delta > 0.0 && cpu_delta > 0.0 {
                (cpu_delta / system_delta) * 100.0 * stat.cpu_stats.online_cpus.unwrap_or(1) as f64
            } else {
                0.0
            };

            Ok(ContainerStats {
                cpu_usage,
                memory_usage: stat.memory_stats.usage.unwrap_or(0),
                network_rx: stat.networks.values()
                    .map(|n| n.rx_bytes)
                    .sum(),
                network_tx: stat.networks.values()
                    .map(|n| n.tx_bytes)
                    .sum(),
            })
        } else {
            Err(anyhow::anyhow!("No stats available for container"))
        }
    }
}
