use anyhow::{Result, Context};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{Pod, PodSpec, Service, ServiceSpec};
use kube::{
    Api, 
    Client, 
    Config, 
    ResourceExt,
    api::{ListParams, PostParams}
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;

/// Kubernetes cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesClusterConfig {
    pub name: String,
    pub context: String,
    pub namespace: String,
    pub kubeconfig_path: PathBuf,
}

/// Kubernetes resource management service
pub struct KubernetesManager {
    client: Client,
    config: KubernetesClusterConfig,
}

/// Deployment configuration for Kubernetes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub name: String,
    pub image: String,
    pub replicas: i32,
    pub ports: Vec<u16>,
    pub environment_vars: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    pub resource_limits: ResourceLimits,
}

/// Resource limits for Kubernetes deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_limit: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_request: Option<String>,
    pub memory_request: Option<String>,
}

/// Helm chart management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmChartConfig {
    pub name: String,
    pub repository: String,
    pub version: String,
    pub values: HashMap<String, serde_json::Value>,
}

impl KubernetesManager {
    /// Create a new Kubernetes manager
    pub async fn new(config: KubernetesClusterConfig) -> Result<Self> {
        // Load kubeconfig
        let kube_config = Config::from_file(&config.kubeconfig_path)
            .context("Failed to load Kubernetes configuration")?;

        // Create Kubernetes client
        let client = Client::try_from(kube_config)
            .context("Failed to create Kubernetes client")?;

        Ok(Self {
            client,
            config,
        })
    }

    /// List all pods in the configured namespace
    pub async fn list_pods(&self) -> Result<Vec<Pod>> {
        let pods: Api<Pod> = Api::namespaced(
            self.client.clone(), 
            &self.config.namespace
        );

        let pod_list = pods.list(&ListParams::default()).await?;
        Ok(pod_list.items)
    }

    /// Create a deployment
    pub async fn create_deployment(&self, deployment_config: &DeploymentConfig) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(
            self.client.clone(), 
            &self.config.namespace
        );

        // Construct Kubernetes deployment
        let deployment = Deployment {
            metadata: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(deployment_config.name.clone()),
                labels: Some(deployment_config.labels.clone()),
                ..Default::default()
            }),
            spec: Some(DeploymentSpec {
                replicas: Some(deployment_config.replicas),
                selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_labels: Some(deployment_config.labels.clone()),
                    ..Default::default()
                },
                template: k8s_openapi::api::core::v1::PodTemplateSpec {
                    metadata: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                        labels: Some(deployment_config.labels.clone()),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![k8s_openapi::api::core::v1::Container {
                            name: deployment_config.name.clone(),
                            image: Some(deployment_config.image.clone()),
                            ports: Some(deployment_config.ports.iter().map(|&port| 
                                k8s_openapi::api::core::v1::ContainerPort {
                                    container_port: port as i32,
                                    ..Default::default()
                                }
                            ).collect()),
                            env: Some(deployment_config.environment_vars.iter().map(|(k, v)| 
                                k8s_openapi::api::core::v1::EnvVar {
                                    name: k.clone(),
                                    value: Some(v.clone()),
                                    ..Default::default()
                                }
                            ).collect()),
                            resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
                                limits: Some(HashMap::from([
                                    (
                                        "cpu".to_string(), 
                                        deployment_config.resource_limits.cpu_limit.clone()
                                    ),
                                    (
                                        "memory".to_string(), 
                                        deployment_config.resource_limits.memory_limit.clone()
                                    )
                                ])),
                                requests: Some(HashMap::from([
                                    (
                                        "cpu".to_string(), 
                                        deployment_config.resource_limits.cpu_request.clone()
                                    ),
                                    (
                                        "memory".to_string(), 
                                        deployment_config.resource_limits.memory_request.clone()
                                    )
                                ])),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create deployment
        deployments.create(&PostParams::default(), &deployment).await?;

        Ok(())
    }

    /// Create a service for a deployment
    pub async fn create_service(&self, deployment_config: &DeploymentConfig) -> Result<()> {
        let services: Api<Service> = Api::namespaced(
            self.client.clone(), 
            &self.config.namespace
        );

        let service = Service {
            metadata: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("{}-service", deployment_config.name)),
                labels: Some(deployment_config.labels.clone()),
                ..Default::default()
            }),
            spec: Some(ServiceSpec {
                selector: Some(deployment_config.labels.clone()),
                ports: Some(deployment_config.ports.iter().map(|&port| 
                    k8s_openapi::api::core::v1::ServicePort {
                        port: port as i32,
                        target_port: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(port as i32)),
                        ..Default::default()
                    }
                ).collect()),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create service
        services.create(&PostParams::default(), &service).await?;

        Ok(())
    }

    /// Deploy Helm chart
    pub async fn deploy_helm_chart(&self, chart_config: &HelmChartConfig) -> Result<()> {
        // Simulate Helm chart deployment
        // In a real implementation, use a Helm library or subprocess
        let helm_command = format!(
            "helm install {} {} --version {} --namespace {} --create-namespace",
            chart_config.name,
            chart_config.repository,
            chart_config.version,
            self.config.namespace
        );

        let output = tokio::process::Command::new("helm")
            .arg("install")
            .arg(&chart_config.name)
            .arg(&chart_config.repository)
            .arg("--version")
            .arg(&chart_config.version)
            .arg("--namespace")
            .arg(&self.config.namespace)
            .arg("--create-namespace")
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Helm chart deployment failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Generate Kubernetes deployment YAML
    pub fn generate_deployment_yaml(deployment_config: &DeploymentConfig) -> Result<String> {
        // Convert deployment config to YAML
        let yaml = serde_yaml::to_string(deployment_config)
            .context("Failed to generate deployment YAML")?;
        Ok(yaml)
    }

    /// Save deployment configuration to file
    pub async fn save_deployment_config(
        &self, 
        deployment_config: &DeploymentConfig, 
        output_path: &PathBuf
    ) -> Result<()> {
        let yaml = Self::generate_deployment_yaml(deployment_config)?;
        fs::write(output_path, yaml).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_deployment_yaml_generation() {
        let deployment_config = DeploymentConfig {
            name: "test-app".to_string(),
            image: "nginx:latest".to_string(),
            replicas: 3,
            ports: vec![80],
            environment_vars: HashMap::from([
                ("ENV".to_string(), "production".to_string())
            ]),
            labels: HashMap::from([
                ("app".to_string(), "test-app".to_string())
            ]),
            resource_limits: ResourceLimits {
                cpu_limit: Some("500m".to_string()),
                memory_limit: Some("512Mi".to_string()),
                cpu_request: Some("250m".to_string()),
                memory_request: Some("256Mi".to_string()),
            },
        };

        let yaml = KubernetesManager::generate_deployment_yaml(&deployment_config).unwrap();
        
        assert!(yaml.contains("test-app"));
        assert!(yaml.contains("nginx:latest"));
        assert!(yaml.contains("replicas: 3"));
    }
}
