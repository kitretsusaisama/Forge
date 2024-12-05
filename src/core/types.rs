use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub env_type: EnvironmentType,
    pub status: EnvironmentStatus,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvironmentType {
    DevContainer,
    Nix,
    Flox,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvironmentStatus {
    Creating,
    Running,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub memory_mb: usize,
    pub cpu_cores: f32,
    pub storage_gb: usize,
}
