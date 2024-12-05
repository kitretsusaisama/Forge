use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevContainer {
    pub name: String,
    pub image: String,
    pub settings: HashMap<String, String>,
    pub extensions: Vec<String>,
    pub features: Vec<String>,
}

impl DevContainer {
    pub fn new(name: String, image: String) -> Self {
        Self {
            name,
            image,
            settings: HashMap::new(),
            extensions: Vec::new(),
            features: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevContainerConfig {
    pub name: String,
    pub image: String,
    pub settings: HashMap<String, String>,
    pub extensions: Vec<String>,
    pub features: Vec<String>,
    pub mount_points: Vec<MountPoint>,
    pub environment: HashMap<String, String>,
    pub forward_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountPoint {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

impl DevContainerConfig {
    pub fn new(name: String, image: String) -> Self {
        Self {
            name,
            image,
            settings: HashMap::new(),
            extensions: Vec::new(),
            features: Vec::new(),
            mount_points: Vec::new(),
            environment: HashMap::new(),
            forward_ports: Vec::new(),
        }
    }
}
