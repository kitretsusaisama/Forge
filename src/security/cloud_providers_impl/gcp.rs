use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::security::cloud_providers::CloudProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpCloudProvider {
    project_id: String,
    credentials_path: Option<String>,
}

#[async_trait]
impl CloudProvider for GcpCloudProvider {
    async fn store_secret(&self, key: &str, value: &[u8]) -> Result<()> {
        // TODO: Implement GCP Secret Manager integration
        Ok(())
    }

    async fn retrieve_secret(&self, key: &str) -> Result<Vec<u8>> {
        // TODO: Implement GCP Secret Manager integration
        Ok(Vec::new())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        // TODO: Implement GCP Secret Manager integration
        Ok(())
    }
}

impl GcpCloudProvider {
    pub fn new(project_id: String, credentials_path: Option<String>) -> Self {
        Self {
            project_id,
            credentials_path,
        }
    }
}
