use async_trait::async_trait;
use anyhow::{Result, Context};
use std::collections::HashMap;
use std::path::Path;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use async_trait::async_trait;
use std::path::PathBuf;
use crate::core::error::ForgeError;

/// Cloud provider authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudProviderCredentials {
    /// OAuth 2.0 credentials
    OAuth {
        client_id: String,
        client_secret: String,
        token_url: String,
    },
    
    /// Service account key authentication
    ServiceAccount {
        key_path: String,
        project_id: Option<String>,
    },
    
    /// API Key authentication
    ApiKey {
        api_key: String,
        api_key_prefix: Option<String>,
    },
    
    /// AWS IAM Role-based authentication
    IamRole {
        role_arn: String,
        external_id: Option<String>,
    },
}

/// Cloud provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderConfig {
    /// Unique provider identifier
    pub provider_id: Uuid,
    
    /// Provider type
    pub provider_type: CloudProviderType,
    
    /// Authentication credentials
    pub credentials: CloudProviderCredentials,
    
    /// Endpoint configuration
    pub endpoint: String,
    
    /// Region or location
    pub region: Option<String>,
    
    /// Additional configuration options
    pub options: HashMap<String, String>,
}

/// Supported cloud provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CloudProviderType {
    AWS,
    GCP,
    Azure,
    DigitalOcean,
    Heroku,
    Custom(String),
}

#[derive(Debug, Clone)]
pub enum CloudProviderTypeTrait {
    AWS,
    GCP,
    Azure,
}

#[async_trait]
pub trait CloudProvider: Send + Sync {
    async fn upload_file(&self, local_path: PathBuf, remote_path: &str) -> Result<String, ForgeError>;
    
    async fn download_file(&self, remote_path: &str, local_path: PathBuf) -> Result<(), ForgeError>;
    
    async fn list_files(&self, prefix: &str) -> Result<Vec<String>, ForgeError>;
    
    async fn delete_file(&self, remote_path: &str) -> Result<(), ForgeError>;
    
    async fn get_signed_url(&self, remote_path: &str, expiry_seconds: u64) -> Result<String, ForgeError>;
}

/// Abstract cloud secret management interface
#[async_trait]
pub trait CloudSecretProvider: Send + Sync {
    /// Store a secret
    async fn store_secret(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Retrieve a secret
    async fn retrieve_secret(&self, key: &str) -> Result<Vec<u8>>;

    /// Update a secret
    async fn update_secret(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Delete a secret
    async fn delete_secret(&self, key: &str) -> Result<()>;

    /// List secrets
    async fn list_secrets(&self) -> Result<Vec<String>>;

    /// Rotate a secret
    async fn rotate_secret(&self, key: &str) -> Result<String>;
}

#[async_trait]
pub trait AsyncCloudSecretProvider: Send + Sync + 'static {
    /// Store a secret
    async fn store_secret(
        &self, 
        secret_id: &str, 
        value: &[u8], 
        metadata: Option<&str>
    ) -> Result<String>;

    /// Retrieve a secret
    async fn retrieve_secret(&self, secret_id: &str) -> Result<Vec<u8>>;

    /// Update a secret
    async fn update_secret(&self, secret_id: &str, value: &[u8], metadata: Option<&str>) -> Result<()>;

    /// Delete a secret
    async fn delete_secret(&self, secret_id: &str) -> Result<()>;

    /// List secrets
    async fn list_secrets(&self) -> Result<Vec<String>>;

    /// Rotate a secret
    async fn rotate_secret(&self, secret_id: &str) -> Result<String>;
}

/// Cloud provider factory for creating secret providers
pub struct CloudProviderFactory;

impl CloudProviderFactory {
    /// Create a cloud secret provider based on configuration
    pub async fn create_provider(
        config: &CloudProviderConfig
    ) -> Result<Box<dyn CloudSecretProvider + AsyncCloudSecretProvider>> {
        match config.provider_type {
            CloudProviderType::AWS => {
                #[cfg(feature = "aws-provider")]
                {
                    use crate::security::cloud_providers_impl::aws::AwsSecretProvider;
                    Ok(Box::new(AwsSecretProvider::new(config).await?))
                }
                #[cfg(not(feature = "aws-provider"))]
                {
                    Err(anyhow::anyhow!("AWS provider support not compiled"))
                }
            },
            CloudProviderType::GCP => {
                #[cfg(feature = "gcp-provider")]
                {
                    use crate::security::cloud_providers_impl::gcp::GcpSecretProvider;
                    Ok(Box::new(GcpSecretProvider::new(config).await?))
                }
                #[cfg(not(feature = "gcp-provider"))]
                {
                    Err(anyhow::anyhow!("GCP provider support not compiled"))
                }
            },
            CloudProviderType::Azure => {
                #[cfg(feature = "azure-provider")]
                {
                    use crate::security::cloud_providers_impl::azure::AzureSecretProvider;
                    Ok(Box::new(AzureSecretProvider::new(config).await?))
                }
                #[cfg(not(feature = "azure-provider"))]
                {
                    Err(anyhow::anyhow!("Azure provider support not compiled"))
                }
            },
            CloudProviderType::Custom(ref provider) => {
                // Future extensibility for custom providers
                Err(anyhow::anyhow!("Custom provider '{}' not implemented", provider))
            },
            _ => Err(anyhow::anyhow!("Unsupported cloud provider")),
        }
    }
}

/// Encryption key management for cloud secrets
pub struct CloudKeyManager {
    base_dir: std::path::PathBuf,
}

impl CloudKeyManager {
    /// Create a new key manager
    pub fn new(base_dir: &Path) -> Result<Self> {
        let base_dir = base_dir.join("cloud_keys");
        std::fs::create_dir_all(&base_dir)?;

        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Generate a new encryption key
    pub fn generate_key(&self, provider: &CloudProviderType) -> Result<Vec<u8>> {
        use rand::RngCore;
        use aes_gcm::KeyInit;

        // Generate a 256-bit key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        // Create key identifier
        let key_id = self.create_key_identifier(provider);
        let key_path = self.base_dir.join(format!("{}.key", key_id));

        // Securely store the key
        self.store_key(&key_path, &key)?;

        Ok(key.to_vec())
    }

    /// Create a unique key identifier
    fn create_key_identifier(&self, provider: &CloudProviderType) -> String {
        let timestamp = chrono::Utc::now().timestamp();
        let provider_prefix = match provider {
            CloudProviderType::AWS => "aws",
            CloudProviderType::GCP => "gcp",
            CloudProviderType::Azure => "azure",
            _ => "custom",
        };
        
        format!("{}_{}_{}", provider_prefix, timestamp, Uuid::new_v4())
    }

    /// Securely store an encryption key
    fn store_key(&self, path: &Path, key: &[u8]) -> Result<()> {
        // Ensure restrictive permissions
        #[cfg(target_os = "windows")]
        {
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(path, perms)?;
        }

        #[cfg(target_os = "unix")]
        {
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            std::fs::set_permissions(path, perms)?;
        }

        std::fs::write(path, key)?;

        Ok(())
    }

    /// Retrieve a stored encryption key
    pub fn retrieve_key(&self, key_identifier: &str) -> Result<Vec<u8>> {
        let key_path = self.base_dir.join(format!("{}.key", key_identifier));
        
        if !key_path.exists() {
            return Err(anyhow::anyhow!("Encryption key not found"));
        }

        std::fs::read(key_path)
            .context("Failed to read encryption key")
    }

    /// Rotate encryption key for a specific provider
    pub fn rotate_key(&self, provider: &CloudProviderType) -> Result<String> {
        // Generate new key
        let new_key = self.generate_key(provider)?;
        
        // Create key identifier
        let key_id = self.create_key_identifier(provider);

        Ok(key_id)
    }

    /// List all stored key identifiers
    pub fn list_keys(&self) -> Result<Vec<String>> {
        std::fs::read_dir(&self.base_dir)?
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    e.file_name()
                     .into_string()
                     .ok()
                     .filter(|name| name.ends_with(".key"))
                     .map(|name| name.trim_end_matches(".key").to_string())
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cloud_provider_config() {
        let config = CloudProviderConfig {
            provider_id: Uuid::new_v4(),
            provider_type: CloudProviderType::AWS,
            credentials: CloudProviderCredentials::OAuth {
                client_id: "test_client".to_string(),
                client_secret: "test_secret".to_string(),
                token_url: "https://oauth.aws.example.com/token".to_string(),
            },
            endpoint: "https://secretsmanager.aws.example.com".to_string(),
            region: Some("us-west-2".to_string()),
            options: HashMap::new(),
        };

        assert_eq!(config.provider_type, CloudProviderType::AWS);
    }

    #[tokio::test]
    async fn test_key_management() {
        let temp_dir = tempdir().unwrap();
        let key_manager = CloudKeyManager::new(temp_dir.path()).unwrap();

        // Generate key
        let key = key_manager.generate_key(&CloudProviderType::AWS).unwrap();
        assert_eq!(key.len(), 32);

        // List keys
        let keys = key_manager.list_keys().unwrap();
        assert_eq!(keys.len(), 1);

        // Retrieve key
        let retrieved_key = key_manager.retrieve_key(&keys[0]).unwrap();
        assert_eq!(key, retrieved_key);
    }
}
