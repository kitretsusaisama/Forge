use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use secrecy::{Secret, ExposeSecret};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use dotenv;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json;
use base64;

mod encryption;
mod audit;

use crate::security::encryption::SecretEncryptionManager;
use crate::security::audit::{SecretAuditLogger, SecretOperation};

/// Secret management with encryption and audit logging
pub struct SecretsManager {
    base_dir: PathBuf,
    secrets_path: PathBuf,
    encryption: SecretEncryptionManager,
    audit: SecretAuditLogger,
    secrets: Arc<RwLock<HashMap<String, Secret<String>>>>,
}

impl SecretsManager {
    /// Create a new secrets manager
    pub async fn new(base_dir: &Path) -> Result<Self> {
        let secrets_path = base_dir.join("secrets.json");
        let encryption_manager = SecretEncryptionManager::new(base_dir).await?;
        let audit_logger = SecretAuditLogger::new(base_dir).await?;

        let mut secrets_manager = Self {
            base_dir: base_dir.to_path_buf(),
            secrets_path,
            encryption: encryption_manager,
            audit: audit_logger,
            secrets: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing secrets or initialize
        secrets_manager.load_secrets().await?;

        Ok(secrets_manager)
    }

    /// Load secrets from file or initialize
    async fn load_secrets(&mut self) -> Result<()> {
        if self.secrets_path.exists() {
            let secrets_json = std::fs::read_to_string(&self.secrets_path)?;
            let encrypted_secrets: HashMap<String, String> = 
                serde_json::from_str(&secrets_json)?;

            // Decrypt each secret
            for (key, encrypted_value) in encrypted_secrets {
                let decrypted_value = self.encryption.decrypt(&encrypted_value).await?;
                self.secrets.write().await.insert(
                    key.clone(), 
                    Secret::new(decrypted_value)
                );
            }
        }

        Ok(())
    }

    /// Save secrets to encrypted file
    async fn save_secrets(&self) -> Result<()> {
        let mut encrypted_secrets = HashMap::new();

        for (key, secret) in self.secrets.read().await.iter() {
            let encrypted_value = self.encryption.encrypt(secret.expose_secret()).await?;
            encrypted_secrets.insert(key.clone(), encrypted_value);
        }

        let secrets_json = serde_json::to_string_pretty(&encrypted_secrets)?;
        std::fs::write(&self.secrets_path, secrets_json)?;

        Ok(())
    }

    /// Set a secret value
    pub async fn set_secret(&mut self, key: &str, value: &str) -> Result<()> {
        // Encrypt and store secret
        let secret = Secret::new(value.to_string());
        self.secrets.write().await.insert(key.to_string(), secret);

        // Save updated secrets
        self.save_secrets().await?;

        // Log secret creation
        self.audit.log_secret_operation(
            SecretOperation::Create, 
            key, 
            None,  // No user context in this method
            true, 
            None
        ).await?;

        Ok(())
    }

    /// Get a secret value
    pub async fn get_secret(&self, key: &str) -> Option<&Secret<String>> {
        // Log secret read attempt
        self.audit.log_secret_operation(
            SecretOperation::Read, 
            key, 
            None,  // No user context in this method
            self.secrets.read().await.contains_key(key), 
            None
        ).await.ok();

        self.secrets.read().await.get(key)
    }

    /// Rotate a specific secret
    pub async fn rotate_secret(&mut self, key: &str) -> Result<()> {
        // Generate new random secret
        let mut new_secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut new_secret_bytes);
        let new_secret = base64::encode(new_secret_bytes);

        // Update secret
        self.set_secret(key, &new_secret).await?;

        // Log secret rotation
        self.audit.log_secret_operation(
            SecretOperation::Rotate, 
            key, 
            None,  // No user context in this method
            true, 
            Some("Secret rotated".to_string())
        ).await?;

        Ok(())
    }

    /// Load environment variables from .env file
    pub async fn load_env(&self) -> Result<()> {
        let env_path = self.base_dir.join(".env");
        if env_path.exists() {
            dotenv::from_path(&env_path)
                .context("Failed to load .env file")?;
        }
        Ok(())
    }

    /// Initialize default secrets if not exists
    pub async fn init_secrets(&mut self) -> Result<()> {
        // Generate default secrets if not exists
        let default_secrets = vec![
            ("FORGE_SECRET_KEY", "Generate a long random key"),
            ("FORGE_ENCRYPTION_KEY", "Generate another long random key"),
        ];

        for (key, default_value) in default_secrets {
            if !self.secrets.read().await.contains_key(key) {
                // Generate a secure random secret
                let mut secret_bytes = [0u8; 64];
                OsRng.fill_bytes(&mut secret_bytes);
                let secret = base64::encode(secret_bytes);

                self.set_secret(key, &secret).await?;
            }
        }

        Ok(())
    }

    /// Validate critical secrets
    pub async fn validate_secrets(&self) -> Result<()> {
        let critical_secrets = vec![
            "FORGE_SECRET_KEY",
            "FORGE_ENCRYPTION_KEY",
        ];

        for key in critical_secrets {
            if self.get_secret(key).await.is_none() {
                return Err(anyhow::anyhow!(
                    "Critical secret '{}' is missing", key
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_secret_management() {
        let temp_dir = tempdir().unwrap();
        let mut secrets_manager = SecretsManager::new(temp_dir.path()).await.unwrap();

        // Set and retrieve a secret
        secrets_manager.set_secret("TEST_SECRET", "super_secret_value").await.unwrap();
        let retrieved_secret = secrets_manager.get_secret("TEST_SECRET").await.unwrap();
        assert_eq!(retrieved_secret.expose_secret(), "super_secret_value");

        // Rotate secret
        secrets_manager.rotate_secret("TEST_SECRET").await.unwrap();
        let rotated_secret = secrets_manager.get_secret("TEST_SECRET").await.unwrap();
        assert_ne!(rotated_secret.expose_secret(), "super_secret_value");
    }

    #[tokio::test]
    async fn test_secret_initialization() {
        let temp_dir = tempdir().unwrap();
        let mut secrets_manager = SecretsManager::new(temp_dir.path()).await.unwrap();

        // Initialize secrets
        secrets_manager.init_secrets().await.unwrap();

        // Validate critical secrets exist
        secrets_manager.validate_secrets().await.unwrap();
    }
}
