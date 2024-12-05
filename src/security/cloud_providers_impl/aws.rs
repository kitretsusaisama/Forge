use async_trait::async_trait;
use anyhow::{Result, Context, anyhow};
use std::collections::HashMap;

use aws_config::SdkConfig;
use aws_sdk_secretsmanager::{
    Client,
    config::Region,
    operation::{
        create_secret::CreateSecretInput,
        get_secret_value::GetSecretValueInput,
        put_secret_value::PutSecretValueInput,
        delete_secret::DeleteSecretInput,
    },
};
use crate::security::prelude::*;
use crate::security::cloud_providers::CloudProviderConfig;

use crate::security::cloud_providers::{
    CloudSecretProvider, 
    CloudProviderCredentials,
    CloudProviderType,
};

use super::utils;
use super::rotation_policy::{KeyRotationScheduler, KeyRotationPolicy};

/// AWS Secrets Manager Secret Provider
pub struct AwsSecretProvider {
    /// AWS Secrets Manager client
    client: aws_sdk_secretsmanager::Client,

    /// Cloud provider configuration
    config: CloudProviderConfig,

    /// Key rotation scheduler
    rotation_scheduler: KeyRotationScheduler,

    /// Encryption key for additional security
    encryption_key: Vec<u8>,
}

#[async_trait]
impl CloudSecretProvider for AwsSecretProvider {
    /// Initialize AWS Secret Provider
    async fn new(config: &CloudProviderConfig) -> Result<Self> {
        // Validate AWS-specific configuration
        let sdk_config = aws_config::from_env()
            .region(Region::new(config.region.clone().unwrap_or_else(|| "us-east-1".to_string())))
            .load()
            .await
            .context("Failed to load AWS SDK configuration")?;

        let client = Client::new(&sdk_config);

        // Generate initial encryption key
        let encryption_key = vec![0; 32];  // 256-bit key placeholder

        // Initialize key rotation scheduler
        let initial_key_id = format!("aws_key_{}", uuid::Uuid::new_v4());
        let rotation_scheduler = KeyRotationScheduler::new(
            Some(KeyRotationPolicy::default()), 
            initial_key_id
        );

        Ok(Self {
            client,
            config: config.clone(),
            rotation_scheduler,
            encryption_key,
        })
    }

    /// Store a secret in AWS Secrets Manager
    async fn store_secret(
        &self, 
        key: &str, 
        value: &[u8], 
        metadata: Option<HashMap<String, String>>
    ) -> Result<String> {
        // Validate secret
        utils::validate_secret(value)?;

        // Encrypt secret before storage
        let encrypted_secret = utils::encrypt_secret(value, &self.encryption_key)?;

        // Prepare metadata
        let mut secret_metadata = utils::generate_secret_metadata();
        if let Some(additional_meta) = metadata {
            secret_metadata.extend(additional_meta);
        }

        // Convert metadata to JSON string
        let metadata_json = serde_json::to_string(&secret_metadata)?;

        // Create secret request
        let request = CreateSecretInput::builder()
            .name(key)
            .description("Forge Development Environment Secret")
            .secret_binary(encrypted_secret)
            .tags(vec![
                aws_sdk_secretsmanager::types::Tag::builder()
                    .key("managed_by")
                    .value("forge_dev_env")
                    .build()?
            ])
            .build()?;

        // Send request to AWS Secrets Manager
        let response = self.client
            .create_secret()
            .set_input(request)
            .send()
            .await
            .context("Failed to create secret in AWS Secrets Manager")?;

        // Return secret ARN
        response.arn()
            .map(|arn| arn.to_string())
            .context("No ARN returned for created secret")
    }

    /// Retrieve a secret from AWS Secrets Manager
    async fn retrieve_secret(&self, secret_id: &str) -> Result<Vec<u8>> {
        // Retrieve secret
        let request = GetSecretValueInput::builder()
            .secret_id(secret_id)
            .build()?;

        let response = self.client
            .get_secret_value()
            .set_input(request)
            .send()
            .await
            .context("Failed to retrieve secret from AWS Secrets Manager")?;

        // Extract secret string
        let encrypted_secret = response.secret_binary()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| anyhow!("No binary secret found"))?;

        // Decrypt secret
        utils::decrypt_secret(encrypted_secret, &self.encryption_key)
    }

    /// Update an existing secret in AWS Secrets Manager
    async fn update_secret(
        &self, 
        secret_id: &str, 
        value: &[u8], 
        metadata: Option<HashMap<String, String>>
    ) -> Result<()> {
        // Validate secret
        utils::validate_secret(value)?;

        // Encrypt secret before update
        let encrypted_secret = utils::encrypt_secret(value, &self.encryption_key)?;

        // Prepare metadata
        let mut secret_metadata = utils::generate_secret_metadata();
        if let Some(additional_meta) = metadata {
            secret_metadata.extend(additional_meta);
        }

        // Create update request
        let request = PutSecretValueInput::builder()
            .secret_id(secret_id)
            .secret_binary(encrypted_secret)
            .build()?;

        // Send update request
        self.client
            .put_secret_value()
            .set_input(request)
            .send()
            .await
            .context("Failed to update secret in AWS Secrets Manager")?;

        Ok(())
    }

    /// Delete a secret from AWS Secrets Manager
    async fn delete_secret(&self, secret_id: &str) -> Result<()> {
        // Create delete request
        let request = DeleteSecretInput::builder()
            .secret_id(secret_id)
            .force_delete_without_recovery(true)
            .build()?;

        // Send delete request
        self.client
            .delete_secret()
            .set_input(request)
            .send()
            .await
            .context("Failed to delete secret from AWS Secrets Manager")?;

        Ok(())
    }

    /// List all secret identifiers in AWS Secrets Manager
    async fn list_secrets(&self) -> Result<Vec<String>> {
        // Note: This is a simplified implementation
        // AWS SDK requires pagination for large number of secrets
        let secrets = self.client
            .list_secrets()
            .send()
            .await
            .context("Failed to list secrets")?;

        Ok(secrets
            .secret_list()
            .iter()
            .filter_map(|secret| secret.name().map(|name| name.to_string()))
            .collect())
    }

    /// Rotate a secret in AWS Secrets Manager
    async fn rotate_secret(&self, secret_id: &str) -> Result<String> {
        // Check if rotation is recommended
        if !self.rotation_scheduler.is_rotation_recommended() {
            return Ok(self.rotation_scheduler.current_key_id().to_string());
        }

        // Retrieve current secret
        let current_secret = self.retrieve_secret(secret_id)?;

        // Generate new secret
        let new_secret = vec![0; current_secret.len()];  // Placeholder for new secret generation

        // Store new secret
        let new_secret_id = self.store_secret(
            &format!("{}_rotated", secret_id), 
            &new_secret, 
            None
        ).await?;

        // Update rotation scheduler
        let mut rotation_scheduler = self.rotation_scheduler.clone();
        rotation_scheduler.record_rotation(new_secret_id.clone());

        Ok(new_secret_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    #[ignore]  // Requires AWS credentials
    async fn test_aws_secret_provider() {
        let config = CloudProviderConfig {
            provider_id: uuid::Uuid::new_v4(),
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

        let provider = AwsSecretProvider::new(&config).await.unwrap();

        // Test secret storage and retrieval
        let secret_key = "test_secret";
        let secret_value = b"top_secret_data";

        let secret_id = provider.store_secret(
            secret_key, 
            secret_value, 
            None
        ).await.unwrap();

        let retrieved_secret = provider.retrieve_secret(&secret_id).await.unwrap();
        assert_eq!(secret_value, retrieved_secret.as_slice());
    }
}
