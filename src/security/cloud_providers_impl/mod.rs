// Cloud provider implementation module
pub mod aws;
pub mod gcp;
pub mod azure;

// Re-export provider implementations
pub use aws::AwsSecretProvider;
pub use gcp::GcpSecretProvider;
pub use azure::AzureSecretProvider;

// Shared utilities for cloud providers
pub mod utils {
    use anyhow::{Result, Context};
    use std::collections::HashMap;
    use base64::{engine::general_purpose, Engine as _};
    use aes_gcm::{
        Aes256Gcm, 
        Key, 
        Nonce
    };
    use rand::RngCore;

    /// Encrypt secret before cloud transmission
    pub fn encrypt_secret(
        secret: &[u8], 
        encryption_key: &[u8]
    ) -> Result<String> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Create key and nonce
        let key = Key::<Aes256Gcm>::from_slice(encryption_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Perform encryption
        let cipher = Aes256Gcm::new(key);
        let encrypted_data = cipher.encrypt(nonce, secret)
            .context("Failed to encrypt secret")?;

        // Combine nonce and encrypted data, then base64 encode
        let mut combined_data = nonce_bytes.to_vec();
        combined_data.extend_from_slice(&encrypted_data);

        Ok(general_purpose::STANDARD.encode(&combined_data))
    }

    /// Decrypt secret after cloud retrieval
    pub fn decrypt_secret(
        encrypted_secret: &str, 
        encryption_key: &[u8]
    ) -> Result<Vec<u8>> {
        // Decode base64 
        let decoded_data = general_purpose::STANDARD
            .decode(encrypted_secret)
            .context("Failed to decode base64 secret")?;

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = decoded_data.split_at(12);

        // Create key and nonce
        let key = Key::<Aes256Gcm>::from_slice(encryption_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Perform decryption
        let cipher = Aes256Gcm::new(key);
        let decrypted_data = cipher.decrypt(nonce, ciphertext)
            .context("Failed to decrypt secret")?;

        Ok(decrypted_data)
    }

    /// Generate metadata for secret tracking
    pub fn generate_secret_metadata() -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert(
            "created_at".to_string(), 
            chrono::Utc::now().to_rfc3339()
        );
        metadata.insert(
            "source".to_string(), 
            "forge_dev_env".to_string()
        );
        metadata
    }

    /// Validate secret before transmission
    pub fn validate_secret(secret: &[u8]) -> Result<()> {
        // Basic validation checks
        if secret.is_empty() {
            return Err(anyhow::anyhow!("Secret cannot be empty"));
        }

        if secret.len() > 65536 {  // 64KB limit
            return Err(anyhow::anyhow!("Secret exceeds maximum size"));
        }

        Ok(())
    }
}

// Advanced key rotation policy
pub mod rotation_policy {
    use chrono::{DateTime, Utc, Duration};
    use serde::{Serialize, Deserialize};

    /// Key rotation policy configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeyRotationPolicy {
        /// Maximum age of a key before mandatory rotation
        pub max_key_age_days: u32,

        /// Minimum key rotation interval
        pub min_rotation_interval_days: u32,

        /// Number of previous keys to retain
        pub retained_key_versions: u8,

        /// Automatic rotation enabled
        pub auto_rotate: bool,
    }

    impl Default for KeyRotationPolicy {
        fn default() -> Self {
            Self {
                max_key_age_days: 90,
                min_rotation_interval_days: 30,
                retained_key_versions: 3,
                auto_rotate: true,
            }
        }
    }

    /// Key rotation status tracker
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeyRotationStatus {
        /// Current key identifier
        pub current_key_id: String,

        /// Timestamp of last key rotation
        pub last_rotation_time: DateTime<Utc>,

        /// List of previous key identifiers
        pub previous_key_ids: Vec<String>,
    }

    impl KeyRotationStatus {
        /// Check if key needs rotation based on policy
        pub fn needs_rotation(
            &self, 
            policy: &KeyRotationPolicy
        ) -> bool {
            let now = Utc::now();
            let key_age = now - self.last_rotation_time;

            // Check if key exceeds maximum age
            key_age > Duration::days(policy.max_key_age_days as i64)
        }

        /// Record a new key rotation
        pub fn record_rotation(
            &mut self, 
            new_key_id: String,
            policy: &KeyRotationPolicy
        ) {
            // Add current key to previous keys
            self.previous_key_ids.push(self.current_key_id.clone());

            // Limit number of retained keys
            if self.previous_key_ids.len() > policy.retained_key_versions as usize {
                self.previous_key_ids.remove(0);
            }

            // Update current key
            self.current_key_id = new_key_id;
            self.last_rotation_time = Utc::now();
        }
    }

    /// Key rotation scheduler
    #[derive(Clone)]
    pub struct KeyRotationScheduler {
        policy: KeyRotationPolicy,
        status: KeyRotationStatus,
    }

    impl KeyRotationScheduler {
        /// Create a new rotation scheduler
        pub fn new(
            policy: Option<KeyRotationPolicy>, 
            initial_key_id: String
        ) -> Self {
            Self {
                policy: policy.unwrap_or_default(),
                status: KeyRotationStatus {
                    current_key_id: initial_key_id,
                    last_rotation_time: Utc::now(),
                    previous_key_ids: Vec::new(),
                },
            }
        }

        /// Determine if key rotation is recommended
        pub fn is_rotation_recommended(&self) -> bool {
            self.policy.auto_rotate && 
            self.status.needs_rotation(&self.policy)
        }

        /// Get current key identifier
        pub fn current_key_id(&self) -> &str {
            &self.status.current_key_id
        }

        /// Record a key rotation
        pub fn record_rotation(&mut self, new_key_id: String) {
            self.status.record_rotation(new_key_id, &self.policy);
        }

        /// Get rotation status
        pub fn get_status(&self) -> &KeyRotationStatus {
            &self.status
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secret_encryption_decryption() {
        let secret = b"top_secret_data";
        let key = vec![0; 32];  // 256-bit key

        let encrypted = utils::encrypt_secret(secret, &key).unwrap();
        let decrypted = utils::decrypt_secret(&encrypted, &key).unwrap();

        assert_eq!(secret, decrypted.as_slice());
    }

    #[test]
    fn test_key_rotation_policy() {
        let initial_key_id = "key_v1".to_string();
        let mut scheduler = rotation_policy::KeyRotationScheduler::new(
            None, 
            initial_key_id.clone()
        );

        assert_eq!(scheduler.current_key_id(), &initial_key_id);
        
        // Simulate key rotation
        let new_key_id = "key_v2".to_string();
        scheduler.record_rotation(new_key_id.clone());

        assert_eq!(scheduler.current_key_id(), &new_key_id);
        assert_eq!(
            scheduler.get_status().previous_key_ids, 
            vec![initial_key_id]
        );
    }
}
