use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use uuid::Uuid;
use aes_gcm::{
    Aes256Gcm, 
    Key, 
    Nonce
};
use aes_gcm::aead::{Aead, NewAead};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::pbkdf2;
use std::num::NonZeroU32;

/// Secrets Management Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsManagerConfig {
    /// Base directory for storing encrypted secrets
    pub secrets_dir: PathBuf,

    /// Encryption key derivation iterations
    pub key_iterations: u32,

    /// Maximum secret size
    pub max_secret_size: usize,
}

/// Secret Entry Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Unique secret identifier
    pub id: Uuid,

    /// Secret name/key
    pub name: String,

    /// Encrypted secret value
    pub encrypted_value: String,

    /// Metadata about the secret
    pub metadata: HashMap<String, String>,
}

/// Secrets Manager
pub struct SecretsManager {
    /// Configuration
    config: SecretsManagerConfig,
}

impl SecretsManager {
    /// Create a new secrets manager
    pub fn new(config: SecretsManagerConfig) -> Result<Self> {
        // Ensure secrets directory exists
        fs::create_dir_all(&config.secrets_dir)?;

        Ok(Self { config })
    }

    /// Derive encryption key from master password
    fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256, 
            NonZeroU32::new(10000).unwrap(), 
            salt, 
            password.as_bytes(), 
            &mut key
        );
        Key::from(key)
    }

    /// Encrypt a secret
    pub fn encrypt_secret(
        &self, 
        name: &str, 
        value: &str, 
        master_password: &str
    ) -> Result<SecretEntry> {
        // Validate secret size
        if value.len() > self.config.max_secret_size {
            return Err(anyhow::anyhow!("Secret exceeds maximum size"));
        }

        // Generate unique salt and nonce
        let salt = uuid::Uuid::new_v4().as_bytes().to_vec();
        let nonce = uuid::Uuid::new_v4().as_bytes()[..12].to_vec();

        // Derive encryption key
        let key = Self::derive_key(master_password, &salt);
        let cipher = Aes256Gcm::new(&key);

        // Encrypt secret
        let encrypted_bytes = cipher.encrypt(
            Nonce::from_slice(&nonce), 
            value.as_bytes()
        ).context("Encryption failed")?;

        // Encode encrypted data
        let encrypted_value = BASE64.encode(&encrypted_bytes);

        // Create secret entry
        let secret_entry = SecretEntry {
            id: Uuid::new_v4(),
            name: name.to_string(),
            encrypted_value,
            metadata: HashMap::from([
                ("salt".to_string(), BASE64.encode(&salt)),
                ("nonce".to_string(), BASE64.encode(&nonce)),
            ]),
        };

        // Save encrypted secret
        self.save_secret(&secret_entry)?;

        Ok(secret_entry)
    }

    /// Decrypt a secret
    pub fn decrypt_secret(
        &self, 
        secret_entry: &SecretEntry, 
        master_password: &str
    ) -> Result<String> {
        // Decode salt and nonce
        let salt = BASE64.decode(
            secret_entry.metadata
                .get("salt")
                .context("Salt not found")?
        )?;

        let nonce = BASE64.decode(
            secret_entry.metadata
                .get("nonce")
                .context("Nonce not found")?
        )?;

        // Derive encryption key
        let key = Self::derive_key(master_password, &salt);
        let cipher = Aes256Gcm::new(&key);

        // Decode and decrypt secret
        let encrypted_bytes = BASE64.decode(&secret_entry.encrypted_value)?;
        let decrypted_bytes = cipher.decrypt(
            Nonce::from_slice(&nonce), 
            encrypted_bytes.as_slice()
        ).context("Decryption failed")?;

        // Convert to string
        let decrypted_value = String::from_utf8(decrypted_bytes)
            .context("Invalid UTF-8 secret")?;

        Ok(decrypted_value)
    }

    /// Save secret to file
    fn save_secret(&self, secret: &SecretEntry) -> Result<()> {
        let secret_path = self.config.secrets_dir
            .join(format!("{}.json", secret.id));

        let secret_json = serde_json::to_string_pretty(secret)?;
        fs::write(secret_path, secret_json)?;

        Ok(())
    }

    /// List all secrets
    pub fn list_secrets(&self) -> Result<Vec<SecretEntry>> {
        let mut secrets = Vec::new();

        for entry in fs::read_dir(&self.config.secrets_dir)? {
            let entry = entry?;
            if entry.path().extension().map_or(false, |ext| ext == "json") {
                let secret_json = fs::read_to_string(entry.path())?;
                let secret: SecretEntry = serde_json::from_str(&secret_json)?;
                secrets.push(secret);
            }
        }

        Ok(secrets)
    }

    /// Delete a secret
    pub fn delete_secret(&self, secret_id: &Uuid) -> Result<()> {
        let secret_path = self.config.secrets_dir
            .join(format!("{}.json", secret_id));

        if secret_path.exists() {
            fs::remove_file(secret_path)?;
        }

        Ok(())
    }

    /// Update a secret
    pub fn update_secret(
        &self, 
        secret_id: &Uuid, 
        new_value: &str, 
        master_password: &str
    ) -> Result<SecretEntry> {
        // Find existing secret
        let mut existing_secrets = self.list_secrets()?;
        let secret_index = existing_secrets
            .iter()
            .position(|s| &s.id == secret_id)
            .context("Secret not found")?;

        let existing_secret = &existing_secrets[secret_index];

        // Delete old secret
        self.delete_secret(secret_id)?;

        // Re-encrypt with new value
        let updated_secret = self.encrypt_secret(
            &existing_secret.name, 
            new_value, 
            master_password
        )?;

        Ok(updated_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secret_encryption_decryption() {
        let temp_dir = tempdir().unwrap();
        let config = SecretsManagerConfig {
            secrets_dir: temp_dir.path().to_path_buf(),
            key_iterations: 10000,
            max_secret_size: 1024,
        };

        let secrets_manager = SecretsManager::new(config).unwrap();

        // Master password
        let master_password = "super_secure_password";

        // Encrypt secret
        let secret_entry = secrets_manager
            .encrypt_secret(
                "test_api_key", 
                "my_super_secret_key", 
                master_password
            )
            .unwrap();

        // Decrypt secret
        let decrypted_value = secrets_manager
            .decrypt_secret(&secret_entry, master_password)
            .unwrap();

        assert_eq!(decrypted_value, "my_super_secret_key");
    }

    #[test]
    fn test_secret_update() {
        let temp_dir = tempdir().unwrap();
        let config = SecretsManagerConfig {
            secrets_dir: temp_dir.path().to_path_buf(),
            key_iterations: 10000,
            max_secret_size: 1024,
        };

        let secrets_manager = SecretsManager::new(config).unwrap();
        let master_password = "super_secure_password";

        // Create initial secret
        let initial_secret = secrets_manager
            .encrypt_secret(
                "test_api_key", 
                "initial_key", 
                master_password
            )
            .unwrap();

        // Update secret
        let updated_secret = secrets_manager
            .update_secret(
                &initial_secret.id, 
                "updated_key", 
                master_password
            )
            .unwrap();

        // Verify updated secret
        let decrypted_value = secrets_manager
            .decrypt_secret(&updated_secret, master_password)
            .unwrap();

        assert_eq!(decrypted_value, "updated_key");
        assert_ne!(initial_secret.id, updated_secret.id);
    }
}
