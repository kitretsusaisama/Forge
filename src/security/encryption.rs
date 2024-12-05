use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, 
    Key,
    Nonce,
};
use generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use base64::{engine::general_purpose, Engine as _};
use anyhow::{Result, Context};
use std::path::{Path, PathBuf};
use secrecy::{ExposeSecret, Secret};

/// Encryption configuration and management
#[derive(Debug, Clone)]
pub struct SecretEncryptionManager {
    key_path: PathBuf,
}

impl SecretEncryptionManager {
    /// Create a new encryption manager
    pub fn new(base_dir: &Path) -> Result<Self> {
        let key_path = base_dir.join("secret.key");
        
        // Ensure key directory exists
        std::fs::create_dir_all(base_dir)?;

        Ok(Self { 
            key_path 
        })
    }

    /// Generate or retrieve encryption key
    fn get_encryption_key(&self) -> Result<Secret<Vec<u8>>> {
        // Check if key file exists
        if self.key_path.exists() {
            // Read existing key
            let key_content = std::fs::read(&self.key_path)?;
            Ok(Secret::new(key_content))
        } else {
            // Generate new encryption key
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);

            // Save key securely
            std::fs::write(&self.key_path, &key)?;
            
            // Set restrictive permissions (Unix-like systems)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&self.key_path)?.permissions();
                perms.set_mode(0o600); // Read/write for owner only
                std::fs::set_permissions(&self.key_path, perms)?;
            }

            Ok(Secret::new(key.to_vec()))
        }
    }

    /// Encrypt a secret value
    pub fn encrypt(&self, secret: &str) -> Result<String> {
        // Get encryption key
        let key = self.get_encryption_key()?;
        let key = Key::from_slice(key.expose_secret());

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new(key);

        // Encrypt the secret
        let encrypted_data = cipher.encrypt(nonce, secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Combine nonce and encrypted data, then base64 encode
        let mut combined_data = nonce_bytes.to_vec();
        combined_data.extend_from_slice(&encrypted_data);

        Ok(general_purpose::STANDARD.encode(&combined_data))
    }

    /// Decrypt a secret value
    pub fn decrypt(&self, encrypted_secret: &str) -> Result<String> {
        // Get encryption key
        let key = self.get_encryption_key()?;
        let key = Key::from_slice(key.expose_secret());

        // Decode base64 encrypted data
        let combined_data = general_purpose::STANDARD
            .decode(encrypted_secret)
            .context("Invalid base64 encoding")?;

        // Split nonce and encrypted data
        let (nonce_bytes, encrypted_data) = combined_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new(key);

        // Decrypt the secret
        let decrypted_data = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        // Convert to string
        String::from_utf8(decrypted_data)
            .context("Decrypted data is not valid UTF-8")
    }

    /// Rotate encryption key
    pub fn rotate_key(&self) -> Result<()> {
        // Generate new key, which will overwrite the existing one
        self.get_encryption_key()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encryption_decryption() {
        let temp_dir = tempdir().unwrap();
        let encryption_manager = SecretEncryptionManager::new(temp_dir.path()).unwrap();

        let original_secret = "super_secret_value_123!@#";
        
        // Encrypt
        let encrypted = encryption_manager.encrypt(original_secret).unwrap();
        
        // Decrypt
        let decrypted = encryption_manager.decrypt(&encrypted).unwrap();
        
        assert_eq!(original_secret, decrypted);
    }

    #[test]
    fn test_key_rotation() {
        let temp_dir = tempdir().unwrap();
        let encryption_manager = SecretEncryptionManager::new(temp_dir.path()).unwrap();

        // Initial key generation
        let initial_key_path = encryption_manager.key_path.clone();
        let initial_key_content = std::fs::read(&initial_key_path).unwrap();

        // Rotate key
        encryption_manager.rotate_key().unwrap();

        // Check key has changed
        let rotated_key_content = std::fs::read(&initial_key_path).unwrap();
        assert_ne!(initial_key_content, rotated_key_content);
    }
}
