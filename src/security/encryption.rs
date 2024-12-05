use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use base64::{engine::general_purpose, Engine as _};
use anyhow::{Result, Context};
use std::path::{Path, PathBuf};
use secrecy::{ExposeSecret, Secret};
use generic_array::typenum::U32;

const NONCE_SIZE: usize = 12;

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
    fn get_encryption_key(&self) -> Result<Secret<[u8; 32]>> {
        // Check if key file exists
        if self.key_path.exists() {
            // Read existing key
            let key_content = std::fs::read(&self.key_path)?;
            Ok(Secret::new(key_content.try_into().expect("Invalid key length")))
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

            Ok(Secret::new(key))
        }
    }

    /// Encrypt a secret value
    pub fn encrypt(&self, secret: &str) -> Result<String> {
        // Get encryption key
        let key = self.get_encryption_key()?;
        
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let key = GenericArray::from_slice(key.expose_secret());
        let cipher = Aes256Gcm::new(key);
        
        let ciphertext = cipher
            .encrypt(nonce, secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(&output))
    }

    /// Decrypt a secret value
    pub fn decrypt(&self, encrypted_secret: &str) -> Result<String> {
        // Get encryption key
        let key = self.get_encryption_key()?;
        
        // Decode base64 encrypted data
        let combined_data = general_purpose::STANDARD
            .decode(encrypted_secret)
            .context("Invalid base64 encoding")?;

        if combined_data.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }

        let (nonce_bytes, ciphertext) = combined_data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let key = GenericArray::from_slice(key.expose_secret());
        let cipher = Aes256Gcm::new(key);

        let decrypted_data = cipher
            .decrypt(nonce, ciphertext)
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
