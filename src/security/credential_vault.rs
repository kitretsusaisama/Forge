use anyhow::{Result, Context, anyhow};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, 
        PasswordHasher, 
        PasswordVerifier, 
        SaltString
    },
    Argon2
};
use aes_gcm::{
    Aes256Gcm, 
    Key, 
    Nonce
};
use aes_gcm::aead::{Aead, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Credential types for secure management
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CredentialType {
    Database,
    CloudProvider,
    APIKey,
    SSHKey,
    Other,
}

/// Secure credential storage structure
#[derive(Debug, Serialize, Deserialize)]
pub struct SecureCredential {
    pub id: Uuid,
    pub name: String,
    pub credential_type: CredentialType,
    pub encrypted_data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Credential Vault for secure storage and management
pub struct CredentialVault {
    vault_path: PathBuf,
    master_key: Vec<u8>,
}

impl CredentialVault {
    /// Create a new credential vault
    pub fn new(vault_path: PathBuf, master_password: &str) -> Result<Self> {
        // Create vault directory if not exists
        std::fs::create_dir_all(&vault_path)?;

        // Generate master key from password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let master_key = argon2.hash_password(
            master_password.as_bytes(), 
            &salt
        )?.hash.unwrap().as_bytes().to_vec();

        Ok(Self {
            vault_path,
            master_key,
        })
    }

    /// Store a new credential securely
    pub fn store_credential(
        &self, 
        name: &str, 
        credential_type: CredentialType, 
        raw_credential: &[u8]
    ) -> Result<Uuid> {
        // Generate unique ID
        let credential_id = Uuid::new_v4();

        // Encrypt credential
        let encrypted_data = self.encrypt_data(raw_credential)?;

        // Prepare secure credential
        let secure_credential = SecureCredential {
            id: credential_id,
            name: name.to_string(),
            credential_type,
            encrypted_data,
            metadata: HashMap::new(),
        };

        // Serialize and save
        let credential_path = self.vault_path.join(format!("{}.credential", credential_id));
        let serialized = serde_json::to_vec(&secure_credential)?;
        std::fs::write(credential_path, serialized)?;

        Ok(credential_id)
    }

    /// Retrieve a credential
    pub fn retrieve_credential(&self, credential_id: &Uuid) -> Result<Vec<u8>> {
        let credential_path = self.vault_path.join(format!("{}.credential", credential_id));
        
        // Read and deserialize
        let serialized = std::fs::read(credential_path)?;
        let secure_credential: SecureCredential = serde_json::from_slice(&serialized)?;

        // Decrypt credential
        self.decrypt_data(&secure_credential.encrypted_data)
    }

    /// Encrypt data using AES-GCM
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&self.master_key[..32]);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let nonce = Nonce::from_slice(b"unique nonce");
        
        // Encrypt
        let encrypted = cipher.encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        
        // Combine nonce and encrypted data
        let mut result = nonce.to_vec();
        result.extend_from_slice(&encrypted);
        
        Ok(result)
    }

    /// Decrypt data using AES-GCM
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&self.master_key[..32]);
        let cipher = Aes256Gcm::new(key);
        
        // Extract nonce and ciphertext
        let (nonce, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce);
        
        // Decrypt
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        
        Ok(decrypted)
    }

    /// List all stored credentials
    pub fn list_credentials(&self) -> Result<Vec<SecureCredential>> {
        let mut credentials = Vec::new();
        
        for entry in std::fs::read_dir(&self.vault_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("credential") {
                let serialized = std::fs::read(&path)?;
                let credential: SecureCredential = serde_json::from_slice(&serialized)?;
                credentials.push(credential);
            }
        }
        
        Ok(credentials)
    }

    /// Delete a credential
    pub fn delete_credential(&self, credential_id: &Uuid) -> Result<()> {
        let credential_path = self.vault_path.join(format!("{}.credential", credential_id));
        std::fs::remove_file(credential_path)?;
        Ok(())
    }

    /// Rotate master password
    pub fn rotate_master_password(
        &mut self, 
        old_password: &str, 
        new_password: &str
    ) -> Result<()> {
        // Verify old password
        self.verify_master_password(old_password)?;

        // Generate new master key
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let new_master_key = argon2.hash_password(
            new_password.as_bytes(), 
            &salt
        )?.hash.unwrap().as_bytes().to_vec();

        // Update master key
        self.master_key = new_master_key;

        Ok(())
    }

    /// Verify master password
    pub fn verify_master_password(&self, password: &str) -> Result<bool> {
        let argon2 = Argon2::default();
        let hash = PasswordHash::new(
            &general_purpose::STANDARD.encode(&self.master_key)
        )?;

        Ok(argon2.verify_password(password.as_bytes(), &hash).is_ok())
    }
}

/// Secure configuration management
pub struct SecureConfigManager {
    vault: CredentialVault,
}

impl SecureConfigManager {
    /// Create a new secure config manager
    pub fn new(vault_path: PathBuf, master_password: &str) -> Result<Self> {
        Ok(Self {
            vault: CredentialVault::new(vault_path, master_password)?,
        })
    }

    /// Store sensitive configuration
    pub fn store_config(
        &self, 
        name: &str, 
        config: &serde_json::Value
    ) -> Result<Uuid> {
        let serialized = serde_json::to_vec(config)?;
        self.vault.store_credential(
            name, 
            CredentialType::Other, 
            &serialized
        )
    }

    /// Retrieve sensitive configuration
    pub fn retrieve_config(&self, config_id: &Uuid) -> Result<serde_json::Value> {
        let decrypted = self.vault.retrieve_credential(config_id)?;
        Ok(serde_json::from_slice(&decrypted)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_credential_vault_basic_operations() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().to_path_buf();
        
        // Create vault
        let vault = CredentialVault::new(
            vault_path.clone(), 
            "test_master_password"
        ).unwrap();

        // Store credential
        let credential_data = b"my_secret_credential";
        let credential_id = vault.store_credential(
            "test_credential", 
            CredentialType::Database, 
            credential_data
        ).unwrap();

        // Retrieve credential
        let retrieved_data = vault.retrieve_credential(&credential_id).unwrap();
        assert_eq!(credential_data, retrieved_data.as_slice());

        // List credentials
        let credentials = vault.list_credentials().unwrap();
        assert_eq!(credentials.len(), 1);

        // Delete credential
        vault.delete_credential(&credential_id).unwrap();
        let credentials = vault.list_credentials().unwrap();
        assert_eq!(credentials.len(), 0);
    }

    #[test]
    fn test_secure_config_management() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().to_path_buf();
        
        // Create secure config manager
        let config_manager = SecureConfigManager::new(
            vault_path, 
            "test_master_password"
        ).unwrap();

        // Store configuration
        let config = serde_json::json!({
            "database": {
                "host": "localhost",
                "port": 5432,
                "username": "testuser"
            }
        });

        let config_id = config_manager.store_config("test_config", &config).unwrap();

        // Retrieve configuration
        let retrieved_config = config_manager.retrieve_config(&config_id).unwrap();
        assert_eq!(config, retrieved_config);
    }
}
