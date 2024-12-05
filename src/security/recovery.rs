use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::{Result, Context};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Duration, Utc};
use secrecy::{Secret, SecretString};
use uuid::Uuid;

/// Secret recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecoveryConfig {
    /// Maximum number of recovery codes allowed
    pub max_recovery_codes: usize,
    /// Validity duration for recovery codes
    #[serde(with = "time_delta_serde")]
    pub code_validity_duration: Duration,
}

impl Default for SecretRecoveryConfig {
    fn default() -> Self {
        Self {
            max_recovery_codes: 5,
            code_validity_duration: Duration::days(30),
        }
    }
}

mod time_delta_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(delta: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(delta.num_seconds())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = i64::deserialize(deserializer)?;
        Duration::seconds(seconds)
    }
}

/// Secret recovery code entry
#[derive(Debug, Serialize, Deserialize)]
struct RecoveryCodeEntry {
    /// Unique identifier for the recovery code
    id: Uuid,
    /// Hashed recovery code
    hashed_code: String,
    /// Creation timestamp
    created_at: DateTime<Utc>,
    /// Whether the code has been used
    used: bool,
}

/// Secret recovery management system
pub struct SecretRecoveryManager {
    recovery_codes_path: PathBuf,
    config: SecretRecoveryConfig,
}

impl SecretRecoveryManager {
    /// Create a new secret recovery manager
    pub fn new(base_dir: &Path, config: Option<SecretRecoveryConfig>) -> Result<Self> {
        let recovery_codes_path = base_dir.join("recovery_codes.json");
        
        // Ensure base directory exists
        std::fs::create_dir_all(base_dir)?;

        Ok(Self {
            recovery_codes_path,
            config: config.unwrap_or_default(),
        })
    }

    /// Generate recovery codes for a user
    pub fn generate_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        // Load existing recovery codes
        let mut recovery_codes = self.load_recovery_codes()?;

        // Clean up expired codes
        self.cleanup_expired_codes(&mut recovery_codes);

        // Check if user has reached maximum recovery codes
        let user_codes = recovery_codes
            .iter()
            .filter(|code| code.used == false)
            .count();

        if user_codes >= self.config.max_recovery_codes {
            return Err(anyhow::anyhow!(
                "Maximum number of recovery codes reached"
            ));
        }

        // Generate new recovery codes
        let mut new_recovery_codes = Vec::new();
        for _ in 0..self.config.max_recovery_codes - user_codes {
            let recovery_code = self.generate_recovery_code();
            let hashed_code = self.hash_recovery_code(&recovery_code);

            recovery_codes.push(RecoveryCodeEntry {
                id: Uuid::new_v4(),
                hashed_code,
                created_at: Utc::now(),
                used: false,
            });

            new_recovery_codes.push(recovery_code);
        }

        // Save updated recovery codes
        self.save_recovery_codes(&recovery_codes)?;

        Ok(new_recovery_codes)
    }

    /// Validate and consume a recovery code
    pub fn validate_recovery_code(
        &self, 
        recovery_code: &str, 
        user_id: &str
    ) -> Result<bool> {
        let mut recovery_codes = self.load_recovery_codes()?;

        // Clean up expired codes
        self.cleanup_expired_codes(&mut recovery_codes);

        // Find matching recovery code
        if let Some(code_entry) = recovery_codes
            .iter_mut()
            .find(|code| {
                !code.used && 
                self.verify_recovery_code(recovery_code, &code.hashed_code)
            }) 
        {
            // Mark code as used
            code_entry.used = true;

            // Save updated recovery codes
            self.save_recovery_codes(&recovery_codes)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Generate a secure recovery code
    fn generate_recovery_code(&self) -> String {
        // Generate a 16-character alphanumeric recovery code
        let mut recovery_code = String::with_capacity(16);
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();

        for _ in 0..16 {
            let idx = OsRng.next_u32() as usize % chars.len();
            recovery_code.push(chars[idx]);
        }

        recovery_code
    }

    /// Hash recovery code for secure storage
    fn hash_recovery_code(&self, recovery_code: &str) -> String {
        use argon2::{
            password_hash::{
                rand_core::OsRng,
                PasswordHasher, 
                SaltString
            },
            Argon2
        };

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(recovery_code.as_bytes(), &salt)
            .expect("Failed to hash recovery code")
            .to_string()
    }

    /// Verify recovery code against stored hash
    fn verify_recovery_code(&self, recovery_code: &str, hashed_code: &str) -> bool {
        use argon2::{
            password_hash::{PasswordHash, PasswordVerifier},
            Argon2
        };

        let parsed_hash = PasswordHash::new(hashed_code)
            .expect("Invalid password hash");

        Argon2::default()
            .verify_password(recovery_code.as_bytes(), &parsed_hash)
            .is_ok()
    }

    /// Load recovery codes from file
    fn load_recovery_codes(&self) -> Result<Vec<RecoveryCodeEntry>> {
        if self.recovery_codes_path.exists() {
            let recovery_codes_json = std::fs::read_to_string(&self.recovery_codes_path)?;
            serde_json::from_str(&recovery_codes_json)
                .context("Failed to parse recovery codes")
        } else {
            Ok(Vec::new())
        }
    }

    /// Save recovery codes to file
    fn save_recovery_codes(&self, recovery_codes: &[RecoveryCodeEntry]) -> Result<()> {
        let recovery_codes_json = serde_json::to_string_pretty(recovery_codes)?;
        std::fs::write(&self.recovery_codes_path, recovery_codes_json)
            .context("Failed to save recovery codes")
    }

    /// Clean up expired recovery codes
    fn cleanup_expired_codes(&self, recovery_codes: &mut Vec<RecoveryCodeEntry>) {
        let now = Utc::now();
        recovery_codes.retain(|code| 
            !code.used && 
            now.signed_duration_since(code.created_at) <= self.config.code_validity_duration
        );
    }

    /// Revoke all recovery codes for a user
    pub fn revoke_all_recovery_codes(&self) -> Result<()> {
        // Simply delete the recovery codes file
        if self.recovery_codes_path.exists() {
            std::fs::remove_file(&self.recovery_codes_path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_recovery_code_generation() {
        let temp_dir = tempdir().unwrap();
        let recovery_manager = SecretRecoveryManager::new(
            temp_dir.path(), 
            None
        ).unwrap();

        let user_id = "test_user";
        let recovery_codes = recovery_manager.generate_recovery_codes(user_id).unwrap();

        assert_eq!(recovery_codes.len(), 5);
        for code in &recovery_codes {
            assert_eq!(code.len(), 16);
        }
    }

    #[test]
    fn test_recovery_code_validation() {
        let temp_dir = tempdir().unwrap();
        let recovery_manager = SecretRecoveryManager::new(
            temp_dir.path(), 
            None
        ).unwrap();

        let user_id = "test_user";
        let recovery_codes = recovery_manager.generate_recovery_codes(user_id).unwrap();

        // Validate first recovery code
        let first_code = &recovery_codes[0];
        let is_valid = recovery_manager
            .validate_recovery_code(first_code, user_id)
            .unwrap();
        assert!(is_valid);

        // Second validation should fail (code already used)
        let is_valid = recovery_manager
            .validate_recovery_code(first_code, user_id)
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_recovery_code_expiration() {
        let temp_dir = tempdir().unwrap();
        let config = SecretRecoveryConfig {
            max_recovery_codes: 5,
            code_validity_duration: Duration::seconds(1), // Very short expiration
        };

        let recovery_manager = SecretRecoveryManager::new(
            temp_dir.path(), 
            Some(config)
        ).unwrap();

        let user_id = "test_user";
        let recovery_codes = recovery_manager.generate_recovery_codes(user_id).unwrap();

        // Wait for code to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Validation should fail due to expiration
        let first_code = &recovery_codes[0];
        let is_valid = recovery_manager
            .validate_recovery_code(first_code, user_id)
            .unwrap();
        assert!(!is_valid);
    }
}
