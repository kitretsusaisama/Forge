use totp_rs::{Algorithm, TOTP};
use base32::encode;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};

/// TOTP Configuration and Management
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TotpConfig {
    /// Secret key for TOTP generation
    secret_key: String,
    
    /// Issuer name (e.g., "Forge DevEnv")
    issuer: String,
    
    /// Account name (usually username)
    account_name: String,
    
    /// Number of digits in TOTP code
    digits: usize,
    
    /// Time step (default: 30 seconds)
    step: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret_key: "".to_string(),
            issuer: "Forge".to_string(),
            account_name: "user".to_string(),
            digits: 6,
            step: 30,
        }
    }
}

/// TOTP (Time-based One-Time Password) Manager
pub struct TotpManager {
    totp: TOTP,
}

impl TotpManager {
    /// Generate a new TOTP configuration
    pub fn generate(
        issuer: &str, 
        account_name: &str
    ) -> Result<TotpConfig> {
        // Generate a cryptographically secure random secret
        let mut secret_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_key);

        // Encode secret key in base32 for QR code compatibility
        let base32_secret = encode(base32::Alphabet::RFC4648 { padding: false }, &secret_key);

        let config = TotpConfig {
            secret_key: base32_secret,
            issuer: issuer.to_string(),
            account_name: account_name.to_string(),
            digits: 6,
            step: 30,
        };

        Ok(config)
    }

    /// Create a new TOTP manager from configuration
    pub fn new(config: TotpConfig) -> Result<Self> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            config.digits,
            1,
            config.step,
            config.secret_key,
        ).map_err(|e| anyhow::anyhow!("Failed to create TOTP: {}", e))?;

        Ok(Self { totp })
    }

    /// Get provisioning URI for TOTP
    pub fn get_provisioning_uri(&self, issuer: &str, account_name: &str) -> String {
        self.totp.get_provisioning_uri(issuer, account_name)
            .unwrap_or_else(|_| String::new())
    }

    /// Verify a TOTP code
    pub fn verify_code(&self, code: &str) -> Result<bool> {
        self.totp.check_current(code)
            .map_err(|e| anyhow::anyhow!("Failed to verify TOTP code: {}", e))
    }

    /// Get current TOTP code
    pub fn generate_code(&self) -> Result<String> {
        self.totp.generate_current()
            .map_err(|e| anyhow::anyhow!("Failed to generate TOTP code: {}", e))
    }

    /// Get remaining time for current code
    pub fn time_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.totp.step - (now % self.totp.step)
    }
}

/// TOTP Configuration Storage
pub struct TotpConfigManager {
    config_path: std::path::PathBuf,
}

impl TotpConfigManager {
    pub fn new(base_dir: &std::path::Path) -> Result<Self> {
        let config_path = base_dir.join("totp_configs");
        
        // Ensure config directory exists
        std::fs::create_dir_all(&config_path)?;

        Ok(Self { config_path })
    }

    /// Save TOTP configuration for a user
    pub fn save_config(
        &self, 
        user_id: &str, 
        config: &TotpConfig
    ) -> Result<()> {
        let user_config_path = self.config_path.join(format!("{}.json", user_id));
        
        let config_str = serde_json::to_string_pretty(config)
            .context("Failed to serialize TOTP configuration")?;

        std::fs::write(user_config_path, config_str)
            .context("Failed to save TOTP configuration")?;

        Ok(())
    }

    /// Load TOTP configuration for a user
    pub fn load_config(&self, user_id: &str) -> Result<Option<TotpConfig>> {
        let user_config_path = self.config_path.join(format!("{}.json", user_id));
        
        if !user_config_path.exists() {
            return Ok(None);
        }

        let config_str = std::fs::read_to_string(&user_config_path)
            .context("Failed to read TOTP configuration")?;
        
        let config: TotpConfig = serde_json::from_str(&config_str)
            .context("Invalid TOTP configuration")?;

        Ok(Some(config))
    }

    /// Remove TOTP configuration for a user
    pub fn remove_config(&self, user_id: &str) -> Result<bool> {
        let user_config_path = self.config_path.join(format!("{}.json", user_id));
        
        if user_config_path.exists() {
            std::fs::remove_file(user_config_path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_totp_generation_and_verification() {
        let config = TotpManager::generate("Forge", "testuser").unwrap();
        let totp_manager = TotpManager::new(config).unwrap();

        // Get current code
        let current_code = totp_manager.generate_code().unwrap();

        // Verify the current code
        assert!(totp_manager.verify_code(&current_code).unwrap());

        // Verify invalid code
        assert!(!totp_manager.verify_code("000000").unwrap());
    }

    #[test]
    fn test_totp_config_management() {
        let temp_dir = tempdir().unwrap();
        let config_manager = TotpConfigManager::new(temp_dir.path()).unwrap();

        let config = TotpManager::generate("Forge", "testuser").unwrap();
        
        // Save configuration
        config_manager.save_config("user123", &config).unwrap();

        // Load configuration
        let loaded_config = config_manager.load_config("user123").unwrap().unwrap();
        
        assert_eq!(config.issuer, loaded_config.issuer);
        assert_eq!(config.account_name, loaded_config.account_name);
    }
}
