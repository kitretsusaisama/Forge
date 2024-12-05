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
    secret_key: Vec<u8>,
    
    /// Issuer name (e.g., "Forge DevEnv")
    issuer: String,
    
    /// Account name (usually username)
    account_name: String,
    
    /// Time step (default: 30 seconds)
    time_step: u64,
    
    /// Number of digits in TOTP code
    digits: usize,
}

/// TOTP (Time-based One-Time Password) Manager
pub struct TotpManager {
    totp: TOTP,
    config: TotpConfig,
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
            secret_key,
            issuer: issuer.to_string(),
            account_name: account_name.to_string(),
            time_step: 30,
            digits: 6,
        };

        Ok(config)
    }

    /// Create a new TOTP manager from configuration
    pub fn new(config: TotpConfig) -> Result<Self> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            config.time_step,
            config.secret_key.clone(),
        )?;

        Ok(Self { totp, config })
    }

    /// Generate a TOTP QR code for authenticator apps
    pub fn generate_qr_code(&self) -> Result<Vec<u8>> {
        // Generate QR code URI for authenticator apps
        let uri = self.totp.get_uri(
            &self.config.issuer, 
            &self.config.account_name
        );

        // Generate QR code image
        let qr_code = qrcode::QrCode::new(&uri)?;
        let image = qr_code.render::<qrcode::render::svg::Color>().build();

        Ok(image.as_bytes().to_vec())
    }

    /// Verify a TOTP code
    pub fn verify_code(&self, code: &str) -> bool {
        // Allow small time drift (1 time step before/after current time)
        self.totp.check_current_code(code)
            .unwrap_or(false)
    }

    /// Get current TOTP code
    pub fn get_current_code(&self) -> String {
        self.totp.generate_current()
    }

    /// Get remaining time for current code
    pub fn get_remaining_time(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.config.time_step - (now % self.config.time_step)
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
        let totp_manager = TotpManager::new(config.clone()).unwrap();

        // Get current code
        let current_code = totp_manager.get_current_code();

        // Verify the current code
        assert!(totp_manager.verify_code(&current_code));

        // Verify invalid code
        assert!(!totp_manager.verify_code("000000"));
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
