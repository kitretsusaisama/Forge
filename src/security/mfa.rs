use std::collections::HashMap;
use std::time::{Duration, Instant};
use rand::Rng;
use serde::{Deserialize, Serialize};
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

/// Multi-Factor Authentication (MFA) Configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MfaConfig {
    /// Enable MFA globally
    pub enabled: bool,
    
    /// Require MFA for specific user roles
    pub required_roles: Vec<String>,
    
    /// MFA code expiration time in seconds
    pub code_expiration_seconds: u64,
    
    /// Number of allowed MFA attempts
    pub max_attempts: u32,
}

/// MFA Method Types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MfaMethod {
    Totp,           // Time-based One-Time Password
    Email,          // Email verification code
    Sms,            // SMS verification code
    RecoveryCode,   // Backup recovery codes
}

impl ToString for MfaMethod {
    fn to_string(&self) -> String {
        match self {
            MfaMethod::Totp => "totp".to_string(),
            MfaMethod::Email => "email".to_string(),
            MfaMethod::Sms => "sms".to_string(),
            MfaMethod::RecoveryCode => "recovery_code".to_string(),
        }
    }
}

impl std::str::FromStr for MfaMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "totp" => Ok(MfaMethod::Totp),
            "email" => Ok(MfaMethod::Email),
            "sms" => Ok(MfaMethod::Sms),
            "recovery_code" => Ok(MfaMethod::RecoveryCode),
            _ => Err(format!("Invalid MFA method: {}", s)),
        }
    }
}

/// Multi-Factor Authentication Manager
pub struct MfaManager {
    /// Temporary storage for MFA codes
    codes: HashMap<String, MfaEntry>,
    
    /// Configuration for MFA
    config: MfaConfig,
}

/// MFA Code Entry
struct MfaEntry {
    /// The actual verification code
    code: String,
    
    /// When the code was generated
    generated_at: Instant,
    
    /// Number of attempts made
    attempts: u32,
    
    /// MFA method used
    method: MfaMethod,
}

impl MfaManager {
    /// Create a new MFA manager
    pub fn new(config: MfaConfig) -> Self {
        Self {
            codes: HashMap::new(),
            config,
        }
    }

    /// Generate a new MFA code for a user
    pub fn generate_code(&mut self, user_id: &str, method: MfaMethod) -> Result<String, String> {
        // Check if MFA is enabled
        if !self.config.enabled {
            return Err("MFA is not enabled".to_string());
        }

        // Generate a 6-digit code
        let code = format!("{:06}", rand::thread_rng().gen_range(100_000..999_999));

        // Hash the code for additional security
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_code = argon2.hash_password(code.as_bytes(), &salt)
            .map_err(|_| "Failed to hash MFA code".to_string())?
            .to_string();

        // Store the MFA entry
        self.codes.insert(
            user_id.to_string(), 
            MfaEntry {
                code: hashed_code,
                generated_at: Instant::now(),
                attempts: 0,
                method,
            }
        );

        // Return the unhashed code for transmission
        Ok(code)
    }

    /// Verify MFA code
    pub fn verify_code(
        &mut self, 
        user_id: &str, 
        provided_code: &str
    ) -> Result<bool, String> {
        // Retrieve MFA entry
        let entry = self.codes.get_mut(user_id)
            .ok_or_else(|| "No MFA code generated".to_string())?;

        // Check attempts
        if entry.attempts >= self.config.max_attempts {
            self.codes.remove(user_id);
            return Err("Max MFA attempts exceeded".to_string());
        }

        // Check code expiration
        let elapsed = entry.generated_at.elapsed();
        if elapsed > Duration::from_secs(self.config.code_expiration_seconds) {
            self.codes.remove(user_id);
            return Err("MFA code expired".to_string());
        }

        // Verify the code
        let parsed_hash = PasswordHash::new(&entry.code)
            .map_err(|_| "Invalid stored hash".to_string())?;

        let verification = Argon2::default()
            .verify_password(provided_code.as_bytes(), &parsed_hash);

        // Increment attempts
        entry.attempts += 1;

        match verification {
            Ok(_) => {
                // Successful verification, remove the entry
                self.codes.remove(user_id);
                Ok(true)
            },
            Err(_) => Ok(false)
        }
    }

    /// Check if MFA is required for a user
    pub fn is_mfa_required(&self, user_roles: &[String]) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check if any of the user's roles require MFA
        user_roles.iter().any(|role| 
            self.config.required_roles.contains(role)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_code_generation() {
        let config = MfaConfig {
            enabled: true,
            required_roles: vec!["admin".to_string()],
            code_expiration_seconds: 300,
            max_attempts: 3,
        };

        let mut mfa_manager = MfaManager::new(config);
        
        // Generate code
        let user_id = "test_user";
        let code = mfa_manager.generate_code(user_id, MfaMethod::Totp).unwrap();
        
        // Verify correct code
        assert!(mfa_manager.verify_code(user_id, &code).unwrap());
        
        // Verify incorrect code fails
        assert!(!mfa_manager.verify_code(user_id, "000000").unwrap());
    }

    #[test]
    fn test_mfa_code_expiration() {
        let mut config = MfaConfig {
            enabled: true,
            required_roles: vec!["admin".to_string()],
            code_expiration_seconds: 1,  // Very short expiration
            max_attempts: 3,
        };

        let mut mfa_manager = MfaManager::new(config);
        
        let user_id = "test_user";
        let code = mfa_manager.generate_code(user_id, MfaMethod::Totp).unwrap();
        
        // Wait for code to expire
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Verify expired code fails
        assert!(mfa_manager.verify_code(user_id, &code).is_err());
    }
}
