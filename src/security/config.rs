use crate::security::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    // Basic security settings
    pub enabled: bool,
    pub password_min_length: usize,
    pub require_special_chars: bool,
    pub require_numbers: bool,
    pub session_duration_hours: u32,
    
    // Encryption and hashing
    pub jwt_secret: Secret<String>,
    pub encryption_key: Secret<String>,
    pub mfa_secret_key: Secret<String>,
    pub password_hash_rounds: u32,
    
    // Session management
    pub session_timeout: TimeDelta,
    
    // MFA settings
    pub mfa_code_length: usize,
    pub mfa_code_expiry: TimeDelta,
    pub mfa_enabled: bool,
    pub mfa_required: bool,
    pub allowed_mfa_methods: Vec<String>,
    
    // Recovery settings
    pub recovery_enabled: bool,
    pub recovery_code_length: usize,
    pub recovery_code_count: usize,
    
    // Rate limiting
    pub max_login_attempts: u32,
    pub lockout_duration: TimeDelta,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            password_min_length: 12,
            require_special_chars: true,
            require_numbers: true,
            session_duration_hours: 24,
            
            jwt_secret: Secret::new("default-jwt-secret".to_string()),
            encryption_key: Secret::new("default-encryption-key".to_string()),
            mfa_secret_key: Secret::new("default-mfa-secret".to_string()),
            password_hash_rounds: 10,
            
            session_timeout: TimeDelta::new(Duration::hours(24)),
            
            mfa_code_length: 6,
            mfa_code_expiry: TimeDelta::new(Duration::minutes(5)),
            mfa_enabled: true,
            mfa_required: false,
            allowed_mfa_methods: vec!["totp".to_string(), "email".to_string()],
            
            recovery_enabled: true,
            recovery_code_length: 16,
            recovery_code_count: 10,
            
            max_login_attempts: 5,
            lockout_duration: TimeDelta::new(Duration::minutes(30)),
        }
    }
}
