// Custom serialization and deserialization for Secret<String>
mod secret_serde {
    use secrecy::{Secret, ExposeSecret};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(secret: &Secret<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(secret.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Secret<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Ok(Secret::new(s))
    }
}

mod access_control;
mod mfa;
mod email;
mod totp;
mod secrets;
mod encryption;
mod audit;
mod recovery;
mod credential_vault;
mod geolocation;
mod prelude;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use secrecy::{Secret, ExposeSecret, SerializableSecret};
use tracing::{info, warn, error};

use crate::security::secrets::SecretsManager;
use crate::security::recovery::SecretRecoveryManager;

pub use access_control::{
    AccessControlManager,
    Session,
};

pub use audit::AuditLog;
pub use config::SecurityConfig;
pub use credential_vault::CredentialVault;
pub use email::{EmailService, EmailConfig};
pub use encryption::EncryptionService;
pub use mfa::{MfaManager, MfaMethod};
pub use recovery::{SecretRecoveryManager, SecretRecoveryConfig};
pub use secrets::SecretsManager;
pub use totp::{TotpManager, TotpConfig};

/// Global security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(remote = "SecurityConfig")]
pub struct SecurityConfig {
    pub enabled: bool,
    pub password_min_length: u8,
    pub require_special_chars: bool,
    pub require_numbers: bool,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
    pub session_timeout: Duration,
    pub mfa_code_length: u8,
    pub mfa_code_expiry: Duration,
    pub allowed_mfa_methods: Vec<MfaMethod>,
    pub geolocation_policies: HashMap<String, GeoAccessPolicy>,
    #[serde(with = "secret_serde")]
    pub jwt_secret: Secret<String>,
    #[serde(with = "secret_serde")]
    pub encryption_key: Secret<String>,
    #[serde(with = "secret_serde")]
    pub mfa_secret_key: Secret<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            password_min_length: 12,
            require_special_chars: true,
            require_numbers: true,
            require_uppercase: true,
            require_lowercase: true,
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(1800),
            session_timeout: Duration::from_secs(86400),
            mfa_code_length: 6,
            mfa_code_expiry: Duration::from_secs(300),
            allowed_mfa_methods: vec![MfaMethod::Totp, MfaMethod::Email],
            geolocation_policies: HashMap::new(),
            jwt_secret: Secret::new("default-jwt-secret".to_string()),
            encryption_key: Secret::new("default-encryption-key".to_string()),
            mfa_secret_key: Secret::new("default-mfa-secret".to_string()),
        }
    }
}

// Secret conversion helpers
impl SecurityConfig {
    pub fn into_secrets(self) -> (Secret<String>, Secret<String>, Secret<String>) {
        (
            Secret::new(self.jwt_secret.expose_secret().clone()),
            Secret::new(self.encryption_key.expose_secret().clone()), 
            Secret::new(self.mfa_secret_key.expose_secret().clone())
        )
    }

    pub fn from_secrets(
        jwt_secret: Secret<String>,
        encryption_key: Secret<String>, 
        mfa_secret_key: Secret<String>,
        config: SecurityConfig,
    ) -> Self {
        Self {
            jwt_secret,
            encryption_key,
            mfa_secret_key,
            ..config
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    pub max_recovery_codes: usize,
    pub recovery_code_length: usize,
    pub recovery_code_expiry_days: u32,
    pub recovery_email_required: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_recovery_codes: 10,
            recovery_code_length: 16,
            recovery_code_expiry_days: 30,
            recovery_email_required: true,
        }
    }
}

/// Validate password complexity
pub fn validate_password(password: &str, config: &SecurityConfig) -> Result<(), String> {
    if password.len() < config.password_min_length as usize {
        return Err(format!("Password must be at least {} characters long", config.password_min_length));
    }

    if config.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Password must contain at least one special character".to_string());
    }

    if config.require_numbers && !password.chars().any(|c| c.is_numeric()) {
        return Err("Password must contain at least one number".to_string());
    }

    if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }

    if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }

    Ok(())
}

/// Audit logging for security events
pub struct SecurityAuditor {
    log_path: PathBuf,
}

impl SecurityAuditor {
    pub fn new(log_directory: &Path) -> std::io::Result<Self> {
        let log_path = log_directory.join("security_audit.log");
        std::fs::create_dir_all(log_directory)?;
        Ok(Self { log_path })
    }

    /// Log a security event
    pub fn log_event(&self, event_type: &str, details: &str) -> std::io::Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let timestamp = chrono::Utc::now().to_rfc3339();
        let log_entry = format!("[{}] {}: {}\n", timestamp, event_type, details);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        file.write_all(log_entry.as_bytes())
    }
}

/// Comprehensive security service
pub struct SecurityService {
    config: Arc<SecurityConfig>,
    access_control: Arc<AccessControlManager>,
    mfa_manager: Arc<MfaManager>,
    secrets_manager: Arc<SecretsManager>,
    email_service: Option<EmailService>,
    totp_manager: Option<TotpManager>,
    recovery_manager: Option<SecretRecoveryManager>,
    credential_vault: Option<CredentialVault>,
    geolocation_service: Option<GeolocationService>,
}

impl SecurityService {
    pub async fn new(base_dir: &Path, config: SecurityConfig) -> Result<Self> {
        let config = Arc::new(config);
        let access_control = Arc::new(AccessControlManager::new(base_dir)?);
        let mfa_manager = Arc::new(MfaManager::new(&config)?);
        let secrets_manager = Arc::new(SecretsManager::new(base_dir).await?);

        Ok(Self {
            config,
            access_control,
            mfa_manager,
            secrets_manager,
            email_service: None,
            totp_manager: None,
            recovery_manager: None,
            credential_vault: None,
            geolocation_service: None,
        })
    }

    pub async fn verify_mfa(&mut self, user_id: &str, mfa_code: &str, method: MfaMethod) -> Result<Session> {
        if !self.config.enabled {
            return Err(anyhow::anyhow!("Security service is disabled"));
        }

        let user = self.access_control.get_user(user_id)?;
        
        if self.mfa_manager.verify_code(user_id, mfa_code)? {
            self.access_control.create_session(&user)
        } else {
            Err(anyhow::anyhow!("Invalid MFA code"))
        }
    }

    pub async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        if !self.config.enabled {
            return Err(anyhow::anyhow!("Security service is disabled"));
        }

        self.secrets_manager.get_secret(key).await
    }

    pub async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        if !self.config.enabled {
            return Err(anyhow::anyhow!("Security service is disabled"));
        }

        self.secrets_manager.set_secret(key, value).await
    }
}

/// Advanced Security Service with Email and TOTP Integration
pub struct AdvancedSecurityService {
    access_control: AccessControlManager,
    session_manager: SessionManager,
    mfa_manager: MfaManager,
    email_service: Option<EmailService>,
    totp_manager: Option<TotpManager>,
    secrets_manager: SecretsManager,
    recovery_manager: SecretRecoveryManager,
    credential_vault: CredentialVault, // New field for credential vault
    geolocation_access_control: GeolocationAccessControlManager, // New field for geolocation access control
    geolocation_service: GeolocationService, // New field for geolocation service
    config: SecurityConfig,
}

impl AdvancedSecurityService {
    pub fn new(base_dir: &Path, config: SecurityConfig) -> Result<Self, anyhow::Error> {
        // Initialize geolocation providers
        let geolocation_providers: Vec<Box<dyn GeoLocationProvider>> = vec![
            Box::new(MaxMindGeoLocationProvider::new(
                base_dir.join("geoip").join("GeoLite2-City.mmdb").to_str().unwrap()
            )?)
        ];

        // Create geolocation service
        let geolocation_service = GeolocationService::new(geolocation_providers);

        // Create geolocation access control manager
        let mut geolocation_access_control = GeolocationAccessControlManager::new(
            geolocation_service.clone()
        );

        // Add policies from config
        for (resource_id, policy) in &config.geolocation_policies {
            geolocation_access_control.add_policy(
                resource_id.clone(), 
                policy.clone()
            );
        }

        // Initialize secrets manager
        let secrets_manager = SecretsManager::new(base_dir)?;
        secrets_manager.load_env()?;
        secrets_manager.init_secrets()?;
        secrets_manager.validate_secrets()?;

        // Retrieve secrets for configuration
        let smtp_username = secrets_manager.get_secret("SMTP_USERNAME")
            .map(|s| s.expose_secret().to_string());
        let smtp_password = secrets_manager.get_secret("SMTP_PASSWORD")
            .map(|s| s.expose_secret().to_string());

        // Initialize email configuration from secrets
        let email_config = EmailConfig {
            smtp_host: secrets_manager.get_secret("SMTP_HOST")
                .map(|s| s.expose_secret().to_string())
                .unwrap_or_else(|| "smtp.example.com".to_string()),
            smtp_port: secrets_manager.get_secret("SMTP_PORT")
                .and_then(|s| s.expose_secret().parse().ok())
                .unwrap_or(587),
            sender_email: secrets_manager.get_secret("SMTP_SENDER_EMAIL")
                .map(|s| s.expose_secret().to_string())
                .unwrap_or_else(|| "forge@example.com".to_string()),
            use_tls: true,
            username: smtp_username,
            password: smtp_password,
        };

        // Initialize core security components
        let access_control = AccessControlManager::new(base_dir)?;
        let session_manager = SessionManager::new();
        let mfa_manager = MfaManager::new(
            config.mfa.clone().unwrap_or_default()
        );

        // Initialize optional email service
        let email_service = EmailService::new(email_config.clone());

        // Initialize optional TOTP manager
        let totp_manager = config.totp_config.as_ref()
            .map(|totp_config| TotpManager::new(totp_config.clone()).ok())
            .flatten();

        // Initialize recovery manager
        let recovery_manager = SecretRecoveryManager::new(config.recovery_config.clone().unwrap_or_default());

        // Initialize credential vault
        let credential_vault = CredentialVault::new(
            base_dir.join("credential_vault"),
            &config.master_password
        )?;

        Ok(Self {
            access_control,
            session_manager,
            mfa_manager,
            email_service: Some(email_service),
            totp_manager,
            secrets_manager,
            recovery_manager,
            credential_vault,
            geolocation_access_control,
            geolocation_service,
            config,
        })
    }

    /// Advanced authentication with multiple MFA methods
    pub fn authenticate(&mut self, username: &str, password: &str) -> Result<Option<Session>, anyhow::Error> {
        // Authenticate user
        let user = self.access_control.authenticate(username, password)?;
        
        // Check if MFA is required
        if self.mfa_manager.is_mfa_required(&[user.role.to_string()]) {
            // Determine MFA method
            let mfa_method = self.config.allowed_mfa_methods.first()
                .cloned()
                .unwrap_or(MfaMethod::Totp);
            
            let mfa_code = self.mfa_manager.generate_code(&user.id, mfa_method)?;
            
            // Send MFA code based on method
            match mfa_method {
                MfaMethod::Email => {
                    if let Some(email_service) = &self.email_service {
                        // TODO: Retrieve user's email from user profile
                        let user_email = format!("{}_email@example.com", username);
                        email_service.send_mfa_code(&user_email, &mfa_code)?;
                    }
                },
                MfaMethod::Totp => {
                    // For TOTP, we generate a new TOTP configuration if not exists
                    if self.totp_manager.is_none() {
                        let totp_config = TotpManager::generate(
                            "Forge DevEnv", 
                            username
                        )?;
                        self.totp_manager = Some(TotpManager::new(totp_config)?);
                    }
                    
                    // The TOTP code is generated dynamically, so we don't need to send it
                    println!("Please use your authenticator app to generate a code");
                },
                _ => {
                    // Fallback to default MFA method
                    println!("MFA Code: {}", mfa_code);
                }
            }
            
            return Ok(None);
        }
        
        // Create session if no MFA required
        let session = self.session_manager.create_session(&user.id)?;
        Ok(Some(session))
    }

    /// Verify MFA code with multiple methods
    pub fn verify_mfa(&mut self, user_id: &str, mfa_code: &str, method: MfaMethod) -> Result<Session, anyhow::Error> {
        match method {
            MfaMethod::Totp => {
                if let Some(totp_manager) = &self.totp_manager {
                    if totp_manager.verify_code(mfa_code) {
                        let session = self.session_manager.create_session(user_id)?;
                        Ok(session)
                    } else {
                        Err(anyhow::anyhow!("Invalid TOTP code"))
                    }
                } else {
                    Err(anyhow::anyhow!("TOTP not configured"))
                }
            },
            _ => {
                // Fallback to default MFA verification
                if self.mfa_manager.verify_code(user_id, mfa_code)? {
                    let session = self.session_manager.create_session(user_id)?;
                    Ok(session)
                } else {
                    Err(anyhow::anyhow!("Invalid MFA code"))
                }
            }
        }
    }

    /// Setup TOTP for a user
    pub fn setup_totp(&mut self, user_id: &str) -> Result<Vec<u8>, anyhow::Error> {
        let totp_config = TotpManager::generate("Forge DevEnv", user_id)?;
        let totp_manager = TotpManager::new(totp_config.clone())?;
        
        // Generate QR code for authenticator app
        let qr_code = totp_manager.generate_qr_code()?;
        
        // TODO: Save TOTP configuration for the user
        
        Ok(qr_code)
    }

    /// Retrieve a secret value
    pub fn get_secret(&self, key: &str) -> Option<String> {
        self.secrets_manager.get_secret(key)
            .map(|s| s.expose_secret().to_string())
    }

    /// Set a secret value
    pub fn set_secret(&mut self, key: &str, value: &str) -> Result<(), anyhow::Error> {
        self.secrets_manager.set_secret(key, value)
    }

    /// Generate recovery codes for a user
    pub fn generate_recovery_codes(&self, user_id: &str) -> Result<Vec<String>, anyhow::Error> {
        self.recovery_manager.generate_recovery_codes(user_id)
    }

    /// Validate a recovery code
    pub fn validate_recovery_code(&mut self, recovery_code: &str, user_id: &str) -> Result<bool, anyhow::Error> {
        self.recovery_manager.validate_recovery_code(recovery_code, user_id)
    }

    /// Revoke all recovery codes
    pub fn revoke_recovery_codes(&mut self) -> Result<(), anyhow::Error> {
        self.recovery_manager.revoke_all_recovery_codes()
    }

    /// Store sensitive credential
    pub fn store_sensitive_credential(&self, name: &str, credential_type: CredentialType, raw_credential: &[u8]) -> Result<Uuid, anyhow::Error> {
        self.credential_vault.store_credential(
            name, 
            credential_type, 
            raw_credential
        ).map_err(|e| anyhow::anyhow!(e))
    }

    /// Retrieve sensitive credential
    pub fn retrieve_sensitive_credential(&self, credential_id: &Uuid) -> Result<Vec<u8>, anyhow::Error> {
        self.credential_vault.retrieve_credential(credential_id)
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// List all stored credentials
    pub fn list_sensitive_credentials(&self) -> Result<Vec<SecureCredential>, anyhow::Error> {
        self.credential_vault.list_credentials()
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Delete a specific credential
    pub fn delete_sensitive_credential(&self, credential_id: &Uuid) -> Result<(), anyhow::Error> {
        self.credential_vault.delete_credential(credential_id)
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Check geolocation-based access for a resource
    pub async fn check_geolocation_access(&self, resource_id: &str, ip_address: std::net::IpAddr) -> Result<bool, anyhow::Error> {
        self.geolocation_access_control
            .is_access_allowed(resource_id, ip_address)
            .await
    }

    /// Add a new geolocation access policy
    pub fn add_geolocation_policy(&mut self, resource_id: String, policy: GeoAccessPolicy) {
        self.geolocation_access_control
            .add_policy(resource_id, policy);
    }

    /// Lookup IP geolocation details
    pub async fn lookup_ip_geolocation(&self, ip_address: std::net::IpAddr) -> Result<GeoLocation, anyhow::Error> {
        self.geolocation_service
            .lookup_ip(ip_address)
            .await
    }

    /// Create a new user
    pub async fn create_user(&self, username: String, password: String, role: UserRole) -> Result<User> {
        let user = self.access_control.create_user(username, password, role)?;
        Ok(user)
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<User>> {
        let users = self.access_control.list_users()?;
        Ok(users)
    }

    /// Delete a user
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        self.access_control.delete_user(user_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_password_validation() {
        let config = SecurityConfig::default();

        // Valid passwords
        assert!(validate_password("StrongP@ssw0rd123", &config).is_ok());
        
        // Invalid passwords
        assert!(validate_password("short", &config).is_err());
        assert!(validate_password("nospecia1chars", &config).is_err());
        assert!(validate_password("nonum3ers!", &config).is_err());
    }

    #[test]
    fn test_security_auditor() {
        let temp_dir = tempdir().unwrap();
        let auditor = SecurityAuditor::new(temp_dir.path()).unwrap();

        auditor.log_event("LOGIN_ATTEMPT", "User testuser logged in").unwrap();
        
        // Verify log file was created and written
        let log_contents = std::fs::read_to_string(temp_dir.path().join("security_audit.log")).unwrap();
        assert!(log_contents.contains("LOGIN_ATTEMPT"));
    }
}
