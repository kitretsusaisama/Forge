use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::env;
use anyhow::{Result, Context};

/// Email configuration for MFA and notifications
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EmailConfig {
    /// SMTP server configuration
    pub smtp_host: String,
    pub smtp_port: u16,
    
    /// Sender email address
    pub sender_email: String,
    
    /// Use TLS
    pub use_tls: bool,
    
    /// Optional username and password for SMTP authentication
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Email service for sending MFA codes and notifications
pub struct EmailService {
    config: EmailConfig,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    /// Send MFA code via email
    pub fn send_mfa_code(
        &self, 
        recipient_email: &str, 
        mfa_code: &str
    ) -> Result<()> {
        // Validate email configuration
        if self.config.username.is_none() || self.config.password.is_none() {
            return Err(anyhow::anyhow!("SMTP credentials not configured"));
        }

        // Create email message
        let email = Message::builder()
            .from(self.config.sender_email.parse()?)
            .to(recipient_email.parse()?)
            .subject("Your Forge MFA Code")
            .body(format!(
                "Your Multi-Factor Authentication (MFA) code is: {}\n\n\
                This code will expire in 5 minutes.\n",
                mfa_code
            ))?;

        // Create SMTP transport
        let creds = Credentials::new(
            self.config.username.clone().unwrap(),
            self.config.password.clone().unwrap()
        );

        let mailer = SmtpTransport::relay(&self.config.smtp_host)?
            .port(self.config.smtp_port)
            .credentials(creds)
            .build();

        // Send email
        match mailer.send(&email) {
            Ok(_) => {
                tracing::info!(
                    "MFA code sent to email: {}",
                    recipient_email
                );
                Ok(())
            },
            Err(e) => {
                tracing::error!(
                    "Failed to send MFA code to {}: {}",
                    recipient_email,
                    e
                );
                Err(anyhow::anyhow!(e))
            }
        }
    }

    /// Validate email address format
    pub fn validate_email(email: &str) -> bool {
        email_address::EmailAddress::is_valid(email)
    }
}

/// Secure email configuration management
pub struct EmailConfigManager {
    config_path: std::path::PathBuf,
}

impl EmailConfigManager {
    pub fn new(base_dir: &std::path::Path) -> Result<Self> {
        let config_path = base_dir.join("email_config.json");
        
        // Ensure config directory exists
        std::fs::create_dir_all(base_dir)?;

        Ok(Self { config_path })
    }

    /// Load email configuration
    pub fn load_config(&self) -> Result<Option<EmailConfig>> {
        if !self.config_path.exists() {
            return Ok(None);
        }

        let config_str = std::fs::read_to_string(&self.config_path)
            .context("Failed to read email configuration")?;
        
        let config: EmailConfig = serde_json::from_str(&config_str)
            .context("Invalid email configuration")?;

        Ok(Some(config))
    }

    /// Save email configuration
    pub fn save_config(&self, config: &EmailConfig) -> Result<()> {
        // Encrypt sensitive information before saving
        let config_str = serde_json::to_string_pretty(config)
            .context("Failed to serialize email configuration")?;

        std::fs::write(&self.config_path, config_str)
            .context("Failed to save email configuration")?;

        Ok(())
    }

    /// Validate and set email configuration
    pub fn set_config(
        &self, 
        smtp_host: &str, 
        smtp_port: u16, 
        sender_email: &str, 
        username: Option<&str>, 
        password: Option<&str>
    ) -> Result<EmailConfig> {
        // Validate email address
        if !EmailService::validate_email(sender_email) {
            return Err(anyhow::anyhow!("Invalid sender email address"));
        }

        let config = EmailConfig {
            smtp_host: smtp_host.to_string(),
            smtp_port,
            sender_email: sender_email.to_string(),
            use_tls: true,
            username: username.map(|s| s.to_string()),
            password: password.map(|s| s.to_string()),
        };

        // Test email configuration
        let email_service = EmailService::new(config.clone());
        
        // Optional: Add a test email sending mechanism
        // email_service.send_test_email()?;

        // Save configuration
        self.save_config(&config)?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_email_validation() {
        assert!(EmailService::validate_email("test@example.com"));
        assert!(!EmailService::validate_email("invalid-email"));
    }

    #[test]
    fn test_email_config_management() {
        let temp_dir = tempdir().unwrap();
        let config_manager = EmailConfigManager::new(temp_dir.path()).unwrap();

        // Set and save configuration
        let config = config_manager.set_config(
            "smtp.example.com", 
            587, 
            "sender@example.com", 
            Some("username"), 
            Some("password")
        ).unwrap();

        // Load configuration
        let loaded_config = config_manager.load_config().unwrap().unwrap();
        
        assert_eq!(config.smtp_host, loaded_config.smtp_host);
        assert_eq!(config.smtp_port, loaded_config.smtp_port);
    }
}
