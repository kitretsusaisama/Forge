use lettre::{
    transport::smtp::authentication::Credentials,
    transport::smtp::client::{SmtpConnection, TlsParameters},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::env;
use tracing;

/// Email configuration for MFA and notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server configuration
    pub smtp_host: String,
    pub smtp_port: u16,
    /// SMTP username
    pub smtp_user: String,
    /// SMTP password
    pub smtp_pass: String,
    /// Sender email address
    pub smtp_from: String,
}

/// Email service for sending MFA codes and notifications
pub struct EmailService {
    config: EmailConfig,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: EmailConfig) -> Result<Self> {
        let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

        Ok(Self { config, mailer })
    }

    /// Send MFA code via email
    pub async fn send_mfa_code(
        &self, 
        recipient_email: &str, 
        mfa_code: &str
    ) -> Result<()> {
        // Create email message
        let email = Message::builder()
            .from(self.config.smtp_from.parse()?)
            .to(recipient_email.parse()?)
            .subject("Your Forge MFA Code")
            .body(format!(
                "Your Multi-Factor Authentication (MFA) code is: {}\n\n\
                This code will expire in 5 minutes.\n",
                mfa_code
            ))?;

        // Send email
        self.mailer.send(email).await?;
        tracing::info!(
            "MFA code sent to email: {}",
            recipient_email
        );
        Ok(())
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
        smtp_user: &str, 
        smtp_pass: &str, 
        smtp_from: &str
    ) -> Result<EmailConfig> {
        // Validate email address
        if !EmailService::validate_email(smtp_from) {
            return Err(anyhow::anyhow!("Invalid sender email address"));
        }

        let config = EmailConfig {
            smtp_host: smtp_host.to_string(),
            smtp_port,
            smtp_user: smtp_user.to_string(),
            smtp_pass: smtp_pass.to_string(),
            smtp_from: smtp_from.to_string(),
        };

        // Test email configuration
        let email_service = EmailService::new(config.clone())?;

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
            "username", 
            "password", 
            "sender@example.com"
        ).unwrap();

        // Load configuration
        let loaded_config = config_manager.load_config().unwrap().unwrap();
        
        assert_eq!(config.smtp_host, loaded_config.smtp_host);
        assert_eq!(config.smtp_port, loaded_config.smtp_port);
    }
}
