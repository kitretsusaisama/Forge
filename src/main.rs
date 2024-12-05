use std::sync::Arc;
use chrono::Duration;
use anyhow::{Result, Context};
use tracing::info;
use tracing_subscriber;
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use directories::ProjectDirs;
use env_logger;
use tokio;

mod core;
mod environments;
mod config;
mod docker;
mod storage;
mod detection;
mod plugins;
mod monitoring;
mod security;
mod templates;
mod agents;
mod api;

use environments::EnvironmentManager;
use security::{
    AdvancedSecurityService, 
    SecurityConfig, 
    MfaMethod,
    UserRole,
    EmailConfig,
    AccessControlManager, 
    SessionManager, 
    Permission,
    SecretsManager,
    RecoveryConfig,
    validate_password,
};
use templates::TemplateManager;
use agents::{AgentOrchestrator, OptimizationAgent, SecurityAgent};
use api::{APIManager, APIEndpoint, HttpMethod, RetryConfiguration, BackoffStrategy};

use crate::config::Settings;
use crate::security::{EmailService, GeolocationService, EmailConfigManager};
use crate::monitoring::TELEMETRY;
use crate::config::AwsConfig;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new development environment
    Create {
        /// Name of the environment
        name: String,
        /// Type of environment (devcontainer, nix, flox, auto)
        #[arg(short, long, default_value = "auto")]
        env_type: String,
    },
    /// List all environments
    List,
    /// Start an existing environment
    Start {
        /// Name of the environment
        name: String,
    },
    /// Stop an environment
    Stop {
        /// Name of the environment
        name: String,
    },
    /// Delete an environment
    Delete {
        /// Name of the environment
        name: String,
    },
    /// Discover environments in the base directory
    Discover,
    /// Check Docker availability
    DockerCheck,
    /// List available environment detection plugins
    ListPlugins,
    /// User management commands
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Login to the system
    Login {
        /// Username
        username: String,
        /// Password
        #[arg(short, long)]
        password: String,
    },
    /// Verify Multi-Factor Authentication code
    VerifyMfa {
        /// User ID
        user_id: String,
        /// MFA Code
        code: String,
    },
    /// Logout and invalidate current session
    Logout,
    /// Setup Multi-Factor Authentication
    SetupMfa {
        /// MFA Method (totp, email)
        method: String,
        
        /// User ID for MFA setup
        user_id: String,
    },

    /// Configure Email for MFA
    ConfigureEmail {
        /// SMTP Host
        #[arg(long)]
        smtp_host: String,
        
        /// SMTP Port
        #[arg(long, default_value = "587")]
        smtp_port: u16,
        
        /// Sender Email
        #[arg(long)]
        sender_email: String,
        
        /// SMTP Username (optional)
        #[arg(long)]
        username: Option<String>,
        
        /// SMTP Password (optional)
        #[arg(long)]
        password: Option<String>,
    },
    /// Manage secrets
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Manage secret recovery
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
}

/// User management subcommands
#[derive(Subcommand)]
enum UserCommand {
    /// Create a new user
    Create {
        /// Username
        username: String,
        /// Password
        #[arg(short, long)]
        password: String,
        /// User role (guest, developer, admin)
        #[arg(short, long, default_value = "developer")]
        role: String,
    },
    /// Delete an existing user
    Delete {
        /// Username
        username: String,
    },
    /// List all users
    List,
}

/// Secret management subcommands
#[derive(Subcommand)]
enum SecretCommand {
    /// Set a secret value
    Set {
        /// Secret key
        key: String,
        /// Secret value
        value: String,
    },
    /// Get a secret value (masked)
    Get {
        /// Secret key
        key: String,
    },
    /// List all configured secret keys
    List,
}

/// Recovery management subcommands
#[derive(Subcommand)]
enum RecoveryCommand {
    /// Generate recovery codes for a user
    Generate {
        /// User ID for which recovery codes are generated
        #[arg(long)]
        user_id: String,
    },
    /// Validate a recovery code
    Validate {
        /// Recovery code to validate
        #[arg(long)]
        code: String,

        /// User ID associated with the recovery code
        #[arg(long)]
        user_id: String,
    },
    /// Revoke all recovery codes
    Revoke,
}

fn get_project_dirs() -> Result<directories::ProjectDirs> {
    directories::ProjectDirs::from("com", "devenv", "forge")
        .context("Failed to get project directories")
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file
    dotenv().ok();

    // Load configuration
    let settings = Settings::new()?;

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&settings.log_level))
        .init();

    // Initialize security service configuration
    use std::time::Duration;
    use crate::security::{SecurityConfig, MfaMethod};
    use std::collections::HashMap;

    let security_config = SecurityConfig {
        enabled: true,
        password_min_length: 8,
        require_special_chars: true,
        require_numbers: true,
        require_uppercase: true,
        require_lowercase: true,
        max_failed_attempts: 5,
        lockout_duration: Duration::from_secs(1800), // 30 minutes
        password_expiry_days: 90,
        session_timeout: Duration::from_secs(settings.security.session_timeout_minutes * 60),
        mfa_code_length: settings.security.mfa_code_length as u8,
        mfa_code_expiry: Duration::from_secs(settings.security.mfa_code_expiry_seconds),
        allowed_mfa_methods: vec![MfaMethod::Totp, MfaMethod::Email],
        geolocation_policies: HashMap::new(),
        jwt_secret: settings.security_keys().0.clone(),
        encryption_key: settings.security_keys().1.clone(),
        mfa_secret_key: settings.security_keys().2.clone(),
    };

    // Initialize security service with configuration
    let security_service = AdvancedSecurityService::new(
        std::path::Path::new(&settings.base_dir),
        security_config
    )?;

    // Initialize email service
    let (smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from) = settings.email_credentials();
    let email_config = EmailConfig {
        smtp_host: smtp_host.to_string(),
        smtp_port,
        smtp_user: smtp_user.to_string(),
        smtp_pass: smtp_pass.to_string(),
        smtp_from: smtp_from.to_string(),
    };
    let email_service = EmailService::new(email_config)?;

    // Initialize geolocation service
    let (geo_api_key, geo_api_url) = settings.geolocation_config();
    let geo_service = GeolocationService::new(
        geo_api_key,
        geo_api_url,
    )?;

    // Initialize telemetry (optional: can pass custom config)
    let telemetry_config = monitoring::TelemetryConfig {
        enabled: true,
        log_level: monitoring::LogLevel::Info,
        log_directory: None,
        anonymize_data: true,
    };
    monitoring::init_telemetry(telemetry_config);

    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Initialize base directory for configuration
    let base_dir = get_project_dirs()?.data_dir().to_path_buf();

    // Initialize secrets manager
    let secrets_manager = SecretsManager::new(&base_dir)?;
    secrets_manager.load_env()?;
    secrets_manager.init_secrets()?;

    // Initialize environment manager
    let env_manager = EnvironmentManager::new().await?;
    
    let cli = Cli::parse();
    
    info!("Dev Environment Manager starting up...");
    
    match &cli.command {
        Commands::Create { name, env_type } => {
            track_performance!("environment_creation");
            match env_manager.create_environment(name, Some(env_type)).await {
                Ok(env) => {
                    TELEMETRY.log_environment_creation(name, env_type, true);
                    info!("Environment created successfully: {:?}", env);
                },
                Err(e) => {
                    log_error!(&e, "Failed to create environment");
                    TELEMETRY.log_environment_creation(name, env_type, false);
                    return Err(e);
                }
            }
        }
        Commands::List => {
            track_performance!("list_environments");
            let environments = env_manager.list_environments().await?;
            if environments.is_empty() {
                println!("No environments found.");
            } else {
                println!("Environments:");
                for env in environments {
                    println!("- {} (Type: {}, Status: {})", 
                        env.name, env.env_type, env.status);
                }
            }
        }
        Commands::Start { name } => {
            track_performance!("start_environment");
            info!("Starting environment '{}'", name);
            env_manager.start_environment(name).await?;
            info!("Environment '{}' started successfully", name);
        }
        Commands::Stop { name } => {
            track_performance!("stop_environment");
            info!("Stopping environment '{}'", name);
            env_manager.stop_environment(name).await?;
            info!("Environment '{}' stopped successfully", name);
        }
        Commands::Delete { name } => {
            track_performance!("delete_environment");
            info!("Deleting environment '{}'", name);
            let deleted = env_manager.delete_environment(name).await?;
            if deleted {
                info!("Environment '{}' deleted successfully", name);
            } else {
                info!("No environment named '{}' found", name);
            }
        }
        Commands::Discover => {
            track_performance!("discover_environments");
            info!("Discovering environments in base directory");
            let environments = env_manager.find_environments().await?;
            if environments.is_empty() {
                println!("No environments discovered.");
            } else {
                println!("Discovered Environments:");
                for env in environments {
                    println!("- {} (Type: {}, Path: {})", 
                        env.name, env.env_type, env.path.display());
                }
            }
        }
        Commands::DockerCheck => {
            track_performance!("docker_check");
            #[cfg(feature = "docker")]
            {
                use crate::docker::DockerClient;
                let is_available = DockerClient::is_docker_available();
                println!("Docker is {}", if is_available { "available" } else { "not available" });
            }
            
            #[cfg(not(feature = "docker"))]
            {
                println!("Docker support is not compiled into this build");
            }
        }
        Commands::ListPlugins => {
            track_performance!("list_plugins");
            let plugins = env_manager.list_plugins();
            
            println!("Available Environment Detection Plugins:");
            for (id, name) in plugins {
                println!("- {}: {}", id, name);
            }
        }
        Commands::User { command } => {
            match command {
                UserCommand::Create { username, password, role } => {
                    // Validate password
                    validate_password(password, &security_service.security_config)
                        .map_err(|e| anyhow::anyhow!(e))?;

                    // Map role string to UserRole
                    let user_role = match role.to_lowercase().as_str() {
                        "guest" => UserRole::Guest,
                        "admin" => UserRole::Administrator,
                        _ => UserRole::Developer,
                    };

                    let user = security_service.create_user(username.to_string(), password.to_string(), user_role).await?;
                    println!("User '{}' created successfully with ID: {}", username, user.id);
                },
                UserCommand::Delete { username } => {
                    // Find user by username first
                    let users = security_service.list_users().await?;
                    let user = users.iter()
                        .find(|u| u.username == *username)
                        .context("User not found")?;

                    let deleted = security_service.delete_user(&user.id).await?;
                    if deleted {
                        println!("User '{}' deleted successfully", username);
                    } else {
                        println!("User '{}' not found", username);
                    }
                },
                UserCommand::List => {
                    let users = security_service.list_users().await?;
                    println!("Registered Users:");
                    for user in users {
                        println!(
                            "ID: {}, Username: {}, Role: {:?}", 
                            user.id, user.username, user.role
                        );
                    }
                },
            }
        },
        Commands::Login { username, password } => {
            match security_service.authenticate(username, password)? {
                Some(session) => {
                    println!(
                        "Login successful. Welcome, {}! Session ID: {}", 
                        username, 
                        session.id
                    );
                },
                None => {
                    println!("MFA required. Please verify your identity.");
                }
            }
        },
        Commands::VerifyMfa { user_id, code } => {
            match security_service.verify_mfa(&user_id, &code) {
                Ok(session) => {
                    println!(
                        "MFA verification successful. Session ID: {}", 
                        session.id
                    );
                },
                Err(e) => {
                    println!("MFA verification failed: {}", e);
                }
            }
        },
        Commands::Logout => {
            // TODO: Implement session management and logout
            println!("Logout functionality not yet implemented");
        },
        Commands::SetupMfa { method, user_id } => {
            match method.to_lowercase().as_str() {
                "totp" => {
                    let qr_code = security_service.setup_totp(user_id)?;
                    
                    // Save QR code to a file or display instructions
                    let qr_path = base_dir.join(format!("{}_totp_qr.svg", user_id));
                    std::fs::write(&qr_path, qr_code)?;
                    
                    println!(
                        "TOTP QR code saved to {}. Scan with your authenticator app.", 
                        qr_path.display()
                    );
                },
                "email" => {
                    println!("Email MFA setup requires email configuration first.");
                },
                _ => {
                    println!("Unsupported MFA method. Use 'totp' or 'email'.");
                }
            }
        },

        Commands::ConfigureEmail { 
            smtp_host, 
            smtp_port, 
            sender_email, 
            username, 
            password 
        } => {
            let email_config = EmailConfig {
                smtp_host: smtp_host.to_string(),
                smtp_port,
                smtp_user: username.clone().unwrap_or_default(),
                smtp_pass: password.clone().unwrap_or_default(),
                smtp_from: sender_email.to_string(),
            };

            // Validate and save email configuration
            let email_config_manager = EmailConfigManager::new(&base_dir)?;
            email_config_manager.set_config(
                smtp_host, 
                *smtp_port, 
                sender_email, 
                username.as_deref(), 
                password.as_deref()
            )?;

            println!("Email configuration saved successfully.");
        },
        Commands::Secret { command } => {
            match command {
                SecretCommand::Set { key, value } => {
                    // Validate and set secret
                    security_service.set_secret(key, value)?;
                    println!("Secret '{}' set successfully.", key);
                },
                SecretCommand::Get { key } => {
                    // Retrieve secret (masked)
                    match security_service.get_secret(key) {
                        Some(_) => println!("Secret '{}' exists.", key),
                        None => println!("Secret '{}' not found.", key),
                    }
                },
                SecretCommand::List => {
                    // TODO: Implement secure secret listing
                    println!("Secret listing not yet implemented.");
                },
            }
        },
        Commands::Recovery { command } => {
            match command {
                RecoveryCommand::Generate { user_id } => {
                    // Generate recovery codes
                    let recovery_codes = security_service
                        .generate_recovery_codes(user_id)?;
                    
                    println!("Recovery Codes Generated:");
                    for (i, code) in recovery_codes.iter().enumerate() {
                        println!("Code {}: {}", i + 1, code);
                    }
                },
                RecoveryCommand::Validate { code, user_id } => {
                    // Validate recovery code
                    let is_valid = security_service
                        .validate_recovery_code(code, user_id)?;
                    
                    if is_valid {
                        println!("Recovery code is valid.");
                    } else {
                        println!("Recovery code is invalid or expired.");
                    }
                },
                RecoveryCommand::Revoke => {
                    // Revoke all recovery codes
                    security_service.revoke_recovery_codes()?;
                    println!("All recovery codes revoked.");
                },
            }
        },
    }

    // Initialize template manager
    let mut template_manager = TemplateManager::new(
        std::path::PathBuf::from("./templates")
    );
    template_manager.load_templates().await?;

    // Setup AI agent orchestrator
    let mut agent_orchestrator = AgentOrchestrator::new();
    
    // Register optimization and security agents
    agent_orchestrator.register_agent(
        OptimizationAgent::new()
    );
    agent_orchestrator.register_agent(
        SecurityAgent::new()
    );

    // Execute agents
    let agent_results = agent_orchestrator.execute_all().await?;
    for result in agent_results {
        println!("Agent Result: {:?}", result);
    }

    // Initialize API manager
    let api_manager = APIManager::new();

    // Example API endpoint registration
    let example_endpoint = APIEndpoint {
        id: uuid::Uuid::new_v4(),
        name: "Example Endpoint".to_string(),
        url: "https://api.example.com/data".to_string(),
        method: HttpMethod::GET,
        authentication: None,
        retry_config: RetryConfiguration {
            max_retries: 3,
            base_delay: std::time::Duration::from_millis(100),
            backoff_strategy: BackoffStrategy::Exponential,
        },
    };

    api_manager.register_endpoint(example_endpoint).await?;

    Ok(())
}
