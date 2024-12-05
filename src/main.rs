use std::sync::Arc;
use std::time::Duration;
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
    CloudSyncConfig,
    CloudProvider,
    CloudAuthMethod,
    CloudProviderType,
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
    /// Manage cloud secret synchronization
    CloudSync {
        #[command(subcommand)]
        command: CloudSyncCommand,
    },
    /// Manage cloud provider encryption keys
    CloudKeys {
        #[command(subcommand)]
        command: CloudKeysCommand,
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

/// Cloud synchronization subcommands
#[derive(Subcommand)]
enum CloudSyncCommand {
    /// Configure cloud synchronization
    Configure {
        /// Cloud provider (aws, gcp, azure, custom)
        #[arg(long)]
        provider: String,

        /// Cloud service endpoint
        #[arg(long)]
        endpoint: String,

        /// Authentication method (oauth, service-account, api-key)
        #[arg(long)]
        auth_method: String,

        /// Client ID for OAuth
        #[arg(long)]
        client_id: Option<String>,

        /// Client secret for OAuth
        #[arg(long)]
        client_secret: Option<String>,

        /// API key for authentication
        #[arg(long)]
        api_key: Option<String>,

        /// Path to service account key file
        #[arg(long)]
        service_account_key: Option<String>,

        /// Enable automatic synchronization
        #[arg(long)]
        auto_sync: bool,

        /// Sync frequency in minutes
        #[arg(long, default_value = "30")]
        sync_frequency: u32,
    },

    /// Synchronize secrets with cloud provider
    Sync,

    /// View recent synchronization history
    History {
        /// Number of recent sync entries to display
        #[arg(long, default_value = "10")]
        limit: usize,
    },
}

/// Cloud key management subcommands
#[derive(Subcommand)]
enum CloudKeysCommand {
    /// Generate a new encryption key for a cloud provider
    Generate {
        /// Cloud provider (aws, gcp, azure)
        #[arg(long)]
        provider: String,
    },

    /// Rotate encryption key for a cloud provider
    Rotate {
        /// Cloud provider (aws, gcp, azure)
        #[arg(long)]
        provider: String,
    },

    /// List all stored cloud provider encryption keys
    List,

    /// Retrieve details about a specific encryption key
    Describe {
        /// Key identifier
        #[arg(long)]
        key_id: String,
    },
}

// New Machine Learning Performance Prediction Module
#[cfg(feature = "ml-performance")]
mod ml {
    pub mod performance_predictor;
}

// New Distributed Tracing Module
#[cfg(feature = "distributed-tracing")]
mod tracing {
    pub mod distributed_tracer;
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

    // Initialize security service with configuration
    let security_service = AdvancedSecurityService::new(SecurityConfig {
        jwt_secret: settings.security_keys().0,
        encryption_key: settings.security_keys().1,
        mfa_secret_key: settings.security_keys().2,
        password_hash_rounds: settings.security.password_hash_rounds,
        session_timeout: Duration::minutes(settings.security.session_timeout_minutes as i64),
        mfa_code_length: settings.security.mfa_code_length,
        mfa_code_expiry: Duration::seconds(settings.security.mfa_code_expiry_seconds as i64),
    })?;

    // Initialize email service
    let (smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from) = settings.email_credentials();
    let email_service = EmailService::new(
        smtp_host,
        smtp_port.parse()?,
        smtp_user,
        smtp_pass,
        smtp_from,
    )?;

    // Initialize AWS cloud provider if configured
    let (aws_key, aws_secret, aws_region) = settings.aws_credentials();
    let cloud_provider = if !aws_key.is_empty() {
        Some(Arc::new(AwsCloudProvider::new(AwsConfig {
            access_key_id: aws_key,
            secret_access_key: aws_secret,
            region: aws_region,
        })) as Arc<dyn CloudProvider>)
    } else {
        None
    };

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
                smtp_port: *smtp_port,
                sender_email: sender_email.to_string(),
                use_tls: true,
                username: username.clone(),
                password: password.clone(),
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
        Commands::CloudSync { command } => {
            match command {
                CloudSyncCommand::Configure { 
                    provider, 
                    endpoint, 
                    auth_method,
                    client_id,
                    client_secret,
                    api_key,
                    service_account_key,
                    auto_sync,
                    sync_frequency,
                } => {
                    // Parse cloud provider
                    let cloud_provider = match provider.to_lowercase().as_str() {
                        "aws" => CloudProvider::AWS,
                        "gcp" => CloudProvider::GCP,
                        "azure" => CloudProvider::Azure,
                        _ => CloudProvider::Custom(provider.clone()),
                    };

                    // Parse authentication method
                    let auth_method = match auth_method.to_lowercase().as_str() {
                        "oauth" => CloudAuthMethod::OAuth {
                            client_id: client_id.clone().unwrap_or_default(),
                            client_secret: client_secret.clone().unwrap_or_default(),
                        },
                        "api-key" => CloudAuthMethod::ApiKey {
                            api_key: api_key.clone().unwrap_or_default(),
                        },
                        "service-account" => CloudAuthMethod::ServiceAccount {
                            key_path: service_account_key.clone()
                                .unwrap_or_else(|| "service_account.json".to_string()),
                        },
                        _ => return Err(anyhow::anyhow!("Invalid authentication method")),
                    };

                    // Update cloud sync configuration
                    let cloud_sync_config = CloudSyncConfig {
                        provider: cloud_provider,
                        endpoint: endpoint.clone(),
                        auth_method,
                        sync_frequency: *sync_frequency,
                        auto_sync: *auto_sync,
                    };

                    // TODO: Implement secure configuration storage
                    println!("Cloud sync configuration updated.");
                },

                CloudSyncCommand::Sync => {
                    // Retrieve secrets for synchronization
                    let secrets = security_service
                        .secrets_manager
                        .get_all_secrets()?;

                    // Perform cloud synchronization
                    let sync_metadata = security_service
                        .synchronize_secrets(&secrets)
                        .await?;

                    println!("Secrets synchronized successfully:");
                    println!("Sync ID: {}", sync_metadata.sync_id);
                    println!("Timestamp: {}", sync_metadata.timestamp);
                    println!("Secrets Count: {}", sync_metadata.secrets_count);
                    println!("Status: {:?}", sync_metadata.status);
                },

                CloudSyncCommand::History { limit } => {
                    // Retrieve recent sync history
                    let sync_history = security_service
                        .get_recent_sync_history(*limit)?;

                    println!("Recent Sync History:");
                    for (i, entry) in sync_history.iter().enumerate() {
                        println!("{}. Sync ID: {}", i + 1, entry.sync_id);
                        println!("   Timestamp: {}", entry.timestamp);
                        println!("   Secrets Count: {}", entry.secrets_count);
                        println!("   Status: {:?}", entry.status);
                        println!();
                    }
                },
            }
        },
        Commands::CloudKeys { command } => {
            match command {
                CloudKeysCommand::Generate { provider } => {
                    // Parse cloud provider
                    let cloud_provider = match provider.to_lowercase().as_str() {
                        "aws" => CloudProviderType::AWS,
                        "gcp" => CloudProviderType::GCP,
                        "azure" => CloudProviderType::Azure,
                        _ => return Err(anyhow::anyhow!("Unsupported cloud provider")),
                    };

                    // Create key manager
                    let key_manager = security_service.create_cloud_key_manager()?;

                    // Generate key
                    let key = key_manager.generate_key(&cloud_provider)?;

                    println!("New encryption key generated for {} provider", provider);
                    println!("Key Length: {} bytes", key.len());
                },

                CloudKeysCommand::Rotate { provider } => {
                    // Parse cloud provider
                    let cloud_provider = match provider.to_lowercase().as_str() {
                        "aws" => CloudProviderType::AWS,
                        "gcp" => CloudProviderType::GCP,
                        "azure" => CloudProviderType::Azure,
                        _ => return Err(anyhow::anyhow!("Unsupported cloud provider")),
                    };

                    // Rotate key
                    let key_id = security_service
                        .rotate_cloud_provider_key(cloud_provider)
                        .await?;

                    println!("Encryption key rotated for {} provider", provider);
                    println!("New Key ID: {}", key_id);
                },

                CloudKeysCommand::List => {
                    // List all keys
                    let keys = security_service.list_cloud_provider_keys()?;

                    if keys.is_empty() {
                        println!("No cloud provider encryption keys found.");
                    } else {
                        println!("Cloud Provider Encryption Keys:");
                        for key in keys {
                            println!("- {}", key);
                        }
                    }
                },

                CloudKeysCommand::Describe { key_id } => {
                    // Create key manager
                    let key_manager = security_service.create_cloud_key_manager()?;

                    // Retrieve key details
                    let key = key_manager.retrieve_key(key_id)?;

                    println!("Key Details:");
                    println!("Key ID: {}", key_id);
                    println!("Key Length: {} bytes", key.len());
                },
            }
        },
    }

    // Initialize Performance Predictor if ML feature is enabled
    #[cfg(feature = "ml-performance")]
    {
        let ml_config = ml::performance_predictor::PerformancePredictorConfig {
            history_window: 100,
            prediction_horizon: 10,
            model_type: ml::performance_predictor::ModelType::LinearRegression,
        };
        let mut performance_predictor = ml::performance_predictor::PerformancePredictor::new(ml_config);
        
        // Example: Record some initial performance data
        performance_predictor.record_performance(
            ml::performance_predictor::PerformanceDataPoint {
                features: vec![1.0, 2.0, 3.0],
                target: 0.5,
            }
        )?;
        
        performance_predictor.train_model()?;
    }

    // Initialize Distributed Tracer if tracing feature is enabled
    #[cfg(feature = "distributed-tracing")]
    {
        let tracing_config = tracing::distributed_tracer::DistributedTracingConfig {
            enabled: true,
            sampling_rate: 1.0,
            max_trace_duration: std::time::Duration::from_secs(10),
            storage: tracing::distributed_tracer::TraceStorageConfig {
                storage_type: tracing::distributed_tracer::StorageType::InMemory,
                max_traces: 100,
                retention_period: std::time::Duration::from_secs(3600),
            },
        };
        let mut distributed_tracer = tracing::distributed_tracer::DistributedTracer::new(tracing_config);
        
        // Example: Start and end a trace
        let trace_id = distributed_tracer.start_trace("main_initialization", None);
        let span_id = distributed_tracer.start_span(trace_id, "module_setup").unwrap();
        
        // Simulate some work
        std::thread::sleep(std::time::Duration::from_millis(50));
        
        distributed_tracer.end_span(trace_id, span_id)?;
        distributed_tracer.end_trace(trace_id)?;
        
        // Analyze traces
        let performance_insights = distributed_tracer.analyze_traces();
        println!("Performance Insights: {:?}", performance_insights);
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
