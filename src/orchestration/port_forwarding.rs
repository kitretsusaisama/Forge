use anyhow::{Result, Context};
use hyper::{
    client::HttpConnector, 
    Client, 
    Request, 
    Body, 
    Uri
};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Port forwarding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardingConfig {
    pub id: Uuid,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub subdomain: Option<String>,
    pub protocol: ForwardingProtocol,
    pub authentication: Option<ForwardingAuthentication>,
}

/// Forwarding protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardingProtocol {
    TCP,
    HTTP,
    HTTPS,
}

/// Authentication method for port forwarding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardingAuthentication {
    Basic { username: String, password: String },
    Token(String),
    OAuth {
        client_id: String,
        client_secret: String,
        token_url: String,
    },
}

/// Port forwarding service
pub struct PortForwardingService {
    /// Active forwarding configurations
    active_forwards: Arc<RwLock<HashMap<Uuid, PortForwardingConfig>>>,
    
    /// Tracking of active tunnels
    active_tunnels: Arc<Mutex<HashMap<Uuid, tokio::task::JoinHandle<()>>>>,
}

impl PortForwardingService {
    /// Create a new port forwarding service
    pub fn new() -> Self {
        Self {
            active_forwards: Arc::new(RwLock::new(HashMap::new())),
            active_tunnels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new port forwarding tunnel
    pub async fn create_tunnel(&self, config: PortForwardingConfig) -> Result<Uuid> {
        // Validate configuration
        self.validate_config(&config)?;

        // Create listener
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            config.local_port
        )).await?;

        // Clone configurations for async move
        let forward_config = config.clone();
        let active_forwards = Arc::clone(&self.active_forwards);
        let active_tunnels = Arc::clone(&self.active_tunnels);

        // Spawn tunnel task
        let tunnel_task = tokio::spawn(async move {
            loop {
                // Accept incoming connection
                let (mut client_socket, _) = match listener.accept().await {
                    Ok(socket) => socket,
                    Err(_) => break,
                };

                // Establish remote connection
                let mut remote_socket = match TcpStream::connect(format!(
                    "{}:{}",
                    forward_config.remote_host,
                    forward_config.remote_port
                )).await {
                    Ok(socket) => socket,
                    Err(_) => continue,
                };

                // Bidirectional data transfer
                tokio::spawn(async move {
                    let (mut client_read, mut client_write) = client_socket.split();
                    let (mut remote_read, mut remote_write) = remote_socket.split();

                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut remote_write) => {},
                        _ = tokio::io::copy(&mut remote_read, &mut client_write) => {},
                    }
                });
            }
        });

        // Store configuration and tunnel
        let mut forwards = active_forwards.write().await;
        let mut tunnels = active_tunnels.lock().await;

        forwards.insert(config.id, config.clone());
        tunnels.insert(config.id, tunnel_task);

        Ok(config.id)
    }

    /// Validate port forwarding configuration
    fn validate_config(&self, config: &PortForwardingConfig) -> Result<()> {
        // Check local port availability
        // In a real implementation, check if port is free
        
        // Validate remote host
        if config.remote_host.is_empty() {
            return Err(anyhow::anyhow!("Remote host cannot be empty"));
        }

        Ok(())
    }

    /// Close a specific tunnel
    pub async fn close_tunnel(&self, tunnel_id: &Uuid) -> Result<()> {
        let mut forwards = self.active_forwards.write().await;
        let mut tunnels = self.active_tunnels.lock().await;

        // Remove configuration
        forwards.remove(tunnel_id);

        // Cancel tunnel task
        if let Some(tunnel_task) = tunnels.remove(tunnel_id) {
            tunnel_task.abort();
        }

        Ok(())
    }

    /// List active tunnels
    pub async fn list_tunnels(&self) -> Vec<PortForwardingConfig> {
        let forwards = self.active_forwards.read().await;
        forwards.values().cloned().collect()
    }

    /// Create secure subdomain for tunnel
    pub async fn create_subdomain(&self, config: &PortForwardingConfig) -> Result<String> {
        // In a real implementation, integrate with DNS provider
        // For now, generate a random subdomain
        let subdomain = config.subdomain.unwrap_or_else(|| {
            format!("{}-{}", 
                config.remote_host.replace('.', "-"), 
                Uuid::new_v4().to_string()[..8]
            )
        });

        Ok(format!("{}.forge.dev", subdomain))
    }

    /// Secure tunnel authentication
    pub async fn authenticate_tunnel(
        &self, 
        config: &PortForwardingConfig, 
        credentials: &ForwardingAuthentication
    ) -> Result<bool> {
        match (config.authentication.as_ref(), credentials) {
            (Some(config_auth), provided_auth) => {
                match (config_auth, provided_auth) {
                    (
                        ForwardingAuthentication::Basic { username: cfg_user, password: cfg_pass },
                        ForwardingAuthentication::Basic { username, password }
                    ) => Ok(cfg_user == username && cfg_pass == password),
                    
                    (
                        ForwardingAuthentication::Token(cfg_token),
                        ForwardingAuthentication::Token(token)
                    ) => Ok(cfg_token == token),
                    
                    _ => Err(anyhow::anyhow!("Authentication method mismatch")),
                }
            },
            (None, _) => Ok(true), // No authentication required
            _ => Err(anyhow::anyhow!("Invalid authentication")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_forwarding_tunnel_creation() {
        let service = PortForwardingService::new();

        let config = PortForwardingConfig {
            id: Uuid::new_v4(),
            local_port: 8080,
            remote_host: "example.com".to_string(),
            remote_port: 80,
            subdomain: Some("test".to_string()),
            protocol: ForwardingProtocol::TCP,
            authentication: Some(ForwardingAuthentication::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        };

        // Create tunnel
        let tunnel_id = service.create_tunnel(config.clone()).await.unwrap();

        // List tunnels
        let tunnels = service.list_tunnels().await;
        assert!(!tunnels.is_empty());

        // Close tunnel
        service.close_tunnel(&tunnel_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_tunnel_authentication() {
        let service = PortForwardingService::new();

        let config = PortForwardingConfig {
            id: Uuid::new_v4(),
            local_port: 8081,
            remote_host: "example.com".to_string(),
            remote_port: 80,
            subdomain: None,
            protocol: ForwardingProtocol::TCP,
            authentication: Some(ForwardingAuthentication::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        };

        // Valid authentication
        let valid_auth = ForwardingAuthentication::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let result = service.authenticate_tunnel(&config, &valid_auth).await.unwrap();
        assert!(result);

        // Invalid authentication
        let invalid_auth = ForwardingAuthentication::Basic {
            username: "wrong".to_string(),
            password: "credentials".to_string(),
        };

        let result = service.authenticate_tunnel(&config, &invalid_auth).await.unwrap();
        assert!(!result);
    }
}
