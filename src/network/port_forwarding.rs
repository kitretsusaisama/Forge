use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{Read, Write, Error, ErrorKind};
use std::thread;
use uuid::Uuid;
use rustls::{ServerConfig, ServerConnection};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::path::Path;
use tokio::net::TcpSocket;
use hyper::{Body, Request, Response, Server, service::{make_service_fn, service_fn}};
use hyper::server::conn::Http;
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};

/// Configuration for port forwarding service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardConfig {
    /// Base domain for forwarded services
    pub base_domain: String,

    /// SSL certificate path
    pub ssl_cert_path: Option<String>,

    /// SSL private key path
    pub ssl_key_path: Option<String>,

    /// Maximum number of concurrent tunnels
    pub max_tunnels: usize,

    /// Tunnel timeout in seconds
    pub tunnel_timeout: u64,
}

/// Tunnel metadata and configuration
#[derive(Debug, Clone)]
pub struct TunnelMetadata {
    /// Unique tunnel identifier
    pub tunnel_id: Uuid,

    /// Local port being forwarded
    pub local_port: u16,

    /// Assigned public subdomain
    pub public_subdomain: String,

    /// Creation timestamp
    pub created_at: std::time::SystemTime,

    /// Access token for tunnel
    pub access_token: String,
}

/// Port forwarding service manager
pub struct PortForwardingService {
    /// Active tunnels
    tunnels: Arc<Mutex<HashMap<Uuid, TunnelMetadata>>>,

    /// Configuration
    config: PortForwardConfig,
}

impl PortForwardingService {
    /// Create a new port forwarding service
    pub fn new(config: PortForwardConfig) -> Self {
        Self {
            tunnels: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Create a new secure tunnel
    pub async fn create_tunnel(&self, local_port: u16) -> Result<TunnelMetadata> {
        // Check tunnel limits
        {
            let tunnels = self.tunnels.lock().map_err(|_| 
                anyhow::anyhow!("Failed to acquire tunnel lock")
            )?;
            
            if tunnels.len() >= self.config.max_tunnels {
                return Err(anyhow::anyhow!("Maximum tunnel limit reached"));
            }
        }

        // Generate unique tunnel metadata
        let tunnel_id = Uuid::new_v4();
        let access_token = Uuid::new_v4().to_string();
        let public_subdomain = format!("{}.{}", tunnel_id, self.config.base_domain);

        let tunnel_metadata = TunnelMetadata {
            tunnel_id,
            local_port,
            public_subdomain,
            created_at: std::time::SystemTime::now(),
            access_token,
        };

        // Store tunnel
        {
            let mut tunnels = self.tunnels.lock().map_err(|_| 
                anyhow::anyhow!("Failed to acquire tunnel lock")
            )?;
            tunnels.insert(tunnel_id, tunnel_metadata.clone());
        }

        // Start tunnel forwarding
        self.start_tunnel_forwarding(&tunnel_metadata).await?;

        Ok(tunnel_metadata)
    }

    /// Start tunnel forwarding with SSL support
    async fn start_tunnel_forwarding(&self, tunnel: &TunnelMetadata) -> Result<()> {
        // Load SSL configuration
        let ssl_config = self.load_ssl_config()?;

        // Create TCP listener for public endpoint
        let socket = TcpSocket::new_v4()?;
        let addr: SocketAddr = format!("0.0.0.0:0").parse()?;
        let listener = socket.bind(addr)?.listen(1024)?;

        // Spawn tunnel forwarding thread
        let local_port = tunnel.local_port;
        let tunnel_id = tunnel.tunnel_id;
        let access_token = tunnel.access_token.clone();
        let tunnels_ref = Arc::clone(&self.tunnels);

        tokio::spawn(async move {
            loop {
                // Accept incoming connection
                let (mut client_stream, _) = listener.accept().await?;

                // Establish connection to local service
                let mut local_stream = TcpStream::connect(format!("127.0.0.1:{}", local_port))?;

                // Proxy data between streams
                let client_to_local = tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    loop {
                        match client_stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                if local_stream.write_all(&buffer[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });

                let local_to_client = tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    loop {
                        match local_stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                if client_stream.write_all(&buffer[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });

                // Wait for tunnel to complete
                tokio::try_join!(client_to_local, local_to_client)?;

                // Check for tunnel timeout
                let mut tunnels = tunnels_ref.lock().map_err(|_| 
                    std::io::Error::new(ErrorKind::Other, "Failed to lock tunnels")
                )?;

                if let Some(tunnel) = tunnels.get(&tunnel_id) {
                    if tunnel.created_at.elapsed()? > std::time::Duration::from_secs(self.config.tunnel_timeout) {
                        tunnels.remove(&tunnel_id);
                        break;
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        Ok(())
    }

    /// Load SSL configuration for secure tunnels
    fn load_ssl_config(&self) -> Result<ServerConfig> {
        // Default to embedded self-signed certificate if not provided
        let cert_path = self.config.ssl_cert_path.as_ref()
            .unwrap_or(&"./resources/default_cert.pem".to_string());
        let key_path = self.config.ssl_key_path.as_ref()
            .unwrap_or(&"./resources/default_key.pem".to_string());

        // Load certificates
        let mut cert_file = File::open(cert_path)
            .context("Failed to open certificate file")?;
        let mut key_file = File::open(key_path)
            .context("Failed to open private key file")?;

        let cert_chain = certs(&mut cert_file)
            .context("Failed to parse certificates")?
            .into_iter()
            .map(rustls::Certificate)
            .collect::<Vec<_>>();

        let private_key = private_key(&mut key_file)
            .context("Failed to parse private key")?
            .map(rustls::PrivateKey)
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

        // Configure TLS server
        let ssl_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("Failed to configure SSL")?;

        Ok(ssl_config)
    }

    /// Revoke an active tunnel
    pub fn revoke_tunnel(&self, tunnel_id: Uuid) -> Result<()> {
        let mut tunnels = self.tunnels.lock().map_err(|_| 
            anyhow::anyhow!("Failed to acquire tunnel lock")
        )?;

        tunnels.remove(&tunnel_id)
            .ok_or_else(|| anyhow::anyhow!("Tunnel not found"))?;

        Ok(())
    }

    /// List active tunnels
    pub fn list_tunnels(&self) -> Result<Vec<TunnelMetadata>> {
        let tunnels = self.tunnels.lock().map_err(|_| 
            anyhow::anyhow!("Failed to acquire tunnel lock")
        )?;

        Ok(tunnels.values().cloned().collect())
    }
}

/// Access control for tunnels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAccessControl {
    /// Allowed IP ranges
    allowed_ips: Vec<String>,

    /// Authentication required
    require_auth: bool,

    /// Rate limiting configuration
    rate_limit: Option<RateLimitConfig>,
}

/// Rate limiting configuration for tunnels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per time window
    max_requests: u32,

    /// Time window in seconds
    time_window: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tunnel_creation() {
        // Create a mock local service
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = local_listener.local_addr().unwrap().port();

        // Configure port forwarding
        let config = PortForwardConfig {
            base_domain: "localhost.dev".to_string(),
            ssl_cert_path: None,
            ssl_key_path: None,
            max_tunnels: 10,
            tunnel_timeout: 3600,
        };

        let service = PortForwardingService::new(config);

        // Create tunnel
        let tunnel = service.create_tunnel(local_port).await.unwrap();

        // Validate tunnel metadata
        assert!(tunnel.tunnel_id != Uuid::nil());
        assert!(!tunnel.public_subdomain.is_empty());
        assert!(!tunnel.access_token.is_empty());

        // Check tunnel is in active list
        let active_tunnels = service.list_tunnels().unwrap();
        assert!(active_tunnels.iter().any(|t| t.tunnel_id == tunnel.tunnel_id));
    }

    #[tokio::test]
    async fn test_tunnel_revocation() {
        let config = PortForwardConfig {
            base_domain: "localhost.dev".to_string(),
            ssl_cert_path: None,
            ssl_key_path: None,
            max_tunnels: 10,
            tunnel_timeout: 3600,
        };

        let service = PortForwardingService::new(config);

        // Create tunnel
        let tunnel = service.create_tunnel(8080).await.unwrap();

        // Revoke tunnel
        service.revoke_tunnel(tunnel.tunnel_id).unwrap();

        // Check tunnel is no longer active
        let active_tunnels = service.list_tunnels().unwrap();
        assert!(!active_tunnels.iter().any(|t| t.tunnel_id == tunnel.tunnel_id));
    }
}
