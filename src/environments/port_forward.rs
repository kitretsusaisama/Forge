use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::{ForgeConfig, PortForwardingConfig as ImportedPortForwardingConfig};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use uuid::Uuid;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardingConfig {
    pub enabled: bool,
    pub ports: HashMap<u16, u16>,
    pub host: String,
    pub base_domain: String,
    pub proxy_port: u16,
    pub start_port: u16,
    pub end_port: u16,
}

impl Default for PortForwardingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ports: HashMap::new(),
            host: "127.0.0.1".to_string(),
            base_domain: "localhost".to_string(),
            proxy_port: 8080,
            start_port: 8081,
            end_port: 65535,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortForward {
    pub container_port: u16,
    pub host_port: u16,
    pub environment_name: String,
}

#[derive(Clone)]
pub struct PortForwardManager {
    config: Arc<ForgeConfig>,
    forwards: Arc<RwLock<HashMap<String, Vec<PortForward>>>>,
}

impl PortForwardManager {
    pub fn new(config: Arc<ForgeConfig>) -> Self {
        Self {
            config,
            forwards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_forward(
        &self,
        env_name: &str,
        container_port: u16,
    ) -> Result<PortForward> {
        let mut forwards = self.forwards.write().await;
        let host_port = self.find_available_port().await?;

        let forward = PortForward {
            container_port,
            host_port,
            environment_name: env_name.to_string(),
        };

        forwards
            .entry(env_name.to_string())
            .or_insert_with(Vec::new)
            .push(forward.clone());

        // Start the proxy for this forward
        self.start_proxy(&forward).await?;

        Ok(forward)
    }

    pub async fn remove_forwards(&self, env_name: &str) -> Result<()> {
        let mut forwards = self.forwards.write().await;
        forwards.remove(env_name);
        Ok(())
    }

    async fn find_available_port(&self) -> Result<u16> {
        let mut rng = rand::thread_rng();
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 100;

        while attempts < MAX_ATTEMPTS {
            let port = rng.gen_range(self.config.port_forwarding.start_port..=self.config.port_forwarding.end_port);
            if !self.is_port_in_use(port).await? {
                return Ok(port);
            }
            attempts += 1;
        }

        anyhow::bail!("Could not find available port after {} attempts", MAX_ATTEMPTS)
    }

    async fn is_port_in_use(&self, port: u16) -> Result<bool> {
        let forwards = self.forwards.read().await;
        for forward_list in forwards.values() {
            if forward_list.iter().any(|f| f.host_port == port) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn start_proxy(&self, forward: &PortForward) -> Result<()> {
        let forward = forward.clone();
        let addr = SocketAddr::from(([0, 0, 0, 0], forward.host_port));

        let make_service = make_service_fn(move |_conn: &AddrStream| {
            let forward = forward.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let forward = forward.clone();
                    async move {
                        Self::proxy_request(req, &forward).await
                    }
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_service);
        
        tokio::spawn(async move {
            if let Err(e) = server.await {
                eprintln!("Proxy server error: {}", e);
            }
        });

        Ok(())
    }

    async fn proxy_request(req: Request<Body>, forward: &PortForward) -> Result<Response<Body>, Infallible> {
        let mut target = format!("http://localhost:{}", forward.container_port);
        if let Some(path_and_query) = req.uri().path_and_query() {
            target.push_str(path_and_query.as_str());
        }

        match TcpStream::connect(("localhost", forward.container_port)).await {
            Ok(_) => {
                let client = hyper::Client::new();
                match client.request(req).await {
                    Ok(response) => Ok(response),
                    Err(_) => Ok(Response::builder()
                        .status(502)
                        .body(Body::from("Bad Gateway"))
                        .unwrap()),
                }
            },
            Err(_) => Ok(Response::builder()
                .status(503)
                .body(Body::from("Service Unavailable"))
                .unwrap()),
        }
    }
}
