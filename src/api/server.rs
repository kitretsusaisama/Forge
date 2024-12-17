use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::{Filter, Reply, Rejection};
use tracing::{info, error};

use crate::api::APIManager;
use crate::templates::TemplateManager;
use crate::agents::AgentOrchestrator;

/// Comprehensive API Server Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIServerConfig {
    pub host: String,
    pub port: u16,
    pub max_concurrent_connections: usize,
    pub enable_cors: bool,
}

/// API Server with Advanced Features
pub struct ForgeAPIServer {
    config: APIServerConfig,
    api_manager: Arc<Mutex<APIManager>>,
    template_manager: Arc<Mutex<TemplateManager>>,
    agent_orchestrator: Arc<Mutex<AgentOrchestrator>>,
}

impl ForgeAPIServer {
    /// Create a new API server
    pub fn new(
        config: APIServerConfig, 
        api_manager: APIManager,
        template_manager: TemplateManager,
        agent_orchestrator: AgentOrchestrator,
    ) -> Self {
        Self {
            config,
            api_manager: Arc::new(Mutex::new(api_manager)),
            template_manager: Arc::new(Mutex::new(template_manager)),
            agent_orchestrator: Arc::new(Mutex::new(agent_orchestrator)),
        }
    }

    /// Start the API server
    pub async fn start(&self) -> Result<()> {
        // CORS configuration
        let cors = warp::cors()
            .allow_any_origin()
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allow_headers(vec!["Content-Type", "Authorization"]);

        // API routes
        let api_routes = self.create_routes();

        // Combine routes with CORS
        let routes = api_routes.with(cors);

        // Server address
        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.port)
            .parse()
            .context("Invalid server address")?;

        info!("Starting Forge API Server on {}", addr);

        // Start server
        warp::serve(routes)
            .max_concurrent_connections(self.config.max_concurrent_connections)
            .run(addr)
            .await;

        Ok(())
    }

    /// Create API routes
    fn create_routes(&self) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        // Template Management Routes
        let template_routes = self.template_routes()
            .or(self.environment_routes());

        // Agent Management Routes
        let agent_routes = self.agent_routes();

        // API Management Routes
        let api_routes = self.api_endpoint_routes();

        // Combine all routes
        template_routes
            .or(agent_routes)
            .or(api_routes)
    }

    /// Template-related routes
    fn template_routes(&self) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        let template_manager = Arc::clone(&self.template_manager);

        // GET /templates
        let list_templates = warp::path("templates")
            .and(warp::get())
            .and_then(move || {
                let template_manager = Arc::clone(&template_manager);
                async move {
                    let manager = template_manager.lock().await;
                    // Implement method to list templates
                    Ok::<_, Rejection>(warp::reply::json(&manager.list_templates()))
                }
            });

        // POST /templates/generate
        let generate_template = warp::path("templates")
            .and(warp::path("generate"))
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |template_config| {
                let template_manager = Arc::clone(&template_manager);
                async move {
                    let mut manager = template_manager.lock().await;
                    // Implement template generation logic
                    let template = manager.generate_template(&template_config)
                        .map_err(|_| warp::reject::custom(TemplateGenerationError))?;
                    Ok::<_, Rejection>(warp::reply::json(&template))
                }
            });

        list_templates.or(generate_template)
    }

    /// Environment-related routes
    fn environment_routes(&self) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        // Future implementation for environment management
        warp::path("environments")
            .and(warp::get())
            .map(|| "Environment routes placeholder")
    }

    /// Agent-related routes
    fn agent_routes(&self) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        let agent_orchestrator = Arc::clone(&self.agent_orchestrator);

        // GET /agents/execute
        warp::path("agents")
            .and(warp::path("execute"))
            .and(warp::get())
            .and_then(move || {
                let agent_orchestrator = Arc::clone(&agent_orchestrator);
                async move {
                    let orchestrator = agent_orchestrator.lock().await;
                    let results = orchestrator.execute_all()
                        .await
                        .map_err(|_| warp::reject::custom(AgentExecutionError))?;
                    Ok::<_, Rejection>(warp::reply::json(&results))
                }
            })
    }

    /// API Endpoint Management Routes
    fn api_endpoint_routes(&self) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        let api_manager = Arc::clone(&self.api_manager);

        // POST /api/endpoints/register
        let register_endpoint = warp::path("api")
            .and(warp::path("endpoints"))
            .and(warp::path("register"))
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |endpoint| {
                let api_manager = Arc::clone(&api_manager);
                async move {
                    let mut manager = api_manager.lock().await;
                    manager.register_endpoint(endpoint)
                        .await
                        .map_err(|_| warp::reject::custom(EndpointRegistrationError))?;
                    Ok::<_, Rejection>(warp::reply::with_status(
                        "Endpoint registered successfully", 
                        warp::http::StatusCode::CREATED
                    ))
                }
            });

        // GET /api/endpoints
        let list_endpoints = warp::path("api")
            .and(warp::path("endpoints"))
            .and(warp::get())
            .and_then(move || {
                let api_manager = Arc::clone(&api_manager);
                async move {
                    let manager = api_manager.lock().await;
                    // Implement method to list endpoints
                    Ok::<_, Rejection>(warp::reply::json(&manager.list_endpoints()))
                }
            });

        register_endpoint.or(list_endpoints)
    }
}

/// Custom Rejection Handlers
#[derive(Debug)]
struct TemplateGenerationError;
impl warp::reject::Reject for TemplateGenerationError {}

#[derive(Debug)]
struct AgentExecutionError;
impl warp::reject::Reject for AgentExecutionError {}

#[derive(Debug)]
struct EndpointRegistrationError;
impl warp::reject::Reject for EndpointRegistrationError {}

/// Global Error Handler
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if err.is_not_found() {
        Ok(warp::reply::with_status(
            "Not Found",
            warp::http::StatusCode::NOT_FOUND,
        ))
    } else if err.find::<TemplateGenerationError>().is_some() {
        Ok(warp::reply::with_status(
            "Template Generation Failed",
            warp::http::StatusCode::BAD_REQUEST,
        ))
    } else if err.find::<AgentExecutionError>().is_some() {
        Ok(warp::reply::with_status(
            "Agent Execution Failed",
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ))
    } else if err.find::<EndpointRegistrationError>().is_some() {
        Ok(warp::reply::with_status(
            "Endpoint Registration Failed",
            warp::http::StatusCode::BAD_REQUEST,
        ))
    } else {
        Err(err)
    }
}

/// Performance Optimization Middleware
fn performance_middleware() -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::any()
        .map(|| {
            // Add performance tracking logic
            // Could integrate with tracing or custom metrics
            info!("Request processed");
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test::request;

    #[tokio::test]
    async fn test_api_server_routes() {
        let api_manager = APIManager::new();
        let template_manager = TemplateManager::new(std::path::PathBuf::from("./templates"));
        let agent_orchestrator = AgentOrchestrator::new();

        let server_config = APIServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            max_concurrent_connections: 100,
            enable_cors: true,
        };

        let server = ForgeAPIServer::new(
            server_config, 
            api_manager, 
            template_manager, 
            agent_orchestrator
        );

        let routes = server.create_routes();

        // Test template list route
        let resp = request()
            .method("GET")
            .path("/templates")
            .reply(&routes)
            .await;

        assert_eq!(resp.status(), 200);
    }
}
