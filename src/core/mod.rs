pub mod config;
pub mod error;
pub mod types;
pub mod resource;

pub use config::Config;
pub use error::ForgeError;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait EnvironmentManager {
    async fn create_environment(&self, config: &str) -> Result<()>;
    async fn destroy_environment(&self, id: &str) -> Result<()>;
    async fn list_environments(&self) -> Result<Vec<String>>;
    async fn get_environment_status(&self, id: &str) -> Result<String>;
}

#[async_trait]
pub trait ResourceManager {
    async fn allocate_resources(&self, requirements: &str) -> Result<()>;
    async fn deallocate_resources(&self, id: &str) -> Result<()>;
    async fn get_resource_usage(&self) -> Result<String>;
}

#[async_trait]
pub trait SecurityManager {
    async fn authenticate(&self, credentials: &str) -> Result<String>;
    async fn authorize(&self, token: &str, resource: &str) -> Result<bool>;
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}
