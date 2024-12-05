use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;
use crate::core::error::ForgeError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub password_hash: String,
    pub permissions: Vec<String>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
pub struct UserManagerImpl {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl UserManagerImpl {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_user(&self, id: &str) -> Option<User> {
        self.users.read().await.get(id).cloned()
    }

    pub async fn add_user(&self, user: User) -> Result<()> {
        self.users.write().await.insert(user.id.clone(), user);
        Ok(())
    }

    pub async fn remove_user(&self, id: &str) -> Option<User> {
        self.users.write().await.remove(id)
    }

    pub async fn list_users(&self) -> Vec<User> {
        self.users.read().await.values().cloned().collect()
    }

    pub async fn update_user(&self, id: &str, user: User) -> Option<User> {
        self.users.write().await.insert(id.to_string(), user)
    }
}

impl Default for UserManagerImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait UserManager: Send + Sync {
    async fn create_user(&self, username: &str) -> Result<(), ForgeError>;
    async fn delete_user(&self, username: &str) -> Result<(), ForgeError>;
    async fn user_exists(&self, username: &str) -> Result<bool, ForgeError>;
    async fn set_user_permissions(&self, username: &str, permissions: &[String]) -> Result<(), ForgeError>;
}

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsUserManager as PlatformUserManager;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::UnixUserManager as PlatformUserManager;
