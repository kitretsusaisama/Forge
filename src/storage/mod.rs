use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{migrate::MigrateDatabase, sqlite::SqlitePool, FromRow, Sqlite};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::environments::{Environment, EnvironmentConfig, EnvironmentStatus};

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct StoredEnvironment {
    pub id: Option<i64>,
    pub name: String,
    pub env_type: String,
    pub path: PathBuf,
    pub status: String,
    pub container_id: Option<String>,
    pub config_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Environment> for StoredEnvironment {
    fn from(env: &Environment) -> Self {
        // Serialize config to JSON if present
        let config_json = env.config.as_ref().map(|config| {
            serde_json::to_string(config)
                .unwrap_or_else(|_| "{}".to_string())
        });

        Self {
            id: None, // Will be set by database
            name: env.name.clone(),
            env_type: env.env_type.clone(),
            path: env.path.clone(),
            status: env.status.to_string(),
            container_id: env.container_id.clone(),
            config_json,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl StoredEnvironment {
    pub fn to_environment(&self) -> Result<Environment> {
        // Deserialize config from JSON if present
        let config = self.config_json.as_ref().and_then(|json| {
            serde_json::from_str(json).ok()
        });

        Ok(Environment {
            name: self.name.clone(),
            env_type: self.env_type.clone(),
            path: self.path.clone(),
            status: match self.status.as_str() {
                "Created" => EnvironmentStatus::Created,
                "Running" => EnvironmentStatus::Running,
                "Stopped" => EnvironmentStatus::Stopped,
                "Error" => EnvironmentStatus::Error,
                _ => EnvironmentStatus::Created,
            },
            config,
            container_id: self.container_id.clone(),
        })
    }
}

#[cfg(feature = "database")]
mod database {
    use super::*;

    pub struct DatabaseStorage {
        pool: SqlitePool,
        base_path: PathBuf,
    }

    impl DatabaseStorage {
        pub async fn new(config: Arc<crate::config::ForgeConfig>) -> Result<Self> {
            // Use project directories to get a standard location
            let base_path = directories::ProjectDirs::from("com", "devenv", "forge")
                .context("Failed to get project directories")?
                .data_dir()
                .to_path_buf();

            // Create base path if it doesn't exist
            std::fs::create_dir_all(&base_path)?;

            // Create database path
            let db_path = base_path.join("environments.db");
            let db_url = format!("sqlite:{}", db_path.to_string_lossy());

            // Create database if it doesn't exist
            if !Sqlite::database_exists(&db_url).await.unwrap_or(false) {
                Sqlite::create_database(&db_url).await?;
            }

            // Create connection pool
            let pool = SqlitePool::connect(&db_url).await?;

            // Run migrations
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .context("Failed to run database migrations")?;

            Ok(Self { pool, base_path })
        }
    }

    #[async_trait]
    impl super::Storage for DatabaseStorage {
        async fn save_environment(&self, env: &Environment) -> Result<()> {
            let stored_env = StoredEnvironment::from(env);

            sqlx::query_as::<Sqlite, ()>(
                "INSERT INTO environments (
                    name, env_type, path, status, container_id, config_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
            .bind(stored_env.name)
            .bind(stored_env.env_type)
            .bind(stored_env.path.to_string_lossy().to_string())
            .bind(stored_env.status)
            .bind(stored_env.container_id)
            .bind(stored_env.config_json)
            .execute(&self.pool)
            .await?;

            Ok(())
        }

        async fn get_environment(&self, name: &str) -> Result<Option<Environment>> {
            let result = sqlx::query_as::<Sqlite, StoredEnvironment>(
                "SELECT * FROM environments WHERE name = ?"
            )
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

            result.map(|stored| stored.to_environment()).transpose()
        }

        async fn list_environments(&self) -> Result<Vec<Environment>> {
            let rows = sqlx::query_as::<Sqlite, StoredEnvironment>(
                "SELECT * FROM environments"
            )
            .fetch_all(&self.pool)
            .await?;

            rows.into_iter()
                .map(|stored| stored.to_environment())
                .collect()
        }

        async fn delete_environment(&self, name: &str) -> Result<()> {
            sqlx::query!(
                "DELETE FROM environments WHERE name = ?",
                name
            )
            .execute(&self.pool)
            .await?;

            Ok(())
        }
    }
}

mod memory {
    use super::*;

    pub struct MemoryStorage {
        environments: std::collections::HashMap<String, Environment>,
    }

    impl MemoryStorage {
        pub fn new() -> Self {
            Self {
                environments: std::collections::HashMap::new(),
            }
        }
    }

    #[async_trait]
    impl super::Storage for MemoryStorage {
        async fn save_environment(&mut self, env: &Environment) -> Result<()> {
            self.environments.insert(env.name.clone(), env.clone());
            Ok(())
        }

        async fn get_environment(&self, name: &str) -> Result<Option<Environment>> {
            Ok(self.environments.get(name).cloned())
        }

        async fn list_environments(&self) -> Result<Vec<Environment>> {
            Ok(self.environments.values().cloned().collect())
        }

        async fn delete_environment(&mut self, name: &str) -> Result<()> {
            self.environments.remove(name);
            Ok(())
        }
    }
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn save_environment(&self, env: &Environment) -> Result<()>;
    async fn get_environment(&self, name: &str) -> Result<Option<Environment>>;
    async fn list_environments(&self) -> Result<Vec<Environment>>;
    async fn delete_environment(&self, name: &str) -> Result<()>;
}

pub struct StorageManager {
    inner: Arc<dyn Storage>,
}

impl StorageManager {
    pub async fn new(config: Arc<crate::config::ForgeConfig>) -> Result<Self> {
        #[cfg(feature = "database")]
        let storage: Arc<dyn Storage> = Arc::new(database::DatabaseStorage::new(config).await?);
        
        #[cfg(not(feature = "database"))]
        let storage: Arc<dyn Storage> = Arc::new(memory::MemoryStorage::new());

        Ok(Self {
            inner: storage,
        })
    }

    pub async fn save_environment(&self, env: &Environment) -> Result<()> {
        self.inner.save_environment(env).await
    }

    pub async fn get_environment(&self, name: &str) -> Result<Option<Environment>> {
        self.inner.get_environment(name).await
    }

    pub async fn list_environments(&self) -> Result<Vec<Environment>> {
        self.inner.list_environments().await
    }

    pub async fn delete_environment(&self, name: &str) -> Result<()> {
        self.inner.delete_environment(name).await
    }
}

// Migrations for SQLite database
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_environment_storage() {
        // Create a temporary directory for the test database
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_environments.db");
        let db_url = format!("sqlite:{}", db_path.to_string_lossy());

        // Create database
        Sqlite::create_database(&db_url).await.unwrap();

        // Create connection pool
        let pool = SqlitePool::connect(&db_url).await.unwrap();

        // Create table manually for testing
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS environments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                env_type TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                container_id TEXT,
                config_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .unwrap();

        // TODO: Add more comprehensive tests
    }
}
