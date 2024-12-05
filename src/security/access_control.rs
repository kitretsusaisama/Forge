use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::RwLock;
use crate::security::platform::UserManager;

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, 
        PasswordHasher, 
        PasswordVerifier, 
        SaltString
    },
    Argon2
};
use rand::Rng;
use uuid::Uuid;

/// User roles with hierarchical permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    Developer,
    Operator,
    Auditor,
    Guest,
    Administrator,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "Admin"),
            UserRole::Developer => write!(f, "Developer"),
            UserRole::Operator => write!(f, "Operator"),
            UserRole::Auditor => write!(f, "Auditor"),
            UserRole::Guest => write!(f, "Guest"),
            UserRole::Administrator => write!(f, "Administrator"),
        }
    }
}

/// Permissions for different actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Permission {
    CreateEnvironment,
    DeleteEnvironment,
    StartEnvironment,
    StopEnvironment,
    ViewEnvironmentDetails,
    ManagePlugins,
    ConfigureSystem,
    ManageUsers,
    ViewAuditLogs,
    ManageSecrets,
}

/// User authentication and authorization details
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    password_hash: String,
    pub role: UserRole,
    pub permissions: Vec<Permission>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub groups: Vec<String>,
}

/// Access control manager
pub struct AccessControlManager {
    users: RwLock<HashMap<String, User>>,
    storage_path: PathBuf,
    user_manager: UserManager,
}

impl AccessControlManager {
    /// Create a new access control manager
    pub fn new(base_dir: &Path) -> Result<Self> {
        let storage_path = base_dir.join("users.json");
        
        // Create users file if it doesn't exist
        if !storage_path.exists() {
            fs::write(&storage_path, "[]")?;
        }

        // Read existing users
        let users_json = fs::read_to_string(&storage_path)?;
        let users: HashMap<String, User> = serde_json::from_str(&users_json)
            .unwrap_or_default();

        Ok(Self {
            users: RwLock::new(users),
            storage_path,
            user_manager: UserManager::new(),
        })
    }

    /// Create a new user
    pub fn create_user(
        &self, 
        username: &str, 
        password: &str, 
        role: UserRole
    ) -> Result<User> {
        // Check if username already exists
        let mut users = self.users.write().map_err(|_| anyhow!("Lock poisoned"))?;
        
        if users.values().any(|u| u.username == username) {
            return Err(anyhow!("Username already exists"));
        }

        // Generate salt and hash password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(
            password.as_bytes(), 
            &salt
        )?.to_string();

        // Determine default permissions based on role
        let permissions = match role {
            UserRole::Admin => vec![
                Permission::CreateEnvironment,
                Permission::DeleteEnvironment,
                Permission::StartEnvironment,
                Permission::StopEnvironment,
                Permission::ViewEnvironmentDetails,
                Permission::ManagePlugins,
                Permission::ConfigureSystem,
            ],
            UserRole::Developer => vec![
                Permission::ViewEnvironmentDetails,
                Permission::CreateEnvironment,
                Permission::StartEnvironment,
                Permission::StopEnvironment,
            ],
            UserRole::Operator => vec![
                Permission::ViewEnvironmentDetails,
                Permission::StartEnvironment,
                Permission::StopEnvironment,
            ],
            UserRole::Auditor => vec![
                Permission::ViewEnvironmentDetails,
            ],
            UserRole::Guest => vec![
                Permission::ViewEnvironmentDetails
            ],
            UserRole::Administrator => vec![
                Permission::CreateEnvironment,
                Permission::DeleteEnvironment,
                Permission::StartEnvironment,
                Permission::StopEnvironment,
                Permission::ViewEnvironmentDetails,
                Permission::ManagePlugins,
                Permission::ConfigureSystem,
            ],
        };

        // Create new user
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            password_hash,
            role,
            permissions,
            created_at: chrono::Utc::now(),
            last_login: None,
            groups: vec![],
        };

        // Store user
        users.insert(user.id.clone(), user.clone());
        
        // Persist to file
        self.persist_users(&users)?;

        Ok(user)
    }

    /// Authenticate user
    pub fn authenticate(&self, username: &str, password: &str) -> Result<User> {
        let users = self.users.read().map_err(|_| anyhow!("Lock poisoned"))?;
        
        // Find user by username
        let user = users.values()
            .find(|u| u.username == username)
            .context("User not found")?;

        // Verify password
        let parsed_hash = PasswordHash::new(&user.password_hash)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .context("Invalid password")?;

        // Update last login
        drop(users); // Release read lock
        
        let mut users = self.users.write().map_err(|_| anyhow!("Lock poisoned"))?;
        if let Some(user) = users.get_mut(&user.id) {
            user.last_login = Some(chrono::Utc::now());
            self.persist_users(&users)?;
        }

        Ok(user.clone())
    }

    /// Check if user has a specific permission
    pub fn check_permission(&self, user_id: &str, permission: Permission) -> Result<bool> {
        let users = self.users.read().map_err(|_| anyhow!("Lock poisoned"))?;
        
        users.get(user_id)
            .map(|user| user.permissions.contains(&permission))
            .context("User not found")
    }

    /// Persist users to storage
    fn persist_users(&self, users: &HashMap<String, User>) -> Result<()> {
        let json = serde_json::to_string_pretty(users)?;
        fs::write(&self.storage_path, json)?;
        Ok(())
    }

    /// Delete a user
    pub fn delete_user(&self, user_id: &str) -> Result<bool> {
        let mut users = self.users.write().map_err(|_| anyhow!("Lock poisoned"))?;
        
        let removed = users.remove(user_id).is_some();
        if removed {
            self.persist_users(&users)?;
        }

        Ok(removed)
    }

    /// List all users
    pub fn list_users(&self) -> Result<Vec<User>> {
        let users = self.users.read().map_err(|_| anyhow!("Lock poisoned"))?;
        
        Ok(users.values()
            .cloned()
            .collect())
    }
}

/// Session management
pub struct SessionManager {
    active_sessions: RwLock<HashMap<String, Session>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            active_sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session for a user
    pub fn create_session(&self, user_id: &str) -> Result<Session> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(8),
        };

        let mut sessions = self.active_sessions.write().map_err(|_| anyhow!("Lock poisoned"))?;
        sessions.insert(session.id.clone(), session.clone());

        Ok(session)
    }

    /// Validate a session
    pub fn validate_session(&self, session_id: &str) -> Result<bool> {
        let sessions = self.active_sessions.read().map_err(|_| anyhow!("Lock poisoned"))?;
        
        sessions.get(session_id)
            .map(|session| session.expires_at > chrono::Utc::now())
            .context("Session not found")
    }

    /// Invalidate a session
    pub fn invalidate_session(&self, session_id: &str) -> Result<bool> {
        let mut sessions = self.active_sessions.write().map_err(|_| anyhow!("Lock poisoned"))?;
        
        let removed = sessions.remove(session_id).is_some();
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_user_creation_and_authentication() {
        let temp_dir = tempdir().unwrap();
        let access_control = AccessControlManager::new(temp_dir.path()).unwrap();

        // Create user
        let user = access_control.create_user(
            "testuser", 
            "password123", 
            UserRole::Developer
        ).unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.role, UserRole::Developer);

        // Authenticate user
        let authenticated_user = access_control.authenticate("testuser", "password123").unwrap();
        assert_eq!(authenticated_user.id, user.id);

        // Failed authentication
        assert!(access_control.authenticate("testuser", "wrongpassword").is_err());
    }

    #[test]
    fn test_permission_checking() {
        let temp_dir = tempdir().unwrap();
        let access_control = AccessControlManager::new(temp_dir.path()).unwrap();

        let user = access_control.create_user(
            "devuser", 
            "password", 
            UserRole::Developer
        ).unwrap();

        // Check developer permissions
        assert!(access_control.check_permission(&user.id, Permission::CreateEnvironment).unwrap());
        assert!(!access_control.check_permission(&user.id, Permission::ConfigureSystem).unwrap());
    }

    #[test]
    fn test_session_management() {
        let session_manager = SessionManager::new();

        // Create session
        let user_id = "user123";
        let session = session_manager.create_session(user_id).unwrap();

        // Validate session
        assert!(session_manager.validate_session(&session.id).unwrap());

        // Invalidate session
        assert!(session_manager.invalidate_session(&session.id).unwrap());
        assert!(!session_manager.validate_session(&session.id).unwrap());
    }
}
