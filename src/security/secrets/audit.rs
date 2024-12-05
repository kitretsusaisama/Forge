use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Login,
    Logout,
    PasswordChange,
    MfaEnabled,
    MfaDisabled,
    SecretAccess,
    SecretModified,
}

impl AuditLog {
    pub fn new(event_type: AuditEventType, user_id: Option<String>, details: String) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            user_id,
            details,
        }
    }
}
