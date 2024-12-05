use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use std::io::{Write, BufWriter};
use chrono::Utc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Audit log entry for secret-related operations
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretAuditEntry {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<Utc>,
    pub operation: SecretOperation,
    pub user_id: Option<String>,
    pub secret_key: String,
    pub success: bool,
    pub metadata: Option<String>,
}

/// Types of secret-related operations
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SecretOperation {
    Create,
    Read,
    Update,
    Delete,
    Rotate,
}

/// Audit logging manager for secret operations
pub struct SecretAuditLogger {
    log_path: PathBuf,
}

impl SecretAuditLogger {
    /// Create a new audit logger
    pub fn new(base_dir: &Path) -> Result<Self, std::io::Error> {
        let log_path = base_dir.join("secret_audit.log");
        
        // Ensure log directory exists
        std::fs::create_dir_all(base_dir)?;

        Ok(Self { 
            log_path 
        })
    }

    /// Log a secret operation
    pub fn log_secret_operation(
        &self, 
        operation: SecretOperation, 
        secret_key: &str,
        user_id: Option<String>,
        success: bool,
        metadata: Option<String>
    ) -> Result<(), std::io::Error> {
        let entry = SecretAuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            operation,
            user_id,
            secret_key: secret_key.to_string(),
            success,
            metadata,
        };

        // Open log file in append mode
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.log_path)?;

        let mut writer = BufWriter::new(file);
        
        // Write JSON log entry
        let log_line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        writeln!(writer, "{}", log_line)?;
        writer.flush()?;

        Ok(())
    }

    /// Retrieve recent audit logs
    pub fn get_recent_logs(&self, limit: usize) -> Result<Vec<SecretAuditEntry>, std::io::Error> {
        use std::io::{BufRead, BufReader};

        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);

        // First collect all entries into a vector
        let mut logs: Vec<SecretAuditEntry> = reader
            .lines()
            .filter_map(|line| {
                line.ok().and_then(|l| 
                    serde_json::from_str(&l).ok()
                )
            })
            .collect();

        // Then reverse and take the limit
        logs.reverse();
        logs.truncate(limit);

        Ok(logs)
    }

    /// Rotate log file to prevent unbounded growth
    pub fn rotate_log(&self) -> Result<(), std::io::Error> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let archived_path = self.log_path.with_file_name(
            format!("secret_audit_{}.log.archived", timestamp)
        );

        // Rename current log file
        std::fs::rename(&self.log_path, &archived_path)?;

        // Create a new log file
        File::create(&self.log_path)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secret_audit_logging() {
        let temp_dir = tempdir().unwrap();
        let audit_logger = SecretAuditLogger::new(temp_dir.path()).unwrap();

        // Log a secret creation
        audit_logger.log_secret_operation(
            SecretOperation::Create, 
            "DOCKER_TOKEN", 
            Some("user123".to_string()), 
            true, 
            Some("Docker registry token".to_string())
        ).unwrap();

        // Retrieve recent logs
        let logs = audit_logger.get_recent_logs(10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].secret_key, "DOCKER_TOKEN");
        assert_eq!(logs[0].operation, SecretOperation::Create);
    }

    #[test]
    fn test_log_rotation() {
        let temp_dir = tempdir().unwrap();
        let audit_logger = SecretAuditLogger::new(temp_dir.path()).unwrap();

        // Log multiple entries
        for _ in 0..5 {
            audit_logger.log_secret_operation(
                SecretOperation::Create, 
                "TEST_SECRET", 
                Some("user123".to_string()), 
                true, 
                None
            ).unwrap();
        }

        // Rotate log
        audit_logger.rotate_log().unwrap();

        // Check that a new log file is created
        assert!(audit_logger.log_path.exists());
        
        // Check archived log exists
        let archived_logs = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| 
                entry.file_name()
                    .to_str()
                    .map(|s| s.contains("secret_audit_") && s.ends_with(".log.archived"))
                    .unwrap_or(false)
            )
            .count();
        
        assert_eq!(archived_logs, 1);
    }
}
