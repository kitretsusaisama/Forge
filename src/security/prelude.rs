pub use std::collections::HashMap;
pub use chrono::{Duration, Utc, DateTime};
pub use serde::{Serialize, Deserialize};
pub use anyhow::{Result, Context};
pub use secrecy::{Secret, ExposeSecret};
pub use async_trait::async_trait;
pub use rand::{thread_rng, RngCore};
pub use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
pub use std::path::{Path, PathBuf};
pub use std::sync::Arc;
pub use tokio::sync::{RwLock, Mutex};

// Re-export common error types
pub use std::error::Error as StdError;
pub use std::io::Error as IoError;

// Common type aliases
pub type BoxError = Box<dyn StdError + Send + Sync>;
pub type DynResult<T> = Result<T, BoxError>;

// Common traits
pub trait AsyncSecurityOperation {
    type Output;
    async fn execute(&self) -> Result<Self::Output>;
}

// Security-specific types
use std::time::Duration as StdDuration;

#[derive(Debug, Clone)]
pub struct TimeDelta(pub Duration);

impl TimeDelta {
    pub fn new(duration: Duration) -> Self {
        Self(duration)
    }

    pub fn into_duration(self) -> Duration {
        self.0
    }
}

// Custom serialization for TimeDelta
impl Serialize for TimeDelta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Convert to milliseconds for serialization
        self.0.num_milliseconds().serialize(serializer)
    }
}

// Custom deserialization for TimeDelta
impl<'de> Deserialize<'de> for TimeDelta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let millis = i64::deserialize(deserializer)?;
        Ok(TimeDelta(Duration::milliseconds(millis)))
    }
}

// Convert from std::time::Duration
impl From<StdDuration> for TimeDelta {
    fn from(duration: StdDuration) -> Self {
        let nanos = duration.subsec_nanos() as i64;
        let secs = duration.as_secs() as i64;
        TimeDelta(Duration::seconds(secs) + Duration::nanoseconds(nanos))
    }
}

// Convert to std::time::Duration
impl From<TimeDelta> for StdDuration {
    fn from(delta: TimeDelta) -> Self {
        let secs = delta.0.num_seconds();
        let nanos = delta.0.subsec_nanos() as u32;
        StdDuration::new(secs as u64, nanos)
    }
}
