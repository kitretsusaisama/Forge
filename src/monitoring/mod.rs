mod telemetry;

pub use telemetry::{
    TelemetryManager,
    TelemetryConfig,
    LogLevel,
    PerformanceTracker,
    Telemetry,
};

// Global telemetry configuration
lazy_static::lazy_static! {
    pub static ref TELEMETRY: TelemetryManager = {
        TelemetryManager::init(None)
            .expect("Failed to initialize telemetry")
    };
}

/// Initialize telemetry with custom configuration
pub fn init_telemetry(config: TelemetryConfig) {
    lazy_static::initialize(&TELEMETRY);
}

/// Convenience macro for performance tracking
#[macro_export]
macro_rules! track_performance {
    ($name:expr) => {
        let _tracker = $crate::monitoring::PerformanceTracker::new($name);
    };
}

/// Convenience macro for logging errors
#[macro_export]
macro_rules! log_error {
    ($error:expr, $context:expr) => {
        $crate::monitoring::TELEMETRY.log_error($error, $context);
    };
}

/// Convenience macro for logging events
#[macro_export]
macro_rules! log_event {
    ($event_type:expr, $details:expr) => {
        $crate::monitoring::TELEMETRY.log_event($event_type, $details);
    };
}
