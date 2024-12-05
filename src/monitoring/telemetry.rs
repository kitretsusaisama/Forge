use std::time::Instant;
use tracing::{error, info, warn, debug, span, Level};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};
use serde::{Serialize, Deserialize};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use metrics::{counter, gauge, histogram};
use sysinfo::{
    System,
    Process,
    Cpu,
    CpuRefreshKind,
    ProcessRefreshKind,
    RefreshKind,
};
use chrono;

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub log_level: LogLevel,
    pub log_directory: Option<PathBuf>,
    pub anonymize_data: bool,
    #[cfg(feature = "monitoring")]
    pub metrics_enabled: bool,
    pub alert_thresholds: Option<AlertThresholds>,
}

/// Alert thresholds for system metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
}

/// System metrics data
#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    pub timestamp: i64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_rx: u64,
    pub network_tx: u64,
    pub process_count: usize,
}

/// Log levels matching tracing's levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Performance tracking for operations
pub struct PerformanceTracker {
    start_time: Instant,
    operation_name: String,
}

impl PerformanceTracker {
    pub fn new(operation_name: &str) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.to_string(),
        }
    }
}

impl Drop for PerformanceTracker {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed();
        debug!(
            operation = %self.operation_name,
            duration_ms = %duration.as_millis(),
            "Operation completed"
        );
        #[cfg(feature = "monitoring")]
        {
            // Record metrics
            histogram!("operation.duration", duration.as_secs_f64(), "operation" => self.operation_name.clone());
        }
    }
}

/// Centralized telemetry manager
pub struct TelemetryManager {
    config: TelemetryConfig,
    system: System,
    monitoring_active: Arc<AtomicBool>,
    #[cfg(feature = "monitoring")]
    metrics_tx: broadcast::Sender<SystemMetrics>,
}

impl TelemetryManager {
    /// Initialize global tracing subscriber
    pub fn init(config: Option<TelemetryConfig>) -> Result<Self> {
        let config = config.unwrap_or_else(|| TelemetryConfig {
            enabled: true,
            log_level: LogLevel::Info,
            log_directory: None,
            anonymize_data: false,
            #[cfg(feature = "monitoring")]
            metrics_enabled: true,
            alert_thresholds: None,
        });

        if config.enabled {
            let env_filter = match config.log_level {
                LogLevel::Error => EnvFilter::new("error"),
                LogLevel::Warn => EnvFilter::new("warn"),
                LogLevel::Info => EnvFilter::new("info"),
                LogLevel::Debug => EnvFilter::new("debug"),
                LogLevel::Trace => EnvFilter::new("trace"),
            };

            let fmt_layer = fmt::layer().with_target(false);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();

            // Initialize metrics if enabled
            #[cfg(feature = "monitoring")]
            if config.metrics_enabled {
                metrics::init_metrics()?;
            }
        }

        #[cfg(feature = "monitoring")]
        let (metrics_tx, _) = broadcast::channel(100);

        Ok(Self {
            config,
            system: System::new_all(),
            monitoring_active: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "monitoring")]
            metrics_tx,
        })
    }

    /// Start real-time system monitoring
    pub async fn start_monitoring(&self) -> Result<broadcast::Receiver<SystemMetrics>> {
        let active = self.monitoring_active.clone();
        active.store(true, Ordering::SeqCst);
        
        #[cfg(feature = "monitoring")]
        {
            let tx = self.metrics_tx.clone();
            let thresholds = self.config.alert_thresholds.clone();

            tokio::spawn(async move {
                while active.load(Ordering::SeqCst) {
                    let mut sys = System::new();
                    sys.refresh_all();

                    let metrics = SystemMetrics {
                        timestamp: chrono::Utc::now().timestamp(),
                        cpu_usage: sys.global_cpu_info().cpu_usage(),
                        memory_usage: sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0,
                        disk_usage: sys.disks().iter()
                            .map(|disk| disk.total_space() - disk.available_space())
                            .sum::<u64>() as f64,
                        network_rx: sys.networks().iter()
                            .map(|(_, data)| data.received())
                            .sum(),
                        network_tx: sys.networks().iter()
                            .map(|(_, data)| data.transmitted())
                            .sum(),
                        process_count: sys.processes().len(),
                    };

                    // Record metrics
                    #[cfg(feature = "monitoring")]
                    {
                        gauge!("system.cpu_usage", metrics.cpu_usage);
                        gauge!("system.memory_usage", metrics.memory_usage);
                        gauge!("system.disk_usage", metrics.disk_usage);
                        gauge!("system.network.rx_bytes", metrics.network_rx as f64);
                        gauge!("system.network.tx_bytes", metrics.network_tx as f64);
                        gauge!("system.process_count", metrics.process_count as f64);
                    }

                    // Check thresholds and emit alerts
                    if let Some(ref thresholds) = thresholds {
                        if metrics.cpu_usage > thresholds.cpu_percent {
                            warn!("CPU usage above threshold: {:.2}%", metrics.cpu_usage);
                        }
                        if metrics.memory_usage > thresholds.memory_percent {
                            warn!("Memory usage above threshold: {:.2}%", metrics.memory_usage);
                        }
                        if metrics.disk_usage > thresholds.disk_percent {
                            warn!("Disk usage above threshold: {:.2}%", metrics.disk_usage);
                        }
                    }

                    #[cfg(feature = "monitoring")]
                    if tx.send(metrics).is_err() {
                        error!("Failed to send metrics update");
                        break;
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        }

        #[cfg(feature = "monitoring")]
        Ok(self.metrics_tx.subscribe())
    }

    /// Stop system monitoring
    pub fn stop_monitoring(&self) {
        self.monitoring_active.store(false, Ordering::SeqCst);
    }

    /// Export metrics to various formats
    pub async fn export_metrics(&self, format: &str) -> Result<String> {
        let metrics = self.collect_current_metrics().await?;
        
        match format.to_lowercase().as_str() {
            "json" => Ok(serde_json::to_string_pretty(&metrics)?),
            "prometheus" => {
                let mut output = String::new();
                output.push_str(&format!("# HELP system_cpu_usage Current CPU usage\n"));
                output.push_str(&format!("# TYPE system_cpu_usage gauge\n"));
                output.push_str(&format!("system_cpu_usage {}\n", metrics.cpu_usage));
                // Add other metrics...
                Ok(output)
            },
            _ => Err(anyhow::anyhow!("Unsupported export format: {}", format)),
        }
    }

    /// Collect current system metrics
    async fn collect_current_metrics(&self) -> Result<SystemMetrics> {
        let mut sys = System::new();
        sys.refresh_all();

        Ok(SystemMetrics {
            timestamp: chrono::Utc::now().timestamp(),
            cpu_usage: sys.global_cpu_info().cpu_usage(),
            memory_usage: sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0,
            disk_usage: sys.disks().iter()
                .map(|disk| disk.total_space() - disk.available_space())
                .sum::<u64>() as f64,
            network_rx: sys.networks().iter()
                .map(|(_, data)| data.received())
                .sum(),
            network_tx: sys.networks().iter()
                .map(|(_, data)| data.transmitted())
                .sum(),
            process_count: sys.processes().len(),
        })
    }

    /// Log environment creation event
    pub fn log_environment_creation(
        &self, 
        env_name: &str, 
        env_type: &str, 
        success: bool
    ) {
        if !self.config.enabled {
            return;
        }

        let event_data = serde_json::json!({
            "event_type": "environment_creation",
            "environment_name": if self.config.anonymize_data { "anonymized" } else { env_name },
            "environment_type": env_type,
            "success": success
        });

        info!(event = %event_data, "Environment Creation Event");
    }

    /// Log plugin detection event
    pub fn log_plugin_detection(
        &self, 
        plugin_id: &str, 
        detected: bool
    ) {
        if !self.config.enabled {
            return;
        }

        let event_data = serde_json::json!({
            "event_type": "plugin_detection",
            "plugin_id": plugin_id,
            "detected": detected
        });

        debug!(event = %event_data, "Plugin Detection Event");
    }

    /// Capture and log errors with context
    pub fn log_error<E: std::error::Error>(&self, error: &E, context: &str) {
        error!(
            error = %error, 
            context = context, 
            "An error occurred"
        );
    }
}

/// Trait for adding telemetry to structs
pub trait Telemetry {
    fn log_event(&self, event_type: &str, details: serde_json::Value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_telemetry_initialization() {
        let log_dir = tempdir().unwrap();
        let config = TelemetryConfig {
            enabled: true,
            log_level: LogLevel::Debug,
            log_directory: Some(log_dir.path().to_path_buf()),
            anonymize_data: true,
            #[cfg(feature = "monitoring")]
            metrics_enabled: true,
            alert_thresholds: None,
        };

        let telemetry = TelemetryManager::init(Some(config)).unwrap();
        
        // Log some test events
        telemetry.log_environment_creation("test-env", "docker", true);
        telemetry.log_plugin_detection("devcontainer", true);
    }

    #[test]
    fn test_performance_tracker() {
        {
            let _tracker = PerformanceTracker::new("test_operation");
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Performance will be logged via drop
    }
}
