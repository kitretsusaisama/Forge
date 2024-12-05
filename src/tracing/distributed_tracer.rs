use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Distributed Tracing Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedTracingConfig {
    /// Enable/disable tracing
    pub enabled: bool,
    
    /// Sampling rate
    pub sampling_rate: f32,
    
    /// Maximum trace duration
    pub max_trace_duration: Duration,
    
    /// Trace storage configuration
    pub storage: TraceStorageConfig,
}

/// Trace storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStorageConfig {
    /// Storage type
    pub storage_type: StorageType,
    
    /// Maximum number of traces to store
    pub max_traces: usize,
    
    /// Retention period for traces
    pub retention_period: Duration,
}

/// Trace storage types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    InMemory,
    Filesystem,
    Database,
}

/// Distributed Tracing Service
pub struct DistributedTracer {
    /// Configuration
    config: DistributedTracingConfig,
    
    /// Active traces
    active_traces: HashMap<Uuid, Trace>,
    
    /// Completed traces
    completed_traces: Vec<Trace>,
}

/// Trace representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    /// Unique trace ID
    pub id: Uuid,
    
    /// Parent trace ID (if this is a child trace)
    pub parent_trace_id: Option<Uuid>,
    
    /// Trace name or description
    pub name: String,
    
    /// Trace start time
    pub start_time: Instant,
    
    /// Trace end time
    pub end_time: Option<Instant>,
    
    /// Trace spans
    pub spans: Vec<TraceSpan>,
    
    /// Trace metadata
    pub metadata: HashMap<String, String>,
}

/// Individual trace span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    /// Span ID
    pub id: Uuid,
    
    /// Span name
    pub name: String,
    
    /// Start time of the span
    pub start_time: Instant,
    
    /// End time of the span
    pub end_time: Option<Instant>,
    
    /// Span attributes
    pub attributes: HashMap<String, String>,
    
    /// Span events
    pub events: Vec<SpanEvent>,
}

/// Span event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    /// Event name
    pub name: String,
    
    /// Event timestamp
    pub timestamp: Instant,
    
    /// Event attributes
    pub attributes: HashMap<String, String>,
}

impl DistributedTracer {
    /// Create a new distributed tracer
    pub fn new(config: DistributedTracingConfig) -> Self {
        Self {
            config,
            active_traces: HashMap::new(),
            completed_traces: Vec::new(),
        }
    }

    /// Start a new trace
    pub fn start_trace(&mut self, name: &str, parent_trace_id: Option<Uuid>) -> Uuid {
        let trace_id = Uuid::new_v4();
        
        let trace = Trace {
            id: trace_id,
            parent_trace_id,
            name: name.to_string(),
            start_time: Instant::now(),
            end_time: None,
            spans: Vec::new(),
            metadata: HashMap::new(),
        };
        
        self.active_traces.insert(trace_id, trace);
        
        trace_id
    }

    /// Start a new span within a trace
    pub fn start_span(&mut self, trace_id: Uuid, name: &str) -> Option<Uuid> {
        let trace = self.active_traces.get_mut(&trace_id)?;
        
        let span_id = Uuid::new_v4();
        
        let span = TraceSpan {
            id: span_id,
            name: name.to_string(),
            start_time: Instant::now(),
            end_time: None,
            attributes: HashMap::new(),
            events: Vec::new(),
        };
        
        trace.spans.push(span);
        
        Some(span_id)
    }

    /// End a span within a trace
    pub fn end_span(&mut self, trace_id: Uuid, span_id: Uuid) -> Result<()> {
        let trace = self.active_traces.get_mut(&trace_id)
            .context("Trace not found")?;
        
        let span = trace.spans.iter_mut()
            .find(|s| s.id == span_id)
            .context("Span not found")?;
        
        span.end_time = Some(Instant::now());
        
        Ok(())
    }

    /// End a trace
    pub fn end_trace(&mut self, trace_id: Uuid) -> Result<()> {
        let mut trace = self.active_traces.remove(&trace_id)
            .context("Trace not found")?;
        
        trace.end_time = Some(Instant::now());
        
        // Check trace duration
        if let Some(end_time) = trace.end_time {
            let duration = end_time.duration_since(trace.start_time);
            if duration > self.config.max_trace_duration {
                // Log or handle long-running traces
            }
        }
        
        // Store completed trace
        self.store_trace(trace);
        
        Ok(())
    }

    /// Store completed trace
    fn store_trace(&mut self, trace: Trace) {
        // Manage trace storage based on configuration
        match self.config.storage.storage_type {
            StorageType::InMemory => {
                // Keep only the most recent traces
                if self.completed_traces.len() >= self.config.storage.max_traces {
                    self.completed_traces.remove(0);
                }
                self.completed_traces.push(trace);
            },
            // Additional storage types can be implemented
            _ => {}
        }
    }

    /// Add event to a span
    pub fn add_span_event(
        &mut self, 
        trace_id: Uuid, 
        span_id: Uuid, 
        event_name: &str, 
        attributes: HashMap<String, String>
    ) -> Result<()> {
        let trace = self.active_traces.get_mut(&trace_id)
            .context("Trace not found")?;
        
        let span = trace.spans.iter_mut()
            .find(|s| s.id == span_id)
            .context("Span not found")?;
        
        let event = SpanEvent {
            name: event_name.to_string(),
            timestamp: Instant::now(),
            attributes,
        };
        
        span.events.push(event);
        
        Ok(())
    }

    /// Retrieve traces
    pub fn get_traces(&self) -> &[Trace] {
        &self.completed_traces
    }

    /// Analyze trace performance
    pub fn analyze_traces(&self) -> Vec<TracePerformanceInsight> {
        let mut insights = Vec::new();

        for trace in &self.completed_traces {
            if let (Some(start), Some(end)) = (trace.start_time, trace.end_time) {
                let total_duration = end.duration_since(start);
                
                // Analyze span durations
                let slow_spans: Vec<_> = trace.spans.iter()
                    .filter_map(|span| {
                        span.end_time.map(|end_time| {
                            let span_duration = end_time.duration_since(span.start_time);
                            (span, span_duration)
                        })
                    })
                    .filter(|(_, duration)| *duration > Duration::from_millis(100))
                    .collect();

                if !slow_spans.is_empty() {
                    insights.push(TracePerformanceInsight {
                        trace_id: trace.id,
                        total_duration,
                        slow_spans: slow_spans.into_iter()
                            .map(|(span, duration)| (span.name.clone(), duration))
                            .collect(),
                    });
                }
            }
        }

        insights
    }
}

/// Performance insight for a trace
#[derive(Debug)]
pub struct TracePerformanceInsight {
    /// Trace ID
    pub trace_id: Uuid,
    
    /// Total trace duration
    pub total_duration: Duration,
    
    /// Slow spans with their durations
    pub slow_spans: Vec<(String, Duration)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_distributed_tracing() {
        let config = DistributedTracingConfig {
            enabled: true,
            sampling_rate: 1.0,
            max_trace_duration: Duration::from_secs(10),
            storage: TraceStorageConfig {
                storage_type: StorageType::InMemory,
                max_traces: 100,
                retention_period: Duration::from_secs(3600),
            },
        };

        let mut tracer = DistributedTracer::new(config);

        // Start a trace
        let trace_id = tracer.start_trace("test_trace", None);

        // Start a span
        let span_id = tracer.start_span(trace_id, "test_span").unwrap();

        // Simulate some work
        thread::sleep(Duration::from_millis(50));

        // Add an event
        tracer.add_span_event(
            trace_id, 
            span_id, 
            "processing", 
            HashMap::from([("key".to_string(), "value".to_string())])
        ).unwrap();

        // End span
        tracer.end_span(trace_id, span_id).unwrap();

        // End trace
        tracer.end_trace(trace_id).unwrap();

        // Analyze traces
        let insights = tracer.analyze_traces();
        assert!(!insights.is_empty());
    }
}
