// Distributed Tracing Module

pub mod distributed_tracer;

// Expose key types and functions
pub use distributed_tracer::{
    DistributedTracer, 
    DistributedTracingConfig, 
    Trace, 
    TraceSpan, 
    TracePerformanceInsight
};
