use serde::{Deserialize, Serialize};

/// Lifecycle phase of one flow's DNS runtime.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FlowDnsPhase {
    /// The whole DNS service is stopped.
    Stopped,
    /// The service is running, but this flow has no listener yet.
    Idle,
    /// A listener is being built for this flow.
    Starting,
    /// The flow has a live listener runtime.
    Running,
    /// The last listener build attempt failed.
    Failed,
}

/// Read-only projection of one flow's DNS runtime state, safe to expose over
/// the API. Internal handlers, tokens and dependency sets stay out of it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowDnsStatus {
    pub flow_id: u32,
    pub phase: FlowDnsPhase,
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = true))]
    pub last_error: Option<String>,
    pub revision: u64,
    /// Unix timestamp in milliseconds when the snapshot last changed.
    pub updated_at: f64,
}

/// Aggregate health of the DNS service across all tracked flows.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DnsServicePhase {
    /// The service is not running.
    Stopped,
    /// At least one flow is being started or refreshed.
    Starting,
    /// The service is running but has no tracked flow.
    Idle,
    /// Every tracked flow has a live listener.
    Running,
    /// Some flows are live while others are failed or idle.
    Degraded,
    /// No flow is live and at least one flow failed.
    Failed,
}

/// Read-only aggregate DNS service status with per-phase flow counts.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsServiceStatus {
    pub phase: DnsServicePhase,
    pub total_flows: u32,
    pub running_flows: u32,
    pub starting_flows: u32,
    pub idle_flows: u32,
    pub failed_flows: u32,
}
