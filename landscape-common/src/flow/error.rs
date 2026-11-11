use landscape_macro::LdApiError;

use crate::config::ConfigId;
use crate::database::error::DbError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum FlowRuleError {
    #[error("Flow rule '{0}' not found")]
    #[api_error(id = "flow_rule.not_found", status = 404)]
    NotFound(ConfigId),

    #[error("Duplicate entry match rule: {0}")]
    #[api_error(id = "flow_rule.duplicate_entry", status = 400)]
    DuplicateEntryRule(String),

    #[error("Entry rule '{rule}' conflicts with flow '{flow_remark}' (ID: {flow_id})")]
    #[api_error(id = "flow_rule.conflict_entry", status = 400)]
    ConflictEntryRule { rule: String, flow_remark: String, flow_id: u32 },

    #[error("At least one configured flow target must have a positive weight")]
    #[api_error(id = "flow_rule.invalid_target_weight", status = 400)]
    InvalidTargetWeight,

    #[error("Flow rule cannot have more than 16 targets (load balancing uses 16 slots)")]
    #[api_error(id = "flow_rule.too_many_targets", status = 400)]
    TooManyTargets,

    #[error("Flow device target '{0}' not found")]
    #[api_error(id = "flow_rule.device_not_found", status = 404)]
    DeviceNotFound(ConfigId),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}

/// Error returned when a DNS listener socket cannot be inserted into the
/// datapath map. Callers must close the listener on error so the kernel cannot
/// distribute traffic to a socket that is missing from the reuseport map.
///
/// Reuseport dispatcher attach failures are intentionally not represented
/// here: all listeners of a role share one reuseport group, so only the first
/// attach takes effect and later ones are logged and ignored.
#[derive(Debug, thiserror::Error)]
pub enum DnsSocketRegisterError {
    #[error("DNS flow id {flow_id} exceeds the supported 0..={max} range")]
    InvalidFlowId { flow_id: u32, max: u32 },

    #[error("failed to update dns_flow_socks: {0}")]
    MapUpdate(String),
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DstIpRuleError {
    #[error("Destination IP rule '{0}' not found")]
    #[api_error(id = "dst_ip_rule.not_found", status = 404)]
    NotFound(ConfigId),
    #[error(
        "Destination IP rule '{0}' cannot be moved to another flow; delete it and create a new rule in the target flow instead"
    )]
    #[api_error(id = "dst_ip_rule.cannot_change_flow", status = 400)]
    CannotChangeFlow(ConfigId),
}
