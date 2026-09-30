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
