use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum ServiceConfigError {
    #[error("{service_name} service config not found")]
    #[api_error(id = "service.config_not_found", status = 404)]
    NotFound { service_name: &'static str },

    #[error(
        "Service '{service_name}' cannot be configured on interface '{iface_name}': zone mismatch"
    )]
    #[api_error(id = "service.zone_mismatch", status = 422)]
    ZoneMismatch { service_name: crate::config_service::iface::ServiceKind, iface_name: String },

    #[error("Interface '{iface_name}' not found")]
    #[api_error(id = "service.iface_not_found", status = 404)]
    IfaceNotFound { iface_name: String },

    #[error("Invalid service config: {reason}")]
    #[api_error(id = "service.invalid_config", status = 422)]
    InvalidConfig { reason: String },

    #[error("Flow ID {flow_id} is outside the supported range 1..=255")]
    #[api_error(id = "service.flow_id_out_of_range", status = 422)]
    FlowIdOutOfRange { flow_id: u32 },

    #[error(
        "Flow {flow_id} needs an enabled primary/backup policy or a single effective WAN target for independent DNS groups"
    )]
    #[api_error(id = "service.wan_dns_flow_unsupported", status = 422)]
    WanDnsFlowUnsupported { flow_id: u32 },

    #[error("DNS upstream is still referenced by: {references}")]
    #[api_error(id = "service.dns_upstream_in_use", status = 422)]
    DnsUpstreamInUse { references: String },

    #[error("WAN link is still referenced by: {references}")]
    #[api_error(id = "service.wan_link_in_use", status = 422)]
    WanLinkInUse { references: String },

    #[error("Redirect target flow {flow_id} does not exist")]
    #[api_error(id = "service.flow_redirect_target_missing", status = 422)]
    FlowRedirectTargetMissing { flow_id: u32 },

    #[error("Flow {flow_id} is still referenced by: {references}")]
    #[api_error(id = "service.flow_referenced", status = 422)]
    FlowReferenced { flow_id: u32, references: String },

    /// Validation could not complete (e.g. a cross-domain read failed);
    /// `reason` is logged server-side, never shown to the frontend.
    #[error("Config validation failed with an internal error")]
    #[api_error(id = "internal.error", status = 500)]
    Internal { reason: String },
}

impl ServiceConfigError {
    /// Log the internal reason server-side and return the redacted error.
    pub fn internal(reason: impl std::fmt::Display) -> Self {
        let reason = reason.to_string();
        tracing::error!("validation internal error: {reason}");
        Self::Internal { reason }
    }
}
