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
