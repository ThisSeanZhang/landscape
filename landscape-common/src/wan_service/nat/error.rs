use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum NatServiceError {
    #[error("NAT config not found for '{0}'")]
    #[api_error(id = "nat.not_found", status = 404)]
    NotFound(String),

    #[error("{name} start port must be > 0")]
    #[api_error(id = "nat.port_start_zero", status = 422)]
    PortStartZero { name: String },

    #[error("{name} start ({start}) must be less than end ({end})")]
    #[api_error(id = "nat.port_range_invalid", status = 422)]
    PortRangeInvalid { name: String, start: u16, end: u16 },
}
