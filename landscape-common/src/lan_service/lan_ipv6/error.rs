use landscape_macro::LdApiError;

use crate::error::LdError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum LanIPv6Error {
    #[error("LAN IPv6 configuration has been modified. Please refresh and try again.")]
    #[api_error(id = "lan_ipv6.config_conflict", status = 409)]
    ConfigConflict,

    #[error("LAN IPv6 prefix slot conflict: {reason}")]
    #[api_error(id = "lan_ipv6.prefix_conflict", status = 409)]
    PrefixConflict { reason: String },

    #[error(transparent)]
    #[api_error(id = "lan_ipv6.internal", status = 500)]
    Internal(#[from] LdError),
}
