use landscape_macro::LdApiError;
use uuid::Uuid;

use crate::config::ConfigId;
use crate::database::error::DbError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum StaticNatError {
    #[error("Static NAT mapping '{0}' not found")]
    #[api_error(id = "static_nat.not_found", status = 404)]
    NotFound(ConfigId),

    #[error("Device '{0}' referenced in static NAT config does not exist")]
    #[api_error(id = "static_nat.device_not_found", status = 404)]
    DeviceNotFound(ConfigId),

    #[error("Device '{0}' does not have an IPv4 address")]
    #[api_error(id = "static_nat.device_missing_ipv4", status = 422)]
    DeviceMissingIpv4(ConfigId),

    #[error("Device '{0}' does not have an IPv6 address")]
    #[api_error(id = "static_nat.device_missing_ipv6", status = 422)]
    DeviceMissingIpv6(ConfigId),

    #[error("Static NAT target must resolve to a valid target: {0}")]
    #[api_error(id = "static_nat.invalid_target", status = 422)]
    InvalidTarget(String),

    #[error("Static NAT port {port} conflicts with dynamic range on '{iface_name}' ({protocol} range {start}-{end})")]
    #[api_error(id = "static_nat.port_conflict", status = 409)]
    PortConflict { port: u16, iface_name: String, protocol: u8, start: u16, end: u16 },

    #[error("Static NAT mapping {mapping_id} port {port} overlaps with dynamic {protocol} range {start}-{end}")]
    #[api_error(id = "static_nat.port_in_dynamic_range", status = 409)]
    PortInDynamicRange { mapping_id: Uuid, port: u16, protocol: u8, start: u16, end: u16 },

    #[error(transparent)]
    #[api_error(id = "static_nat.internal", status = 500)]
    Internal(#[from] DbError),
}
