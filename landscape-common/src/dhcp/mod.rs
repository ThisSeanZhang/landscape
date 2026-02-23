use landscape_macro::LdApiError;

pub mod v4_server;
pub mod v6_client;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DhcpError {
    #[error("DHCPv4 service config for '{0}' not found")]
    #[api_error(id = "dhcp.config_not_found", status = 404)]
    ConfigNotFound(String),

    #[error("DHCP IP range conflict: {0}")]
    #[api_error(id = "dhcp.ip_conflict", status = 409)]
    IpConflict(String),
}
