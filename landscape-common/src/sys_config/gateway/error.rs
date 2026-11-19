use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum GatewayConfigError {
    #[error("Gateway {field} must not be zero")]
    #[api_error(id = "gateway.config.zero_port", status = 400)]
    ZeroPort { field: &'static str },
    #[error("Gateway HTTP and HTTPS cannot use the same port {port}")]
    #[api_error(id = "gateway.config.port_conflict", status = 400)]
    PortConflict { port: u16 },
}
