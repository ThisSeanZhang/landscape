use super::settings::LandscapeGatewayConfig;

const DEFAULT_ENABLE: bool = false;
const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Debug, Clone)]
pub struct GatewayRuntimeConfig {
    pub enable: bool,
    pub http_port: u16,
    pub https_port: u16,
}

impl Default for GatewayRuntimeConfig {
    fn default() -> Self {
        Self {
            enable: DEFAULT_ENABLE,
            http_port: DEFAULT_HTTP_PORT,
            https_port: DEFAULT_HTTPS_PORT,
        }
    }
}

impl GatewayRuntimeConfig {
    pub fn from_file_config(config: &LandscapeGatewayConfig) -> Self {
        Self {
            enable: config.enable.unwrap_or(DEFAULT_ENABLE),
            http_port: config.http_port.unwrap_or(DEFAULT_HTTP_PORT),
            https_port: config.https_port.unwrap_or(DEFAULT_HTTPS_PORT),
        }
    }
}
