use super::{config::LandscapeGatewayConfig, error::GatewayConfigError};
use crate::sys_config::{RuntimeConfigSource, runtime::warn_repair};

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
        config.build_runtime()
    }
}

impl RuntimeConfigSource for LandscapeGatewayConfig {
    type Runtime = GatewayRuntimeConfig;
    type Error = GatewayConfigError;

    fn validate(&self) -> Result<(), Self::Error> {
        let http = self.http_port.unwrap_or(DEFAULT_HTTP_PORT);
        let https = self.https_port.unwrap_or(DEFAULT_HTTPS_PORT);
        for (field, port) in [("http_port", http), ("https_port", https)] {
            if port == 0 {
                return Err(GatewayConfigError::ZeroPort { field });
            }
        }
        if http == https {
            return Err(GatewayConfigError::PortConflict { port: http });
        }
        Ok(())
    }

    fn build_runtime(&self) -> Self::Runtime {
        let repair_port = |field, port: Option<u16>, default| match port {
            Some(0) => {
                warn_repair(
                    "gateway",
                    field,
                    GatewayConfigError::ZeroPort { field },
                    "using default",
                    default,
                );
                default
            }
            port => port.unwrap_or(default),
        };
        let mut http_port = repair_port("http_port", self.http_port, DEFAULT_HTTP_PORT);
        let mut https_port = repair_port("https_port", self.https_port, DEFAULT_HTTPS_PORT);
        if http_port == https_port {
            let error = GatewayConfigError::PortConflict { port: http_port };
            if http_port == DEFAULT_HTTPS_PORT {
                http_port = DEFAULT_HTTP_PORT;
                warn_repair("gateway", "http_port", error, "using default", http_port);
            } else {
                https_port = DEFAULT_HTTPS_PORT;
                warn_repair("gateway", "https_port", error, "using default", https_port);
            }
        }
        GatewayRuntimeConfig {
            enable: self.enable.unwrap_or(DEFAULT_ENABLE),
            http_port,
            https_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_updates_reject_conflicting_and_ephemeral_ports() {
        for config in [
            LandscapeGatewayConfig { http_port: Some(0), ..Default::default() },
            LandscapeGatewayConfig { https_port: Some(0), ..Default::default() },
            LandscapeGatewayConfig { http_port: Some(443), ..Default::default() },
        ] {
            assert!(config.to_runtime().is_err());
            let repaired = config.build_runtime();
            assert_ne!(repaired.http_port, 0);
            assert_ne!(repaired.https_port, 0);
            assert_ne!(repaired.http_port, repaired.https_port);
        }
    }
}
