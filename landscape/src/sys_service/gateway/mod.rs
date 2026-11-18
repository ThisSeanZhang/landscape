use landscape_common::{service::ServiceStatus, sys_config::GatewayRuntimeConfig};
#[cfg(feature = "gateway")]
mod service;
#[cfg(not(feature = "gateway"))]
#[path = "unsupported.rs"]
mod service;
pub use service::GatewayService;
pub struct GatewayRuntimeStatus {
    pub config: Option<GatewayRuntimeConfig>,
    pub status: ServiceStatus,
    pub https_ready: bool,
    pub last_error: Option<String>,
}

impl GatewayService {
    pub fn status(&self) -> ServiceStatus {
        self.runtime_status().status
    }
    pub fn last_error(&self) -> Option<String> {
        self.runtime_status().last_error
    }
    pub fn has_https_listener(&self) -> bool {
        self.runtime_status().https_ready
    }
    pub fn runtime_config(&self) -> Option<GatewayRuntimeConfig> {
        self.runtime_status().config
    }
}
