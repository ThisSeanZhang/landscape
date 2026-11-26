use super::GatewayRuntimeStatus;
use crate::cert::order_service::CertService;
use crate::config_service::gateway_rule_service::GatewayRuleConfigService;
use landscape_common::{
    service::ServiceStatus, sys_config::GatewayRuntimeConfig, sys_service::gateway::GatewayError,
};
use std::time::Duration;

#[derive(Clone)]
pub struct GatewayService;
impl GatewayService {
    pub async fn init_service(
        _: GatewayRuleConfigService,
        _: GatewayRuntimeConfig,
        _: &CertService,
    ) -> Self {
        Self
    }

    pub fn is_supported(&self) -> bool {
        false
    }

    pub fn runtime_status(&self) -> GatewayRuntimeStatus {
        GatewayRuntimeStatus {
            config: None,
            status: ServiceStatus::Stop,
            https_ready: false,
            last_error: None,
        }
    }

    pub async fn restart(&self, _: GatewayRuntimeConfig, _: Duration) -> Result<(), GatewayError> {
        Err(GatewayError::Unsupported)
    }

    pub async fn shutdown_and_wait(&self, _: Duration) -> Result<(), GatewayError> {
        Ok(())
    }
}
