//! Runtime boundary for builds without gateway support. No proxy state is kept.

use std::time::Duration;

use landscape_common::cert::CertError;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_config::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};

use crate::cert::order_service::CertService;

#[derive(Clone)]
pub(super) struct GatewayRuntime;

#[derive(Default)]
pub(super) struct PreparedRoutes;

impl GatewayRuntime {
    pub(super) async fn new(
        _routes: PreparedRoutes,
        _config: GatewayRuntimeConfig,
        _cert_service: &CertService,
    ) -> Result<Self, CertError> {
        Ok(Self)
    }

    pub(super) fn is_supported() -> bool {
        false
    }

    pub(super) fn prepare_rules(
        _rules: &[HttpUpstreamRuleConfig],
    ) -> Result<PreparedRoutes, GatewayError> {
        // Import preflight still performs shared business validation, but there
        // is no proxy backend to compile on this build. CRUD remains unsupported.
        Ok(PreparedRoutes)
    }

    pub(super) fn status(&self) -> ServiceStatus {
        ServiceStatus::Stop
    }

    pub(super) fn has_https_listener(&self) -> bool {
        false
    }

    pub(super) fn config(&self) -> Option<GatewayRuntimeConfig> {
        None
    }

    pub(super) async fn shutdown_and_wait(&self, _timeout: Duration) {}

    pub(super) async fn restart(
        &self,
        _routes: PreparedRoutes,
        _config: GatewayRuntimeConfig,
        _timeout: Duration,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::Unsupported)
    }

    pub(super) fn publish_routes(&self, _routes: PreparedRoutes) {}
}
