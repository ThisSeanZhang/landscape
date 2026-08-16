use arc_swap::{ArcSwap, ArcSwapOption};
use std::sync::Arc;
use std::time::Duration;

use landscape_common::config::ConfigId;
use landscape_common::database::error::DbError;
use landscape_common::database::LandscapeStore;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_service::gateway::settings::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::HttpUpstreamRuleConfig;
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
#[cfg(feature = "gateway")]
use landscape_database::repository::Repository;

#[cfg(feature = "gateway")]
#[derive(Debug, Clone)]
pub struct GatewayTlsConfig {
    inner: landscape_gateway::GatewayTlsConfig,
}

#[cfg(feature = "gateway")]
impl GatewayTlsConfig {
    pub fn new(server_config: std::sync::Arc<rustls::ServerConfig>) -> Self {
        Self {
            inner: landscape_gateway::GatewayTlsConfig { server_config },
        }
    }
}

#[cfg(feature = "gateway")]
#[derive(Clone)]
pub struct GatewayService {
    store: GatewayHttpUpstreamRepository,
    inner: Arc<ArcSwap<landscape_gateway::service::GatewayService>>,
    tls_config: Arc<ArcSwapOption<landscape_gateway::GatewayTlsConfig>>,
}

#[cfg(feature = "gateway")]
impl GatewayService {
    pub async fn init_service(
        store: GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        tls_config: Option<GatewayTlsConfig>,
    ) -> Self {
        let gateway_tls_config = tls_config.map(|config| config.inner);
        let inner = landscape_gateway::service::GatewayService::init_service(
            store.clone(),
            config,
            gateway_tls_config.clone(),
        )
        .await;
        Self {
            store,
            inner: Arc::new(ArcSwap::from_pointee(inner)),
            tls_config: Arc::new(ArcSwapOption::from(gateway_tls_config.map(Arc::new))),
        }
    }

    fn current(&self) -> Arc<landscape_gateway::service::GatewayService> {
        self.inner.load_full()
    }

    pub fn is_supported(&self) -> bool {
        true
    }

    pub fn status(&self) -> ServiceStatus {
        self.current().status()
    }

    pub fn has_https_listener(&self) -> bool {
        self.current().has_https_listener()
    }

    pub fn config(&self) -> GatewayRuntimeConfig {
        self.current().config().clone()
    }

    pub async fn shutdown_and_wait(&self, timeout: Duration) {
        self.current().shutdown_and_wait(timeout).await;
    }

    pub async fn restart(&self, config: GatewayRuntimeConfig, timeout: Duration) {
        let old_inner = self.current();
        old_inner.shutdown_and_wait(timeout).await;

        let tls_config = self.tls_config.load_full().as_deref().cloned();
        let new_inner = landscape_gateway::service::GatewayService::init_service(
            self.store.clone(),
            config,
            tls_config,
        )
        .await;
        self.inner.store(Arc::new(new_inner));
    }

    pub async fn list_rules(&self) -> Result<Vec<HttpUpstreamRuleConfig>, DbError> {
        self.store.list().await
    }

    pub async fn save_rule(
        &self,
        rule: HttpUpstreamRuleConfig,
    ) -> Result<HttpUpstreamRuleConfig, DbError> {
        self.store.set(rule).await
    }

    pub async fn find_rule(&self, id: ConfigId) -> Result<Option<HttpUpstreamRuleConfig>, DbError> {
        Repository::find_by_id(&self.store, id).await
    }

    pub async fn delete_rule(&self, id: ConfigId) -> Result<(), DbError> {
        self.store.delete(id).await
    }

    pub async fn reload_rules(&self) {
        self.current().reload_rules().await;
    }

    pub async fn stored_rule_count(&self) -> usize {
        self.list_rules().await.map(|rules| rules.len()).unwrap_or_default()
    }
}

#[cfg(not(feature = "gateway"))]
#[derive(Debug, Clone)]
pub struct GatewayTlsConfig;

#[cfg(not(feature = "gateway"))]
impl GatewayTlsConfig {
    #[allow(dead_code)]
    pub fn new(_server_config: std::sync::Arc<rustls::ServerConfig>) -> Self {
        Self
    }
}

#[cfg(not(feature = "gateway"))]
#[derive(Clone)]
pub struct GatewayService {
    store: GatewayHttpUpstreamRepository,
    config: Arc<ArcSwap<GatewayRuntimeConfig>>,
}

#[cfg(not(feature = "gateway"))]
impl GatewayService {
    pub async fn init_service(
        store: GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        _tls_config: Option<GatewayTlsConfig>,
    ) -> Self {
        Self {
            store,
            config: Arc::new(ArcSwap::from_pointee(config)),
        }
    }

    pub fn is_supported(&self) -> bool {
        false
    }

    pub fn status(&self) -> ServiceStatus {
        ServiceStatus::Stop
    }

    pub fn has_https_listener(&self) -> bool {
        false
    }

    pub fn config(&self) -> GatewayRuntimeConfig {
        (*self.config.load_full()).clone()
    }

    pub async fn shutdown_and_wait(&self, _timeout: Duration) {}

    pub async fn restart(&self, config: GatewayRuntimeConfig, _timeout: Duration) {
        self.config.store(Arc::new(config));
    }

    pub async fn list_rules(&self) -> Result<Vec<HttpUpstreamRuleConfig>, DbError> {
        Err(DbError::Internal("gateway is not supported on this target architecture".to_string()))
    }

    pub async fn save_rule(
        &self,
        _rule: HttpUpstreamRuleConfig,
    ) -> Result<HttpUpstreamRuleConfig, DbError> {
        Err(DbError::Internal("gateway is not supported on this target architecture".to_string()))
    }

    pub async fn find_rule(
        &self,
        _id: ConfigId,
    ) -> Result<Option<HttpUpstreamRuleConfig>, DbError> {
        Err(DbError::Internal("gateway is not supported on this target architecture".to_string()))
    }

    pub async fn delete_rule(&self, _id: ConfigId) -> Result<(), DbError> {
        Err(DbError::Internal("gateway is not supported on this target architecture".to_string()))
    }

    pub async fn reload_rules(&self) {}

    pub async fn stored_rule_count(&self) -> usize {
        self.store.list().await.map(|rules| rules.len()).unwrap_or_default()
    }
}
