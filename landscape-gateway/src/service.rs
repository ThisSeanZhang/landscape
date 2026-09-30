use crate::{GatewayManager, GatewayTlsConfig};
use landscape_common::database::store::ConfigStore;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_service::gateway::settings::GatewayRuntimeConfig;
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
use std::sync::Arc;

#[derive(Clone)]
pub struct GatewayService {
    manager: Arc<GatewayManager>,
    store: GatewayHttpUpstreamRepository,
}

impl GatewayService {
    pub fn new(manager: Arc<GatewayManager>, store: GatewayHttpUpstreamRepository) -> Self {
        Self { manager, store }
    }

    pub async fn init_service(
        store: GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        tls_config: Option<GatewayTlsConfig>,
    ) -> Self {
        let initial_rules = store.list().await.unwrap_or_default();
        let manager = Arc::new(GatewayManager::new(initial_rules, config, tls_config));

        let service = Self::new(manager, store);
        if service.manager.config().enable {
            service.start();
        }
        service
    }

    pub fn manager(&self) -> &Arc<GatewayManager> {
        &self.manager
    }

    pub fn store(&self) -> &GatewayHttpUpstreamRepository {
        &self.store
    }

    pub fn config(&self) -> &GatewayRuntimeConfig {
        self.manager.config()
    }

    pub fn has_https_listener(&self) -> bool {
        self.manager.has_https_listener()
    }

    pub fn start(&self) {
        self.manager.start();
    }

    /// Signal gateway to stop (non-blocking). Any ongoing requests will be
    /// interrupted when the Arc<GatewayManager> is dropped (which calls join).
    pub fn shutdown(&self) {
        self.manager.shutdown();
    }

    /// Signal gateway to stop and wait up to `timeout` for the gateway run to
    /// report a terminal status. Awaits the run's completion watch instead of
    /// polling; the blocking thread join still happens at manager drop.
    pub async fn shutdown_and_wait(&self, timeout: std::time::Duration) {
        self.manager.shutdown();
        let Some(done_rx) = self.manager.done_receiver() else {
            tracing::info!("Gateway not running.");
            return;
        };
        let mut done_rx = done_rx;
        let terminal = done_rx
            .wait_for(|status| matches!(status, ServiceStatus::Stop | ServiceStatus::Failed));
        match tokio::time::timeout(timeout, terminal).await {
            // 完成通道在极端路径下关闭(如 send 前线程即退出):以状态单元收尾
            Ok(_) => tracing::info!("Gateway run finished: {:?}", self.status()),
            Err(_) => tracing::warn!(
                "Gateway did not stop within {}s timeout, proceeding.",
                timeout.as_secs()
            ),
        }
    }

    pub fn is_running(&self) -> bool {
        self.manager.is_running()
    }

    pub fn status(&self) -> ServiceStatus {
        self.manager.status()
    }

    pub async fn reload_rules(&self) {
        let rules = self.store.list().await.unwrap_or_default();
        self.manager.reload_rules(rules);
    }
}
