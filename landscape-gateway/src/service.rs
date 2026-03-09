use crate::{GatewayManager, GatewayTlsConfig};
use landscape_common::config::gateway::config::GatewayRuntimeConfig;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
use landscape_database::repository::Repository;
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
        let initial_rules = store.list_all().await.unwrap_or_default();
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

    /// Signal gateway to stop and wait up to `timeout` for the Pingora thread
    /// to exit cleanly, without blocking the async runtime.
    pub async fn shutdown_and_wait(&self, timeout: std::time::Duration) {
        self.manager.shutdown();
        let manager = self.manager.clone();
        let join_task = tokio::task::spawn_blocking(move || {
            manager.join();
        });
        match tokio::time::timeout(timeout, join_task).await {
            Ok(Ok(())) => tracing::info!("Gateway thread exited cleanly."),
            Ok(Err(e)) => tracing::error!("Gateway join task panicked: {:?}", e),
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

    pub fn watch_service(&self) -> WatchService {
        self.manager.watch_service()
    }

    pub async fn reload_rules(&self) {
        let rules = self.store.list_all().await.unwrap_or_default();
        self.manager.reload_rules(rules);
    }
}
