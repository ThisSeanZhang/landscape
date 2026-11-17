//! Proxy runtime for builds with gateway support.
//! GatewayService serializes lifecycle changes and supplies persistent rules.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use landscape_common::cert::CertError;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_config::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use landscape_gateway::{GatewayServer, GatewayTlsConfig};

use crate::cert::order_service::CertService;

#[derive(Clone)]
pub(super) struct GatewayRuntime {
    server: Arc<ArcSwap<GatewayServer>>,
    tls_config: GatewayTlsConfig,
}

impl GatewayRuntime {
    pub(super) async fn new(
        rules: Vec<HttpUpstreamRuleConfig>,
        config: GatewayRuntimeConfig,
        cert_service: &CertService,
    ) -> Result<Self, CertError> {
        let count = cert_service.reload_gateway_tls_mapping().await?;
        if count == 0 {
            tracing::warn!(
                "No valid for_gateway certificate found; gateway HTTPS listener will start but reject TLS handshakes until a certificate is loaded"
            );
        }
        let mut server_config = landscape_core::cert::build_tls_server_config_with_shared_resolver(
            cert_service.gateway_tls_resolver(),
        );
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls_config = GatewayTlsConfig { server_config: Arc::new(server_config) };
        let server = Self::create_server(rules, config, tls_config.clone());
        Ok(Self {
            server: Arc::new(ArcSwap::from(server)),
            tls_config,
        })
    }

    fn create_server(
        rules: Vec<HttpUpstreamRuleConfig>,
        config: GatewayRuntimeConfig,
        tls_config: GatewayTlsConfig,
    ) -> Arc<GatewayServer> {
        let server = Arc::new(GatewayServer::new(rules, config, Some(tls_config)));
        if server.config().enable {
            server.start();
        }
        server
    }

    pub(super) fn is_supported() -> bool {
        true
    }

    pub(super) fn status(&self) -> ServiceStatus {
        self.server.load().status()
    }

    pub(super) fn has_https_listener(&self) -> bool {
        self.server.load().has_https_listener()
    }

    pub(super) fn config(&self) -> Option<GatewayRuntimeConfig> {
        Some(self.server.load().config().clone())
    }

    pub(super) async fn shutdown_and_wait(&self, timeout: Duration) {
        let server = self.server.load_full();
        server.shutdown();
        let Some(mut done_rx) = server.done_receiver() else {
            return;
        };
        let terminal = done_rx
            .wait_for(|status| matches!(status, ServiceStatus::Stop | ServiceStatus::Failed));
        match tokio::time::timeout(timeout, terminal).await {
            Ok(_) => tracing::info!("Gateway run finished: {:?}", server.status()),
            Err(_) => tracing::warn!(
                "Gateway did not stop within {}s timeout, proceeding.",
                timeout.as_secs()
            ),
        }
    }

    pub(super) async fn restart(
        &self,
        rules: Vec<HttpUpstreamRuleConfig>,
        config: GatewayRuntimeConfig,
        timeout: Duration,
    ) -> Result<(), GatewayError> {
        self.shutdown_and_wait(timeout).await;
        let server = Self::create_server(rules, config, self.tls_config.clone());
        self.server.store(server);
        Ok(())
    }

    pub(super) fn reload_rules(
        &self,
        rules: Vec<HttpUpstreamRuleConfig>,
    ) -> Result<(), GatewayError> {
        self.server.load().reload_rules(rules);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn shared_rules(&self) -> landscape_gateway::SharedRules {
        self.server.load().shared_rules()
    }
}
