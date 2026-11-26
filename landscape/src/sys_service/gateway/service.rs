use super::GatewayRuntimeStatus;
use crate::cert::order_service::CertService;
use crate::config_service::gateway_rule_service::GatewayRuleConfigService;
use arc_swap::ArcSwap;
use landscape_common::error::LdApiErrorInfo;
use landscape_common::{
    service::ServiceStatus, sys_config::GatewayRuntimeConfig, sys_service::gateway::GatewayError,
};
use landscape_gateway::{GatewayServer, GatewayTlsConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

enum GatewayState {
    Uninitialized { config: GatewayRuntimeConfig, error: String },
    Disabled(GatewayRuntimeConfig),
    Serving { config: GatewayRuntimeConfig, server: GatewayServer },
}

#[derive(Clone)]
pub struct GatewayService {
    rules: GatewayRuleConfigService,
    cert_service: CertService,
    lifecycle: Arc<Mutex<()>>,
    state: Arc<ArcSwap<GatewayState>>,
}

impl GatewayService {
    pub async fn init_service(
        rules: GatewayRuleConfigService,
        config: GatewayRuntimeConfig,
        cert_service: &CertService,
    ) -> Self {
        let rule_error = rules.initial_error();
        let service = Self {
            rules,
            cert_service: cert_service.clone(),
            lifecycle: Default::default(),
            state: Arc::new(ArcSwap::from_pointee(GatewayState::Uninitialized {
                config: config.clone(),
                error: "Gateway rules are valid; restart the gateway to retry initialization"
                    .into(),
            })),
        };
        if let Some(error) = rule_error {
            tracing::error!("Gateway rule initialization failed: {error}");
        } else if let Err(error) = service.restart(config, Duration::ZERO).await {
            tracing::error!("Gateway initialization failed: {error}");
        }
        service
    }

    pub fn is_supported(&self) -> bool {
        true
    }

    pub fn runtime_status(&self) -> GatewayRuntimeStatus {
        let (config, status, https_ready, last_error) = match &**self.state.load() {
            GatewayState::Uninitialized { config, error } => (
                Some(config.clone()),
                ServiceStatus::Failed,
                false,
                Some(self.rules.initial_error().unwrap_or_else(|| error.clone())),
            ),
            GatewayState::Disabled(config) => {
                (Some(config.clone()), ServiceStatus::Stop, false, self.rules.initial_error())
            }
            GatewayState::Serving { config, server } => (
                Some(config.clone()),
                server.status(),
                server.has_https_listener(),
                server.last_error(),
            ),
        };
        GatewayRuntimeStatus { config, status, https_ready, last_error }
    }

    pub async fn restart(
        &self,
        config: GatewayRuntimeConfig,
        timeout: Duration,
    ) -> Result<(), GatewayError> {
        let _guard = self.lifecycle.lock().await;
        if !config.enable {
            self.stop_server(timeout).await?;
            self.state.store(Arc::new(GatewayState::Disabled(config)));
            return Ok(());
        }
        if self.rules.initial_error().is_some() {
            self.rules.reload_rules().await?;
        }
        let tls = match self.prepare_tls().await {
            Ok(tls) => tls,
            Err(error) => {
                if matches!(&**self.state.load(), GatewayState::Uninitialized { .. }) {
                    self.state.store(Arc::new(GatewayState::Uninitialized {
                        config,
                        error: error.to_public_message(),
                    }));
                }
                return Err(error);
            }
        };
        self.stop_server(timeout).await?;
        let server = GatewayServer::spawn(self.rules.shared_routes(), &config, Some(tls));
        self.state.store(Arc::new(GatewayState::Serving { config, server }));
        Ok(())
    }

    async fn stop_server(&self, timeout: Duration) -> Result<(), GatewayError> {
        if let GatewayState::Serving { server, .. } = &*self.state.load_full() {
            server.shutdown_and_wait(timeout).await?;
        }
        Ok(())
    }

    pub async fn shutdown_and_wait(&self, timeout: Duration) -> Result<(), GatewayError> {
        let _guard = self.lifecycle.lock().await;
        self.stop_server(timeout).await
    }

    async fn prepare_tls(&self) -> Result<GatewayTlsConfig, GatewayError> {
        let count = self.cert_service.reload_gateway_tls_mapping().await?;
        if count == 0 {
            tracing::warn!(
                "No valid for_gateway certificate found; gateway HTTPS listener will start but reject TLS handshakes until a certificate is loaded"
            );
        }
        let mut server_config = landscape_core::cert::build_tls_server_config_with_shared_resolver(
            self.cert_service.gateway_tls_resolver(),
        );
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(GatewayTlsConfig { server_config: Arc::new(server_config) })
    }
}
