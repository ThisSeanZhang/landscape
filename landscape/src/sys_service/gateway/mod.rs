//! Gateway application service: persistent rules, DNS/certificate integration,
//! and the lifecycle of the optional proxy server.

mod rules;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use landscape_common::cert::CertError;
use landscape_common::config::ConfigId;
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_config::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
use landscape_database::repository::Repository;
use tokio::sync::Mutex;

#[cfg(feature = "gateway")]
use landscape_gateway::{GatewayServer, GatewayTlsConfig};

use crate::cert::order_service::CertService;
use crate::dns::redirect_service::DNSRedirectService;
use rules::{build_gateway_dynamic_dns_redirect_batch, validate_gateway_rule};

#[derive(Clone)]
pub struct GatewayService {
    store: GatewayHttpUpstreamRepository,
    dns_redirect_service: DNSRedirectService,
    /// Serialize mutations so that a concurrent reload cannot publish stale rules
    /// or update a server that is being replaced.
    operation_lock: Arc<Mutex<()>>,
    #[cfg(feature = "gateway")]
    server: Arc<ArcSwap<GatewayServer>>,
    #[cfg(feature = "gateway")]
    tls_config: GatewayTlsConfig,
    #[cfg(not(feature = "gateway"))]
    config: Arc<ArcSwap<GatewayRuntimeConfig>>,
}

impl GatewayService {
    pub async fn init_service(
        store: GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        cert_service: &CertService,
        dns_redirect_service: DNSRedirectService,
    ) -> Result<Self, CertError> {
        #[cfg(feature = "gateway")]
        let tls_config = {
            let count = cert_service.reload_gateway_tls_mapping().await?;
            if count == 0 {
                tracing::warn!(
                    "No valid for_gateway certificate found; gateway HTTPS listener will start but reject TLS handshakes until a certificate is loaded"
                );
            }
            let mut server_config =
                landscape_core::cert::build_tls_server_config_with_shared_resolver(
                    cert_service.gateway_tls_resolver(),
                );
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            GatewayTlsConfig { server_config: Arc::new(server_config) }
        };
        #[cfg(feature = "gateway")]
        let server = Self::create_server(&store, config, tls_config.clone()).await;
        #[cfg(not(feature = "gateway"))]
        let _ = cert_service;

        Ok(Self {
            store,
            dns_redirect_service,
            operation_lock: Arc::new(Mutex::new(())),
            #[cfg(feature = "gateway")]
            server: Arc::new(ArcSwap::from(server)),
            #[cfg(feature = "gateway")]
            tls_config,
            #[cfg(not(feature = "gateway"))]
            config: Arc::new(ArcSwap::from_pointee(config)),
        })
    }

    #[cfg(feature = "gateway")]
    async fn create_server(
        store: &GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        tls_config: GatewayTlsConfig,
    ) -> Arc<GatewayServer> {
        let initial_rules = store.list().await.unwrap_or_default();
        let server = Arc::new(GatewayServer::new(initial_rules, config, Some(tls_config)));
        if server.config().enable {
            server.start();
        }
        server
    }

    pub fn is_supported(&self) -> bool {
        cfg!(feature = "gateway")
    }

    pub fn status(&self) -> ServiceStatus {
        #[cfg(feature = "gateway")]
        return self.server.load().status();
        #[cfg(not(feature = "gateway"))]
        ServiceStatus::Stop
    }

    pub fn has_https_listener(&self) -> bool {
        #[cfg(feature = "gateway")]
        return self.server.load().has_https_listener();
        #[cfg(not(feature = "gateway"))]
        false
    }

    pub fn config(&self) -> GatewayRuntimeConfig {
        #[cfg(feature = "gateway")]
        return self.server.load().config().clone();
        #[cfg(not(feature = "gateway"))]
        (*self.config.load_full()).clone()
    }

    pub async fn shutdown_and_wait(&self, timeout: Duration) {
        let _guard = self.operation_lock.lock().await;
        #[cfg(feature = "gateway")]
        Self::stop_server(&self.server.load_full(), timeout).await;
        #[cfg(not(feature = "gateway"))]
        let _ = timeout;
    }

    #[cfg(feature = "gateway")]
    async fn stop_server(server: &GatewayServer, timeout: Duration) {
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

    pub async fn restart(&self, config: GatewayRuntimeConfig, timeout: Duration) {
        let _guard = self.operation_lock.lock().await;
        #[cfg(feature = "gateway")]
        {
            Self::stop_server(&self.server.load_full(), timeout).await;
            let server = Self::create_server(&self.store, config, self.tls_config.clone()).await;
            self.server.store(server);
        }
        #[cfg(not(feature = "gateway"))]
        {
            let _ = timeout;
            self.config.store(Arc::new(config));
        }
    }

    fn ensure_supported(&self) -> Result<(), DbError> {
        if self.is_supported() {
            Ok(())
        } else {
            Err(DbError::Internal(
                "gateway is not supported on this target architecture".to_string(),
            ))
        }
    }

    pub async fn list_rules(&self) -> Result<Vec<HttpUpstreamRuleConfig>, DbError> {
        self.ensure_supported()?;
        self.store.list().await
    }

    pub async fn save_rule(
        &self,
        rule: HttpUpstreamRuleConfig,
    ) -> Result<HttpUpstreamRuleConfig, GatewayError> {
        let _guard = self.operation_lock.lock().await;
        self.ensure_supported()?;
        let existing_rules = self.store.list().await?;
        validate_gateway_rule(&rule, &existing_rules)?;
        let saved = self.store.upsert(rule).await?.new;
        self.reload_rules_inner().await;
        Ok(saved)
    }

    pub async fn find_rule(&self, id: ConfigId) -> Result<Option<HttpUpstreamRuleConfig>, DbError> {
        self.ensure_supported()?;
        Repository::find_by_id(&self.store, id).await
    }

    pub async fn delete_rule(&self, id: ConfigId) -> Result<(), DbError> {
        let _guard = self.operation_lock.lock().await;
        self.ensure_supported()?;
        self.store.delete_and_get(id).await?;
        self.reload_rules_inner().await;
        Ok(())
    }

    pub async fn reload_rules(&self) {
        let _guard = self.operation_lock.lock().await;
        self.reload_rules_inner().await;
    }

    async fn reload_rules_inner(&self) {
        let rules = self.list_rules().await.unwrap_or_default();
        self.dns_redirect_service
            .set_dynamic_batch(build_gateway_dynamic_dns_redirect_batch(&rules))
            .await;
        #[cfg(feature = "gateway")]
        self.server.load().reload_rules(rules);
    }

    pub async fn sync_dynamic_dns_redirects(&self) {
        let _guard = self.operation_lock.lock().await;
        let rules = self.list_rules().await.unwrap_or_default();
        self.dns_redirect_service
            .set_dynamic_batch(build_gateway_dynamic_dns_redirect_batch(&rules))
            .await;
    }

    pub async fn stored_rule_count(&self) -> usize {
        self.store.list().await.map(|rules| rules.len()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::account_service::CertAccountService;
    use landscape_common::event::dns::DnsEvent;
    use landscape_database::provider::LandscapeDBServiceProvider;

    async fn service() -> (GatewayService, CertService, tokio::sync::mpsc::Receiver<DnsEvent>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let db = LandscapeDBServiceProvider::mem_test_db().await;
        let (events_tx, events_rx) = tokio::sync::mpsc::channel(32);
        let dns = DNSRedirectService::new(db.clone(), events_tx).await;
        let accounts = CertAccountService::new(db.clone()).await;
        let certs = CertService::new(db.clone(), accounts, Some(dns.clone())).await;
        let service = GatewayService::init_service(
            db.gateway_http_upstream_store(),
            GatewayRuntimeConfig::default(),
            &certs,
            dns,
        )
        .await
        .unwrap();
        (service, certs, events_rx)
    }

    fn rule() -> HttpUpstreamRuleConfig {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "app",
            "enable": true,
            "domains": ["app.example.com"],
            "match_rule": { "t": "host" },
            "upstream": {
                "targets": [{ "address": "127.0.0.1", "port": 8080 }]
            }
        }))
        .unwrap()
    }

    #[cfg(feature = "gateway")]
    #[tokio::test]
    async fn rule_mutations_update_storage_server_and_dns() {
        let (service, certs, _events_rx) = service().await;
        let rule = service.save_rule(rule()).await.unwrap();
        assert_eq!(service.find_rule(rule.id).await.unwrap().unwrap().domains, rule.domains);
        assert_eq!(service.server.load().shared_rules().load().len(), 1);
        let batches = service.dns_redirect_service.list_dynamic_batches().await;
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].records.len(), 1);

        // Restart recreates the server from persistent rules without binding ports
        // when the gateway is disabled.
        service.restart(GatewayRuntimeConfig::default(), Duration::from_secs(1)).await;
        assert_eq!(service.status(), ServiceStatus::Stop);
        assert_eq!(service.server.load().shared_rules().load().len(), 1);

        let mut conflict = rule.clone();
        conflict.id = uuid::Uuid::new_v4();
        assert!(matches!(
            service.save_rule(conflict).await,
            Err(GatewayError::HostConflict { .. })
        ));
        let mut invalid = rule.clone();
        invalid.domains.clear();
        assert!(matches!(
            service.save_rule(invalid).await,
            Err(GatewayError::DomainsRequired { .. })
        ));
        assert_eq!(service.stored_rule_count().await, 1);
        assert_eq!(service.server.load().shared_rules().load()[0].domains, rule.domains);

        service.delete_rule(rule.id).await.unwrap();
        assert!(service.find_rule(rule.id).await.unwrap().is_none());
        assert!(service.server.load().shared_rules().load().is_empty());
        assert!(service.dns_redirect_service.list_dynamic_batches().await.is_empty());
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[cfg(not(feature = "gateway"))]
    #[tokio::test]
    async fn without_gateway_feature_service_remains_available_but_rejects_rules() {
        let (service, certs, _events_rx) = service().await;
        assert!(!service.is_supported());
        assert!(!service.has_https_listener());
        assert_eq!(service.status(), ServiceStatus::Stop);
        assert!(service.save_rule(rule()).await.is_err());
        assert!(service.list_rules().await.is_err());
        assert_eq!(service.stored_rule_count().await, 0);
        service
            .restart(
                GatewayRuntimeConfig { enable: true, http_port: 8080, https_port: 8443 },
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(service.config().http_port, 8080);
        assert_eq!(service.status(), ServiceStatus::Stop);
        service.sync_dynamic_dns_redirects().await;
        assert!(service.dns_redirect_service.list_dynamic_batches().await.is_empty());
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }
}
