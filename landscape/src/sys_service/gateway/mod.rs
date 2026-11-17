//! Gateway application service: persistent rules, DNS/certificate integration,
//! and the lifecycle of the optional proxy server.

mod rules;
#[cfg(feature = "gateway")]
mod runtime;
#[cfg(not(feature = "gateway"))]
#[path = "runtime_unsupported.rs"]
mod runtime;

use std::sync::Arc;
use std::time::Duration;

use landscape_common::cert::CertError;
use landscape_common::config::ConfigId;
use landscape_common::database::store::ConfigStore;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_config::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
use landscape_database::repository::Repository;
use tokio::sync::Mutex;

use crate::cert::order_service::CertService;
use crate::dns::redirect_service::DNSRedirectService;
use rules::{build_gateway_dynamic_dns_redirect_batch, validate_gateway_rule};
use runtime::GatewayRuntime;

#[derive(Clone)]
pub struct GatewayService {
    store: GatewayHttpUpstreamRepository,
    dns_redirect_service: DNSRedirectService,
    /// Serialize mutations so that a concurrent reload cannot publish stale rules
    /// or update a server that is being replaced.
    operation_lock: Arc<Mutex<()>>,
    runtime: GatewayRuntime,
}

impl GatewayService {
    pub async fn init_service(
        store: GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        cert_service: &CertService,
        dns_redirect_service: DNSRedirectService,
    ) -> Result<Self, CertError> {
        let initial_rules = if GatewayRuntime::is_supported() {
            store.list().await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let runtime = GatewayRuntime::new(initial_rules, config, cert_service).await?;
        Ok(Self {
            store,
            dns_redirect_service,
            operation_lock: Arc::new(Mutex::new(())),
            runtime,
        })
    }

    pub fn is_supported(&self) -> bool {
        GatewayRuntime::is_supported()
    }

    pub fn status(&self) -> ServiceStatus {
        self.runtime.status()
    }

    pub fn has_https_listener(&self) -> bool {
        self.runtime.has_https_listener()
    }

    /// Configuration used by the proxy server, absent when gateway support is not compiled.
    pub fn runtime_config(&self) -> Option<GatewayRuntimeConfig> {
        self.runtime.config()
    }

    pub async fn shutdown_and_wait(&self, timeout: Duration) {
        let _guard = self.operation_lock.lock().await;
        self.runtime.shutdown_and_wait(timeout).await;
    }

    pub async fn restart(
        &self,
        config: GatewayRuntimeConfig,
        timeout: Duration,
    ) -> Result<(), GatewayError> {
        self.ensure_supported()?;
        let _guard = self.operation_lock.lock().await;
        let rules = self.store.list().await.unwrap_or_default();
        self.runtime.restart(rules, config, timeout).await
    }

    fn ensure_supported(&self) -> Result<(), GatewayError> {
        if self.is_supported() { Ok(()) } else { Err(GatewayError::Unsupported) }
    }

    pub async fn list_rules(&self) -> Result<Vec<HttpUpstreamRuleConfig>, GatewayError> {
        self.ensure_supported()?;
        self.store.list().await.map_err(Into::into)
    }

    pub async fn save_rule(
        &self,
        rule: HttpUpstreamRuleConfig,
    ) -> Result<HttpUpstreamRuleConfig, GatewayError> {
        self.ensure_supported()?;
        let _guard = self.operation_lock.lock().await;
        let existing_rules = self.store.list().await?;
        validate_gateway_rule(&rule, &existing_rules)?;
        let saved = self.store.upsert(rule).await?.new;
        self.reload_rules_inner().await?;
        Ok(saved)
    }

    pub async fn find_rule(
        &self,
        id: ConfigId,
    ) -> Result<Option<HttpUpstreamRuleConfig>, GatewayError> {
        self.ensure_supported()?;
        Repository::find_by_id(&self.store, id).await.map_err(Into::into)
    }

    pub async fn delete_rule(&self, id: ConfigId) -> Result<(), GatewayError> {
        self.ensure_supported()?;
        let _guard = self.operation_lock.lock().await;
        self.store.delete_and_get(id).await?;
        self.reload_rules_inner().await?;
        Ok(())
    }

    pub async fn reload_rules(&self) -> Result<(), GatewayError> {
        self.ensure_supported()?;
        let _guard = self.operation_lock.lock().await;
        self.reload_rules_inner().await?;
        Ok(())
    }

    async fn reload_rules_inner(&self) -> Result<(), GatewayError> {
        let rules = self.list_rules().await.unwrap_or_default();
        self.dns_redirect_service
            .set_dynamic_batch(build_gateway_dynamic_dns_redirect_batch(&rules))
            .await;
        self.runtime.reload_rules(rules)
    }

    pub async fn sync_dynamic_dns_redirects(&self) {
        let _guard = self.operation_lock.lock().await;
        // Unsupported builds must remove any gateway DNS batch without reading rules.
        let rules = if self.is_supported() {
            self.store.list().await.unwrap_or_default()
        } else {
            Vec::new()
        };
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
        assert!(service.runtime_config().is_some());
        service.reload_rules().await.unwrap();
        let rule = service.save_rule(rule()).await.unwrap();
        assert_eq!(service.find_rule(rule.id).await.unwrap().unwrap().domains, rule.domains);
        assert_eq!(service.runtime.shared_rules().load().len(), 1);
        let batches = service.dns_redirect_service.list_dynamic_batches().await;
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].records.len(), 1);

        // Restart recreates the server from persistent rules without binding ports
        // when the gateway is disabled.
        service.restart(GatewayRuntimeConfig::default(), Duration::from_secs(1)).await.unwrap();
        assert_eq!(service.status(), ServiceStatus::Stop);
        assert_eq!(service.runtime.shared_rules().load().len(), 1);

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
        assert_eq!(service.runtime.shared_rules().load()[0].domains, rule.domains);

        service.delete_rule(rule.id).await.unwrap();
        assert!(service.find_rule(rule.id).await.unwrap().is_none());
        assert!(service.runtime.shared_rules().load().is_empty());
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
        assert!(service.runtime_config().is_none());
        let cloned = service.clone();
        let stored = service.store.upsert(rule()).await.unwrap().new;
        service
            .dns_redirect_service
            .set_dynamic_batch(build_gateway_dynamic_dns_redirect_batch(std::slice::from_ref(
                &stored,
            )))
            .await;
        let before_dns = service.dns_redirect_service.list_dynamic_batches().await;
        assert_eq!(before_dns.len(), 1);

        assert!(matches!(service.save_rule(rule()).await, Err(GatewayError::Unsupported)));
        assert!(matches!(service.list_rules().await, Err(GatewayError::Unsupported)));
        assert!(matches!(service.find_rule(stored.id).await, Err(GatewayError::Unsupported)));
        assert!(matches!(service.delete_rule(stored.id).await, Err(GatewayError::Unsupported)));
        assert!(matches!(service.reload_rules().await, Err(GatewayError::Unsupported)));
        let result = service
            .restart(
                GatewayRuntimeConfig { enable: true, http_port: 8080, https_port: 8443 },
                Duration::from_secs(1),
            )
            .await;
        assert!(matches!(result, Err(GatewayError::Unsupported)));
        assert!(service.runtime_config().is_none());
        assert!(cloned.runtime_config().is_none());
        assert_eq!(service.status(), ServiceStatus::Stop);
        let after_rules = service.store.list().await.unwrap();
        assert_eq!(after_rules.len(), 1);
        assert_eq!(after_rules[0].id, stored.id);
        assert_eq!(after_rules[0].domains, stored.domains);
        assert_eq!(service.stored_rule_count().await, 1);
        let after_dns = service.dns_redirect_service.list_dynamic_batches().await;
        assert_eq!(after_dns.len(), before_dns.len());
        assert_eq!(after_dns[0].source_id, before_dns[0].source_id);
        assert_eq!(after_dns[0].scope, before_dns[0].scope);
        let snapshot = |batch: &landscape_common::dns::redirect::DynamicDnsRedirectBatch| {
            batch
                .records
                .iter()
                .map(|record| {
                    (
                        record.match_rule.clone(),
                        record.answer_mode,
                        record.result_info.clone(),
                        record.ttl_secs,
                        record.block_metadata_queries,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(snapshot(&after_dns[0]), snapshot(&before_dns[0]));

        // Startup synchronization explicitly removes stale gateway DNS records,
        // even when persistent rules exist in an unsupported build.
        service.sync_dynamic_dns_redirects().await;
        assert!(service.dns_redirect_service.list_dynamic_batches().await.is_empty());
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }
}
