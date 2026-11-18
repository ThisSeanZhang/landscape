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
use landscape_common::dns::redirect::DynamicDnsRedirectBatch;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_config::GatewayRuntimeConfig;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
use landscape_database::repository::Repository;
use tokio::sync::Mutex;

use crate::cert::order_service::CertService;
use crate::dns::redirect_service::DNSRedirectService;
use rules::{
    build_gateway_dynamic_dns_redirect_batch, normalize_persisted_gateway_rules,
    validate_gateway_rule, validate_persisted_gateway_rules,
};
use runtime::{GatewayRuntime, PreparedRoutes};

#[derive(Debug, thiserror::Error)]
pub enum GatewayServiceInitError {
    #[error(transparent)]
    Rules(#[from] GatewayError),
    #[error(transparent)]
    Certificate(#[from] CertError),
}

/// All fallible preparation finishes before persistence or publication.
struct PreparedGatewayRules {
    routes: PreparedRoutes,
    dns_batch: DynamicDnsRedirectBatch,
}

impl PreparedGatewayRules {
    fn compile(rules: &mut [HttpUpstreamRuleConfig]) -> Result<Self, GatewayError> {
        normalize_persisted_gateway_rules(rules);
        validate_persisted_gateway_rules(rules)?;
        Ok(Self {
            routes: GatewayRuntime::prepare_rules(rules)?,
            dns_batch: build_gateway_dynamic_dns_redirect_batch(rules),
        })
    }
}

/// Prepare imported rules using the same compatibility, validation and
/// compilation path as startup and reload, before an importer writes anything.
/// The caller receives canonical persisted values, including SNI header policy.
pub fn prepare_gateway_rules_for_import(
    rules: &mut [HttpUpstreamRuleConfig],
) -> Result<(), GatewayError> {
    PreparedGatewayRules::compile(rules).map(|_| ())
}

#[derive(Clone)]
pub struct GatewayService {
    store: GatewayHttpUpstreamRepository,
    dns_redirect_service: DNSRedirectService,
    /// Retain the DNS batch for the published routes. This lock also serializes
    /// mutations, DNS syncs and lifecycle changes so none publish stale state.
    published_dns: Arc<Mutex<DynamicDnsRedirectBatch>>,
    runtime: GatewayRuntime,
}

impl GatewayService {
    pub async fn init_service(
        store: GatewayHttpUpstreamRepository,
        config: GatewayRuntimeConfig,
        cert_service: &CertService,
        dns_redirect_service: DNSRedirectService,
    ) -> Result<Self, GatewayServiceInitError> {
        let prepared = if GatewayRuntime::is_supported() {
            let mut rules = store.list().await.map_err(GatewayError::from)?;
            PreparedGatewayRules::compile(&mut rules)?
        } else {
            PreparedGatewayRules {
                routes: PreparedRoutes::default(),
                dns_batch: build_gateway_dynamic_dns_redirect_batch(&[]),
            }
        };
        let runtime = GatewayRuntime::new(prepared.routes, config, cert_service).await?;
        Ok(Self {
            store,
            dns_redirect_service,
            published_dns: Arc::new(Mutex::new(prepared.dns_batch)),
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
        let _guard = self.published_dns.lock().await;
        self.runtime.shutdown_and_wait(timeout).await;
    }

    pub async fn restart(
        &self,
        config: GatewayRuntimeConfig,
        timeout: Duration,
    ) -> Result<(), GatewayError> {
        self.ensure_supported()?;
        let mut published_dns = self.published_dns.lock().await;
        let mut rules = self.store.list().await?;
        let prepared = PreparedGatewayRules::compile(&mut rules)?;
        // Read and compile before stopping the current server.
        self.runtime.restart(prepared.routes, config, timeout).await?;
        *published_dns = prepared.dns_batch;
        self.dns_redirect_service.set_dynamic_batch(published_dns.clone()).await;
        Ok(())
    }

    fn ensure_supported(&self) -> Result<(), GatewayError> {
        if self.is_supported() { Ok(()) } else { Err(GatewayError::Unsupported) }
    }

    pub async fn list_rules(&self) -> Result<Vec<HttpUpstreamRuleConfig>, GatewayError> {
        self.ensure_supported()?;
        let mut rules = self.store.list().await?;
        normalize_persisted_gateway_rules(&mut rules);
        Ok(rules)
    }

    pub async fn save_rule(
        &self,
        rule: HttpUpstreamRuleConfig,
    ) -> Result<HttpUpstreamRuleConfig, GatewayError> {
        self.ensure_supported()?;
        let mut published_dns = self.published_dns.lock().await;
        let mut candidate = self.store.list().await?;
        validate_gateway_rule(&rule, &candidate)?;
        if let Some(existing) = candidate.iter_mut().find(|existing| existing.id == rule.id) {
            *existing = rule.clone();
        } else {
            candidate.push(rule.clone());
        }
        let prepared = PreparedGatewayRules::compile(&mut candidate)?;
        // Persistence only changes update_at, which is not part of routing.
        let saved = self.store.upsert(rule).await?.new;
        self.publish_rules(prepared, &mut published_dns).await;
        Ok(saved)
    }

    pub async fn find_rule(
        &self,
        id: ConfigId,
    ) -> Result<Option<HttpUpstreamRuleConfig>, GatewayError> {
        self.ensure_supported()?;
        let mut rule = Repository::find_by_id(&self.store, id).await?;
        if let Some(rule) = &mut rule {
            normalize_persisted_gateway_rules(std::slice::from_mut(rule));
        }
        Ok(rule)
    }

    pub async fn delete_rule(&self, id: ConfigId) -> Result<(), GatewayError> {
        self.ensure_supported()?;
        let mut published_dns = self.published_dns.lock().await;
        let mut candidate = self.store.list().await?;
        candidate.retain(|rule| rule.id != id);
        let prepared = PreparedGatewayRules::compile(&mut candidate)?;
        self.store.delete_and_get(id).await?;
        self.publish_rules(prepared, &mut published_dns).await;
        Ok(())
    }

    pub async fn reload_rules(&self) -> Result<(), GatewayError> {
        self.ensure_supported()?;
        let mut published_dns = self.published_dns.lock().await;
        let mut rules = self.store.list().await?;
        let prepared = PreparedGatewayRules::compile(&mut rules)?;
        self.publish_rules(prepared, &mut published_dns).await;
        Ok(())
    }

    async fn publish_rules(
        &self,
        prepared: PreparedGatewayRules,
        published_dns: &mut DynamicDnsRedirectBatch,
    ) {
        // HTTP, HTTPS and SNI switch atomically. Publish routing before DNS so
        // newly advertised domains have routes. DNS notification is asynchronous;
        // the two subsystems do not form a cross-system transaction.
        self.runtime.publish_routes(prepared.routes);
        *published_dns = prepared.dns_batch;
        self.dns_redirect_service.set_dynamic_batch(published_dns.clone()).await;
    }

    pub async fn sync_dynamic_dns_redirects(&self) {
        let published_dns = self.published_dns.lock().await;
        // Synchronize the active version, never a fresh unvalidated database read.
        // Unsupported builds retain an empty batch to remove stale gateway DNS.
        self.dns_redirect_service.set_dynamic_batch(published_dns.clone()).await;
    }

    pub async fn stored_rule_count(&self) -> usize {
        self.store.list().await.map(|rules| rules.len()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
