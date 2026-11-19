//! Stored gateway rules and the live routing snapshot consumed by the proxy.

mod rules;

use crate::dns::redirect_service::DNSRedirectService;
use arc_swap::ArcSwapOption;
use landscape_common::config::ConfigId;
use landscape_common::database::store::ConfigStore;
use landscape_common::dns::redirect::DynamicDnsRedirectBatch;
use landscape_common::error::LdApiErrorInfo;
use landscape_common::sys_service::gateway::{
    GatewayError, HttpUpstreamRuleConfig,
    routes::{CompiledGatewayRoutes as PreparedRoutes, SharedGatewayRoutes},
};
use landscape_database::gateway::repository::GatewayHttpUpstreamRepository;
use rules::{
    build_gateway_dynamic_dns_redirect_batch, normalize_persisted_gateway_rules,
    validate_gateway_rule, validate_persisted_gateway_rules,
};
use std::sync::Arc;
use tokio::sync::Mutex;

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
            routes: PreparedRoutes::compile(rules)?,
            // An execution-disabled build must clear previously advertised domains.
            dns_batch: build_gateway_dynamic_dns_redirect_batch(if cfg!(feature = "gateway") {
                rules
            } else {
                &[]
            }),
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
pub struct GatewayRuleConfigService {
    store: GatewayHttpUpstreamRepository,
    dns_redirect_service: DNSRedirectService,
    // Serialize candidate reads, writes, snapshot publication and DNS synchronization.
    published_dns: Arc<Mutex<DynamicDnsRedirectBatch>>,
    routes: SharedGatewayRoutes,
    // Present only when startup could not produce the first valid snapshot.
    initial_error: Arc<ArcSwapOption<String>>,
}

impl GatewayRuleConfigService {
    pub async fn new(
        store: GatewayHttpUpstreamRepository,
        dns_redirect_service: DNSRedirectService,
    ) -> Self {
        let service = Self {
            store,
            dns_redirect_service,
            published_dns: Arc::new(Mutex::new(build_gateway_dynamic_dns_redirect_batch(&[]))),
            routes: Arc::new(landscape_common::sys_service::gateway::routes::GatewayRoutes::new(
                PreparedRoutes::default(),
            )),
            initial_error: Arc::new(ArcSwapOption::empty()),
        };
        match service.load_prepared_rules().await {
            Ok(prepared) => {
                service.routes.store(Arc::new(prepared.routes));
                *service.published_dns.lock().await = prepared.dns_batch;
            }
            Err(error) => {
                service.initial_error.store(Some(Arc::new(error.to_public_message())));
            }
        }
        service
    }

    #[cfg(feature = "gateway")]
    pub(crate) fn shared_routes(&self) -> SharedGatewayRoutes {
        self.routes.clone()
    }
    #[cfg(feature = "gateway")]
    pub(crate) fn initial_error(&self) -> Option<String> {
        self.initial_error.load_full().map(|e| (*e).clone())
    }

    async fn apply_repair(
        &self,
        result: Result<PreparedGatewayRules, GatewayError>,
        batch: &mut DynamicDnsRedirectBatch,
    ) {
        match result {
            Ok(prepared) => self.publish_rules(prepared, batch).await,
            Err(error) => self.initial_error.store(Some(Arc::new(error.to_public_message()))),
        }
    }

    pub async fn list_rules(&self) -> Result<Vec<HttpUpstreamRuleConfig>, GatewayError> {
        let mut rules = self.store.list_checked().await?;
        normalize_persisted_gateway_rules(&mut rules);
        Ok(rules)
    }

    pub async fn save_rule(
        &self,
        rule: HttpUpstreamRuleConfig,
    ) -> Result<HttpUpstreamRuleConfig, GatewayError> {
        let mut published_dns = self.published_dns.lock().await;
        let mut candidate = self.store.list_checked().await?;
        let repairing = self.initial_error.load().is_some();
        validate_gateway_rule(&rule, &candidate)?;
        // Repair mode still rejects a new rule that cannot compile on its own.
        // Other malformed rows are allowed to remain until repaired separately.
        if repairing {
            PreparedRoutes::compile(std::slice::from_ref(&rule))?;
        }
        if let Some(existing) = candidate.iter_mut().find(|existing| existing.id == rule.id) {
            *existing = rule.clone();
        } else {
            candidate.push(rule.clone());
        }
        if repairing {
            let saved = self.store.upsert(rule).await?.new;
            self.apply_repair(PreparedGatewayRules::compile(&mut candidate), &mut published_dns)
                .await;
            return Ok(saved);
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
        let mut rule = self.store.find_by_id_checked(id).await?;
        if let Some(rule) = &mut rule {
            normalize_persisted_gateway_rules(std::slice::from_mut(rule));
        }
        Ok(rule)
    }

    pub async fn delete_rule(&self, id: ConfigId) -> Result<(), GatewayError> {
        let mut published_dns = self.published_dns.lock().await;
        if self.initial_error.load().is_some() {
            self.store.delete_by_id_raw(id).await?;
            self.apply_repair(self.load_prepared_rules().await, &mut published_dns).await;
            return Ok(());
        }
        let mut candidate = self.store.list_checked().await?;
        candidate.retain(|rule| rule.id != id);
        let prepared = PreparedGatewayRules::compile(&mut candidate)?;
        self.store.delete_and_get(id).await?;
        self.publish_rules(prepared, &mut published_dns).await;
        Ok(())
    }

    pub async fn reload_rules(&self) -> Result<(), GatewayError> {
        let mut published_dns = self.published_dns.lock().await;
        let prepared = self.load_prepared_rules().await;
        if let Err(error) = &prepared
            && self.initial_error.load().is_some()
        {
            self.initial_error.store(Some(Arc::new(error.to_public_message())));
        }
        let prepared = prepared?;
        self.publish_rules(prepared, &mut published_dns).await;
        Ok(())
    }

    async fn load_prepared_rules(&self) -> Result<PreparedGatewayRules, GatewayError> {
        let mut rules = self.store.list_checked().await?;
        PreparedGatewayRules::compile(&mut rules)
    }

    async fn publish_rules(
        &self,
        prepared: PreparedGatewayRules,
        published_dns: &mut DynamicDnsRedirectBatch,
    ) {
        // HTTP, HTTPS and SNI switch atomically. Publish routing before DNS so
        // newly advertised domains have routes. DNS notification is asynchronous;
        // the two subsystems do not form a cross-system transaction.
        self.routes.store(Arc::new(prepared.routes));
        *published_dns = prepared.dns_batch;
        self.initial_error.store(None);
        self.dns_redirect_service.set_dynamic_batch(published_dns.clone()).await;
    }

    pub async fn sync_dynamic_dns_redirects(&self) {
        let published_dns = self.published_dns.lock().await;
        // Synchronize the active version, never a fresh unvalidated database read.
        // Unsupported builds retain an empty batch to remove stale gateway DNS.
        self.dns_redirect_service.set_dynamic_batch(published_dns.clone()).await;
    }

    pub async fn stored_rule_count(&self) -> usize {
        self.store
            .count()
            .await
            .map(|count| usize::try_from(count).unwrap_or(usize::MAX))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
