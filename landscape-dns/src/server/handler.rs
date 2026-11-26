use std::{sync::Arc, time::Instant};

use arc_swap::ArcSwap;
use hickory_proto::{op::Message, rr::RecordType};

#[cfg(test)]
use crate::resolve::redirect::RedirectAnswer;
use crate::{
    CheckChainDnsResult,
    domain::ParsedDomain,
    listener::wire::{self, DnsRequest},
    resolve::{
        RuntimeSnapshot, answer::DnsQueryAnswer, chain::ResolveChain, engine::ResolveEngine,
        local::LocalResolver, redirect::RedirectEngine,
    },
    server::snapshot::{SnapshotPatch, SnapshotStore},
};
use landscape_common::utils::time::now_ms;
use landscape_common::{
    dns::error::DnsServiceError,
    flow::DnsResultSink,
    metric::dns::{DnsMetricEvent, DnsMetricReporter},
    sys_config::CacheRuntimeConfig,
};

#[derive(Clone)]
pub struct DnsRequestHandler {
    snapshot: Arc<SnapshotStore>,
    pub flow_id: u32,
    pub metric_reporter: DnsMetricReporter,
}

pub(crate) struct HandlerDeps {
    pub runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
    pub flow_id: u32,
    pub metric_reporter: DnsMetricReporter,
    pub local_resolver: Arc<LocalResolver>,
    pub sink: Arc<dyn DnsResultSink>,
}

impl DnsRequestHandler {
    pub fn from_engines(
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
        deps: HandlerDeps,
    ) -> DnsRequestHandler {
        let HandlerDeps {
            runtime_config,
            flow_id,
            metric_reporter,
            local_resolver,
            sink,
        } = deps;
        DnsRequestHandler {
            snapshot: Arc::new(SnapshotStore::new(
                redirect_engine,
                resolve_engine,
                runtime_config,
                flow_id,
                local_resolver,
                sink,
            )),
            flow_id,
            metric_reporter,
        }
    }

    pub async fn renew_engines(
        &self,
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
    ) {
        self.snapshot.apply(SnapshotPatch::Full { redirect_engine, resolve_engine }).await;
    }

    pub async fn renew_dns_rules(&self, resolve_engine: ResolveEngine) {
        self.snapshot.apply(SnapshotPatch::Resolves { resolve_engine }).await;
    }

    pub async fn renew_redirect_rules(&self, redirect_engine: RedirectEngine) {
        self.snapshot.apply(SnapshotPatch::Redirects { redirect_engine }).await;
    }

    pub async fn renew_runtime_config(&self, rebuild_cache: bool) {
        if rebuild_cache {
            self.snapshot.apply(SnapshotPatch::RebuildCache).await;
        }
    }

    #[cfg(test)]
    pub fn lookup_redirects(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<RedirectAnswer> {
        let runtime = self.snapshot.load();
        runtime.redirect_engine.lookup(
            domain,
            query_type,
            self.snapshot.local_resolver().local_answer_provider(),
        )
    }

    fn chain<'a>(&'a self, runtime: &'a RuntimeSnapshot) -> ResolveChain<'a> {
        ResolveChain::new(runtime, self.snapshot.local_resolver())
    }

    /// The full resolution chain for live queries.
    async fn resolve_query(&self, domain: &ParsedDomain, query_type: RecordType) -> DnsQueryAnswer {
        let runtime = self.snapshot.load_full();
        self.chain(&runtime).resolve(domain, query_type).await
    }

    pub async fn handle(&self, req: &DnsRequest) -> Message {
        let start_time = Instant::now();
        let query_type = req.query_type;
        let src_ip = req.src.ip();

        let DnsQueryAnswer { dns, outcome, authoritative } =
            self.resolve_query(&req.domain, query_type).await;
        let response_code = dns.response_code;

        self.metric_reporter.record_with(|| DnsMetricEvent {
            flow_id: self.flow_id,
            domain: req.domain.raw_arc().clone(),
            query_type,
            response_code,
            status: outcome,
            report_time: now_ms(),
            duration_ms: start_time.elapsed().as_millis() as u32,
            src_ip,
            answers: dns.records.clone(),
        });

        let mut message = wire::build_response(req, response_code, dns.records);
        message.metadata.authoritative = authoritative;
        message.metadata.truncation = dns.truncated;
        if let Some(soa) = dns.soa {
            message.authorities.push(*soa);
        }
        message
    }

    pub async fn check_domain(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) -> CheckChainDnsResult {
        let runtime = self.snapshot.load_full();
        self.chain(&runtime).check(domain, query_type, apply_filter).await
    }

    pub async fn invalidate_cache_entry(&self, domain: &ParsedDomain, query_type: RecordType) {
        let runtime = self.snapshot.load_full();
        runtime.cache.invalidate(domain, query_type).await;
        runtime.cache.refresh_marks();
    }

    pub async fn refresh_cache_entry(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) -> Result<CheckChainDnsResult, DnsServiceError> {
        let runtime = self.snapshot.load_full();
        self.chain(&runtime).refresh(domain, query_type, apply_filter).await
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
pub(crate) mod tests;
