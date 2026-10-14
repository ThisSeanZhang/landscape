use std::{sync::Arc, time::Instant};

use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Record, RecordType},
};

#[cfg(test)]
use crate::resolve::redirect::RedirectAnswer;
use crate::{
    CheckChainDnsResult,
    domain::ParsedDomain,
    listener::wire::{self, DnsRequest},
    resolve::{
        answer::DnsQueryAnswer, chain::ResolveChain, engine::ResolveEngine, local::LocalResolver,
        redirect::RedirectEngine,
    },
    server::{
        CacheRuntimeConfig, MetricSenderState,
        snapshot::{RuntimeSnapshot, SnapshotPatch, SnapshotStore},
    },
};
use landscape_common::utils::time::now_ms;
use landscape_common::{
    dns::error::DnsServiceError,
    event::DnsMetricMessage,
    flow::DnsResultSink,
    metric::dns::{DnsMetric, DnsOutcome},
};

#[derive(Clone)]
pub struct DnsRequestHandler {
    snapshot: Arc<SnapshotStore>,
    pub flow_id: u32,
    pub msg_tx: MetricSenderState,
}

impl DnsRequestHandler {
    pub fn from_engines(
        redirect_engine: RedirectEngine,
        resolve_engine: ResolveEngine,
        runtime_config: Arc<ArcSwap<CacheRuntimeConfig>>,
        flow_id: u32,
        msg_tx: MetricSenderState,
        local_resolver: Arc<LocalResolver>,
        sink: Arc<dyn DnsResultSink>,
    ) -> DnsRequestHandler {
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
            msg_tx,
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
        ResolveChain::new(
            runtime,
            self.snapshot.local_resolver(),
            self.snapshot.sink().as_ref(),
            self.snapshot.flow_id(),
        )
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

        let answer = self.resolve_query(&req.domain, query_type).await;
        let (records, outcome, response_code) =
            (answer.records, answer.outcome, answer.response_code);

        self.send_metric(
            req.domain.raw(),
            query_type,
            outcome,
            response_code,
            start_time,
            src_ip,
            &records,
        );

        wire::build_response(req, response_code, records)
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
        self.snapshot.refresh_maps_from_cache(&runtime.cache);
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

    #[allow(clippy::too_many_arguments)]
    fn send_metric(
        &self,
        domain: &str,
        query_type: RecordType,
        outcome: DnsOutcome,
        response_code: ResponseCode,
        start_time: Instant,
        src_ip: std::net::IpAddr,
        records: &[Record],
    ) {
        if let Some(msg_tx) = self.msg_tx.load_full() {
            let dns_metric = DnsMetric {
                flow_id: self.flow_id,
                domain: domain.to_string(),
                query_type: query_type.to_string(),
                response_code: response_code.to_string(),
                status: outcome,
                report_time: now_ms(),
                duration_ms: start_time.elapsed().as_millis() as u32,
                src_ip,
                answers: records.iter().map(|r| r.to_string()).collect(),
            };
            let _ = msg_tx.try_send(DnsMetricMessage::Metric(dns_metric));
        }
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
pub(crate) mod tests;
