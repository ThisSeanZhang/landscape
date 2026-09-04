use std::{sync::Arc, time::Instant};

use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Header, Metadata, OpCode, ResponseCode},
    rr::{DNSClass, Record, RecordType},
};
use hickory_server::{
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};

use crate::{
    domain::ParsedDomain,
    server::{
        answer::DnsQueryAnswer,
        chain::ResolveChain,
        local::LocalResolver,
        redirect_engine::{RedirectAnswer, RedirectEngine},
        resolve_engine::ResolveEngine,
        snapshot::{RuntimeSnapshot, SnapshotPatch, SnapshotStore},
        CacheRuntimeConfig, MetricSenderState,
    },
    CheckChainDnsResult,
};
use landscape_common::{
    dns::error::DnsServiceError,
    event::DnsMetricMessage,
    flow::DnsResultSink,
    metric::dns::{DnsMetric, DnsOutcome},
};
use landscape_core::time::get_current_time_ms;

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
                report_time: get_current_time_ms().unwrap_or_default(),
                duration_ms: start_time.elapsed().as_millis() as u32,
                src_ip,
                answers: records.iter().map(|r| r.to_string()).collect(),
            };
            let _ = msg_tx.try_send(DnsMetricMessage::Metric(dns_metric));
        }
    }

    async fn send_error_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        code: ResponseCode,
    ) -> ResponseInfo {
        let response = MessageResponseBuilder::from_message_request(request)
            .build_no_records(response_metadata(&request.metadata, code));
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Error response failed: {}", e);
                serve_failed(&request.metadata)
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsRequestHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let start_time = Instant::now();

        // Validation
        let req = match validate_request(request) {
            Ok(req) => req,
            Err(code) => {
                return self.send_error_response(request, response_handle, code).await;
            }
        };
        let query_type = req.query_type();
        let src_ip = request.src().ip();

        // Dispatch
        let pd = match ParsedDomain::new(&req.name().to_string()) {
            Ok(pd) => pd,
            Err(_) => {
                return self
                    .send_error_response(request, response_handle, ResponseCode::FormErr)
                    .await;
            }
        };
        let answer = self.resolve_query(&pd, query_type).await;
        let (records, outcome, response_code) =
            (answer.records, answer.outcome, answer.response_code);

        // Build response
        let builder = MessageResponseBuilder::from_message_request(request);
        let metadata = response_metadata(&request.metadata, response_code);
        let result = if records.is_empty() {
            let response = builder.build_no_records(metadata);
            response_handle.send_response(response).await
        } else {
            let response = builder.build(metadata, records.iter(), vec![], vec![], vec![]);
            response_handle.send_response(response).await
        };
        self.send_metric(
            pd.raw(),
            query_type,
            outcome,
            response_code,
            start_time,
            src_ip,
            &records,
        );

        match result {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Response failed: {}", e);
                serve_failed(&request.metadata)
            }
        }
    }
}

/// Response metadata with the common authoritative/recursion flags set.
fn response_metadata(request_metadata: &Metadata, code: ResponseCode) -> Metadata {
    let mut metadata = Metadata::response_from_request(request_metadata);
    metadata.response_code = code;
    metadata.recursion_available = true;
    metadata.authoritative = true;
    metadata
}

fn serve_failed(req_metadata: &Metadata) -> ResponseInfo {
    ResponseInfo::from(Header {
        metadata: response_metadata(req_metadata, ResponseCode::ServFail),
        counts: Default::default(),
    })
}

/// Validates the request; returns the query it carries on success, or the
/// response code to send on failure.
fn validate_request(request: &Request) -> Result<&hickory_proto::op::LowerQuery, ResponseCode> {
    let queries = request.queries.queries();
    if queries.len() != 1 {
        return Err(ResponseCode::FormErr);
    }
    if request.metadata.op_code != OpCode::Query {
        return Err(ResponseCode::NotImp);
    }

    let req = &queries[0];
    if req.query_class() != DNSClass::IN {
        return Err(ResponseCode::Refused);
    }
    match req.query_type() {
        RecordType::ANY | RecordType::AXFR | RecordType::IXFR => Err(ResponseCode::Refused),
        RecordType::OPT | RecordType::ZERO => Err(ResponseCode::FormErr),
        RecordType::TSIG | RecordType::Unknown(249) => Err(ResponseCode::NotImp),
        _ => Ok(req),
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
