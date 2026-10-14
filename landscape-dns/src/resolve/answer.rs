use hickory_proto::{op::ResponseCode, rr::Record};
use landscape_common::metric::dns::DnsOutcome;

/// The final answer of a resolution chain: the records to serve, the business
/// classification for metrics and the authoritative protocol response code.
///
/// `outcome` and `response_code` are deliberately decoupled: `outcome`
/// describes how the query was handled (redirect/local/cache/upstream) for
/// statistics, while `response_code` is what the client actually receives.
/// Upstream error codes (Refused, NotImp, FormErr, ServFail, ...) are passed
/// through as-is instead of being flattened to ServFail.
pub(crate) struct DnsQueryAnswer {
    pub records: Vec<Record>,
    pub outcome: DnsOutcome,
    pub response_code: ResponseCode,
}

/// Default protocol response code for a business outcome, used by stages that
/// own their answer (redirect, local, cache) and as the fallback for failures
/// without a specific upstream code.
pub(crate) fn response_code_for(outcome: DnsOutcome) -> ResponseCode {
    match outcome {
        DnsOutcome::NxDomain => ResponseCode::NXDomain,
        DnsOutcome::Error => ResponseCode::ServFail,
        _ => ResponseCode::NoError,
    }
}
