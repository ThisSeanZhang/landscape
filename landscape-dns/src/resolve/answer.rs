use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, RecordType},
};
use landscape_common::metric::dns::DnsOutcome;

/// DNS data shared by upstream, cache and client response paths.
#[derive(Clone, Debug)]
pub(crate) struct DnsAnswer {
    pub records: Vec<Record>,
    pub response_code: ResponseCode,
    pub truncated: bool,
    /// The final name returned NXDOMAIN or NODATA, even if the alias chain contains records.
    pub is_negative: bool,
    pub soa: Option<Box<Record>>,
}

impl DnsAnswer {
    pub fn new(records: Vec<Record>, response_code: ResponseCode) -> Self {
        Self {
            is_negative: response_code == ResponseCode::NXDomain
                || (response_code == ResponseCode::NoError && records.is_empty()),
            records,
            response_code,
            truncated: false,
            soa: None,
        }
    }

    pub fn negative(response_code: ResponseCode, mut soa: Option<Box<Record>>) -> Self {
        if let Some(record) = soa.as_mut()
            && let RData::SOA(data) = &record.data
        {
            record.ttl = record.ttl.min(data.minimum);
        }
        Self { soa, ..Self::new(vec![], response_code) }
    }

    pub fn is_negative_message(message: &Message) -> bool {
        if message.response_code != ResponseCode::NoError {
            return message.response_code == ResponseCode::NXDomain;
        }
        if message.answers.is_empty() {
            return true;
        }
        // An alias chain can end in NODATA. Recursive upstreams sometimes
        // put the final address in the additional section instead.
        let Some(query) = message.queries.first() else { return false };
        if matches!(query.query_type(), RecordType::CNAME | RecordType::ANY)
            || !message.answers.iter().all(|r| r.record_type() == RecordType::CNAME)
            || !message.authorities.iter().any(|r| r.record_type() == RecordType::SOA)
        {
            return false;
        }
        !message.additionals.iter().any(|r| {
            r.record_type() == query.query_type()
                && message
                    .answers
                    .iter()
                    .any(|alias| matches!(&alias.data, RData::CNAME(target) if target.0 == r.name))
        })
    }

    pub fn from_message(message: Message) -> Self {
        let mut answer = if Self::is_negative_message(&message) {
            let soa = message.authorities.into_iter().find(|r| r.record_type() == RecordType::SOA);
            let mut negative = Self::negative(message.metadata.response_code, soa.map(Box::new));
            negative.records = message.answers;
            negative
        } else {
            Self::new(message.answers, message.metadata.response_code)
        };
        answer.truncated = message.metadata.truncation;
        answer
    }

    pub fn cacheable(&self) -> bool {
        !self.truncated
            && matches!(self.response_code, ResponseCode::NoError | ResponseCode::NXDomain)
    }
}

impl std::ops::Deref for DnsAnswer {
    type Target = [Record];

    fn deref(&self) -> &[Record] {
        &self.records
    }
}

impl IntoIterator for DnsAnswer {
    type Item = Record;
    type IntoIter = std::vec::IntoIter<Record>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter()
    }
}

/// The final answer of a resolution chain: the records to serve, the business
/// classification for metrics and the authoritative protocol response code.
///
/// `outcome` and `response_code` are deliberately decoupled: `outcome`
/// describes how the query was handled (redirect/local/cache/upstream) for
/// statistics, while `response_code` is what the client actually receives.
/// Upstream error codes (Refused, NotImp, FormErr, ServFail, ...) are passed
/// through as-is instead of being flattened to ServFail.
pub(crate) struct DnsQueryAnswer {
    pub dns: DnsAnswer,
    pub outcome: DnsOutcome,
    pub authoritative: bool,
}

impl DnsQueryAnswer {
    pub fn local(records: Vec<Record>, outcome: DnsOutcome, code: ResponseCode) -> Self {
        Self {
            dns: DnsAnswer::new(records, code),
            outcome,
            authoritative: true,
        }
    }
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
