use std::sync::Arc;

use hickory_proto::rr::{Record, RecordType};
use uuid::Uuid;

use landscape_common::metric::dns::DnsOutcome;

use crate::domain::ParsedDomain;
use crate::server::{rule::DNSRedirectRuntime, LocalDnsAnswerProvider};

/// Outcome of a matched redirect rule. `redirect_id` and
/// `dynamic_redirect_source` identify the rule for the check API.
#[derive(Debug)]
pub struct RedirectAnswer {
    pub records: Vec<Record>,
    pub outcome: DnsOutcome,
    pub redirect_id: Option<Uuid>,
    pub dynamic_redirect_source: Option<String>,
}

#[derive(Debug, Default)]
pub struct RedirectEngine {
    rules: Vec<DNSRedirectRuntime>,
}

impl RedirectEngine {
    pub fn new(rules: Vec<DNSRedirectRuntime>) -> Self {
        Self { rules }
    }

    pub fn lookup(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        local_answer_provider: Option<&Arc<dyn LocalDnsAnswerProvider>>,
    ) -> Option<RedirectAnswer> {
        for rule in &self.rules {
            if !rule.is_match(domain) {
                continue;
            }

            let uses_provider = rule.uses_local_answer_provider();
            let records = if uses_provider {
                let Some(provider) = local_answer_provider else {
                    continue;
                };
                let addrs = provider.load_local_answer_addrs(query_type);
                rule.lookup_with_addrs(domain, query_type, &addrs)
            } else {
                rule.lookup(domain, query_type)
            };

            if uses_provider && records.is_empty() {
                continue;
            }

            let outcome = if rule.is_block() { DnsOutcome::Block } else { DnsOutcome::Local };
            return Some(RedirectAnswer {
                records,
                outcome,
                redirect_id: rule.redirect_id,
                dynamic_redirect_source: rule.dynamic_redirect_source.clone(),
            });
        }
        None
    }
}
