use std::{collections::BTreeMap, sync::Arc};

use hickory_proto::rr::{Record, RecordType};
use uuid::Uuid;

use landscape_common::metric::dns::DnsOutcome;

use crate::server::{
    rule::{DNSRedirectRuntime, DNSResolveRuntime},
    LocalDnsAnswerProvider,
};

#[derive(Debug, Default)]
pub struct RedirectEngine {
    rules: Vec<DNSRedirectRuntime>,
}

impl RedirectEngine {
    pub fn new(rules: Vec<DNSRedirectRuntime>) -> Self {
        Self { rules }
    }

    pub fn is_match(&self, domain: &str) -> bool {
        self.rules.iter().any(|rule| rule.is_match(domain))
    }

    pub fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
        local_answer_provider: Option<&Arc<dyn LocalDnsAnswerProvider>>,
    ) -> Option<(Vec<Record>, DnsOutcome, Option<Uuid>, Option<String>)> {
        for rule in &self.rules {
            if !rule.is_match(domain) {
                continue;
            }

            let records = if rule.uses_local_answer_provider() {
                let Some(provider) = local_answer_provider else {
                    continue;
                };
                let addrs = provider.load_local_answer_addrs(query_type);
                rule.lookup_with_addrs(domain, query_type, &addrs)
            } else {
                rule.lookup(domain, query_type)
            };

            if rule.uses_local_answer_provider() && records.is_empty() {
                continue;
            }

            let outcome = if rule.is_block() { DnsOutcome::Block } else { DnsOutcome::Local };
            return Some((
                records,
                outcome,
                rule.redirect_id,
                rule.dynamic_redirect_source.clone(),
            ));
        }
        None
    }
}

#[derive(Debug, Default)]
pub struct ResolveEngine {
    rules: BTreeMap<u32, DNSResolveRuntime>,
}

impl ResolveEngine {
    pub fn new(rules: BTreeMap<u32, DNSResolveRuntime>) -> Self {
        Self { rules }
    }

    pub fn find_match(&self, domain: &str) -> Option<&DNSResolveRuntime> {
        self.rules.values().find(|rule| rule.is_match(domain))
    }

    pub fn get(&self, order: u32) -> Option<&DNSResolveRuntime> {
        self.rules.get(&order)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u32, &DNSResolveRuntime)> {
        self.rules.iter()
    }
}
