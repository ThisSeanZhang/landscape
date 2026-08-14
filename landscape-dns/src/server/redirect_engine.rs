use std::sync::Arc;

use hickory_proto::rr::{Record, RecordType};
use uuid::Uuid;

use landscape_common::metric::dns::DnsOutcome;

use crate::domain::ParsedDomain;
use crate::server::{answer::response_code_for, rule::DNSRedirectRuntime, LocalDnsAnswerProvider};

/// Outcome of a matched redirect rule. `redirect_id` and
/// `dynamic_redirect_source` identify the rule for the check API.
#[derive(Debug)]
pub struct RedirectAnswer {
    pub records: Vec<Record>,
    pub outcome: DnsOutcome,
    pub redirect_id: Option<Uuid>,
    pub dynamic_redirect_source: Option<String>,
}

impl RedirectAnswer {
    /// The protocol response code this redirect answer implies: redirect
    /// answers are served with NoError (including empty/blocked ones), the
    /// same behavior the live path had before.
    pub fn response_code(&self) -> hickory_proto::op::ResponseCode {
        response_code_for(self.outcome)
    }
}

/// Whitelist of metadata-only query types that carry no redirect answer and
/// can be passed through to the upstream resolver on rules that opt out of
/// intercepting them. Every other type (A/AAAA/HTTPS/SVCB/CNAME/PTR/...)
/// stays intercepted: a pass-through could leak real addresses or let
/// clients bypass the redirect.
fn is_pass_through_query_type(query_type: RecordType) -> bool {
    matches!(
        query_type,
        RecordType::NS | RecordType::SOA | RecordType::TXT | RecordType::MX | RecordType::CAA
    )
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

            // Metadata queries (NS/SOA/TXT/MX/CAA) on rules that opt out of
            // intercepting them carry no redirect answer; pass them through
            // so upstream answers reach the client. Block rules and rules
            // with `block_metadata_queries` keep intercepting everything.
            // The first matching rule decides: once a rule passes the query
            // through, no later (broader) rule is consulted.
            if !uses_provider
                && !rule.is_block()
                && !rule.blocks_metadata_queries()
                && records.is_empty()
                && is_pass_through_query_type(query_type)
            {
                return None;
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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use hickory_proto::rr::{rdata::A, RData, RecordType};

    use landscape_common::dns::{
        redirect::DnsRedirectAnswerMode,
        rule::{DomainConfig, DomainMatchType},
    };

    use crate::server::matcher::RuntimeRuleMatcher;
    use crate::server::rule::RedirectRuleParams;

    use super::*;

    fn pd(name: &str) -> ParsedDomain {
        ParsedDomain::new(name).unwrap()
    }

    fn static_rule(addrs: Vec<IpAddr>, block_metadata_queries: bool) -> DNSRedirectRuntime {
        DNSRedirectRuntime::new(RedirectRuleParams {
            redirect_id: None,
            dynamic_redirect_source: None,
            answer_mode: DnsRedirectAnswerMode::StaticIps,
            matcher: RuntimeRuleMatcher::new(
                vec![DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: "example.com".to_string(),
                }],
                vec![],
                vec![],
                false,
            ),
            result_info: addrs,
            ttl_secs: 60,
            block_metadata_queries,
        })
    }

    fn provider(addrs: Vec<IpAddr>) -> Arc<dyn LocalDnsAnswerProvider> {
        struct MockProvider {
            addrs: Vec<IpAddr>,
        }
        impl LocalDnsAnswerProvider for MockProvider {
            fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
                Arc::new(
                    self.addrs
                        .iter()
                        .copied()
                        .filter(|addr| {
                            matches!(
                                (addr, query_type),
                                (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                            )
                        })
                        .collect(),
                )
            }
        }
        Arc::new(MockProvider { addrs })
    }

    #[test]
    fn metadata_pass_through_is_off_by_default() {
        let engine = RedirectEngine::new(vec![static_rule(
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            true,
        )]);

        // Default (strict): metadata queries stay intercepted.
        for ty in
            [RecordType::NS, RecordType::SOA, RecordType::TXT, RecordType::MX, RecordType::CAA]
        {
            let answer = engine.lookup(&pd("example.com."), ty, None).unwrap();
            assert!(answer.records.is_empty(), "{ty:?} should be intercepted by default");
            assert_eq!(answer.outcome, DnsOutcome::Local);
        }
    }

    #[test]
    fn static_ips_rule_passes_through_metadata_queries_when_opted_out() {
        let engine = RedirectEngine::new(vec![static_rule(
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            false,
        )]);

        // Address queries keep the redirect answer.
        let answer = engine.lookup(&pd("example.com."), RecordType::A, None).unwrap();
        assert_eq!(answer.records.len(), 1);
        assert!(matches!(answer.records[0].data, RData::A(A(_))));
        assert_eq!(answer.outcome, DnsOutcome::Local);

        // AAAA/HTTPS/SVCB/CNAME/PTR stay intercepted with an empty answer.
        for ty in [
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::CNAME,
            RecordType::PTR,
        ] {
            let answer = engine.lookup(&pd("example.com."), ty, None).unwrap();
            assert!(answer.records.is_empty(), "{ty:?} should be intercepted");
        }

        // Metadata queries pass through to upstream.
        for ty in
            [RecordType::NS, RecordType::SOA, RecordType::TXT, RecordType::MX, RecordType::CAA]
        {
            assert!(
                engine.lookup(&pd("example.com."), ty, None).is_none(),
                "{ty:?} should pass through"
            );
        }
    }

    #[test]
    fn pass_through_wins_over_later_broader_rule() {
        let engine = RedirectEngine::new(vec![
            static_rule(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))], false),
            static_rule(vec![], true),
        ]);

        // A matching first rule that opts out passes metadata queries through
        // even if a later, broader rule would have intercepted them.
        for ty in
            [RecordType::NS, RecordType::SOA, RecordType::TXT, RecordType::MX, RecordType::CAA]
        {
            assert!(
                engine.lookup(&pd("example.com."), ty, None).is_none(),
                "{ty:?} should pass through without consulting later rules"
            );
        }

        // Address queries still hit the first rule's redirect answer.
        let answer = engine.lookup(&pd("example.com."), RecordType::A, None).unwrap();
        assert_eq!(answer.records.len(), 1);
    }

    #[test]
    fn block_rule_intercepts_all_query_types() {
        let engine = RedirectEngine::new(vec![static_rule(vec![], false)]);

        for ty in [RecordType::A, RecordType::NS, RecordType::TXT, RecordType::AAAA] {
            let answer = engine.lookup(&pd("example.com."), ty, None).unwrap();
            assert!(answer.records.is_empty(), "{ty:?} should be blocked");
            assert_eq!(answer.outcome, DnsOutcome::Block);
        }
    }

    #[test]
    fn all_local_ips_rule_keeps_passing_through_metadata_queries() {
        let rule = DNSRedirectRuntime::new(RedirectRuleParams {
            redirect_id: None,
            dynamic_redirect_source: None,
            answer_mode: DnsRedirectAnswerMode::AllLocalIps,
            matcher: RuntimeRuleMatcher::new(
                vec![DomainConfig {
                    match_type: DomainMatchType::Full,
                    value: "example.com".to_string(),
                }],
                vec![],
                vec![],
                false,
            ),
            result_info: vec![],
            ttl_secs: 60,
            block_metadata_queries: true,
        });
        let engine = RedirectEngine::new(vec![rule]);
        let provider = provider(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);

        let answer = engine.lookup(&pd("example.com."), RecordType::A, Some(&provider)).unwrap();
        assert_eq!(answer.records.len(), 1);

        assert!(engine.lookup(&pd("example.com."), RecordType::NS, Some(&provider)).is_none());
    }
}
