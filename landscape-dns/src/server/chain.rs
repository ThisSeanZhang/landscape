use std::{future::Future, time::Duration};

use hickory_proto::{
    op::ResponseCode,
    rr::{
        rdata::{
            svcb::{SvcParamKey, SVCB},
            HTTPS,
        },
        RData, Record, RecordType,
    },
};
use landscape_common::{dns::error::DnsError, dns::rule::FilterResult, metric::dns::DnsOutcome};

use crate::{
    domain::ParsedDomain,
    server::{
        answer::{response_code_for, DnsQueryAnswer},
        cache::CacheHandle,
        ebpf::DnsMarkMap,
        local::{LocalAnswer, LocalResolver},
        redirect_engine::RedirectAnswer,
        rule::DNSResolveRuntime,
        snapshot::RuntimeSnapshot,
    },
    CheckChainDnsResult,
};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a matched rule's upstream lookup; the caller (`stage_rule`) has
/// already applied the cache write policy via `apply_outcome_to_cache`.
enum RuleLookupOutcome {
    /// Upstream answered (possibly an empty NOERROR answer).
    NoError { records: Vec<Record> },
    /// Upstream answered NXDOMAIN.
    NxDomain,
    /// Upstream answered with an explicit error code (Refused, NotImp,
    /// FormErr, ServFail, ...). The code is passed through to the client.
    ErrorCode(ResponseCode),
    /// Unrecoverable upstream failure (timeout, ServFail, ...).
    Failed,
}

impl RuleLookupOutcome {
    /// The (records, response code) pair to cache for this outcome, if any.
    /// `NxDomain` caches an empty (negative) answer, explicit error codes and
    /// failures nothing.
    fn cache_write(&self) -> Option<(Vec<Record>, ResponseCode)> {
        match self {
            RuleLookupOutcome::NoError { records } => {
                Some((records.clone(), ResponseCode::NoError))
            }
            RuleLookupOutcome::NxDomain => Some((vec![], ResponseCode::NXDomain)),
            RuleLookupOutcome::ErrorCode(_) | RuleLookupOutcome::Failed => None,
        }
    }
}

/// Cache write behaviour for a rule lookup.
#[derive(Clone, Copy)]
enum CacheWritePolicy {
    /// Read-only: upstream lookup only, cache untouched.
    ReadOnly,
    /// Persist the outcome; `query_filtered` queries clear any stale entry
    /// instead of inserting.
    Write { query_filtered: bool },
}

/// The resolution chain shared by live queries, config checks and cache
/// refreshes: (1) redirect → (2) local classification → (3) cache/upstream.
/// Each entry point composes the same stages with its own side-effect policy,
/// so live traffic, check and refresh always agree on one classification.
pub(crate) struct ResolveChain<'a> {
    runtime: &'a RuntimeSnapshot,
    local_resolver: &'a LocalResolver,
    maps: &'a dyn DnsMarkMap,
    flow_id: u32,
}

impl<'a> ResolveChain<'a> {
    pub fn new(
        runtime: &'a RuntimeSnapshot,
        local_resolver: &'a LocalResolver,
        maps: &'a dyn DnsMarkMap,
        flow_id: u32,
    ) -> Self {
        Self { runtime, local_resolver, maps, flow_id }
    }

    // ---- stages ----

    fn stage_redirect(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<RedirectAnswer> {
        self.runtime.redirect_engine.lookup(
            domain,
            query_type,
            self.local_resolver.local_answer_provider(),
        )
    }

    fn stage_local(&self, domain: &ParsedDomain, query_type: RecordType) -> Option<LocalAnswer> {
        self.local_resolver.resolve_local(domain, query_type)
    }

    async fn stage_cache(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Option<(Vec<Record>, FilterResult, ResponseCode)> {
        self.runtime.cache.lookup(domain, query_type).await
    }

    async fn stage_rule(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        resolver: &DNSResolveRuntime,
        policy: CacheWritePolicy,
    ) -> RuleLookupOutcome {
        let outcome =
            match with_lookup_timeout(resolver.lookup(domain.raw(), query_type), LOOKUP_TIMEOUT)
                .await
            {
                Ok(rdata_vec) => RuleLookupOutcome::NoError { records: rdata_vec },
                Err(err) => rule_lookup_outcome_from_error(&err),
            };

        if let CacheWritePolicy::Write { query_filtered } = policy {
            apply_outcome_to_cache(
                &self.runtime.cache,
                resolver,
                domain,
                query_type,
                query_filtered,
                &outcome,
            )
            .await;
        }

        outcome
    }

    // ---- entry points ----

    /// The live query path: redirect → local classification → cache/upstream.
    pub async fn resolve(&self, domain: &ParsedDomain, query_type: RecordType) -> DnsQueryAnswer {
        // (1) Redirect (global check first)
        if let Some(answer) = self.stage_redirect(domain, query_type) {
            let response_code = answer.response_code();
            return DnsQueryAnswer {
                records: answer.records,
                outcome: answer.outcome,
                response_code,
            };
        }

        // (2) Local classification (blocked TLDs, localhost, local zone,
        // `.arpa`). `None` means the resolver does not own the query and it
        // must continue to (3) Cache → (4) Upstream.
        if let Some(answer) = self.stage_local(domain, query_type) {
            let response_code = answer.response_code();
            let (records, outcome) = match answer {
                LocalAnswer::Answered { records, outcome } => (records, outcome),
                LocalAnswer::Empty { outcome } => (vec![], outcome),
            };
            return DnsQueryAnswer { records, outcome, response_code };
        }
        self.resolve_from_cache_or_upstream(domain, query_type).await
    }

    async fn resolve_from_cache_or_upstream(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> DnsQueryAnswer {
        if let Some((cached_records, filter, code)) = self.stage_cache(domain, query_type).await {
            if is_type_filtered(query_type, &filter) {
                let outcome = if code == ResponseCode::NXDomain {
                    DnsOutcome::NxDomain
                } else {
                    DnsOutcome::Filter
                };
                return DnsQueryAnswer {
                    records: vec![],
                    outcome,
                    response_code: response_code_for(outcome),
                };
            }
            let outcome =
                if code == ResponseCode::NXDomain { DnsOutcome::NxDomain } else { DnsOutcome::Hit };
            return DnsQueryAnswer {
                records: filter_result(cached_records, &filter),
                outcome,
                response_code: response_code_for(outcome),
            };
        }

        if let Some(resolver) = self.runtime.resolve_engine.find_match(domain) {
            let filter = resolver.filter_mode();
            if is_type_filtered(query_type, &filter) {
                return DnsQueryAnswer {
                    records: vec![],
                    outcome: DnsOutcome::Filter,
                    response_code: response_code_for(DnsOutcome::Filter),
                };
            }

            return match self
                .stage_rule(
                    domain,
                    query_type,
                    resolver,
                    CacheWritePolicy::Write { query_filtered: false },
                )
                .await
            {
                RuleLookupOutcome::NoError { records } => DnsQueryAnswer {
                    records: filter_result(records, &filter),
                    outcome: DnsOutcome::Normal,
                    response_code: ResponseCode::NoError,
                },
                RuleLookupOutcome::NxDomain => DnsQueryAnswer {
                    records: vec![],
                    outcome: DnsOutcome::NxDomain,
                    response_code: ResponseCode::NXDomain,
                },
                RuleLookupOutcome::ErrorCode(code) => DnsQueryAnswer {
                    records: vec![],
                    outcome: DnsOutcome::Error,
                    response_code: code,
                },
                RuleLookupOutcome::Failed => DnsQueryAnswer {
                    records: vec![],
                    outcome: DnsOutcome::Error,
                    response_code: response_code_for(DnsOutcome::Error),
                },
            };
        }
        DnsQueryAnswer {
            records: vec![],
            outcome: DnsOutcome::Normal,
            response_code: ResponseCode::NoError,
        }
    }

    /// Config-check path: read-only chain report, plus a projection of what a
    /// client would currently get from the cache.
    pub async fn check(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) -> CheckChainDnsResult {
        let mut result = CheckChainDnsResult::default();

        // (1) Redirect
        if let Some(answer) = self.stage_redirect(domain, query_type) {
            result.redirect_id = answer.redirect_id;
            result.dynamic_redirect_source = answer.dynamic_redirect_source;
            result.records = Some(crate::to_common_records(answer.records));
        } else if let Some(answer) = self.stage_local(domain, query_type) {
            // (2) Local classification
            if let LocalAnswer::Answered { records, .. } = answer {
                result.records = Some(crate::to_common_records(records));
            }
            return result;
        } else if let Some(resolver) = self.runtime.resolve_engine.find_match(domain) {
            // (3) Rules (read-only; the cache report below shows what a client
            // would currently see)
            result.rule_id = Some(resolver.get_config_id());
            let filter = resolver.filter_mode();
            result.rule_filter = Some(filter.clone());

            result.query_filtered = is_type_filtered(query_type, &filter);
            if result.query_filtered && apply_filter {
                result.records = Some(vec![]);
            } else {
                // Read-only: no cache writes here, the cache report below
                // shows what a client would currently see.
                if let RuleLookupOutcome::NoError { records } =
                    self.stage_rule(domain, query_type, resolver, CacheWritePolicy::ReadOnly).await
                {
                    result.records = Some(crate::to_common_records(if apply_filter {
                        filter_result(records, &filter)
                    } else {
                        records
                    }));
                }
            }
        }

        // (4) Cache report
        Self::fill_cache_records(
            &mut result,
            &self.runtime.cache,
            domain,
            query_type,
            apply_filter,
        )
        .await;

        result
    }

    /// Cache-refresh path: recomputes the answer with cache writes enabled and
    /// converges the cache (clearing stale local/`.arpa` entries).
    pub async fn refresh(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) -> Result<CheckChainDnsResult, DnsError> {
        // (1) Redirect
        if self.stage_redirect(domain, query_type).is_some() {
            return Err(DnsError::RefreshRedirected(domain.raw().to_string()));
        }

        // (2) Local classification. Local answers never enter the cache, but
        // any stale entry is cleared first (an entry can only exist if an
        // earlier config let this name reach the cache/upstream stage).
        if let Some(answer) = self.stage_local(domain, query_type) {
            self.clear_stale_entry_and_refresh_maps(domain, query_type).await;
            return Ok(match answer {
                LocalAnswer::Answered { records, .. } => CheckChainDnsResult {
                    records: Some(crate::to_common_records(records)),
                    ..Default::default()
                },
                LocalAnswer::Empty { .. } => CheckChainDnsResult::default(),
            });
        }

        // (2b) Non-local `.arpa` names (public reverse lookups, e.g.
        // `8.8.8.8.in-addr.arpa.`): the resolver is only a recursive
        // forwarder here, exactly like the live path. Clear any stale entry
        // first so the cache converges with what clients see, then resolve
        // through the rules engine. Without a matching rule the live path
        // answers NOERROR/empty, so refresh must return Ok as well, not
        // `RefreshRequiresRule`.
        if domain.name().ends_with(".arpa") {
            self.clear_stale_entry_and_refresh_maps(domain, query_type).await;
            let answer = self.resolve_from_cache_or_upstream(domain, query_type).await;
            return Ok(CheckChainDnsResult {
                records: Some(crate::to_common_records(answer.records)),
                ..Default::default()
            });
        }

        let Some(resolver) = self.runtime.resolve_engine.find_match(domain) else {
            return Err(DnsError::RefreshRequiresRule(domain.raw().to_string()));
        };

        let filter = resolver.filter_mode();
        let query_filtered = is_type_filtered(query_type, &filter);
        let mut result = CheckChainDnsResult {
            rule_id: Some(resolver.get_config_id()),
            rule_filter: Some(filter.clone()),
            query_filtered,
            ..Default::default()
        };

        match self
            .stage_rule(domain, query_type, resolver, CacheWritePolicy::Write { query_filtered })
            .await
        {
            RuleLookupOutcome::NoError { records } => {
                result.records = Some(if apply_filter {
                    crate::to_common_records(filter_result(records, &filter))
                } else {
                    crate::to_common_records(records)
                });
            }
            RuleLookupOutcome::NxDomain => {
                result.records = Some(vec![]);
            }
            RuleLookupOutcome::ErrorCode(_) => {
                // Explicit upstream error: nothing to cache, treat like a
                // failure for the refresh contract.
                result.records = Some(vec![]);
                if !query_filtered {
                    return Err(DnsError::RefreshFailed(domain.raw().to_string()));
                }
            }
            RuleLookupOutcome::Failed => {
                // Filtered queries are served an empty answer, so a
                // failure is not an error here; anything else cannot be
                // resolved at all.
                result.records = Some(vec![]);
                if !query_filtered {
                    return Err(DnsError::RefreshFailed(domain.raw().to_string()));
                }
            }
        }

        self.refresh_maps_from_cache();

        Self::fill_cache_records(
            &mut result,
            &self.runtime.cache,
            domain,
            query_type,
            apply_filter,
        )
        .await;

        Ok(result)
    }

    // ---- shared helpers ----

    /// Shared cache report for check/refresh: projects the current cache entry
    /// into `cache_records` and merges its filter state into the result.
    async fn fill_cache_records(
        result: &mut CheckChainDnsResult,
        cache: &CacheHandle,
        domain: &ParsedDomain,
        query_type: RecordType,
        apply_filter: bool,
    ) {
        if let Some((records, filter, _)) = cache.lookup(domain, query_type).await {
            let query_filtered = is_type_filtered(query_type, &filter);
            result.query_filtered |= query_filtered;
            if result.rule_filter.is_none() {
                result.rule_filter = Some(filter.clone());
            }
            result.cache_records = Some(if query_filtered && apply_filter {
                vec![]
            } else if apply_filter {
                crate::to_common_records(filter_result(records, &filter))
            } else {
                crate::to_common_records(records)
            });
        }
    }

    async fn clear_stale_entry_and_refresh_maps(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) {
        if self.runtime.cache.invalidate_if_present(domain, query_type).await {
            self.refresh_maps_from_cache();
        }
    }

    fn refresh_maps_from_cache(&self) {
        self.maps.refresh_flow_dns(
            self.flow_id,
            self.runtime.cache.dns_mark_list().into_iter().collect(),
        );
        self.maps.recreate_route_cache();
    }
}

/// Persists a rule lookup outcome to the cache: filtered queries clear any
/// stale entry, cacheable outcomes are inserted with their response code.
/// Non-representable failures (`Failed`) leave the cache untouched.
async fn apply_outcome_to_cache(
    cache: &CacheHandle,
    resolver: &DNSResolveRuntime,
    domain: &ParsedDomain,
    query_type: RecordType,
    query_filtered: bool,
    outcome: &RuleLookupOutcome,
) {
    if query_filtered {
        cache.invalidate(domain, query_type).await;
    } else if let Some((records, code)) = outcome.cache_write() {
        cache
            .insert(CacheHandle::resolver_cache_entry(
                resolver,
                domain.raw_arc(),
                query_type,
                records,
                code,
            ))
            .await;
    }
}

/// Maps an upstream lookup error to the rule outcome. Explicit protocol codes
/// are preserved so they can be passed through to the client; NXDomain and
/// NoError are still treated as negative answers, everything else fails.
fn rule_lookup_outcome_from_error(err: &crate::error::DnsError) -> RuleLookupOutcome {
    match err {
        crate::error::DnsError::Protocol(code) if *code == ResponseCode::NXDomain => {
            RuleLookupOutcome::NxDomain
        }
        crate::error::DnsError::Protocol(code) if *code == ResponseCode::NoError => {
            RuleLookupOutcome::NoError { records: vec![] }
        }
        crate::error::DnsError::Protocol(code) => RuleLookupOutcome::ErrorCode(*code),
        _ => RuleLookupOutcome::Failed,
    }
}

async fn with_lookup_timeout<F, T>(future: F, timeout: Duration) -> crate::error::DnsResult<T>
where
    F: Future<Output = crate::error::DnsResult<T>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(crate::error::DnsError::Timeout),
    }
}

fn filter_result(un_filter_records: Vec<Record>, filter: &FilterResult) -> Vec<Record> {
    if matches!(filter, FilterResult::Unfilter) {
        return un_filter_records;
    }
    un_filter_records
        .into_iter()
        .filter(|r| match (r.record_type(), filter) {
            (RecordType::A, FilterResult::OnlyIPv4) => true,
            (RecordType::A, FilterResult::OnlyIPv6) => false,
            (RecordType::AAAA, FilterResult::OnlyIPv4) => false,
            (RecordType::AAAA, FilterResult::OnlyIPv6) => true,
            _ => true,
        })
        .map(|mut r| {
            // For HTTPS records, strip ipv4hint/ipv6hint SvcParams
            // that contradict the IP-version filter, so clients won't
            // use a hint to bypass the filter.
            if r.record_type() == RecordType::HTTPS {
                if let RData::HTTPS(https) = r.data.clone() {
                    let key_to_remove = match filter {
                        FilterResult::OnlyIPv4 => Some(SvcParamKey::Ipv6Hint),
                        FilterResult::OnlyIPv6 => Some(SvcParamKey::Ipv4Hint),
                        FilterResult::Unfilter => None,
                    };
                    if let Some(remove_key) = key_to_remove {
                        let filtered_params: Vec<_> = https
                            .0
                            .svc_params
                            .iter()
                            .filter(|(k, _)| *k != remove_key)
                            .cloned()
                            .collect();
                        let new_svcb = SVCB::new(
                            https.0.svc_priority,
                            https.0.target_name.clone(),
                            filtered_params,
                        );
                        r.data = RData::HTTPS(HTTPS(new_svcb));
                    }
                }
            }
            r
        })
        .collect()
}

fn is_type_filtered(query_type: RecordType, filter: &FilterResult) -> bool {
    match (query_type, filter) {
        (RecordType::A, FilterResult::OnlyIPv6) => true,
        (RecordType::AAAA, FilterResult::OnlyIPv4) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA};
    use landscape_common::dns::rule::FilterResult;
    use std::{net::Ipv4Addr, str::FromStr};

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
    }

    #[test]
    fn test_is_type_filtered() {
        assert!(is_type_filtered(RecordType::A, &FilterResult::OnlyIPv6));
        assert!(!is_type_filtered(RecordType::AAAA, &FilterResult::OnlyIPv6));
        assert!(is_type_filtered(RecordType::AAAA, &FilterResult::OnlyIPv4));
        assert!(!is_type_filtered(RecordType::A, &FilterResult::OnlyIPv4));
        assert!(!is_type_filtered(RecordType::A, &FilterResult::Unfilter));
    }

    #[test]
    fn test_filter_result() {
        let name = hickory_proto::rr::Name::from_str("test.com.").unwrap();
        let records = vec![
            Record::from_rdata(name.clone(), 60, RData::A(A(Ipv4Addr::new(1, 1, 1, 1)))),
            Record::from_rdata(
                name.clone(),
                60,
                RData::AAAA(AAAA(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            ),
        ];

        let filtered_v4 = filter_result(records.clone(), &FilterResult::OnlyIPv4);
        assert_eq!(filtered_v4.len(), 1);
        assert_eq!(filtered_v4[0].record_type(), RecordType::A);

        let filtered_v6 = filter_result(records.clone(), &FilterResult::OnlyIPv6);
        assert_eq!(filtered_v6.len(), 1);
        assert_eq!(filtered_v6[0].record_type(), RecordType::AAAA);

        let filtered_none = filter_result(records.clone(), &FilterResult::Unfilter);
        assert_eq!(filtered_none.len(), 2);
    }

    #[test]
    fn test_rule_lookup_outcome_from_error_passes_upstream_error_codes_through() {
        use crate::error::DnsError;

        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Protocol(ResponseCode::Refused)),
            RuleLookupOutcome::ErrorCode(ResponseCode::Refused)
        ));
        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Protocol(ResponseCode::NotImp)),
            RuleLookupOutcome::ErrorCode(ResponseCode::NotImp)
        ));
        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Protocol(ResponseCode::ServFail)),
            RuleLookupOutcome::ErrorCode(ResponseCode::ServFail)
        ));
        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Protocol(ResponseCode::NXDomain)),
            RuleLookupOutcome::NxDomain
        ));
        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Protocol(ResponseCode::NoError)),
            RuleLookupOutcome::NoError { .. }
        ));
        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Timeout),
            RuleLookupOutcome::Failed
        ));
        assert!(matches!(
            rule_lookup_outcome_from_error(&DnsError::Internal("boom".into())),
            RuleLookupOutcome::Failed
        ));

        let no_error = RuleLookupOutcome::NoError { records: vec![] };
        let (records, code) = no_error.cache_write().unwrap();
        assert!(records.is_empty());
        assert_eq!(code, ResponseCode::NoError);

        let nxdomain = RuleLookupOutcome::NxDomain;
        let (records, code) = nxdomain.cache_write().unwrap();
        assert!(records.is_empty());
        assert_eq!(code, ResponseCode::NXDomain);

        // Explicit upstream error codes are never cached, like failures.
        assert!(RuleLookupOutcome::ErrorCode(ResponseCode::Refused).cache_write().is_none());
        assert!(RuleLookupOutcome::Failed.cache_write().is_none());
    }

    #[test]
    fn test_with_lookup_timeout_maps_timeout_and_passes_through_inner_result() {
        run_async_test(async {
            let timeout = with_lookup_timeout(
                async {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok::<_, crate::error::DnsError>(vec![1_u8])
                },
                Duration::from_millis(5),
            )
            .await;
            assert!(matches!(timeout, Err(crate::error::DnsError::Timeout)));

            let inner = with_lookup_timeout(
                async { Ok::<_, crate::error::DnsError>(vec![1_u8, 2_u8]) },
                Duration::from_millis(50),
            )
            .await;
            assert_eq!(inner.unwrap(), vec![1_u8, 2_u8]);
        });
    }
}
