use std::{future::Future, time::Duration};

use hickory_proto::{
    op::ResponseCode,
    rr::{
        RData, Record, RecordType,
        rdata::{
            HTTPS,
            svcb::{SVCB, SvcParamKey},
        },
    },
};
use landscape_common::{
    dns::error::{DnsResult, DnsServiceError},
    dns::rule::FilterResult,
    metric::dns::DnsOutcome,
};

use crate::{
    CheckChainDnsResult,
    domain::ParsedDomain,
    resolve::{
        RuntimeSnapshot,
        answer::{DnsAnswer, DnsQueryAnswer},
        cache::CacheHandle,
        local::{LocalAnswer, LocalResolver},
        redirect::RedirectAnswer,
        rule::DNSResolveRuntime,
    },
};

/// Outer envelope for one rule's upstream lookup. Must stay strictly above
/// the native pool's worst-case internal budget (`attempts × query_timeout
/// + connect_timeout` = 5s with the current defaults): with equal budgets
/// the caller's timeout fires at the exact moment the pool's final attempt
/// completes, discarding a valid answer. Pool defaults are covered by
/// `pool_config::tests::default_budget_leaves_caller_margin`.
pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(6);

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
}

impl<'a> ResolveChain<'a> {
    pub fn new(runtime: &'a RuntimeSnapshot, local_resolver: &'a LocalResolver) -> Self {
        Self { runtime, local_resolver }
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

    async fn stage_rule(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
        resolver: &DNSResolveRuntime,
        policy: CacheWritePolicy,
    ) -> DnsAnswer {
        let answer =
            with_lookup_timeout(resolver.lookup_answer(domain, query_type), LOOKUP_TIMEOUT)
                .await
                .unwrap_or_else(|_| DnsAnswer::new(vec![], ResponseCode::ServFail));

        match policy {
            CacheWritePolicy::Write { query_filtered: true } => {
                self.runtime.cache.invalidate(domain, query_type).await;
            }
            CacheWritePolicy::Write { query_filtered: false } if answer.cacheable() => {
                self.runtime
                    .cache
                    .insert(CacheHandle::resolver_cache_entry(
                        resolver,
                        domain.raw_arc(),
                        query_type,
                        answer.clone(),
                    ))
                    .await;
            }
            _ => {}
        }
        answer
    }

    // ---- entry points ----

    /// The live query path: redirect → local classification → cache/upstream.
    pub async fn resolve(&self, domain: &ParsedDomain, query_type: RecordType) -> DnsQueryAnswer {
        // (1) Redirect (global check first)
        if let Some(answer) = self.stage_redirect(domain, query_type) {
            let response_code = answer.response_code();
            return DnsQueryAnswer::local(answer.records, answer.outcome, response_code);
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
            return DnsQueryAnswer::local(records, outcome, response_code);
        }
        self.resolve_from_cache_or_upstream(domain, query_type).await
    }

    async fn resolve_from_cache_or_upstream(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> DnsQueryAnswer {
        if let Some((mut dns, filter)) = self.runtime.cache.lookup(domain, query_type).await {
            let filtered = is_type_filtered(query_type, &filter);
            let outcome = if dns.response_code == ResponseCode::NXDomain {
                DnsOutcome::NxDomain
            } else if filtered {
                DnsOutcome::Filter
            } else {
                DnsOutcome::Hit
            };
            dns.records = if filtered { vec![] } else { filter_result(dns.records, &filter) };
            return DnsQueryAnswer { dns, outcome, authoritative: false };
        }

        let Some(resolver) = self.runtime.resolve_engine.find_match(domain) else {
            return DnsQueryAnswer {
                dns: DnsAnswer::new(vec![], ResponseCode::NoError),
                outcome: DnsOutcome::Normal,
                authoritative: false,
            };
        };
        let filter = resolver.filter_mode();
        if is_type_filtered(query_type, &filter) {
            return DnsQueryAnswer {
                dns: DnsAnswer::new(vec![], ResponseCode::NoError),
                outcome: DnsOutcome::Filter,
                authoritative: false,
            };
        }

        let mut dns = self
            .stage_rule(
                domain,
                query_type,
                resolver,
                CacheWritePolicy::Write { query_filtered: false },
            )
            .await;
        let outcome = match dns.response_code {
            ResponseCode::NoError => DnsOutcome::Normal,
            ResponseCode::NXDomain => DnsOutcome::NxDomain,
            _ => DnsOutcome::Error,
        };
        dns.records = filter_result(dns.records, &filter);
        DnsQueryAnswer { dns, outcome, authoritative: false }
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
                let answer =
                    self.stage_rule(domain, query_type, resolver, CacheWritePolicy::ReadOnly).await;
                // NXDOMAIN can carry the CNAME chain leading to the missing target.
                if answer.response_code == ResponseCode::NoError
                    || (answer.response_code == ResponseCode::NXDomain
                        && !answer.records.is_empty())
                {
                    result.records = Some(report_records(
                        answer.records,
                        query_type,
                        apply_filter.then_some(&filter),
                    ));
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
    ) -> Result<CheckChainDnsResult, DnsServiceError> {
        // (1) Redirect
        if self.stage_redirect(domain, query_type).is_some() {
            return Err(DnsServiceError::RefreshRedirected(domain.raw().to_string()));
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
                records: Some(crate::to_common_records(answer.dns.records)),
                ..Default::default()
            });
        }

        let Some(resolver) = self.runtime.resolve_engine.find_match(domain) else {
            return Err(DnsServiceError::RefreshRequiresRule(domain.raw().to_string()));
        };

        let filter = resolver.filter_mode();
        let query_filtered = is_type_filtered(query_type, &filter);
        let mut result = CheckChainDnsResult {
            rule_id: Some(resolver.get_config_id()),
            rule_filter: Some(filter.clone()),
            query_filtered,
            ..Default::default()
        };

        let answer = self
            .stage_rule(domain, query_type, resolver, CacheWritePolicy::Write { query_filtered })
            .await;
        result.records = Some(match answer.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => {
                report_records(answer.records, query_type, apply_filter.then_some(&filter))
            }
            _ if query_filtered => vec![],
            _ => return Err(DnsServiceError::RefreshFailed(domain.raw().to_string())),
        });

        self.runtime.cache.refresh_marks();

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
        if let Some((answer, filter)) = cache.lookup(domain, query_type).await {
            result.query_filtered |= is_type_filtered(query_type, &filter);
            if result.rule_filter.is_none() {
                result.rule_filter = Some(filter.clone());
            }
            result.cache_records =
                Some(report_records(answer.records, query_type, apply_filter.then_some(&filter)));
        }
    }

    async fn clear_stale_entry_and_refresh_maps(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) {
        if self.runtime.cache.invalidate_if_present(domain, query_type).await {
            self.runtime.cache.refresh_marks();
        }
    }
}

async fn with_lookup_timeout<F, T>(future: F, timeout: Duration) -> DnsResult<T>
where
    F: Future<Output = DnsResult<T>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(DnsServiceError::Timeout),
    }
}

fn report_records(
    records: Vec<Record>,
    query_type: RecordType,
    filter: Option<&FilterResult>,
) -> Vec<crate::CommonRecord> {
    let records = match filter {
        Some(filter) if is_type_filtered(query_type, filter) => return vec![],
        Some(filter) => filter_result(records, filter),
        None => records,
    };
    crate::to_common_records(records)
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
            if r.record_type() == RecordType::HTTPS
                && let RData::HTTPS(https) = r.data.clone()
            {
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
            r
        })
        .collect()
}

fn is_type_filtered(query_type: RecordType, filter: &FilterResult) -> bool {
    matches!(
        (query_type, filter),
        (RecordType::A, FilterResult::OnlyIPv6) | (RecordType::AAAA, FilterResult::OnlyIPv4)
    )
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
    fn only_complete_positive_and_negative_answers_are_cacheable() {
        for code in [
            ResponseCode::NoError,
            ResponseCode::NXDomain,
            ResponseCode::Refused,
            ResponseCode::NotImp,
            ResponseCode::ServFail,
        ] {
            let mut answer = DnsAnswer::new(vec![], code);
            assert_eq!(
                answer.cacheable(),
                matches!(code, ResponseCode::NoError | ResponseCode::NXDomain)
            );
            answer.truncated = true;
            assert!(!answer.cacheable());
        }
    }

    #[test]
    fn test_with_lookup_timeout_maps_timeout_and_passes_through_inner_result() {
        run_async_test(async {
            let timeout = with_lookup_timeout(
                async {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok::<_, DnsServiceError>(vec![1_u8])
                },
                Duration::from_millis(5),
            )
            .await;
            assert!(matches!(timeout, Err(DnsServiceError::Timeout)));

            let inner = with_lookup_timeout(
                async { Ok::<_, DnsServiceError>(vec![1_u8, 2_u8]) },
                Duration::from_millis(50),
            )
            .await;
            assert_eq!(inner.unwrap(), vec![1_u8, 2_u8]);
        });
    }
}
