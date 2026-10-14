use std::fmt;

#[cfg(feature = "pool-native")]
use std::sync::Arc;

use hickory_proto::rr::RecordType;
use hickory_resolver::{Resolver, lookup::Lookup, net::NetError};

use landscape_common::dns::config::DnsUpstreamConfig;

use legacy::provider::MarkConnectionProvider;

pub(crate) mod legacy;
pub(crate) mod pool;
pub(crate) mod socket;

#[cfg(feature = "pool-native")]
pub(crate) mod native;

#[cfg(feature = "pool-exp")]
pub(crate) mod exp_pool;

#[cfg(all(test, feature = "pool-native"))]
mod integration_tests;
#[cfg(all(test, feature = "pool-native"))]
pub(crate) mod test_util;

#[cfg(feature = "pool-native")]
use hickory_proto::{op::Query, rr::Name};
#[cfg(feature = "pool-native")]
use hickory_resolver::net::{DnsError, NoRecords};
#[cfg(feature = "pool-native")]
use std::time::{Duration, Instant};

/// Upstream engine handle. `use_experimental_pool` picks the variant at
/// runtime; which experimental implementation backs the toggle is chosen at
/// compile time by the `pool-exp` / `pool-native` features. All variants
/// expose the same lookup surface.
// The hickory `Resolver` is far larger than the Arc-based variants, but the
// enum only ever lives behind an `Arc` (see `ResolvePool`), so the size
// difference never turns into copies.
#[allow(clippy::large_enum_variant)]
pub(crate) enum LandscapeResolver {
    /// hickory's built-in name server pool.
    Legacy(Resolver<MarkConnectionProvider>),
    /// Experimental self-managed engine, see `exp_pool`.
    #[cfg(feature = "pool-exp")]
    Pooled(exp_pool::PooledDnsResolver),
    /// Native upstream pool, see `native`.
    #[cfg(feature = "pool-native")]
    Native(Arc<native::UpstreamPool>),
}

impl LandscapeResolver {
    pub(crate) async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Lookup, NetError> {
        match self {
            Self::Legacy(resolver) => resolver.lookup(domain, query_type).await,
            #[cfg(feature = "pool-exp")]
            Self::Pooled(resolver) => resolver.lookup(domain, query_type).await,
            #[cfg(feature = "pool-native")]
            Self::Native(pool) => {
                let name = Name::parse(domain, None).map_err(NetError::from)?;
                let query = Query::query(name, query_type);
                match pool.lookup(domain, query_type).await {
                    Ok(answer) => {
                        // A truncated answer is served as-is (matching the
                        // legacy/exp behaviour); the TC-bit passthrough to
                        // the client rides on the RFC 2308 semantics port.
                        if answer.truncated {
                            tracing::debug!(
                                "upstream answer for {domain} was truncated; serving \
                                 partial records"
                            );
                        }
                        let min_ttl =
                            answer.records.iter().map(|record| record.ttl).min().unwrap_or(300);
                        let valid_until = Instant::now() + Duration::from_secs(u64::from(min_ttl));
                        Ok(Lookup::new_with_deadline(query, answer.records, valid_until))
                    }
                    Err(err) => Err(map_native_error(query, err)),
                }
            }
        }
    }
}

/// Maps the native pool's error surface onto the hickory `NetError` shape
/// `rule.rs` already understands. The RFC 2308 SOA riding on `Protocol` is
/// dropped here for now; surfacing it end-to-end is follow-up work.
#[cfg(feature = "pool-native")]
fn map_native_error(query: Query, err: native::UpstreamError) -> NetError {
    match err {
        native::UpstreamError::Timeout | native::UpstreamError::Offline => NetError::Timeout,
        native::UpstreamError::Protocol(code, _soa) => {
            NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(Box::new(query), code)))
        }
        native::UpstreamError::NoConnections => NetError::from("no usable upstream connections"),
        native::UpstreamError::Tls(e) => NetError::from(format!("upstream TLS failure: {e}")),
        native::UpstreamError::Internal(e) => {
            NetError::from(format!("upstream internal error: {e}"))
        }
    }
}

impl fmt::Debug for LandscapeResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(resolver) => fmt::Debug::fmt(resolver, f),
            #[cfg(feature = "pool-exp")]
            Self::Pooled(resolver) => fmt::Debug::fmt(resolver, f),
            #[cfg(feature = "pool-native")]
            Self::Native(resolver) => fmt::Debug::fmt(resolver, f),
        }
    }
}

pub(crate) fn create_resolver(
    flow_id: u32,
    mark_value: u32,
    config: DnsUpstreamConfig,
) -> Option<LandscapeResolver> {
    // Opt-in gate: only explicitly opted-in upstreams use the self-managed pool.
    if config.use_experimental_pool.unwrap_or(false) {
        #[cfg(feature = "pool-native")]
        {
            let provider =
                native::mark::MarkRuntimeProvider::new(mark_value, config.bind_config.clone());
            return native::UpstreamPool::new(
                flow_id,
                mark_value,
                &config,
                provider,
                &native::pool_config::PoolSettings::default(),
                None,
            )
            .map(LandscapeResolver::Native);
        }
        #[cfg(feature = "pool-exp")]
        {
            return match exp_pool::PooledDnsResolver::new(flow_id, mark_value, &config) {
                Ok(resolver) => Some(LandscapeResolver::Pooled(resolver)),
                Err(e) => {
                    tracing::error!(
                        "[flow: {flow_id}]: failed to build experimental DNS resolver: {e}"
                    );
                    None
                }
            };
        }
        #[cfg(not(any(feature = "pool-exp", feature = "pool-native")))]
        {
            tracing::warn!(
                "[flow: {flow_id}]: use_experimental_pool is set but neither pool-exp nor \
                 pool-native is compiled in; falling back to the legacy resolver"
            );
        }
    }

    legacy::create_legacy_resolver(flow_id, mark_value, config)
}
