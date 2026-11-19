use std::fmt;

#[cfg(feature = "pool-native")]
use std::sync::Arc;

use crate::resolve::answer::DnsAnswer;
use hickory_proto::{op::Message, rr::RecordType};
use hickory_resolver::{
    Resolver,
    net::{DnsError, NetError},
};

use landscape_common::dns::config::DnsUpstreamConfig;

use crate::domain::ParsedDomain;
use legacy::provider::MarkConnectionProvider;

pub(crate) mod legacy;
pub(crate) mod pool;
pub(crate) mod socket;

#[cfg(feature = "pool-native")]
pub(crate) mod native;

#[cfg(all(test, feature = "pool-native"))]
mod integration_tests;
#[cfg(all(test, feature = "pool-native"))]
pub(crate) mod test_util;

/// Upstreams opt into the native pool with `use_experimental_pool` when
/// the binary includes `pool-native`. Otherwise they use Hickory.
// The hickory `Resolver` is far larger than the native pool handle, but the
// enum only ever lives behind an `Arc` (see `ResolvePool`), so the size
// difference never turns into copies.
#[allow(clippy::large_enum_variant)]
pub(crate) enum LandscapeResolver {
    /// hickory's built-in name server pool.
    Legacy(Resolver<MarkConnectionProvider>),
    /// Native upstream pool, see `native`.
    #[cfg(feature = "pool-native")]
    Native(Arc<native::UpstreamPool>),
}

impl LandscapeResolver {
    pub(crate) async fn lookup(
        &self,
        domain: &ParsedDomain,
        query_type: RecordType,
    ) -> Result<DnsAnswer, NetError> {
        // Reuse the wire name so valid DNS labels containing underscores survive IDNA parsing.
        let name = domain.as_dns_name().clone();
        match self {
            Self::Legacy(resolver) => match resolver.lookup(name, query_type).await {
                Ok(lookup) => Ok(DnsAnswer::from_message(Message::from(lookup))),
                Err(NetError::Dns(DnsError::NoRecordsFound(negative))) => {
                    let soa = negative.soa.map(|r| Box::new(r.into_record_of_rdata()));
                    Ok(DnsAnswer::negative(negative.response_code, soa))
                }
                Err(NetError::Dns(DnsError::ResponseCode(code))) => {
                    Ok(DnsAnswer::new(vec![], code))
                }
                Err(err) => Err(err),
            },
            #[cfg(feature = "pool-native")]
            Self::Native(pool) => match pool.lookup_name(name, query_type).await {
                Ok(answer) => Ok(answer),
                Err(native::UpstreamError::Protocol(code, soa)) => {
                    Ok(DnsAnswer::negative(code, soa))
                }
                Err(native::UpstreamError::Timeout | native::UpstreamError::Offline) => {
                    Err(NetError::Timeout)
                }
                Err(err) => Err(NetError::from(err.to_string())),
            },
        }
    }
}

impl fmt::Debug for LandscapeResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(resolver) => fmt::Debug::fmt(resolver, f),
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
        #[cfg(not(feature = "pool-native"))]
        {
            tracing::warn!(
                "[flow: {flow_id}]: use_experimental_pool is set but pool-native is not compiled in; falling back to the legacy resolver"
            );
        }
    }

    legacy::create_legacy_resolver(flow_id, mark_value, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upstream_pool_opt_in_selects_the_compiled_backend() {
        for opt_in in [None, Some(false), Some(true)] {
            let config = DnsUpstreamConfig {
                use_experimental_pool: opt_in,
                ..Default::default()
            };
            let resolver = create_resolver(7, 0x8007, config).unwrap();
            let expect_native = opt_in == Some(true) && cfg!(feature = "pool-native");
            assert_eq!(matches!(resolver, LandscapeResolver::Legacy(_)), !expect_native);
        }
    }
}
