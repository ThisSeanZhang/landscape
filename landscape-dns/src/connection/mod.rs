use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::RecordType;
use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts},
    lookup::Lookup,
    net::NetError,
};

use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

use crate::connection::provider::{HickoryMarkProvider, MarkConnectionProvider};

pub(crate) mod pool;
pub(crate) mod provider;
#[cfg(feature = "pool-native")]
pub(crate) mod upstream;

#[cfg(all(test, feature = "pool-native"))]
mod integration_tests;
#[cfg(all(test, feature = "pool-native"))]
pub(crate) mod test_util;

#[cfg(feature = "pool-native")]
use hickory_proto::{op::Query, rr::Name};
#[cfg(feature = "pool-native")]
use hickory_resolver::net::{DnsError, NoRecords};
#[cfg(feature = "pool-native")]
use std::time::Instant;

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
    /// Experimental self-managed engine, see `exp_conn_pool`.
    #[cfg(feature = "pool-exp")]
    Pooled(crate::exp_conn_pool::PooledDnsResolver),
    /// Native upstream pool, see `connection::upstream`.
    #[cfg(feature = "pool-native")]
    Native(Arc<upstream::UpstreamPool>),
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
fn map_native_error(query: Query, err: upstream::UpstreamError) -> NetError {
    match err {
        upstream::UpstreamError::Timeout | upstream::UpstreamError::Offline => NetError::Timeout,
        upstream::UpstreamError::Protocol(code, _soa) => {
            NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(Box::new(query), code)))
        }
        upstream::UpstreamError::NoConnections => NetError::from("no usable upstream connections"),
        upstream::UpstreamError::Tls(e) => NetError::from(format!("upstream TLS failure: {e}")),
        upstream::UpstreamError::Internal(e) => {
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
            let provider = crate::connection::provider::MarkRuntimeProvider::new(
                mark_value,
                config.bind_config.clone(),
            );
            return upstream::UpstreamPool::new(
                flow_id,
                mark_value,
                &config,
                provider,
                &upstream::pool_config::PoolSettings::default(),
                None,
            )
            .map(LandscapeResolver::Native);
        }
        #[cfg(feature = "pool-exp")]
        {
            return match crate::exp_conn_pool::PooledDnsResolver::new(flow_id, mark_value, &config)
            {
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

    let DnsUpstreamConfig { mode, ips, port, bind_config, .. } = config;
    let name_server: Vec<NameServerConfig> = match mode {
        DnsUpstreamMode::Plaintext => ips
            .iter()
            .map(|ip| {
                let port = port.unwrap_or(53);
                let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
                udp.port = port;
                let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
                tcp.port = port;
                NameServerConfig::new(*ip, true, vec![udp, tcp])
            })
            .collect(),
        DnsUpstreamMode::Tls { domain } => ips
            .iter()
            .map(|ip| {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Tls {
                    server_name: domain.clone().into(),
                });
                conn.port = port.unwrap_or(853);
                NameServerConfig::new(*ip, true, vec![conn])
            })
            .collect(),
        DnsUpstreamMode::Https { domain, http_endpoint } => ips
            .iter()
            .map(|ip| {
                let path: Arc<str> = http_endpoint
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.clone().into())
                    .unwrap_or_else(|| Arc::from("/dns-query"));
                let mut conn = ConnectionConfig::new(ProtocolConfig::Https {
                    server_name: domain.clone().into(),
                    path,
                });
                conn.port = port.unwrap_or(443);
                NameServerConfig::new(*ip, true, vec![conn])
            })
            .collect(),
        DnsUpstreamMode::Quic { domain } => ips
            .iter()
            .map(|ip| {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Quic {
                    server_name: domain.clone().into(),
                });
                conn.port = port.unwrap_or(853);
                NameServerConfig::new(*ip, true, vec![conn])
            })
            .collect(),
    };

    let resolve = ResolverConfig::from_parts(None, vec![], name_server);

    let mut options = ResolverOpts::default();
    options.cache_size = 0;
    options.num_concurrent_reqs = 4;
    options.preserve_intermediates = true;
    // options.use_hosts_file = ResolveHosts::Never;
    // Keep each attempt short (1s) so the resolver's built-in retry
    // (attempts = 3) can recover from transient first-packet loss well within
    // the 5s outer lookup timeout; with the 5s default the second attempt
    // never gets to run and the client sees a 5s ServFail on the first query.
    // Normal lookups complete in milliseconds and never hit this timeout.
    options.timeout = Duration::from_secs(1);
    options.attempts = 3;
    let resolver = match Resolver::builder_with_config(
        resolve,
        HickoryMarkProvider::new(mark_value, bind_config),
    )
    .with_options(options)
    .build()
    {
        Ok(resolver) => resolver,
        Err(e) => {
            tracing::error!("[flow: {flow_id}]: failed to build DNS resolver: {e}");
            return None;
        }
    };

    Some(LandscapeResolver::Legacy(resolver))
}
