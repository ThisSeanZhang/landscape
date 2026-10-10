mod allowance;
mod connection;
mod pool;
mod scheduler;
mod transport;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{DnsRequest, DnsRequestOptions, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::config::{ConnectionConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::{PoolContext, TlsConfig};
use landscape_common::dns::bind::DnsBindConfig;
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::dns::pool_config::UpstreamPoolConfig;
use landscape_common::dns::upstream::DnsUpstreamMode;

use crate::exp_conn_pool::connection::EndpointKey;
use crate::exp_conn_pool::pool::StreamConnectionPool;
use crate::exp_conn_pool::scheduler::Scheduler;
use crate::exp_conn_pool::transport::DialParams;

pub(crate) struct PooledDnsResolver {
    flow_id: u32,
    scheduler: Scheduler,
    config: UpstreamPoolConfig,
}

impl PooledDnsResolver {
    pub(crate) fn new(
        flow_id: u32,
        mark_value: u32,
        config: &DnsUpstreamConfig,
    ) -> Result<Self, NetError> {
        Self::with_config(flow_id, mark_value, config, UpstreamPoolConfig::default())
    }

    fn endpoint_configs(
        config: &DnsUpstreamConfig,
    ) -> Result<(HashMap<EndpointKey, ConnectionConfig>, Vec<EndpointKey>), NetError> {
        let DnsUpstreamConfig { mode, ips, port, .. } = config;

        let connection_configs: Vec<ConnectionConfig> = match mode {
            DnsUpstreamMode::Plaintext => {
                let port = port.unwrap_or(53);
                let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
                udp.port = port;
                let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
                tcp.port = port;
                vec![udp, tcp]
            }
            DnsUpstreamMode::Tls { domain } => {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Tls {
                    server_name: domain.clone().into(),
                });
                conn.port = port.unwrap_or(853);
                vec![conn]
            }
            DnsUpstreamMode::Https { .. } => {
                return Err(NetError::from(
                    "HTTPS upstreams are not supported by the pooled engine",
                ));
            }
            DnsUpstreamMode::Quic { domain } => {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Quic {
                    server_name: domain.clone().into(),
                });
                conn.port = port.unwrap_or(853);
                vec![conn]
            }
        };

        let mut pool_configs = HashMap::new();
        let mut endpoint_keys = Vec::new();
        for ip in ips {
            for conn in &connection_configs {
                let key = EndpointKey {
                    addr: SocketAddr::new(*ip, conn.port),
                    protocol: conn.protocol.to_protocol(),
                };
                pool_configs.insert(key, conn.clone());
                endpoint_keys.push(key);
            }
        }
        Ok((pool_configs, endpoint_keys))
    }

    pub(crate) fn with_config(
        flow_id: u32,
        mark_value: u32,
        config: &DnsUpstreamConfig,
        pool_config: UpstreamPoolConfig,
    ) -> Result<Self, NetError> {
        let DnsUpstreamConfig { bind_config, .. } = config;
        let (pool_configs, endpoint_keys) = Self::endpoint_configs(config)?;

        let mut options = ResolverOpts::default();
        options.cache_size = 0;
        options.num_concurrent_reqs = pool_config.concurrency;
        options.preserve_intermediates = true;
        options.timeout = pool_config.round_timeout;
        options.attempts = pool_config.attempts as usize;
        options.max_active_requests = pool_config.max_inflight_per_conn;
        let cx = Arc::new(PoolContext::new(options, TlsConfig::new()?));
        Self::assemble(
            flow_id,
            mark_value,
            bind_config,
            pool_configs,
            endpoint_keys,
            pool_config,
            cx,
        )
    }

    // The caller-supplied TLS config lets tests trust an ad-hoc self-signed
    // certificate instead of the platform verifier.
    #[cfg(test)]
    pub(crate) fn with_config_and_tls(
        flow_id: u32,
        mark_value: u32,
        config: &DnsUpstreamConfig,
        pool_config: UpstreamPoolConfig,
        tls: TlsConfig,
    ) -> Result<Self, NetError> {
        let DnsUpstreamConfig { bind_config, .. } = config;
        let (pool_configs, endpoint_keys) = Self::endpoint_configs(config)?;

        let mut options = ResolverOpts::default();
        options.cache_size = 0;
        options.num_concurrent_reqs = pool_config.concurrency;
        options.preserve_intermediates = true;
        options.timeout = pool_config.round_timeout;
        options.attempts = pool_config.attempts as usize;
        options.max_active_requests = pool_config.max_inflight_per_conn;
        let cx = Arc::new(PoolContext::new(options, tls));
        Self::assemble(
            flow_id,
            mark_value,
            bind_config,
            pool_configs,
            endpoint_keys,
            pool_config,
            cx,
        )
    }

    fn assemble(
        flow_id: u32,
        mark_value: u32,
        bind_config: &DnsBindConfig,
        pool_configs: HashMap<EndpointKey, ConnectionConfig>,
        endpoint_keys: Vec<EndpointKey>,
        pool_config: UpstreamPoolConfig,
        cx: Arc<PoolContext>,
    ) -> Result<Self, NetError> {
        let dial = DialParams {
            mark_value,
            bind_addr4: bind_config.bind_addr4,
            bind_addr6: bind_config.bind_addr6,
        };
        let pool = Arc::new(StreamConnectionPool::new(dial, cx, pool_configs, pool_config));
        let endpoint_count = endpoint_keys.len();
        let scheduler = Scheduler::new(pool, endpoint_keys, pool_config);

        tracing::debug!(
            flow_id,
            mark_value,
            endpoints = endpoint_count,
            "experimental pooled DNS resolver created"
        );

        Ok(Self { flow_id, scheduler, config: pool_config })
    }

    pub(crate) async fn lookup(
        &self,
        domain: &str,
        query_type: RecordType,
    ) -> Result<Lookup, NetError> {
        let name = Name::parse(domain, None).map_err(NetError::from)?;
        self.lookup_name(name, query_type).await
    }

    async fn lookup_name(&self, name: Name, query_type: RecordType) -> Result<Lookup, NetError> {
        let original = Query::query(name.clone(), query_type);
        let mut query = original.clone();
        let mut records: Vec<Record> = Vec::new();

        for depth in 0..=self.config.max_cname_depth {
            let request = DnsRequest::from_query(query.clone(), DnsRequestOptions::default());
            let response = match self.scheduler.resolve(request).await {
                Ok(response) => response,
                Err(e) if depth > 0 && is_nodata(&e) => break,
                Err(e) => return Err(e),
            };

            let answers = &response.answers;
            let search_name = query.name().clone();
            let direct_answer = answers
                .iter()
                .any(|record| record.record_type() == query_type && record.name == search_name);
            let cname_target = answers.iter().find_map(|record| match &record.data {
                RData::CNAME(cname) if record.name == search_name => Some(cname.0.clone()),
                _ => None,
            });

            records.extend(answers.iter().cloned());

            if direct_answer || cname_target.is_none() || depth == self.config.max_cname_depth {
                break;
            }
            query = Query::query(cname_target.unwrap(), query_type);
        }

        let valid_until = Instant::now()
            + Duration::from_secs(u64::from(
                records.iter().map(|record| record.ttl).min().unwrap_or(300),
            ));
        Ok(Lookup::new_with_deadline(original, records, valid_until))
    }
}

fn is_nodata(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Dns(DnsError::NoRecordsFound(no_records))
            if no_records.response_code == hickory_proto::op::ResponseCode::NoError
    )
}

#[cfg(test)]
impl PooledDnsResolver {
    pub(crate) fn live_tcp_connection_count(&self) -> usize {
        self.scheduler
            .live_connection_counts()
            .into_iter()
            .filter(|(endpoint, _)| !endpoint.protocol.is_datagram())
            .map(|(_, count)| count)
            .sum()
    }

    pub(crate) fn srtt_snapshot(&self) -> Vec<crate::exp_conn_pool::scheduler::SrttSample> {
        self.scheduler.srtt_snapshot()
    }

    pub(crate) fn sweep_idle(&self) {
        self.scheduler.sweep_idle();
    }
}

impl std::fmt::Debug for PooledDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledDnsResolver")
            .field("flow_id", &self.flow_id)
            .field("connections", &self.scheduler.live_connection_counts())
            .finish()
    }
}

#[cfg(test)]
mod tests;
