use std::sync::Arc;

use hickory_resolver::{
    config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts},
    Resolver,
};

use landscape_common::{
    dns::{config::DnsBindConfig, upstream::DnsUpstreamMode, RuntimeUpstreamTarget},
    flow::mark::FlowMark,
};

use crate::connection::provider::{MarkConnectionProvider, MarkRuntimeProvider};

pub(crate) mod provider;

pub(crate) type LandscapeMarkDNSResolver = Resolver<MarkConnectionProvider>;

pub(crate) fn create_resolver(
    flow_id: u32,
    mark: FlowMark,
    bind_config: DnsBindConfig,
    RuntimeUpstreamTarget { mode, ips, port, .. }: RuntimeUpstreamTarget,
) -> LandscapeMarkDNSResolver {
    let name_server: Vec<NameServerConfig> = match mode {
        DnsUpstreamMode::Plaintext => ips
            .iter()
            .map(|ip| {
                let mut conn = ConnectionConfig::new(ProtocolConfig::Udp);
                conn.port = port.unwrap_or(53);
                NameServerConfig::new(*ip, true, vec![conn])
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

    let mark_value = mark.get_dns_mark(flow_id);

    let mut options = ResolverOpts::default();
    options.cache_size = 0;
    options.num_concurrent_reqs = 4;
    options.preserve_intermediates = true;
    // options.use_hosts_file = ResolveHosts::Never;
    let resolver =
        Resolver::builder_with_config(resolve, MarkRuntimeProvider::new(mark_value, bind_config))
            .with_options(options)
            .build()
            .expect("Failed to build DNS resolver");

    resolver
}
