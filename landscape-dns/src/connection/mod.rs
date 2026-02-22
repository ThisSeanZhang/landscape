use std::net::SocketAddr;

use hickory_proto::xfer::Protocol;
use hickory_resolver::{
    config::{NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts},
    Resolver,
};

use landscape_common::{
    dns::{
        config::{DnsBindConfig, DnsUpstreamConfig},
        upstream::DnsUpstreamMode,
    },
    flow::mark::FlowMark,
};

use crate::connection::provider::{MarkConnectionProvider, MarkRuntimeProvider};

pub(crate) mod provider;

pub(crate) type LandscapeMarkDNSResolver = Resolver<MarkConnectionProvider>;

pub(crate) fn create_resolver(
    flow_id: u32,
    mark: FlowMark,
    bind_config: DnsBindConfig,
    DnsUpstreamConfig { mode, ips, port, .. }: DnsUpstreamConfig,
) -> LandscapeMarkDNSResolver {
    let name_server = match mode {
        DnsUpstreamMode::Plaintext => {
            NameServerConfigGroup::from_ips_clear(&ips, port.unwrap_or(53), true)
        }
        DnsUpstreamMode::Tls { domain } => {
            NameServerConfigGroup::from_ips_tls(&ips, port.unwrap_or(853), domain.to_string(), true)
        }
        DnsUpstreamMode::Https { domain, http_endpoint } => {
            let mut group = NameServerConfigGroup::with_capacity(ips.len());
            let port = port.unwrap_or(443);
            for ip in ips {
                let config = NameServerConfig {
                    socket_addr: SocketAddr::new(ip, port),
                    protocol: Protocol::Https,
                    tls_dns_name: Some(domain.clone()),
                    http_endpoint: http_endpoint.clone(),
                    trust_negative_responses: true,
                    bind_addr: None,
                };
                group.push(config);
            }
            group
        }
        DnsUpstreamMode::Quic { domain } => NameServerConfigGroup::from_ips_quic(
            &ips,
            port.unwrap_or(853),
            domain.to_string(),
            true,
        ),
    };

    let resolve = ResolverConfig::from_parts(None, vec![], name_server);

    let mark_value = mark.get_dns_mark(flow_id);

    let mut options = ResolverOpts::default();
    options.cache_size = 0;
    options.num_concurrent_reqs = 4;
    options.preserve_intermediates = true;
    // options.use_hosts_file = ResolveHosts::Never;
    let resolver = Resolver::builder_with_config(
        resolve,
        MarkConnectionProvider::new(MarkRuntimeProvider::new(mark_value, bind_config)),
    )
    .with_options(options)
    .build();

    resolver
}
