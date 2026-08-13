use std::sync::Arc;

use landscape_common::flow::FlowMarkInfo;

/// eBPF map side effects of the DNS resolution chain: the flow-dns mark map
/// and the LAN route cache. Abstracted so tests can inject a no-op.
pub(crate) trait DnsMarkMap: Send + Sync {
    /// Writes (mark, ip) pairs for a freshly cached answer.
    fn update_flow_dns_rule(&self, flow_id: u32, marks: Vec<FlowMarkInfo>);

    /// Recomputes the flow-dns map from the whole cache.
    fn refresh_flow_dns(&self, flow_id: u32, marks: Vec<FlowMarkInfo>);

    /// Rebuilds the LAN route cache.
    fn recreate_route_cache(&self);
}

/// Real writer backed by the landscape_ebpf maps.
#[cfg(not(test))]
pub(crate) struct EbpfDnsMarkMap;

#[cfg(not(test))]
impl DnsMarkMap for EbpfDnsMarkMap {
    fn update_flow_dns_rule(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
        landscape_ebpf::map_setting::flow_dns::update_flow_dns_rule(flow_id, marks);
    }

    fn refresh_flow_dns(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
        landscape_ebpf::map_setting::flow_dns::refreash_flow_dns_inner_map(flow_id, marks);
    }

    fn recreate_route_cache(&self) {
        landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }
}

/// No-op writer used by tests.
#[cfg(test)]
pub(crate) struct NoopDnsMarkMap;

#[cfg(test)]
impl DnsMarkMap for NoopDnsMarkMap {
    fn update_flow_dns_rule(&self, _flow_id: u32, _marks: Vec<FlowMarkInfo>) {}

    fn refresh_flow_dns(&self, _flow_id: u32, _marks: Vec<FlowMarkInfo>) {}

    fn recreate_route_cache(&self) {}
}

pub(crate) fn default_dns_mark_map() -> Arc<dyn DnsMarkMap> {
    #[cfg(test)]
    return Arc::new(NoopDnsMarkMap);
    #[cfg(not(test))]
    Arc::new(EbpfDnsMarkMap)
}
