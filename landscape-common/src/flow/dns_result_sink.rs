use crate::flow::FlowMarkInfo;

/// Side effects applied to DNS resolution results.
///
/// The DNS layer resolves a query, produces a set of (ip, mark) pairs and hands
/// them here. The concrete implementation decides how (and whether) to make
/// them take effect in the datapath: today that's eBPF maps and route caches,
/// any other backend (userspace routing, DPDK, TC, ...) can plug in later.
pub trait DnsResultSink: Send + Sync {
    /// Write (ip, mark) pairs for a freshly cached answer.
    fn record_dns_answer(&self, flow_id: u32, marks: Vec<FlowMarkInfo>);

    /// Recompute the DNS mark table for a flow from its whole cache.
    fn refresh_dns_marks(&self, flow_id: u32, marks: Vec<FlowMarkInfo>);

    /// Rebuild the LAN route cache.
    fn rebuild_route_cache(&self);
}

/// No-op sink used by tests and non-Linux builds.
pub struct NoopDnsResultSink;

impl DnsResultSink for NoopDnsResultSink {
    fn record_dns_answer(&self, _flow_id: u32, _marks: Vec<FlowMarkInfo>) {}

    fn refresh_dns_marks(&self, _flow_id: u32, _marks: Vec<FlowMarkInfo>) {}

    fn rebuild_route_cache(&self) {}
}
