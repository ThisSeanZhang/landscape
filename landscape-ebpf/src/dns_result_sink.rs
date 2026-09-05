use std::sync::Arc;

use landscape_common::flow::{DnsResultSink, FlowMarkInfo};

use crate::maps::{flow_dns, route, LandscapeMapPath};

/// eBPF-backed [`DnsResultSink`]: writes DNS answers into the flow-dns mark
/// maps and keeps the LAN route cache in sync.
pub struct EbpfDnsResultSink {
    paths: Arc<LandscapeMapPath>,
}

impl EbpfDnsResultSink {
    pub fn new(paths: Arc<LandscapeMapPath>) -> Self {
        Self { paths }
    }
}

impl DnsResultSink for EbpfDnsResultSink {
    fn record_dns_answer(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
        flow_dns::update_flow_dns_rule(&self.paths, flow_id, marks);
    }

    fn refresh_dns_marks(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
        flow_dns::refreash_flow_dns_inner_map(&self.paths, flow_id, marks);
    }

    fn rebuild_route_cache(&self) {
        route::cache::recreate_route_lan_cache_inner_map(&self.paths);
    }
}
