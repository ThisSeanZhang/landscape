use landscape_common::flow::{DnsResultSink, FlowMarkInfo};

use crate::maps::{flow_dns, route};

/// eBPF-backed [`DnsResultSink`]: writes DNS answers into the flow-dns mark
/// maps and keeps the LAN route cache in sync.
pub struct EbpfDnsResultSink;

impl DnsResultSink for EbpfDnsResultSink {
    fn record_dns_answer(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
        flow_dns::update_flow_dns_rule(flow_id, marks);
    }

    fn refresh_dns_marks(&self, flow_id: u32, marks: Vec<FlowMarkInfo>) {
        flow_dns::refreash_flow_dns_inner_map(flow_id, marks);
    }

    fn rebuild_route_cache(&self) {
        route::cache::recreate_route_lan_cache_inner_map();
    }
}
