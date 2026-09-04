use std::net::Ipv4Addr;

use landscape_common::flow::{mark::FlowMark, FlowMarkInfo};

// cargo run --package landscape-ebpf --bin map_inmap_insert_test
pub fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    landscape_ebpf::maps::flow_dns::refreash_flow_dns_inner_map(12, vec![]);
    landscape_ebpf::maps::flow_dns::update_flow_dns_rule(
        12,
        vec![FlowMarkInfo {
            mark: FlowMark::default().into(),
            ip: std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
            priority: 0,
        }],
    );

    landscape_ebpf::maps::flow_dns::update_flow_dns_rule(
        12,
        vec![FlowMarkInfo {
            mark: FlowMark::default().into(),
            ip: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            priority: 1,
        }],
    );

    // landscape_ebpf::maps::flow_wanip::add_wan_ip_mark(1, vec![]);
}
