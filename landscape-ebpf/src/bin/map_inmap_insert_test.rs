use std::net::Ipv4Addr;

use landscape_common::flow::{mark::FlowDnsMark, FlowDnsMarkInfo};

// cargo run --package landscape-ebpf --bin map_inmap_insert_test
pub fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    landscape_ebpf::map_setting::flow_dns::create_flow_dns_inner_map(11, vec![]);
    landscape_ebpf::map_setting::flow_dns::update_flow_dns_rule(
        11,
        vec![FlowDnsMarkInfo {
            mark: FlowDnsMark::KeepGoing.into(),
            ip: std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
        }],
    );

    landscape_ebpf::map_setting::flow_dns::update_flow_dns_rule(
        11,
        vec![FlowDnsMarkInfo {
            mark: FlowDnsMark::KeepGoing.into(),
            ip: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        }],
    );

    // landscape_ebpf::map_setting::flow_wanip::add_wan_ip_mark(1, vec![]);
}
