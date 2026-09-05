use std::net::Ipv4Addr;

use landscape_common::flow::{mark::FlowMark, FlowMarkInfo};

// cargo run --package landscape-ebpf --bin map_inmap_insert_test
pub fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let paths =
        landscape_ebpf::runtime::init_map_paths("map_inmap_insert_test").expect("init map paths");
    let paths = paths.as_ref();

    landscape_ebpf::maps::flow_dns::refreash_flow_dns_inner_map(paths, 12, vec![]);
    landscape_ebpf::maps::flow_dns::update_flow_dns_rule(
        paths,
        12,
        vec![FlowMarkInfo {
            mark: FlowMark::default().into(),
            ip: std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
            priority: 0,
        }],
    );

    landscape_ebpf::maps::flow_dns::update_flow_dns_rule(
        paths,
        12,
        vec![FlowMarkInfo {
            mark: FlowMark::default().into(),
            ip: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            priority: 1,
        }],
    );

    // landscape_ebpf::maps::flow_wanip::add_wan_ip_mark(&paths, 1, vec![]);
}
