use landscape_common::flow::FlowDnsMarkInfo;
use libbpf_rs::{MapCore, MapFlags};

use crate::MAP_PATHS;

use super::share_map::types::{flow_dns_match_key, u_inet_addr};

pub fn update_flow_dns_mark_rules(flow_id: u32, marks: Vec<FlowDnsMarkInfo>) {
    let flow_verdict_dns_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

    if let Err(e) = update_flow_dns_mark_rules_inner(&flow_verdict_dns_map, flow_id, marks) {
        tracing::error!("update_flow_dns_mark_rules: {e:?}");
    }
}

fn update_flow_dns_mark_rules_inner<'obj, T>(
    map: &T,
    flow_id: u32,
    data: Vec<FlowDnsMarkInfo>,
) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if data.is_empty() {
        return Ok(());
    }
    let mut keys = vec![];
    let mut values = vec![];

    let counts = data.len() as u32;
    for FlowDnsMarkInfo { ip, mark } in data.into_iter() {
        let addr = match ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                let mut ip = u_inet_addr::default();
                ip.ip = ipv4_addr.to_bits().to_be();
                ip
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() }
            }
        };

        let key = flow_dns_match_key { flow_id, addr };
        let mark: u32 = mark.into();
        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&mark) });
    }

    map.update_batch(&keys, &values, counts, MapFlags::ANY, MapFlags::ANY)
}

pub fn del_flow_dns_mark_rules(flow_id: u32, marks: Vec<FlowDnsMarkInfo>) {
    let flow_verdict_dns_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.flow_verdict_dns_map).unwrap();

    if let Err(e) = del_flow_dns_mark_rules_inner(&flow_verdict_dns_map, flow_id, marks) {
        tracing::error!("del_flow_dns_mark_rules: {e:?}");
    }
}

fn del_flow_dns_mark_rules_inner<'obj, T>(
    map: &T,
    flow_id: u32,
    data: Vec<FlowDnsMarkInfo>,
) -> libbpf_rs::Result<()>
where
    T: MapCore,
{
    if data.is_empty() {
        return Ok(());
    }
    let mut keys = vec![];

    let counts = data.len() as u32;
    for FlowDnsMarkInfo { ip, .. } in data.into_iter() {
        let addr = match ip {
            std::net::IpAddr::V4(ipv4_addr) => {
                let mut ip = u_inet_addr::default();
                ip.ip = ipv4_addr.to_bits().to_be();
                ip
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                u_inet_addr { bits: ipv6_addr.to_bits().to_be_bytes() }
            }
        };

        let key = flow_dns_match_key { flow_id, addr };
        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
    }

    map.delete_batch(&keys, counts, MapFlags::ANY, MapFlags::ANY)
}
