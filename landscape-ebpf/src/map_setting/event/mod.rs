use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use landscape_common::metric::connect::{ConnectKey, ConnectMetric, ConnectStatusType};

use crate::{
    map_setting::share_map::types::{nat_conn_metric_event, u_inet_addr},
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE,
};

unsafe impl plain::Plain for u_inet_addr {}
unsafe impl plain::Plain for nat_conn_metric_event {}

pub mod nat;

impl From<&nat_conn_metric_event> for ConnectMetric {
    fn from(ev: &nat_conn_metric_event) -> Self {
        let key = ConnectKey { create_time: ev.create_time, cpu_id: ev.cpu_id };

        ConnectMetric {
            key,
            src_ip: convert_ip(&ev.src_addr, ev.l3_proto),
            dst_ip: convert_ip(&ev.dst_addr, ev.l3_proto),
            src_port: ev.src_port.to_be(),
            dst_port: ev.dst_port.to_be(),
            l4_proto: ev.l4_proto,
            l3_proto: ev.l3_proto,
            flow_id: ev.flow_id,
            trace_id: ev.trace_id,
            report_time: ev.time,
            ingress_bytes: ev.ingress_bytes,
            ingress_packets: ev.ingress_packets,
            egress_bytes: ev.egress_bytes,
            egress_packets: ev.egress_packets,
            status: ConnectStatusType::from(ev.status),
        }
    }
}

pub(crate) fn convert_ip(raw: &u_inet_addr, proto: u8) -> IpAddr {
    match proto {
        LANDSCAPE_IPV4_TYPE => {
            let ip = unsafe { raw.ip.clone().to_be() };
            IpAddr::V4(Ipv4Addr::from_bits(ip))
        }
        LANDSCAPE_IPV6_TYPE => {
            let bits = unsafe { raw.bits };
            IpAddr::V6(Ipv6Addr::from(bits))
        }
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED), // fallback
    }
}
