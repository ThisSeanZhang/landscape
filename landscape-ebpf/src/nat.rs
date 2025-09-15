use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use land_nat::{
    types::{nat_conn_event, u_inet_addr},
    *,
};
use landscape_common::{
    config::nat::NatConfig,
    event::nat::{NatEvent, NatEventType},
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};
use tokio::sync::oneshot;

use crate::{
    landscape::TcHookProxy, LANDSCAPE_IPV6_TYPE, NAT_EGRESS_PRIORITY, NAT_INGRESS_PRIORITY,
};
use crate::{LANDSCAPE_IPV4_TYPE, MAP_PATHS};

pub(crate) mod land_nat {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_nat.skel.rs"));
}

// fn bump_memlock_rlimit() {
//     let rlimit = libc::rlimit { rlim_cur: 128 << 20, rlim_max: 128 << 20 };

//     if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
//         panic!("Failed to increase rlimit");
//     }
// }

unsafe impl plain::Plain for nat_conn_event {}
unsafe impl plain::Plain for u_inet_addr {}

impl From<&nat_conn_event> for NatEvent {
    fn from(ev: &nat_conn_event) -> Self {
        fn convert_ip(raw: &u_inet_addr, proto: u8) -> IpAddr {
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

        NatEvent {
            event_type: NatEventType::from(ev.event_type),
            src_ip: convert_ip(&ev.src_addr, ev.l3_proto),
            dst_ip: convert_ip(&ev.dst_addr, ev.l3_proto),
            src_port: ev.src_port.to_be(),
            dst_port: ev.dst_port.to_be(),
            l4_proto: ev.l4_proto,
            flow_id: ev.flow_id,
            trace_id: ev.trace_id,
            l3_proto: ev.l3_proto,
            time: ev.time,
        }
    }
}

pub fn init_nat(
    ifindex: i32,
    has_mac: bool,
    service_status: oneshot::Receiver<()>,
    config: NatConfig,
) {
    // bump_memlock_rlimit();
    let landscape_builder = LandNatSkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();
    // println!("reuse_pinned_map: {:?}", MAP_PATHS.wan_ip);
    landscape_open.maps.wan_ipv4_binding.set_pin_path(&MAP_PATHS.wan_ip).unwrap();
    landscape_open.maps.static_nat_mappings.set_pin_path(&MAP_PATHS.static_nat_mappings).unwrap();
    landscape_open.maps.nat_conn_events.set_pin_path(&MAP_PATHS.nat_conn_events).unwrap();
    if let Err(e) = landscape_open.maps.wan_ipv4_binding.reuse_pinned_map(&MAP_PATHS.wan_ip) {
        tracing::error!("error: {e:?}");
    }
    if let Err(e) =
        landscape_open.maps.static_nat_mappings.reuse_pinned_map(&MAP_PATHS.static_nat_mappings)
    {
        tracing::error!("error: {e:?}");
    }

    if let Err(e) = landscape_open.maps.nat_conn_events.reuse_pinned_map(&MAP_PATHS.nat_conn_events)
    {
        tracing::error!("error: {e:?}");
    }
    landscape_open.maps.rodata_data.tcp_range_start = config.tcp_range.start;
    landscape_open.maps.rodata_data.tcp_range_end = config.tcp_range.end;
    landscape_open.maps.rodata_data.udp_range_start = config.udp_range.start;
    landscape_open.maps.rodata_data.udp_range_end = config.udp_range.end;

    landscape_open.maps.rodata_data.icmp_range_start = config.icmp_in_range.start;
    landscape_open.maps.rodata_data.icmp_range_end = config.icmp_in_range.end;

    if !has_mac {
        landscape_open.maps.rodata_data.current_eth_net_offset = 0;
    }

    let landscape_skel = landscape_open.load().unwrap();

    // let (nat_conn_events_tx, mut nat_conn_events_rx) =
    //     tokio::sync::mpsc::unbounded_channel::<Box<NatEvent>>();
    // event ringbuf
    // let callback = |data: &[u8]| -> i32 {
    //     let time = landscape_common::utils::time::get_boot_time_ns().unwrap_or_default();
    //     let nat_conn_event_value = plain::from_bytes::<nat_conn_event>(data);
    //     if let Ok(data) = nat_conn_event_value {
    //         let event = NatEvent::from(data);
    //         println!("event, {:#?}, time: {time}, diff: {}", event, time - data.time);
    //     }
    //     // let _ = nat_conn_events_tx.send(Box::new(data.to_vec()));
    //     0
    // };
    // let mut builder = libbpf_rs::RingBufferBuilder::new();
    // builder
    //     .add(&landscape_skel.maps.nat_conn_events, callback)
    //     .expect("failed to add nat_conn_events ringbuf");
    // let mgr = builder.build().expect("failed to build");

    let nat_egress = landscape_skel.progs.egress_nat;
    let nat_ingress = landscape_skel.progs.ingress_nat;

    let mut nat_egress_hook =
        TcHookProxy::new(&nat_egress, ifindex, TC_EGRESS, NAT_EGRESS_PRIORITY);
    let mut nat_ingress_hook =
        TcHookProxy::new(&nat_ingress, ifindex, TC_INGRESS, NAT_INGRESS_PRIORITY);

    nat_egress_hook.attach();
    nat_ingress_hook.attach();
    // 'wait_stop: loop {
    //     let _ = mgr.poll(Duration::from_millis(1000));
    //     match service_status.try_recv() {
    //         Ok(_) => break 'wait_stop,
    //         Err(TryRecvError::Empty) => {}
    //         Err(TryRecvError::Closed) => break 'wait_stop,
    //     }
    // }
    let _ = service_status.blocking_recv();
    drop(nat_egress_hook);
    drop(nat_ingress_hook);
}
