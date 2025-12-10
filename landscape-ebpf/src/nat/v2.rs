use std::mem::MaybeUninit;

use land_nat_v2::*;
use landscape_common::config::nat::NatConfig;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};
use tokio::sync::oneshot;

use crate::MAP_PATHS;
use crate::{landscape::TcHookProxy, NAT_EGRESS_PRIORITY, NAT_INGRESS_PRIORITY};

pub(crate) mod land_nat_v2 {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_nat_v2.skel.rs"));
}

pub fn init_nat_v2(
    ifindex: i32,
    has_mac: bool,
    service_status: oneshot::Receiver<()>,
    config: NatConfig,
) {
    let landscape_builder = LandNatV2SkelBuilder::default();
    // landscape_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();
    // println!("reuse_pinned_map: {:?}", MAP_PATHS.wan_ip);

    landscape_open.maps.debug_counter.set_pin_path(&MAP_PATHS.debug_counter).unwrap();
    landscape_open.maps.debug_counter.reuse_pinned_map(&MAP_PATHS.debug_counter).unwrap();

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

    let rodata_data =
        landscape_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");

    rodata_data.tcp_range_start = config.tcp_range.start;
    rodata_data.tcp_range_end = config.tcp_range.end;
    rodata_data.udp_range_start = config.udp_range.start;
    rodata_data.udp_range_end = config.udp_range.end;

    rodata_data.icmp_range_start = config.icmp_in_range.start;
    rodata_data.icmp_range_end = config.icmp_in_range.end;

    if !has_mac {
        rodata_data.current_l3_offset = 0;
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
