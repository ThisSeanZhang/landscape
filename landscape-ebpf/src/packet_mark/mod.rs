use std::{mem::MaybeUninit, path::PathBuf};

use firewall::*;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};

use tokio::sync::oneshot;

use crate::{
    landscape::TcHookProxy, BLOCK_IP_MAP_PING_PATH, FIREWALL_EGRESS_PRIORITY,
    FIREWALL_INGRESS_PRIORITY, PACKET_MARK_MAP_PING_PATH, REDIRECT_INDEX_MAP_PING_PATH,
};

mod firewall {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/packet_mark.skel.rs"));
}

pub fn init_packet_mark(ifindex: i32, has_mac: bool, service_status: oneshot::Receiver<()>) {
    let mut landscape_builder = PacketMarkSkelBuilder::default();
    landscape_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();
    // if let Err(e) = landscape_open
    //     .maps
    //     .firewall_block_map
    //     .reuse_pinned_map(PathBuf::from(BLOCK_IP_MAP_PING_PATH))
    // {
    //     println!("error: {e:?}");
    // }
    if !has_mac {
        landscape_open.maps.rodata_data.current_eth_net_offset = 0;
    }

    if let Err(e) = landscape_open
        .maps
        .packet_mark_map
        .reuse_pinned_map(PathBuf::from(PACKET_MARK_MAP_PING_PATH))
    {
        println!("error: {e:?}");
    }
    if let Err(e) = landscape_open
        .maps
        .redirect_index_map
        .reuse_pinned_map(PathBuf::from(REDIRECT_INDEX_MAP_PING_PATH))
    {
        println!("error: {e:?}");
    }

    let landscape_skel = landscape_open.load().unwrap();
    let nat_egress = landscape_skel.progs.egress_packet_mark;
    let nat_ingress = landscape_skel.progs.ingress_packet_mark;

    let mut nat_egress_hook =
        TcHookProxy::new(&nat_egress, ifindex, TC_EGRESS, FIREWALL_EGRESS_PRIORITY);
    let mut nat_ingress_hook =
        TcHookProxy::new(&nat_ingress, ifindex, TC_INGRESS, FIREWALL_INGRESS_PRIORITY);

    nat_egress_hook.attach();
    nat_ingress_hook.attach();
    let _ = service_status.blocking_recv();
    drop(nat_egress_hook);
    drop(nat_ingress_hook);
}
