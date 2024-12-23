pub mod land_nat {
    include!(concat!(env!("OUT_DIR"), "/land_nat.skel.rs"));
}

use core::ops::Range;
use std::{mem::MaybeUninit, path::PathBuf};

use land_nat::*;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::WAN_IP_MAP_PING_PATH;
use crate::{landscape::TcHookProxy, NAT_EGRESS_PRIORITY, NAT_INGRESS_PRIORITY};

// fn bump_memlock_rlimit() {
//     let rlimit = libc::rlimit { rlim_cur: 128 << 20, rlim_max: 128 << 20 };

//     if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
//         panic!("Failed to increase rlimit");
//     }
// }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NatConfig {
    tcp_range: Range<u16>,
    udp_range: Range<u16>,
    icmp_in_range: Range<u16>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            tcp_range: 32768..65535,
            udp_range: 32768..65535,
            icmp_in_range: 32768..65535,
        }
    }
}

pub fn init_nat(ifindex: i32, service_status: oneshot::Receiver<()>, config: NatConfig) {
    // bump_memlock_rlimit();
    let mut landscape_builder = LandNatSkelBuilder::default();
    landscape_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();
    if let Err(e) =
        landscape_open.maps.wan_ipv4_binding.reuse_pinned_map(PathBuf::from(WAN_IP_MAP_PING_PATH))
    {
        println!("error: {e:?}");
    }
    landscape_open.maps.rodata_data.tcp_range_start = config.tcp_range.start;
    landscape_open.maps.rodata_data.tcp_range_end = config.tcp_range.end;
    landscape_open.maps.rodata_data.udp_range_start = config.udp_range.start;
    landscape_open.maps.rodata_data.udp_range_end = config.udp_range.end;

    landscape_open.maps.rodata_data.icmp_range_start = config.icmp_in_range.start;
    landscape_open.maps.rodata_data.icmp_range_end = config.icmp_in_range.end;

    let landscape_skel = landscape_open.load().unwrap();
    let nat_egress = landscape_skel.progs.egress_nat;
    let nat_ingress = landscape_skel.progs.ingress_nat;

    let mut nat_egress_hook =
        TcHookProxy::new(&nat_egress, ifindex, TC_EGRESS, NAT_EGRESS_PRIORITY);
    let mut nat_ingress_hook =
        TcHookProxy::new(&nat_ingress, ifindex, TC_INGRESS, NAT_INGRESS_PRIORITY);

    nat_egress_hook.attach();
    nat_ingress_hook.attach();
    let _ = service_status.blocking_recv();
    drop(nat_egress_hook);
    drop(nat_ingress_hook);
}
