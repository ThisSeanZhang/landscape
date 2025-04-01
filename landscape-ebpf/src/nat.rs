use core::ops::Range;
use std::{mem::MaybeUninit, net::Ipv4Addr};

use land_nat::{
    types::{nat_mapping_key, nat_mapping_value, u_inet_addr},
    *,
};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, TC_EGRESS, TC_INGRESS,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::MAP_PATHS;
use crate::{landscape::TcHookProxy, NAT_EGRESS_PRIORITY, NAT_INGRESS_PRIORITY};

mod land_nat {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_nat.skel.rs"));
}

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
    if let Err(e) = landscape_open.maps.wan_ipv4_binding.reuse_pinned_map(&MAP_PATHS.wan_ip) {
        tracing::error!("error: {e:?}");
    }
    if let Err(e) =
        landscape_open.maps.static_nat_mappings.reuse_pinned_map(&MAP_PATHS.static_nat_mappings)
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

#[allow(dead_code)]
pub(crate) fn set_nat_static_mapping<'obj, T>(mapping: (Ipv4Addr, u16, Ipv4Addr, u16), map: &T)
where
    T: MapCore,
{
    let an = mapping.0.to_bits().to_be();
    let pn = mapping.1.to_be();
    let ac = mapping.2.to_bits().to_be();
    let pc = mapping.3.to_be();

    let kn = nat_mapping_key {
        gress: 0,
        l4proto: 6,
        from_port: pn,
        from_addr: u_inet_addr { ip: an },
    };
    let kn = unsafe { plain::as_bytes(&kn) };

    let vn = nat_mapping_value {
        addr: u_inet_addr { ip: ac },
        trigger_addr: u_inet_addr { ip: 0 },
        port: pc,
        trigger_port: 0,
        is_static: 1,
        _pad: [0; 3],
        active_time: 0,
    };
    let vn = unsafe { plain::as_bytes(&vn) };

    let kc = nat_mapping_key {
        gress: 1,
        l4proto: 6,
        from_port: pc,
        from_addr: u_inet_addr { ip: ac },
    };
    let kc = unsafe { plain::as_bytes(&kc) };

    let vc = nat_mapping_value {
        addr: u_inet_addr { ip: an },
        trigger_addr: u_inet_addr { ip: 0 },
        port: pn,
        trigger_port: 0,
        is_static: 1,
        _pad: [0; 3],
        active_time: 0,
    };
    let vc = unsafe { plain::as_bytes(&vc) };

    map.update(kn, vn, MapFlags::ANY).unwrap();
    map.update(kc, vc, MapFlags::ANY).unwrap();
}
