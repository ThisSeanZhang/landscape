use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};

mod firewall_bpf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/firewall.skel.rs"));
}

use firewall_bpf::*;
use tokio::sync::oneshot;

use crate::{
    bpf_error::LdEbpfResult, landscape::TcHookProxy, FIREWALL_EGRESS_PRIORITY,
    FIREWALL_INGRESS_PRIORITY, MAP_PATHS,
};

pub fn new_firewall(
    ifindex: i32,
    has_mac: bool,
    service_status: oneshot::Receiver<()>,
) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let firewall_builder = FirewallSkelBuilder::default();
    let mut open_skel = firewall_builder.open(&mut open_object)?;
    if !has_mac {
        open_skel.maps.rodata_data.current_eth_net_offset = 0;
    }

    open_skel.maps.firewall_block_ip4_map.set_pin_path(&MAP_PATHS.firewall_ipv4_block)?;
    open_skel.maps.firewall_block_ip6_map.set_pin_path(&MAP_PATHS.firewall_ipv6_block)?;
    open_skel.maps.firewall_allow_rules_map.set_pin_path(&MAP_PATHS.firewall_allow_rules_map)?;

    open_skel.maps.firewall_block_ip4_map.reuse_pinned_map(&MAP_PATHS.firewall_ipv4_block)?;
    open_skel.maps.firewall_block_ip6_map.reuse_pinned_map(&MAP_PATHS.firewall_ipv6_block)?;
    open_skel
        .maps
        .firewall_allow_rules_map
        .reuse_pinned_map(&MAP_PATHS.firewall_allow_rules_map)?;

    let skel = open_skel.load()?;

    let egress_firewall = skel.progs.egress_firewall;
    let ingress_firewall = skel.progs.ingress_firewall;

    let mut egress_firewall_hook =
        TcHookProxy::new(&egress_firewall, ifindex, TC_EGRESS, FIREWALL_EGRESS_PRIORITY);
    let mut ingress_firewall_hook =
        TcHookProxy::new(&ingress_firewall, ifindex, TC_INGRESS, FIREWALL_INGRESS_PRIORITY);

    egress_firewall_hook.attach();
    ingress_firewall_hook.attach();
    let _ = service_status.blocking_recv();
    drop(egress_firewall_hook);
    drop(ingress_firewall_hook);

    Ok(())
}
