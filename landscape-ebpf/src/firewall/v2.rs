use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};

pub(crate) mod firewall_v2_bpf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/firewall_v2.skel.rs"));
}

use firewall_v2_bpf::*;
use tokio::sync::oneshot;

use crate::{
    bpf_error::LdEbpfResult, landscape::TcHookProxy, FIREWALL_EGRESS_PRIORITY,
    FIREWALL_INGRESS_PRIORITY, MAP_PATHS,
};

pub fn firewall_v2(
    ifindex: i32,
    has_mac: bool,
    service_status: oneshot::Receiver<()>,
) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let firewall_builder = FirewallV2SkelBuilder::default();
    // let mut open_opts = libbpf_sys::bpf_object_open_opts::default();
    // open_opts.sz = std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as _;

    // const LOG_BUF_SIZE: usize = (1 << 20) * 5;
    // let mut log_buf = vec![0u8; LOG_BUF_SIZE];
    // let log_buf_ptr = log_buf.as_mut_ptr() as *mut i8;

    // open_opts.kernel_log_buf = log_buf_ptr;
    // open_opts.kernel_log_size = LOG_BUF_SIZE as _;
    // open_opts.kernel_log_level = 1;

    // let mut open_skel = firewall_builder.open_opts(open_opts, &mut open_object)?;

    let mut open_skel = firewall_builder.open(&mut open_object)?;
    let rodata_data =
        open_skel.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");

    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

    open_skel.maps.firewall_block_ip4_map.set_pin_path(&MAP_PATHS.firewall_ipv4_block)?;
    open_skel.maps.firewall_block_ip6_map.set_pin_path(&MAP_PATHS.firewall_ipv6_block)?;
    open_skel.maps.firewall_conn_events.set_pin_path(&MAP_PATHS.firewall_conn_events)?;
    open_skel
        .maps
        .firewall_conn_metric_events
        .set_pin_path(&MAP_PATHS.firewall_conn_metric_events)?;
    open_skel.maps.firewall_allow_rules_map.set_pin_path(&MAP_PATHS.firewall_allow_rules_map)?;

    open_skel.maps.firewall_block_ip4_map.reuse_pinned_map(&MAP_PATHS.firewall_ipv4_block)?;
    open_skel.maps.firewall_block_ip6_map.reuse_pinned_map(&MAP_PATHS.firewall_ipv6_block)?;
    open_skel.maps.firewall_conn_events.reuse_pinned_map(&MAP_PATHS.firewall_conn_events)?;
    open_skel
        .maps
        .firewall_conn_metric_events
        .reuse_pinned_map(&MAP_PATHS.firewall_conn_metric_events)?;

    open_skel
        .maps
        .firewall_allow_rules_map
        .reuse_pinned_map(&MAP_PATHS.firewall_allow_rules_map)?;
    let skel = open_skel.load()?;

    // let skel = match open_skel.load() {
    //     Ok(skel) => skel,
    //     Err(e) => {
    //         let log_str = String::from_utf8_lossy(&log_buf);
    //         let trimmed_log = log_str.trim_matches('\0');
    //         println!("===> Verify failed: {}", trimmed_log);
    //         return Err(bpf_error::LandscapeEbpfError::Libbpf(e));
    //     }
    // };

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
