use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::tc_chain::manager::{
    tc_pipe_exits_lan_ingress_path, tc_pipe_exits_wan_egress_path, tc_pipe_exits_wan_ingress_path,
    StageEntry, StageType, TcChainManager,
};

mod tc_mss_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_mss.skel.rs"));
}

pub struct TcMssHandle {
    _skel: tc_mss_skel::TcMssSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcMssHandle {
    fn drop(&mut self) {
        let manager = TcChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Mss);
    }
}

pub fn attach_tc_mss(ifindex: u32, mtu: u16, has_mac: bool) -> LdEbpfResult<TcMssHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex)?;

    let builder = tc_mss_skel::TcMssSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_mss skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().mtu_size = mtu;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset =
        if has_mac { 14 } else { 0 };

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &tc_pipe_exits_wan_egress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_lan_ingress,
        &tc_pipe_exits_lan_ingress_path(),
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_mss skeleton")?;

    let entry = StageEntry {
        wan_ingress_prog_fd: skel.progs.tc_mss_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: skel.progs.tc_mss_wan_egress.as_fd().as_raw_fd(),
        lan_ingress_prog_fd: skel.progs.tc_mss_lan_ingress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        lan_ingress_next_stage_fd: skel.maps.lan_ingress_next_stage.as_fd().as_raw_fd(),
    };

    manager.inject(ifindex, StageType::Mss, entry)?;

    Ok(TcMssHandle { _skel: skel, _backing: backing, ifindex })
}
