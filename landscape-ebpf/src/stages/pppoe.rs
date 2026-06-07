use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};

mod tc_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_pppoe.skel.rs"));
}

pub struct PppoeHandle {
    _skel: tc_pppoe_skel::TcPppoeSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

impl Drop for PppoeHandle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::{StageType, TcChainManager};
        let manager = TcChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Pppoe);
    }
}

pub fn attach_tc_pppoe(ifindex: u32, session_id: u16, _has_mac: bool) -> LdEbpfResult<PppoeHandle> {
    use crate::chain::tc_manager::{
        tc_pipe_exits_wan_egress_path, tc_pipe_exits_wan_ingress_path, StageEntry, StageType,
        TcChainManager,
    };

    let manager = TcChainManager::instance();
    manager.ensure_egress_roots_only(ifindex)?;

    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_pppoe skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().session_id = session_id;

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &tc_pipe_exits_wan_egress_path(),
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_pppoe skeleton")?;

    let entry = StageEntry {
        wan_ingress_prog_fd: 0,
        wan_egress_prog_fd: skel.progs.tc_pppoe_wan_egress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: 0,
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };

    manager.inject(ifindex, StageType::Pppoe, entry)?;

    Ok(PppoeHandle { _skel: skel, _backing: backing, ifindex })
}
