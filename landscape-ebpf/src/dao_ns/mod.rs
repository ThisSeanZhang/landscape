use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{OwnedOpenObject, TcHookProxy, pin_and_reuse_map};
use crate::runtime::EbpfRuntime;

pub(crate) mod tc_lan_dao_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_dao.skel.rs"));
}
use tc_lan_dao_skel::TcLanDaoSkelBuilder;

/// Standalone DAD-NS observer filter attached by the LAN IPv6 service;
/// reuses the shared map space (`ip_mac_v6` / `rt6_lan_map` /
/// `ip6_dao_events`).
pub struct TcLanDaoHandle {
    _dao_skel: tc_lan_dao_skel::TcLanDaoSkel<'static>,
    _dao_backing: OwnedOpenObject,
    dao_hook: Option<TcHookProxy>,
    _ifindex: u32,
}

unsafe impl Send for TcLanDaoHandle {}
unsafe impl Sync for TcLanDaoHandle {}

impl Drop for TcLanDaoHandle {
    fn drop(&mut self) {
        self.dao_hook.take();
    }
}

/// Attach the DAD observer as an ingress TC filter on `ifindex`. LAN IPv6
/// interfaces always carry an Ethernet header, so `l3_offset` is fixed at
/// 14. The filter is a self-contained classifier returning `TC_ACT_UNSPEC`
/// and `TcHookProxy::attach` creates the clsact qdisc itself.
pub fn init_tc_lan_dao(rt: &Arc<EbpfRuntime>, ifindex: u32) -> LdEbpfResult<TcLanDaoHandle> {
    let paths = &rt.paths;
    let l3_offset: u32 = 14;

    let (dao_backing, dao_obj) = OwnedOpenObject::new();
    let dao_builder = TcLanDaoSkelBuilder::default();
    let mut dao_open_skel = bpf_ctx!(dao_builder.open(dao_obj), "open per-if tc_lan_dao")?;
    dao_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut dao_open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "tc_lan_dao pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut dao_open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "tc_lan_dao pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut dao_open_skel.maps.ip6_dao_events, &paths.ip6_dao_events),
        "tc_lan_dao pin ip6_dao_events"
    )?;
    let dao_skel = bpf_ctx!(dao_open_skel.load(), "load per-if tc_lan_dao")?;
    let mut dao_hook = TcHookProxy::new(
        &dao_skel.progs.tc_lan_dao,
        ifindex as i32,
        libbpf_rs::TC_INGRESS,
        crate::TC_LAN_INGRESS_DAO_PRIORITY,
    );
    dao_hook.attach();

    Ok(TcLanDaoHandle {
        _dao_skel: dao_skel,
        _dao_backing: dao_backing,
        dao_hook: Some(dao_hook),
        _ifindex: ifindex,
    })
}
