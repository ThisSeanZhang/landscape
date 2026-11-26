use std::sync::Arc;

use crate::{
    bpf_error::LdEbpfResult,
    chain::wan_link::{TcPppoeExitGuard, WanLinkDataplane},
    stages::pppoe::XdpPppoeHandle,
};

pub use crate::skel::tc_wan_pppoe_exit::types::pppoe_egress_tmpl as PppoeEgressTmpl;

/// Per-link native PPPoE dataplane: the dedicated TC chain exit
/// encapsulates with this link's session template (so no separate TC
/// encap stage is wired), and the XDP from-LAN chain keeps its existing
/// terminal stage until the XDP exit merge lands.
pub struct PppoeHandle {
    _tc: TcPppoeExitGuard,
    _xdp: XdpPppoeHandle,
}

unsafe impl Send for PppoeHandle {}
unsafe impl Sync for PppoeHandle {}

pub fn create_pppoe_handle(
    dp: Arc<WanLinkDataplane>,
    _ifindex: u32,
    tmpl: PppoeEgressTmpl,
    _mtu: u16,
) -> LdEbpfResult<PppoeHandle> {
    let session_id = u16::from_be(tmpl.session_id);

    let tc = dp.install_tc_pppoe_exit(&tmpl)?;
    let xdp = crate::stages::pppoe::init_xdp_pppoe(&dp, session_id)?;
    Ok(PppoeHandle { _tc: tc, _xdp: xdp })
}
