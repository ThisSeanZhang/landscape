use std::net::Ipv6Addr;
use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::runtime::EbpfRuntime;

// ========================================================================
// v6 NAT stage — TC (timer-map owner) + XDP (FD borrower)
// ========================================================================

pub(crate) mod tc_nat6_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_nat6.skel.rs"));
}

pub(crate) mod xdp_nat6_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat6.skel.rs"));
}

/// Bake value for the `wan_ro_prefix6` rodata field shared by the nat6
/// objects: the first 8 bytes (the /64-or-shorter span) of the WAN prefix,
/// network order, written through the union's byte view. `None` bakes the
/// all-zero "unconfigured" prefix (drop semantics). Single place that knows
/// the layout; all loaders and tests go through it.
pub(crate) fn wan_ro_prefix6(prefix: Option<Ipv6Addr>) -> [u8; 8] {
    let mut out = [0u8; 8];
    if let Some(prefix) = prefix {
        out.copy_from_slice(&prefix.octets()[..8]);
    }
    out
}

/// The v6 NAT stage: TC ingress/egress + XDP LAN/WAN with a shared
/// conntrack timer map.
pub struct Nat6Handle {
    pub tc: TcNat6Handle,
    pub xdp: XdpNat6Handle,
}

pub struct TcNat6Handle {
    runtime: Arc<EbpfRuntime>,
    _skel: tc_nat6_skel::TcNat6Skel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcNat6Handle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::StageType;
        let _ = self.runtime.tc.remove(self.ifindex, StageType::Nat6);
    }
}

pub struct XdpNat6Handle {
    runtime: Arc<EbpfRuntime>,
    _skel: xdp_nat6_skel::XdpNat6Skel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpNat6Handle {}
unsafe impl Sync for XdpNat6Handle {}

impl Drop for XdpNat6Handle {
    fn drop(&mut self) {
        use crate::chain::xdp_manager::StageType;
        let _ = self.runtime.xdp.remove(self.ifindex, StageType::Nat6);
    }
}

// ========================================================================
// v6 NAT (ingress + egress, TC owns the timer map, XDP borrows it)
// ========================================================================

pub fn attach_nat6(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    has_eth_header: bool,
    prefix: Option<(Ipv6Addr, u8)>,
) -> LdEbpfResult<Nat6Handle> {
    use crate::chain::tc_manager::{StageEntry, StageType};
    use crate::chain::xdp_manager::{StageEntry as XdpStageEntry, StageType as XdpStageType};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = &rt.paths;

    // Bake the WAN prefix into rodata; `None` bakes the all-zero
    // "unconfigured" prefix, which the dataplane treats as drop (the
    // old map-miss semantics).
    let npt_mask = match prefix {
        Some((_, prefix_len)) => crate::maps::wan::compute_npt_mask(prefix_len),
        None => 0,
    };

    // ── 1. Load TC nat6 first (ingress + egress, for timer map sharing with XDP) ──

    rt.tc.ensure_roots(ifindex, has_eth_header)?;

    let tc_builder = tc_nat6_skel::TcNat6SkelBuilder::default();
    let (tc_backing, tc_obj) = OwnedOpenObject::new();
    let mut tc_open = bpf_ctx!(tc_builder.open(tc_obj), "open tc_nat6 skeleton")?;

    let tc_rodata = tc_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memory mapped");
    tc_rodata.current_l3_offset = if has_eth_header { 14 } else { 0 };
    tc_rodata.wan_ro_prefix6.b = wan_ro_prefix6(prefix.map(|(addr, _)| addr));
    tc_rodata.wan_ro_npt_mask = npt_mask;

    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_egress,
        &paths.tc_pipe_exits_wan_egress_path(),
    )?;
    pin_and_reuse_map(&mut tc_open.maps.nat6_static_map, &paths.nat6_static_map)?;
    pin_and_reuse_map(&mut tc_open.maps.nat_metric_events, &paths.nat_metric_events)?;

    let tc_skel = bpf_ctx!(tc_open.load(), "load tc_nat6 skeleton")?;

    // ── 2. Open XDP nat6, reuse TC's timer map FD ──

    let xdp_builder = xdp_nat6_skel::XdpNat6SkelBuilder::default();
    let (xdp_backing, xdp_obj) = OwnedOpenObject::new();
    let mut xdp_open = bpf_ctx!(xdp_builder.open(xdp_obj), "open xdp_nat6 skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path()
        ),
        "xdp_nat6 pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path()),
        "xdp_nat6 pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path()),
        "xdp_nat6 pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_nat6 pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat6_static_map, &paths.nat6_static_map,),
        "xdp_nat6 pin nat6_static_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat_metric_events, &paths.nat_metric_events,),
        "xdp_nat6 pin nat_metric_events"
    )?;

    crate::bpf_ctx!(
        xdp_open.maps.nat6_timer_map.reuse_fd(tc_skel.maps.nat6_timer_map.as_fd()),
        "xdp_nat6 reuse nat6_timer_map fd"
    )?;

    {
        let xdp_rodata =
            xdp_open.maps.rodata_data.as_deref_mut().expect("xdp_nat6 rodata not memory mapped");
        xdp_rodata.current_ifindex = ifindex;
        xdp_rodata.wan_ro_prefix6.b = wan_ro_prefix6(prefix.map(|(addr, _)| addr));
        xdp_rodata.wan_ro_npt_mask = npt_mask;
    }

    let xdp_skel = bpf_ctx!(xdp_open.load(), "load xdp_nat6 skeleton")?;

    // ── 3. Inject into chain managers ──

    let tc_entry = StageEntry {
        wan_ingress_prog_v4_fd: 0,
        wan_ingress_prog_v6_fd: tc_skel.progs.tc_nat_wan_ingress_v6.as_fd().as_raw_fd(),
        wan_egress_prog_v4_fd: 0,
        wan_egress_prog_v6_fd: tc_skel.progs.tc_nat_wan_egress_v6.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: tc_skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: tc_skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };
    rt.tc.inject(ifindex, StageType::Nat6, tc_entry)?;

    let xdp_entry = XdpStageEntry {
        lan_prog_v4_fd: 0,
        lan_prog_v6_fd: xdp_skel.progs.egress_nat_v6.as_fd().as_raw_fd(),
        wan_prog_v4_fd: 0,
        wan_prog_v6_fd: xdp_skel.progs.ingress_nat_v6.as_fd().as_raw_fd(),
        next_stage_map_fd: xdp_skel.maps.next_stage.as_fd().as_raw_fd(),
    };
    rt.xdp.inject(ifindex, XdpStageType::Nat6, xdp_entry)?;

    Ok(Nat6Handle {
        tc: TcNat6Handle {
            runtime: rt.clone(),
            _skel: tc_skel,
            _backing: tc_backing,
            ifindex,
        },
        xdp: XdpNat6Handle {
            runtime: rt.clone(),
            _skel: xdp_skel,
            _backing: xdp_backing,
            ifindex,
        },
    })
}
