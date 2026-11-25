use std::net::Ipv6Addr;
use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::wan_link::WanLinkDataplane;

// ========================================================================
// v6 NAT stage — TC and XDP share the per-WAN mapping and CT maps
// ========================================================================

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

/// Bake value for the `wan_ro_addr6` rodata field: the complete WAN-side
/// /128 (prefix + shared WAN IID), network order. `None` bakes all zeros.
pub(crate) fn wan_ro_addr6(addr: Option<Ipv6Addr>) -> [u8; 16] {
    addr.map(|addr| addr.octets()).unwrap_or([0u8; 16])
}

/// Compute the NPT (Network Prefix Translation) mask for IPv6 prefix translation.
///
/// For a given prefix length N (0..64), the mask covers the bits between the
/// prefix and the 64-bit interface-ID boundary. These are the bits that should
/// be preserved from the LAN-side address during NPT translation.
///
/// The result is a little-endian u64 where each byte corresponds to bytes 0..7
/// of the IPv6 address (in network order). Bits *inside* the prefix are 0
/// (replaced by the WAN prefix) and bits *outside* the prefix (up to bit 63)
/// are 1 (kept from the LAN address).
pub(crate) fn compute_npt_mask(prefix_len: u8) -> u64 {
    if prefix_len >= 64 {
        return 0;
    }
    let mut mask: u64 = 0;
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;
    for i in 0..8usize {
        let byte_mask: u8 = if i < full_bytes {
            0x00
        } else if i == full_bytes && remaining_bits > 0 {
            (1u8 << (8 - remaining_bits)) - 1
        } else {
            0xFF
        };
        mask |= (byte_mask as u64) << (i * 8);
    }
    mask
}

/// The v6 NAT stage: TC ingress/egress + XDP LAN/WAN with shared
/// endpoint mapping and conntrack maps.
pub struct Nat6Handle {
    pub tc: TcNat6Handle,
    pub xdp: XdpNat6Handle,
}

pub struct TcNat6Handle {
    dp: Arc<WanLinkDataplane>,
    _skel: crate::skel::tc_nat6::TcNat6Skel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
}

impl Drop for TcNat6Handle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        self.dp.tc().remove_from_wan(FromWanStageType::Nat, StageFamily::V6);
        self.dp.tc().remove_from_lan(FromLanStageType::Nat, StageFamily::V6);
    }
}

pub struct XdpNat6Handle {
    dp: Arc<WanLinkDataplane>,
    _skel: crate::skel::xdp_nat6::XdpNat6Skel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
}

unsafe impl Send for XdpNat6Handle {}
unsafe impl Sync for XdpNat6Handle {}

impl Drop for XdpNat6Handle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        self.dp.xdp().remove_from_wan(FromWanStageType::Nat, StageFamily::V6);
        self.dp.xdp().remove_from_lan(FromLanStageType::Nat, StageFamily::V6);
    }
}

// ========================================================================
// v6 NAT (ingress + egress, TC owns the mapping and timer maps, XDP borrows both)
// ========================================================================

pub fn attach_nat6(
    dp: &Arc<WanLinkDataplane>,
    ifindex: u32,
    has_eth_header: bool,
    prefix: Option<(Ipv6Addr, u8)>,
    wan_addr: Option<Ipv6Addr>,
) -> LdEbpfResult<Nat6Handle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = dp.backbone().paths();

    // Bake the WAN prefix into rodata; `None` bakes the all-zero
    // "unconfigured" prefix, which the dataplane treats as drop (the
    // old map-miss semantics).
    let npt_mask = match prefix {
        Some((_, prefix_len)) => compute_npt_mask(prefix_len),
        None => 0,
    };

    // ── 1. Load TC nat6 first (ingress + egress, to share its maps with XDP) ──

    let tc_builder = crate::skel::tc_nat6::TcNat6SkelBuilder::default();
    let (tc_backing, tc_obj) = OwnedOpenObject::new();
    let mut tc_open = bpf_ctx!(tc_builder.open(tc_obj), "open tc_nat6 skeleton")?;

    let tc_rodata = tc_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memory mapped");
    tc_rodata.current_l3_offset = if has_eth_header { 14 } else { 0 };
    tc_rodata.wan_ro_prefix6.b = wan_ro_prefix6(prefix.map(|(addr, _)| addr));
    tc_rodata.wan_ro_addr6.b = wan_ro_addr6(wan_addr);
    tc_rodata.wan_ro_npt_mask = npt_mask;

    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    dp.reuse_tc_wan_egress_exit_map(&mut tc_open.maps.tc_from_lan_exit_map)?;
    pin_and_reuse_map(&mut tc_open.maps.nat6_static_map, &paths.nat6_static_map)?;
    pin_and_reuse_map(&mut tc_open.maps.nat_metric_events, &paths.nat_metric_events)?;
    pin_and_reuse_map(&mut tc_open.maps.frag6_cache_lan, &paths.frag6_cache_lan)?;
    pin_and_reuse_map(&mut tc_open.maps.frag6_cache_wan, &paths.frag6_cache_wan)?;

    let tc_skel = bpf_ctx!(tc_open.load(), "load tc_nat6 skeleton")?;

    // ── 2. Open XDP nat6, reuse TC's mapping and timer map FDs ──

    let xdp_builder = crate::skel::xdp_nat6::XdpNat6SkelBuilder::default();
    let (xdp_backing, xdp_obj) = OwnedOpenObject::new();
    let mut xdp_open = bpf_ctx!(xdp_builder.open(xdp_obj), "open xdp_nat6 skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path()
        ),
        "xdp_nat6 pin xdp_pipe_root_progs"
    )?;
    dp.reuse_xdp_lan_exit_map(&mut xdp_open.maps.xdp_from_lan_exit_map)?;
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
        xdp_open.maps.nat6_mapping_map.reuse_fd(tc_skel.maps.nat6_mapping_map.as_fd()),
        "xdp_nat6 reuse nat6_mapping_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat6_timer_map.reuse_fd(tc_skel.maps.nat6_timer_map.as_fd()),
        "xdp_nat6 reuse nat6_timer_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.frag6_cache_lan.reuse_fd(tc_skel.maps.frag6_cache_lan.as_fd()),
        "xdp_nat6 reuse frag6_cache_lan fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.frag6_cache_wan.reuse_fd(tc_skel.maps.frag6_cache_wan.as_fd()),
        "xdp_nat6 reuse frag6_cache_wan fd"
    )?;

    {
        let xdp_rodata =
            xdp_open.maps.rodata_data.as_deref_mut().expect("xdp_nat6 rodata not memory mapped");
        xdp_rodata.current_ifindex = ifindex;
        xdp_rodata.current_l3_offset = if has_eth_header { 14 } else { 0 };
        xdp_rodata.wan_ro_prefix6.b = wan_ro_prefix6(prefix.map(|(addr, _)| addr));
        xdp_rodata.wan_ro_addr6.b = wan_ro_addr6(wan_addr);
        xdp_rodata.wan_ro_npt_mask = npt_mask;
    }

    let xdp_skel = bpf_ctx!(xdp_open.load(), "load xdp_nat6 skeleton")?;

    // ── 3. Inject into the link's chain ──

    dp.tc().inject_from_wan(
        FromWanStageType::Nat,
        StageFamily::V6,
        FamilyProg {
            prog_fd: tc_skel.progs.tc_nat_wan_ingress_v6.as_fd().as_raw_fd(),
            next_stage_map_fd: tc_skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        },
    )?;
    dp.tc().inject_from_lan(
        FromLanStageType::Nat,
        StageFamily::V6,
        FamilyProg {
            prog_fd: tc_skel.progs.tc_nat_wan_egress_v6.as_fd().as_raw_fd(),
            next_stage_map_fd: tc_skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        },
    )?;

    let next_stage_fd = xdp_skel.maps.next_stage.as_fd().as_raw_fd();
    dp.xdp().inject_from_wan(
        FromWanStageType::Nat,
        StageFamily::V6,
        FamilyProg {
            prog_fd: xdp_skel.progs.ingress_nat_v6.as_fd().as_raw_fd(),
            next_stage_map_fd: next_stage_fd,
        },
    )?;
    dp.xdp().inject_from_lan(
        FromLanStageType::Nat,
        StageFamily::V6,
        FamilyProg {
            prog_fd: xdp_skel.progs.egress_nat_v6.as_fd().as_raw_fd(),
            next_stage_map_fd: next_stage_fd,
        },
    )?;

    Ok(Nat6Handle {
        tc: TcNat6Handle {
            dp: dp.clone(),
            _skel: tc_skel,
            _backing: tc_backing,
        },
        xdp: XdpNat6Handle {
            dp: dp.clone(),
            _skel: xdp_skel,
            _backing: xdp_backing,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{wan_ro_addr6, wan_ro_prefix6};

    #[test]
    fn wan_ro_addr6_bakes_network_order_and_zero_default() {
        let addr = "2001:db8:1::8000:0:0:1234".parse().unwrap();
        assert_eq!(wan_ro_addr6(Some(addr)), addr.octets());
        assert_eq!(wan_ro_addr6(None), [0u8; 16]);
    }

    #[test]
    fn wan_ro_prefix6_keeps_the_first_eight_bytes() {
        let addr = "2001:db8:1::8000:0:0:1234".parse().unwrap();
        assert_eq!(wan_ro_prefix6(Some(addr)), addr.octets()[..8]);
        assert_eq!(wan_ro_prefix6(None), [0u8; 8]);
    }
}
