use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use landscape_common::config_service::static_nat::config4::RuntimeStaticNatMappingV4Config;
use landscape_common::wan_service::nat::config::NatConfig;
use libbpf_rs::MapCore;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::wan_link::WanLinkDataplane;
use crate::skel::tc_nat4_v4::{TcNat4V4Skel, TcNat4V4SkelBuilder, types};
use crate::skel::xdp_nat4_v4::{XdpNat4V4Skel, XdpNat4V4SkelBuilder};

const NAPT_MAPPING_STATIC: u8 = 2;
const NAPT_WAN_STATE_ACTIVE: u64 = 1;
const NAPT_WAN_STATE_SHIFT: u32 = 56;
const NAPT_FROM_WAN_TCP_BASE: u32 = 65536;
const NAPT_FROM_WAN_ICMP_BASE: u32 = 131072;

/// Bake value for the NAT4 rodata field.
pub(crate) fn wan_ro_addr4(wan_addr: Ipv4Addr) -> u32 {
    wan_addr.to_bits().to_be()
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

/// The v4 NAT stage owns the TC and XDP ingress/egress programs. TC owns the
/// shared nat_v4 maps; XDP reuses their FDs so both datapaths see one state.
pub struct Nat4Handle {
    dp: Arc<WanLinkDataplane>,
    _tc_skel: TcNat4V4Skel<'static>,
    _xdp_skel: XdpNat4V4Skel<'static>,
    _tc_backing: crate::landscape::OwnedOpenObject,
    _xdp_backing: crate::landscape::OwnedOpenObject,
}

impl Drop for Nat4Handle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        self.dp.xdp().remove_from_wan(FromWanStageType::Nat, StageFamily::V4);
        self.dp.xdp().remove_from_lan(FromLanStageType::Nat, StageFamily::V4);
        self.dp.tc().remove_from_wan(FromWanStageType::Nat, StageFamily::V4);
        self.dp.tc().remove_from_lan(FromLanStageType::Nat, StageFamily::V4);
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16, reserved: &HashSet<(u8, u16)>, proto: u8)
where
    M: libbpf_rs::MapCore,
{
    let fd = map.as_fd().as_raw_fd();
    for port in start..=end {
        if reserved.contains(&(proto, port)) {
            continue;
        }
        let value = types::napt_port_slot { port: port.to_be(), pad: 0, generation: 0 };
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                fd,
                std::ptr::null(),
                (&value as *const types::napt_port_slot).cast(),
                0,
            )
        };
        if ret != 0 {
            break;
        }
    }
}

fn seed_runtime_queues(skel: &TcNat4V4Skel<'_>, config: &NatConfig, reserved: &HashSet<(u8, u16)>) {
    seed_port_queue(
        &skel.maps.napt_tcp_ports,
        config.tcp_range.start,
        config.tcp_range.end,
        reserved,
        6,
    );
    seed_port_queue(
        &skel.maps.napt_udp_ports,
        config.udp_range.start,
        config.udp_range.end,
        reserved,
        17,
    );
    seed_port_queue(
        &skel.maps.napt_icmp_ids,
        config.icmp_in_range.start,
        config.icmp_in_range.end,
        reserved,
        1,
    );
}

/// Seed static LAN and WAN entries. Dynamic ports never overlap these; the
/// reserved set also protects against a malformed runtime configuration.
fn seed_static_nat4(
    skel: &TcNat4V4Skel<'_>,
    configs: &[RuntimeStaticNatMappingV4Config],
) -> HashSet<(u8, u16)> {
    let mut reserved = HashSet::new();

    for config in configs {
        let internal_addr = u32::from_ne_bytes(config.lan_ipv4.octets());
        for &proto in &config.l4_protocols {
            for pair in &config.mapping_pair_ports {
                let lan_key = types::napt_from_lan_key {
                    internal_addr,
                    internal_port: pair.lan_port.to_be(),
                    proto,
                    pad: 0,
                };
                let lan_value = types::napt_from_lan_value {
                    external_port: pair.wan_port.to_be(),
                    kind: NAPT_MAPPING_STATIC,
                    allow_reuse: 1,
                    generation: 0,
                    trigger_addr: 0,
                    trigger_port: 0,
                    pad: 0,
                };
                skel.maps
                    .napt_from_lan
                    .update(as_bytes(&lan_key), as_bytes(&lan_value), libbpf_rs::MapFlags::ANY)
                    .expect("seed static napt_from_lan");

                let base = match proto {
                    6 => NAPT_FROM_WAN_TCP_BASE,
                    1 => NAPT_FROM_WAN_ICMP_BASE,
                    _ => 0,
                };
                let wan_index = base + u32::from(pair.wan_port);
                let wan_value = types::napt_from_wan_value {
                    internal_addr,
                    internal_port: pair.lan_port.to_be(),
                    kind: NAPT_MAPPING_STATIC,
                    allow_reuse: 1,
                    trigger_addr: 0,
                    trigger_port: 0,
                    pad0: 0,
                    generation: 0,
                    pad1: 0,
                    state_ref: NAPT_WAN_STATE_ACTIVE << NAPT_WAN_STATE_SHIFT,
                };
                skel.maps
                    .napt_from_wan
                    .update(
                        &wan_index.to_ne_bytes(),
                        as_bytes(&wan_value),
                        libbpf_rs::MapFlags::ANY,
                    )
                    .expect("seed static napt_from_wan");

                reserved.insert((proto, pair.wan_port));
            }
        }
    }

    reserved
}

pub fn attach_nat4(
    dp: &Arc<WanLinkDataplane>,
    ifindex: u32,
    has_eth_header: bool,
    config: &NatConfig,
    wan_addr: Ipv4Addr,
    static_configs: &[RuntimeStaticNatMappingV4Config],
) -> LdEbpfResult<Nat4Handle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};

    let paths = dp.backbone().paths();
    let builder = TcNat4V4SkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open = bpf_ctx!(builder.open(obj), "open tc_nat4_v4 skeleton")?;

    {
        let rodata = open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memory mapped");
        rodata.current_l3_offset = if has_eth_header { 14 } else { 0 };
        rodata.land_nat_external_addr = wan_ro_addr4(wan_addr);
        rodata.land_nat_udp_range_start = config.udp_range.start;
        rodata.land_nat_udp_range_end = config.udp_range.end;
        rodata.land_nat_tcp_range_start = config.tcp_range.start;
        rodata.land_nat_tcp_range_end = config.tcp_range.end;
    }

    pin_and_reuse_map(
        &mut open.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open.maps.tc_pipe_exits_wan_egress,
        &paths.tc_pipe_exits_wan_egress_path(),
    )?;
    pin_and_reuse_map(&mut open.maps.nat_metric_events, &paths.nat_metric_events)?;
    pin_and_reuse_map(&mut open.maps.frag4_cache_lan, &paths.frag4_cache_lan)?;
    pin_and_reuse_map(&mut open.maps.frag4_cache_wan, &paths.frag4_cache_wan)?;

    let tc_skel = bpf_ctx!(open.load(), "load tc_nat4_v4 skeleton")?;
    let reserved = seed_static_nat4(&tc_skel, static_configs);
    seed_runtime_queues(&tc_skel, config, &reserved);

    // ── XDP nat4: reuse the TC-owned nat_v4 maps ──

    let xdp_builder = XdpNat4V4SkelBuilder::default();
    let (xdp_backing, xdp_obj) = OwnedOpenObject::new();
    let mut xdp_open = bpf_ctx!(xdp_builder.open(xdp_obj), "open xdp_nat4_v4 skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path()
        ),
        "xdp_nat4_v4 pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path()),
        "xdp_nat4_v4 pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path()),
        "xdp_nat4_v4 pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_nat4_v4 pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        xdp_open.maps.napt_udp_ports.reuse_fd(tc_skel.maps.napt_udp_ports.as_fd()),
        "xdp_nat4_v4 reuse napt_udp_ports"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.napt_tcp_ports.reuse_fd(tc_skel.maps.napt_tcp_ports.as_fd()),
        "xdp_nat4_v4 reuse napt_tcp_ports"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.napt_icmp_ids.reuse_fd(tc_skel.maps.napt_icmp_ids.as_fd()),
        "xdp_nat4_v4 reuse napt_icmp_ids"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.napt_from_lan.reuse_fd(tc_skel.maps.napt_from_lan.as_fd()),
        "xdp_nat4_v4 reuse napt_from_lan"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.napt_from_wan.reuse_fd(tc_skel.maps.napt_from_wan.as_fd()),
        "xdp_nat4_v4 reuse napt_from_wan"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.napt_ct.reuse_fd(tc_skel.maps.napt_ct.as_fd()),
        "xdp_nat4_v4 reuse napt_ct"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.frag4_cache_lan.reuse_fd(tc_skel.maps.frag4_cache_lan.as_fd()),
        "xdp_nat4_v4 reuse frag4_cache_lan"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.frag4_cache_wan.reuse_fd(tc_skel.maps.frag4_cache_wan.as_fd()),
        "xdp_nat4_v4 reuse frag4_cache_wan"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat_metric_events.reuse_fd(tc_skel.maps.nat_metric_events.as_fd()),
        "xdp_nat4_v4 reuse nat_metric_events"
    )?;

    {
        let xdp_rodata =
            xdp_open.maps.rodata_data.as_deref_mut().expect("xdp_nat4_v4 rodata not memory mapped");
        xdp_rodata.current_ifindex = ifindex;
        xdp_rodata.current_l3_offset = if has_eth_header { 14 } else { 0 };
        xdp_rodata.land_nat_external_addr = wan_ro_addr4(wan_addr);
    }

    let xdp_skel = bpf_ctx!(xdp_open.load(), "load xdp_nat4_v4 skeleton")?;

    dp.tc().inject_from_wan(
        FromWanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: tc_skel.progs.tc_v4_from_wan.as_fd().as_raw_fd(),
            next_stage_map_fd: tc_skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        },
    )?;
    dp.tc().inject_from_lan(
        FromLanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: tc_skel.progs.tc_v4_from_lan.as_fd().as_raw_fd(),
            next_stage_map_fd: tc_skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        },
    )?;

    let next_stage_fd = xdp_skel.maps.next_stage.as_fd().as_raw_fd();
    dp.xdp().inject_from_wan(
        FromWanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: xdp_skel.progs.ingress_nat_v4_v4.as_fd().as_raw_fd(),
            next_stage_map_fd: next_stage_fd,
        },
    )?;
    dp.xdp().inject_from_lan(
        FromLanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: xdp_skel.progs.egress_nat_v4_v4.as_fd().as_raw_fd(),
            next_stage_map_fd: next_stage_fd,
        },
    )?;

    Ok(Nat4Handle {
        dp: dp.clone(),
        _tc_skel: tc_skel,
        _xdp_skel: xdp_skel,
        _tc_backing: backing,
        _xdp_backing: xdp_backing,
    })
}
