use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use landscape_common::wan_service::nat::config::NatConfig;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::wan_link::WanLinkDataplane;

// ========================================================================
// v4 NAT stage — TC (map owner) + XDP (FD borrower)
// ========================================================================

pub(crate) mod tc_nat4_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_nat4.skel.rs"));
}

/// Bake value for the `wan_ro_addr4` rodata field shared by the nat4 objects.
///
/// The BPF side treats it as a network-order `__be32` (same convention as the
/// old `wan_ip_binding` map values) — this is the single place that knows the
/// conversion; all loaders and tests go through it.
pub(crate) fn wan_ro_addr4(wan_addr: Ipv4Addr) -> u32 {
    wan_addr.to_bits().to_be()
}

pub(crate) mod xdp_nat4_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat4.skel.rs"));
}

/// The v4 NAT stage: TC ingress/egress + XDP LAN/WAN with shared runtime
/// maps (dynamic NAT state, conntrack timers, port queues).
pub struct Nat4Handle {
    pub tc: TcNat4Handle,
    pub xdp: XdpNat4Handle,
}

pub struct TcNat4Handle {
    dp: Arc<WanLinkDataplane>,
    _skel: tc_nat4_skel::TcNat4Skel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
}

impl Drop for TcNat4Handle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        self.dp.tc().remove_from_wan(FromWanStageType::Nat, StageFamily::V4);
        self.dp.tc().remove_from_lan(FromLanStageType::Nat, StageFamily::V4);
    }
}

pub struct XdpNat4Handle {
    dp: Arc<WanLinkDataplane>,
    _skel: xdp_nat4_skel::XdpNat4Skel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
}

unsafe impl Send for XdpNat4Handle {}
unsafe impl Sync for XdpNat4Handle {}

impl Drop for XdpNat4Handle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        self.dp.xdp().remove_from_wan(FromWanStageType::Nat, StageFamily::V4);
        self.dp.xdp().remove_from_lan(FromLanStageType::Nat, StageFamily::V4);
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16)
where
    M: libbpf_rs::MapCore,
{
    let fd = map.as_fd().as_raw_fd();
    for port in start..=end {
        let value = tc_nat4_skel::types::nat4_port_queue_value_v3 {
            port: port.to_be(),
            last_generation: 0,
        };
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                fd,
                std::ptr::null(),
                (&value as *const tc_nat4_skel::types::nat4_port_queue_value_v3).cast_mut().cast(),
                0,
            )
        };
        if ret != 0 {
            break;
        }
    }
}

fn seed_runtime_queues<M1, M2, M3>(
    tcp_queue: &M1,
    udp_queue: &M2,
    icmp_queue: &M3,
    config: &NatConfig,
) where
    M1: libbpf_rs::MapCore,
    M2: libbpf_rs::MapCore,
    M3: libbpf_rs::MapCore,
{
    seed_port_queue(tcp_queue, config.tcp_range.start, config.tcp_range.end);
    seed_port_queue(udp_queue, config.udp_range.start, config.udp_range.end);
    seed_port_queue(icmp_queue, config.icmp_in_range.start, config.icmp_in_range.end);
}

// ========================================================================
// v4 NAT (ingress + egress, TC owns the runtime maps, XDP borrows them)
// ========================================================================

pub fn attach_nat4(
    dp: &Arc<WanLinkDataplane>,
    ifindex: u32,
    has_eth_header: bool,
    config: &NatConfig,
    wan_addr: Ipv4Addr,
) -> LdEbpfResult<Nat4Handle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = dp.backbone().paths();

    // ── 1. Load TC nat4 first (ingress + egress, for runtime map sharing with XDP) ──

    let tc_builder = tc_nat4_skel::TcNat4SkelBuilder::default();
    let (tc_backing, tc_obj) = OwnedOpenObject::new();
    let mut tc_open = bpf_ctx!(tc_builder.open(tc_obj), "open tc_nat4 skeleton")?;

    let tc_rodata = tc_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memory mapped");
    tc_rodata.current_l3_offset = if has_eth_header { 14 } else { 0 };
    tc_rodata.wan_ro_addr4 = wan_ro_addr4(wan_addr);
    tc_rodata.tcp_range_start = config.tcp_range.start;
    tc_rodata.tcp_range_end = config.tcp_range.end;
    tc_rodata.udp_range_start = config.udp_range.start;
    tc_rodata.udp_range_end = config.udp_range.end;
    tc_rodata.icmp_range_start = config.icmp_in_range.start;
    tc_rodata.icmp_range_end = config.icmp_in_range.end;

    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_egress,
        &paths.tc_pipe_exits_wan_egress_path(),
    )?;
    pin_and_reuse_map(&mut tc_open.maps.nat4_static_map, &paths.nat4_static_map)?;
    pin_and_reuse_map(&mut tc_open.maps.nat_metric_events, &paths.nat_metric_events)?;

    let tc_skel = bpf_ctx!(tc_open.load(), "load tc_nat4 skeleton")?;

    seed_runtime_queues(
        &tc_skel.maps.nat4_tcp_port_queue,
        &tc_skel.maps.nat4_udp_port_queue,
        &tc_skel.maps.nat4_icmp_port_queue,
        config,
    );

    // ── 2. Open XDP nat4, reuse TC's runtime map FDs ──

    let xdp_builder = xdp_nat4_skel::XdpNat4SkelBuilder::default();
    let (xdp_backing, xdp_obj) = OwnedOpenObject::new();
    let mut xdp_open = bpf_ctx!(xdp_builder.open(xdp_obj), "open xdp_nat4 skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path()
        ),
        "xdp_nat4 pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path()),
        "xdp_nat4 pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path()),
        "xdp_nat4 pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_nat4 pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat4_static_map, &paths.nat4_static_map),
        "xdp_nat4 pin nat4_static_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat_metric_events, &paths.nat_metric_events,),
        "xdp_nat4 pin nat_metric_events"
    )?;

    // Reuse TC's runtime map FDs in XDP (FD sharing, no pinning)
    crate::bpf_ctx!(
        xdp_open.maps.nat4_ingress_dyn_map.reuse_fd(tc_skel.maps.nat4_ingress_dyn_map.as_fd()),
        "xdp_nat4 reuse nat4_ingress_dyn_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_egress_dyn_map.reuse_fd(tc_skel.maps.nat4_egress_dyn_map.as_fd()),
        "xdp_nat4 reuse nat4_egress_dyn_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_timer_map.reuse_fd(tc_skel.maps.nat4_timer_map.as_fd()),
        "xdp_nat4 reuse nat4_timer_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_tcp_port_queue.reuse_fd(tc_skel.maps.nat4_tcp_port_queue.as_fd()),
        "xdp_nat4 reuse nat4_tcp_port_queue fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_udp_port_queue.reuse_fd(tc_skel.maps.nat4_udp_port_queue.as_fd()),
        "xdp_nat4 reuse nat4_udp_port_queue fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_icmp_port_queue.reuse_fd(tc_skel.maps.nat4_icmp_port_queue.as_fd()),
        "xdp_nat4 reuse nat4_icmp_port_queue fd"
    )?;

    {
        let xdp_rodata =
            xdp_open.maps.rodata_data.as_deref_mut().expect("xdp_nat4 rodata not memory mapped");
        xdp_rodata.current_ifindex = ifindex;
        xdp_rodata.wan_ro_addr4 = wan_ro_addr4(wan_addr);
        xdp_rodata.tcp_range_start = config.tcp_range.start;
        xdp_rodata.tcp_range_end = config.tcp_range.end;
        xdp_rodata.udp_range_start = config.udp_range.start;
        xdp_rodata.udp_range_end = config.udp_range.end;
        xdp_rodata.icmp_range_start = config.icmp_in_range.start;
        xdp_rodata.icmp_range_end = config.icmp_in_range.end;
    }

    let xdp_skel = bpf_ctx!(xdp_open.load(), "load xdp_nat4 skeleton")?;

    // ── 3. Inject into the link's chain ──

    dp.tc().inject_from_wan(
        FromWanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: tc_skel.progs.tc_nat_wan_ingress_v4.as_fd().as_raw_fd(),
            next_stage_map_fd: tc_skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        },
    )?;
    dp.tc().inject_from_lan(
        FromLanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: tc_skel.progs.tc_nat_wan_egress_v4.as_fd().as_raw_fd(),
            next_stage_map_fd: tc_skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        },
    )?;

    let next_stage_fd = xdp_skel.maps.next_stage.as_fd().as_raw_fd();
    dp.xdp().inject_from_wan(
        FromWanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: xdp_skel.progs.ingress_nat_v4.as_fd().as_raw_fd(),
            next_stage_map_fd: next_stage_fd,
        },
    )?;
    dp.xdp().inject_from_lan(
        FromLanStageType::Nat,
        StageFamily::V4,
        FamilyProg {
            prog_fd: xdp_skel.progs.egress_nat_v4.as_fd().as_raw_fd(),
            next_stage_map_fd: next_stage_fd,
        },
    )?;

    Ok(Nat4Handle {
        tc: TcNat4Handle {
            dp: dp.clone(),
            _skel: tc_skel,
            _backing: tc_backing,
        },
        xdp: XdpNat4Handle {
            dp: dp.clone(),
            _skel: xdp_skel,
            _backing: xdp_backing,
        },
    })
}
