use std::path::{Path, PathBuf};

use landscape_common::args::LAND_ARGS;
use once_cell::sync::Lazy;

pub mod bpf_error;
pub(crate) mod bpf_rs_shared;
pub mod dns_result_sink;
pub mod flow_socket_registrar;
pub mod landscape;
pub mod maps;
pub mod metric;
pub mod pppoe;
pub mod stages;
pub mod tproxy;

#[cfg(test)]
mod tests;

pub mod chain;
pub mod dns_dispatcher;

static MAP_PATHS: Lazy<LandscapeMapPath> = Lazy::new(|| {
    let ebpf_map_space = &LAND_ARGS.ebpf_map_space;
    tracing::info!("ebpf_map_space is: {ebpf_map_space}");
    let ebpf_map_path = format!("/sys/fs/bpf/landscape/{}", ebpf_map_space);
    if !PathBuf::from(&ebpf_map_path).exists() {
        if let Err(e) = std::fs::create_dir_all(&ebpf_map_path) {
            panic!("can not create bpf map path: {ebpf_map_path:?}, err: {e:?}");
        }
    }
    let paths = LandscapeMapPath::from_root(Path::new(&ebpf_map_path));
    tracing::info!("ebpf map paths is: {paths:#?}");
    maps::init_path(&paths);
    paths
});

#[derive(Clone, Debug)]
pub(crate) struct LandscapeMapPath {
    pub wan_ip: PathBuf,
    // NAT
    pub nat6_static_map: PathBuf,
    pub nat4_static_map: PathBuf,

    // 防火墙黑名单
    pub firewall_ipv4_block: PathBuf,
    pub firewall_ipv6_block: PathBuf,

    /// Flow
    pub flow_match_map: PathBuf,

    /// DNS Socket fd <=> Flow ID
    pub dns_flow_socks: PathBuf,

    pub nat_metric_events: PathBuf,
    pub firewall_conn_metric_events: PathBuf,

    /// route - LAN
    pub rt4_lan_map: PathBuf,
    pub rt4_target_slot_map: PathBuf,
    pub flow4_dns_map: PathBuf,
    pub flow4_ip_map: PathBuf,

    pub rt6_lan_map: PathBuf,
    pub rt6_target_slot_map: PathBuf,
    pub flow6_dns_map: PathBuf,
    pub flow6_ip_map: PathBuf,

    pub rt4_cache_map: PathBuf,
    pub rt6_cache_map: PathBuf,

    // IP MAC
    pub ip_mac_v4: PathBuf,
    pub ip_mac_v6: PathBuf,

    /// DAD NS learning ringbuf
    pub ip6_dao_events: PathBuf,

    pub xdp_redirect_able: PathBuf,
    pub xdp_base: PathBuf,
}

impl LandscapeMapPath {
    /// Build every shared-map pin path under `root`.
    ///
    /// Pin file names are the per-domain `*_PIN` constants, which are also
    /// referenced by the corresponding `MapCreateSpec.name`, so production
    /// paths, skeleton pin reuse and tests all share one source of truth.
    pub(crate) fn from_root(root: &Path) -> Self {
        use crate::maps::{
            dns, firewall, flow, flow_dns, flow_wanip, mac, nat, redirect_able, route, wan,
        };

        Self {
            wan_ip: root.join(wan::WAN_IP_BINDING_PIN),
            // NAT
            nat6_static_map: root.join(nat::NAT6_STATIC_MAP_PIN),
            nat4_static_map: root.join(nat::NAT4_STATIC_MAP_PIN),

            // 防火墙黑名单
            firewall_ipv4_block: root.join(firewall::FIREWALL_BLOCK_IP4_MAP_PIN),
            firewall_ipv6_block: root.join(firewall::FIREWALL_BLOCK_IP6_MAP_PIN),

            // Flow
            flow_match_map: root.join(flow::FLOW_MATCH_MAP_PIN),

            // DNS Socket fd <=> Flow ID
            dns_flow_socks: root.join(dns::DNS_FLOW_SOCKS_PIN),

            nat_metric_events: root.join(nat::NAT_METRIC_EVENTS_PIN),
            firewall_conn_metric_events: root.join(firewall::FIREWALL_CONN_METRIC_EVENTS_PIN),

            // route - LAN
            rt4_lan_map: root.join(route::RT4_LAN_MAP_PIN),
            rt4_target_slot_map: root.join(route::RT4_TARGET_SLOT_MAP_PIN),
            flow4_dns_map: root.join(flow_dns::FLOW4_DNS_MAP_PIN),
            flow4_ip_map: root.join(flow_wanip::FLOW4_IP_MAP_PIN),

            rt6_lan_map: root.join(route::RT6_LAN_MAP_PIN),
            rt6_target_slot_map: root.join(route::RT6_TARGET_SLOT_MAP_PIN),
            flow6_dns_map: root.join(flow_dns::FLOW6_DNS_MAP_PIN),
            flow6_ip_map: root.join(flow_wanip::FLOW6_IP_MAP_PIN),

            rt4_cache_map: root.join(route::RT4_CACHE_MAP_PIN),
            rt6_cache_map: root.join(route::RT6_CACHE_MAP_PIN),

            // IP MAC
            ip_mac_v4: root.join(mac::IP_MAC_V4_PIN),
            ip_mac_v6: root.join(mac::IP_MAC_V6_PIN),

            // DAD NS learning ringbuf
            ip6_dao_events: root.join(mac::IP6_DAO_EVENTS_PIN),

            xdp_redirect_able: root.join(redirect_able::XDP_REDIRECT_ABLE_PIN),
            xdp_base: root.join("xdp"),
        }
    }
}

// Fire wall -> nat -> pppoe
// const PPPOE_MTU_FILTER_EGRESS_PRIORITY: u32 = 1;
const PPPOE_EGRESS_PRIORITY: u32 = 2;

// LAN ingress TC classifier priorities (smaller runs first)
pub(crate) const TC_LAN_INGRESS_INTRO_PRIORITY: u32 = 1;
pub(crate) const TC_LAN_INGRESS_DAO_PRIORITY: u32 = 2;

// const FLOW_EGRESS_PRIORITY: u32 = 4;
const LANDSCAPE_IPV4_TYPE: u8 = 0;
const LANDSCAPE_IPV6_TYPE: u8 = 1;

const NAT_MAPPING_INGRESS: u8 = 0;
const NAT_MAPPING_EGRESS: u8 = 1;

fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit { rlim_cur: 1024 << 20, rlim_max: 1024 << 20 };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        tracing::error!("Failed to increase rlimit");
    }
}

pub fn setting_libbpf_log() {
    bump_memlock_rlimit();
    use libbpf_rs::PrintLevel;
    use tracing::{debug, info, span, warn};
    libbpf_rs::set_print(Some((PrintLevel::Debug, |level, msg| {
        let span = span!(tracing::Level::ERROR, "libbpf-rs");
        let _enter = span.enter();

        let msg = msg.trim_start_matches("libbpf: ").trim_end_matches('\n');

        match level {
            PrintLevel::Info => info!("{}", msg),
            PrintLevel::Warn => warn!("{}", msg),
            PrintLevel::Debug => debug!("{}", msg),
        }
    })));
}
