use std::path::PathBuf;

use landscape_common::args::LAND_ARGS;
use once_cell::sync::Lazy;

pub mod base;
pub mod bpf_error;
pub mod firewall;
pub mod landscape;
pub mod map_setting;
pub mod metric;
pub mod mss_clamp;
pub mod nat;
pub(crate) mod pipeline;
pub mod pppoe;
pub mod route;
pub mod tproxy;

#[cfg(test)]
mod tests;

pub mod dns_dispatcher;
pub mod xdp;

static MAP_PATHS: Lazy<LandscapeMapPath> = Lazy::new(|| {
    let ebpf_map_space = &LAND_ARGS.ebpf_map_space;
    tracing::info!("ebpf_map_space is: {ebpf_map_space}");
    let ebpf_map_path = format!("/sys/fs/bpf/landscape/{}", ebpf_map_space);
    if !PathBuf::from(&ebpf_map_path).exists() {
        if let Err(e) = std::fs::create_dir_all(&ebpf_map_path) {
            panic!("can not create bpf map path: {ebpf_map_path:?}, err: {e:?}");
        }
    }
    let paths = LandscapeMapPath {
        wan_ip: PathBuf::from(format!("{}/wan_ip_binding", ebpf_map_path)),
        nat6_static_mappings: PathBuf::from(format!("{}/nat_static_mapping", ebpf_map_path)),
        nat4_st_map: PathBuf::from(format!("{}/nat4_st_map", ebpf_map_path)),

        firewall_ipv4_block: PathBuf::from(format!("{}/firewall_block_ip4_map", ebpf_map_path)),
        firewall_ipv6_block: PathBuf::from(format!("{}/firewall_block_ip6_map", ebpf_map_path)),
        firewall_allow_rules_map: PathBuf::from(format!(
            "{}/firewall_allow_rules_map",
            ebpf_map_path
        )),
        // DNS
        dns_flow_socks: PathBuf::from(format!("{}/dns_flow_socks", ebpf_map_path)),
        // metric
        metric_map: PathBuf::from(format!("{}/metric_map", ebpf_map_path)),

        // nat_conn_events: PathBuf::from(format!("{}/nat_conn_events", ebpf_map_path)),
        nat_conn_metric_events: PathBuf::from(format!("{}/nat_conn_metric_events", ebpf_map_path)),

        // firewall_conn_events: PathBuf::from(format!("{}/firewall_conn_events", ebpf_map_path)),
        firewall_conn_metric_events: PathBuf::from(format!(
            "{}/firewall_conn_metric_events",
            ebpf_map_path
        )),

        flow_match_map: PathBuf::from(format!("{}/flow_match_map", ebpf_map_path)),
        // route
        // v4 version map path
        rt4_lan_map: PathBuf::from(format!("{}/rt4_lan_map", ebpf_map_path)),
        rt4_target_slot_map: PathBuf::from(format!("{}/rt4_target_slot_map", ebpf_map_path)),
        flow4_dns_map: PathBuf::from(format!("{}/flow4_dns_map", ebpf_map_path)),
        flow4_ip_map: PathBuf::from(format!("{}/flow4_ip_map", ebpf_map_path)),

        rt6_lan_map: PathBuf::from(format!("{}/rt6_lan_map", ebpf_map_path)),
        rt6_target_slot_map: PathBuf::from(format!("{}/rt6_target_slot_map", ebpf_map_path)),
        flow6_dns_map: PathBuf::from(format!("{}/flow6_dns_map", ebpf_map_path)),
        flow6_ip_map: PathBuf::from(format!("{}/flow6_ip_map", ebpf_map_path)),

        rt4_cache_map: PathBuf::from(format!("{}/rt4_cache_map", ebpf_map_path)),
        rt6_cache_map: PathBuf::from(format!("{}/rt6_cache_map", ebpf_map_path)),

        wan_tc_pipeline_ingress: PathBuf::from(format!(
            "{}/wan_tc_pipeline_ingress",
            ebpf_map_path
        )),
        wan_tc_pipeline_egress: PathBuf::from(format!("{}/wan_tc_pipeline_egress", ebpf_map_path)),
        lan_tc_pipeline_ingress: PathBuf::from(format!(
            "{}/lan_tc_pipeline_ingress",
            ebpf_map_path
        )),
        lan_tc_pipeline_egress: PathBuf::from(format!("{}/lan_tc_pipeline_egress", ebpf_map_path)),

        ip_mac_v4: PathBuf::from(format!("{}/ip_mac_v4", ebpf_map_path)),
        ip_mac_v6: PathBuf::from(format!("{}/ip_mac_v6", ebpf_map_path)),

        xdp_base: PathBuf::from(format!("{}/xdp", ebpf_map_path)),
    };
    tracing::info!("ebpf map paths is: {paths:#?}");
    map_setting::init_path(&paths);
    paths
});

#[derive(Clone, Debug)]
pub(crate) struct LandscapeMapPath {
    pub wan_ip: PathBuf,
    // NAT
    pub nat6_static_mappings: PathBuf,
    pub nat4_st_map: PathBuf,

    // 防火墙黑名单
    pub firewall_ipv4_block: PathBuf,
    pub firewall_ipv6_block: PathBuf,
    // 允许通过的协议
    pub firewall_allow_rules_map: PathBuf,

    /// Flow
    pub flow_match_map: PathBuf,

    /// DNS Socket fd <=> Flow ID
    pub dns_flow_socks: PathBuf,

    /// metric
    pub metric_map: PathBuf,
    pub nat_conn_metric_events: PathBuf,
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

    pub wan_tc_pipeline_ingress: PathBuf,
    pub wan_tc_pipeline_egress: PathBuf,
    pub lan_tc_pipeline_ingress: PathBuf,
    pub lan_tc_pipeline_egress: PathBuf,

    // IP MAC
    pub ip_mac_v4: PathBuf,
    pub ip_mac_v6: PathBuf,

    pub xdp_base: PathBuf,
}

const WAN_ROUTE_INGRESS_PRIORITY: u32 = 7;

// Fire wall -> nat -> pppoe
// const PPPOE_MTU_FILTER_EGRESS_PRIORITY: u32 = 1;
const WAN_ROUTE_EGRESS_PRIORITY: u32 = 3;

// const FLOW_EGRESS_PRIORITY: u32 = 4;
const PPPOE_EGRESS_PRIORITY: u32 = 8;

// lAN PRIORITY
const LAN_ROUTE_INGRESS_PRIORITY: u32 = 2;

const LAN_ROUTE_EGRESS_PRIORITY: u32 = 2;

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
