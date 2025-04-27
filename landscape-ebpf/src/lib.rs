use std::path::PathBuf;

use landscape_common::args::LAND_ARGS;
use once_cell::sync::Lazy;

pub mod bpf_error;
pub mod firewall;
pub mod flow;
pub mod landscape;
pub mod map_setting;
pub mod nat;
pub mod ns_proxy;
pub mod packet_mark;
pub mod pppoe;
pub mod tproxy;

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
        wan_ip: PathBuf::from(format!("{}/wan_ipv4_binding", ebpf_map_path)),
        static_nat_mappings: PathBuf::from(format!("{}/nat_static_mapping", ebpf_map_path)),
        lanip_mark: PathBuf::from(format!("{}/lanip_mark_map", ebpf_map_path)),
        wanip_mark: PathBuf::from(format!("{}/wanip_mark_map", ebpf_map_path)),
        packet_mark: PathBuf::from(format!("{}/packet_mark_map", ebpf_map_path)),
        redirect_index: PathBuf::from(format!("{}/redirect_index_map", ebpf_map_path)),

        firewall_ipv4_block: PathBuf::from(format!("{}/firewall_block_ip4_map", ebpf_map_path)),
        firewall_ipv6_block: PathBuf::from(format!("{}/firewall_block_ip6_map", ebpf_map_path)),
        firewall_allow_rules_map: PathBuf::from(format!(
            "{}/firewall_allow_rules_map",
            ebpf_map_path
        )),
        flow_verdict_dns_map: PathBuf::from(format!("{}/flow_verdict_dns_map", ebpf_map_path)),
        flow_verdict_dns_map_test: PathBuf::from(format!(
            "{}/flow_verdict_dns_map_test",
            ebpf_map_path
        )),
        flow_verdict_ip_map: PathBuf::from(format!("{}/flow_verdict_ip_map", ebpf_map_path)),
        flow_match_map: PathBuf::from(format!("{}/flow_match_map", ebpf_map_path)),
        flow_target_map: PathBuf::from(format!("{}/flow_target_map", ebpf_map_path)),
    };
    tracing::info!("ebpf map paths is: {paths:#?}");
    map_setting::init_path(paths.clone());
    paths
});

#[derive(Clone, Debug)]
pub(crate) struct LandscapeMapPath {
    pub wan_ip: PathBuf,
    pub static_nat_mappings: PathBuf,
    // pub block_ip: PathBuf,
    pub packet_mark: PathBuf,

    // LAN IP 标记
    pub lanip_mark: PathBuf,
    /// WAN IP 标记
    pub wanip_mark: PathBuf,

    pub redirect_index: PathBuf,

    // 防火墙黑名单
    pub firewall_ipv4_block: PathBuf,
    pub firewall_ipv6_block: PathBuf,
    // 允许通过的协议
    pub firewall_allow_rules_map: PathBuf,

    /// Flow
    pub flow_verdict_dns_map: PathBuf,
    pub flow_verdict_dns_map_test: PathBuf,
    pub flow_verdict_ip_map: PathBuf,
    pub flow_match_map: PathBuf,
    /// 存储 flow 目标的主机
    pub flow_target_map: PathBuf,
}

// pppoe -> Fire wall -> nat
const PPPOE_INGRESS_PRIORITY: u32 = 1;
const FIREWALL_INGRESS_PRIORITY: u32 = 2;
const MARK_INGRESS_PRIORITY: u32 = 3;
const NAT_INGRESS_PRIORITY: u32 = 4;

// Fire wall -> nat -> pppoe
// const PPPOE_MTU_FILTER_EGRESS_PRIORITY: u32 = 1;
const FLOW_EGRESS_PRIORITY: u32 = 2;
const MARK_EGRESS_PRIORITY: u32 = 3;
const NAT_EGRESS_PRIORITY: u32 = 4;
const FIREWALL_EGRESS_PRIORITY: u32 = 5;
const PPPOE_EGRESS_PRIORITY: u32 = 6;

// MARK ->
const LAN_FLOW_MARK_INGRESS_PRIORITY: u32 = 2;
// MARK ->
const LAN_FLOW_MARK_EGRESS_PRIORITY: u32 = 2;

const LANDSCAPE_IPV4_TYPE: u8 = 0;
const LANDSCAPE_IPV6_TYPE: u8 = 1;

pub fn init_ebpf() {
    std::thread::spawn(|| {
        landscape::test();
    });
}

pub fn setting_libbpf_log() {
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
