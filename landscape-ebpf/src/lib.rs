use std::path::PathBuf;

use landscape_common::args::LAND_ARGS;
use once_cell::sync::Lazy;

pub mod landscape;
pub mod map_setting;
pub mod nat;
pub mod ns_proxy;
pub mod packet_mark;
pub mod pppoe;
pub mod tproxy;

static MAP_PATHS: Lazy<LandscapeMapPath> = Lazy::new(|| {
    let ebpf_map_space = &LAND_ARGS.ebpf_map_space;
    let ebpf_map_path = format!("/sys/fs/bpf/landscape/{}", ebpf_map_space);
    if !PathBuf::from(&ebpf_map_path).exists() {
        if let Err(e) = std::fs::create_dir_all(&ebpf_map_path) {
            panic!("can not create bpf map path: {ebpf_map_path:?}, err: {e:?}");
        }
    }
    let paths = LandscapeMapPath {
        wan_ip: PathBuf::from(format!("{}/wan_ipv4_binding", ebpf_map_path)),
        static_nat_mappings: PathBuf::from(format!("{}/nat_static_mapping", ebpf_map_path)),
        // block_ip: PathBuf::from(format!("{}/firewall_block_map", ebpf_map_path)),
        lanip_mark: PathBuf::from(format!("{}/lanip_mark_map", ebpf_map_path)),
        wanip_mark: PathBuf::from(format!("{}/wanip_mark_map", ebpf_map_path)),
        packet_mark: PathBuf::from(format!("{}/packet_mark_map", ebpf_map_path)),
        redirect_index: PathBuf::from(format!("{}/redirect_index_map", ebpf_map_path)),
    };
    map_setting::init_path(paths.clone());
    paths
});

#[derive(Clone)]
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
}

// pppoe -> Fire wall -> nat
const PPPOE_INGRESS_PRIORITY: u32 = 1;
const FIREWALL_INGRESS_PRIORITY: u32 = 2;
const NAT_INGRESS_PRIORITY: u32 = 3;

// Fire wall -> nat -> pppoe
// const PPPOE_MTU_FILTER_EGRESS_PRIORITY: u32 = 1;
const FIREWALL_EGRESS_PRIORITY: u32 = 2;
const NAT_EGRESS_PRIORITY: u32 = 3;
const PPPOE_EGRESS_PRIORITY: u32 = 4;
pub fn init_ebpf() {
    std::thread::spawn(|| {
        landscape::test();
    });
}
