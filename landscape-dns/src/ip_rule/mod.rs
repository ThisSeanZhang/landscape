use std::net::IpAddr;
use std::path::PathBuf;
use std::{collections::HashMap, net::Ipv4Addr};

use landscape_common::ip_mark::{IpConfig, IpMarkInfo, LanIPRuleConfig, WanIPRuleConfig};
use landscape_common::mark::PacketMark;

use crate::protos::geo::GeoIPListOwned;

// 更新新的文件
fn convert_mark_map_to_vec_mark(value: HashMap<IpConfig, PacketMark>) -> Vec<IpMarkInfo> {
    let mut result = Vec::with_capacity(value.len());
    for (cidr, mark) in value.into_iter() {
        result.push(IpMarkInfo { mark, cidr });
    }
    result
}

pub fn update_lan_rules(mut rules: Vec<LanIPRuleConfig>, mut old_rules: Vec<LanIPRuleConfig>) {
    rules.sort_by(|a, b| a.index.cmp(&b.index));
    old_rules.sort_by(|a, b| a.index.cmp(&b.index));
    let mut rules = lan_mark_into_map(rules);
    let old_rules = lan_mark_into_map(old_rules);

    let delete_keys = find_delete_rule_keys(&mut rules, old_rules);

    landscape_ebpf::map_setting::add_lan_ip_mark(convert_mark_map_to_vec_mark(rules));
    landscape_ebpf::map_setting::del_lan_ip_mark(delete_keys);
}

pub async fn update_wan_rules(
    mut rules: Vec<WanIPRuleConfig>,
    mut old_rules: Vec<WanIPRuleConfig>,
    new_path: PathBuf,
    old_path: Option<PathBuf>,
) {
    rules.sort_by(|a, b| a.index.cmp(&b.index));
    old_rules.sort_by(|a, b| a.index.cmp(&b.index));
    let old_path = if let Some(old_path) = old_path { old_path } else { new_path.clone() };
    tracing::debug!("path: {:?} / {:?}", new_path, old_path);
    let mut rules = wan_mark_into_map(rules, new_path).await;
    let old_rules = wan_mark_into_map(old_rules, old_path).await;
    tracing::debug!("rules: {:?}", rules);
    tracing::debug!("old_rules: {:?}", old_rules);

    let delete_keys = find_delete_rule_keys(&mut rules, old_rules);
    tracing::debug!("update_config: {:?}", rules);
    tracing::debug!("delete_keys: {:?}", delete_keys);

    landscape_ebpf::map_setting::add_wan_ip_mark(convert_mark_map_to_vec_mark(rules));
    landscape_ebpf::map_setting::del_wan_ip_mark(delete_keys);
}

fn lan_mark_into_map(rules: Vec<LanIPRuleConfig>) -> HashMap<IpConfig, PacketMark> {
    let mut new_mark_infos = HashMap::new();

    for ip_rule in rules.into_iter() {
        if !ip_rule.enable {
            continue;
        }
        for each_cidr in ip_rule.source.into_iter() {
            new_mark_infos.insert(each_cidr, ip_rule.mark);
        }
    }
    new_mark_infos
}

async fn wan_mark_into_map(
    rules: Vec<WanIPRuleConfig>,
    geo_file_path: PathBuf,
) -> HashMap<IpConfig, PacketMark> {
    let country_code_map = get_geo_ip_map(geo_file_path).await;
    let mut new_mark_infos = HashMap::new();
    for ip_rule in rules.into_iter() {
        if !ip_rule.enable {
            continue;
        }
        let mut source = Vec::with_capacity(ip_rule.source.len());
        for src in ip_rule.source.into_iter() {
            match src {
                landscape_common::ip_mark::WanIPRuleSource::GeoKey { country_code } => {
                    let Some(data) = country_code_map.get(&country_code) else {
                        continue;
                    };
                    source.extend_from_slice(data);
                }
                landscape_common::ip_mark::WanIPRuleSource::Config(ip_config) => {
                    source.push(ip_config);
                }
            };
        }

        for each_cidr in source.into_iter() {
            new_mark_infos.insert(each_cidr, ip_rule.mark);
        }
    }
    new_mark_infos
}

// pub fn init_lan_mark_ips(rules: Vec<LanIPRuleConfig>) {
//     let mut new_mark_infos = HashMap::new();

//     for ip_rule in rules.into_iter() {
//         if !ip_rule.enable {
//             continue;
//         }
//         for each_cidr in ip_rule.source.into_iter() {
//             new_mark_infos.insert(each_cidr, ip_rule.mark);
//         }
//     }

//     landscape_ebpf::map_setting::add_lan_ip_mark(convert_mark_map_to_vec_mark(new_mark_infos));
// }

// pub async fn init_wan_mark_ips(rules: Vec<WanIPRuleConfig>) {
//     let geo_file_path = LAND_HOME_PATH.join(GEO_IP_FILE_NAME);
//     let country_code_map = get_geo_ip_map(geo_file_path).await;
//     let mut new_mark_infos = HashMap::new();
//     for ip_rule in rules.into_iter() {
//         if !ip_rule.enable {
//             continue;
//         }
//         let mut source = Vec::with_capacity(ip_rule.source.len());
//         for src in ip_rule.source.into_iter() {
//             match src {
//                 landscape_common::ip_mark::WanIPRuleSource::GeoKey { country_code } => {
//                     let Some(data) = country_code_map.get(&country_code) else {
//                         continue;
//                     };
//                     source.extend_from_slice(data);
//                 }
//                 landscape_common::ip_mark::WanIPRuleSource::Config(ip_config) => {
//                     source.push(ip_config);
//                 }
//             };
//         }

//         for each_cidr in source.into_iter() {
//             new_mark_infos.insert(each_cidr, ip_rule.mark);
//         }
//     }

//     landscape_ebpf::map_setting::add_wan_ip_mark(convert_mark_map_to_vec_mark(new_mark_infos));
// }

fn find_delete_rule_keys(
    new_rules: &mut HashMap<IpConfig, PacketMark>,
    old_rules: HashMap<IpConfig, PacketMark>,
) -> Vec<IpConfig> {
    let mut delete_keys = vec![];
    for (key, old_mark) in old_rules.into_iter() {
        if let Some(mark) = new_rules.get(&key) {
            if *mark == old_mark {
                new_rules.remove(&key);
            } else {
                continue;
            }
        } else {
            delete_keys.push(key);
        }
    }
    delete_keys
}

pub async fn get_geo_ip_map(geo_file_path: PathBuf) -> HashMap<String, Vec<IpConfig>> {
    let mut result = HashMap::new();
    if geo_file_path.exists() && geo_file_path.is_file() {
        // 读取文件并解析为 Owned 结构体
        let data = tokio::fs::read(geo_file_path).await.unwrap();
        let list = GeoIPListOwned::try_from(data).unwrap();

        for entry in list.entry.iter() {
            let domains = entry.cidr.iter().filter_map(convert_ipconfig_from_proto).collect();
            result.insert(entry.country_code.to_string(), domains);
        }
    } else {
        tracing::error!("geo file don't exists or not a file, return empty map");
    }

    result
}

pub fn convert_ipconfig_from_proto(value: &crate::protos::geo::CIDR) -> Option<IpConfig> {
    let bytes = value.ip.as_ref();
    match bytes.len() {
        4 => {
            // IPv4 地址构造
            let ip = IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
            Some(IpConfig { ip, prefix: value.prefix })
        }
        // 16 => {
        //     // IPv6 地址构造
        //     let mut octets = [0u8; 16];
        //     octets.copy_from_slice(bytes);
        //     Some(IpAddr::V6(Ipv6Addr::from(octets)))
        // }
        _ => None, // 字节数不合法
    }
}
