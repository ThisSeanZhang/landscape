use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use landscape_common::flow::mark::FlowDnsMark;
use landscape_common::ip_mark::{IpConfig, IpMarkInfo, WanIPRuleConfig};

// 更新新的文件
fn convert_mark_map_to_vec_mark(value: HashMap<IpConfig, (FlowDnsMark, bool)>) -> Vec<IpMarkInfo> {
    let mut result = Vec::with_capacity(value.len());
    for (cidr, (mark, override_dns)) in value.into_iter() {
        result.push(IpMarkInfo { mark, cidr, override_dns });
    }
    result
}

// pub fn update_lan_rules(mut rules: Vec<LanIPRuleConfig>, mut old_rules: Vec<LanIPRuleConfig>) {
//     rules.sort_by(|a, b| a.index.cmp(&b.index));
//     old_rules.sort_by(|a, b| a.index.cmp(&b.index));
//     let mut rules = lan_mark_into_map(rules);
//     let old_rules = lan_mark_into_map(old_rules);

//     let delete_keys = find_delete_rule_keys(&mut rules, old_rules);

//     landscape_ebpf::map_setting::add_lan_ip_mark(convert_mark_map_to_vec_mark(rules));
//     landscape_ebpf::map_setting::del_lan_ip_mark(delete_keys);
// }

async fn update_wan_rules_flow(
    flow_id: u32,
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

    landscape_ebpf::map_setting::flow_wanip::add_wan_ip_mark(
        flow_id,
        convert_mark_map_to_vec_mark(rules),
    );
    landscape_ebpf::map_setting::flow_wanip::del_wan_ip_mark(flow_id, delete_keys);
}

/// TODO: using database to replace
pub async fn update_wan_rules(
    rules: Vec<WanIPRuleConfig>,
    old_rules: Vec<WanIPRuleConfig>,
    new_path: PathBuf,
    old_path: Option<PathBuf>,
) {
    let mut flow_ids = HashSet::new();
    let mut rule_map: HashMap<u32, Vec<WanIPRuleConfig>> = HashMap::new();
    let mut old_rule_map: HashMap<u32, Vec<WanIPRuleConfig>> = HashMap::new();

    for r in rules.into_iter() {
        if !flow_ids.contains(&r.flow_id) {
            flow_ids.insert(r.flow_id.clone());
        }
        match rule_map.entry(r.flow_id.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(r),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(vec![r]);
            }
        }
    }

    for r in old_rules.into_iter() {
        if !flow_ids.contains(&r.flow_id) {
            flow_ids.insert(r.flow_id.clone());
        }
        match old_rule_map.entry(r.flow_id.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(r),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(vec![r]);
            }
        }
    }

    for flow_id in flow_ids {
        let rules = rule_map.remove(&flow_id).unwrap_or_default();
        let old_rules = old_rule_map.remove(&flow_id).unwrap_or_default();
        update_wan_rules_flow(flow_id, rules, old_rules, new_path.clone(), old_path.clone()).await;
    }
}

// fn lan_mark_into_map(rules: Vec<LanIPRuleConfig>) -> HashMap<IpConfig, FlowDnsMark> {
//     let mut new_mark_infos = HashMap::new();

//     for ip_rule in rules.into_iter() {
//         if !ip_rule.enable {
//             continue;
//         }
//         for each_cidr in ip_rule.source.into_iter() {
//             new_mark_infos.insert(each_cidr, ip_rule.mark);
//         }
//     }
//     new_mark_infos
// }

async fn wan_mark_into_map(
    rules: Vec<WanIPRuleConfig>,
    geo_file_path: PathBuf,
) -> HashMap<IpConfig, (FlowDnsMark, bool)> {
    let country_code_map = landscape_protobuf::read_geo_ips(geo_file_path).await;
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
            new_mark_infos.insert(each_cidr, (ip_rule.mark, ip_rule.override_dns));
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
    new_rules: &mut HashMap<IpConfig, (FlowDnsMark, bool)>,
    old_rules: HashMap<IpConfig, (FlowDnsMark, bool)>,
) -> Vec<IpConfig> {
    let mut delete_keys = vec![];
    // for (key, (old_mark, old_override_dns)) in old_rules.into_iter() {
    //     if let Some((mark, override_dns)) = new_rules.get(&key) {
    //         if *mark == old_mark && *override_dns == old_override_dns {
    //             new_rules.remove(&key);
    //         } else {
    //             continue;
    //         }
    //     } else {
    //         delete_keys.push(key);
    //     }
    // }

    for (key, _) in old_rules.into_iter() {
        if new_rules.contains_key(&key) {
            continue;
        } else {
            delete_keys.push(key);
        }
    }
    delete_keys
}
