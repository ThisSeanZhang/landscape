use std::collections::HashMap;

use landscape_common::{
    firewall::{FirewallRuleConfig, FirewallRuleItem, FirewallRuleMark},
    mark::PacketMark,
};

fn convert_mark_map_to_vec_mark(
    value: HashMap<FirewallRuleItem, PacketMark>,
) -> Vec<FirewallRuleMark> {
    let mut result = Vec::with_capacity(value.len());
    for (item, mark) in value.into_iter() {
        result.push(FirewallRuleMark { mark, item });
    }
    result
}

pub fn update_firewall_rules(
    mut rules: Vec<FirewallRuleConfig>,
    mut old_rules: Vec<FirewallRuleConfig>,
) {
    rules.sort_by(|a, b| a.index.cmp(&b.index));
    old_rules.sort_by(|a, b| a.index.cmp(&b.index));

    let mut rules = firewall_rule_into_hash(rules);
    let old_rules = firewall_rule_into_hash(old_rules);
    tracing::debug!("rules: {:?}", rules);
    tracing::debug!("old_rules: {:?}", old_rules);

    let delete_keys = find_delete_rule_keys(&mut rules, old_rules);
    tracing::debug!("update_config: {:?}", rules);
    tracing::debug!("delete_keys: {:?}", delete_keys);

    landscape_ebpf::map_setting::add_firewall_rule(convert_mark_map_to_vec_mark(rules));
    landscape_ebpf::map_setting::del_firewall_rule(delete_keys);
}

fn firewall_rule_into_hash(
    rules: Vec<FirewallRuleConfig>,
) -> HashMap<FirewallRuleItem, PacketMark> {
    let mut new_mark_infos = HashMap::new();

    for ip_rule in rules.into_iter() {
        if !ip_rule.enable {
            continue;
        }
        for item in ip_rule.items.into_iter() {
            new_mark_infos.insert(item, ip_rule.mark);
        }
    }
    new_mark_infos
}

fn find_delete_rule_keys(
    new_rules: &mut HashMap<FirewallRuleItem, PacketMark>,
    old_rules: HashMap<FirewallRuleItem, PacketMark>,
) -> Vec<FirewallRuleItem> {
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
