//! Shared checks for live edits and complete imported snapshots. References are
//! checked against the whole snapshot, never the order its rows are inserted.
use std::collections::HashSet;

use landscape_common::{
    config::InitConfig,
    database::validator::ValidatableConfig,
    dns::{config::DnsUpstreamConfig, rule::DNSRuleConfig},
    flow::{FlowTarget, config::FlowConfig, mark::FlowMark},
    service::ServiceConfigError,
    wan_link::WanLinkConfig,
};

fn invalid(reason: impl Into<String>) -> ServiceConfigError {
    ServiceConfigError::InvalidConfig { reason: reason.into() }
}

pub(crate) async fn ensure_redirect_flow_exists(
    txn: &sea_orm::DatabaseTransaction,
    mark: FlowMark,
) -> Result<(), crate::writer::UpsertErr> {
    use crate::flow_rule::entity::{Column, FlowConfigEntity};
    use landscape_common::database::error::DbError;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    if let Some(flow_id) = mark.redirect_flow_id().filter(|flow_id| *flow_id != 0)
        && FlowConfigEntity::find().filter(Column::FlowId.eq(flow_id)).one(txn).await?.is_none()
    {
        return Err(crate::writer::UpsertErr::Database(DbError::Validation(
            ServiceConfigError::FlowRedirectTargetMissing { flow_id },
        )));
    }
    Ok(())
}

fn validate_redirect(mark: FlowMark, flow_ids: &HashSet<u32>) -> Result<(), ServiceConfigError> {
    if let Some(flow_id) = mark.redirect_flow_id()
        && flow_id != 0
        && !flow_ids.contains(&flow_id)
    {
        return Err(ServiceConfigError::FlowRedirectTargetMissing { flow_id });
    }
    Ok(())
}

/// Ordered mode has one selected WAN even with automatic switching disabled.
/// Weighted mode is unambiguous only when all positive weights name one WAN.
pub(crate) fn supports_wan_dns(flow: &FlowConfig) -> bool {
    if !flow.enable {
        return false;
    }
    if flow.failover.ordered_targets() {
        return true;
    }
    let mut links = HashSet::new();
    for target in flow.flow_targets.iter().filter(|entry| entry.weight > 0) {
        match target.target {
            FlowTarget::Interface { link_id, .. } => {
                links.insert(link_id);
            }
            FlowTarget::Netns { .. } => return false,
        }
    }
    links.len() == 1
}

pub(crate) fn validate_rule_wan_flow(
    rule: &DNSRuleConfig,
    flows: &[FlowConfig],
) -> Result<(), ServiceConfigError> {
    if !rule.enable || rule.wan_upstreams.is_empty() || rule.flow_id == 0 {
        return Ok(());
    }
    if !flows.iter().any(|flow| flow.flow_id == rule.flow_id && supports_wan_dns(flow)) {
        return Err(ServiceConfigError::WanDnsFlowUnsupported { flow_id: rule.flow_id });
    }
    Ok(())
}

pub(crate) fn validate_rule_wan_refs(
    rule: &DNSRuleConfig,
    links: &[WanLinkConfig],
    upstreams: &[DnsUpstreamConfig],
) -> Result<(), ServiceConfigError> {
    for mapping in &rule.wan_upstreams {
        if !links.iter().any(|link| link.id == mapping.link_id) {
            return Err(invalid(format!("DNS WAN {} does not exist", mapping.link_id)));
        }
        let Some(upstream) = upstreams.iter().find(|upstream| upstream.id == mapping.upstream_id)
        else {
            return Err(invalid(format!("DNS upstream {} does not exist", mapping.upstream_id)));
        };
        if !upstream.is_independent_wan_group() {
            return Err(invalid(format!(
                "DNS 规则“{}”（分流 {}）引用的上游“{}”不是独立 DNS 组：必须填写服务器地址，且不能设置自己的分流、源地址或 WAN 绑定",
                rule.name,
                rule.flow_id,
                upstream.name.as_deref().unwrap_or(&upstream.remark)
            )));
        }
    }
    Ok(())
}

/// Import cannot use row-by-row checked writes: a referenced WAN/upstream may
/// appear later in the file. Keep legacy defaults and chain-ID normalization,
/// while applying the same content and WAN/DNS reference rules as live edits.
pub(crate) fn validate_network_snapshot(config: &InitConfig) -> Result<(), ServiceConfigError> {
    let mut link_ids = HashSet::new();
    for link in &config.wan_links {
        link.validate()?;
        if !link_ids.insert(link.id) {
            return Err(invalid(format!("重复的 WAN 标识 {}", link.id)));
        }
    }
    let mut flow_ids = HashSet::new();
    let mut default_owner = None;
    for flow in &config.flow_rules {
        flow.validate()?;
        if !flow_ids.insert(flow.flow_id) {
            return Err(invalid(format!("重复的分流编号 {}", flow.flow_id)));
        }
        if flow.enable && flow.failover.bind_default_flow {
            if let Some(owner) = default_owner {
                return Err(invalid(format!(
                    "分流 {owner} 和 {} 同时绑定默认出口，只能启用一个默认出口策略",
                    flow.flow_id
                )));
            }
            default_owner = Some(flow.flow_id);
        }
        for target in &flow.flow_targets {
            if let FlowTarget::Interface { link_id, .. } = target.target {
                let Some(link) = config.wan_links.iter().find(|link| link.id == link_id) else {
                    return Err(invalid(format!(
                        "分流 {} 引用了不存在的 WAN {link_id}",
                        flow.flow_id
                    )));
                };
                if flow.enable && flow.failover.requires_health_checks() {
                    link.validate_failover_health()?;
                }
            }
        }
    }
    let mut upstream_ids = HashSet::new();
    for upstream in &config.dns_upstream_configs {
        upstream.validate()?;
        if !upstream_ids.insert(upstream.id) {
            return Err(invalid(format!("重复的 DNS 上游标识 {}", upstream.id)));
        }
        if let Some(id) = upstream.bind_config.follow_flow.filter(|id| *id != 0)
            && !config
                .flow_rules
                .iter()
                .any(|flow| flow.flow_id == id && flow.enable && flow.failover.ordered_targets())
        {
            return Err(invalid(format!("DNS 上游绑定的分流 {id} 必须是启用的主备分流")));
        }
        for servers in &upstream.bind_config.wan_servers {
            if !config.wan_links.iter().any(|link| link.id == servers.link_id) {
                return Err(invalid(format!("DNS WAN {} does not exist", servers.link_id)));
            }
        }
    }
    for rule in &config.dns_rules {
        rule.validate()?;
        validate_redirect(rule.mark, &flow_ids)?;
        if rule.flow_id != 0 && !flow_ids.contains(&rule.flow_id) {
            return Err(invalid(format!(
                "DNS 规则“{}”引用的分流 {} 不存在",
                rule.name, rule.flow_id
            )));
        }
        validate_rule_wan_flow(rule, &config.flow_rules)?;
        validate_rule_wan_refs(rule, &config.wan_links, &config.dns_upstream_configs)?;
        if rule.wan_upstreams.is_empty()
            && !config.dns_upstream_configs.iter().any(|upstream| upstream.id == rule.upstream_id)
        {
            return Err(invalid(format!(
                "DNS 规则“{}”（分流 {}）引用的上游 {} 不存在",
                rule.name, rule.flow_id, rule.upstream_id
            )));
        }
    }
    for rule in &config.dst_ip_mark {
        rule.validate()?;
        if rule.flow_id != 0 && !flow_ids.contains(&rule.flow_id) {
            return Err(invalid(format!(
                "IP 规则“{}”引用的分流 {} 不存在",
                rule.name.as_deref().unwrap_or(&rule.remark),
                rule.flow_id
            )));
        }
        validate_redirect(rule.mark, &flow_ids)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "dns_wan_validation_tests.rs"]
mod tests;
