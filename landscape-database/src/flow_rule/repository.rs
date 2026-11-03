use std::collections::{HashMap, HashSet};

use landscape_common::config::FlowId;
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::flow::config::FlowConfig;
use landscape_common::flow::{
    FlowEntryMatchMode, FlowEntryRule, FlowRuleError, FlowTarget, ResolvedFlowEntryMatchMode,
    ResolvedFlowEntryRule, RuntimeFlowConfig,
};
use migration::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, TransactionTrait};

use crate::DBId;
use crate::dns_rule::entity::{DNSRuleConfigColumn, DNSRuleConfigEntity};
use crate::dst_ip_rule::entity::{DstIpRuleConfigColumn, DstIpRuleConfigEntity};
use crate::enrolled_device::repository::EnrolledDeviceRepository;
use crate::flow_rule::entity::Column;

use super::entity::{FlowConfigActiveModel, FlowConfigEntity, FlowConfigModel};

#[derive(Clone)]
pub struct FlowConfigRepository {
    db: DatabaseConnection,
}

impl FlowConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn check_wan_dns_transaction(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        changes: &[FlowConfig],
    ) -> Result<(), crate::writer::UpsertErr> {
        use crate::{
            dns_upstream::entity::DnsUpstreamConfigEntity, wan_link::entity::WanLinkConfigEntity,
            writer::UpsertErr,
        };
        use landscape_common::{
            dns::{config::DnsUpstreamConfig, rule::DNSRuleConfig},
            service::ServiceConfigError,
            wan_link::WanLinkConfig,
        };
        let invalid = |error| UpsertErr::Database(DbError::Validation(error));
        let previous: Vec<_> =
            FlowConfigEntity::find().all(txn).await?.into_iter().map(FlowConfig::from).collect();
        let mut flows = previous.clone();
        for change in changes {
            flows.retain(|flow| flow.id != change.id);
            flows.push(change.clone());
        }
        if flows.iter().filter(|flow| flow.enable && flow.failover.bind_default_flow).count() > 1 {
            return Err(invalid(ServiceConfigError::InvalidConfig {
                reason: "only one enabled flow may control the default WAN policy".into(),
            }));
        }
        let rules: Vec<_> = DNSRuleConfigEntity::find()
            .all(txn)
            .await?
            .into_iter()
            .map(DNSRuleConfig::from)
            .collect();
        let upstreams: Vec<_> = DnsUpstreamConfigEntity::find()
            .all(txn)
            .await?
            .into_iter()
            .map(DnsUpstreamConfig::from)
            .collect();
        let links: Vec<_> = WanLinkConfigEntity::find()
            .all(txn)
            .await?
            .into_iter()
            .map(WanLinkConfig::from)
            .collect();
        for change in changes {
            if let Some(old) = previous.iter().find(|flow| flow.id == change.id) {
                if change.flow_id != old.flow_id {
                    Self::ensure_no_rule_references(txn, old.flow_id, false).await?;
                }
                if (!change.enable
                    || !change.failover.ordered_targets()
                    || change.flow_id != old.flow_id)
                    && upstreams
                        .iter()
                        .any(|upstream| upstream.bind_config.follow_flow == Some(old.flow_id))
                {
                    return Err(invalid(ServiceConfigError::InvalidConfig { reason: "change DNS upstream WAN bindings before disabling, renumbering or leaving primary/backup mode on their followed flow".into() }));
                }
                for rule in rules.iter().filter(|rule| {
                    rule.enable && rule.flow_id == old.flow_id && !rule.wan_upstreams.is_empty()
                }) {
                    if change.flow_id != old.flow_id {
                        return Err(invalid(ServiceConfigError::WanDnsFlowUnsupported {
                            flow_id: old.flow_id,
                        }));
                    }
                    crate::dns_wan_validation::validate_rule_wan_flow(rule, &flows)
                        .map_err(invalid)?;
                }
            }
            for target in &change.flow_targets {
                if let FlowTarget::Interface { link_id, .. } = target.target {
                    let Some(link) = links.iter().find(|link| link.id == link_id) else {
                        return Err(invalid(ServiceConfigError::InvalidConfig {
                            reason: format!("flow target references unknown wan link {link_id}"),
                        }));
                    };
                    if change.enable && change.failover.requires_health_checks() {
                        link.validate_failover_health().map_err(invalid)?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn ensure_no_rule_references(
        txn: &sea_orm::DatabaseTransaction,
        flow_id: FlowId,
        deleting: bool,
    ) -> Result<(), crate::writer::UpsertErr> {
        use landscape_common::{
            dns::rule::DNSRuleConfig, flow::ip_mark::WanIpRuleConfig, service::ServiceConfigError,
        };
        let mut references = Vec::new();
        for rule in DNSRuleConfigEntity::find().all(txn).await?.into_iter().map(DNSRuleConfig::from)
        {
            // Delete cascades the owner's rules. Renumbering does not, so it
            // must also reject rules that would be stranded on the old ID.
            if deleting && rule.flow_id == flow_id {
                continue;
            }
            if (!deleting && rule.flow_id == flow_id)
                || rule.mark.redirect_flow_id() == Some(flow_id)
            {
                references.push(format!(
                    "分流 {} 的 DNS 规则“{}” ({})",
                    rule.flow_id, rule.name, rule.id
                ));
            }
        }
        for rule in
            DstIpRuleConfigEntity::find().all(txn).await?.into_iter().map(WanIpRuleConfig::from)
        {
            if deleting && rule.flow_id == flow_id {
                continue;
            }
            if (!deleting && rule.flow_id == flow_id)
                || rule.mark.redirect_flow_id() == Some(flow_id)
            {
                references.push(format!(
                    "分流 {} 的 IP 规则“{}” ({})",
                    rule.flow_id,
                    rule.name.as_deref().unwrap_or(&rule.remark),
                    rule.id
                ));
            }
        }
        references.sort();
        if !references.is_empty() {
            return Err(crate::writer::UpsertErr::Database(DbError::Validation(
                ServiceConfigError::FlowReferenced { flow_id, references: references.join("、") },
            )));
        }
        Ok(())
    }

    pub async fn list_runtime_configs(&self) -> Result<Vec<RuntimeFlowConfig>, DbError> {
        let configs = self.list().await?;
        let devices = self.load_devices_for_configs(&configs).await?;
        let mut result = Vec::new();

        for config in configs.into_iter().filter(|config| config.enable) {
            let flow_match_rules = config
                .flow_match_rules
                .into_iter()
                .filter_map(|rule| resolve_flow_entry_rule(rule, &devices))
                .collect();

            result.push(RuntimeFlowConfig { flow_id: config.flow_id, flow_match_rules });
        }

        Ok(result)
    }

    async fn load_devices_for_configs(
        &self,
        configs: &[FlowConfig],
    ) -> Result<DevicesById, DbError> {
        let mut device_ids = HashSet::new();
        for config in configs {
            for rule in &config.flow_match_rules {
                if let FlowEntryMatchMode::Device { device_id } = rule.mode {
                    device_ids.insert(device_id);
                }
            }
        }

        let devices = EnrolledDeviceRepository::new(self.db.clone())
            .find_ids(device_ids.into_iter().collect())
            .await?;
        Ok(devices.into_iter().map(|device| (device.id, device)).collect())
    }

    pub async fn find_by_flow_id(&self, flow_id: FlowId) -> Result<Option<FlowConfig>, DbError> {
        let result =
            FlowConfigEntity::find().filter(Column::FlowId.eq(flow_id)).one(&self.db).await?;

        Ok(result.map(From::from))
    }

    pub async fn delete_flow_with_rules(&self, id: DBId) -> Result<Option<FlowConfig>, DbError> {
        crate::writer::txn_retry_loop!(self, |txn| async move {
            let model = FlowConfigEntity::find_by_id(id).one(txn).await?;
            let Some(model) = model else {
                return Ok::<_, crate::writer::UpsertErr>(None);
            };
            let flow_id = model.flow_id;
            let upstreams =
                crate::dns_upstream::entity::DnsUpstreamConfigEntity::find().all(txn).await?;
            if upstreams.iter().any(|upstream| {
                upstream.bind_config["follow_flow"].as_u64() == Some(u64::from(flow_id))
            }) {
                return Err(crate::writer::UpsertErr::Database(DbError::Validation(
                    landscape_common::service::ServiceConfigError::InvalidConfig {
                        reason:
                            "change DNS upstream WAN bindings before deleting their followed flow"
                                .into(),
                    },
                )));
            }

            Self::ensure_no_rule_references(txn, flow_id, true).await?;

            DNSRuleConfigEntity::delete_many()
                .filter(DNSRuleConfigColumn::FlowId.eq(flow_id))
                .exec(txn)
                .await?;
            DstIpRuleConfigEntity::delete_many()
                .filter(DstIpRuleConfigColumn::FlowId.eq(flow_id))
                .exec(txn)
                .await?;
            FlowConfigEntity::delete_by_id(id).exec(txn).await?;
            Ok::<_, crate::writer::UpsertErr>(Some(model.into()))
        })
    }

    /// 查询是否有其他 flow config（排除 exclude_id）包含相同的入口匹配规则
    pub async fn find_conflict_by_entry_mode(
        &self,
        exclude_id: DBId,
        mode: &FlowEntryMatchMode,
    ) -> Result<Option<FlowConfig>, DbError> {
        let (condition_sql, params) = match mode {
            FlowEntryMatchMode::Mac { mac_addr } => (
                "json_extract(json_each.value, '$.mode.t') = 'mac' AND json_extract(json_each.value, '$.mode.mac_addr') = ?",
                vec![sea_orm::Value::String(Some(Box::new(mac_addr.to_string())))],
            ),
            FlowEntryMatchMode::Ip { ip, prefix_len } => (
                "json_extract(json_each.value, '$.mode.t') = 'ip' AND json_extract(json_each.value, '$.mode.ip') = ? AND json_extract(json_each.value, '$.mode.prefix_len') = ?",
                vec![
                    sea_orm::Value::String(Some(Box::new(ip.to_string()))),
                    sea_orm::Value::Int(Some(*prefix_len as i32)),
                ],
            ),
            FlowEntryMatchMode::Device { device_id } => (
                "json_extract(json_each.value, '$.mode.t') = 'device' AND json_extract(json_each.value, '$.mode.device_id') = ?",
                vec![sea_orm::Value::String(Some(Box::new(device_id.to_string())))],
            ),
        };

        let full_sql = format!(
            "EXISTS (
            SELECT 1 FROM json_each(flow_match_rules)
            WHERE {}
        )",
            condition_sql
        );

        let expr = Expr::cust_with_values(&full_sql, params);

        let result = FlowConfigEntity::find()
            .filter(Column::Id.ne(exclude_id))
            .filter(expr)
            .one(&self.db)
            .await?;

        Ok(result.map(From::from))
    }

    pub async fn find_resolved_conflict_by_entry_mode(
        &self,
        exclude_id: DBId,
        mode: &FlowEntryMatchMode,
    ) -> Result<Option<FlowConfig>, DbError> {
        let configs = self.list().await?;
        let mut devices = self.load_devices_for_configs(&configs).await?;
        if let FlowEntryMatchMode::Device { device_id } = mode
            && !devices.contains_key(device_id)
            && let Some(device) =
                ConfigStore::find_by_id(&EnrolledDeviceRepository::new(self.db.clone()), *device_id)
                    .await?
        {
            devices.insert(device.id, device);
        }
        let Some(target_mode) = resolve_flow_entry_mode(mode.clone(), &devices) else {
            return Ok(None);
        };

        for config in configs {
            if config.id == exclude_id {
                continue;
            }

            for rule in &config.flow_match_rules {
                if let Some(mode) = resolve_flow_entry_mode(rule.mode.clone(), &devices)
                    && mode == target_mode
                {
                    return Ok(Some(config));
                }
            }
        }

        Ok(None)
    }

    pub async fn find_resolved_conflict_for_modes(
        &self,
        exclude_id: DBId,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<(FlowEntryMatchMode, FlowConfig)>, FlowRuleError> {
        let configs = self.list().await?;
        let mut devices = self.load_devices_for_configs(&configs).await?;
        devices.extend(self.load_devices_for_modes(modes).await?);

        if let Some(device_id) = find_missing_device_id(modes.iter(), &devices) {
            return Err(FlowRuleError::DeviceNotFound(device_id));
        }

        for mode in modes {
            let Some(resolved) = resolve_flow_entry_mode(mode.clone(), &devices) else {
                continue;
            };
            for config in &configs {
                if config.id == exclude_id {
                    continue;
                }
                for rule in &config.flow_match_rules {
                    if let Some(rule_mode) = resolve_flow_entry_mode(rule.mode.clone(), &devices)
                        && rule_mode == resolved
                    {
                        return Ok(Some((mode.clone(), config.clone())));
                    }
                }
            }
        }

        Ok(None)
    }

    pub async fn resolve_modes(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Vec<(FlowEntryMatchMode, ResolvedFlowEntryMatchMode)>, FlowRuleError> {
        let devices = self.load_devices_for_modes(modes).await?;

        if let Some(device_id) = find_missing_device_id(modes.iter(), &devices) {
            return Err(FlowRuleError::DeviceNotFound(device_id));
        }

        Ok(modes
            .iter()
            .filter_map(|mode| {
                resolve_flow_entry_mode(mode.clone(), &devices).and_then(|resolved| {
                    into_resolved_match_mode(resolved).map(|resolved| (mode.clone(), resolved))
                })
            })
            .collect())
    }

    async fn load_devices_for_modes(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<DevicesById, DbError> {
        let device_ids = collect_device_ids(modes.iter());
        let devices = EnrolledDeviceRepository::new(self.db.clone())
            .find_ids(device_ids.into_iter().collect())
            .await?;
        Ok(devices.into_iter().map(|device| (device.id, device)).collect())
    }

    pub async fn validate_modes_resolvable(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<(), FlowRuleError> {
        let devices = self.load_devices_for_modes(modes).await?;

        if let Some(device_id) = find_missing_device_id(modes.iter(), &devices) {
            return Err(FlowRuleError::DeviceNotFound(device_id));
        }

        Ok(())
    }
}

type DevicesById = std::collections::HashMap<
    DBId,
    landscape_common::config_service::enrolled_device::EnrolledDevice,
>;

fn collect_device_ids<'a>(
    modes: impl IntoIterator<Item = &'a FlowEntryMatchMode>,
) -> HashSet<DBId> {
    let mut device_ids = HashSet::new();
    for mode in modes {
        if let FlowEntryMatchMode::Device { device_id } = mode {
            device_ids.insert(*device_id);
        }
    }
    device_ids
}

fn find_missing_device_id<'a>(
    modes: impl IntoIterator<Item = &'a FlowEntryMatchMode>,
    devices: &DevicesById,
) -> Option<DBId> {
    for mode in modes {
        if let FlowEntryMatchMode::Device { device_id } = mode
            && !devices.contains_key(device_id)
        {
            return Some(*device_id);
        }
    }

    None
}

fn resolve_flow_entry_rule(
    rule: FlowEntryRule,
    devices: &DevicesById,
) -> Option<ResolvedFlowEntryRule> {
    match rule.mode {
        FlowEntryMatchMode::Device { device_id } => {
            let device = devices.get(&device_id)?;
            Some(ResolvedFlowEntryRule {
                qos: rule.qos,
                mode: ResolvedFlowEntryMatchMode::Mac { mac_addr: device.mac },
            })
        }
        FlowEntryMatchMode::Mac { mac_addr } => Some(ResolvedFlowEntryRule {
            qos: rule.qos,
            mode: ResolvedFlowEntryMatchMode::Mac { mac_addr },
        }),
        FlowEntryMatchMode::Ip { ip, prefix_len } => Some(ResolvedFlowEntryRule {
            qos: rule.qos,
            mode: ResolvedFlowEntryMatchMode::Ip { ip, prefix_len },
        }),
    }
}

fn resolve_flow_entry_mode(
    mode: FlowEntryMatchMode,
    devices: &DevicesById,
) -> Option<FlowEntryMatchMode> {
    match mode {
        FlowEntryMatchMode::Device { device_id } => {
            let device = devices.get(&device_id)?;
            Some(FlowEntryMatchMode::Mac { mac_addr: device.mac })
        }
        mode => Some(mode),
    }
}

fn into_resolved_match_mode(mode: FlowEntryMatchMode) -> Option<ResolvedFlowEntryMatchMode> {
    match mode {
        FlowEntryMatchMode::Mac { mac_addr } => Some(ResolvedFlowEntryMatchMode::Mac { mac_addr }),
        FlowEntryMatchMode::Ip { ip, prefix_len } => {
            Some(ResolvedFlowEntryMatchMode::Ip { ip, prefix_len })
        }
        FlowEntryMatchMode::Device { .. } => None,
    }
}

pub fn find_duplicate_resolved_modes(
    resolved_modes: &[(FlowEntryMatchMode, ResolvedFlowEntryMatchMode)],
) -> Option<FlowEntryMatchMode> {
    let mut seen = HashMap::new();
    for (original_mode, resolved_mode) in resolved_modes {
        if seen.insert(resolved_mode.clone(), original_mode.clone()).is_some() {
            return Some(original_mode.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{DevicesById, find_duplicate_resolved_modes, find_missing_device_id};
    use landscape_common::config_service::enrolled_device::EnrolledDevice;
    use landscape_common::flow::{FlowEntryMatchMode, ResolvedFlowEntryMatchMode};
    use landscape_common::net::MacAddr;
    use sea_orm::prelude::Uuid;
    use std::collections::HashMap;

    #[test]
    fn detects_duplicate_resolved_modes() {
        let mac_addr = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let resolved = vec![
            (
                FlowEntryMatchMode::Device { device_id: Uuid::new_v4() },
                ResolvedFlowEntryMatchMode::Mac { mac_addr },
            ),
            (FlowEntryMatchMode::Mac { mac_addr }, ResolvedFlowEntryMatchMode::Mac { mac_addr }),
        ];

        let duplicate = find_duplicate_resolved_modes(&resolved);

        assert!(matches!(duplicate, Some(FlowEntryMatchMode::Mac { .. })));
    }

    #[test]
    fn reports_missing_device_targets() {
        let device_id = Uuid::new_v4();
        let modes = [FlowEntryMatchMode::Device { device_id }];

        assert_eq!(find_missing_device_id(modes.iter(), &HashMap::new()), Some(device_id));
    }

    #[test]
    fn accepts_known_device_targets() {
        let device_id = Uuid::new_v4();
        let modes = [FlowEntryMatchMode::Device { device_id }];
        let devices: DevicesById = HashMap::from([(
            device_id,
            EnrolledDevice {
                id: device_id,
                update_at: 0.0,
                iface_name: None,
                name: "device".to_string(),
                fake_name: None,
                remark: None,
                hostname: None,
                mac: MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
                ipv4: None,
                ipv6: None,
                tag: vec![],
                dhcp_custom_options: vec![],
                dhcp_filter_options: vec![],
            },
        )]);

        assert_eq!(find_missing_device_id(modes.iter(), &devices), None);
    }
}

crate::impl_repository!(
    FlowConfigRepository,
    FlowConfigModel,
    FlowConfigEntity,
    FlowConfigActiveModel,
    FlowConfig,
    DBId,
    transactional_check = check_wan_dns_transaction
);

crate::impl_flow_store!(FlowConfigRepository, FlowConfigModel, FlowConfigEntity);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<FlowConfig> for FlowConfigRepository {
    async fn check_zone(
        &self,
        _config: &FlowConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }

    async fn validate_cross(
        &self,
        config: &mut FlowConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        fn map_err(
            e: landscape_common::flow::FlowRuleError,
        ) -> landscape_common::service::ServiceConfigError {
            landscape_common::service::ServiceConfigError::InvalidConfig { reason: e.to_string() }
        }

        if let Some(previous) = self
            .find_by_id(config.id)
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
            && (!config.enable
                || !config.failover.ordered_targets()
                || previous.flow_id != config.flow_id)
        {
            let upstreams =
                crate::dns_upstream::repository::DnsUpstreamRepository::new(self.db.clone())
                    .list()
                    .await
                    .map_err(landscape_common::service::ServiceConfigError::internal)?;
            if upstreams
                .iter()
                .any(|upstream| upstream.bind_config.follow_flow == Some(previous.flow_id))
            {
                return Err(landscape_common::service::ServiceConfigError::InvalidConfig { reason: "change DNS upstream WAN bindings before disabling, renumbering or leaving primary/backup mode on their followed flow".into() });
            }
        }

        if let Some(previous) = self
            .find_by_id(config.id)
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
            && (previous.flow_id != config.flow_id
                || !crate::dns_wan_validation::supports_wan_dns(config))
        {
            let rules = crate::dns_rule::repository::DNSRuleRepository::new(self.db.clone())
                .list()
                .await
                .map_err(landscape_common::service::ServiceConfigError::internal)?;
            let mut references: Vec<_> = rules
                .iter()
                .filter(|rule| {
                    rule.enable
                        && rule.flow_id == previous.flow_id
                        && !rule.wan_upstreams.is_empty()
                })
                .map(|rule| format!("“{}” ({})", rule.name, rule.id))
                .collect();
            references.sort();
            if !references.is_empty() {
                return Err(landscape_common::service::ServiceConfigError::WanDnsFlowUnsupported {
                    flow_id: previous.flow_id,
                });
            }
        }

        if config.enable && config.failover.bind_default_flow {
            let configs = self
                .list()
                .await
                .map_err(landscape_common::service::ServiceConfigError::internal)?;
            if configs.iter().any(|other| {
                other.id != config.id && other.enable && other.failover.bind_default_flow
            }) {
                return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                    reason: "only one enabled flow may control the default WAN policy".into(),
                });
            }
        }
        // Interface targets reference wan links by uuid; resolve strictly
        // and refresh the net-iface name mirror.
        if config.flow_targets.iter().any(|t| matches!(t.target, FlowTarget::Interface { .. })) {
            let links = crate::wan_link::repository::WanLinkRepository::new(self.db.clone())
                .net_iface_map()
                .await
                .map_err(landscape_common::service::ServiceConfigError::internal)?;
            for target in &mut config.flow_targets {
                if let FlowTarget::Interface { link_id, name } = &mut target.target {
                    let iface = crate::wan_link::repository::resolve_wan_link_name(
                        &links,
                        *link_id,
                        "flow target",
                    )?;
                    if name != iface {
                        *name = iface.to_string();
                    }
                }
            }
        }

        if config.enable && config.failover.requires_health_checks() {
            let store = crate::wan_link::repository::WanLinkRepository::new(self.db.clone());
            for target in &config.flow_targets {
                if let FlowTarget::Interface { link_id, .. } = target.target {
                    let link = store
                        .find_by_id(link_id)
                        .await
                        .map_err(landscape_common::service::ServiceConfigError::internal)?;
                    if let Some(link) = link {
                        link.validate_failover_health()?;
                    } else {
                        return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                            reason: "enable health checks on every primary/backup WAN before enabling failover".into(),
                        });
                    }
                }
            }
        }

        let modes: Vec<_> = config.flow_match_rules.iter().map(|r| r.mode.clone()).collect();

        self.validate_modes_resolvable(&modes).await.map_err(map_err)?;

        let resolved_modes = self.resolve_modes(&modes).await.map_err(map_err)?;
        if let Some(duplicate) = find_duplicate_resolved_modes(&resolved_modes) {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!("duplicate entry rule mode '{duplicate}' after resolution"),
            });
        }

        if let Some((conflict_mode, conflict_config)) =
            self.find_resolved_conflict_for_modes(config.id, &modes).await.map_err(map_err)?
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "entry rule '{}' conflicts with flow '{}' (flow_id {})",
                    conflict_mode, conflict_config.remark, conflict_config.flow_id
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod wan_link_ref_tests {
    use landscape_common::database::store::ConfigStore;
    use landscape_common::flow::{FlowTarget, WeightedFlowTarget, config::FlowConfig};
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn pppd(ppp: &str) -> WanLinkKind {
        WanLinkKind::Pppd {
            ppp_iface_name: ppp.to_string(),
            peer_id: "peer".to_string(),
            password: "pass".to_string(),
            ac: None,
            plugin: Default::default(),
        }
    }

    fn link(id: Uuid, attach: &str, kind: WanLinkKind) -> WanLinkConfig {
        WanLinkConfig {
            id,
            name: String::new(),
            attach_iface_name: attach.to_string(),
            link_chain_id: 0,
            kind,
            v4: Default::default(),
            pd: Default::default(),
            nat: Default::default(),
            firewall: Default::default(),
            mss: Default::default(),
            health_check: Default::default(),
            update_at: 0.0,
        }
    }

    fn flow_config(link_id: Uuid, name: &str) -> FlowConfig {
        FlowConfig {
            id: Uuid::new_v4(),
            enable: true,
            flow_id: 1,
            failover: Default::default(),
            flow_match_rules: vec![],
            flow_targets: vec![WeightedFlowTarget::new(
                FlowTarget::Interface { link_id, name: name.to_string() },
                1,
            )],
            name: String::new(),
            remark: String::new(),
            update_at: 0.0,
        }
    }

    async fn setup() -> (LandscapeDBServiceProvider, Uuid) {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let id = Uuid::new_v4();
        provider.wan_link_store().upsert(link(id, "eth1", pppd("ppp0"))).await.unwrap();
        (provider, id)
    }

    #[tokio::test]
    async fn independent_wan_groups_roundtrip_and_reject_conflicting_bindings() {
        use landscape_common::dns::{config::DnsUpstreamConfig, rule::DnsWanUpstream};
        let (provider, link_id) = setup().await;
        let group = DnsUpstreamConfig::default();
        provider.dns_upstream_config_store().checked_upsert(group.clone()).await.unwrap();
        let mut rule: landscape_common::dns::rule::DNSRuleConfig = serde_json::from_value(serde_json::json!({
            "name":"independent groups", "index":10, "enable":true, "flow_id":0, "upstream_id":group.id
        })).unwrap();
        rule.upstream_id = group.id;
        rule.wan_upstreams = vec![DnsWanUpstream { link_id, upstream_id: group.id }];
        let saved =
            provider.dns_rule_store().checked_upsert_flow_rule(rule.clone()).await.unwrap().new;
        let read = provider.dns_rule_store().find_by_id(rule.id).await.unwrap().unwrap();
        assert_eq!(read.wan_upstreams, rule.wan_upstreams);
        assert!(read.resolved_wan.is_none());
        let mut invalid = saved.clone();
        invalid.wan_upstreams[0].upstream_id = Uuid::new_v4();
        assert!(provider.dns_rule_store().checked_upsert_flow_rule(invalid).await.is_err());
        let mut invalid = saved.clone();
        invalid.wan_upstreams[0].link_id = Uuid::new_v4();
        assert!(provider.dns_rule_store().checked_upsert_flow_rule(invalid).await.is_err());
        let mut invalid = saved;
        invalid.wan_upstreams.push(invalid.wan_upstreams[0].clone());
        assert!(provider.dns_rule_store().checked_upsert_flow_rule(invalid).await.is_err());
        let mut ambiguous =
            provider.dns_upstream_config_store().find_by_id(group.id).await.unwrap().unwrap();
        ambiguous.bind_config.follow_flow = Some(0);
        assert!(provider.dns_upstream_config_store().checked_upsert(ambiguous).await.is_err());
    }

    #[tokio::test]
    async fn per_wan_dns_servers_roundtrip_and_reject_missing_links() {
        let (provider, link_id) = setup().await;
        let mut upstream = landscape_common::dns::config::DnsUpstreamConfig::default();
        upstream.bind_config.follow_flow = Some(0);
        upstream.bind_config.wan_servers = vec![landscape_common::dns::bind::DnsWanServers {
            link_id,
            ips: vec!["202.96.128.86".parse().unwrap()],
        }];
        provider.dns_upstream_config_store().checked_upsert(upstream.clone()).await.unwrap();
        let saved =
            provider.dns_upstream_config_store().find_by_id(upstream.id).await.unwrap().unwrap();
        assert_eq!(saved.bind_config.wan_servers, upstream.bind_config.wan_servers);
        upstream.bind_config.wan_servers[0].link_id = Uuid::new_v4();
        assert!(provider.dns_upstream_config_store().checked_upsert(upstream).await.is_err());
    }

    #[tokio::test]
    async fn followed_dns_flow_cannot_be_disabled_renumbered_or_deleted() {
        use landscape_common::database::validator::StoreValidator;
        let (provider, link_id) = setup().await;
        let mut flow = flow_config(link_id, "ppp0");
        flow.failover.mode = landscape_common::flow::FlowTargetMode::PrimaryBackup;
        provider.flow_rule_store().upsert(flow.clone()).await.unwrap();
        let mut upstream = landscape_common::dns::config::DnsUpstreamConfig::default();
        upstream.bind_config.follow_flow = Some(flow.flow_id);
        provider.dns_upstream_config_store().checked_upsert(upstream.clone()).await.unwrap();
        flow.enable = false;
        assert!(provider.flow_rule_store().validate_cross(&mut flow).await.is_err());
        flow.enable = true;
        flow.flow_id = 2;
        assert!(provider.flow_rule_store().validate_cross(&mut flow).await.is_err());
        flow.flow_id = 1;
        assert!(provider.flow_rule_store().validate_cross(&mut flow).await.is_ok());
        assert!(provider.flow_rule_store().delete_flow_with_rules(flow.id).await.is_err());
        upstream.bind_config.follow_flow = None;
        provider.dns_upstream_config_store().upsert(upstream).await.unwrap();
        assert!(
            provider.flow_rule_store().delete_flow_with_rules(flow.id).await.unwrap().is_some()
        );
    }

    #[tokio::test]
    async fn default_wan_binding_has_one_enabled_owner() {
        use landscape_common::database::validator::StoreValidator;
        let (provider, link_id) = setup().await;
        let mut owner = flow_config(link_id, "ppp0");
        owner.failover.mode = landscape_common::flow::FlowTargetMode::PrimaryBackup;
        owner.failover.bind_default_flow = true;
        provider.flow_rule_store().upsert(owner.clone()).await.unwrap();
        let mut candidate = owner.clone();
        candidate.id = Uuid::new_v4();
        candidate.flow_id = 2;
        assert!(provider.flow_rule_store().validate_cross(&mut candidate).await.is_err());
        assert!(provider.flow_rule_store().validate_cross(&mut owner).await.is_ok());
        owner.enable = false;
        provider.flow_rule_store().upsert(owner).await.unwrap();
        assert!(provider.flow_rule_store().validate_cross(&mut candidate).await.is_ok());
    }

    #[tokio::test]
    async fn health_check_cannot_be_disabled_while_failover_references_it() {
        use landscape_common::database::validator::StoreValidator;
        let (provider, link_id) = setup().await;
        let mut flow = flow_config(link_id, "ppp0");
        flow.failover.enable = true;
        provider.flow_rule_store().upsert(flow.clone()).await.unwrap();
        let mut wan = provider.wan_link_store().find_by_id(link_id).await.unwrap().unwrap();
        wan.v4.enable = true;
        wan.health_check.enable = false;
        let error = provider.wan_link_store().validate_cross(&mut wan).await.unwrap_err();
        assert!(error.to_string().contains("health"));
        flow.failover.enable = false;
        provider.flow_rule_store().upsert(flow).await.unwrap();
        assert!(provider.wan_link_store().validate_cross(&mut wan).await.is_ok());
    }

    #[tokio::test]
    async fn dual_stack_failover_requires_both_probe_families_on_flow_and_wan_edits() {
        use landscape_common::database::validator::StoreValidator;
        let (provider, link_id) = setup().await;
        let mut wan = provider.wan_link_store().find_by_id(link_id).await.unwrap().unwrap();
        wan.v4.enable = true;
        wan.pd.enable = true;
        wan.health_check.enable = true;
        wan.health_check.probe = serde_json::from_value(serde_json::json!({
            "t": "multi", "groups": [{"name": "test", "quorum": 1, "targets": [
                {"t": "icmp", "address": "192.0.2.1"}
            ]}]
        }))
        .unwrap();
        provider.wan_link_store().upsert(wan.clone()).await.unwrap();
        let mut flow = flow_config(link_id, "ppp0");
        flow.failover.enable = true;
        let error = provider.flow_rule_store().validate_cross(&mut flow).await.unwrap_err();
        assert!(error.to_string().contains("IPv6 probe: false"));
        let v4_only = wan.health_check.probe.clone();
        wan.health_check.probe = serde_json::from_value(serde_json::json!({
            "t": "multi", "groups": [
                {"name": "test", "quorum": 1, "targets": [{"t": "icmp", "address": "192.0.2.1"}]},
                {"name": "test", "quorum": 1, "targets": [{"t": "icmp", "address": "2001:db8::1"}]}
            ]
        }))
        .unwrap();
        provider.wan_link_store().upsert(wan.clone()).await.unwrap();
        assert!(provider.flow_rule_store().validate_cross(&mut flow).await.is_ok());
        provider.flow_rule_store().upsert(flow.clone()).await.unwrap();
        assert!(provider.wan_link_store().validate_cross(&mut wan).await.is_ok());
        wan.health_check.probe = v4_only;
        let error = provider.wan_link_store().validate_cross(&mut wan).await.unwrap_err();
        assert!(error.to_string().contains("IPv6 probe: false"));
        // Explicitly opting out of IPv6 probing is valid for both save paths.
        wan.health_check.ipv6_probe_enabled = false;
        assert!(provider.wan_link_store().validate_cross(&mut wan).await.is_ok());
        provider.wan_link_store().upsert(wan.clone()).await.unwrap();
        assert!(provider.flow_rule_store().validate_cross(&mut flow).await.is_ok());
        wan.health_check.ipv4_probe_enabled = false;
        assert!(provider.wan_link_store().validate_cross(&mut wan).await.is_err());
        wan.health_check.ipv4_probe_enabled = true;
        // Once automatic failover is off, the WAN can use a legacy IPv4-only probe.
        flow.failover.enable = false;
        provider.flow_rule_store().upsert(flow).await.unwrap();
        assert!(provider.wan_link_store().validate_cross(&mut wan).await.is_ok());
    }

    #[tokio::test]
    async fn interface_target_mirror_is_rewritten_from_the_link() {
        let (provider, link_id) = setup().await;

        let saved = provider
            .flow_rule_store()
            .checked_upsert(flow_config(link_id, "stale"))
            .await
            .unwrap()
            .new;
        match &saved.flow_targets[0].target {
            FlowTarget::Interface { name, .. } => assert_eq!(name, "ppp0"),
            other => panic!("expected interface target, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn interface_target_with_unknown_link_id_is_rejected() {
        let (provider, _) = setup().await;

        let result =
            provider.flow_rule_store().checked_upsert(flow_config(Uuid::new_v4(), "ppp0")).await;
        assert!(result.is_err(), "an unknown link_id must be rejected");
    }
}

#[cfg(test)]
mod cascade_delete_tests {
    use landscape_common::config::FlowId;
    use landscape_common::database::error::DbError;
    use landscape_common::database::store::{ConfigFlowStore, ConfigStore};
    use landscape_common::dns::rule::{DNSRuleConfig, FilterResult};
    use landscape_common::flow::config::FlowConfig;
    use landscape_common::flow::ip_mark::WanIpRuleConfig;
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn flow(id: Uuid, flow_id: FlowId) -> FlowConfig {
        FlowConfig {
            id,
            enable: true,
            flow_id,
            failover: Default::default(),
            flow_match_rules: vec![],
            flow_targets: vec![],
            name: String::new(),
            remark: String::new(),
            update_at: 0.0,
        }
    }

    fn dns_rule(id: Uuid, flow_id: FlowId) -> DNSRuleConfig {
        DNSRuleConfig {
            id,
            name: format!("dns-{flow_id}"),
            index: 0,
            enable: true,
            filter: FilterResult::default(),
            upstream_id: Uuid::new_v4(),
            wan_upstreams: vec![],
            resolved_wan: None,
            mark: Default::default(),
            source: vec![],
            flow_id,
            update_at: 0.0,
        }
    }

    fn ip_rule(id: Uuid, flow_id: FlowId) -> WanIpRuleConfig {
        WanIpRuleConfig {
            id,
            name: None,
            index: 0,
            enable: true,
            mark: Default::default(),
            source: vec![],
            remark: String::new(),
            flow_id,
            override_dns: false,
            update_at: 0.0,
        }
    }

    async fn setup_rules(
        victim_flow_id: FlowId,
        other_flow_id: FlowId,
    ) -> (LandscapeDBServiceProvider, Uuid) {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let victim_flow_uuid = Uuid::new_v4();

        provider.flow_rule_store().upsert(flow(victim_flow_uuid, victim_flow_id)).await.unwrap();
        provider.flow_rule_store().upsert(flow(Uuid::new_v4(), other_flow_id)).await.unwrap();

        provider.dns_rule_store().upsert(dns_rule(Uuid::new_v4(), victim_flow_id)).await.unwrap();
        provider.dns_rule_store().upsert(dns_rule(Uuid::new_v4(), other_flow_id)).await.unwrap();

        provider.dst_ip_rule_store().upsert(ip_rule(Uuid::new_v4(), victim_flow_id)).await.unwrap();
        provider.dst_ip_rule_store().upsert(ip_rule(Uuid::new_v4(), other_flow_id)).await.unwrap();

        (provider, victim_flow_uuid)
    }

    #[tokio::test]
    async fn deleting_a_flow_removes_its_dns_and_dst_ip_rules() {
        let (provider, victim_flow_uuid) = setup_rules(7, 8).await;

        let deleted =
            provider.flow_rule_store().delete_flow_with_rules(victim_flow_uuid).await.unwrap();

        assert_eq!(deleted.map(|config| config.flow_id), Some(7));
        assert!(provider.flow_rule_store().find_by_id(victim_flow_uuid).await.unwrap().is_none());
        assert!(provider.dns_rule_store().find_by_flow_id(7).await.unwrap().is_empty());
        assert!(provider.dst_ip_rule_store().find_by_flow_id(7).await.unwrap().is_empty());
        assert_eq!(provider.dns_rule_store().find_by_flow_id(8).await.unwrap().len(), 1);
        assert_eq!(provider.dst_ip_rule_store().find_by_flow_id(8).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn persists_failover_settings_and_exit_order() {
        use landscape_common::flow::{FlowFailoverConfig, FlowTarget, WeightedFlowTarget};
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let id = Uuid::new_v4();
        let mut config = flow(id, 7);
        config.failover = FlowFailoverConfig {
            enable: true,
            auto_failback: false,
            ..Default::default()
        };
        config.flow_targets = [2, 1]
            .into_iter()
            .map(|id| {
                WeightedFlowTarget::new(
                    FlowTarget::Interface { link_id: Uuid::from_u128(id), name: String::new() },
                    1,
                )
            })
            .collect();
        provider.flow_rule_store().upsert(config.clone()).await.unwrap();
        let loaded = provider.flow_rule_store().find_by_id(id).await.unwrap().unwrap();
        assert_eq!(loaded.failover, config.failover);
        assert_eq!(
            serde_json::to_value(loaded.flow_targets).unwrap(),
            serde_json::to_value(config.flow_targets).unwrap()
        );
    }

    #[tokio::test]
    async fn checked_upsert_rejects_reserved_default_flow_id() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;

        let result = provider.flow_rule_store().checked_upsert(flow(Uuid::new_v4(), 0)).await;

        assert!(matches!(result, Err(DbError::Validation(_))));
        assert!(provider.flow_rule_store().list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_a_missing_flow_deletes_nothing() {
        let (provider, _) = setup_rules(7, 8).await;

        let deleted =
            provider.flow_rule_store().delete_flow_with_rules(Uuid::new_v4()).await.unwrap();

        assert!(deleted.is_none());
        assert_eq!(provider.dns_rule_store().find_by_flow_id(7).await.unwrap().len(), 1);
        assert_eq!(provider.dst_ip_rule_store().find_by_flow_id(7).await.unwrap().len(), 1);
    }
}
