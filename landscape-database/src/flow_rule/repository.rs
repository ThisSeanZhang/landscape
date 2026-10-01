use std::collections::{HashMap, HashSet};

use landscape_common::config::FlowId;
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::flow::config::FlowConfig;
use landscape_common::flow::{
    FlowEntryMatchMode, FlowEntryRule, FlowRuleError, ResolvedFlowEntryMatchMode,
    ResolvedFlowEntryRule, RuntimeFlowConfig,
};
use migration::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::DBId;
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
    DBId
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
        config: &FlowConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        fn map_err(
            e: landscape_common::flow::FlowRuleError,
        ) -> landscape_common::service::ServiceConfigError {
            landscape_common::service::ServiceConfigError::InvalidConfig { reason: e.to_string() }
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
