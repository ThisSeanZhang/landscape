use landscape_common::database::store::ConfigStore;
use sea_orm::DatabaseConnection;

use landscape_common::config_service::iface::{IfaceZoneType, ZoneAwareConfig, ZoneRequirement};
use landscape_common::service::ServiceConfigError;

use crate::iface::repository::NetIfaceRepository;
use crate::pppd::repository::PPPDServiceRepository;

/// 共享 zone 校验器:检查 config 的 iface 是否存在于 iface 表且
/// zone 类型满足服务域的 [`ZoneRequirement`]。
///
/// 逻辑自 webserver `LandscapeApp::validate_zone` 迁移,数据源全部为
/// DB 读取(iface 表 + pppd 表),可在 store 写路径内运行。
pub struct ZoneChecker {
    db: DatabaseConnection,
}

impl ZoneChecker {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn check<C: ZoneAwareConfig>(&self, config: &C) -> Result<(), ServiceConfigError> {
        let iface_name = config.iface_name();
        let requirement = C::zone_requirement();

        // WanOrPpp: PPP 设备优先(存在以该名字命名的 PPPD 配置,且其
        // 附加物理接口存在,则视为合法 PPP 设备,跳过 zone 矩阵)
        if matches!(requirement, ZoneRequirement::WanOrPpp)
            && let Some(ppp_config) = PPPDServiceRepository::new(self.db.clone())
                .find_by_id(iface_name.to_string())
                .await
                .map_err(ServiceConfigError::internal)?
            && NetIfaceRepository::new(self.db.clone())
                .find_by_id(ppp_config.attach_iface_name)
                .await
                .map_err(ServiceConfigError::internal)?
                .is_some()
        {
            return Ok(());
        }

        // docker0 特例:允许 LanOnly 服务
        if iface_name == "docker0" && matches!(requirement, ZoneRequirement::LanOnly) {
            return Ok(());
        }

        let iface_config = NetIfaceRepository::new(self.db.clone())
            .find_by_id(iface_name.to_string())
            .await
            .map_err(ServiceConfigError::internal)?
            .ok_or_else(|| ServiceConfigError::IfaceNotFound {
                iface_name: iface_name.to_string(),
            })?;

        let allowed = match requirement {
            ZoneRequirement::WanOnly | ZoneRequirement::WanOrPpp => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan)
            }
            ZoneRequirement::LanOnly => matches!(iface_config.zone_type, IfaceZoneType::Lan),
            ZoneRequirement::WanOrLan => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan | IfaceZoneType::Lan)
            }
            ZoneRequirement::LanOrUndefined => {
                matches!(iface_config.zone_type, IfaceZoneType::Lan | IfaceZoneType::Undefined)
            }
        };

        if allowed {
            Ok(())
        } else {
            Err(ServiceConfigError::ZoneMismatch {
                service_name: C::service_kind(),
                iface_name: iface_name.to_string(),
            })
        }
    }
}
