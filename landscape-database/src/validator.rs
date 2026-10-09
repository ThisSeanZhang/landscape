use landscape_common::database::store::ConfigStore;
use sea_orm::DatabaseConnection;

use landscape_common::config_service::iface::{IfaceZoneType, ZoneAwareConfig, ZoneRequirement};
use landscape_common::service::ServiceConfigError;

use crate::iface::repository::NetIfaceRepository;
use crate::wan_link::repository::WanLinkRepository;
use landscape_common::wan_link::WanLinkKind;

/// 共享 zone 校验器:检查 config 的 iface 是否存在于 iface 表且
/// zone 类型满足服务域的 [`ZoneRequirement`]。
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

        if matches!(requirement, ZoneRequirement::WanOrPpp)
            && self.ppp_iface_is_declared(iface_name).await?
        {
            return Ok(());
        }

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

    /// Whether a pppd WAN link owns `iface_name` as its ppp device, with the
    /// link's attach iface still present.
    async fn ppp_iface_is_declared(&self, iface_name: &str) -> Result<bool, ServiceConfigError> {
        let links = WanLinkRepository::new(self.db.clone())
            .list()
            .await
            .map_err(ServiceConfigError::internal)?;
        for link in links {
            let WanLinkKind::Pppd { ppp_iface_name, .. } = &link.kind else {
                continue;
            };
            if ppp_iface_name != iface_name {
                continue;
            }
            let attach_exists = NetIfaceRepository::new(self.db.clone())
                .find_by_id(link.attach_iface_name.clone())
                .await
                .map_err(ServiceConfigError::internal)?
                .is_some();
            if attach_exists {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config_service::iface::{
        CreateDevType, NetworkIfaceConfig, ServiceKind, WifiMode,
    };
    use landscape_common::database::store::ConfigStore;
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    struct PppProbe(String);

    impl ZoneAwareConfig for PppProbe {
        fn iface_name(&self) -> &str {
            &self.0
        }
        fn zone_requirement() -> ZoneRequirement {
            ZoneRequirement::WanOrPpp
        }
        fn service_kind() -> ServiceKind {
            ServiceKind::RouteWan
        }
    }

    fn wan_iface(name: &str) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name: name.to_string(),
            create_dev_type: CreateDevType::NoNeedToCreate,
            controller_name: None,
            zone_type: IfaceZoneType::Wan,
            enable_in_boot: true,
            wifi_mode: WifiMode::default(),
            xps_rps: None,
            update_at: 0.0,
        }
    }

    fn pppd_link(attach: &str, ppp: &str) -> WanLinkConfig {
        WanLinkConfig {
            id: Uuid::new_v4(),
            name: String::new(),
            attach_iface_name: attach.to_string(),
            link_chain_id: 0,
            kind: WanLinkKind::Pppd {
                ppp_iface_name: ppp.to_string(),
                peer_id: "peer".to_string(),
                password: "pass".to_string(),
                ac: None,
                plugin: Default::default(),
            },
            v4: Default::default(),
            pd: Default::default(),
            nat: Default::default(),
            firewall: Default::default(),
            mss: Default::default(),
            update_at: 0.0,
        }
    }

    #[tokio::test]
    async fn ppp_iface_declared_by_a_wan_link_is_accepted() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        provider.iface_store().upsert(wan_iface("ens6")).await.unwrap();
        provider.wan_link_store().upsert(pppd_link("ens6", "ppp-ens6-1i73")).await.unwrap();

        let checker = ZoneChecker::new(provider.database());
        let probe = PppProbe("ppp-ens6-1i73".to_string());
        assert!(checker.check(&probe).await.is_ok());
    }

    #[tokio::test]
    async fn unknown_iface_is_rejected() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let checker = ZoneChecker::new(provider.database());
        let probe = PppProbe("ppp-does-not-exist".to_string());
        assert!(matches!(
            checker.check(&probe).await,
            Err(ServiceConfigError::IfaceNotFound { .. })
        ));
    }
}
