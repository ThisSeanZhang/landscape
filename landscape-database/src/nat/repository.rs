use landscape_common::database::error::DbError;
use landscape_common::wan_service::nat::config::NatServiceConfig;
use migration::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Value};

use super::entity::{
    Column as NatCol, NatServiceConfigActiveModel, NatServiceConfigEntity, NatServiceConfigModel,
};
use crate::static_nat_mapping_v4::entity::{Column as StCol, StaticNatMappingV4ConfigEntity};

#[derive(Clone)]
pub struct NatServiceRepository {
    db: DatabaseConnection,
}

impl NatServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_active_nat_config(&self) -> Result<Option<NatServiceConfig>, DbError> {
        let res = NatServiceConfigEntity::find()
            .filter(NatCol::Enable.eq(true))
            .one(&self.db)
            .await?
            .map(Into::into);
        Ok(res)
    }

    pub async fn has_static_port_in_dynamic_range(
        &self,
        proto: u8,
        range_start: u16,
        range_end: u16,
    ) -> Result<bool, DbError> {
        let expr = Expr::cust_with_values(
            "EXISTS (
                SELECT 1 FROM json_each(static_nat_mapping_v4_configs.l4_protocols) AS proto,
                              json_each(static_nat_mapping_v4_configs.mapping_pair_ports) AS mp
                WHERE proto.value = ?
                  AND json_extract(mp.value, '$.wan_port') BETWEEN ? AND ?
            )",
            vec![
                Value::Int(Some(proto as i32)),
                Value::Int(Some(range_start as i32)),
                Value::Int(Some(range_end as i32)),
            ],
        );

        let res = StaticNatMappingV4ConfigEntity::find()
            .filter(StCol::Enable.eq(true))
            .filter(expr)
            .one(&self.db)
            .await?;
        Ok(res.is_some())
    }

    pub async fn is_port_in_dynamic_range(&self, proto: u8, port: u16) -> Result<bool, DbError> {
        let expr = Expr::cust_with_values(
            "EXISTS (
                SELECT 1 FROM nat_service_config
                WHERE enable = 1
                  AND ((proto = 6  AND ? BETWEEN tcp_range_start AND tcp_range_end)
                    OR (proto = 17 AND ? BETWEEN udp_range_start AND udp_range_end))
            )",
            vec![
                Value::Int(Some(proto as i32)),
                Value::Int(Some(port as i32)),
                Value::Int(Some(proto as i32)),
                Value::Int(Some(port as i32)),
            ],
        );

        let res = NatServiceConfigEntity::find()
            .filter(NatCol::Enable.eq(true))
            .filter(expr)
            .one(&self.db)
            .await?;
        Ok(res.is_some())
    }
}

crate::impl_repository!(
    NatServiceRepository,
    NatServiceConfigModel,
    NatServiceConfigEntity,
    NatServiceConfigActiveModel,
    NatServiceConfig,
    String
);

#[cfg(test)]
mod tests {
    use landscape_common::config_service::static_nat::config::StaticMapPair;
    use landscape_common::config_service::static_nat::config4::{
        StaticNatMappingV4Config, StaticNatV4Target,
    };
    use landscape_common::database::LandscapeStore;
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    async fn insert_static_mapping(provider: &LandscapeDBServiceProvider, port: u16, proto: u8) {
        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: port, lan_port: port }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![proto],
            update_at: 0.0,
        };
        provider.static_nat_mapping_v4_store().set(config).await.unwrap();
    }

    #[tokio::test]
    async fn port_in_range_returns_true() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_static_mapping(&provider, 8080, 6).await;

        let repo = provider.nat_service_store();
        let result = repo.has_static_port_in_dynamic_range(6, 8000, 9000).await.unwrap();
        assert!(result, "port 8080 should be detected inside range 8000-9000");
    }

    #[tokio::test]
    async fn port_outside_range_returns_false() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_static_mapping(&provider, 80, 6).await;

        let repo = provider.nat_service_store();
        let result = repo.has_static_port_in_dynamic_range(6, 8000, 9000).await.unwrap();
        assert!(!result, "port 80 should not be inside range 8000-9000");
    }

    #[tokio::test]
    async fn wrong_protocol_returns_false() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_static_mapping(&provider, 8080, 6).await;

        let repo = provider.nat_service_store();
        let result = repo.has_static_port_in_dynamic_range(17, 8000, 9000).await.unwrap();
        assert!(!result, "UDP check should not find TCP-only static mapping");
    }

    #[tokio::test]
    async fn disabled_mapping_returns_false() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: false,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 8080, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![6],
            update_at: 0.0,
        };
        provider.static_nat_mapping_v4_store().set(config).await.unwrap();

        let repo = provider.nat_service_store();
        let result = repo.has_static_port_in_dynamic_range(6, 8000, 9000).await.unwrap();
        assert!(!result, "disabled mapping should be ignored");
    }

    #[tokio::test]
    async fn boundary_port_returns_true() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_static_mapping(&provider, 8000, 6).await;

        let repo = provider.nat_service_store();
        let result = repo.has_static_port_in_dynamic_range(6, 8000, 9000).await.unwrap();
        assert!(result, "port at range start should be detected");
    }

    #[tokio::test]
    async fn multiple_protocols_one_matches() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 8080, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![6, 17],
            update_at: 0.0,
        };
        provider.static_nat_mapping_v4_store().set(config).await.unwrap();

        let repo = provider.nat_service_store();
        assert!(
            repo.has_static_port_in_dynamic_range(17, 8000, 9000).await.unwrap(),
            "UDP check should match multi-protocol mapping"
        );
    }
}
