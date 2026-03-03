use sea_orm::prelude::Uuid;

pub mod repository;

pub mod dhcp_v4_server;
pub mod dhcp_v6_client;
pub mod enrolled_device;
pub mod error;
pub mod firewall;
pub mod flow_wan;
pub mod iface;
pub mod iface_ip;
pub mod lan_ipv6;
pub mod mss_clamp;
pub mod pppd;
pub mod provider;
pub mod ra;
pub mod wifi;

pub mod dst_ip_rule;
pub mod firewall_blacklist;
pub mod firewall_rule;
pub mod flow_rule;

pub mod geo_ip;
pub mod geo_site;

pub mod route_lan;
pub mod route_wan;

pub mod nat;
pub mod static_nat_mapping;

pub mod cert;
pub mod cert_account;
pub mod dns_redirect;
pub mod dns_rule;
pub mod dns_upstream;

/// 定义 ID 类型
pub(crate) type DBId = Uuid;
/// 定义 JSON
pub(crate) type DBJson = serde_json::Value;
/// 定义通用时间戳存储, 用于乐观锁判断
pub(crate) type DBTimestamp = f64;

/// 为 Repository struct 生成 `impl Repository` + `impl LandscapeStore`
/// struct 本身由各 repository.rs 手动定义，保持组合灵活性
macro_rules! impl_repository {
    ($repo:ty, $model:ty, $entity:ty, $active:ty, $data:ty, $id:ty) => {
        #[async_trait::async_trait]
        impl crate::repository::Repository for $repo {
            type Model = $model;
            type Entity = $entity;
            type ActiveModel = $active;
            type Data = $data;
            type Id = $id;
            fn db(&self) -> &sea_orm::DatabaseConnection {
                &self.db
            }
        }
        #[async_trait::async_trait]
        impl landscape_common::database::LandscapeStore for $repo {
            type Data = $data;
            type Id = $id;
            async fn set(
                &self,
                config: Self::Data,
            ) -> Result<Self::Data, landscape_common::error::LdError> {
                use crate::repository::Repository;
                use landscape_common::database::repository::LandscapeDBStore;
                self.set_or_update_model(config.get_id(), config).await
            }
            async fn list(&self) -> Result<Vec<Self::Data>, landscape_common::error::LdError> {
                use crate::repository::Repository;
                self.list_all().await
            }
            async fn delete(&self, id: Self::Id) -> Result<(), landscape_common::error::LdError> {
                use crate::repository::Repository;
                self.delete_model(id).await
            }
            async fn find_by_id(
                &self,
                id: Self::Id,
            ) -> Result<Option<Self::Data>, landscape_common::error::LdError> {
                use crate::repository::Repository;
                Repository::find_by_id(self, id).await
            }
            async fn find_by_ids(&self, ids: Vec<Self::Id>) -> Vec<Self::Data> {
                use crate::repository::Repository;
                Repository::find_by_ids(self, ids).await
            }
            async fn check_conflict(
                &self,
                config: &Self::Data,
            ) -> Result<Option<Self::Data>, landscape_common::error::LdError> {
                use crate::repository::Repository;
                use landscape_common::database::repository::LandscapeDBStore;
                self.check_conflict_by_id(config.get_id(), config.get_update_at()).await
            }
            async fn checked_set(
                &self,
                config: Self::Data,
            ) -> Result<Self::Data, landscape_common::error::LdError> {
                use crate::repository::Repository;
                use landscape_common::database::repository::LandscapeDBStore;
                self.checked_set_or_update_model(config.get_id(), config).await
            }
        }
    };
}

/// 为 Model 实现了 FlowFilterExpr 的 Repository 生成 `impl LandscapeFlowStore`
macro_rules! impl_flow_store {
    ($repo:ty, $model:ty, $entity:ty) => {
        #[async_trait::async_trait]
        impl landscape_common::database::LandscapeFlowStore for $repo {
            async fn find_by_flow_id(
                &self,
                flow_id: landscape_common::config::FlowId,
            ) -> Result<Vec<Self::Data>, landscape_common::error::LdError> {
                use crate::repository::{FlowFilterExpr, Repository};
                use sea_orm::{EntityTrait, QueryFilter};
                let models = <$entity as EntityTrait>::find()
                    .filter(<$model as FlowFilterExpr>::get_flow_filter(flow_id))
                    .all(self.db())
                    .await?;
                Ok(models.into_iter().map(From::from).collect())
            }
        }
    };
}

pub(crate) use impl_flow_store;
pub(crate) use impl_repository;
