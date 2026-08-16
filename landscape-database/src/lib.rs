use sea_orm::prelude::Uuid;

pub mod repository;
pub mod writer;

pub mod ddns;
pub mod dhcp_v4_server;
pub mod dhcp_v6_client;
pub mod dns_provider_profile;
pub mod enrolled_device;
pub mod error;
pub mod firewall;
pub mod flow_wan;
pub mod iface;
pub mod iface_ip;
pub mod lan_ipv6_v2;
pub mod mss_clamp;
pub mod pppd;
pub mod provider;
pub mod rollback;
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
pub mod static_nat_mapping_v4;
pub mod static_nat_mapping_v6;

pub mod cert;
pub mod cert_account;
pub mod dns_redirect;
pub mod dns_rule;
pub mod dns_upstream;
pub mod gateway;

/// ID type.
pub(crate) type DBId = Uuid;
/// JSON value type.
pub(crate) type DBJson = serde_json::Value;
/// Generic timestamp storage type, used for optimistic-lock checks.
pub(crate) type DBTimestamp = f64;

/// Generates `impl Repository` + `impl LandscapeStore` for a Repository struct.
/// The struct itself is defined manually in each repository.rs for composition flexibility.
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
        #[async_trait::async_trait]
        impl landscape_common::database::store::ConfigStore for $repo {
            type Data = $data;
            type Id = $id;
            async fn upsert(
                &self,
                config: Self::Data,
            ) -> Result<
                landscape_common::database::store::Change<Self::Data>,
                landscape_common::database::error::DbError,
            > {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .upsert(config)
                    .await
            }
            async fn checked_upsert(
                &self,
                config: Self::Data,
            ) -> Result<
                landscape_common::database::store::Change<Self::Data>,
                landscape_common::database::error::DbError,
            > {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .checked_upsert(config)
                    .await
            }
            async fn upsert_many(
                &self,
                configs: Vec<Self::Data>,
            ) -> Result<
                Vec<landscape_common::database::store::Change<Self::Data>>,
                landscape_common::database::error::DbError,
            > {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .upsert_many(configs)
                    .await
            }
            async fn checked_upsert_many(
                &self,
                configs: Vec<Self::Data>,
            ) -> Result<
                Vec<landscape_common::database::store::Change<Self::Data>>,
                landscape_common::database::error::DbError,
            > {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .checked_upsert_many(configs)
                    .await
            }
            async fn delete_and_get(
                &self,
                id: Self::Id,
            ) -> Result<Option<Self::Data>, landscape_common::database::error::DbError> {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .delete_and_get(id)
                    .await
            }
            async fn find_ids(
                &self,
                ids: Vec<Self::Id>,
            ) -> Result<Vec<Self::Data>, landscape_common::database::error::DbError> {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .find_ids(ids)
                    .await
            }
        }
    };
}

/// Generates `impl LandscapeFlowStore` for a Repository whose Model implements FlowFilterExpr.
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
