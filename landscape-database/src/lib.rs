use sea_orm::prelude::Uuid;

pub mod repository;
pub mod validator;
pub mod writer;

pub mod ddns;
pub mod dhcp_v4_server;
pub mod dhcp_v6_client;
pub mod dns_provider_profile;
pub mod enrolled_device;
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

/// Generates `impl Repository` + `impl ConfigStore` for a Repository struct.
/// The struct itself is defined manually in each repository.rs for composition flexibility.
///
/// # 校验注入(用户写路径)
///
/// `checked_upsert`/`checked_upsert_many` 在写入前按固定顺序调用:
///
/// 1. `<$data as ValidatableConfig>::validate` — 纯内容校验,挂在 config 上
/// 2. `StoreValidator::<$data>::check_zone` — zone 检查,挂在 repo 上
/// 3. `StoreValidator::<$data>::validate_cross` — 跨域冲突,挂在 repo 上
///
/// 全限定调用:config 未实现 `ValidatableConfig` 或 repo 未实现
/// `StoreValidator` 时宏展开直接编译失败 —— "入库必须实现校验"的
/// 编译期强制。校验失败以 [`DbError::Validation`] 拒绝,零副作用。
/// 盲写路径(`upsert`/`upsert_many`)不注入校验:可信系统路径(播种/
/// ACME/geo/网关运行时/设备注册)。
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
        impl landscape_common::database::store::ConfigStore for $repo {
            type Data = $data;
            type Id = $id;
            async fn list(
                &self,
            ) -> Result<Vec<Self::Data>, landscape_common::database::error::DbError> {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone()).list().await
            }
            async fn find_by_id(
                &self,
                id: Self::Id,
            ) -> Result<Option<Self::Data>, landscape_common::database::error::DbError> {
                crate::writer::StoreWriter::<$entity, $data>::new(self.db.clone())
                    .find_by_id(id)
                    .await
            }
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
                if let Err(error) =
                    <$data as landscape_common::database::validator::ValidatableConfig>::validate(
                        &config,
                    )
                {
                    return Err(landscape_common::database::error::DbError::Validation(error));
                }
                if let Err(error) =
                    landscape_common::database::validator::StoreValidator::<$data>::check_zone(
                        self,
                        &config,
                    )
                    .await
                {
                    return Err(landscape_common::database::error::DbError::Validation(error));
                }
                if let Err(error) =
                    landscape_common::database::validator::StoreValidator::<$data>::validate_cross(
                        self,
                        &config,
                    )
                    .await
                {
                    return Err(landscape_common::database::error::DbError::Validation(error));
                }
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
                for config in &configs {
                    if let Err(error) =
                        <$data as landscape_common::database::validator::ValidatableConfig>::validate(
                            config,
                        )
                    {
                        return Err(landscape_common::database::error::DbError::Validation(error));
                    }
                    if let Err(error) =
                        landscape_common::database::validator::StoreValidator::<$data>::check_zone(
                            self,
                            config,
                        )
                        .await
                    {
                        return Err(landscape_common::database::error::DbError::Validation(error));
                    }
                    if let Err(error) =
                        landscape_common::database::validator::StoreValidator::<$data>::validate_cross(
                            self,
                            config,
                        )
                        .await
                    {
                        return Err(landscape_common::database::error::DbError::Validation(error));
                    }
                }
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

/// Generates `impl ConfigFlowStore` for a Repository whose Model implements FlowFilterExpr.
macro_rules! impl_flow_store {
    ($repo:ty, $model:ty, $entity:ty) => {
        #[async_trait::async_trait]
        impl landscape_common::database::store::ConfigFlowStore for $repo {
            async fn find_by_flow_id(
                &self,
                flow_id: landscape_common::config::FlowId,
            ) -> Result<Vec<Self::Data>, landscape_common::database::error::DbError> {
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

/// 显式"无 zone / 无跨域校验"声明:该域的 repo 侧校验两个方法均通过
/// (纯内容校验在 config 侧的 `ValidatableConfig`)。一行宏只省样板,
/// 不隐藏任何控制流 —— 写路径仍由 `impl_repository!` 锁定。
macro_rules! impl_trivial_validator {
    ($repo:ty, $data:ty) => {
        #[async_trait::async_trait]
        impl landscape_common::database::validator::StoreValidator<$data> for $repo {
            async fn check_zone(
                &self,
                _config: &$data,
            ) -> Result<(), landscape_common::service::ServiceConfigError> {
                Ok(())
            }
            async fn validate_cross(
                &self,
                _config: &$data,
            ) -> Result<(), landscape_common::service::ServiceConfigError> {
                Ok(())
            }
        }
    };
}

/// zone-only 服务域声明:`check_zone` 委托共享 `ZoneChecker`,
/// 无跨域校验(`validate_cross` 显式通过)。
macro_rules! impl_zone_validator {
    ($repo:ty, $data:ty) => {
        #[async_trait::async_trait]
        impl landscape_common::database::validator::StoreValidator<$data> for $repo {
            async fn check_zone(
                &self,
                config: &$data,
            ) -> Result<(), landscape_common::service::ServiceConfigError> {
                crate::validator::ZoneChecker::new(self.db.clone()).check(config).await
            }
            async fn validate_cross(
                &self,
                _config: &$data,
            ) -> Result<(), landscape_common::service::ServiceConfigError> {
                Ok(())
            }
        }
    };
}

pub(crate) use impl_flow_store;
pub(crate) use impl_repository;
pub(crate) use impl_trivial_validator;
pub(crate) use impl_zone_validator;
