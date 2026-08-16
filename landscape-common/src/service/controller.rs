use std::collections::HashMap;
use std::fmt::Debug;

use crate::config::FlowId;
use crate::database::error::DbError;
use crate::database::store::{Change, ConfigStore};
use crate::database::{LandscapeFlowStore, LandscapeStore};

use super::{
    manager::{ServiceManager, ServiceStarterTrait},
    WatchService,
};

#[async_trait::async_trait]
pub trait ControllerService {
    type Id: ToString + Clone + Send;
    type Config: Send + Sync + Clone;
    type DatabseAction: LandscapeStore<Data = Self::Config, Id = Self::Id> + Send;
    type H: ServiceStarterTrait<Config = Self::Config>;

    fn get_service(&self) -> &ServiceManager<Self::H>;
    fn get_repository(&self) -> &Self::DatabseAction;

    /// 获得所有服务状态
    async fn get_all_status(&self) -> HashMap<String, WatchService> {
        self.get_service().get_all_status().await
    }

    async fn handle_service_config(&self, config: Self::Config) -> Result<(), DbError> {
        // 1. 先检查冲突，获取旧配置用于回滚
        let old_config = self.get_repository().check_conflict(&config).await?;

        // 2. 启动/更新服务
        if let Ok(()) = self.get_service().update_service(config.clone()).await {
            // 3. 写入 DB（内部再次检查 update_at）
            match self.get_repository().checked_set(config).await {
                Ok(_) => {}
                Err(e) => {
                    // 4. 写入失败，用旧配置回滚服务
                    if let Some(old) = old_config {
                        let _ = self.get_service().update_service(old).await;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    async fn delete_and_stop_iface_service(&self, iface_name: Self::Id) -> Option<WatchService> {
        self.get_repository().delete(iface_name.clone()).await.unwrap();
        self.get_service().stop_service(iface_name.to_string()).await
    }

    async fn get_config_by_name(&self, iface_name: Self::Id) -> Option<Self::Config> {
        self.get_repository().find_by_id(iface_name).await.unwrap()
    }
}

#[async_trait::async_trait]
pub trait ConfigController {
    type Id: Clone + Send;
    type Config: Send + Sync + Clone;
    type DatabseAction: LandscapeStore<Data = Self::Config, Id = Self::Id> + Send;

    fn get_repository(&self) -> &Self::DatabseAction;

    async fn after_update_config(
        &self,
        _new_configs: Vec<Self::Config>,
        _old_configs: Vec<Self::Config>,
    ) {
    }

    async fn update_one_config(&self, _config: Self::Config) {}
    async fn delete_one_config(&self, _config: Self::Config) {}
    async fn update_many_config(&self, _configs: Vec<Self::Config>) {}

    async fn set(&self, config: Self::Config) -> Self::Config {
        let old_configs = self.list().await;
        let add_result = self.get_repository().set(config).await.unwrap();
        let new_configs = self.list().await;
        self.after_update_config(new_configs, old_configs).await;
        self.update_one_config(add_result.clone()).await;
        add_result
    }

    async fn checked_set(&self, config: Self::Config) -> Result<Self::Config, DbError> {
        let old_configs = self.list().await;
        let add_result = self.get_repository().checked_set(config).await?;
        let new_configs = self.list().await;
        self.after_update_config(new_configs, old_configs).await;
        self.update_one_config(add_result.clone()).await;
        Ok(add_result)
    }

    async fn set_list(&self, configs: Vec<Self::Config>) {
        let old_configs = self.list().await;
        for config in configs.clone() {
            let _ = self.get_repository().set(config).await.unwrap();
        }
        let new_configs = self.list().await;
        self.after_update_config(new_configs, old_configs).await;
        self.update_many_config(configs).await;
    }

    async fn checked_set_list(&self, configs: Vec<Self::Config>) -> Result<(), DbError> {
        // Phase 1: 预检查所有项的冲突
        for config in &configs {
            self.get_repository().check_conflict(config).await?;
        }
        // Phase 2: 逐个 checked_set（内部再次检查）
        let old_configs = self.list().await;
        for config in configs.clone() {
            self.get_repository().checked_set(config).await?;
        }
        let new_configs = self.list().await;
        self.after_update_config(new_configs, old_configs).await;
        self.update_many_config(configs).await;
        Ok(())
    }

    async fn list(&self) -> Vec<Self::Config> {
        self.get_repository().list().await.unwrap()
    }

    async fn find_by_id(&self, id: Self::Id) -> Option<Self::Config> {
        self.get_repository().find_by_id(id).await.ok()?
    }

    async fn find_by_ids(&self, ids: Vec<Self::Id>) -> Vec<Self::Config> {
        self.get_repository().find_by_ids(ids).await
    }

    async fn delete(&self, id: Self::Id) {
        if let Some(config) = self.find_by_id(id.clone()).await {
            let old_configs = self.list().await;
            self.get_repository().delete(id).await.unwrap();
            let new_configs = self.list().await;
            self.after_update_config(new_configs, old_configs).await;
            self.update_one_config(config).await;
        }
    }
}

#[async_trait::async_trait]
pub trait FlowConfigController: ConfigController
where
    Self::DatabseAction: LandscapeFlowStore,
{
    async fn list_flow_configs(&self, id: FlowId) -> Vec<Self::Config> {
        self.get_repository().find_by_flow_id(id).await.unwrap()
    }
}

/// Next-generation controller over [`ConfigStore`]: shared write orchestration
/// (transactional, atomic optimistic lock, typed `DbError`) plus a minimal
/// per-domain notification slot. Runs in parallel with the legacy
/// [`ConfigController`] and will replace it once all domains are migrated.
///
/// # Write semantics
///
/// Every write in this trait **notifies**: `checked_set`/`checked_set_list`/
/// `delete` dispatch to `notify_changed`/`notify_deleted` after the write
/// succeeds. Domains that do not care (no overridden hook, or a no-op) simply
/// ignore the notification. Blind server-authoritative writes (seeding, state
/// machines, link-event sync) are deliberately NOT part of this trait: they go
/// straight to the underlying [`ConfigStore`] primitives
/// (`upsert`/`upsert_many`/`delete_and_get`) which never notify.
///
/// # Change delivery
///
/// `notify_changed` receives the full before/after (`Change { old, new }`) per
/// item, so a domain can scope its reaction precisely (e.g. DNS redirects
/// refreshing only `old.apply_flows ∪ new.apply_flows`) instead of the legacy
/// full-table `after_update_config` diff. Reads (`list`/`find_by_id`) live on
/// this trait as well and return `Result` so DB errors propagate to the caller
/// instead of being swallowed; flow-scoped reads are provided by the
/// [`ConfigStoreFlowController`] subtrait.
#[async_trait::async_trait]
pub trait ConfigStoreController: Send + Sync {
    type Id: Clone + Send + Sync + Debug;
    type Config: Send + Sync + Clone + Debug;
    type Store: ConfigStore<Data = Self::Config, Id = Self::Id>
        + LandscapeStore<Data = Self::Config, Id = Self::Id>
        + Send
        + Sync;

    fn get_store(&self) -> &Self::Store;

    /// Domain notification slot: translate the changes into the domain's own
    /// events (or run any rebuild). Single writes arrive as `vec![change]`;
    /// domains distinguishing single vs batch branch on `changes.len()`.
    async fn notify_changed(&self, _changes: Vec<Change<Self::Config>>) {}

    /// Domain notification slot for deletes; `old` is the deleted value.
    async fn notify_deleted(&self, _old: Self::Config) {}

    /// Optimistic-lock write, then notify. Returns the saved config with the
    /// refreshed `update_at` for the client to echo back.
    async fn checked_set(&self, config: Self::Config) -> Result<Self::Config, DbError> {
        let change = self.get_store().checked_upsert(config).await?;
        self.notify_changed(vec![change.clone()]).await;
        Ok(change.new)
    }

    /// Atomic batch optimistic-lock write in one transaction, then notify.
    async fn checked_set_list(&self, configs: Vec<Self::Config>) -> Result<(), DbError> {
        let changes = self.get_store().checked_upsert_many(configs).await?;
        self.notify_changed(changes).await;
        Ok(())
    }

    /// Read and delete atomically, then notify; `Ok(None)` if the id was missing.
    async fn delete(&self, id: Self::Id) -> Result<Option<Self::Config>, DbError> {
        let old = self.get_store().delete_and_get(id).await?;
        if let Some(old) = &old {
            self.notify_deleted(old.clone()).await;
        }
        Ok(old)
    }

    /// Lists all configs; DB errors propagate instead of being swallowed.
    async fn list(&self) -> Result<Vec<Self::Config>, DbError> {
        self.get_store().list().await
    }

    /// Finds one config; `Ok(None)` if missing. DB errors propagate.
    async fn find_by_id(&self, id: Self::Id) -> Result<Option<Self::Config>, DbError> {
        self.get_store().find_by_id(id).await
    }
}

/// Flow-scoped reads for configs that belong to a [`FlowId`].
#[async_trait::async_trait]
pub trait ConfigStoreFlowController: ConfigStoreController
where
    Self::Store: LandscapeFlowStore,
{
    async fn list_flow_configs(&self, id: FlowId) -> Result<Vec<Self::Config>, DbError> {
        self.get_store().find_by_flow_id(id).await
    }
}
