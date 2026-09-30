use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

use crate::config::FlowId;
use crate::database::error::DbError;
use crate::database::repository::LandscapeDBStore;
use crate::database::store::{Change, ConfigStore};
use crate::database::{LandscapeFlowStore, LandscapeStore};

use super::{
    ServiceStatus, StartOutcome,
    manager::{ServiceKeyProvider, ServiceManager, ServiceStarterTrait},
};

#[async_trait::async_trait]
pub trait ControllerService {
    type Id: ToString + Clone + Send;
    type Config: Send + Sync + Clone;
    type DatabseAction: LandscapeStore<Data = Self::Config, Id = Self::Id> + Send;
    type H: ServiceStarterTrait<Config = Self::Config>;

    fn get_service(&self) -> &ServiceManager<Self::H>;
    fn get_repository(&self) -> &Self::DatabseAction;

    /// 获得所有服务状态快照
    async fn get_all_status(&self) -> HashMap<String, ServiceStatus> {
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

    async fn delete_and_stop_iface_service(&self, iface_name: Self::Id) -> Option<ServiceStatus> {
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

/// Service-managed controller over [`ConfigStoreController`]: orchestrates a
/// running service (through [`ServiceManager`]) around the transactional
/// store. Successor of the legacy [`ControllerService`].
///
/// # Write ordering (persist-after-verify)
///
/// 1. The previous config is loaded as a fallback pre-image; DB errors
///    surface before any service churn.
/// 2. The run triggered by this update is observed through
///    [`ServiceManager::update_service_and_wait`]:
///    [`StartOutcome::Running`] and [`StartOutcome::CleanStop`] (the starter
///    explicitly reported `Disabled`) proceed to the persist;
///    [`StartOutcome::Timeout`] also proceeds under a warning (the start is
///    treated as slow rather than broken; the policy lives here, the
///    primitive stays neutral);
///    [`StartOutcome::Failed`]/[`StartOutcome::Stopped`] (a broken or
///    self-terminating start — this attempt already terminated the previous
///    run) and [`StartOutcome::NotDelivered`] (the request was rejected, no
///    run triggered) fail fast with [`DbError::ServiceStart`] and leave the
///    store untouched.
/// 3. The store write is a single atomic `checked_upsert` — no separate
///    pre-check, so no check-then-write race window.
/// 4. Every failure path that disturbed the service converges it back to the
///    store (the authority) before the error surfaces: a failed start
///    (step 2) and a failed persist (step 3) both re-read the store and
///    restore the current value via
///    [`ServiceManager::update_service_wait_and_observe`] (on a `Conflict`
///    that is the concurrent winner's value, not necessarily the pre-image);
///    a missing record stops the leftover run; an unreadable store falls
///    back to the step-1 pre-image. Delivery is bounded best-effort: on
///    timeout the convergence is not guaranteed and only warned about.
///    [`StartOutcome::NotDelivered`] does not converge — nothing was
///    disturbed by this request; the consistency of whatever is pending in
///    the queue is owned by whoever queued it (channel capacity is 1, so
///    concurrent updates may briefly run a value that is neither the
///    store's nor this request's).
///
/// A failing request therefore takes at most two observation windows (start
/// plus convergence) before its error surfaces.
///
/// Every successful write notifies through the base trait's
/// `notify_changed`/`notify_deleted` slots, which the legacy `ControllerService`
/// never did.
#[async_trait::async_trait]
pub trait ConfigStoreServiceController: ConfigStoreController
where
    Self::Config: LandscapeDBStore<Self::Id> + ServiceKeyProvider,
{
    type H: ServiceStarterTrait<Config = Self::Config>;

    fn get_service(&self) -> &ServiceManager<Self::H>;

    /// Timeout for observing one start attempt in [`Self::handle_service_config`];
    /// slow-setup domains may override.
    fn start_confirm_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    /// Verify the service start with the config, then persist it atomically.
    async fn handle_service_config(&self, config: Self::Config) -> Result<Self::Config, DbError> {
        let service_key = config.service_key();
        let id = config.get_id();
        let old = self.get_store().find_by_id(id.clone()).await?;

        let timeout = self.start_confirm_timeout();
        let outcome = self.get_service().update_service_and_wait(config.clone(), timeout).await;
        match outcome {
            StartOutcome::Failed | StartOutcome::Stopped => {
                // 本次尝试已终止旧运行,以 store 为准恢复后再报错
                let error = DbError::ServiceStart(format!(
                    "service start for '{service_key}' observed {outcome:?}"
                ));
                self.converge_service_to_store(id, service_key, old, timeout).await;
                return Err(error);
            }
            StartOutcome::NotDelivered => {
                return Err(DbError::ServiceStart(format!(
                    "service start for '{service_key}' observed {outcome:?}"
                )));
            }
            StartOutcome::Timeout => {
                tracing::warn!(service_key, "start confirmation timed out; persisting anyway");
            }
            StartOutcome::Running | StartOutcome::CleanStop => {}
        }

        match self.get_store().checked_upsert(config).await {
            Ok(change) => {
                self.notify_changed(vec![change.clone()]).await;
                Ok(change.new)
            }
            Err(error) => {
                tracing::warn!(
                    service_key,
                    error = ?error,
                    "persisting the verified config failed; converging the service back to the store"
                );
                self.converge_service_to_store(id, service_key, old, timeout).await;
                Err(error)
            }
        }
    }

    /// 以 store 为准收敛服务:重读当前值(读取失败回退到调用方前像),
    /// 有值则弹性投递并观测恢复,无值则停掉残留运行。
    /// 投递为有界 best-effort:超时不保证收敛,仅告警。
    async fn converge_service_to_store(
        &self,
        id: Self::Id,
        service_key: String,
        old: Option<Self::Config>,
        timeout: Duration,
    ) {
        let target = match self.get_store().find_by_id(id).await {
            Ok(current) => current,
            Err(read_error) => {
                tracing::warn!(
                    service_key,
                    error = ?read_error,
                    "re-reading the store failed; falling back to the pre-image"
                );
                old
            }
        };
        match target {
            Some(prev) => {
                let outcome =
                    self.get_service().update_service_wait_and_observe(prev, timeout).await;
                if !matches!(outcome, StartOutcome::Running | StartOutcome::CleanStop) {
                    tracing::warn!(
                        service_key,
                        outcome = ?outcome,
                        "convergence did not reach Running"
                    );
                }
            }
            None => {
                let _ = self.get_service().stop_service(service_key).await;
            }
        }
    }

    /// Delete from the store, stop the running service, then notify;
    /// `Ok(None)` if the id was missing (the store is left untouched).
    async fn delete_and_stop_service(
        &self,
        id: Self::Id,
    ) -> Result<Option<ServiceStatus>, DbError> {
        let old = self.get_store().delete_and_get(id).await?;
        let Some(old) = old else { return Ok(None) };
        let status = self.get_service().stop_service(old.service_key()).await;
        self.notify_deleted(old).await;
        Ok(status)
    }

    /// Status snapshot of every running service, keyed by service key.
    async fn get_all_status(&self) -> HashMap<String, ServiceStatus> {
        self.get_service().get_all_status().await
    }
}

#[cfg(test)]
mod service_controller_tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::database::repository::LandscapeDBStore;
    use crate::service::{StartOutcome, WatchService};

    #[derive(Clone, Debug, PartialEq)]
    struct MockConfig {
        id: String,
        value: u32,
        update_at: f64,
    }

    impl LandscapeDBStore<String> for MockConfig {
        fn get_id(&self) -> String {
            self.id.clone()
        }
        fn get_update_at(&self) -> f64 {
            self.update_at
        }
        fn set_update_at(&mut self, ts: f64) {
            self.update_at = ts;
        }
    }

    impl ServiceKeyProvider for MockConfig {
        fn service_key(&self) -> String {
            self.id.clone()
        }
    }

    #[derive(Clone, Default)]
    struct MockStore {
        rows: Arc<Mutex<HashMap<String, MockConfig>>>,
        ts: Arc<AtomicU64>,
        fail_checked_upsert: Arc<AtomicBool>,
    }

    impl MockStore {
        fn next_ts(&self) -> f64 {
            self.ts.fetch_add(1, Ordering::SeqCst) as f64 + 1.0
        }
        fn seed(&self, config: MockConfig) {
            self.rows.lock().unwrap().insert(config.id.clone(), config);
        }
        fn get(&self, id: &str) -> Option<MockConfig> {
            self.rows.lock().unwrap().get(id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl LandscapeStore for MockStore {
        type Data = MockConfig;
        type Id = String;

        async fn set(&self, mut config: MockConfig) -> Result<MockConfig, DbError> {
            config.update_at = self.next_ts();
            self.rows.lock().unwrap().insert(config.id.clone(), config.clone());
            Ok(config)
        }

        async fn list(&self) -> Result<Vec<MockConfig>, DbError> {
            Ok(self.rows.lock().unwrap().values().cloned().collect())
        }

        async fn delete(&self, id: String) -> Result<(), DbError> {
            self.rows.lock().unwrap().remove(&id);
            Ok(())
        }

        async fn find_by_id(&self, id: String) -> Result<Option<MockConfig>, DbError> {
            Ok(self.get(&id))
        }

        async fn find_by_ids(&self, ids: Vec<String>) -> Vec<MockConfig> {
            let rows = self.rows.lock().unwrap();
            ids.into_iter().filter_map(|id| rows.get(&id).cloned()).collect()
        }

        async fn check_conflict(&self, config: &MockConfig) -> Result<Option<MockConfig>, DbError> {
            match self.get(&config.id) {
                Some(old) if old.update_at != config.update_at => Err(DbError::Conflict),
                other => Ok(other),
            }
        }

        async fn checked_set(&self, config: MockConfig) -> Result<MockConfig, DbError> {
            self.checked_upsert(config).await.map(|c| c.new)
        }
    }

    #[async_trait::async_trait]
    impl ConfigStore for MockStore {
        type Data = MockConfig;
        type Id = String;

        async fn upsert(&self, mut config: MockConfig) -> Result<Change<MockConfig>, DbError> {
            let old = self.get(&config.id);
            config.update_at = self.next_ts();
            self.rows.lock().unwrap().insert(config.id.clone(), config.clone());
            Ok(Change { old, new: config })
        }

        async fn checked_upsert(
            &self,
            mut config: MockConfig,
        ) -> Result<Change<MockConfig>, DbError> {
            if self.fail_checked_upsert.load(Ordering::SeqCst) {
                return Err(DbError::Conflict);
            }
            let old = self.get(&config.id);
            if let Some(old) = &old
                && old.update_at != config.update_at
            {
                return Err(DbError::Conflict);
            }
            config.update_at = self.next_ts();
            self.rows.lock().unwrap().insert(config.id.clone(), config.clone());
            Ok(Change { old, new: config })
        }

        async fn upsert_many(
            &self,
            configs: Vec<MockConfig>,
        ) -> Result<Vec<Change<MockConfig>>, DbError> {
            let mut changes = Vec::with_capacity(configs.len());
            for config in configs {
                changes.push(self.upsert(config).await?);
            }
            Ok(changes)
        }

        async fn checked_upsert_many(
            &self,
            configs: Vec<MockConfig>,
        ) -> Result<Vec<Change<MockConfig>>, DbError> {
            let mut changes = Vec::with_capacity(configs.len());
            for config in configs {
                changes.push(self.checked_upsert(config).await?);
            }
            Ok(changes)
        }

        async fn delete_and_get(&self, id: String) -> Result<Option<MockConfig>, DbError> {
            Ok(self.rows.lock().unwrap().remove(&id))
        }

        async fn find_ids(&self, ids: Vec<String>) -> Result<Vec<MockConfig>, DbError> {
            let rows = self.rows.lock().unwrap();
            Ok(ids.into_iter().filter_map(|id| rows.get(&id).cloned()).collect())
        }
    }

    /// Records every `start()` invocation as `(key, value)`; optionally blocks
    /// inside `start()` forever so the supervisor stops consuming its channel.
    /// With `auto_start` the started handle follows the starter contract:
    /// status enters `Staring` before return and a long-lived task is
    /// registered in the tracker (setting `Failed` instead of `Running` when
    /// `fail_start` is set). With `noop` it settles to `Stop` without Running.
    #[derive(Clone)]
    struct MockStarter {
        started: Arc<Mutex<Vec<(String, u32)>>>,
        block_start: Arc<AtomicBool>,
        auto_start: Arc<AtomicBool>,
        fail_start: Arc<AtomicBool>,
        noop: Arc<AtomicBool>,
        disabled: Arc<AtomicBool>,
        fail_next: Arc<AtomicBool>,
    }

    impl MockStarter {
        fn new() -> Self {
            Self {
                started: Arc::new(Mutex::new(Vec::new())),
                block_start: Arc::new(AtomicBool::new(false)),
                auto_start: Arc::new(AtomicBool::new(false)),
                fail_start: Arc::new(AtomicBool::new(false)),
                noop: Arc::new(AtomicBool::new(false)),
                disabled: Arc::new(AtomicBool::new(false)),
                fail_next: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ServiceStarterTrait for MockStarter {
        type Config = MockConfig;

        async fn start(&self, config: MockConfig) -> WatchService {
            self.started.lock().unwrap().push((config.id.clone(), config.value));
            if self.block_start.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let handle = WatchService::new();
            if self.disabled.load(Ordering::SeqCst) {
                handle.just_change_status(ServiceStatus::Disabled);
                return handle;
            }
            if self.noop.load(Ordering::SeqCst) {
                handle.just_change_status(ServiceStatus::Staring);
                let inner = handle.clone();
                handle.spawn_task("service.test.noop", async move {
                    inner.just_change_status(ServiceStatus::Stop);
                });
                return handle;
            }
            if self.auto_start.load(Ordering::SeqCst) {
                // 契约:返回前进入 Staring;长驻任务经 tracker 注册
                handle.just_change_status(ServiceStatus::Staring);
                // fail_next 为一次性:只打掉下一次启动,收敛重启可恢复
                let fail = self.fail_start.load(Ordering::SeqCst)
                    || self.fail_next.swap(false, Ordering::SeqCst);
                let inner = handle.clone();
                handle.spawn_task("service.test.autostart", async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    if fail {
                        inner.just_change_status(ServiceStatus::Failed);
                        return;
                    }
                    inner.just_change_status(ServiceStatus::Running);
                    // 模拟真实长驻服务:等待停止信号后收尾汇报
                    inner.stop_token().cancelled().await;
                    inner.just_change_status(ServiceStatus::Stop);
                });
            }
            handle
        }
    }

    struct MockController {
        store: MockStore,
        service: ServiceManager<MockStarter>,
        notify_log: Arc<Mutex<Vec<String>>>,
    }

    async fn controller(store: MockStore, starter: MockStarter) -> MockController {
        MockController {
            store: store.clone(),
            service: ServiceManager::init(Vec::new(), starter).await,
            notify_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[async_trait::async_trait]
    impl ConfigStoreController for MockController {
        type Id = String;
        type Config = MockConfig;
        type Store = MockStore;

        fn get_store(&self) -> &Self::Store {
            &self.store
        }

        async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
            for change in changes {
                self.notify_log.lock().unwrap().push(format!("changed:{}", change.new.value));
            }
        }

        async fn notify_deleted(&self, old: Self::Config) {
            self.notify_log.lock().unwrap().push(format!("deleted:{}", old.value));
        }
    }

    impl ConfigStoreServiceController for MockController {
        type H = MockStarter;

        fn get_service(&self) -> &ServiceManager<Self::H> {
            &self.service
        }

        fn start_confirm_timeout(&self) -> Duration {
            Duration::from_millis(500)
        }
    }

    async fn wait_for(mut cond: impl FnMut() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not met in time");
    }

    #[tokio::test]
    async fn happy_path_persists_and_starts_service() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        let config = MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 };
        let saved = controller.handle_service_config(config).await.unwrap();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 1);
        // Persist-after-verify: the start was observed Running before returning.
        assert_eq!(*starter.started.lock().unwrap(), vec![("wan0".to_string(), 1)]);
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
    }

    #[tokio::test]
    async fn service_rejection_leaves_store_untouched() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.block_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        // Fill the service channel: the first update is consumed by the
        // (blocked) supervisor, the second one queues up, the third must be
        // rejected with a full channel.
        assert!(
            controller
                .service
                .update_service(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
                .await
                .is_ok()
        );
        wait_for(|| !starter.started.lock().unwrap().is_empty()).await;
        assert!(
            controller
                .service
                .update_service(MockConfig { id: "wan0".to_string(), value: 2, update_at: 0.0 })
                .await
                .is_ok()
        );

        let result = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 3, update_at: 0.0 })
            .await;

        assert!(matches!(result, Err(DbError::ServiceStart(_))));
        assert!(store.get("wan0").is_none(), "rejected config must not be persisted");
        assert!(controller.notify_log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn persist_failure_converges_service_to_stored_config() {
        let store = MockStore::default();
        let old = MockConfig { id: "wan0".to_string(), value: 7, update_at: 0.0 };
        store.seed(old.clone());
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        // Incoming config echoes the stored update_at, but the write fails.
        store.fail_checked_upsert.store(true, Ordering::SeqCst);
        let incoming = MockConfig {
            id: "wan0".to_string(),
            value: 8,
            update_at: old.update_at,
        };

        let result = controller.handle_service_config(incoming).await;
        assert!(matches!(result, Err(DbError::Conflict)));

        // The service ran the new config (observed Running), then was
        // converged back to the stored config; the store keeps the old value.
        assert_eq!(
            *starter.started.lock().unwrap(),
            vec![("wan0".to_string(), 8), ("wan0".to_string(), 7)]
        );
        assert_eq!(store.get("wan0").unwrap().value, 7);
    }

    #[tokio::test]
    async fn write_failure_on_fresh_insert_stops_service() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        store.fail_checked_upsert.store(true, Ordering::SeqCst);
        let incoming = MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 };

        let result = controller.handle_service_config(incoming).await;
        assert!(matches!(result, Err(DbError::Conflict)));

        // The store re-read finds nothing, so the service entry is stopped
        // and removed, nothing persisted.
        assert!(controller.service.get_all_status().await.is_empty());
        assert!(store.get("wan0").is_none());
    }

    #[tokio::test]
    async fn failed_start_over_existing_config_converges_back_to_store() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();

        starter.fail_next.store(true, Ordering::SeqCst);

        let result = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 2, update_at: 0.0 })
            .await;
        assert!(matches!(result, Err(DbError::ServiceStart(_))));

        // The failed attempt killed the old run; convergence restarts the
        // stored config and the service ends up Running again.
        assert_eq!(
            *starter.started.lock().unwrap(),
            vec![("wan0".to_string(), 1), ("wan0".to_string(), 2), ("wan0".to_string(), 1)]
        );
        assert_eq!(store.get("wan0").unwrap().value, 1);
        assert_eq!(
            controller.service.get_all_status().await.get("wan0"),
            Some(&ServiceStatus::Running)
        );
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
    }

    #[tokio::test]
    async fn start_failure_skips_persist_and_leaves_store_untouched() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        starter.fail_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        let result = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await;

        assert!(matches!(result, Err(DbError::ServiceStart(_))));
        assert!(store.get("wan0").is_none(), "failed start must not be persisted");
        assert!(controller.notify_log.lock().unwrap().is_empty());
        // 收敛目标为空:残留运行被停掉并移除
        assert!(controller.service.get_all_status().await.is_empty());
    }

    #[tokio::test]
    async fn stopped_outcome_skips_persist_and_leaves_store_untouched() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.noop.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        let result = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await;

        assert!(matches!(result, Err(DbError::ServiceStart(_))));
        assert!(store.get("wan0").is_none(), "self-terminating start must not be persisted");
        assert!(controller.notify_log.lock().unwrap().is_empty());
        assert!(controller.service.get_all_status().await.is_empty());
    }

    #[tokio::test]
    async fn disabled_config_persists_as_clean_stop() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.disabled.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        let saved = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 1);
        assert_eq!(
            controller.service.get_all_status().await.get("wan0"),
            Some(&ServiceStatus::Disabled)
        );
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
    }

    #[tokio::test]
    async fn start_timeout_persists_with_warning() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.block_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        // start() blocks before reporting any status, so the observation
        // times out (500ms via the mock's start_confirm_timeout) and the
        // persist proceeds anyway.
        let saved = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 1);
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
    }

    #[tokio::test]
    async fn delete_and_stop_service_roundtrip() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter).await;

        let missing = controller.delete_and_stop_service("wan0".to_string()).await.unwrap();
        assert!(missing.is_none());

        controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 3, update_at: 0.0 })
            .await
            .unwrap();

        let deleted = controller.delete_and_stop_service("wan0".to_string()).await.unwrap();
        // 快照语义:返回被停服务的终态
        assert!(matches!(deleted, Some(ServiceStatus::Stop)));
        assert!(store.get("wan0").is_none());
        assert_eq!(
            *controller.notify_log.lock().unwrap(),
            vec!["changed:3".to_string(), "deleted:3".to_string()]
        );
        assert!(controller.service.get_all_status().await.is_empty());
    }

    #[tokio::test]
    async fn update_service_and_wait_reports_running() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store, starter).await;

        // 新键:placeholder(generation 0)→ 首次真实启动(1)后观测
        let outcome = controller
            .service
            .update_service_and_wait(
                MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(outcome, StartOutcome::Running);
        assert_eq!(
            controller.service.get_all_status().await.get("wan0"),
            Some(&ServiceStatus::Running)
        );

        // 既有键:更新触发的下一次运行(1 → 2)
        let outcome = controller
            .service
            .update_service_and_wait(
                MockConfig { id: "wan0".to_string(), value: 2, update_at: 0.0 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(outcome, StartOutcome::Running);
        assert_eq!(
            controller.service.get_all_status().await.get("wan0"),
            Some(&ServiceStatus::Running)
        );
    }

    #[tokio::test]
    async fn update_service_and_wait_reports_failure() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        starter.fail_start.store(true, Ordering::SeqCst);
        let controller = controller(store, starter).await;

        let outcome = controller
            .service
            .update_service_and_wait(
                MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(outcome, StartOutcome::Failed);
    }

    #[tokio::test]
    async fn update_service_and_wait_reports_stopped_when_start_settles_stop() {
        // 启动后未经历 Running 即落 Stop,应观测到 Stopped
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.noop.store(true, Ordering::SeqCst);
        let controller = controller(store, starter).await;

        let outcome = controller
            .service
            .update_service_and_wait(
                MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(outcome, StartOutcome::Stopped);
    }

    #[tokio::test]
    async fn update_service_and_wait_reports_not_delivered_when_channel_full() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.block_start.store(true, Ordering::SeqCst);
        let starter_probe = starter.clone();
        let controller = controller(store, starter).await;

        // 第一份:触发 spawn,supervisor 接收后进入 start() 并永久阻塞
        controller
            .service
            .update_service(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();

        // 等 start() 真正进入(此时通道已腾空),消除与 supervisor 调度的竞态
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while starter_probe.started.lock().unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "starter did not enter start()");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // 第二份:占满容量 1 的通道
        controller
            .service
            .update_service(MockConfig { id: "wan0".to_string(), value: 2, update_at: 0.0 })
            .await
            .unwrap();

        // 第三份:通道满被去重 → 未投递,须与真实停止(Stopped)区分
        let outcome = controller
            .service
            .update_service_and_wait(
                MockConfig { id: "wan0".to_string(), value: 3, update_at: 0.0 },
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(outcome, StartOutcome::NotDelivered);
    }

    #[tokio::test]
    async fn update_service_wait_and_observe_reports_running_on_fresh_and_existing_key() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store, starter).await;

        // 无条目:重建(spawn)后观测首次运行
        let outcome = controller
            .service
            .update_service_wait_and_observe(
                MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(outcome, StartOutcome::Running);

        // 既有条目:等容量投递后观测由本次更新触发的运行
        let outcome = controller
            .service
            .update_service_wait_and_observe(
                MockConfig { id: "wan0".to_string(), value: 2, update_at: 0.0 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(outcome, StartOutcome::Running);
        assert_eq!(
            controller.service.get_all_status().await.get("wan0"),
            Some(&ServiceStatus::Running)
        );
    }

    #[tokio::test]
    async fn update_service_wait_and_observe_delivery_timeout_is_bounded() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.block_start.store(true, Ordering::SeqCst);
        let starter_probe = starter.clone();
        let controller = controller(store, starter).await;

        // 第一份:supervisor 接收后在 start() 内永久阻塞
        controller
            .service
            .update_service(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();

        // 等 start() 真正进入(此时通道已腾空),消除与 supervisor 调度的竞态
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while starter_probe.started.lock().unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "starter did not enter start()");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // 第二份:占满容量 1 的通道,supervisor 卡死不再消费
        controller
            .service
            .update_service(MockConfig { id: "wan0".to_string(), value: 2, update_at: 0.0 })
            .await
            .unwrap();

        // 第三份:投递等待容量,须在单一 deadline 内以 Timeout 放弃,而非再等一轮观测
        let started_at = tokio::time::Instant::now();
        let outcome = controller
            .service
            .update_service_wait_and_observe(
                MockConfig { id: "wan0".to_string(), value: 3, update_at: 0.0 },
                Duration::from_millis(500),
            )
            .await;
        let elapsed = started_at.elapsed();
        assert_eq!(outcome, StartOutcome::Timeout);
        assert!(
            elapsed < Duration::from_secs(2),
            "delivery timeout must be bounded by a single deadline, took {elapsed:?}"
        );
    }
}
