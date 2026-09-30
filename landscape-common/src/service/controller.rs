use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

use crate::config::FlowId;
use crate::database::error::DbError;
use crate::database::repository::LandscapeDBStore;
use crate::database::store::{Change, ConfigFlowStore, ConfigStore};

use super::{
    ServiceStatus,
    manager::{ServiceKeyProvider, ServiceManager, ServiceStarterTrait},
};

/// Controller over [`ConfigStore`]: shared write orchestration (transactional,
/// atomic optimistic lock, typed `DbError`) plus a minimal per-domain
/// notification slot.
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
/// refreshing only `old.apply_flows ∪ new.apply_flows`). Reads (`list`/`find_by_id`) live on
/// this trait as well and return `Result` so DB errors propagate to the caller
/// instead of being swallowed; flow-scoped reads are provided by the
/// [`ConfigStoreFlowController`] subtrait.
#[async_trait::async_trait]
pub trait ConfigStoreController: Send + Sync {
    type Id: Clone + Send + Sync + Debug;
    type Config: Send + Sync + Clone + Debug;
    type Store: ConfigStore<Data = Self::Config, Id = Self::Id> + Send + Sync;

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
    Self::Store: ConfigFlowStore,
{
    async fn list_flow_configs(&self, id: FlowId) -> Result<Vec<Self::Config>, DbError> {
        self.get_store().find_by_flow_id(id).await
    }
}

/// Service-managed controller over [`ConfigStoreController`]: orchestrates a
/// running service (through [`ServiceManager`]) around the transactional
/// store.
///
/// # Write ordering (persist-first, no rollback)
///
/// The store is the authority for *intent*: it always holds the latest
/// validated config the user submitted, never older than the runtime.
///
/// 1. `checked_upsert` writes atomically — validation (content → zone →
///    cross-domain, injected by `impl_repository!`) and the staleness check
///    (`update_at` optimistic lock → `DbError::Conflict`) both live inside
///    the store write, so a rejection happens with zero side effects:
///    nothing persisted, nothing notified, nothing delivered.
/// 2. `notify_changed` dispatches after the write succeeds.
/// 3. The saved config is delivered to the service through bounded
///    backpressure ([`ServiceManager::deliver_bounded`]). A delivery timeout
///    only warns: the stored config converges on the next trigger (restart
///    replay, netlink observers). A failing start is NOT an error here —
///    the config stays stored and the service reports `Failed` through the
///    status API.
///
/// Validation is an existence guarantee, not an atomicity guarantee: the
/// validation reads happen before the write transaction, so concurrent
/// writers may both pass cross-domain checks (same window as the previous
/// handler-level validation). Moving validation inside the write
/// transaction is a possible hardening, at the cost of longer write locks.
///
/// Every successful write notifies through the base trait's
/// `notify_changed`/`notify_deleted` slots.
#[async_trait::async_trait]
pub trait ConfigStoreServiceController: ConfigStoreController
where
    Self::Config: LandscapeDBStore<Self::Id> + ServiceKeyProvider,
{
    type H: ServiceStarterTrait<Config = Self::Config>;

    fn get_service(&self) -> &ServiceManager<Self::H>;

    /// Deadline for the bounded delivery of a just-persisted config.
    fn deliver_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    /// Persist-first pipeline: validated atomic write → notify → bounded
    /// delivery. See the trait docs for the write-ordering contract.
    async fn handle_service_config(&self, config: Self::Config) -> Result<Self::Config, DbError> {
        let change = self.get_store().checked_upsert(config).await?;
        self.notify_changed(vec![change.clone()]).await;
        let saved = change.new;
        self.get_service().deliver_bounded(saved.clone(), self.deliver_timeout()).await;
        Ok(saved)
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
    use crate::service::ServiceHandle;

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
    impl ConfigStore for MockStore {
        type Data = MockConfig;
        type Id = String;

        async fn list(&self) -> Result<Vec<MockConfig>, DbError> {
            Ok(self.rows.lock().unwrap().values().cloned().collect())
        }

        async fn find_by_id(&self, id: String) -> Result<Option<MockConfig>, DbError> {
            Ok(self.get(&id))
        }

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
    /// `fail_start`/`fail_next` is set). With `disabled` it reports `Disabled`.
    #[derive(Clone)]
    struct MockStarter {
        started: Arc<Mutex<Vec<(String, u32)>>>,
        block_start: Arc<AtomicBool>,
        auto_start: Arc<AtomicBool>,
        fail_start: Arc<AtomicBool>,
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
                disabled: Arc::new(AtomicBool::new(false)),
                fail_next: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ServiceStarterTrait for MockStarter {
        type Config = MockConfig;

        async fn start(&self, config: MockConfig) -> ServiceHandle {
            self.started.lock().unwrap().push((config.id.clone(), config.value));
            if self.block_start.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let handle = ServiceHandle::new();
            if self.disabled.load(Ordering::SeqCst) {
                handle.just_change_status(ServiceStatus::Disabled);
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

        fn deliver_timeout(&self) -> Duration {
            Duration::from_millis(200)
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

    async fn wait_status(controller: &MockController, key: &str, expected: ServiceStatus) {
        for _ in 0..400 {
            if controller.service.get_all_status().await.get(key) == Some(&expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("status of '{key}' did not reach {expected:?}");
    }

    #[tokio::test]
    async fn happy_path_persists_notifies_and_delivers() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        let config = MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 };
        let saved = controller.handle_service_config(config).await.unwrap();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 1);
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
        wait_for(|| !starter.started.lock().unwrap().is_empty()).await;
        assert_eq!(*starter.started.lock().unwrap(), vec![("wan0".to_string(), 1)]);
        wait_status(&controller, "wan0", ServiceStatus::Running).await;
    }

    #[tokio::test]
    async fn stale_update_at_rejects_with_zero_side_effects() {
        let store = MockStore::default();
        let old = MockConfig { id: "wan0".to_string(), value: 7, update_at: 3.0 };
        store.seed(old.clone());
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        let stale = MockConfig {
            id: "wan0".to_string(),
            value: 8,
            update_at: old.update_at + 1.0,
        };
        let result = controller.handle_service_config(stale).await;

        assert!(matches!(result, Err(DbError::Conflict)));
        assert_eq!(store.get("wan0").unwrap(), old);
        assert!(controller.notify_log.lock().unwrap().is_empty());
        assert!(starter.started.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn persist_failure_propagates_without_notify_or_delivery() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        store.fail_checked_upsert.store(true, Ordering::SeqCst);
        let result = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await;

        assert!(matches!(result, Err(DbError::Conflict)));
        assert!(store.get("wan0").is_none());
        assert!(controller.notify_log.lock().unwrap().is_empty());
        assert!(starter.started.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_start_is_persisted_and_reported() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        starter.fail_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter).await;

        let saved = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 1);
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
        wait_status(&controller, "wan0", ServiceStatus::Failed).await;
    }

    #[tokio::test]
    async fn failed_start_keeps_latest_intent_without_rollback() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.auto_start.store(true, Ordering::SeqCst);
        let controller = controller(store.clone(), starter.clone()).await;

        controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();
        wait_status(&controller, "wan0", ServiceStatus::Running).await;

        starter.fail_next.store(true, Ordering::SeqCst);
        let saved = controller
            .handle_service_config(MockConfig {
                id: "wan0".to_string(),
                value: 2,
                update_at: store.get("wan0").unwrap().update_at,
            })
            .await
            .unwrap();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 2, "latest intent must not roll back");
        assert_eq!(
            *controller.notify_log.lock().unwrap(),
            vec!["changed:1".to_string(), "changed:2".to_string()]
        );
        wait_for(|| starter.started.lock().unwrap().len() == 2).await;
        assert_eq!(
            *starter.started.lock().unwrap(),
            vec![("wan0".to_string(), 1), ("wan0".to_string(), 2)]
        );
        wait_status(&controller, "wan0", ServiceStatus::Failed).await;
    }

    #[tokio::test]
    async fn disabled_config_persists_and_reports_disabled() {
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
        wait_status(&controller, "wan0", ServiceStatus::Disabled).await;
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:1".to_string()]);
    }

    #[tokio::test]
    async fn saturated_queue_times_out_delivery_but_persists() {
        let store = MockStore::default();
        let starter = MockStarter::new();
        starter.block_start.store(true, Ordering::SeqCst);
        let starter_probe = starter.clone();
        let controller = controller(store.clone(), starter.clone()).await;

        // 第一份:supervisor 接收后进入 start() 并永久阻塞,通道腾空
        controller
            .service
            .update_service(MockConfig { id: "wan0".to_string(), value: 1, update_at: 0.0 })
            .await
            .unwrap();
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

        // 第三份:经 handle_service_config 投递须等满 deliver_timeout 后放弃,
        // 但入库与通知照常完成
        let started_at = tokio::time::Instant::now();
        let saved = controller
            .handle_service_config(MockConfig { id: "wan0".to_string(), value: 3, update_at: 0.0 })
            .await
            .unwrap();
        let elapsed = started_at.elapsed();

        assert!(saved.update_at > 0.0);
        assert_eq!(store.get("wan0").unwrap().value, 3);
        assert_eq!(*controller.notify_log.lock().unwrap(), vec!["changed:3".to_string()]);
        assert!(
            elapsed >= Duration::from_millis(200),
            "delivery must wait out the bounded timeout, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "delivery timeout must stay bounded, took {elapsed:?}"
        );
        assert_eq!(*starter.started.lock().unwrap(), vec![("wan0".to_string(), 1)]);
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
}
