mod job_sync;
mod runtime_state;
mod task_registry;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::concurrency::task_label;
use landscape_common::database::store::ConfigStore;
use landscape_common::ddns::{DdnsError, DdnsJob, DdnsJobRuntime, DdnsTaskProgress};
use landscape_common::event::hub::{
    IAPrefixEvent, IAPrefixEventReader, LanDeviceChange, LanDeviceEventReader,
};
use landscape_common::memtrack::{TaggedFuture, subsystem_from_task_label};
use landscape_common::{
    database::error::DbError, database::store::Change, service::controller::ConfigStoreController,
};
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_core::pd_prefix::IAPrefixMap;
use landscape_database::ddns::repository::DdnsJobRepository;
use landscape_database::dns_provider_profile::repository::DnsProviderProfileRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::RwLock;
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;
use uuid::Uuid;

use runtime_state::{
    build_job_runtime, job_has_enrolled_device_ipv6, job_has_enrolled_device_ipv6_for_wan,
    job_has_enrolled_device_source_for_device, job_matches_wan_event, job_needs_retry,
};
use task_registry::{DdnsTaskFinish, DdnsTaskRegistry, DdnsTaskStart};

use crate::cert::dns_provider::{build_record_updater, validate_provider_zone_access};
use crate::sys_service::route::{IpRouteService, WanRouteEvent};

const DDNS_SYNC_INTERVAL_SECS: u64 = 60;
const DDNS_RETRY_INTERVAL_SECS: u64 = 5;
const DEFAULT_DDNS_RECORD_TTL: u32 = 120;

type DdnsRuntimeMap = Arc<RwLock<HashMap<Uuid, DdnsJobRuntime>>>;

#[derive(Clone)]
pub struct DdnsService {
    store: DdnsJobRepository,
    profile_store: DnsProviderProfileRepository,
    route_service: IpRouteService,
    runtime: DdnsRuntimeMap,
    tasks: DdnsTaskRegistry,
    prefix_map: IAPrefixMap,
    directory: Arc<LanDeviceDirectory>,
    stop_token: CancellationToken,
    tracker: TaskTracker,
}

impl DdnsService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        directory: Arc<LanDeviceDirectory>,
        lan_device_reader: LanDeviceEventReader,
        prefix_reader: IAPrefixEventReader,
    ) -> Self {
        let service = Self {
            store: store.ddns_job_store(),
            profile_store: store.dns_provider_profile_store(),
            route_service,
            runtime: Arc::new(RwLock::new(HashMap::new())),
            tasks: DdnsTaskRegistry::default(),
            prefix_map,
            directory,
            stop_token: CancellationToken::new(),
            tracker: TaskTracker::new(),
        };
        service.refresh_runtime_from_store().await;
        service.spawn_sync_loop();
        service.spawn_retry_loop();
        service.spawn_wan_update_loop();
        service.spawn_lan_device_loop(lan_device_reader);
        service.spawn_pd_prefix_loop(prefix_reader);
        service
    }

    pub async fn get_runtime_statuses(&self) -> HashMap<Uuid, DdnsJobRuntime> {
        self.runtime.read().await.clone()
    }

    pub fn task_progress_snapshot(&self) -> Vec<DdnsTaskProgress> {
        self.tasks.progress_snapshot()
    }

    /// Tracked spawn: registers the task into this service's tracker, keeping
    /// the same memtrack/tracing semantics as the global `spawn_task`; the
    /// stop side waits deterministically on it for all background loops.
    fn spawn_tracked<Fut>(&self, label: &'static str, future: Fut) -> TokioJoinHandle<Fut::Output>
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let tag = subsystem_from_task_label(label);
        self.tracker.spawn(
            TaggedFuture::new(tag, future).instrument(tracing::info_span!("task", task = label)),
        )
    }

    /// Request stop and wait for all background loops to finish; `timeout`
    /// bounds hung in-flight provider calls (the HTTP client already enforces
    /// a 30s request timeout, this is the shutdown-side ceiling).
    pub async fn shutdown_and_wait(&self, timeout: Duration) {
        self.stop_token.cancel();
        self.tasks.cancel_all();
        self.tracker.close();
        match tokio::time::timeout(timeout, self.tracker.wait()).await {
            Ok(()) => tracing::info!("ddns background loops stopped"),
            Err(_) => tracing::warn!(
                "ddns shutdown timed out after {timeout:?}; in-flight sync may still be draining"
            ),
        }
    }

    pub async fn sync_job_now(&self, job_id: Uuid) -> Result<DdnsJobRuntime, DdnsError> {
        let job =
            self.store.find_by_id(job_id).await?.ok_or_else(|| DdnsError::JobNotFound(job_id))?;

        if job.enable {
            if !self.spawn_job_sync_strict(job.clone()) {
                return Err(DdnsError::TaskInProgress(job_id));
            }
        } else {
            self.sync_runtime_for_job(&job).await;
        }

        Ok(self
            .runtime
            .read()
            .await
            .get(&job.id)
            .cloned()
            .unwrap_or_else(|| DdnsJobRuntime::from_config(&job)))
    }

    fn spawn_sync_loop(&self) {
        let service = self.clone();
        let token = self.stop_token.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(DDNS_SYNC_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        if let Err(e) = service.sync_all_enabled_jobs().await {
                            tracing::warn!("ddns sync pass failed: {e:?}");
                        }
                    }
                }
            }
            tracing::info!("ddns sync loop stopped");
        });
    }

    fn spawn_retry_loop(&self) {
        let service = self.clone();
        let token = self.stop_token.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(DDNS_RETRY_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        if let Err(e) = service.retry_pending_jobs().await {
                            tracing::warn!("ddns retry pass failed: {e:?}");
                        }
                    }
                }
            }
            tracing::info!("ddns retry loop stopped");
        });
    }

    fn spawn_wan_update_loop(&self) {
        let service = self.clone();
        let mut events = self.route_service.subscribe_wan_route_events();
        let token = self.stop_token.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    result = events.recv() => {
                        match result {
                            Ok(event) => {
                                if let Err(e) = service.sync_jobs_for_wan_event(event).await {
                                    tracing::warn!("ddns wan-triggered sync failed: {e:?}");
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::warn!(
                                    "ddns wan event listener lagged, skipped {skipped} events"
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
            tracing::info!("ddns wan event loop stopped");
        });
    }

    /// Trigger on directory change events: the directory already folded the
    /// raw protocol events (DHCPv6/SLAAC/Flush, DHCPv4 leases, ARP), so a
    /// single notification replaces the per-protocol diffing the old
    /// ipv6-assign listener had to do itself. `Identity` also triggers: a
    /// device that is enrolled after its addresses were observed changes no
    /// address set, yet its jobs become resolvable.
    fn spawn_lan_device_loop(&self, mut reader: LanDeviceEventReader) {
        let service = self.clone();
        let token = self.stop_token.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    result = reader.recv() => {
                        match result {
                            Ok(event) => {
                                if !matches!(
                                    event.change,
                                    LanDeviceChange::Addresses | LanDeviceChange::Identity
                                ) {
                                    continue;
                                }
                                let Some(device_id) = event.device_id else { continue };
                                if let Err(e) = service.on_device_changed(device_id).await {
                                    tracing::warn!("ddns lan device handler failed: {e:?}");
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                // Missed notifications are reconciled by the periodic
                                // full sync (DDNS_SYNC_INTERVAL_SECS).
                                tracing::warn!(
                                    "ddns lan device listener lagged, skipped {skipped} events; periodic full sync will reconcile"
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
            tracing::info!("ddns lan device loop stopped");
        });
    }

    /// A device's addresses or identity moved in the directory: re-resolve
    /// every enabled job anchored on it (both families).
    async fn on_device_changed(&self, device_id: Uuid) -> Result<(), DbError> {
        let jobs = self.store.find_enabled().await?;
        let matching: Vec<_> = jobs
            .into_iter()
            .filter(|job| job_has_enrolled_device_source_for_device(job, device_id))
            .collect();

        if !matching.is_empty() {
            self.sync_jobs_now(matching).await;
        }
        Ok(())
    }

    fn spawn_pd_prefix_loop(&self, mut reader: IAPrefixEventReader) {
        let svc = self.clone();
        let token = self.stop_token.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    result = reader.recv() => {
                        match result {
                            Ok(IAPrefixEvent::Updated { link_id })
                            | Ok(IAPrefixEvent::Expired { link_id }) => {
                                let jobs = match svc.store.find_enabled().await {
                                    Ok(jobs) => jobs,
                                    Err(e) => {
                                        tracing::error!("ddns pd prefix loop: find_enabled error: {e:?}");
                                        continue;
                                    }
                                };
                                let matching: Vec<_> = jobs
                                    .into_iter()
                                    .filter(|job| job_has_enrolled_device_ipv6_for_wan(job, &link_id))
                                    .collect();
                                if !matching.is_empty() {
                                    svc.sync_jobs_now(matching).await;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("ddns pd prefix loop: lagged by {n} messages");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
            tracing::info!("ddns pd prefix loop stopped");
        });
    }

    async fn on_config_changed_for_pd(&self, jobs: &[DdnsJob]) {
        let matching: Vec<_> = jobs
            .iter()
            .filter(|j| j.enable)
            .filter(|job| job_has_enrolled_device_ipv6(job))
            .cloned()
            .collect();
        if !matching.is_empty() {
            self.sync_jobs_now(matching).await;
        }
    }

    pub async fn checked_set_job(&self, mut config: DdnsJob) -> Result<DdnsJob, DdnsError> {
        if self.tasks.has_task(config.id) {
            return Err(DdnsError::TaskInProgress(config.id));
        }
        config.normalize_for_save().map_err(DdnsError::InvalidConfig)?;
        config.validate().map_err(DdnsError::InvalidConfig)?;
        let profile = self
            .profile_store
            .find_by_id(config.provider_profile_id)
            .await?
            .ok_or_else(|| DdnsError::ProviderProfileNotFound(config.provider_profile_id))?;
        build_record_updater(&profile.provider_config)
            .map_err(|e| DdnsError::ProviderUnavailable(e.to_string()))?;
        validate_provider_zone_access(&profile.provider_config, &config.zone_name)
            .await
            .map_err(|e| DdnsError::ZoneAccessDenied(e.to_string()))?;

        // Capture before save: the notify rebuild drops last_published_ips.
        let disable_cleanup = match self.store.find_by_id(config.id).await? {
            Some(old) if old.enable && !config.enable => {
                Some((old, self.cleanup_targets(config.id).await))
            }
            _ => None,
        };

        let saved = self.checked_set(config).await?;
        if saved.enable {
            self.sync_enabled_job_now(&saved).await;
        } else {
            if let Some((old, targets)) = disable_cleanup
                && !targets.is_empty()
            {
                self.spawn_job_cleanup(old, targets);
            }
            self.sync_runtime_for_job(&saved).await;
        }
        Ok(saved)
    }

    pub async fn checked_delete(&self, id: Uuid) -> Result<Option<DdnsJob>, DdnsError> {
        if self.tasks.has_task(id) {
            return Err(DdnsError::TaskInProgress(id));
        }
        let targets = self.cleanup_targets(id).await;
        let deleted = self.delete(id).await?;
        if let Some(old) = &deleted
            && !targets.is_empty()
        {
            self.spawn_job_cleanup(old.clone(), targets);
        }
        Ok(deleted)
    }

    async fn refresh_runtime_from_store(&self) {
        let jobs = self.store.list().await.unwrap_or_default();
        self.refresh_runtime_with_jobs(jobs).await;
    }

    /// Incrementally fold write changes into the runtime map, reusing the
    /// previous entry for an updated job like the full rebuild does.
    async fn apply_changes_to_runtime(&self, changes: &[Change<DdnsJob>]) {
        let mut runtime = self.runtime.write().await;
        for change in changes {
            let prev = runtime.remove(&change.new.id);
            runtime.insert(change.new.id, build_job_runtime(&change.new, prev));
        }
    }

    async fn refresh_runtime_with_jobs(&self, jobs: Vec<DdnsJob>) {
        let mut runtime = self.runtime.write().await;
        let mut current = std::mem::take(&mut *runtime);
        for job in jobs {
            runtime.insert(job.id, build_job_runtime(&job, current.remove(&job.id)));
        }
    }

    async fn sync_runtime_for_job(&self, job: &DdnsJob) {
        let mut runtime = self.runtime.write().await;
        let next = build_job_runtime(job, runtime.remove(&job.id));
        runtime.insert(job.id, next);
    }

    async fn sync_all_enabled_jobs(&self) -> Result<(), DbError> {
        self.sync_jobs_now(self.store.find_enabled().await?).await;
        Ok(())
    }

    async fn retry_pending_jobs(&self) -> Result<(), DbError> {
        let jobs = self.store.find_enabled().await?;
        let runtime = self.runtime.read().await.clone();
        let pending: Vec<_> =
            jobs.into_iter().filter(|job| job_needs_retry(job, runtime.get(&job.id))).collect();
        if pending.is_empty() {
            return Ok(());
        }

        self.sync_jobs_now(pending).await;
        Ok(())
    }

    async fn sync_jobs_for_wan_event(&self, event: WanRouteEvent) -> Result<(), DbError> {
        let matching: Vec<_> = self
            .store
            .find_enabled()
            .await?
            .into_iter()
            .filter(|job| job_matches_wan_event(job, &event))
            .collect();
        if matching.is_empty() {
            return Ok(());
        }

        self.sync_jobs_now(matching).await;
        Ok(())
    }

    async fn sync_enabled_job_now(&self, job: &DdnsJob) {
        self.sync_jobs_now(vec![job.clone()]).await;
    }

    async fn sync_jobs_now(&self, jobs: Vec<DdnsJob>) {
        for job in jobs {
            self.spawn_job_sync(job);
        }
    }

    /// Background entry: start or mark pending.
    fn spawn_job_sync(&self, job: DdnsJob) {
        if let DdnsTaskStart::Started(cancel) = self.tasks.start_or_mark(job.id) {
            self.spawn_sync_reconcile_loop(job, cancel);
        }
    }

    /// Strict entry for manual sync: returns false instead of queueing.
    fn spawn_job_sync_strict(&self, job: DdnsJob) -> bool {
        let Ok(cancel) = self.tasks.insert(job.id) else {
            return false;
        };
        self.spawn_sync_reconcile_loop(job, cancel);
        true
    }

    /// Runs full-state sync rounds until the pending flag stops being set.
    fn spawn_sync_reconcile_loop(&self, job: DdnsJob, cancel: CancellationToken) {
        let svc = self.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            let mut job = job;
            loop {
                let runtime = svc.sync_one_job(&job, &cancel).await;

                match svc.store.find_by_id(job.id).await {
                    Ok(Some(current)) => {
                        job = current;
                        if job.enable {
                            svc.runtime.write().await.insert(job.id, runtime);
                        } else {
                            svc.tasks.remove(job.id);
                            break;
                        }
                    }
                    _ => {
                        svc.tasks.remove(job.id);
                        break;
                    }
                }

                if cancel.is_cancelled() {
                    svc.tasks.remove(job.id);
                    break;
                }

                match svc.tasks.finish_or_continue(job.id) {
                    DdnsTaskFinish::Continue => continue,
                    DdnsTaskFinish::Stopped => break,
                }
            }
        });
    }

    pub async fn cancel_job_sync(&self, job_id: Uuid) -> Result<DdnsJobRuntime, DdnsError> {
        let job =
            self.store.find_by_id(job_id).await?.ok_or_else(|| DdnsError::JobNotFound(job_id))?;
        self.tasks.cancel_task(job_id);
        Ok(self
            .runtime
            .read()
            .await
            .get(&job_id)
            .cloned()
            .unwrap_or_else(|| DdnsJobRuntime::from_config(&job)))
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for DdnsService {
    type Id = Uuid;
    type Config = DdnsJob;
    type Store = DdnsJobRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    // Remote cleanup on disable/delete is triggered by the API layer
    // (checked_set_job/checked_delete), not here; notify only rebuilds state.
    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        let jobs: Vec<DdnsJob> = changes.iter().map(|c| c.new.clone()).collect();
        self.apply_changes_to_runtime(&changes).await;
        self.on_config_changed_for_pd(&jobs).await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.runtime.write().await.remove(&old.id);
    }
}
