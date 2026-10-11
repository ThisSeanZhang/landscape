use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::concurrency::task_label;
use landscape_common::database::store::ConfigStore;
use landscape_common::ddns::{
    DdnsError, DdnsFamilyRuntime, DdnsJob, DdnsJobRuntime, DdnsJobStatus, DdnsRecordRuntime,
    DdnsRuntimeReason, DdnsSource, DdnsTaskPhase, DdnsTaskProgress, IpFamily, fqdn_for_zone_record,
};
use landscape_common::dns::provider_profile::DnsProviderProfile;
use landscape_common::event::hub::{
    IAPrefixEvent, IAPrefixEventReader, LanDeviceChange, LanDeviceEventReader,
};
use landscape_common::lan_service::lan_ipv6::{combine_ipv6_prefix_suffix, extract_ipv6_suffix};
use landscape_common::memtrack::{TaggedFuture, subsystem_from_task_label};
use landscape_common::{
    database::error::DbError, database::store::Change, service::controller::ConfigStoreController,
};
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_core::pd_prefix::IAPrefixMap;
use landscape_database::{
    ddns::repository::DdnsJobRepository,
    dns_provider_profile::repository::DnsProviderProfileRepository,
    provider::LandscapeDBServiceProvider,
};

use tokio::sync::RwLock;
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;
use uuid::Uuid;

use crate::cert::dns_provider::{build_record_updater, validate_provider_zone_access};
use crate::sys_service::route::{IpRouteService, WanRouteEvent};

use landscape_common::sys_service::route_service::RouteOwner;

const DDNS_SYNC_INTERVAL_SECS: u64 = 60;
const DDNS_RETRY_INTERVAL_SECS: u64 = 5;
const DEFAULT_DDNS_RECORD_TTL: u32 = 120;

type DdnsRuntimeMap = Arc<RwLock<HashMap<Uuid, DdnsJobRuntime>>>;

#[derive(Clone)]
struct DdnsTaskEntry {
    cancel: CancellationToken,
    progress: DdnsTaskProgress,
    /// Reconcile-loop dirty flag: set by triggers arriving while this task runs.
    pending: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
struct DdnsTaskRegistry {
    entries: Arc<ArcSwap<HashMap<Uuid, DdnsTaskEntry>>>,
}

enum DdnsTaskStart {
    Started(CancellationToken),
    MarkedPending,
}

enum DdnsTaskFinish {
    /// The pending flag was set: keep the entry and run another round.
    Continue,
    /// No pending work: the entry was removed.
    Stopped,
}

impl DdnsTaskRegistry {
    /// Strict insert for user-initiated sync: fails when a task already runs.
    fn insert(&self, id: Uuid) -> Result<CancellationToken, ()> {
        let cancel = CancellationToken::new();
        let mut duplicate = false;
        self.entries.rcu(|current| {
            if current.contains_key(&id) {
                duplicate = true;
                return current.clone();
            }
            duplicate = false;
            let mut next = HashMap::clone(current);
            next.insert(
                id,
                DdnsTaskEntry {
                    cancel: cancel.clone(),
                    progress: DdnsTaskProgress::new(id),
                    pending: Arc::new(AtomicBool::new(false)),
                },
            );
            Arc::new(next)
        });
        if duplicate { Err(()) } else { Ok(cancel) }
    }

    /// Start when the slot is free, else mark the running task's pending flag.
    fn start_or_mark(&self, id: Uuid) -> DdnsTaskStart {
        let mut started = None;
        self.entries.rcu(|current| {
            // rcu retries under contention: drop any token from a lost
            // attempt so we never report an orphaned start.
            started = None;
            if let Some(entry) = current.get(&id) {
                entry.pending.store(true, Ordering::Release);
                return current.clone();
            }
            let cancel = CancellationToken::new();
            let mut next = HashMap::clone(current);
            next.insert(
                id,
                DdnsTaskEntry {
                    cancel: cancel.clone(),
                    progress: DdnsTaskProgress::new(id),
                    pending: Arc::new(AtomicBool::new(false)),
                },
            );
            started = Some(cancel);
            Arc::new(next)
        });
        match started {
            Some(cancel) => DdnsTaskStart::Started(cancel),
            None => DdnsTaskStart::MarkedPending,
        }
    }

    /// Consume a pending mark (keep the entry, reset progress) or remove the
    /// entry; one rcu so a racing mark is never discarded with the entry.
    fn finish_or_continue(&self, id: Uuid) -> DdnsTaskFinish {
        let mut keep_going = false;
        self.entries.rcu(|current| {
            let Some(entry) = current.get(&id) else {
                keep_going = false;
                return current.clone();
            };
            let mut next = HashMap::clone(current);
            // The pending flag lives on a shared Arc, so a failed rcu attempt
            // may already have consumed a mark; honor it across retries.
            keep_going = entry.pending.swap(false, Ordering::AcqRel) || keep_going;
            if keep_going {
                next.insert(
                    id,
                    DdnsTaskEntry {
                        cancel: entry.cancel.clone(),
                        progress: DdnsTaskProgress::new(id),
                        pending: entry.pending.clone(),
                    },
                );
            } else {
                keep_going = false;
                next.remove(&id);
            }
            Arc::new(next)
        });
        if keep_going { DdnsTaskFinish::Continue } else { DdnsTaskFinish::Stopped }
    }

    fn has_task(&self, id: Uuid) -> bool {
        self.entries.load().contains_key(&id)
    }

    fn remove(&self, id: Uuid) {
        self.entries.rcu(|current| {
            if !current.contains_key(&id) {
                return current.clone();
            }
            let mut next = HashMap::clone(current);
            next.remove(&id);
            Arc::new(next)
        });
    }

    fn update_phase(&self, id: Uuid, phase: DdnsTaskPhase, detail: Option<String>) {
        self.entries.rcu(|current| {
            let Some(entry) = current.get(&id) else {
                return current.clone();
            };
            let mut next = HashMap::clone(current);
            let mut progress = entry.progress.clone();
            progress.advance(phase, detail.clone());
            next.insert(
                id,
                DdnsTaskEntry {
                    cancel: entry.cancel.clone(),
                    progress,
                    pending: entry.pending.clone(),
                },
            );
            Arc::new(next)
        });
    }

    fn cancel_task(&self, id: Uuid) -> bool {
        if let Some(entry) = self.entries.load().get(&id) {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }

    fn cancel_all(&self) {
        for entry in self.entries.load().values() {
            entry.cancel.cancel();
        }
    }

    fn progress_snapshot(&self) -> Vec<DdnsTaskProgress> {
        self.entries.load().values().map(|entry| entry.progress.clone()).collect()
    }
}

/// A (record, family) pair previously published by this process and thus
/// owned for remote cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DdnsRecordCleanupTarget {
    record_name: String,
    family: IpFamily,
}

fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
    }
}

fn family_runtime_mut(record: &mut DdnsRecordRuntime, family: IpFamily) -> &mut DdnsFamilyRuntime {
    match family {
        IpFamily::Ipv4 => &mut record.ipv4,
        IpFamily::Ipv6 => &mut record.ipv6,
    }
}

/// Only families with recorded published IPs are eligible for remote cleanup.
fn cleanup_targets_from_runtime(runtime: &DdnsJobRuntime) -> Vec<DdnsRecordCleanupTarget> {
    runtime
        .records
        .iter()
        .flat_map(|record| {
            [(IpFamily::Ipv4, &record.ipv4), (IpFamily::Ipv6, &record.ipv6)]
                .into_iter()
                .filter(|(_, family)| !family.last_published_ips.is_empty())
                .map(|(family, _)| DdnsRecordCleanupTarget {
                    record_name: record.name.clone(),
                    family,
                })
        })
        .collect()
}

struct ResolveRecordIpError {
    status: DdnsJobStatus,
    reason: DdnsRuntimeReason,
    detail: String,
    retryable: bool,
    next_retry_at: Option<f64>,
}

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

    async fn cleanup_targets(&self, job_id: Uuid) -> Vec<DdnsRecordCleanupTarget> {
        let runtime = self.runtime.read().await;
        runtime.get(&job_id).map(cleanup_targets_from_runtime).unwrap_or_default()
    }

    fn spawn_job_cleanup(&self, job: DdnsJob, targets: Vec<DdnsRecordCleanupTarget>) {
        let Ok(cancel) = self.tasks.insert(job.id) else {
            tracing::warn!(
                "ddns cleanup for job {}: task slot busy, skipping remote cleanup",
                job.id
            );
            self.tasks.cancel_task(job.id);
            return;
        };
        let svc = self.clone();
        self.spawn_tracked(task_label::task::DNS_DDNS_JOB, async move {
            svc.cleanup_one_job(&job, &targets, &cancel).await;
            svc.tasks.remove(job.id);
        });
    }

    async fn cleanup_one_job(
        &self,
        job: &DdnsJob,
        targets: &[DdnsRecordCleanupTarget],
        cancel: &CancellationToken,
    ) {
        let profile = match self.profile_store.find_by_id(job.provider_profile_id).await {
            Ok(Some(profile)) => profile,
            Ok(None) => {
                tracing::warn!(
                    "ddns cleanup for job {}: provider profile not found, remote records left as-is",
                    job.id
                );
                return;
            }
            Err(e) => {
                tracing::warn!("ddns cleanup for job {}: profile lookup failed: {e:?}", job.id);
                return;
            }
        };

        let total = targets.len();
        self.tasks.update_phase(job.id, DdnsTaskPhase::CleaningUp, None);

        for (idx, target) in targets.iter().enumerate() {
            if cancel.is_cancelled() {
                break;
            }
            self.tasks.update_phase(
                job.id,
                DdnsTaskPhase::CleaningUp,
                Some(format!(
                    "{} ({}, {}/{total})",
                    target.record_name,
                    family_label(target.family),
                    idx + 1,
                )),
            );
            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                result = delete_dns_records(
                    &profile.provider_config,
                    &job.zone_name,
                    &target.record_name,
                    target.family,
                ) => result,
            };
            let now = landscape_common::utils::time::get_f64_timestamp();
            let mut runtime = self.runtime.write().await;
            let Some(runtime) = runtime.get_mut(&job.id) else { continue };
            let Some(family_runtime) = runtime
                .records
                .iter_mut()
                .find(|record| record.name.eq_ignore_ascii_case(&target.record_name))
                .map(|record| family_runtime_mut(record, target.family))
            else {
                continue;
            };
            match result {
                Ok(()) => {
                    family_runtime.last_published_ips.clear();
                    family_runtime.last_sync_at = Some(now);
                    apply_family_runtime_state(
                        family_runtime,
                        DdnsJobStatus::Idle,
                        DdnsRuntimeReason::Disabled,
                        Some(runtime_message_for_reason(DdnsRuntimeReason::Disabled).to_string()),
                        None,
                        false,
                        None,
                    );
                }
                Err(e) => {
                    let (reason, retryable) = classify_provider_error(&e);
                    tracing::warn!(
                        "ddns cleanup for job {} record '{}' failed: {e}",
                        job.id,
                        target.record_name
                    );
                    family_runtime.last_sync_at = Some(now);
                    apply_family_runtime_state(
                        family_runtime,
                        DdnsJobStatus::Error,
                        reason,
                        Some(runtime_message_for_reason(reason).to_string()),
                        Some(e),
                        retryable,
                        None,
                    );
                }
            }
            runtime.last_update_at = Some(now);
            apply_job_runtime_summary(runtime);
        }
    }

    async fn sync_one_job(&self, job: &DdnsJob, cancel: &CancellationToken) -> DdnsJobRuntime {
        let mut runtime = {
            let current = self.runtime.read().await.get(&job.id).cloned();
            build_job_runtime(job, current)
        };

        self.tasks.update_phase(job.id, DdnsTaskPhase::ResolvingSource, None);

        let profile = match self.profile_store.find_by_id(job.provider_profile_id).await {
            Ok(Some(profile)) => profile,
            Ok(None) => {
                apply_job_error(
                    &mut runtime,
                    DdnsRuntimeReason::ProviderProfileMissing,
                    "DNS provider profile not found".to_string(),
                    false,
                    None,
                );
                return runtime;
            }
            Err(e) => {
                apply_job_error(
                    &mut runtime,
                    DdnsRuntimeReason::UnknownError,
                    e.to_string(),
                    false,
                    None,
                );
                return runtime;
            }
        };

        let configured_families = [IpFamily::Ipv4, IpFamily::Ipv6]
            .into_iter()
            .filter(|family| job.has_source_for_family(*family))
            .count();
        let total_steps = job.records.iter().filter(|cfg| cfg.enable).count() * configured_families;
        let mut step = 0usize;

        'records: for record in &mut runtime.records {
            let enabled = job
                .records
                .iter()
                .find(|cfg| cfg.name == record.name)
                .map(|cfg| cfg.enable)
                .unwrap_or(false);
            if !enabled {
                for family in [IpFamily::Ipv4, IpFamily::Ipv6] {
                    {
                        let family_runtime = family_runtime_mut(record, family);
                        if family_runtime.last_published_ips.is_empty() {
                            apply_family_runtime_state(
                                family_runtime,
                                DdnsJobStatus::Idle,
                                DdnsRuntimeReason::Disabled,
                                None,
                                None,
                                false,
                                None,
                            );
                            continue;
                        }
                    }

                    if cancel.is_cancelled() {
                        break 'records;
                    }

                    self.tasks.update_phase(
                        job.id,
                        DdnsTaskPhase::CleaningUp,
                        Some(format!("{} ({})", record.name, family_label(family))),
                    );
                    let result = tokio::select! {
                        _ = cancel.cancelled() => break 'records,
                        result = delete_dns_records(
                            &profile.provider_config,
                            &job.zone_name,
                            &record.name,
                            family,
                        ) => result,
                    };
                    let now = landscape_common::utils::time::get_f64_timestamp();
                    let family_runtime = family_runtime_mut(record, family);
                    family_runtime.last_sync_at = Some(now);
                    match result {
                        Ok(()) => {
                            family_runtime.last_published_ips.clear();
                            apply_family_runtime_state(
                                family_runtime,
                                DdnsJobStatus::Idle,
                                DdnsRuntimeReason::Disabled,
                                Some(
                                    runtime_message_for_reason(DdnsRuntimeReason::Disabled)
                                        .to_string(),
                                ),
                                None,
                                false,
                                None,
                            );
                        }
                        Err(e) => {
                            // Keep last_published_ips so the periodic sync retries.
                            let (reason, retryable) = classify_provider_error(&e);
                            apply_family_runtime_state(
                                family_runtime,
                                DdnsJobStatus::Error,
                                reason,
                                Some(runtime_message_for_reason(reason).to_string()),
                                Some(e),
                                retryable,
                                None,
                            );
                        }
                    }
                }
                continue;
            }

            for family in [IpFamily::Ipv4, IpFamily::Ipv6] {
                if !job.has_source_for_family(family) {
                    let family_runtime = match family {
                        IpFamily::Ipv4 => &mut record.ipv4,
                        IpFamily::Ipv6 => &mut record.ipv6,
                    };
                    apply_family_runtime_state(
                        family_runtime,
                        DdnsJobStatus::Idle,
                        DdnsRuntimeReason::NotConfigured,
                        Some(
                            runtime_message_for_reason(DdnsRuntimeReason::NotConfigured)
                                .to_string(),
                        ),
                        None,
                        false,
                        None,
                    );
                    continue;
                }

                if cancel.is_cancelled() {
                    break 'records;
                }

                let current_ips = self.resolve_record_ip(&job.sources, family).await;
                step += 1;
                self.tasks.update_phase(
                    job.id,
                    DdnsTaskPhase::Publishing,
                    Some(format!(
                        "{} ({}, {}/{total_steps})",
                        record.name,
                        family_label(family),
                        step,
                    )),
                );
                tokio::select! {
                    _ = cancel.cancelled() => break 'records,
                    _ = self.sync_one_record_family(
                        &profile.provider_config,
                        &job.zone_name,
                        record,
                        family,
                        current_ips,
                        effective_ddns_ttl(job, &profile),
                        effective_ttl_config_updated_at(job, &profile),
                    ) => {}
                }
            }
        }

        runtime.last_update_at = Some(landscape_common::utils::time::get_f64_timestamp());
        apply_job_runtime_summary(&mut runtime);
        runtime
    }

    async fn resolve_record_ip(
        &self,
        sources: &[DdnsSource],
        wanted_family: IpFamily,
    ) -> Result<Vec<IpAddr>, ResolveRecordIpError> {
        let ts = landscape_common::utils::time::get_f64_timestamp();
        let mut last_error = None;
        for source in sources {
            match source {
                DdnsSource::LocalWan { iface_name, link_id, family, .. }
                    if *family == wanted_family =>
                {
                    let owner = RouteOwner::Link(*link_id);
                    let route = match family {
                        IpFamily::Ipv4 => self.route_service.get_ipv4_wan_route(&owner).await,
                        IpFamily::Ipv6 => self.route_service.get_ipv6_wan_route(&owner).await,
                    };
                    if let Some(route) = route {
                        if wanted_family == IpFamily::Ipv6
                            && let IpAddr::V6(addr) = route.iface_ip
                            && !((addr.segments()[0] & 0xe000) == 0x2000)
                            && !addr.is_unique_local()
                        {
                            last_error = Some(ResolveRecordIpError {
                                status: DdnsJobStatus::Idle,
                                reason: DdnsRuntimeReason::WaitingWanIp,
                                detail: format!(
                                    "WAN interface '{iface_name}' IPv6 address is link-local, waiting for a global/unique-local address"
                                ),
                                retryable: true,
                                next_retry_at: Some(ts + DDNS_RETRY_INTERVAL_SECS as f64),
                            });
                            continue;
                        }
                        return Ok(vec![route.iface_ip]);
                    }
                    last_error = Some(ResolveRecordIpError {
                        status: DdnsJobStatus::Idle,
                        reason: DdnsRuntimeReason::WaitingWanIp,
                        detail: format!("WAN route for interface '{iface_name}' is not ready yet"),
                        retryable: true,
                        next_retry_at: Some(ts + DDNS_RETRY_INTERVAL_SECS as f64),
                    });
                }
                DdnsSource::EnrolledDevice { device_id, wan_pd_link_id, family, .. }
                    if *family == wanted_family =>
                {
                    match wanted_family {
                        IpFamily::Ipv6 => {
                            let raw_ips: Vec<Ipv6Addr> = match self
                                .directory
                                .entry_by_device_id(device_id)
                            {
                                Some(entry) => entry.ipv6_addrs.keys().copied().collect(),
                                None => {
                                    last_error = Some(ResolveRecordIpError {
                                        status: DdnsJobStatus::Idle,
                                        reason: DdnsRuntimeReason::WaitingLanDeviceIp,
                                        detail: format!(
                                            "waiting for device {device_id} IPv6 address assignment"
                                        ),
                                        retryable: true,
                                        next_retry_at: Some(ts + DDNS_RETRY_INTERVAL_SECS as f64),
                                    });
                                    continue;
                                }
                            };

                            let pd = match self.prefix_map.load_actual(wan_pd_link_id) {
                                Some(p) => p,
                                None => {
                                    last_error = Some(ResolveRecordIpError {
                                        status: DdnsJobStatus::Idle,
                                        reason: DdnsRuntimeReason::WaitingWanPdPrefix,
                                        detail: format!(
                                            "waiting for WAN link {wan_pd_link_id} PD prefix delegation"
                                        ),
                                        retryable: true,
                                        next_retry_at: Some(ts + DDNS_RETRY_INTERVAL_SECS as f64),
                                    });
                                    continue;
                                }
                            };

                            let mut seen_suffixes = HashSet::new();
                            let mut result = Vec::new();
                            for raw_ip in &raw_ips {
                                if !((raw_ip.segments()[0] & 0xe000) == 0x2000)
                                    && !raw_ip.is_unique_local()
                                {
                                    continue;
                                }
                                let suffix = extract_ipv6_suffix(*raw_ip, pd.prefix_len);
                                if seen_suffixes.insert(suffix) {
                                    let ip = combine_ipv6_prefix_suffix(
                                        pd.prefix_ip,
                                        pd.prefix_len,
                                        suffix,
                                    );
                                    result.push(IpAddr::V6(ip));
                                }
                            }

                            if result.is_empty() {
                                last_error = Some(ResolveRecordIpError {
                                    status: DdnsJobStatus::Idle,
                                    reason: DdnsRuntimeReason::WaitingLanDeviceIp,
                                    detail: format!(
                                        "device {device_id} has no usable (non-link-local) IPv6 address"
                                    ),
                                    retryable: true,
                                    next_retry_at: Some(ts + DDNS_RETRY_INTERVAL_SECS as f64),
                                });
                                continue;
                            }

                            return Ok(result);
                        }
                        IpFamily::Ipv4 => {
                            let ipv4 = self
                                .directory
                                .entry_by_device_id(device_id)
                                .and_then(|entry| entry.ipv4);
                            let Some(ipv4) = ipv4 else {
                                last_error = Some(ResolveRecordIpError {
                                    status: DdnsJobStatus::Idle,
                                    reason: DdnsRuntimeReason::WaitingLanDeviceIp,
                                    detail: format!(
                                        "waiting for device {device_id} IPv4 address assignment"
                                    ),
                                    retryable: true,
                                    next_retry_at: Some(ts + DDNS_RETRY_INTERVAL_SECS as f64),
                                });
                                continue;
                            };
                            return Ok(vec![IpAddr::V4(ipv4)]);
                        }
                    }
                }
                _ => {}
            }
        }

        Err(last_error.unwrap_or_else(|| ResolveRecordIpError {
            status: DdnsJobStatus::Error,
            reason: DdnsRuntimeReason::NoMatchingSource,
            detail: format!("no matching DDNS source found for {:?}", wanted_family),
            retryable: false,
            next_retry_at: None,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn sync_one_record_family(
        &self,
        provider: &DnsProviderConfig,
        zone_name: &str,
        record: &mut DdnsRecordRuntime,
        family: IpFamily,
        current_ips: Result<Vec<IpAddr>, ResolveRecordIpError>,
        ttl: Option<u32>,
        config_updated_at: f64,
    ) {
        let ts = landscape_common::utils::time::get_f64_timestamp();
        let family_runtime = match family {
            IpFamily::Ipv4 => &mut record.ipv4,
            IpFamily::Ipv6 => &mut record.ipv6,
        };
        let last_sync_before = family_runtime.last_sync_at;
        let was_success = family_runtime.status == DdnsJobStatus::Success;
        let is_initial_publish = family_runtime.last_published_ips.is_empty();
        family_runtime.last_sync_at = Some(ts);

        let current_ips = match current_ips {
            Ok(ips) => ips,
            Err(issue) => {
                let last_error =
                    if issue.status == DdnsJobStatus::Error { Some(issue.detail) } else { None };
                apply_family_runtime_state(
                    family_runtime,
                    issue.status,
                    issue.reason,
                    Some(runtime_message_for_reason(issue.reason).to_string()),
                    last_error,
                    issue.retryable,
                    issue.next_retry_at,
                );
                return;
            }
        };

        let current_set: HashSet<IpAddr> = current_ips.iter().cloned().collect();
        let last_set: HashSet<IpAddr> = family_runtime.last_published_ips.iter().cloned().collect();

        if was_success
            && current_set == last_set
            && !current_set.is_empty()
            && last_sync_before.is_some_and(|last_sync| last_sync >= config_updated_at)
        {
            apply_family_runtime_state(
                family_runtime,
                DdnsJobStatus::Success,
                DdnsRuntimeReason::UpToDate,
                Some(runtime_message_for_reason(DdnsRuntimeReason::UpToDate).to_string()),
                None,
                false,
                None,
            );
            return;
        }

        match reconcile_dns_records(provider, zone_name, &record.name, &current_ips, ttl).await {
            Ok(()) => {
                family_runtime.last_published_ips = current_ips;
                apply_family_runtime_state(
                    family_runtime,
                    DdnsJobStatus::Success,
                    DdnsRuntimeReason::Published,
                    Some(runtime_message_for_reason(DdnsRuntimeReason::Published).to_string()),
                    None,
                    false,
                    None,
                );
            }
            Err(e) => {
                let (reason, retryable) = classify_provider_error(&e);
                let next_retry_at = if retryable {
                    Some(ts + retry_delay_secs(reason, is_initial_publish) as f64)
                } else {
                    None
                };
                apply_family_runtime_state(
                    family_runtime,
                    DdnsJobStatus::Error,
                    reason,
                    Some(runtime_message_for_reason(reason).to_string()),
                    Some(e),
                    retryable,
                    next_retry_at,
                );
            }
        }
    }
}

fn preserve_runtime(job: &DdnsJob, current: DdnsJobRuntime) -> DdnsJobRuntime {
    let current_records: HashMap<String, DdnsRecordRuntime> = current
        .records
        .into_iter()
        .map(|record| (record.name.to_ascii_lowercase(), record))
        .collect();
    let mut next = DdnsJobRuntime::from_config(job);
    next.records = job
        .records
        .iter()
        .map(|cfg| {
            current_records.get(&cfg.name.to_ascii_lowercase()).cloned().unwrap_or_else(|| {
                DdnsRecordRuntime {
                    name: cfg.name.clone(),
                    ipv4: DdnsFamilyRuntime::from_enabled(cfg.enable),
                    ipv6: DdnsFamilyRuntime::from_enabled(cfg.enable),
                }
            })
        })
        .collect();
    next.last_update_at = current.last_update_at;
    apply_job_runtime_summary(&mut next);
    next
}

fn build_job_runtime(job: &DdnsJob, current: Option<DdnsJobRuntime>) -> DdnsJobRuntime {
    if !job.enable {
        return DdnsJobRuntime::from_config(job);
    }

    current
        .map(|state| preserve_runtime(job, state))
        .unwrap_or_else(|| DdnsJobRuntime::from_config(job))
}

fn effective_ddns_ttl(job: &DdnsJob, profile: &DnsProviderProfile) -> Option<u32> {
    job.ttl.or(profile.ddns_default_ttl)
}

fn effective_ttl_config_updated_at(job: &DdnsJob, profile: &DnsProviderProfile) -> f64 {
    if job.ttl.is_some() { job.update_at } else { job.update_at.max(profile.update_at) }
}

fn job_matches_wan_event(job: &DdnsJob, event: &WanRouteEvent) -> bool {
    job.sources.iter().any(|source| match source {
        DdnsSource::LocalWan { link_id, family, .. }
            if RouteOwner::Link(*link_id) == event.owner && *family == event.family =>
        {
            true
        }
        DdnsSource::EnrolledDevice { wan_pd_link_id, family, .. }
            if RouteOwner::Link(*wan_pd_link_id) == event.owner && *family == event.family =>
        {
            true
        }
        _ => false,
    })
}

fn job_has_matching_source(job: &DdnsJob, wanted_family: IpFamily) -> bool {
    job.sources.iter().any(|source| {
        matches!(
            source,
            DdnsSource::LocalWan { family, .. } | DdnsSource::EnrolledDevice { family, .. }
                if *family == wanted_family
        )
    })
}

fn job_has_enrolled_device_source_for_device(job: &DdnsJob, device_id: Uuid) -> bool {
    job.sources.iter().any(|source| {
        matches!(source, DdnsSource::EnrolledDevice { device_id: id, .. } if *id == device_id)
    })
}

/// PD-prefix-dependent source detection is keyed by `wan_pd_link_id`; the
/// `wan_pd_id` name mirror is server-internal and may be absent on
/// API-saved jobs, so it must not gate immediate re-sync.
fn job_has_enrolled_device_ipv6(job: &DdnsJob) -> bool {
    job.sources
        .iter()
        .any(|source| matches!(source, DdnsSource::EnrolledDevice { family: IpFamily::Ipv6, .. }))
}

fn job_has_enrolled_device_ipv6_for_wan(job: &DdnsJob, wan_pd_link_id: &Uuid) -> bool {
    job_has_enrolled_device_ipv6(job)
        && job.sources.iter().any(|source| {
            matches!(
                source,
                DdnsSource::EnrolledDevice {
                    wan_pd_link_id: id,
                    family: IpFamily::Ipv6,
                    ..
                } if id == wan_pd_link_id
            )
        })
}

fn family_needs_retry(
    job: &DdnsJob,
    family: IpFamily,
    runtime: &DdnsFamilyRuntime,
    now_ts: f64,
) -> bool {
    job_has_matching_source(job, family)
        && runtime.retryable
        && runtime.last_published_ips.is_empty()
        && runtime.next_retry_at.map(|ts| ts <= now_ts).unwrap_or(true)
}

fn job_needs_retry(job: &DdnsJob, runtime: Option<&DdnsJobRuntime>) -> bool {
    if !job.enable {
        return false;
    }

    let should_retry = job_has_matching_source(job, IpFamily::Ipv4)
        || job_has_matching_source(job, IpFamily::Ipv6);
    if !should_retry {
        return false;
    }

    let Some(runtime) = runtime else {
        return true;
    };
    let now_ts = landscape_common::utils::time::get_f64_timestamp();

    job.records.iter().filter(|record| record.enable).any(|record| {
        let Some(record_runtime) = runtime
            .records
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(&record.name))
        else {
            return true;
        };

        family_needs_retry(job, IpFamily::Ipv4, &record_runtime.ipv4, now_ts)
            || family_needs_retry(job, IpFamily::Ipv6, &record_runtime.ipv6, now_ts)
    })
}

fn apply_job_error(
    runtime: &mut DdnsJobRuntime,
    reason: DdnsRuntimeReason,
    message: String,
    retryable: bool,
    next_retry_at: Option<f64>,
) {
    let ts = landscape_common::utils::time::get_f64_timestamp();
    runtime.last_update_at = Some(ts);
    runtime.status = DdnsJobStatus::Error;
    runtime.reason = reason;
    runtime.message = Some(runtime_message_for_reason(reason).to_string());
    runtime.retryable = retryable;
    runtime.next_retry_at = next_retry_at;
    for record in &mut runtime.records {
        record.ipv4.last_sync_at = Some(ts);
        apply_family_runtime_state(
            &mut record.ipv4,
            DdnsJobStatus::Error,
            reason,
            Some(runtime_message_for_reason(reason).to_string()),
            Some(message.clone()),
            retryable,
            next_retry_at,
        );
        record.ipv6.last_sync_at = Some(ts);
        apply_family_runtime_state(
            &mut record.ipv6,
            DdnsJobStatus::Error,
            reason,
            Some(runtime_message_for_reason(reason).to_string()),
            Some(message.clone()),
            retryable,
            next_retry_at,
        );
    }
}

fn apply_job_runtime_summary(runtime: &mut DdnsJobRuntime) {
    let families: Vec<&DdnsFamilyRuntime> =
        runtime.records.iter().flat_map(|record| [&record.ipv4, &record.ipv6]).collect();
    let Some(primary) = select_primary_family_runtime(&families) else {
        runtime.status = DdnsJobStatus::Idle;
        runtime.reason = DdnsRuntimeReason::Pending;
        runtime.message = None;
        runtime.retryable = false;
        runtime.next_retry_at = None;
        return;
    };

    runtime.status = primary.status.clone();
    runtime.reason = primary.reason;
    runtime.message = primary.message.clone();
    runtime.retryable = families.iter().any(|family| family.retryable);
    runtime.next_retry_at = families
        .iter()
        .filter(|family| family.retryable)
        .filter_map(|family| family.next_retry_at)
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
}

fn select_primary_family_runtime<'a>(
    families: &'a [&'a DdnsFamilyRuntime],
) -> Option<&'a DdnsFamilyRuntime> {
    families
        .iter()
        .copied()
        .find(|family| family.status == DdnsJobStatus::Error)
        .or_else(|| families.iter().copied().find(|family| family.status == DdnsJobStatus::Syncing))
        .or_else(|| {
            families.iter().copied().find(|family| {
                family.status == DdnsJobStatus::Success
                    && family.reason == DdnsRuntimeReason::Published
            })
        })
        .or_else(|| families.iter().copied().find(|family| family.status == DdnsJobStatus::Success))
        .or_else(|| {
            families.iter().copied().find(|family| {
                family.status == DdnsJobStatus::Idle
                    && family.reason != DdnsRuntimeReason::Disabled
                    && family.reason != DdnsRuntimeReason::NotConfigured
            })
        })
        .or_else(|| families.first().copied())
}

fn apply_family_runtime_state(
    family_runtime: &mut DdnsFamilyRuntime,
    status: DdnsJobStatus,
    reason: DdnsRuntimeReason,
    message: Option<String>,
    last_error: Option<String>,
    retryable: bool,
    next_retry_at: Option<f64>,
) {
    family_runtime.status = status;
    family_runtime.reason = reason;
    family_runtime.message = message;
    family_runtime.last_error = last_error;
    family_runtime.retryable = retryable;
    family_runtime.next_retry_at = next_retry_at;
}

fn classify_provider_error(message: &str) -> (DdnsRuntimeReason, bool) {
    let lower = message.to_ascii_lowercase();
    if lower.contains("manual dns provider does not support ddns")
        || lower.contains("does not support ddns updates")
    {
        return (DdnsRuntimeReason::ProviderUnsupported, false);
    }
    if lower.contains("unauthorized")
        || lower.contains("forbidden")
        || lower.contains("invalid token")
        || lower.contains("invalid key")
        || lower.contains("invalid secret")
        || lower.contains("invalid signature")
        || lower.contains("authentication")
        || lower.contains("auth failed")
        || lower.contains("access key")
        || lower.contains("api token")
    {
        return (DdnsRuntimeReason::AuthFailed, false);
    }
    if lower.contains("rate limit") || lower.contains("too many requests") || lower.contains("429")
    {
        return (DdnsRuntimeReason::RateLimited, true);
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return (DdnsRuntimeReason::Timeout, true);
    }
    if lower.contains("request failed")
        || lower.contains("dns lookup failed")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("network")
    {
        return (DdnsRuntimeReason::NetworkError, true);
    }
    if lower.contains("not found") || lower.contains("invalid") || lower.contains("rejected") {
        return (DdnsRuntimeReason::RemoteRejected, false);
    }
    (DdnsRuntimeReason::UnknownError, false)
}

fn retry_delay_secs(reason: DdnsRuntimeReason, is_initial_publish: bool) -> u64 {
    if is_initial_publish
        && matches!(
            reason,
            DdnsRuntimeReason::WaitingWanIp
                | DdnsRuntimeReason::RateLimited
                | DdnsRuntimeReason::Timeout
                | DdnsRuntimeReason::NetworkError
        )
    {
        DDNS_RETRY_INTERVAL_SECS
    } else {
        DDNS_SYNC_INTERVAL_SECS
    }
}

fn normalized_ddns_ttl(ttl: Option<u32>) -> u32 {
    ttl.unwrap_or(DEFAULT_DDNS_RECORD_TTL)
}

fn runtime_message_for_reason(reason: DdnsRuntimeReason) -> &'static str {
    match reason {
        DdnsRuntimeReason::Disabled => "DDNS sync is disabled",
        DdnsRuntimeReason::NotConfigured => "This IP family is not configured for the DDNS job",
        DdnsRuntimeReason::Pending => "Waiting for the first DDNS sync",
        DdnsRuntimeReason::Publishing => "Syncing DNS record",
        DdnsRuntimeReason::Published => "DNS record updated successfully",
        DdnsRuntimeReason::UpToDate => "DNS record is already up to date",
        DdnsRuntimeReason::WaitingWanIp => "Waiting for WAN IP",
        DdnsRuntimeReason::NoMatchingSource => "No DDNS source matches this IP family",
        DdnsRuntimeReason::SourceNotImplemented => "Selected DDNS source is not implemented yet",
        DdnsRuntimeReason::WaitingLanDeviceIp => "Waiting for device IPv6 address assignment",
        DdnsRuntimeReason::WaitingWanPdPrefix => "Waiting for WAN PD prefix delegation",
        DdnsRuntimeReason::ProviderProfileMissing => "DNS provider profile was not found",
        DdnsRuntimeReason::ProviderUnsupported => "Selected DNS provider does not support DDNS",
        DdnsRuntimeReason::AuthFailed => "DNS provider authentication failed",
        DdnsRuntimeReason::RateLimited => "DNS provider rate limited the update request",
        DdnsRuntimeReason::Timeout => "DDNS update timed out",
        DdnsRuntimeReason::NetworkError => "Network error while updating DNS record",
        DdnsRuntimeReason::RemoteRejected => "DNS provider rejected the update request",
        DdnsRuntimeReason::UnknownError => "DDNS update failed due to an unknown error",
    }
}

fn relative_record_name_for_ddns(zone_name: &str, record_name: &str) -> Result<String, String> {
    let fqdn = fqdn_for_zone_record(zone_name, record_name)?;
    if fqdn == zone_name {
        Ok("@".to_string())
    } else {
        fqdn.strip_suffix(&format!(".{zone_name}"))
            .map(|prefix| prefix.to_string())
            .ok_or_else(|| format!("record '{record_name}' does not belong to zone '{zone_name}'"))
    }
}

async fn reconcile_dns_records(
    provider: &DnsProviderConfig,
    zone_name: &str,
    record_name: &str,
    desired_ips: &[IpAddr],
    ttl: Option<u32>,
) -> Result<(), String> {
    let Some(first) = desired_ips.first() else {
        return Ok(());
    };

    let record_type = match first {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    };
    let ttl = normalized_ddns_ttl(ttl);
    let record_name = relative_record_name_for_ddns(zone_name, record_name)?;
    let values: Vec<String> = desired_ips.iter().map(|ip| ip.to_string()).collect();
    let updater = build_record_updater(provider).map_err(|e| e.to_string())?;
    updater
        .reconcile_records(zone_name, &record_name, record_type, &values, ttl)
        .await
        .map_err(|e| e.to_string())
}

/// Reconcile to an empty desired set: the provider deletes every record
/// under this exact (fqdn, record_type) and leaves anything else untouched.
async fn delete_dns_records(
    provider: &DnsProviderConfig,
    zone_name: &str,
    record_name: &str,
    family: IpFamily,
) -> Result<(), String> {
    let record_type = match family {
        IpFamily::Ipv4 => "A",
        IpFamily::Ipv6 => "AAAA",
    };
    let record_name = relative_record_name_for_ddns(zone_name, record_name)?;
    let updater = build_record_updater(provider).map_err(|e| e.to_string())?;
    updater
        .reconcile_records(zone_name, &record_name, record_type, &[], DEFAULT_DDNS_RECORD_TTL)
        .await
        .map_err(|e| e.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys_service::route::WanRouteEventKind;

    #[test]
    fn task_registry_insert_and_duplicate() {
        let registry = DdnsTaskRegistry::default();
        let id = Uuid::new_v4();

        assert!(registry.progress_snapshot().is_empty());
        let token = registry.insert(id).expect("first insert should succeed");
        assert_eq!(registry.progress_snapshot().len(), 1);
        assert!(registry.insert(id).is_err(), "duplicate insert should fail");

        let snapshot = registry.progress_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].job_id, id);
        assert_eq!(snapshot[0].phase, DdnsTaskPhase::ResolvingSource);

        drop(token);
    }

    #[test]
    fn task_registry_cancel_token_survives_phase_updates() {
        let registry = DdnsTaskRegistry::default();
        let id = Uuid::new_v4();
        let token = registry.insert(id).expect("insert should succeed");

        registry.update_phase(id, DdnsTaskPhase::Publishing, Some("@ (ipv4, 1/2)".into()));
        assert!(registry.cancel_task(id));
        assert!(token.is_cancelled());

        let snapshot = registry.progress_snapshot();
        assert_eq!(snapshot[0].phase, DdnsTaskPhase::Publishing);
        assert_eq!(snapshot[0].phase_detail.as_deref(), Some("@ (ipv4, 1/2)"));
        assert!(snapshot[0].updated_at >= snapshot[0].started_at);
    }

    #[test]
    fn task_registry_remove_and_cancel_missing() {
        let registry = DdnsTaskRegistry::default();
        let id = Uuid::new_v4();
        registry.insert(id).expect("insert should succeed");

        registry.remove(id);
        registry.remove(id);

        assert!(registry.progress_snapshot().is_empty());
        assert!(!registry.cancel_task(id));
        registry.update_phase(id, DdnsTaskPhase::Publishing, None);
        assert!(registry.progress_snapshot().is_empty());
    }

    #[test]
    fn task_registry_cancel_all() {
        let registry = DdnsTaskRegistry::default();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let first_token = registry.insert(first).expect("insert should succeed");
        let second_token = registry.insert(second).expect("insert should succeed");

        registry.cancel_all();
        assert!(first_token.is_cancelled());
        assert!(second_token.is_cancelled());
    }

    #[test]
    fn task_registry_start_or_mark_and_finish_or_continue() {
        let registry = DdnsTaskRegistry::default();
        let id = Uuid::new_v4();

        assert!(!registry.has_task(id));
        let DdnsTaskStart::Started(token) = registry.start_or_mark(id) else {
            panic!("free slot should start");
        };
        assert!(registry.has_task(id));

        assert!(matches!(registry.start_or_mark(id), DdnsTaskStart::MarkedPending));
        assert!(!token.is_cancelled(), "marking pending must not cancel the task");

        // Pending was set: the entry survives and progress resets.
        assert!(matches!(registry.finish_or_continue(id), DdnsTaskFinish::Continue));
        assert!(registry.has_task(id));
        assert_eq!(registry.progress_snapshot().len(), 1);

        // No new mark: the entry is removed.
        assert!(matches!(registry.finish_or_continue(id), DdnsTaskFinish::Stopped));
        assert!(!registry.has_task(id));

        // Slot is free again for a fresh start.
        assert!(matches!(registry.start_or_mark(id), DdnsTaskStart::Started(_)));
    }

    #[test]
    fn task_registry_strict_insert_rejects_busy_slot() {
        let registry = DdnsTaskRegistry::default();
        let id = Uuid::new_v4();
        registry.insert(id).expect("insert should succeed");
        assert!(registry.has_task(id));
        assert!(registry.insert(id).is_err());
    }

    #[test]
    fn cleanup_targets_only_include_published_families() {
        let mut job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            link_id: Uuid::nil(),
            family: IpFamily::Ipv4,
        }]);
        job.records.push(landscape_common::ddns::DdnsRecordConfig {
            name: "home".to_string(),
            enable: true,
        });

        let mut runtime = DdnsJobRuntime::from_config(&job);
        runtime.records[0].ipv4.last_published_ips =
            vec![IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10))];
        runtime.records[1].ipv6.last_published_ips = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];

        let mut targets = cleanup_targets_from_runtime(&runtime);
        targets.sort_by(|a, b| a.record_name.cmp(&b.record_name));
        assert_eq!(
            targets,
            vec![
                DdnsRecordCleanupTarget {
                    record_name: "@".to_string(),
                    family: IpFamily::Ipv4
                },
                DdnsRecordCleanupTarget {
                    record_name: "home".to_string(),
                    family: IpFamily::Ipv6
                },
            ]
        );

        runtime.records[0].ipv4.last_published_ips.clear();
        runtime.records[1].ipv6.last_published_ips.clear();
        assert!(cleanup_targets_from_runtime(&runtime).is_empty());
    }

    fn test_job(sources: Vec<DdnsSource>) -> DdnsJob {
        DdnsJob {
            id: Uuid::nil(),
            name: "test".to_string(),
            enable: true,
            sources,
            zone_name: "example.com".to_string(),
            provider_profile_id: Uuid::nil(),
            ttl: Some(120),
            records: vec![landscape_common::ddns::DdnsRecordConfig {
                name: "@".to_string(),
                enable: true,
            }],
            update_at: 0.0,
        }
    }

    fn test_profile(ddns_default_ttl: Option<u32>) -> DnsProviderProfile {
        DnsProviderProfile {
            id: Uuid::nil(),
            name: "profile".to_string(),
            provider_config: DnsProviderConfig::Cloudflare { api_token: "token".to_string() },
            remark: None,
            ddns_default_ttl,
            update_at: 0.0,
        }
    }

    #[test]
    fn wan_event_only_matches_same_iface_and_family() {
        let wan0 = Uuid::nil();
        let wan1 = Uuid::new_v4();
        let job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            link_id: wan0,
            family: IpFamily::Ipv4,
        }]);

        assert!(job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Link(wan0),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Link(wan1),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Link(wan0),
                family: IpFamily::Ipv6,
                kind: WanRouteEventKind::Upserted,
            }
        ));
    }

    #[test]
    fn fast_retry_only_applies_before_first_publish() {
        let job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            link_id: Uuid::nil(),
            family: IpFamily::Ipv4,
        }]);
        let mut runtime = DdnsJobRuntime::from_config(&job);
        runtime.records[0].ipv4.reason = DdnsRuntimeReason::WaitingWanIp;
        runtime.records[0].ipv4.retryable = true;
        runtime.records[0].ipv4.next_retry_at = Some(0.0);

        assert!(job_needs_retry(&job, Some(&runtime)));

        runtime.records[0].ipv4.last_published_ips =
            vec![IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10))];
        runtime.records[0].ipv4.status = DdnsJobStatus::Error;
        assert!(!job_needs_retry(&job, Some(&runtime)));
    }

    #[test]
    fn custom_job_ttl_overrides_profile_default() {
        let job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            link_id: Uuid::nil(),
            family: IpFamily::Ipv4,
        }]);

        assert_eq!(effective_ddns_ttl(&job, &test_profile(Some(600))), Some(120));
        assert_eq!(effective_ddns_ttl(&job, &test_profile(None)), Some(120));
    }

    #[test]
    fn inherited_job_ttl_uses_profile_default() {
        let mut job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            link_id: Uuid::nil(),
            family: IpFamily::Ipv4,
        }]);
        job.ttl = None;

        assert_eq!(effective_ddns_ttl(&job, &test_profile(Some(600))), Some(600));
        assert_eq!(effective_ddns_ttl(&job, &test_profile(None)), None);
    }

    #[test]
    fn single_stack_job_summary_ignores_unconfigured_family() {
        let job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            link_id: Uuid::nil(),
            family: IpFamily::Ipv6,
        }]);
        let mut runtime = DdnsJobRuntime::from_config(&job);

        runtime.records[0].ipv6.status = DdnsJobStatus::Success;
        runtime.records[0].ipv6.reason = DdnsRuntimeReason::UpToDate;
        runtime.records[0].ipv6.message =
            Some(runtime_message_for_reason(DdnsRuntimeReason::UpToDate).to_string());

        apply_job_runtime_summary(&mut runtime);

        assert_eq!(runtime.records[0].ipv4.reason, DdnsRuntimeReason::NotConfigured);
        assert_eq!(runtime.status, DdnsJobStatus::Success);
        assert_eq!(runtime.reason, DdnsRuntimeReason::UpToDate);
    }

    #[test]
    fn wan_event_matches_enrolled_device_source() {
        let wan0 = Uuid::nil();
        let wan1 = Uuid::new_v4();
        let job = test_job(vec![DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_link_id: wan0,
            wan_pd_id: Some("wan0".to_string()),
            family: IpFamily::Ipv4,
        }]);

        assert!(job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Link(wan0),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Link(wan0),
                family: IpFamily::Ipv6,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Link(wan1),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
    }

    #[test]
    fn wan_event_does_not_match_netns_owner_for_enrolled_device() {
        let job = test_job(vec![DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_link_id: Uuid::nil(),
            wan_pd_id: None,
            family: IpFamily::Ipv4,
        }]);

        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: RouteOwner::Netns("any".to_string()),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
    }

    #[test]
    fn config_change_pd_sync_ignores_missing_wan_pd_id_mirror() {
        let job = test_job(vec![
            DdnsSource::EnrolledDevice {
                device_id: Uuid::nil(),
                wan_pd_link_id: Uuid::nil(),
                wan_pd_id: None,
                family: IpFamily::Ipv6,
            },
            DdnsSource::EnrolledDevice {
                device_id: Uuid::nil(),
                wan_pd_link_id: Uuid::new_v4(),
                wan_pd_id: None,
                family: IpFamily::Ipv4,
            },
        ]);

        assert!(job_has_enrolled_device_ipv6(&job));
        assert!(job_has_enrolled_device_ipv6_for_wan(&job, &Uuid::nil()));
        assert!(!job_has_enrolled_device_ipv6_for_wan(&job, &Uuid::new_v4()));
    }

    #[test]
    fn ipv6_gua_and_ula_accepted_not_link_local() {
        let gua = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let loopback = Ipv6Addr::LOCALHOST;
        let multicast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

        let acceptable = |addr: Ipv6Addr| -> bool {
            (addr.segments()[0] & 0xe000) == 0x2000 || addr.is_unique_local()
        };

        assert!(acceptable(gua));
        assert!(acceptable(ula));
        assert!(!acceptable(link_local));
        assert!(!acceptable(loopback));
        assert!(!acceptable(multicast));
    }

    #[test]
    fn enrolled_device_suffix_dedup_produces_unique_ips() {
        let pd_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        let pd_len = 64;

        let device_ips = vec![
            Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20),
            Ipv6Addr::new(0x2001, 0xdb8, 0x2, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20),
        ];

        let mut seen_suffixes = HashSet::new();
        let mut result: Vec<IpAddr> = Vec::new();
        for raw_ip in &device_ips {
            if !((raw_ip.segments()[0] & 0xe000) == 0x2000) && !raw_ip.is_unique_local() {
                continue;
            }
            let suffix = extract_ipv6_suffix(*raw_ip, pd_len);
            if seen_suffixes.insert(suffix) {
                let ip = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
                result.push(IpAddr::V6(ip));
            }
        }

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20))
        );
    }

    #[test]
    fn enrolled_device_different_suffixes_produce_multiple_ips() {
        let pd_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        let pd_len = 64;

        let device_ips = vec![
            Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0),
        ];

        let mut seen_suffixes = HashSet::new();
        let mut result: Vec<IpAddr> = Vec::new();
        for raw_ip in &device_ips {
            if !((raw_ip.segments()[0] & 0xe000) == 0x2000) && !raw_ip.is_unique_local() {
                continue;
            }
            let suffix = extract_ipv6_suffix(*raw_ip, pd_len);
            if seen_suffixes.insert(suffix) {
                let ip = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
                result.push(IpAddr::V6(ip));
            }
        }

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn enrolled_device_fe80_is_filtered_out() {
        let pd_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        let pd_len = 64;

        let device_ips = vec![Ipv6Addr::new(0xfe80, 0, 0, 0, 0xde0c, 0xd570, 0x6ff0, 0xad20)];

        let mut seen_suffixes = HashSet::new();
        let mut result: Vec<IpAddr> = Vec::new();
        for raw_ip in &device_ips {
            if !((raw_ip.segments()[0] & 0xe000) == 0x2000) && !raw_ip.is_unique_local() {
                continue;
            }
            let suffix = extract_ipv6_suffix(*raw_ip, pd_len);
            if seen_suffixes.insert(suffix) {
                let ip = combine_ipv6_prefix_suffix(pd_prefix, pd_len, suffix);
                result.push(IpAddr::V6(ip));
            }
        }

        assert!(result.is_empty());
    }
}
