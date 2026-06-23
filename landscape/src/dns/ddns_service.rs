use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::database::LandscapeStore;
use landscape_common::ddns::{
    fqdn_for_zone_record, DdnsFamilyRuntime, DdnsJob, DdnsJobRuntime, DdnsJobStatus,
    DdnsRecordRuntime, DdnsRuntimeReason, DdnsSource, IpFamily,
};
use landscape_common::dns::provider_profile::DnsProviderProfile;
use landscape_common::event::hub::{IPv6AssignEvent, IPv6AssignEventReader};
use landscape_common::ipv6::{combine_ipv6_prefix_suffix, extract_ipv6_suffix};
use landscape_common::ipv6_pd::IAPrefixMap;
use landscape_common::{error::LdError, service::controller::ConfigController};
use landscape_database::{
    ddns::repository::DdnsJobRepository,
    dns_provider_profile::repository::DnsProviderProfileRepository,
    provider::LandscapeDBServiceProvider,
};

use tokio::sync::{Mutex, RwLock};
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

use crate::cert::dns_provider::{build_record_updater, validate_provider_zone_access};
use crate::route::{IpRouteService, WanRouteEvent};

const DDNS_SYNC_INTERVAL_SECS: u64 = 60;
const DDNS_RETRY_INTERVAL_SECS: u64 = 5;
const DEFAULT_DDNS_RECORD_TTL: u32 = 120;

type DdnsRuntimeMap = Arc<RwLock<HashMap<Uuid, DdnsJobRuntime>>>;
type DdnsSyncLock = Arc<Mutex<()>>;

#[derive(Default)]
struct EnrolledDeviceCache {
    raw_ips: HashSet<Ipv6Addr>,
}

type EnrolledCache = Arc<DashMap<Uuid, EnrolledDeviceCache>>;
type PdWatchHandles = Arc<DashMap<String, tokio::task::AbortHandle>>;

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
    sync_lock: DdnsSyncLock,
    prefix_map: IAPrefixMap,
    enrolled_cache: EnrolledCache,
    pd_watchers: PdWatchHandles,
}

impl DdnsService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        ipv6_reader: IPv6AssignEventReader,
        enrolled_ipv6_cache: HashMap<Uuid, Ipv6Addr>,
    ) -> Self {
        let service = Self {
            store: store.ddns_job_store(),
            profile_store: store.dns_provider_profile_store(),
            route_service,
            runtime: Arc::new(RwLock::new(HashMap::new())),
            sync_lock: Arc::new(Mutex::new(())),
            prefix_map,
            enrolled_cache: Arc::new(
                enrolled_ipv6_cache
                    .into_iter()
                    .map(|(id, ip)| (id, EnrolledDeviceCache { raw_ips: HashSet::from([ip]) }))
                    .collect(),
            ),
            pd_watchers: Arc::new(DashMap::new()),
        };
        service.refresh_runtime_from_store().await;
        service.spawn_sync_loop();
        service.spawn_retry_loop();
        service.spawn_wan_update_loop();
        service.spawn_ipv6_assign_loop(ipv6_reader);
        service.reconcile_pd_watchers_from_store().await;
        service
    }

    pub async fn get_runtime_statuses(&self) -> HashMap<Uuid, DdnsJobRuntime> {
        self.runtime.read().await.clone()
    }

    pub async fn sync_job_now(&self, job_id: Uuid) -> Result<DdnsJobRuntime, LdError> {
        let job = self
            .store
            .find_by_id(job_id)
            .await?
            .ok_or_else(|| LdError::ConfigError(format!("DDNS job {job_id} not found")))?;

        if job.enable {
            self.sync_jobs_now(vec![job.clone()]).await;
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
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(DDNS_SYNC_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(e) = service.sync_all_enabled_jobs().await {
                    tracing::warn!("ddns sync pass failed: {e:?}");
                }
            }
        });
    }

    fn spawn_retry_loop(&self) {
        let service = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(DDNS_RETRY_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = service.retry_pending_jobs().await {
                    tracing::warn!("ddns retry pass failed: {e:?}");
                }
            }
        });
    }

    fn spawn_wan_update_loop(&self) {
        let service = self.clone();
        let mut events = self.route_service.subscribe_wan_route_events();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if let Err(e) = service.sync_jobs_for_wan_event(event).await {
                            tracing::warn!("ddns wan-triggered sync failed: {e:?}");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!("ddns wan event listener lagged, skipped {skipped} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    fn spawn_ipv6_assign_loop(&self, mut reader: IPv6AssignEventReader) {
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                match reader.recv().await {
                    Ok(IPv6AssignEvent::Allocated(info)) => {
                        if let Some(device_id) = info.device_id {
                            if let Err(e) =
                                service.on_device_ipv6_allocated(device_id, info.ip).await
                            {
                                tracing::warn!("ddns lan ipv6 allocated handler failed: {e:?}");
                            }
                        }
                    }
                    Ok(IPv6AssignEvent::Expired(info)) => {
                        if let Some(device_id) = info.device_id {
                            if let Some(mut entry) = service.enrolled_cache.get_mut(&device_id) {
                                entry.raw_ips.remove(&info.ip);
                                if entry.raw_ips.is_empty() {
                                    drop(entry);
                                    service.enrolled_cache.remove(&device_id);
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            "ddns ipv6 assign listener lagged, skipped {skipped} events"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    async fn on_device_ipv6_allocated(
        &self,
        device_id: Uuid,
        ip: std::net::Ipv6Addr,
    ) -> Result<(), LdError> {
        let jobs = self.store.find_enabled().await?;
        let matching: Vec<_> = jobs
            .into_iter()
            .filter(|job| job_has_enrolled_device_ipv6_for_device(job, device_id))
            .collect();

        if matching.is_empty() {
            return Ok(());
        }

        self.enrolled_cache.entry(device_id).or_default().raw_ips.insert(ip);
        self.sync_jobs_now(matching).await;
        Ok(())
    }

    async fn on_pd_prefix_changed(&self, wan_pd_id: &str) -> Result<(), LdError> {
        let jobs = self.store.find_enabled().await?;
        let matching: Vec<_> = jobs
            .into_iter()
            .filter(|job| job_has_enrolled_device_ipv6_for_wan(job, wan_pd_id))
            .collect();

        if !matching.is_empty() {
            self.sync_jobs_now(matching).await;
        }
        Ok(())
    }

    async fn start_pd_watcher(&self, wan_pd_id: &str) {
        let mut rx = self.prefix_map.get_ia_prefix(wan_pd_id).await;
        let iface = wan_pd_id.to_string();
        let svc = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                if let Err(e) = svc.on_pd_prefix_changed(&iface).await {
                    tracing::warn!("ddns pd watcher error for {iface}: {e:?}");
                }
            }
        });
        // TODO: if pd_watchers already has an entry for wan_pd_id, the old
        // AbortHandle is silently overwritten without aborting the old task,
        // causing a task leak. The sole caller reconcile_pd_watchers guards
        // with contains_key, but independent calls would leak.
        self.pd_watchers.insert(wan_pd_id.to_string(), handle.abort_handle());
    }

    // TODO: the stale-removal & needed-startup phases are not atomic. A
    // concurrent config change between the two phases could leave a watcher
    // running for an interface that is no longer needed, or fail to start one
    // that is newly needed. If the watcher strategy is revised (e.g. using
    // a single background task with a shared subscription), this race goes
    // away naturally.
    async fn reconcile_pd_watchers(&self, jobs: &[DdnsJob]) {
        use std::collections::HashSet;

        let needed: HashSet<String> = jobs
            .iter()
            .filter(|j| j.enable)
            .flat_map(|j| &j.sources)
            .filter_map(|s| match s {
                DdnsSource::EnrolledDevice {
                    wan_pd_id: Some(iface),
                    family: IpFamily::Ipv6,
                    ..
                } => Some(iface.clone()),
                _ => None,
            })
            .collect();

        let stale: Vec<String> = self
            .pd_watchers
            .iter()
            .filter(|kv| !needed.contains(kv.key()))
            .map(|kv| kv.key().clone())
            .collect();
        for iface in &stale {
            if let Some((_, handle)) = self.pd_watchers.remove(iface) {
                handle.abort();
            }
        }

        for iface in &needed {
            if !self.pd_watchers.contains_key(iface) {
                self.start_pd_watcher(iface).await;
                // TODO: initial sync failure is silently swallowed (only a
                // warning log). Under the revised watcher design, consider
                // surfacing this as a runtime error so the user has visibility.
                if let Err(e) = self.on_pd_prefix_changed(iface).await {
                    tracing::warn!("ddns initial pd sync for {iface} failed: {e:?}");
                }
            }
        }
    }

    async fn reconcile_pd_watchers_from_store(&self) {
        let jobs = self.store.list().await.unwrap_or_default();
        self.reconcile_pd_watchers(&jobs).await;
    }

    pub async fn checked_set_job(&self, mut config: DdnsJob) -> Result<DdnsJob, LdError> {
        config.normalize_for_save().map_err(LdError::ConfigError)?;
        config.validate().map_err(LdError::ConfigError)?;
        let profile =
            self.profile_store.find_by_id(config.provider_profile_id).await?.ok_or_else(|| {
                LdError::ConfigError(format!(
                    "DNS provider profile {} not found",
                    config.provider_profile_id
                ))
            })?;
        build_record_updater(&profile.provider_config)
            .map_err(|e| LdError::ConfigError(e.to_string()))?;
        validate_provider_zone_access(&profile.provider_config, &config.zone_name)
            .await
            .map_err(|e| LdError::ConfigError(e.to_string()))?;
        let saved = self.checked_set(config).await?;
        if saved.enable {
            self.sync_enabled_job_now(&saved).await;
        } else {
            self.sync_runtime_for_job(&saved).await;
        }
        Ok(saved)
    }

    async fn refresh_runtime_from_store(&self) {
        let jobs = self.store.list().await.unwrap_or_default();
        self.refresh_runtime_with_jobs(jobs).await;
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

    async fn sync_all_enabled_jobs(&self) -> Result<(), LdError> {
        self.sync_jobs_now(self.store.find_enabled().await?).await;
        Ok(())
    }

    async fn retry_pending_jobs(&self) -> Result<(), LdError> {
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

    async fn sync_jobs_for_wan_event(&self, event: WanRouteEvent) -> Result<(), LdError> {
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
        if jobs.is_empty() {
            return;
        }

        let _guard = self.sync_lock.lock().await;
        for job in jobs {
            let runtime = self.sync_one_job(&job).await;
            self.runtime.write().await.insert(job.id, runtime);
        }
    }

    async fn sync_one_job(&self, job: &DdnsJob) -> DdnsJobRuntime {
        let mut runtime = {
            let current = self.runtime.read().await.get(&job.id).cloned();
            build_job_runtime(job, current)
        };

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

        for record in &mut runtime.records {
            let enabled = job
                .records
                .iter()
                .find(|cfg| cfg.name == record.name)
                .map(|cfg| cfg.enable)
                .unwrap_or(false);
            if !enabled {
                apply_family_runtime_state(
                    &mut record.ipv4,
                    DdnsJobStatus::Idle,
                    DdnsRuntimeReason::Disabled,
                    None,
                    None,
                    false,
                    None,
                );
                apply_family_runtime_state(
                    &mut record.ipv6,
                    DdnsJobStatus::Idle,
                    DdnsRuntimeReason::Disabled,
                    None,
                    None,
                    false,
                    None,
                );
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

                let current_ips = self.resolve_record_ip(&job.sources, family).await;
                self.sync_one_record_family(
                    &profile.provider_config,
                    &job.zone_name,
                    record,
                    family,
                    current_ips,
                    effective_ddns_ttl(job, &profile),
                    effective_ttl_config_updated_at(job, &profile),
                )
                .await;
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
                DdnsSource::LocalWan { iface_name, family } if *family == wanted_family => {
                    let route = match family {
                        IpFamily::Ipv4 => self.route_service.get_ipv4_wan_route(iface_name).await,
                        IpFamily::Ipv6 => self.route_service.get_ipv6_wan_route(iface_name).await,
                    };
                    if let Some(route) = route {
                        if wanted_family == IpFamily::Ipv6 {
                            if let IpAddr::V6(addr) = route.iface_ip {
                                if !((addr.segments()[0] & 0xe000) == 0x2000)
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
                            }
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
                DdnsSource::EnrolledDevice { device_id, wan_pd_id, family }
                    if *family == wanted_family =>
                {
                    match (wanted_family, wan_pd_id) {
                        (IpFamily::Ipv6, Some(wan)) => {
                            let entry = match self.enrolled_cache.get(device_id) {
                                Some(e) => e,
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
                            let raw_ips: Vec<Ipv6Addr> = entry.raw_ips.iter().copied().collect();
                            drop(entry);

                            let pd_rx = self.prefix_map.get_ia_prefix(wan).await;
                            let pd = match pd_rx.borrow().clone() {
                                Some(p) => p,
                                None => {
                                    last_error = Some(ResolveRecordIpError {
                                        status: DdnsJobStatus::Idle,
                                        reason: DdnsRuntimeReason::WaitingWanPdPrefix,
                                        detail: format!(
                                            "waiting for WAN {wan} PD prefix delegation"
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
                        _ => {
                            last_error = Some(ResolveRecordIpError {
                                status: DdnsJobStatus::Error,
                                reason: DdnsRuntimeReason::SourceNotImplemented,
                                detail: "enrolled device DDNS source is not implemented yet"
                                    .to_string(),
                                retryable: false,
                                next_retry_at: None,
                            });
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

        apply_family_runtime_state(
            family_runtime,
            DdnsJobStatus::Syncing,
            DdnsRuntimeReason::Publishing,
            Some(runtime_message_for_reason(DdnsRuntimeReason::Publishing).to_string()),
            None,
            false,
            None,
        );

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
    if job.ttl.is_some() {
        job.update_at
    } else {
        job.update_at.max(profile.update_at)
    }
}

fn job_matches_wan_event(job: &DdnsJob, event: &WanRouteEvent) -> bool {
    job.sources.iter().any(|source| match source {
        DdnsSource::LocalWan { iface_name, family }
            if iface_name == &event.owner && *family == event.family =>
        {
            true
        }
        DdnsSource::EnrolledDevice { wan_pd_id: Some(iface), family, .. }
            if iface == &event.owner && *family == event.family =>
        {
            true
        }
        _ => false,
    })
}

fn job_has_matching_source(job: &DdnsJob, wanted_family: IpFamily) -> bool {
    job.sources.iter().any(|source| match source {
        DdnsSource::LocalWan { family, .. } | DdnsSource::EnrolledDevice { family, .. }
            if *family == wanted_family =>
        {
            true
        }
        _ => false,
    })
}

fn job_has_enrolled_device_ipv6_for_device(job: &DdnsJob, device_id: Uuid) -> bool {
    job.sources.iter().any(|source| {
        matches!(
            source,
            DdnsSource::EnrolledDevice {
                device_id: id,
                wan_pd_id: Some(_),
                family: IpFamily::Ipv6,
            } if *id == device_id
        )
    })
}

fn job_has_enrolled_device_ipv6_for_wan(job: &DdnsJob, wan_pd_id: &str) -> bool {
    job.sources.iter().any(|source| {
        matches!(
            source,
            DdnsSource::EnrolledDevice {
                wan_pd_id: Some(iface),
                family: IpFamily::Ipv6,
                ..
            } if iface == wan_pd_id
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

#[async_trait::async_trait]
impl ConfigController for DdnsService {
    type Id = Uuid;
    type Config = DdnsJob;
    type DatabseAction = DdnsJobRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn after_update_config(
        &self,
        new_configs: Vec<Self::Config>,
        _old_configs: Vec<Self::Config>,
    ) {
        self.refresh_runtime_with_jobs(new_configs.clone()).await;
        self.reconcile_pd_watchers(&new_configs).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::WanRouteEventKind;

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
        let job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
            family: IpFamily::Ipv4,
        }]);

        assert!(job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "wan0".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "wan1".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "wan0".to_string(),
                family: IpFamily::Ipv6,
                kind: WanRouteEventKind::Upserted,
            }
        ));
    }

    #[test]
    fn fast_retry_only_applies_before_first_publish() {
        let job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
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
            family: IpFamily::Ipv4,
        }]);

        assert_eq!(effective_ddns_ttl(&job, &test_profile(Some(600))), Some(120));
        assert_eq!(effective_ddns_ttl(&job, &test_profile(None)), Some(120));
    }

    #[test]
    fn inherited_job_ttl_uses_profile_default() {
        let mut job = test_job(vec![DdnsSource::LocalWan {
            iface_name: "wan0".to_string(),
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
        let job = test_job(vec![DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_id: Some("wan0".to_string()),
            family: IpFamily::Ipv4,
        }]);

        assert!(job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "wan0".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "wan0".to_string(),
                family: IpFamily::Ipv6,
                kind: WanRouteEventKind::Upserted,
            }
        ));
        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "wan1".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
    }

    #[test]
    fn wan_event_does_not_match_enrolled_device_without_wan_pd_id() {
        let job = test_job(vec![DdnsSource::EnrolledDevice {
            device_id: Uuid::nil(),
            wan_pd_id: None,
            family: IpFamily::Ipv4,
        }]);

        assert!(!job_matches_wan_event(
            &job,
            &WanRouteEvent {
                owner: "any".to_string(),
                family: IpFamily::Ipv4,
                kind: WanRouteEventKind::Upserted,
            }
        ));
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
