use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::concurrency::task_label;
use landscape_common::database::store::ConfigStore;
use landscape_common::ddns::{
    DdnsJob, DdnsJobRuntime, DdnsJobStatus, DdnsRecordRuntime, DdnsRuntimeReason, DdnsSource,
    DdnsTaskPhase, IpFamily,
};
use landscape_common::lan_service::lan_ipv6::{combine_ipv6_prefix_suffix, extract_ipv6_suffix};
use landscape_common::sys_service::route_service::RouteOwner;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::DDNS_RETRY_INTERVAL_SECS;
use super::DdnsService;
use super::runtime_state::{
    DdnsRecordCleanupTarget, apply_family_runtime_state, apply_job_error,
    apply_job_runtime_summary, build_job_runtime, classify_provider_error,
    cleanup_targets_from_runtime, delete_dns_records, effective_ddns_ttl,
    effective_ttl_config_updated_at, family_label, family_runtime_mut, reconcile_dns_records,
    retry_delay_secs, runtime_message_for_reason,
};

struct ResolveRecordIpError {
    status: DdnsJobStatus,
    reason: DdnsRuntimeReason,
    detail: String,
    retryable: bool,
    next_retry_at: Option<f64>,
}

impl DdnsService {
    pub(super) async fn cleanup_targets(&self, job_id: Uuid) -> Vec<DdnsRecordCleanupTarget> {
        let runtime = self.runtime.read().await;
        runtime.get(&job_id).map(cleanup_targets_from_runtime).unwrap_or_default()
    }

    pub(super) fn spawn_job_cleanup(&self, job: DdnsJob, targets: Vec<DdnsRecordCleanupTarget>) {
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

    pub(super) async fn sync_one_job(
        &self,
        job: &DdnsJob,
        cancel: &CancellationToken,
    ) -> DdnsJobRuntime {
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
