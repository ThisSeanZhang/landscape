use std::collections::HashMap;
use std::net::IpAddr;

use landscape_common::cert::order::DnsProviderConfig;
use landscape_common::ddns::{
    DdnsFamilyRuntime, DdnsJob, DdnsJobRuntime, DdnsJobStatus, DdnsRecordRuntime,
    DdnsRuntimeReason, DdnsSource, IpFamily, fqdn_for_zone_record,
};
use landscape_common::dns::provider_profile::DnsProviderProfile;
use landscape_common::sys_service::route_service::RouteOwner;
use uuid::Uuid;

use super::{DDNS_RETRY_INTERVAL_SECS, DDNS_SYNC_INTERVAL_SECS, DEFAULT_DDNS_RECORD_TTL};
use crate::cert::dns_provider::build_record_updater;
use crate::sys_service::route::WanRouteEvent;

/// A (record, family) pair previously published by this process and thus
/// owned for remote cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DdnsRecordCleanupTarget {
    pub(super) record_name: String,
    pub(super) family: IpFamily,
}

pub(super) fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
    }
}

pub(super) fn family_runtime_mut(
    record: &mut DdnsRecordRuntime,
    family: IpFamily,
) -> &mut DdnsFamilyRuntime {
    match family {
        IpFamily::Ipv4 => &mut record.ipv4,
        IpFamily::Ipv6 => &mut record.ipv6,
    }
}

/// Only families with recorded published IPs are eligible for remote cleanup.
pub(super) fn cleanup_targets_from_runtime(
    runtime: &DdnsJobRuntime,
) -> Vec<DdnsRecordCleanupTarget> {
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

pub(super) fn build_job_runtime(job: &DdnsJob, current: Option<DdnsJobRuntime>) -> DdnsJobRuntime {
    if !job.enable {
        return DdnsJobRuntime::from_config(job);
    }

    current
        .map(|state| preserve_runtime(job, state))
        .unwrap_or_else(|| DdnsJobRuntime::from_config(job))
}

pub(super) fn effective_ddns_ttl(job: &DdnsJob, profile: &DnsProviderProfile) -> Option<u32> {
    job.ttl.or(profile.ddns_default_ttl)
}

pub(super) fn effective_ttl_config_updated_at(job: &DdnsJob, profile: &DnsProviderProfile) -> f64 {
    if job.ttl.is_some() { job.update_at } else { job.update_at.max(profile.update_at) }
}

pub(super) fn job_matches_wan_event(job: &DdnsJob, event: &WanRouteEvent) -> bool {
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

pub(super) fn job_has_enrolled_device_source_for_device(job: &DdnsJob, device_id: Uuid) -> bool {
    job.sources.iter().any(|source| {
        matches!(source, DdnsSource::EnrolledDevice { device_id: id, .. } if *id == device_id)
    })
}

/// PD-prefix-dependent source detection is keyed by `wan_pd_link_id`; the
/// `wan_pd_id` name mirror is server-internal and may be absent on
/// API-saved jobs, so it must not gate immediate re-sync.
pub(super) fn job_has_enrolled_device_ipv6(job: &DdnsJob) -> bool {
    job.sources
        .iter()
        .any(|source| matches!(source, DdnsSource::EnrolledDevice { family: IpFamily::Ipv6, .. }))
}

pub(super) fn job_has_enrolled_device_ipv6_for_wan(job: &DdnsJob, wan_pd_link_id: &Uuid) -> bool {
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

pub(super) fn job_needs_retry(job: &DdnsJob, runtime: Option<&DdnsJobRuntime>) -> bool {
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

pub(super) fn apply_job_error(
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

pub(super) fn apply_job_runtime_summary(runtime: &mut DdnsJobRuntime) {
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

pub(super) fn apply_family_runtime_state(
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

pub(super) fn classify_provider_error(message: &str) -> (DdnsRuntimeReason, bool) {
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

pub(super) fn retry_delay_secs(reason: DdnsRuntimeReason, is_initial_publish: bool) -> u64 {
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

pub(super) fn runtime_message_for_reason(reason: DdnsRuntimeReason) -> &'static str {
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

pub(super) async fn reconcile_dns_records(
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
pub(super) async fn delete_dns_records(
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
