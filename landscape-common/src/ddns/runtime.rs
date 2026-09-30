use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use super::config::{DdnsJob, IpFamily};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DdnsJobStatus {
    #[default]
    Idle,
    Syncing,
    Success,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DdnsRuntimeReason {
    Disabled,
    NotConfigured,
    #[default]
    Pending,
    Publishing,
    Published,
    UpToDate,
    WaitingWanIp,
    NoMatchingSource,
    SourceNotImplemented,
    WaitingLanDeviceIp,
    WaitingWanPdPrefix,
    ProviderProfileMissing,
    ProviderUnsupported,
    AuthFailed,
    RateLimited,
    Timeout,
    NetworkError,
    RemoteRejected,
    UnknownError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DdnsFamilyRuntime {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = Vec<String>))]
    pub last_published_ips: Vec<IpAddr>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub last_sync_at: Option<f64>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub message: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub last_error: Option<String>,
    #[serde(default)]
    pub status: DdnsJobStatus,
    #[serde(default)]
    pub reason: DdnsRuntimeReason,
    #[serde(default)]
    pub retryable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub next_retry_at: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DdnsRecordRuntime {
    pub name: String,
    pub ipv4: DdnsFamilyRuntime,
    pub ipv6: DdnsFamilyRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DdnsJobRuntime {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub job_id: Uuid,
    pub status: DdnsJobStatus,
    pub reason: DdnsRuntimeReason,
    pub records: Vec<DdnsRecordRuntime>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub message: Option<String>,
    #[serde(default)]
    pub retryable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub next_retry_at: Option<f64>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub last_update_at: Option<f64>,
}

impl DdnsJobRuntime {
    pub fn from_config(job: &DdnsJob) -> Self {
        let reason = if job.enable && job.records.iter().any(|record| record.enable) {
            DdnsRuntimeReason::Pending
        } else {
            DdnsRuntimeReason::Disabled
        };
        Self {
            job_id: job.id,
            status: DdnsJobStatus::Idle,
            reason,
            records: job
                .records
                .iter()
                .map(|record| DdnsRecordRuntime {
                    name: record.name.clone(),
                    ipv4: DdnsFamilyRuntime::from_tracking(
                        job.enable && record.enable,
                        job.has_source_for_family(IpFamily::Ipv4),
                    ),
                    ipv6: DdnsFamilyRuntime::from_tracking(
                        job.enable && record.enable,
                        job.has_source_for_family(IpFamily::Ipv6),
                    ),
                })
                .collect(),
            message: None,
            retryable: false,
            next_retry_at: None,
            last_update_at: None,
        }
    }
}

impl DdnsFamilyRuntime {
    pub fn from_enabled(enabled: bool) -> Self {
        Self::from_tracking(enabled, true)
    }

    pub fn from_tracking(enabled: bool, configured: bool) -> Self {
        let reason = if enabled { DdnsRuntimeReason::Pending } else { DdnsRuntimeReason::Disabled };
        let reason = if enabled && !configured { DdnsRuntimeReason::NotConfigured } else { reason };
        Self {
            last_published_ips: Vec::new(),
            last_sync_at: None,
            message: None,
            last_error: None,
            status: DdnsJobStatus::Idle,
            reason,
            retryable: false,
            next_retry_at: None,
        }
    }
}
