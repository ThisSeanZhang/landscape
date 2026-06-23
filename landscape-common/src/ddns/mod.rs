use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DdnsSource {
    LocalWan {
        iface_name: String,
        family: IpFamily,
    },
    EnrolledDevice {
        device_id: Uuid,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        wan_pd_id: Option<String>,
        family: IpFamily,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DdnsJobStatus {
    Idle,
    Syncing,
    Success,
    Error,
}

impl Default for DdnsJobStatus {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DdnsRuntimeReason {
    Disabled,
    NotConfigured,
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

impl Default for DdnsRuntimeReason {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DdnsRecordConfig {
    pub name: String,
    #[serde(default = "default_enable")]
    pub enable: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DdnsJob {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_enable")]
    pub enable: bool,
    pub sources: Vec<DdnsSource>,
    pub zone_name: String,
    pub provider_profile_id: Uuid,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub records: Vec<DdnsRecordConfig>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

fn default_enable() -> bool {
    true
}

impl LandscapeDBStore<Uuid> for DdnsJob {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_update_at(&self) -> f64 {
        self.update_at
    }

    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl DdnsJob {
    pub fn normalize_for_save(&mut self) -> Result<(), String> {
        self.zone_name = normalize_zone_name(&self.zone_name)?;
        for record in &mut self.records {
            record.name = normalize_record_name(&record.name)?;
        }
        Ok(())
    }

    pub fn has_source_for_family(&self, wanted_family: IpFamily) -> bool {
        self.sources.iter().any(|source| match source {
            DdnsSource::LocalWan { family, .. } | DdnsSource::EnrolledDevice { family, .. } => {
                *family == wanted_family
            }
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let zone_name = normalize_zone_name(&self.zone_name)?;
        if let Some(ttl) = self.ttl {
            if ttl == 0 {
                return Err("ttl must be greater than 0 when provided".to_string());
            }
        }
        if self.records.is_empty() {
            return Err("at least one DDNS record is required".to_string());
        }
        if self.sources.is_empty() {
            return Err("at least one DDNS source is required".to_string());
        }

        for source in &self.sources {
            match source {
                DdnsSource::LocalWan { iface_name, .. } => {
                    if iface_name.trim().is_empty() {
                        return Err("DDNS source iface_name must not be empty".to_string());
                    }
                }
                DdnsSource::EnrolledDevice { wan_pd_id, .. } => {
                    let iface = wan_pd_id.as_ref().ok_or("DDNS source wan_pd_id is required")?;
                    if iface.trim().is_empty() {
                        return Err("DDNS source wan_pd_id must not be empty".to_string());
                    }
                }
            }
        }

        let mut seen_sources = HashSet::new();
        for source in &self.sources {
            let source_key = match source {
                DdnsSource::LocalWan { iface_name, family } => {
                    format!("local_wan:{}:{family:?}", iface_name.trim())
                }
                DdnsSource::EnrolledDevice { device_id, wan_pd_id, family } => {
                    format!("enrolled_device:{device_id}:{:?}:{family:?}", wan_pd_id)
                }
            };
            if !seen_sources.insert(source_key) {
                return Err("duplicate DDNS source is not allowed".to_string());
            }
        }

        let mut seen = HashSet::new();
        for record in &self.records {
            let normalized = normalize_record_name(&record.name)?;
            if !seen.insert(normalized.clone()) {
                return Err(format!(
                    "duplicate DDNS record '{}' under zone '{}'",
                    normalized, zone_name
                ));
            }
        }
        Ok(())
    }
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

pub fn normalize_zone_name(zone_name: &str) -> Result<String, String> {
    let zone_name = zone_name.trim().trim_end_matches('.').to_ascii_lowercase();
    if zone_name.is_empty() {
        return Err("zone_name must not be empty".to_string());
    }
    if zone_name.contains('*') {
        return Err("zone_name must not contain wildcard characters".to_string());
    }
    if zone_name.split('.').any(|label| label.is_empty()) {
        return Err(format!("invalid zone_name '{zone_name}'"));
    }
    Ok(zone_name)
}

pub fn normalize_record_name(name: &str) -> Result<String, String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return Err("record name must not be empty".to_string());
    }
    if name == "@" || name == "*" {
        return Ok(name);
    }

    let labels: Vec<&str> = name.split('.').collect();
    if labels.iter().any(|label| label.is_empty()) {
        return Err(format!("invalid DDNS record name '{name}'"));
    }
    for (idx, label) in labels.iter().enumerate() {
        if *label == "*" {
            if idx != 0 {
                return Err(format!(
                    "wildcard DDNS record '{name}' must only appear as the leading label"
                ));
            }
            continue;
        }
        if label.contains('*') {
            return Err(format!("invalid wildcard DDNS record '{name}'"));
        }
    }
    Ok(name)
}

pub fn fqdn_for_zone_record(zone_name: &str, record_name: &str) -> Result<String, String> {
    let zone_name = normalize_zone_name(zone_name)?;
    let record_name = normalize_record_name(record_name)?;
    if record_name == "@" {
        Ok(zone_name)
    } else {
        Ok(format!("{record_name}.{zone_name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_for_save_canonicalizes_zone_and_record_names() {
        let mut job = DdnsJob {
            id: Uuid::nil(),
            name: "test".to_string(),
            enable: true,
            sources: vec![DdnsSource::LocalWan {
                iface_name: "wan0".to_string(),
                family: IpFamily::Ipv4,
            }],
            zone_name: " Example.COM. ".to_string(),
            provider_profile_id: Uuid::nil(),
            ttl: Some(120),
            records: vec![DdnsRecordConfig { name: "WWW.".to_string(), enable: true }],
            update_at: 0.0,
        };

        job.normalize_for_save().unwrap();

        assert_eq!(job.zone_name, "example.com");
        assert_eq!(job.records[0].name, "www");
    }

    #[test]
    fn validate_rejects_duplicate_sources() {
        let job = DdnsJob {
            id: Uuid::nil(),
            name: "test".to_string(),
            enable: true,
            sources: vec![
                DdnsSource::LocalWan {
                    iface_name: "wan0".to_string(),
                    family: IpFamily::Ipv4,
                },
                DdnsSource::LocalWan {
                    iface_name: "wan0".to_string(),
                    family: IpFamily::Ipv4,
                },
            ],
            zone_name: "example.com".to_string(),
            provider_profile_id: Uuid::nil(),
            ttl: Some(120),
            records: vec![DdnsRecordConfig { name: "www".to_string(), enable: true }],
            update_at: 0.0,
        };

        let err = job.validate().unwrap_err();
        assert!(err.contains("duplicate DDNS source"));
    }
}
