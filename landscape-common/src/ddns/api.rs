use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::config::{DdnsJob, DdnsRecordConfig, DdnsSource, IpFamily};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

fn default_enable() -> bool {
    true
}

/// API view of [`DdnsSource`]: the iface-name mirrors are server-internal
/// (DB write-back for downgraded binaries) and never cross the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ApiDdnsSource {
    LocalWan {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        link_id: Uuid,
        family: IpFamily,
    },
    EnrolledDevice {
        device_id: Uuid,
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        wan_pd_link_id: Uuid,
        family: IpFamily,
    },
}

impl From<DdnsSource> for ApiDdnsSource {
    fn from(value: DdnsSource) -> Self {
        match value {
            DdnsSource::LocalWan { link_id, family, .. } => {
                ApiDdnsSource::LocalWan { link_id, family }
            }
            DdnsSource::EnrolledDevice { device_id, wan_pd_link_id, family, .. } => {
                ApiDdnsSource::EnrolledDevice { device_id, wan_pd_link_id, family }
            }
        }
    }
}

impl From<ApiDdnsSource> for DdnsSource {
    fn from(value: ApiDdnsSource) -> Self {
        match value {
            ApiDdnsSource::LocalWan { link_id, family } => {
                DdnsSource::LocalWan { link_id, iface_name: String::new(), family }
            }
            ApiDdnsSource::EnrolledDevice { device_id, wan_pd_link_id, family } => {
                DdnsSource::EnrolledDevice { device_id, wan_pd_link_id, wan_pd_id: None, family }
            }
        }
    }
}

/// API view of [`DdnsJob`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiDdnsJob {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_enable")]
    pub enable: bool,
    pub sources: Vec<ApiDdnsSource>,
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

impl From<DdnsJob> for ApiDdnsJob {
    fn from(value: DdnsJob) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enable: value.enable,
            sources: value.sources.into_iter().map(Into::into).collect(),
            zone_name: value.zone_name,
            provider_profile_id: value.provider_profile_id,
            ttl: value.ttl,
            records: value.records,
            update_at: value.update_at,
        }
    }
}

impl From<ApiDdnsJob> for DdnsJob {
    fn from(value: ApiDdnsJob) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enable: value.enable,
            sources: value.sources.into_iter().map(Into::into).collect(),
            zone_name: value.zone_name,
            provider_profile_id: value.provider_profile_id,
            ttl: value.ttl,
            records: value.records,
            update_at: value.update_at,
        }
    }
}
