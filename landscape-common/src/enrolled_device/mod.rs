use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum EnrolledDeviceError {
    #[error("Invalid enrolled device data: {0}")]
    #[api_error(id = "enrolled_device.invalid", status = 400)]
    InvalidData(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/enrolled_device.d.ts")]
pub struct EnrolledDevice {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,

    /// Optional interface name this binding belongs to
    #[serde(default)]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub iface_name: Option<String>,

    /// The display name chosen by the user
    pub name: String,
    /// Name to show when "Private Mode" is enabled
    #[serde(default)]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub fake_name: Option<String>,

    /// Optional remark for the device
    #[serde(default)]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub remark: Option<String>,

    /// Unique MacAddr for this binding
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub mac: MacAddr,
    /// Static IPv4 assignment (Optional)
    #[serde(default)]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub ipv4: Option<Ipv4Addr>,
    /// Static IPv6 assignment (Optional)
    #[serde(default)]
    #[ts(optional)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub ipv6: Option<Ipv6Addr>,
    /// Tags for grouping devices (e.g., "Family", "IoT")
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub tag: Vec<String>,
}

impl LandscapeDBStore<Uuid> for EnrolledDevice {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/enrolled_device.d.ts")]
pub struct ValidateIpPayload {
    pub iface_name: String,
    pub ipv4: String,
}
