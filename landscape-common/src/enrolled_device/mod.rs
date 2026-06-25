use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::dhcp::v4_server::config::CustomDhcpOption;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnrolledDevice {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,

    /// Optional interface name this binding belongs to
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub iface_name: Option<String>,

    /// The display name chosen by the user
    pub name: String,
    /// Name to show when "Private Mode" is enabled
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub fake_name: Option<String>,

    /// Optional remark for the device
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub remark: Option<String>,

    /// Hostname for LAN DNS resolution (e.g., "my-phone")
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub hostname: Option<String>,

    /// Unique MacAddr for this binding
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub mac: MacAddr,
    /// Static IPv4 assignment (Optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub ipv4: Option<Ipv4Addr>,
    /// Static IPv6 assignment (Optional)
    /// For static LAN prefixes, store the full IPv6 address.
    /// For PD-based IA_NA, store only the host suffix; runtime combines it with the current /64 prefix.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub ipv6: Option<Ipv6Addr>,
    /// Tags for grouping devices (e.g., "Family", "IoT")
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub tag: Vec<String>,

    /// Per-device custom DHCP options (override global DHCP server custom_options)
    /// 注意：此字段的修改需要重启 DHCP 服务才能生效。
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub dhcp_custom_options: Vec<CustomDhcpOption>,
    /// Per-device DHCP option filter blocklist (option codes to not send to this device)
    /// 注意：此字段的修改需要重启 DHCP 服务才能生效。
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub dhcp_filter_options: Vec<u8>,
}

impl LandscapeDBStore<Uuid> for EnrolledDevice {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ValidateIpPayload {
    pub iface_name: String,
    pub ipv4: String,
}
