use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/mac_binding.d.ts")]
pub struct IpMacBinding {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    pub id: Uuid,
    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    pub update_at: f64,

    /// Optional interface name this binding belongs to
    #[serde(default)]
    #[ts(optional)]
    pub iface_name: Option<String>,

    /// The display name chosen by the user
    pub name: String,
    /// Name to show when "Private Mode" is enabled
    #[serde(default)]
    #[ts(optional)]
    pub fake_name: Option<String>,

    /// Optional remark for the device
    #[serde(default)]
    #[ts(optional)]
    pub remark: Option<String>,

    /// Unique MacAddr for this binding
    pub mac: MacAddr,
    /// Static IPv4 assignment (Optional)
    #[serde(default)]
    #[ts(optional)]
    pub ipv4: Option<Ipv4Addr>,
    /// Static IPv6 assignment (Optional)
    #[serde(default)]
    #[ts(optional)]
    pub ipv6: Option<Ipv6Addr>,
    /// Tags for grouping devices (e.g., "Family", "IoT")
    #[serde(default)]
    pub tag: Vec<String>,
}

impl LandscapeDBStore<Uuid> for IpMacBinding {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/mac_binding.d.ts")]
pub struct ValidateIpPayload {
    pub iface_name: String,
    pub ipv4: String,
}
