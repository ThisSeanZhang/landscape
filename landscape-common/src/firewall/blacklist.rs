use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::config::geo::GeoConfigKey;
use crate::config::ConfigId;
use crate::database::repository::LandscapeDBStore;
use crate::ip_mark::IpConfig;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum FirewallBlacklistError {
    #[error("Firewall blacklist '{0}' not found")]
    #[api_error(id = "firewall_blacklist.not_found", status = 404)]
    NotFound(ConfigId),
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/firewall_blacklist.d.ts")]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FirewallBlacklistSource {
    GeoKey(GeoConfigKey),
    Config(IpConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/firewall_blacklist.d.ts")]
pub struct FirewallBlacklistConfig {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub enable: bool,
    pub source: Vec<FirewallBlacklistSource>,
    pub remark: String,
    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for FirewallBlacklistConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
}
