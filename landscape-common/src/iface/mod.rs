use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::config::iface::IfaceZoneType;

#[derive(Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "common/iface.d.ts")]
pub struct BridgeCreate {
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "common/iface.d.ts")]
pub struct AddController {
    pub link_name: String,
    pub link_ifindex: u32,
    #[serde(default)]
    pub master_name: Option<String>,
    #[serde(default)]
    pub master_ifindex: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "common/iface.d.ts")]
pub struct ChangeZone {
    pub iface_name: String,
    pub zone: IfaceZoneType,
}
