use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// 无线接口类型
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/iface.d.ts")]
#[serde(tag = "t")]
pub enum WLANType {
    Unspecified,
    Adhoc,
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    Other(u32),
}

/// 当前硬件状态结构体
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/iface.d.ts")]
pub struct LandscapeWifiInterface {
    pub name: String,
    pub index: u32,
    pub wifi_type: WLANType,
}
