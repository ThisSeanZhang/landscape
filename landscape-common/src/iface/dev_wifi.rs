use serde::{Deserialize, Serialize};

/// 无线接口类型
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeWifiInterface {
    pub name: String,
    pub index: u32,
    pub wifi_type: WLANType,
}
