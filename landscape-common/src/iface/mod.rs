use serde::{Deserialize, Serialize};

use crate::config::iface::{IfaceZoneType, NetworkIfaceConfig};
use crate::dev::LandscapeInterface;
use dev_wifi::LandscapeWifiInterface;

pub mod dev_wifi;

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BridgeCreate {
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AddController {
    pub link_name: String,
    pub link_ifindex: u32,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub master_name: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub master_ifindex: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ChangeZone {
    pub iface_name: String,
    pub zone: IfaceZoneType,
}

// 前端渲染拓扑节点
#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfaceTopology {
    // 配置
    #[serde(flatten)]
    pub config: NetworkIfaceConfig,
    // 当前的状态: 除了 IP 之类的
    #[serde(flatten)]
    pub status: LandscapeInterface,

    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub wifi_info: Option<LandscapeWifiInterface>,
}

/// 已管理的网卡
#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfaceInfo {
    /// 持久化的配置
    pub config: NetworkIfaceConfig,
    /// 当前网卡的配置, 可能网卡现在不存在
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub status: Option<LandscapeInterface>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub wifi_info: Option<LandscapeWifiInterface>,
}

/// 未纳入配置的网卡
#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RawIfaceInfo {
    /// 当前网卡的配置
    pub status: LandscapeInterface,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub wifi_info: Option<LandscapeWifiInterface>,
}

#[derive(Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfacesInfo {
    pub managed: Vec<IfaceInfo>,
    pub unmanaged: Vec<RawIfaceInfo>,
}
