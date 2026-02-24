use crate::database::repository::LandscapeDBStore;
use crate::utils::time::get_f64_timestamp;
use crate::{store::storev2::LandscapeStore, LANDSCAPE_DEFAULT_LAN_NAME};
use sea_orm::{prelude::StringLen, DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};

/// 用于存储网卡信息的结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NetworkIfaceConfig {
    // 名称 关联的网卡名称 相当于网卡的唯一 id
    pub name: String,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub create_dev_type: CreateDevType,

    // 是否有 master 使用 name 因为 Linux 中名称是唯一的
    pub controller_name: Option<String>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub zone_type: IfaceZoneType,

    #[serde(default = "yes")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub enable_in_boot: bool,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub wifi_mode: WifiMode,

    /// NIC XPS / RPS Config
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub xps_rps: Option<IfaceCpuSoftBalance>,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl LandscapeStore for NetworkIfaceConfig {
    fn get_store_key(&self) -> String {
        self.name.clone()
    }
}

impl LandscapeDBStore<String> for NetworkIfaceConfig {
    fn get_id(&self) -> String {
        self.name.clone()
    }
}

fn yes() -> bool {
    true
}

impl NetworkIfaceConfig {
    pub fn get_iface_name(&self) -> String {
        self.name.clone()
    }

    pub fn crate_default_br_lan() -> NetworkIfaceConfig {
        NetworkIfaceConfig::crate_bridge(
            LANDSCAPE_DEFAULT_LAN_NAME.into(),
            Some(IfaceZoneType::Lan),
        )
    }

    pub fn crate_bridge(name: String, zone_type: Option<IfaceZoneType>) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name,
            create_dev_type: CreateDevType::Bridge,
            controller_name: None,
            enable_in_boot: true,
            zone_type: zone_type.unwrap_or_default(),
            wifi_mode: WifiMode::default(),
            xps_rps: None,
            update_at: get_f64_timestamp(),
        }
    }
}

/// 需要创建的设备类型
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(100))", rename_all = "snake_case")]
pub enum CreateDevType {
    #[default]
    NoNeedToCreate,
    Bridge,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(100))", rename_all = "snake_case")]
pub enum WifiMode {
    #[default]
    Undefined,
    Client,
    #[serde(rename = "ap")]
    AP,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(100))", rename_all = "snake_case")]
pub enum IfaceZoneType {
    // 未定义类型
    #[default]
    Undefined,
    Wan,
    Lan,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfaceCpuSoftBalance {
    pub xps: String,
    pub rps: String,
}
