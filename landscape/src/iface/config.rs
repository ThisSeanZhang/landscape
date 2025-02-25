use landscape_common::{store::storev2::LandScapeStore, LANDSCAPE_DEFAULT_LAN_NAME};
use serde::{Deserialize, Serialize};

use crate::dev::{DeviceKind, DeviceType, LandScapeInterface};

/// 用于存储网卡信息的结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkIfaceConfig {
    // 名称 关联的网卡名称 相当于网卡的唯一 id
    pub name: String,
    #[serde(default)]
    pub create_dev_type: CreateDevType,
    // 是否有 master 使用 name 因为 Linux 中名称是唯一的
    pub controller_name: Option<String>,
    #[serde(default)]
    pub zone_type: IfaceZoneType,
    #[serde(default = "yes")]
    pub enable_in_boot: bool,
}

impl LandScapeStore for NetworkIfaceConfig {
    fn get_store_key(&self) -> String {
        self.name.clone()
    }
}

fn yes() -> bool {
    true
}

impl NetworkIfaceConfig {
    pub fn from_phy_dev(iface: &LandScapeInterface) -> NetworkIfaceConfig {
        let zone_type = match iface.dev_type {
            DeviceType::Ppp => IfaceZoneType::Wan,
            _ => IfaceZoneType::Undefined,
        };
        NetworkIfaceConfig {
            name: iface.name.clone(),
            create_dev_type: CreateDevType::create_from(iface),
            controller_name: None,
            enable_in_boot: matches!(iface.dev_status, crate::dev::DevState::Up),
            zone_type,
        }
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
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum IfaceZoneType {
    // 未定义类型
    #[default]
    Undefined,
    Wan,
    Lan,
}

/// 需要创建的设备类型
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum CreateDevType {
    #[default]
    NoNeedToCreate,
    Bridge,
}

impl CreateDevType {
    pub fn create_from(iface: &LandScapeInterface) -> Self {
        if !iface.is_virtual_dev() {
            CreateDevType::default()
        } else {
            match iface.dev_kind {
                DeviceKind::Bridge => CreateDevType::Bridge,
                _ => CreateDevType::default(),
            }
        }
    }
}
