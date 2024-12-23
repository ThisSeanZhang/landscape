use serde::{Deserialize, Serialize};

use crate::dev::{DeviceKind, DeviceType, LandScapeInterface};

/// 用于存储网卡信息的结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkIfaceConfig {
    // 名称 关联的网卡名称 相当于网卡的唯一 id
    pub name: String,
    // 类型 网卡还是桥接设备
    pub dev_kind: DeviceKind,
    pub dev_type: DeviceType,
    // 是否有 master 使用 name 因为 Linux 中名称是唯一的
    pub controller_name: Option<String>,
    pub zone_type: IfaceZoneType,
    #[serde(default = "yes")]
    pub enable_in_boot: bool,
}

fn yes() -> bool {
    true
}

impl NetworkIfaceConfig {
    pub fn from_phy_dev(iface: &LandScapeInterface) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name: iface.name.clone(),
            dev_kind: iface.dev_kind.clone(),
            dev_type: iface.dev_type.clone(),
            controller_name: None,
            enable_in_boot: matches!(iface.dev_status, crate::dev::DevState::Up),
            zone_type: IfaceZoneType::Undefined,
        }
    }

    pub fn crate_default_br_lan() -> NetworkIfaceConfig {
        NetworkIfaceConfig::crate_bridge("br_lan".into())
    }

    pub fn crate_bridge(name: String) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name,
            dev_kind: DeviceKind::Bridge,
            dev_type: DeviceType::Ethernet,
            controller_name: None,
            enable_in_boot: true,
            zone_type: IfaceZoneType::Undefined,
        }
    }

    pub fn is_virtual_dev(&self) -> bool {
        !matches!(self.dev_kind, DeviceKind::UnKnow)
    }

    pub fn is_lo(&self) -> bool {
        self.name == "lo"
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
