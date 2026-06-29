use crate::netlink::convert::{DeviceKind, DeviceType, LandscapeInterface};
use landscape_common::{
    dev::DevState,
    iface::config::{CreateDevType, IfaceZoneType, NetworkIfaceConfig, WifiMode},
    utils::time::get_f64_timestamp,
};

use crate::netlink::wifi::{LandscapeWifiInterface, WLANType};

pub fn from_phy_dev(iface: &LandscapeInterface) -> NetworkIfaceConfig {
    from_phy_dev_with_wifi_info(iface, &None)
}

pub fn from_phy_dev_with_wifi_info(
    iface: &LandscapeInterface,
    wifi_info: &Option<LandscapeWifiInterface>,
) -> NetworkIfaceConfig {
    let zone_type = match iface.dev_type {
        DeviceType::Ppp => IfaceZoneType::Wan,
        _ => IfaceZoneType::Undefined,
    };
    let wifi_mode = if let Some(info) = wifi_info {
        match info.wifi_type {
            WLANType::Station => WifiMode::Client,
            WLANType::Ap => WifiMode::AP,
            _ => WifiMode::Undefined,
        }
    } else {
        WifiMode::default()
    };
    NetworkIfaceConfig {
        name: iface.name.clone(),
        create_dev_type: create_from(iface),
        controller_name: None,
        enable_in_boot: matches!(iface.dev_status, DevState::Up),
        zone_type,
        wifi_mode,
        xps_rps: None,
        update_at: get_f64_timestamp(),
    }
}

pub fn create_from(iface: &LandscapeInterface) -> CreateDevType {
    if !iface.is_virtual_dev() {
        CreateDevType::default()
    } else {
        match iface.dev_kind {
            DeviceKind::Bridge => CreateDevType::Bridge,
            _ => CreateDevType::default(),
        }
    }
}
