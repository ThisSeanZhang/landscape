use crate::net::MacAddr;
use libc::{c_char, if_nametoindex};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use ts_rs::TS;

/// 当前硬件状态结构体
#[derive(Debug, Serialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/iface.d.ts")]
pub struct LandscapeInterface {
    #[serde(rename = "iface_name")]
    pub name: String,
    pub index: u32,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub mac: Option<MacAddr>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub perm_mac: Option<MacAddr>,
    pub dev_type: DeviceType,
    pub dev_kind: DeviceKind,
    pub dev_status: DevState,
    pub controller_id: Option<u32>,
    // 网线是否插入
    pub carrier: bool,
    pub netns_id: Option<i32>,
    pub peer_link_id: Option<u32>,
    pub is_wireless: bool,
}

impl LandscapeInterface {
    pub fn is_virtual_dev(&self) -> bool {
        !matches!(self.dev_kind, DeviceKind::UnKnow)
    }

    pub fn is_lo(&self) -> bool {
        self.name == "lo"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/iface.d.ts")]
#[serde(rename_all = "lowercase")]
#[serde(tag = "t", content = "c")]
pub enum DevState {
    /// Status can't be determined
    #[default]
    Unknown,
    /// Some component is missing
    NotPresent,
    /// Down
    Down,
    /// Down due to state of lower layer
    LowerLayerDown,
    /// In some test mode
    Testing,
    /// Not up but pending an external event
    Dormant,
    /// Up, ready to send packets
    Up,
    /// Place holder for new state introduced by kernel when current crate does
    /// not support so.
    Other(u8),
}

/// 设备类型小类
#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/iface.d.ts")]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Dummy,
    Ifb,
    Bridge,
    Tun,
    Nlmon,
    Vlan,
    Veth,
    Vxlan,
    Bond,
    IpVlan,
    MacVlan,
    MacVtap,
    GreTap,
    GreTap6,
    IpTun,
    SitTun,
    GreTun,
    GreTun6,
    Vti,
    Vrf,
    Gtp,
    Ipoib,
    Wireguard,
    Xfrm,
    MacSec,
    Hsr,
    Other(String),
    #[default]
    UnKnow,
}

/// 设备类型大类
#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/iface.d.ts")]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    UnSupport,
    Loopback,
    Ethernet,
    Ppp,
    Tunnel,
    Tunnel6,
}

pub fn get_interface_index_by_name(iface_name: &str) -> Option<u32> {
    let c_iface_name = match CString::new(iface_name) {
        Ok(c_iface_name) => c_iface_name,
        Err(e) => {
            tracing::error!("Invalid interface name: {:?}", e);
            return None;
        }
    };

    let index = unsafe { if_nametoindex(c_iface_name.as_ptr() as *const c_char) };

    if index == 0 {
        tracing::error!("Interface '{}' not found", iface_name);
        None
    } else {
        Some(index)
    }
}
