use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use serde::{Deserialize, Serialize};

use crate::macaddr::MacAddr;

/// 当前硬件状态结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LandScapeInterface {
    pub name: String,
    pub index: u32,
    pub mac: Option<MacAddr>,
    pub perm_mac: Option<MacAddr>,
    pub dev_type: DeviceType,
    pub dev_kind: DeviceKind,
    pub dev_status: DevState,
    pub controller_id: Option<u32>,
    // 网线是否插入
    pub carrier: bool,
    pub netns_id: Option<i32>,
    pub peer_link_id: Option<u32>,
}

impl LandScapeInterface {
    pub fn new(msg: LinkMessage) -> Option<LandScapeInterface> {
        let mut name = None;
        let mut mac = None;
        let mut perm_mac = None;
        let mut controller_id = None;
        let mut status = None;
        let mut kind = None;
        let mut carrier = false;

        let mut netns_id = None;
        let mut peer_link_id = None;
        // let mut port_kind = None;
        // let mut data = None;
        // let mut port_data = None;
        for nla in msg.attributes.into_iter() {
            // println!("{:?}", nla);
            // println!();
            match nla {
                LinkAttribute::Address(address) => {
                    if address.len() >= 6 {
                        mac = Some(MacAddr(
                            address[0], address[1], address[2], address[3], address[4], address[5],
                        ));
                    }
                }
                LinkAttribute::IfName(n) => {
                    // println!("name: {:?}", n);
                    name = Some(n)
                }
                LinkAttribute::Controller(ctrl) => controller_id = Some(ctrl),
                // LinkAttribute::VfInfoList(macs) => {
                //     println!("VfInfoList {:?} ", macs)
                // }
                //     LinkAttribute::VfPorts(_) => todo!(),
                //     LinkAttribute::PortSelf(_) => todo!(),
                LinkAttribute::PhysPortId(id) => {
                    println!("PhysPortId: {id:?}")
                }
                LinkAttribute::PhysSwitchId(_) => {
                    // PhysSwitchId 有物理交换机
                    // println!("PhysSwitchId: {id:?}")
                }
                // LinkAttribute::Xdp(xdp_link) => todo!(),
                //     LinkAttribute::Event(_) => todo!(),
                //     LinkAttribute::NewNetnsId(_) => todo!(),
                //     LinkAttribute::IfNetnsId(_) => todo!(),
                //     LinkAttribute::CarrierUpCount(_) => todo!(),
                //     LinkAttribute::CarrierDownCount(_) => todo!(),
                //     LinkAttribute::NewIfIndex(_) => todo!(),
                LinkAttribute::LinkInfo(info) => {
                    for info in info.into_iter() {
                        match info {
                            netlink_packet_route::link::LinkInfo::Xstats(_) => {}
                            netlink_packet_route::link::LinkInfo::Kind(k) => {
                                // println!("Kind: {k:?}");
                                kind = Some(k)
                            }
                            netlink_packet_route::link::LinkInfo::Data(_) => {
                                // data = Some(d);
                            }
                            netlink_packet_route::link::LinkInfo::PortKind(_) => {
                                // port_kind = Some(p_k);
                            }
                            netlink_packet_route::link::LinkInfo::PortData(_) => {
                                // port_data = Some(p_d)
                            }
                            netlink_packet_route::link::LinkInfo::Other(_) => {}
                            _ => {}
                        }
                    }
                }
                //     LinkAttribute::Wireless(_) => todo!(),
                //     LinkAttribute::ProtoInfoBridge(_) => todo!(),
                //     LinkAttribute::ProtoInfoInet6(_) => todo!(),
                //     LinkAttribute::ProtoInfoUnknown(_) => todo!(),
                //     LinkAttribute::PropList(_) => todo!(),
                //     LinkAttribute::ProtoDownReason(_) => todo!(),
                //     LinkAttribute::Broadcast(_) => todo!(),
                LinkAttribute::PermAddress(address) => {
                    if address.len() >= 6 {
                        let mac = MacAddr(
                            address[0], address[1], address[2], address[3], address[4], address[5],
                        );
                        perm_mac = Some(mac);
                        // println!("PermAddress: {:?}", mac);
                    }
                }
                //     LinkAttribute::Qdisc(_) => todo!(),
                //     LinkAttribute::IfAlias(_) => todo!(),
                //     LinkAttribute::PhysPortName(_) => todo!(),
                //     LinkAttribute::Mode(_) => todo!(),
                LinkAttribute::Carrier(c) => {
                    carrier = c != 0;
                }
                //     LinkAttribute::ProtoDown(_) => todo!(),
                //     LinkAttribute::Mtu(_) => todo!(),
                LinkAttribute::Link(id) => peer_link_id = Some(id),
                //     LinkAttribute::Controller(_) => todo!(),
                //     LinkAttribute::TxQueueLen(_) => todo!(),
                //     LinkAttribute::NetNsPid(_) => todo!(),
                LinkAttribute::NumVf(data) => println!("NumVf: {data:?}"),
                //     LinkAttribute::Group(_) => todo!(),
                //     LinkAttribute::NetNsFd(_) => todo!(),
                //     LinkAttribute::ExtMask(_) => todo!(),
                //     LinkAttribute::Promiscuity(_) => todo!(),
                //     LinkAttribute::NumTxQueues(_) => todo!(),
                //     LinkAttribute::NumRxQueues(_) => todo!(),
                //     LinkAttribute::CarrierChanges(_) => todo!(),
                //     LinkAttribute::GsoMaxSegs(_) => todo!(),
                //     LinkAttribute::GsoMaxSize(_) => todo!(),
                //     LinkAttribute::MinMtu(_) => todo!(),
                //     LinkAttribute::MaxMtu(_) => todo!(),
                LinkAttribute::NetnsId(id) => netns_id = Some(id),
                LinkAttribute::OperState(s) => status = Some(s),
                //     LinkAttribute::Stats(_) => todo!(),
                //     LinkAttribute::Stats64(_) => todo!(),
                //     LinkAttribute::Map(_) => todo!(),
                //     LinkAttribute::AfSpecUnspec(_) => todo!(),
                //     LinkAttribute::AfSpecBridge(_) => todo!(),
                //     LinkAttribute::AfSpecUnknown(_) => todo!(),
                //     LinkAttribute::Other(_) => todo!(),
                _ => {}
            }
        }

        match name {
            Some(name) => Some(LandScapeInterface {
                name,
                index: msg.header.index,
                mac,
                dev_type: msg.header.link_layer_type.into(),
                controller_id,
                dev_status: status.map_or(DevState::Unknown, |status| status.into()),
                dev_kind: kind.map_or(DeviceKind::UnKnow, |kind| kind.into()),
                perm_mac,
                carrier,
                netns_id,
                peer_link_id,
            }),
            _ => None,
        }
    }

    pub fn is_virtual_dev(&self) -> bool {
        !matches!(self.dev_kind, DeviceKind::UnKnow)
    }

    pub fn is_lo(&self) -> bool {
        self.name == "lo"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
impl Into<DevState> for netlink_packet_route::link::State {
    fn into(self) -> DevState {
        match self {
            netlink_packet_route::link::State::Unknown => DevState::Unknown,
            netlink_packet_route::link::State::NotPresent => DevState::NotPresent,
            netlink_packet_route::link::State::Down => DevState::Down,
            netlink_packet_route::link::State::LowerLayerDown => DevState::LowerLayerDown,
            netlink_packet_route::link::State::Testing => DevState::Testing,
            netlink_packet_route::link::State::Dormant => DevState::Dormant,
            netlink_packet_route::link::State::Up => DevState::Up,
            netlink_packet_route::link::State::Other(o) => DevState::Other(o),
            _ => DevState::Unknown,
        }
    }
}

/// 设备类型小类
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
impl Into<DeviceKind> for netlink_packet_route::link::InfoKind {
    fn into(self) -> DeviceKind {
        match self {
            netlink_packet_route::link::InfoKind::Dummy => DeviceKind::Dummy,
            netlink_packet_route::link::InfoKind::Ifb => DeviceKind::Ifb,
            netlink_packet_route::link::InfoKind::Bridge => DeviceKind::Bridge,
            netlink_packet_route::link::InfoKind::Tun => DeviceKind::Tun,
            netlink_packet_route::link::InfoKind::Nlmon => DeviceKind::Nlmon,
            netlink_packet_route::link::InfoKind::Vlan => DeviceKind::Vlan,
            netlink_packet_route::link::InfoKind::Veth => DeviceKind::Veth,
            netlink_packet_route::link::InfoKind::Vxlan => DeviceKind::Vxlan,
            netlink_packet_route::link::InfoKind::Bond => DeviceKind::Bond,
            netlink_packet_route::link::InfoKind::IpVlan => DeviceKind::IpVlan,
            netlink_packet_route::link::InfoKind::MacVlan => DeviceKind::MacVlan,
            netlink_packet_route::link::InfoKind::MacVtap => DeviceKind::MacVtap,
            netlink_packet_route::link::InfoKind::GreTap => DeviceKind::GreTap,
            netlink_packet_route::link::InfoKind::GreTap6 => DeviceKind::GreTap6,
            netlink_packet_route::link::InfoKind::IpTun => DeviceKind::IpTun,
            netlink_packet_route::link::InfoKind::SitTun => DeviceKind::SitTun,
            netlink_packet_route::link::InfoKind::GreTun => DeviceKind::GreTun,
            netlink_packet_route::link::InfoKind::GreTun6 => DeviceKind::GreTun6,
            netlink_packet_route::link::InfoKind::Vti => DeviceKind::Vti,
            netlink_packet_route::link::InfoKind::Vrf => DeviceKind::Vrf,
            netlink_packet_route::link::InfoKind::Gtp => DeviceKind::Gtp,
            netlink_packet_route::link::InfoKind::Ipoib => DeviceKind::Ipoib,
            netlink_packet_route::link::InfoKind::Wireguard => DeviceKind::Wireguard,
            netlink_packet_route::link::InfoKind::Xfrm => DeviceKind::Xfrm,
            netlink_packet_route::link::InfoKind::MacSec => DeviceKind::MacSec,
            netlink_packet_route::link::InfoKind::Hsr => DeviceKind::Hsr,
            netlink_packet_route::link::InfoKind::Other(s) => DeviceKind::Other(s),
            _ => DeviceKind::UnKnow,
        }
    }
}

/// 设备类型大类
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DeviceType {
    UnSupport,
    Loopback,
    Ethernet,
    Ppp,
    Tunnel,
    Tunnel6,
}
impl Into<DeviceType> for netlink_packet_route::link::LinkLayerType {
    fn into(self) -> DeviceType {
        match self {
            netlink_packet_route::link::LinkLayerType::Ether => DeviceType::Ethernet,
            netlink_packet_route::link::LinkLayerType::Ppp => DeviceType::Ppp,
            netlink_packet_route::link::LinkLayerType::Tunnel => DeviceType::Tunnel,
            netlink_packet_route::link::LinkLayerType::Tunnel6 => DeviceType::Tunnel6,
            netlink_packet_route::link::LinkLayerType::Loopback => DeviceType::Loopback,
            _ => DeviceType::UnSupport,
        }
    }
}
