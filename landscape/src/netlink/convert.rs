use std::path::Path;

pub use landscape_common::dev::{DevState, DeviceKind, DeviceType, LandscapeInterface};
use landscape_common::net::MacAddr;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};

pub fn parse_link_message(msg: LinkMessage) -> Option<LandscapeInterface> {
    let mut name = None;
    let mut mac = None;
    let mut perm_mac = None;
    let mut controller_id = None;
    let mut status = None;
    let mut kind = None;
    let mut carrier = false;

    let mut netns_id = None;
    let mut peer_link_id = None;
    // println!("link_layer_type: {:?}", msg.header.link_layer_type);
    // println!("interface_family: {:?}", msg.header.interface_family);
    // println!("flags: {:?}", msg.header.flags);
    // let mut port_kind = None;
    // let mut data = None;
    // let mut port_data = None;
    // println!("{:?}", msg.attributes);
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
            LinkAttribute::PhysPortId(_) => {
                // println!("PhysPortId: {id:?}")
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
            LinkAttribute::IfNetnsId(id) => netns_id = Some(id),
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
        Some(name) => {
            let path = format!("/sys/class/net/{}/wireless", name);
            let is_wireless = Path::new(&path).exists();
            Some(LandscapeInterface {
                name,
                index: msg.header.index,
                mac,
                dev_type: convert_link_type(msg.header.link_layer_type),
                controller_id,
                dev_status: status.map_or(DevState::Unknown, |status| convert_link_state(status)),
                dev_kind: kind.map_or(DeviceKind::UnKnow, |kind| convert_link_kind(kind)),
                perm_mac,
                carrier,
                netns_id,
                peer_link_id,
                is_wireless,
            })
        }
        _ => None,
    }
}

pub fn convert_link_state(state: netlink_packet_route::link::State) -> DevState {
    match state {
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

pub fn convert_link_kind(kind: netlink_packet_route::link::InfoKind) -> DeviceKind {
    match kind {
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

pub fn convert_link_type(ty: netlink_packet_route::link::LinkLayerType) -> DeviceType {
    match ty {
        netlink_packet_route::link::LinkLayerType::Ether => DeviceType::Ethernet,
        netlink_packet_route::link::LinkLayerType::Ppp => DeviceType::Ppp,
        netlink_packet_route::link::LinkLayerType::Tunnel => DeviceType::Tunnel,
        netlink_packet_route::link::LinkLayerType::Tunnel6 => DeviceType::Tunnel6,
        netlink_packet_route::link::LinkLayerType::Loopback => DeviceType::Loopback,
        _ => DeviceType::UnSupport,
    }
}
