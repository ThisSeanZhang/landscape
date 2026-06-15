use landscape_common::observer::IfaceObserverAction;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{address::AddressMessage, RouteNetlinkMessage};
use netlink_sys::AsyncSocket;
use rtnetlink::constants::{RTMGRP_IPV4_IFADDR, RTMGRP_LINK};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tracing::instrument;

use super::handle::create_connection_with_messages;

pub async fn ip_observer() {
    tokio::spawn(async move {
        let (mut connection, _, mut messages) =
            create_connection_with_messages().map_err(|e| format!("{e}")).unwrap();
        let mgroup_flags = RTMGRP_IPV4_IFADDR;

        let addr = netlink_sys::SocketAddr::new(0, mgroup_flags);
        connection.socket_mut().socket_mut().bind(&addr).expect("failed to bind");
        tokio::spawn(connection);
        while let Some((message, _)) = messages.next().await {
            println!("Route change message - {message:?}");
            handle_address_msg(message);
        }
    });
}

pub async fn dev_observer() -> broadcast::Receiver<IfaceObserverAction> {
    let (tx, rx) = broadcast::channel(30);

    tokio::spawn(async move {
        let (mut connection, _, mut messages) =
            create_connection_with_messages().map_err(|e| format!("{e}")).unwrap();
        let mgroup_flags = RTMGRP_LINK;

        let addr = netlink_sys::SocketAddr::new(0, mgroup_flags);
        connection.socket_mut().socket_mut().bind(&addr).expect("failed to bind");
        tokio::spawn(connection);
        while let Some((message, _)) = messages.next().await {
            // println!("Route change message - {message:?}");
            if let Some(msg) = filter_message_status(message) {
                if let IfaceObserverAction::Up(ref ifname) = msg {
                    let ifname = ifname.clone();
                    tokio::spawn(async move {
                        crate::netlink::ethtool::disable_gro(&ifname).await;
                    });
                }
                if let Err(e) = tx.send(msg) {
                    println!("too many msg, drop this msg: {e:?}");
                }
            }
        }
    });
    rx
}

pub fn filter_message_status(
    message: NetlinkMessage<RouteNetlinkMessage>,
) -> Option<IfaceObserverAction> {
    match message.payload {
        NetlinkPayload::InnerMessage(inner_message) => {
            // println!("Received Inner message: {:?}", inner_message);
            match inner_message {
                RouteNetlinkMessage::NewLink(link_message) => {
                    // tracing::debug!("NewLink: {:?}", link_message);
                    if link_message
                        .header
                        .change_mask
                        .contains(netlink_packet_route::link::LinkFlags::Up)
                    {
                        let mut ifacename = None;
                        for attr in link_message.attributes {
                            match attr {
                                netlink_packet_route::link::LinkAttribute::IfName(iface_name) => {
                                    ifacename = Some(iface_name);
                                }
                                _ => {}
                            }
                        }

                        let Some(ifacename) = ifacename else {
                            return None;
                        };

                        let mut result = IfaceObserverAction::Down(ifacename.clone());
                        if link_message
                            .header
                            .flags
                            .contains(netlink_packet_route::link::LinkFlags::Up)
                        {
                            result = IfaceObserverAction::Up(ifacename);
                        }

                        Some(result)
                    } else {
                        None
                    }
                }
                RouteNetlinkMessage::DelLink(_link_message) => {
                    // tracing::debug!("DelLink: {:?}", link_message);
                    None
                }
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn handle_address_msg(message: NetlinkMessage<RouteNetlinkMessage>) {
    match message.payload {
        NetlinkPayload::InnerMessage(inner_message) => {
            match inner_message {
                RouteNetlinkMessage::NewAddress(link_message) => {
                    handle_address_update(link_message, true); // 对应 add_wan_ip
                }
                RouteNetlinkMessage::DelAddress(link_message) => {
                    handle_address_update(link_message, false); // 对应 del_wan_ip
                }
                _ => {}
            }
        }
        _ => {}
    }
}

#[instrument(skip(link_message))]
fn handle_address_update(link_message: AddressMessage, is_add: bool) {
    // let link_ifindex = link_message.header.index;
    let mut addr = None;

    for attr in link_message.attributes.iter() {
        match attr {
            netlink_packet_route::address::AddressAttribute::Address(address) => {
                addr = Some(address);
            }
            _ => {}
        }
    }

    if let Some(addr) = addr {
        let _ = match addr {
            std::net::IpAddr::V4(ipv4_addr) => ipv4_addr,
            std::net::IpAddr::V6(_) => {
                return; // 如果是 IPv6，可以直接返回，或根据需要处理
            }
        };

        // if is_add {
        //     landscape_ebpf::map_setting::add_ipv4_wan_ip(link_ifindex, ip.clone());
        // } else {
        //     landscape_ebpf::map_setting::del_ipv4_wan_ip(link_ifindex);
        // }
    }
}
