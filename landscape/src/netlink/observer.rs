//! Link event source (Linux 6.12)
//!
//! Admin up/down: dev_open / dev_change_flags -> __dev_notify_flags
//!                -> rtmsg_ifinfo(change includes IFF_UP)
//! Carrier change: netif_carrier_on/off -> linkwatch -> netdev_state_change
//!                 -> rtmsg_ifinfo(change = 0)
//! Device creation: register_netdevice / rtnl_configure_link
//!                  -> rtmsg_ifinfo(change = ~0U)
//!
//! | Scenario                       | change | flags      | Action    |
//! | ------------------------------ | ------ | ---------- | --------- |
//! | Creation                       | ~0U    | Up / no Up | Up / Down |
//! | Admin up/down                  | IFF_UP | Up / no Up | Up / Down |
//! | Carrier change (insert/remove) | 0      | Up / -     | none      |
//! | Device deletion                | ~0U    | -          | Down      |
//!
//! Conventions:
//! - Carrier transitions are intentionally ignored: a cable insertion/removal
//!   arrives with `change = 0`, and the WAN clients recover through their own
//!   reconnect loops.
//! - Newly created interfaces always carry change = ~0U, so no startup baseline
//!   is needed.

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::{event::hub::EventHub, event::hub::iface::IfaceObserverAction};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkFlags, LinkMessage},
};
use netlink_sys::AsyncSocket;
use rtnetlink::constants::RTMGRP_LINK;
use tokio_stream::StreamExt;

use super::handle::create_connection_with_messages;

pub async fn dev_observer(hub: &EventHub) {
    let sender = hub.iface_sender();

    spawn_task(task_label::task::EVENT_NETLINK_DISPATCH, async move {
        let Ok((mut connection, _, mut messages)) = create_connection_with_messages() else {
            tracing::error!("failed to create netlink connection for dev_observer");
            return;
        };

        let addr = netlink_sys::SocketAddr::new(0, RTMGRP_LINK);
        if let Err(e) = connection.socket_mut().socket_mut().bind(&addr) {
            tracing::error!("failed to bind netlink socket for dev_observer: {e}");
            return;
        }
        spawn_task(task_label::task::NETLINK_CONN_OBSERVER, connection);

        let mut filter = LinkEventFilter;
        while let Some((message, _)) = messages.next().await {
            let Some(action) = filter.filter_message_status(message) else {
                continue;
            };

            if let IfaceObserverAction::Up(ref ifname) = action {
                let ifname = ifname.clone();
                spawn_task(task_label::task::EVENT_NETLINK_DISPATCH, async move {
                    crate::netlink::ethtool::disable_gro(&ifname).await;
                });
            }

            if let Err(e) = sender.send(action).await {
                tracing::warn!("EventHub mpsc send failed: {e:?}");
            }
        }
    });
}

/// Translates link notifications into the interface events consumed by the
/// rest of the system.
///
/// Only admin (`IFF_UP`) transitions and device deletion are reported. Carrier
/// notifications arrive with an empty `change_mask` (linkwatch calls
/// `netdev_state_change()` -> `rtmsg_ifinfo(..., change = 0, ...)`) and are
/// ignored; their consumers recover through the WAN clients' own reconnect
/// loops.
pub struct LinkEventFilter;

impl LinkEventFilter {
    /// - admin up/down (`IFF_UP` change) maps to [`IfaceObserverAction::Up`] /
    ///   [`IfaceObserverAction::Down`];
    /// - deleting the link maps to [`IfaceObserverAction::Down`];
    /// - carrier-only changes are ignored.
    pub fn filter_message_status(
        &mut self,
        message: NetlinkMessage<RouteNetlinkMessage>,
    ) -> Option<IfaceObserverAction> {
        let NetlinkPayload::InnerMessage(inner_message) = message.payload else {
            return None;
        };

        match inner_message {
            RouteNetlinkMessage::NewLink(link_message) => {
                if !link_message.header.change_mask.contains(LinkFlags::Up) {
                    return None;
                }
                let ifname = link_name(&link_message)?;
                Some(if link_message.header.flags.contains(LinkFlags::Up) {
                    IfaceObserverAction::Up(ifname)
                } else {
                    IfaceObserverAction::Down(ifname)
                })
            }
            RouteNetlinkMessage::DelLink(link_message) => {
                Some(IfaceObserverAction::Down(link_name(&link_message)?))
            }
            _ => None,
        }
    }
}

fn link_name(link_message: &LinkMessage) -> Option<String> {
    link_message.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::IfName(name) => Some(name.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFINDEX: u32 = 2;

    fn admin_event(
        flags: LinkFlags,
        change_mask: LinkFlags,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut link = LinkMessage::default();
        link.header.index = IFINDEX;
        link.header.flags = flags;
        link.header.change_mask = change_mask;
        link.attributes = vec![LinkAttribute::IfName("wan0".to_string())];
        NetlinkMessage::from(RouteNetlinkMessage::NewLink(link))
    }

    fn carrier_event(flags: LinkFlags) -> NetlinkMessage<RouteNetlinkMessage> {
        // A real kernel linkwatch notification: change_mask is empty and the
        // current flags/carrier attributes describe the new state.
        let mut link = LinkMessage::default();
        link.header.index = IFINDEX;
        link.header.flags = flags;
        link.attributes =
            vec![LinkAttribute::IfName("wan0".to_string()), LinkAttribute::Carrier(1)];
        NetlinkMessage::from(RouteNetlinkMessage::NewLink(link))
    }

    fn del_event() -> NetlinkMessage<RouteNetlinkMessage> {
        let mut link = LinkMessage::default();
        link.header.index = IFINDEX;
        link.attributes = vec![LinkAttribute::IfName("wan0".to_string())];
        NetlinkMessage::from(RouteNetlinkMessage::DelLink(link))
    }

    #[test]
    fn admin_up_maps_to_up() {
        let mut filter = LinkEventFilter;
        let message = admin_event(LinkFlags::Up, LinkFlags::Up);
        assert_eq!(
            filter.filter_message_status(message),
            Some(IfaceObserverAction::Up("wan0".into()))
        );
    }

    #[test]
    fn admin_down_maps_to_down() {
        let mut filter = LinkEventFilter;
        let message = admin_event(LinkFlags::empty(), LinkFlags::Up);
        assert_eq!(
            filter.filter_message_status(message),
            Some(IfaceObserverAction::Down("wan0".into()))
        );
    }

    #[test]
    fn carrier_only_change_is_ignored() {
        let mut filter = LinkEventFilter;

        // Cable insertion: carrier is up, but only change = 0 is reported.
        assert_eq!(filter.filter_message_status(carrier_event(LinkFlags::Up)), None);

        // Cable removal: admin state stays up, change is still 0.
        assert_eq!(filter.filter_message_status(carrier_event(LinkFlags::Up)), None);
    }

    #[test]
    fn deleted_link_maps_to_down() {
        let mut filter = LinkEventFilter;
        assert_eq!(
            filter.filter_message_status(del_event()),
            Some(IfaceObserverAction::Down("wan0".into()))
        );
    }
}
