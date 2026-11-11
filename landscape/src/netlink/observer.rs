//! Link event source (Linux 6.12)
//!
//! Admin up/down: dev_open / dev_change_flags -> __dev_notify_flags
//!                -> rtmsg_ifinfo(change includes IFF_UP)
//! Carrier change: netif_carrier_on/off -> linkwatch -> netdev_state_change
//!                 -> rtmsg_ifinfo(change = 0)
//! Device creation: register_netdevice / rtnl_configure_link
//!                  -> rtmsg_ifinfo(change = ~0U)
//!
//! | Scenario                        | change | flags      | CARRIER | UP_COUNT | Action    |
//! | ------------------------------- | ------ | ---------- | ------- | -------- | --------- |
//! | Creation                        | ~0U    | Up / no Up | current | current  | Up / Down |
//! | Admin up/down                   | IFF_UP | Up / no Up | current | current  | Up / Down |
//! | Cable insertion                 | 0      | Up+LowerUp | 1       | +1       | CarrierUp |
//! | Cable removal                   | 0      | Up         | 0       | unchanged | none      |
//! | Carrier change while admin down | none   | -          | -       | +1       | none      |
//! | Device deletion                 | ~0U    | -          | current | current  | Down      |
//!
//! Conventions:
//! - Removal and admin down do not trigger WAN reconfiguration; Down is still
//!   broadcast so consumers can decide.
//! - Newly created interfaces always carry change = ~0U, so no startup baseline
//!   is needed.
//! - IFLA_CARRIER / IFLA_CARRIER_UP_COUNT are always populated by
//!   rtnl_fill_ifinfo().
//! - netif_carrier_event() increments both up/down (mlx5/mlx4); other
//!   change = 0 dormant/stacked events with an unchanged carrier produce no
//!   action.

use std::collections::HashMap;

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

        let mut filter = LinkEventFilter::default();
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
/// Carrier transitions must not rely on `ifi_change`: linkwatch calls
/// `netdev_state_change()` -> `rtmsg_ifinfo(..., change = 0, ...)`, so a real
/// cable insertion arrives with an empty `change_mask`. Instead we track the
/// per-interface carrier state and `IFLA_CARRIER_UP_COUNT`, both of which are
/// always present in `rtnl_fill_ifinfo()`.
#[derive(Default)]
pub struct LinkEventFilter {
    carrier_state: HashMap<u32, bool>,
    carrier_up_count: HashMap<u32, u32>,
}

impl LinkEventFilter {
    /// - admin up/down (`IFF_UP` change) maps to [`IfaceObserverAction::Up`] /
    ///   [`IfaceObserverAction::Down`];
    /// - a cable insertion maps to [`IfaceObserverAction::CarrierUp`]. Cable
    ///   removal is ignored;
    /// - deleting the link maps to [`IfaceObserverAction::Down`].
    pub fn filter_message_status(
        &mut self,
        message: NetlinkMessage<RouteNetlinkMessage>,
    ) -> Option<IfaceObserverAction> {
        let NetlinkPayload::InnerMessage(inner_message) = message.payload else {
            return None;
        };

        match inner_message {
            RouteNetlinkMessage::NewLink(link_message) => {
                let ifindex = link_message.header.index;
                let carrier_now = carrier_is_up(&link_message);
                let carrier_before = self.carrier_state.insert(ifindex, carrier_now);
                let up_count_now = carrier_up_count(&link_message);
                let up_count_before = match up_count_now {
                    Some(count) => self.carrier_up_count.insert(ifindex, count),
                    None => self.carrier_up_count.get(&ifindex).copied(),
                };

                if link_message.header.change_mask.contains(LinkFlags::Up) {
                    let ifname = link_name(&link_message)?;
                    return Some(if link_message.header.flags.contains(LinkFlags::Up) {
                        IfaceObserverAction::Up(ifname)
                    } else {
                        IfaceObserverAction::Down(ifname)
                    });
                }

                let carrier_inserted = carrier_now
                    && match up_count_now {
                        // The counter survives missed notifications, so an
                        // increment is enough even if we never saw the cable
                        // being removed. An unknown ifindex is treated as an
                        // insertion (covers interfaces that predate the observer).
                        Some(count) => {
                            up_count_before.map_or(carrier_before != Some(true), |old| count > old)
                        }
                        // Fallback for kernels without IFLA_CARRIER_UP_COUNT.
                        None => carrier_before != Some(true),
                    };
                if carrier_inserted {
                    return Some(IfaceObserverAction::CarrierUp(link_name(&link_message)?));
                }

                None
            }
            RouteNetlinkMessage::DelLink(link_message) => {
                self.carrier_state.remove(&link_message.header.index);
                self.carrier_up_count.remove(&link_message.header.index);
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

fn carrier_is_up(link_message: &LinkMessage) -> bool {
    link_message
        .attributes
        .iter()
        .any(|attr| matches!(attr, LinkAttribute::Carrier(value) if *value != 0))
}

fn carrier_up_count(link_message: &LinkMessage) -> Option<u32> {
    link_message.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::CarrierUpCount(count) => Some(*count),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFINDEX: u32 = 2;

    /// Build a message shaped like a real kernel linkwatch notification:
    /// `change_mask` is empty and the current state is carried by `flags`,
    /// `IFLA_CARRIER` and `IFLA_CARRIER_UP_COUNT`.
    fn link_event(
        flags: LinkFlags,
        carrier: u8,
        up_count: Option<u32>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut message = LinkMessage::default();
        message.header.index = IFINDEX;
        message.header.flags = flags;
        message.attributes =
            vec![LinkAttribute::IfName("wan0".to_string()), LinkAttribute::Carrier(carrier)];
        if let Some(up_count) = up_count {
            message.attributes.push(LinkAttribute::CarrierUpCount(up_count));
        }
        NetlinkMessage::from(RouteNetlinkMessage::NewLink(message))
    }

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

    fn del_event() -> NetlinkMessage<RouteNetlinkMessage> {
        let mut link = LinkMessage::default();
        link.header.index = IFINDEX;
        link.attributes = vec![LinkAttribute::IfName("wan0".to_string())];
        NetlinkMessage::from(RouteNetlinkMessage::DelLink(link))
    }

    #[test]
    fn admin_up_maps_to_up() {
        let mut filter = LinkEventFilter::default();
        let message = admin_event(LinkFlags::Up, LinkFlags::Up);
        assert_eq!(
            filter.filter_message_status(message),
            Some(IfaceObserverAction::Up("wan0".into()))
        );
    }

    #[test]
    fn admin_down_maps_to_down() {
        let mut filter = LinkEventFilter::default();
        let message = admin_event(LinkFlags::empty(), LinkFlags::Up);
        assert_eq!(
            filter.filter_message_status(message),
            Some(IfaceObserverAction::Down("wan0".into()))
        );
    }

    #[test]
    fn new_iface_already_up_emits_carrier_up() {
        let mut filter = LinkEventFilter::default();
        assert_eq!(
            filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(1))),
            Some(IfaceObserverAction::CarrierUp("wan0".into()))
        );
    }

    #[test]
    fn carrier_insertion_with_empty_change_mask_maps_to_carrier_up() {
        let mut filter = LinkEventFilter::default();

        // Baseline: admin up, cable unplugged. Real kernel message has no
        // change bits set.
        let unplugged = link_event(LinkFlags::Up, 0, Some(0));
        assert_eq!(filter.filter_message_status(unplugged), None);

        // Cable inserted: only carrier state/counter changed.
        let inserted = link_event(LinkFlags::Up, 1, Some(1));
        assert_eq!(
            filter.filter_message_status(inserted),
            Some(IfaceObserverAction::CarrierUp("wan0".into()))
        );
    }

    #[test]
    fn reinsertion_with_higher_count_emits_carrier_up() {
        let mut filter = LinkEventFilter::default();

        // Baseline, then an unrelated notification at the same counter.
        let _ = filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(1)));
        assert_eq!(filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(1))), None);

        // The removal notification was dropped, but the counter still proves
        // that a new insertion happened.
        assert_eq!(
            filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(2))),
            Some(IfaceObserverAction::CarrierUp("wan0".into()))
        );
    }

    #[test]
    fn carrier_fallback_without_up_count() {
        let mut filter = LinkEventFilter::default();

        let unplugged = link_event(LinkFlags::Up, 0, None);
        assert_eq!(filter.filter_message_status(unplugged), None);

        let inserted = link_event(LinkFlags::Up, 1, None);
        assert_eq!(
            filter.filter_message_status(inserted),
            Some(IfaceObserverAction::CarrierUp("wan0".into()))
        );
    }

    #[test]
    fn cable_removal_is_ignored() {
        let mut filter = LinkEventFilter::default();

        let _ = filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(1)));
        let removed = link_event(LinkFlags::Up, 0, Some(1));
        assert_eq!(filter.filter_message_status(removed), None);
    }

    #[test]
    fn unrelated_state_change_is_ignored() {
        let mut filter = LinkEventFilter::default();

        let _ = filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(3)));

        // e.g. operstate/qdisc change: change_mask is empty, carrier and
        // counter are unchanged.
        let unchanged = link_event(LinkFlags::Up, 1, Some(3));
        assert_eq!(filter.filter_message_status(unchanged), None);
    }

    #[test]
    fn deleted_link_maps_to_down_and_clears_state() {
        let mut filter = LinkEventFilter::default();
        let _ = filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(1)));

        assert_eq!(
            filter.filter_message_status(del_event()),
            Some(IfaceObserverAction::Down("wan0".into()))
        );
        assert!(!filter.carrier_state.contains_key(&IFINDEX));
        assert!(!filter.carrier_up_count.contains_key(&IFINDEX));

        // Re-created interface is treated as a fresh insertion.
        assert_eq!(
            filter.filter_message_status(link_event(LinkFlags::Up, 1, Some(1))),
            Some(IfaceObserverAction::CarrierUp("wan0".into()))
        );
    }
}
