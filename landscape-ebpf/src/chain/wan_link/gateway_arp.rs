use super::{Inner, WanLinkDataplane};
use landscape_common::net::MacAddr;
use landscape_common::wan_link::GatewayArpTarget;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Default)]
pub(super) struct GatewayArpState {
    target: watch::Sender<Option<Arc<GatewayArpTarget>>>,
    confirmed: Option<(GatewayArpTarget, MacAddr)>,
}

impl GatewayArpState {
    pub(super) fn active_confirmation(&self) -> Option<(GatewayArpTarget, MacAddr)> {
        self.target.borrow().as_ref()?;
        self.confirmed
    }
}

impl Inner {
    fn gateway_arp_target(&self) -> Option<GatewayArpTarget> {
        let bind = self.v4?;
        if !self.has_eth_header || bind.is_pppoe || Some(bind.ifindex) != self.ifindex {
            return None;
        }
        let (IpAddr::V4(local_ip), IpAddr::V4(gateway_ip)) = (bind.addr, bind.gateway?) else {
            return None;
        };
        let target = GatewayArpTarget {
            ifindex: bind.ifindex,
            local_mac: bind.mac?,
            local_ip,
            gateway_ip,
        };
        target.validate().ok()?;
        Some(target)
    }

    pub(super) fn sync_gateway_arp_target(&mut self) {
        let next = self.gateway_arp_target();
        // A missing lease suspends probing. A different interface or next hop
        // must establish its own MAC, even if a prior ARP request is still in flight.
        if let Some((last, _)) = self.gateway_arp.confirmed
            && (Some(last.ifindex) != self.ifindex
                || next.is_some_and(|t| t.gateway_ip != last.gateway_ip))
        {
            self.gateway_arp.confirmed = None;
        }
        let changed = self.gateway_arp.target.send_if_modified(|current| {
            if current.as_deref() == next.as_ref() {
                return false;
            }
            *current = next.map(Arc::new);
            true
        });
        if changed {
            self.sync_root_gateway_mac();
        }
    }

    fn sync_root_gateway_mac(&mut self) {
        if let Some(root) = self.tc.egress_root.as_mut() {
            root.sync_gateway_mac(&self.gateway_arp);
        }
    }

    pub(super) fn clear_gateway_arp(&mut self) {
        self.gateway_arp.target.send_if_modified(|target| target.take().is_some());
        self.gateway_arp.confirmed = None;
        self.sync_root_gateway_mac();
    }
}

impl WanLinkDataplane {
    /// Clone the current target and drop the watch borrow before calling back into the dataplane.
    pub fn subscribe_gateway_arp(&self) -> watch::Receiver<Option<Arc<GatewayArpTarget>>> {
        let inner = self.inner.lock().unwrap();
        if inner.closed {
            return watch::channel(None).1;
        }
        inner.gateway_arp.target.subscribe()
    }

    /// Forget the last confirmation when IPv4 acquisition is explicitly disabled.
    pub fn clear_gateway_arp(&self) {
        self.inner.lock().unwrap().clear_gateway_arp();
    }

    /// Accept a reply only for the binding that started the probe. A return to
    /// identical addresses after an unbind creates a fresh target instance.
    pub fn confirm_gateway_mac(&self, target: &Arc<GatewayArpTarget>, mac: MacAddr) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let state = &mut inner.gateway_arp;
        if !state.target.borrow().as_ref().is_some_and(|current| Arc::ptr_eq(current, target))
            || mac.is_zero()
            || mac.is_multicast()
        {
            return false;
        }
        let changed = state.confirmed.is_none_or(|(_, old_mac)| old_mac != mac);
        state.confirmed = Some((**target, mac));
        if changed {
            inner.sync_root_gateway_mac();
        }
        changed
    }

    /// Last confirmed MAC for the active Ethernet gateway, if any.
    pub fn confirmed_gateway_mac(&self) -> Option<MacAddr> {
        self.inner.lock().unwrap().gateway_arp.active_confirmation().map(|(_, mac)| mac)
    }
}
