use tokio::sync::broadcast;

use super::device::{EnrolledDeviceEvent, EnrolledDeviceEventReader};
use super::frontend_event::{FrontendEvent, FrontendEventReader};
use super::iface::IfaceEventReader;
use super::ipv4::{IPv4AssignEvent, IPv4AssignEventReader};
use super::ipv6::{IAPrefixEvent, IAPrefixEventReader, IPv6AssignEvent, IPv6AssignEventReader};
use crate::observer::IfaceObserverAction;

pub struct EventHubHandle {
    iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
    ipv4_broadcast_tx: broadcast::Sender<IPv4AssignEvent>,
    ipv6_broadcast_tx: broadcast::Sender<IPv6AssignEvent>,
    ia_prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
    // Keep the initial receivers alive so the broadcast channels always have at
    // least one active receiver. This prevents dispatcher events from being
    // dropped due to zero receivers before services subscribe.
    _broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
    _frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
    _device_broadcast_rx: broadcast::Receiver<EnrolledDeviceEvent>,
    _ipv4_broadcast_rx: broadcast::Receiver<IPv4AssignEvent>,
    _ipv6_broadcast_rx: broadcast::Receiver<IPv6AssignEvent>,
    _ia_prefix_broadcast_rx: broadcast::Receiver<IAPrefixEvent>,
}

impl EventHubHandle {
    pub(super) fn new(
        iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
        iface_broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
        frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
        frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
        device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
        device_broadcast_rx: broadcast::Receiver<EnrolledDeviceEvent>,
        ipv4_broadcast_tx: broadcast::Sender<IPv4AssignEvent>,
        ipv4_broadcast_rx: broadcast::Receiver<IPv4AssignEvent>,
        ipv6_broadcast_tx: broadcast::Sender<IPv6AssignEvent>,
        ipv6_broadcast_rx: broadcast::Receiver<IPv6AssignEvent>,
        ia_prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
        ia_prefix_broadcast_rx: broadcast::Receiver<IAPrefixEvent>,
    ) -> Self {
        Self {
            iface_broadcast_tx,
            frontend_broadcast_tx,
            device_broadcast_tx,
            ipv4_broadcast_tx,
            ipv6_broadcast_tx,
            ia_prefix_broadcast_tx,
            _broadcast_rx: iface_broadcast_rx,
            _frontend_broadcast_rx: frontend_broadcast_rx,
            _device_broadcast_rx: device_broadcast_rx,
            _ipv4_broadcast_rx: ipv4_broadcast_rx,
            _ipv6_broadcast_rx: ipv6_broadcast_rx,
            _ia_prefix_broadcast_rx: ia_prefix_broadcast_rx,
        }
    }

    pub fn subscribe_iface(&self) -> IfaceEventReader {
        IfaceEventReader::new(self.iface_broadcast_tx.subscribe())
    }

    pub fn subscribe_frontend(&self) -> FrontendEventReader {
        FrontendEventReader::new(self.frontend_broadcast_tx.subscribe())
    }

    pub fn subscribe_device(&self) -> EnrolledDeviceEventReader {
        EnrolledDeviceEventReader::new(self.device_broadcast_tx.subscribe())
    }

    pub fn subscribe_ipv4_assign(&self) -> IPv4AssignEventReader {
        IPv4AssignEventReader::new(self.ipv4_broadcast_tx.subscribe())
    }

    pub fn subscribe_ipv6_assign(&self) -> IPv6AssignEventReader {
        IPv6AssignEventReader::new(self.ipv6_broadcast_tx.subscribe())
    }

    pub fn subscribe_ipv6_prefix(&self) -> IAPrefixEventReader {
        IAPrefixEventReader::new(self.ia_prefix_broadcast_tx.subscribe())
    }

    // TODO: Refactor LanIPv6Service to use subscribe_ipv6_prefix() instead of
    // receiving the raw broadcast::Sender. The sender is currently threaded
    // through multiple service layers (LanIPv6ManagerService -> LanIPv6Service
    // -> spawn_prefix_watcher / spawn_pd_watcher) only so watchers can call
    // .subscribe() on it. Once that is cleaned up this method can be removed.
    pub fn ipv6_prefix_broadcast_tx(&self) -> broadcast::Sender<IAPrefixEvent> {
        self.ia_prefix_broadcast_tx.clone()
    }
}
