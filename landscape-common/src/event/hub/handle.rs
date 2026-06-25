use tokio::sync::broadcast;

use super::device::EnrolledDeviceEvent;
use super::frontend_event::FrontendEvent;
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

    pub fn subscribe_frontend(&self) -> broadcast::Receiver<FrontendEvent> {
        self.frontend_broadcast_tx.subscribe()
    }

    pub fn subscribe_device(&self) -> broadcast::Receiver<EnrolledDeviceEvent> {
        self.device_broadcast_tx.subscribe()
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

    pub fn ipv6_prefix_broadcast_tx(&self) -> broadcast::Sender<IAPrefixEvent> {
        self.ia_prefix_broadcast_tx.clone()
    }
}
