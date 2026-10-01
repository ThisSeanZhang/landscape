mod device;
mod discovery;
mod frontend_event;
mod handle;
pub mod iface;
mod ipv4;
mod ipv6;
mod lan_device;

pub use device::{EnrolledDeviceEvent, EnrolledDeviceEventReader, EnrolledDeviceEventSender};
pub use discovery::{
    LanDiscoveryEvent, LanDiscoveryEventReader, LanDiscoveryEventSender, LanDiscoverySource,
};
pub use frontend_event::{FrontendEvent, FrontendEventReader};
pub use handle::EventHubHandle;
pub use iface::{IfaceEventReader, IfaceEventSender};
pub use ipv4::{IPv4AssignEvent, IPv4AssignEventReader, IPv4AssignEventSender, IPv4AssignInfo};
pub use ipv6::{
    IAPrefixEvent, IAPrefixEventReader, IAPrefixEventSender, IPv6AssignEvent,
    IPv6AssignEventReader, IPv6AssignEventSender, IPv6AssignInfo, IPv6AssignSource,
    Ipv6AssignAddress,
};
pub use lan_device::{LanDeviceChange, LanDeviceEvent, LanDeviceEventReader, LanDeviceEventSender};

use tokio::sync::{broadcast, mpsc};

use iface::IfaceObserverAction;

const IFACE_MPSC_CAPACITY: usize = 32;
const IFACE_BROADCAST_CAPACITY: usize = 64;
const FRONTEND_BROADCAST_CAPACITY: usize = 256;
const DEVICE_MPSC_CAPACITY: usize = 32;
const DEVICE_BROADCAST_CAPACITY: usize = 64;
const IPV4_MPSC_CAPACITY: usize = 32;
const IPV4_BROADCAST_CAPACITY: usize = 64;
const IPV6_MPSC_CAPACITY: usize = 32;
const IPV6_BROADCAST_CAPACITY: usize = 64;
const IAPREFIX_MPSC_CAPACITY: usize = 32;
const IAPREFIX_BROADCAST_CAPACITY: usize = 64;
const DISCOVERY_MPSC_CAPACITY: usize = 256;
const DISCOVERY_BROADCAST_CAPACITY: usize = 256;
// The lan_device pipeline must absorb a full directory re-seed (enrollment
// backfill plus first-scan discovery observations) without dropping events.
const LAN_DEVICE_MPSC_CAPACITY: usize = 512;
const LAN_DEVICE_BROADCAST_CAPACITY: usize = 512;

pub struct EventHub {
    rx: mpsc::Receiver<IfaceObserverAction>,
    broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
    mpsc_tx: mpsc::Sender<IfaceObserverAction>,

    device_rx: mpsc::Receiver<EnrolledDeviceEvent>,
    device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
    device_broadcast_rx: broadcast::Receiver<EnrolledDeviceEvent>,
    device_mpsc_tx: mpsc::Sender<EnrolledDeviceEvent>,

    ipv4_rx: mpsc::Receiver<IPv4AssignEvent>,
    ipv4_broadcast_tx: broadcast::Sender<IPv4AssignEvent>,
    ipv4_broadcast_rx: broadcast::Receiver<IPv4AssignEvent>,
    ipv4_mpsc_tx: mpsc::Sender<IPv4AssignEvent>,

    ipv6_rx: mpsc::Receiver<IPv6AssignEvent>,
    ipv6_broadcast_tx: broadcast::Sender<IPv6AssignEvent>,
    ipv6_broadcast_rx: broadcast::Receiver<IPv6AssignEvent>,
    ipv6_mpsc_tx: mpsc::Sender<IPv6AssignEvent>,

    ia_prefix_rx: mpsc::Receiver<IAPrefixEvent>,
    ia_prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
    ia_prefix_broadcast_rx: broadcast::Receiver<IAPrefixEvent>,
    ia_prefix_mpsc_tx: mpsc::Sender<IAPrefixEvent>,

    discovery_rx: mpsc::Receiver<LanDiscoveryEvent>,
    discovery_broadcast_tx: broadcast::Sender<LanDiscoveryEvent>,
    discovery_broadcast_rx: broadcast::Receiver<LanDiscoveryEvent>,
    discovery_mpsc_tx: mpsc::Sender<LanDiscoveryEvent>,

    lan_device_rx: mpsc::Receiver<LanDeviceEvent>,
    lan_device_broadcast_tx: broadcast::Sender<LanDeviceEvent>,
    lan_device_broadcast_rx: broadcast::Receiver<LanDeviceEvent>,
    lan_device_mpsc_tx: mpsc::Sender<LanDeviceEvent>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(IFACE_MPSC_CAPACITY);
        let (broadcast_tx, broadcast_rx) = broadcast::channel(IFACE_BROADCAST_CAPACITY);
        let (frontend_broadcast_tx, frontend_broadcast_rx) =
            broadcast::channel(FRONTEND_BROADCAST_CAPACITY);

        let (device_tx, device_rx) = mpsc::channel(DEVICE_MPSC_CAPACITY);
        let (device_broadcast_tx, device_broadcast_rx) =
            broadcast::channel(DEVICE_BROADCAST_CAPACITY);

        let (ipv4_tx, ipv4_rx) = mpsc::channel(IPV4_MPSC_CAPACITY);
        let (ipv4_broadcast_tx, ipv4_broadcast_rx) = broadcast::channel(IPV4_BROADCAST_CAPACITY);

        let (ipv6_tx, ipv6_rx) = mpsc::channel(IPV6_MPSC_CAPACITY);
        let (ipv6_broadcast_tx, ipv6_broadcast_rx) = broadcast::channel(IPV6_BROADCAST_CAPACITY);

        let (ia_prefix_tx, ia_prefix_rx) = mpsc::channel(IAPREFIX_MPSC_CAPACITY);
        let (ia_prefix_broadcast_tx, ia_prefix_broadcast_rx) =
            broadcast::channel(IAPREFIX_BROADCAST_CAPACITY);

        let (discovery_tx, discovery_rx) = mpsc::channel(DISCOVERY_MPSC_CAPACITY);
        let (discovery_broadcast_tx, discovery_broadcast_rx) =
            broadcast::channel(DISCOVERY_BROADCAST_CAPACITY);

        let (lan_device_tx, lan_device_rx) = mpsc::channel(LAN_DEVICE_MPSC_CAPACITY);
        let (lan_device_broadcast_tx, lan_device_broadcast_rx) =
            broadcast::channel(LAN_DEVICE_BROADCAST_CAPACITY);

        Self {
            rx,
            broadcast_tx,
            broadcast_rx,
            frontend_broadcast_tx,
            frontend_broadcast_rx,
            mpsc_tx: tx,

            device_rx,
            device_broadcast_tx,
            device_broadcast_rx,
            device_mpsc_tx: device_tx,

            ipv4_rx,
            ipv4_broadcast_tx,
            ipv4_broadcast_rx,
            ipv4_mpsc_tx: ipv4_tx,

            ipv6_rx,
            ipv6_broadcast_tx,
            ipv6_broadcast_rx,
            ipv6_mpsc_tx: ipv6_tx,

            ia_prefix_rx,
            ia_prefix_broadcast_tx,
            ia_prefix_broadcast_rx,
            ia_prefix_mpsc_tx: ia_prefix_tx,

            discovery_rx,
            discovery_broadcast_tx,
            discovery_broadcast_rx,
            discovery_mpsc_tx: discovery_tx,

            lan_device_rx,
            lan_device_broadcast_tx,
            lan_device_broadcast_rx,
            lan_device_mpsc_tx: lan_device_tx,
        }
    }

    pub fn iface_sender(&self) -> IfaceEventSender {
        IfaceEventSender::new(self.mpsc_tx.clone())
    }

    pub fn enrolled_device_sender(&self) -> EnrolledDeviceEventSender {
        EnrolledDeviceEventSender::new(self.device_mpsc_tx.clone())
    }

    pub fn ipv4_sender(&self) -> IPv4AssignEventSender {
        IPv4AssignEventSender::new(self.ipv4_mpsc_tx.clone())
    }

    pub fn ipv6_sender(&self) -> IPv6AssignEventSender {
        IPv6AssignEventSender::new(self.ipv6_mpsc_tx.clone())
    }

    pub fn ipv6_prefix_sender(&self) -> IAPrefixEventSender {
        IAPrefixEventSender::new(self.ia_prefix_mpsc_tx.clone())
    }

    pub fn lan_discovery_sender(&self) -> LanDiscoveryEventSender {
        LanDiscoveryEventSender::new(self.discovery_mpsc_tx.clone())
    }

    pub fn lan_device_sender(&self) -> LanDeviceEventSender {
        LanDeviceEventSender::new(self.lan_device_mpsc_tx.clone())
    }

    pub fn spawn(self) -> EventHubHandle {
        let Self {
            rx,
            broadcast_tx,
            broadcast_rx,
            frontend_broadcast_tx,
            frontend_broadcast_rx,
            mpsc_tx: _,

            device_rx,
            device_broadcast_tx,
            device_broadcast_rx,
            device_mpsc_tx: _,

            ipv4_rx,
            ipv4_broadcast_tx,
            ipv4_broadcast_rx,
            ipv4_mpsc_tx: _,

            ipv6_rx,
            ipv6_broadcast_tx,
            ipv6_broadcast_rx,
            ipv6_mpsc_tx: _,

            ia_prefix_rx,
            ia_prefix_broadcast_tx,
            ia_prefix_broadcast_rx,
            ia_prefix_mpsc_tx: _,

            discovery_rx,
            discovery_broadcast_tx,
            discovery_broadcast_rx,
            discovery_mpsc_tx: _,

            lan_device_rx,
            lan_device_broadcast_tx,
            lan_device_broadcast_rx,
            lan_device_mpsc_tx: _,
        } = self;

        let handle = EventHubHandle::new(
            broadcast_tx.clone(),
            broadcast_rx,
            frontend_broadcast_tx.clone(),
            frontend_broadcast_rx,
            device_broadcast_tx.clone(),
            device_broadcast_rx,
            ipv4_broadcast_tx.clone(),
            ipv4_broadcast_rx,
            ipv6_broadcast_tx.clone(),
            ipv6_broadcast_rx,
            ia_prefix_broadcast_tx.clone(),
            ia_prefix_broadcast_rx,
            discovery_broadcast_tx.clone(),
            discovery_broadcast_rx,
            lan_device_broadcast_tx.clone(),
            lan_device_broadcast_rx,
        );
        crate::concurrency::spawn_task(
            crate::concurrency::task_label::task::EVENT_HUB_DISPATCHER,
            async move {
                Self::run_dispatcher(
                    rx,
                    broadcast_tx,
                    frontend_broadcast_tx,
                    device_rx,
                    device_broadcast_tx,
                    ipv4_rx,
                    ipv4_broadcast_tx,
                    ipv6_rx,
                    ipv6_broadcast_tx,
                    ia_prefix_rx,
                    ia_prefix_broadcast_tx,
                    discovery_rx,
                    discovery_broadcast_tx,
                    lan_device_rx,
                    lan_device_broadcast_tx,
                )
                .await
            },
        );
        handle
    }

    #[allow(clippy::too_many_arguments)] // 各事件域独立的 channel tx/rx，成对传入
    async fn run_dispatcher(
        mut rx: mpsc::Receiver<IfaceObserverAction>,
        broadcast_tx: broadcast::Sender<IfaceObserverAction>,
        frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
        mut device_rx: mpsc::Receiver<EnrolledDeviceEvent>,
        device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
        mut ipv4_rx: mpsc::Receiver<IPv4AssignEvent>,
        ipv4_broadcast_tx: broadcast::Sender<IPv4AssignEvent>,
        mut ipv6_rx: mpsc::Receiver<IPv6AssignEvent>,
        ipv6_broadcast_tx: broadcast::Sender<IPv6AssignEvent>,
        mut ia_prefix_rx: mpsc::Receiver<IAPrefixEvent>,
        ia_prefix_broadcast_tx: broadcast::Sender<IAPrefixEvent>,
        mut discovery_rx: mpsc::Receiver<LanDiscoveryEvent>,
        discovery_broadcast_tx: broadcast::Sender<LanDiscoveryEvent>,
        mut lan_device_rx: mpsc::Receiver<LanDeviceEvent>,
        lan_device_broadcast_tx: broadcast::Sender<LanDeviceEvent>,
    ) {
        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch Iface event");
                    if let Err(e) = broadcast_tx.send(event.clone()) {
                        tracing::warn!("EventHub: iface broadcast channel full, dropping event: {e:?}");
                    }
                    if let Err(e) = frontend_broadcast_tx.send(FrontendEvent::from(event)) {
                        tracing::warn!("EventHub: frontend broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = device_rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch Device event");
                    if let Err(e) = device_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: device broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = ipv4_rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch IPv4 event");
                    if let Err(e) = ipv4_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: ipv4 broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = ipv6_rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch IPv6 event");
                    if let Err(e) = ipv6_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: ipv6 broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = ia_prefix_rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch IAPrefix event");
                    if let Err(e) = ia_prefix_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: ia_prefix broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = discovery_rx.recv() => {
                    tracing::trace!(?event, "EventHub: dispatch Discovery event");
                    if let Err(e) = discovery_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: discovery broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = lan_device_rx.recv() => {
                    tracing::trace!(?event, "EventHub: dispatch LanDevice event");
                    if let Err(e) = lan_device_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: lan_device broadcast channel full, dropping event: {e:?}");
                    }
                }
                else => break,
            }
        }
        tracing::info!("EventHub dispatcher task stopped");
    }
}
