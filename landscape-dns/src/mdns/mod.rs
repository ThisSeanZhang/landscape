use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::resolve::LocalDnsAnswerProvider;

mod interface;
mod packet;
mod response;
mod runtime;
mod socket;

#[cfg(test)]
mod tests;

const MDNS_PORT: u16 = 5353;
const MDNS_V4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
const MDNS_HOSTNAME: &str = "landscape.local.";
const MDNS_HOST_TTL_SECS: u32 = 120;
const LEGACY_UNICAST_TTL_SECS: u32 = 10;
const MDNS_PACKET_QUEUE_CAPACITY: usize = 256;
const MDNS_LINK_HOP_LIMIT: u32 = 255;
const MDNS_SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(1);

pub struct MdnsService {
    token: CancellationToken,
    runtime: JoinHandle<()>,
}

impl MdnsService {
    pub fn spawn(
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    ) -> Option<Arc<Self>> {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(e) => {
                tracing::warn!("start mDNS responder failed without Tokio runtime: {e}");
                return None;
            }
        };
        let interfaces = interface::load_mdns_interfaces();
        let v4 = match socket::create_v4_socket(&interfaces) {
            Ok(socket) => Some(Arc::new(socket)),
            Err(e) => {
                tracing::warn!("create IPv4 mDNS socket failed: {e}");
                None
            }
        };
        let v6 = match socket::create_v6_socket(&interfaces) {
            Ok(socket) => Some(Arc::new(socket)),
            Err(e) => {
                tracing::warn!("create IPv6 mDNS socket failed: {e}");
                None
            }
        };

        if v4.is_none() && v6.is_none() {
            return None;
        }
        if interfaces.is_empty() {
            tracing::warn!("mDNS responder has no multicast-capable non-loopback interfaces");
        }

        let (packet_tx, packet_rx) = mpsc::channel(MDNS_PACKET_QUEUE_CAPACITY);
        let token = CancellationToken::new();
        if let Some(socket) = v4.as_ref() {
            socket::spawn_socket_listener(
                socket::MdnsSocket::V4(socket.clone()),
                packet_tx.clone(),
                token.clone(),
            );
        }
        if let Some(socket) = v6.as_ref() {
            socket::spawn_socket_listener(
                socket::MdnsSocket::V6(socket.clone()),
                packet_tx.clone(),
                token.clone(),
            );
        }

        let runtime = runtime::MdnsRuntime::new(
            v4,
            v6,
            interfaces,
            packet_rx,
            local_answer_provider,
            token.clone(),
        );
        let runtime = handle.spawn(runtime.run());

        Some(Arc::new(Self { token, runtime }))
    }
}

impl Drop for MdnsService {
    fn drop(&mut self) {
        self.token.cancel();
        self.runtime.abort();
    }
}
