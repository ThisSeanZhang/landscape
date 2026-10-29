use std::{io, os::fd::AsRawFd, sync::Arc};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::resolve::LocalDnsAnswerProvider;

use super::interface::{MdnsInterface, select_response_interfaces};
use super::packet::{MdnsFamily, MdnsPacket, MdnsSource, has_valid_mdns_hop_limit};
use super::response::{MdnsResponseMode, build_response, select_response_mode};
use super::socket::{send_v4_message, send_v6_message};

pub(super) struct MdnsRuntime {
    v4: Option<Arc<std::net::UdpSocket>>,
    v6: Option<Arc<std::net::UdpSocket>>,
    interfaces: Vec<MdnsInterface>,
    packet_rx: mpsc::Receiver<io::Result<MdnsPacket>>,
    local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    token: CancellationToken,
}

impl MdnsRuntime {
    pub(super) fn new(
        v4: Option<Arc<std::net::UdpSocket>>,
        v6: Option<Arc<std::net::UdpSocket>>,
        interfaces: Vec<MdnsInterface>,
        packet_rx: mpsc::Receiver<io::Result<MdnsPacket>>,
        local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
        token: CancellationToken,
    ) -> Self {
        Self {
            v4,
            v6,
            interfaces,
            packet_rx,
            local_answer_provider,
            token,
        }
    }

    pub(super) async fn run(mut self) {
        loop {
            tokio::select! {
                _ = self.token.cancelled() => break,
                packet = self.packet_rx.recv() => {
                    let Some(packet) = packet else {
                        break;
                    };
                    self.handle_packet(packet);
                }
            }
        }
    }

    fn handle_packet(&self, packet: io::Result<MdnsPacket>) {
        let packet = match packet {
            Ok(packet) => packet,
            Err(e) => {
                tracing::debug!("receive mDNS packet failed: {e}");
                return;
            }
        };
        if !has_valid_mdns_hop_limit(packet.family, packet.hop_limit) {
            tracing::trace!("discard mDNS packet with invalid hop limit: {:?}", packet.hop_limit);
            return;
        }

        let mode = select_response_mode(
            &packet.src,
            packet.query_unicast_response,
            packet.destination_is_multicast,
        );
        let Some(response) = build_response(
            &packet.bytes,
            packet.ifindex,
            self.local_answer_provider.as_deref(),
            mode,
        ) else {
            return;
        };

        self.send_response(packet.family, packet.ifindex, packet.src, mode, &response);
    }

    fn send_response(
        &self,
        family: MdnsFamily,
        ifindex: u32,
        src: MdnsSource,
        mode: MdnsResponseMode,
        response: &[u8],
    ) {
        let response_addr = if mode.is_unicast() { Some(src) } else { None };

        match family {
            MdnsFamily::V4 => {
                let Some(socket) = self.v4.as_ref() else {
                    return;
                };
                for interface in select_response_interfaces(&self.interfaces, ifindex)
                    .into_iter()
                    .filter(|interface| interface.has_ipv4)
                {
                    if let Err(e) = send_v4_message(
                        socket.as_raw_fd(),
                        response,
                        response_addr.as_ref(),
                        interface.ifindex,
                    ) {
                        tracing::debug!(
                            "send IPv4 mDNS response on {} failed: {e}",
                            interface.name
                        );
                    }
                }
            }
            MdnsFamily::V6 => {
                let Some(socket) = self.v6.as_ref() else {
                    return;
                };
                for interface in select_response_interfaces(&self.interfaces, ifindex)
                    .into_iter()
                    .filter(|interface| interface.has_ipv6)
                {
                    if let Err(e) = send_v6_message(
                        socket.as_raw_fd(),
                        response,
                        response_addr.as_ref(),
                        interface.ifindex,
                    ) {
                        tracing::debug!(
                            "send IPv6 mDNS response on {} failed: {e}",
                            interface.name
                        );
                    }
                }
            }
        }
    }
}
