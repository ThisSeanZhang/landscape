use std::{
    io,
    io::{IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, RawFd},
    str::FromStr,
    sync::Arc,
    thread,
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{
        rdata::{A, AAAA},
        DNSClass, Name, RData, Record, RecordType,
    },
};
use nix::{
    cmsg_space,
    ifaddrs::getifaddrs,
    net::if_::{if_nametoindex, InterfaceFlags},
    sys::socket::{
        recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
        SockaddrIn, SockaddrIn6,
    },
};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};
use tokio::{
    sync::{mpsc, mpsc::error::TrySendError},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::server::LocalDnsAnswerProvider;

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

enum MdnsSocket {
    V4(Arc<std::net::UdpSocket>),
    V6(Arc<std::net::UdpSocket>),
}

#[derive(Clone, Copy)]
enum MdnsFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MdnsResponseMode {
    MulticastMdns,
    UnicastMdns,
    LegacyUnicast,
}

struct MdnsRuntime {
    v4: Option<Arc<std::net::UdpSocket>>,
    v6: Option<Arc<std::net::UdpSocket>>,
    interfaces: Vec<MdnsInterface>,
    packet_rx: mpsc::Receiver<io::Result<MdnsPacket>>,
    local_answer_provider: Option<Arc<dyn LocalDnsAnswerProvider>>,
    token: CancellationToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MdnsInterface {
    ifindex: u32,
    name: String,
    has_ipv4: bool,
    has_ipv6: bool,
}

impl MdnsInterface {
    fn fallback(ifindex: u32) -> Self {
        Self {
            ifindex,
            name: format!("ifindex {ifindex}"),
            has_ipv4: true,
            has_ipv6: true,
        }
    }
}

struct MdnsPacket {
    bytes: Vec<u8>,
    ifindex: u32,
    hop_limit: Option<u32>,
    destination_is_multicast: bool,
    family: MdnsFamily,
    src: MdnsSource,
    query_unicast_response: bool,
}

#[derive(Clone)]
enum MdnsSource {
    V4(SockaddrIn),
    V6(SockaddrIn6),
}

impl MdnsSource {
    fn port(&self) -> u16 {
        match self {
            MdnsSource::V4(addr) => addr.port(),
            MdnsSource::V6(addr) => addr.port(),
        }
    }
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
        let interfaces = load_mdns_interfaces();
        let v4 = match create_v4_socket(&interfaces) {
            Ok(socket) => Some(Arc::new(socket)),
            Err(e) => {
                tracing::warn!("create IPv4 mDNS socket failed: {e}");
                None
            }
        };
        let v6 = match create_v6_socket(&interfaces) {
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
            spawn_socket_listener(MdnsSocket::V4(socket.clone()), packet_tx.clone(), token.clone());
        }
        if let Some(socket) = v6.as_ref() {
            spawn_socket_listener(MdnsSocket::V6(socket.clone()), packet_tx.clone(), token.clone());
        }

        let runtime = MdnsRuntime {
            v4,
            v6,
            interfaces,
            packet_rx,
            local_answer_provider,
            token: token.clone(),
        };
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

impl MdnsRuntime {
    async fn run(mut self) {
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

fn select_response_interfaces(interfaces: &[MdnsInterface], ifindex: u32) -> Vec<MdnsInterface> {
    if ifindex == 0 {
        return interfaces.to_vec();
    }

    let matched = interfaces
        .iter()
        .filter(|interface| interface.ifindex == ifindex)
        .cloned()
        .collect::<Vec<_>>();
    if matched.is_empty() {
        vec![MdnsInterface::fallback(ifindex)]
    } else {
        matched
    }
}

fn build_response(
    packet: &[u8],
    ifindex: u32,
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
    mode: MdnsResponseMode,
) -> Option<Vec<u8>> {
    let Ok(message) = Message::from_vec(packet) else {
        return None;
    };
    if message.message_type() != MessageType::Query || message.op_code() != OpCode::Query {
        return None;
    }

    let ttl = mode.answer_ttl();
    let cache_flush = mode.uses_cache_flush();
    let answers = message
        .queries()
        .iter()
        .flat_map(|query| {
            answer_records_for_query(query, ifindex, local_answer_provider, ttl, cache_flush)
        })
        .fold(Vec::new(), dedup_answer_record)
        .into_iter()
        .filter(|answer| !is_suppressed_by_known_answers(answer, message.answers()))
        .collect::<Vec<_>>();
    if answers.is_empty() {
        return None;
    }

    let mut response = Message::new();
    response.set_id(if mode == MdnsResponseMode::LegacyUnicast { message.id() } else { 0 });
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_authoritative(true);
    if mode == MdnsResponseMode::LegacyUnicast {
        for query in message.queries() {
            response.add_query(query.clone());
        }
    }
    for answer in answers {
        response.add_answer(answer);
    }

    response.to_vec().ok()
}

fn answer_records_for_query(
    query: &Query,
    ifindex: u32,
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
    ttl: u32,
    cache_flush: bool,
) -> Vec<Record> {
    if !normalize_name(&query.name().to_string()).eq_ignore_ascii_case(MDNS_HOSTNAME) {
        return Vec::new();
    }
    if !matches!(query.query_class(), DNSClass::IN | DNSClass::ANY) {
        return Vec::new();
    }

    let mut answers = Vec::new();
    let name = match Name::from_str(MDNS_HOSTNAME) {
        Ok(name) => name,
        Err(_) => return answers,
    };

    if matches!(query.query_type(), RecordType::A | RecordType::ANY) {
        for ip in load_answer_addrs(local_answer_provider, RecordType::A, ifindex) {
            if let IpAddr::V4(ip) = ip {
                let mut record = Record::from_rdata(name.clone(), ttl, RData::A(A(ip)));
                record.set_mdns_cache_flush(cache_flush);
                answers.push(record);
            }
        }
    }

    if matches!(query.query_type(), RecordType::AAAA | RecordType::ANY) {
        for ip in load_answer_addrs(local_answer_provider, RecordType::AAAA, ifindex) {
            if let IpAddr::V6(ip) = ip {
                let mut record = Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(ip)));
                record.set_mdns_cache_flush(cache_flush);
                answers.push(record);
            }
        }
    }

    answers
}

fn dedup_answer_record(mut answers: Vec<Record>, answer: Record) -> Vec<Record> {
    if !answers.iter().any(|existing| {
        existing.record_type() == answer.record_type() && existing.data() == answer.data()
    }) {
        answers.push(answer);
    }

    answers
}

fn is_suppressed_by_known_answers(answer: &Record, known_answers: &[Record]) -> bool {
    known_answers.iter().any(|known_answer| {
        known_answer.name() == answer.name()
            && known_answer.record_type() == answer.record_type()
            && known_answer.dns_class() == answer.dns_class()
            && known_answer.data() == answer.data()
            && known_answer.ttl() >= answer.ttl() / 2
    })
}

impl MdnsResponseMode {
    fn is_unicast(self) -> bool {
        matches!(self, Self::UnicastMdns | Self::LegacyUnicast)
    }

    fn answer_ttl(self) -> u32 {
        match self {
            Self::LegacyUnicast => LEGACY_UNICAST_TTL_SECS,
            Self::MulticastMdns | Self::UnicastMdns => MDNS_HOST_TTL_SECS,
        }
    }

    fn uses_cache_flush(self) -> bool {
        !matches!(self, Self::LegacyUnicast)
    }
}

fn select_response_mode(
    src: &MdnsSource,
    query_unicast_response: bool,
    destination_is_multicast: bool,
) -> MdnsResponseMode {
    if src.port() != MDNS_PORT {
        MdnsResponseMode::LegacyUnicast
    } else if query_unicast_response || !destination_is_multicast {
        MdnsResponseMode::UnicastMdns
    } else {
        MdnsResponseMode::MulticastMdns
    }
}

fn load_answer_addrs(
    local_answer_provider: Option<&dyn LocalDnsAnswerProvider>,
    query_type: RecordType,
    ifindex: u32,
) -> Vec<IpAddr> {
    local_answer_provider
        .map(|provider| {
            if ifindex == 0 {
                provider.load_local_answer_addrs(query_type)
            } else {
                provider.load_local_answer_addrs_for_ifindex(query_type, ifindex)
            }
        })
        .unwrap_or_default()
        .iter()
        .copied()
        .collect()
}

fn spawn_socket_listener(
    socket: MdnsSocket,
    tx: mpsc::Sender<io::Result<MdnsPacket>>,
    token: CancellationToken,
) {
    thread::spawn(move || loop {
        if token.is_cancelled() {
            break;
        }

        let result = match &socket {
            MdnsSocket::V4(socket) => recv_v4_packet(socket.as_raw_fd()),
            MdnsSocket::V6(socket) => recv_v6_packet(socket.as_raw_fd()),
        };

        match result {
            Ok(packet) => match tx.try_send(Ok(packet)) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => break,
            },
            Err(e) if is_temporary_recv_error(&e) => {}
            Err(e) => {
                let _ = tx.try_send(Err(e));
                break;
            }
        }
    });
}

fn is_temporary_recv_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn load_mdns_interfaces() -> Vec<MdnsInterface> {
    let mut interfaces = std::collections::HashMap::<String, MdnsInterface>::new();
    let Ok(addrs) = getifaddrs() else {
        return Vec::new();
    };

    for addr in addrs {
        if !addr.flags.contains(InterfaceFlags::IFF_UP)
            || addr.flags.contains(InterfaceFlags::IFF_LOOPBACK)
            || !addr.flags.contains(InterfaceFlags::IFF_MULTICAST)
        {
            continue;
        }

        let Ok(ifindex) = if_nametoindex(addr.interface_name.as_str()) else {
            continue;
        };
        let entry =
            interfaces.entry(addr.interface_name.clone()).or_insert_with(|| MdnsInterface {
                ifindex,
                name: addr.interface_name.clone(),
                has_ipv4: false,
                has_ipv6: false,
            });

        let Some(sockaddr) = addr.address else {
            continue;
        };
        if sockaddr.as_sockaddr_in().is_some() {
            entry.has_ipv4 = true;
        }
        if sockaddr.as_sockaddr_in6().is_some() {
            entry.has_ipv6 = true;
        }
    }

    interfaces.into_values().collect()
}

fn create_v4_socket(interfaces: &[MdnsInterface]) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos"
    ))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into())?;
    for interface in interfaces.iter().filter(|interface| interface.has_ipv4) {
        if let Err(e) = socket
            .join_multicast_v4_n(&MDNS_V4_GROUP, &InterfaceIndexOrAddress::Index(interface.ifindex))
        {
            tracing::warn!("join IPv4 mDNS group on {} failed: {e}", interface.name);
        }
    }
    socket.set_multicast_ttl_v4(255)?;
    socket.set_ttl_v4(255)?;
    socket.set_multicast_loop_v4(true)?;
    setsockopt(&socket, sockopt::Ipv4PacketInfo, &true).map_err(nix_to_io)?;
    setsockopt(&socket, sockopt::Ipv4RecvTtl, &true).map_err(nix_to_io)?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(MDNS_SOCKET_READ_TIMEOUT))?;
    Ok(socket)
}

fn create_v6_socket(interfaces: &[MdnsInterface]) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos"
    ))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0).into())?;
    for interface in interfaces.iter().filter(|interface| interface.has_ipv6) {
        if let Err(e) = socket.join_multicast_v6(&MDNS_V6_GROUP, interface.ifindex) {
            tracing::warn!("join IPv6 mDNS group on {} failed: {e}", interface.name);
        }
    }
    socket.set_multicast_hops_v6(255)?;
    socket.set_unicast_hops_v6(255)?;
    socket.set_multicast_loop_v6(true)?;
    setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true).map_err(nix_to_io)?;
    setsockopt(&socket, sockopt::Ipv6RecvHopLimit, &true).map_err(nix_to_io)?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(MDNS_SOCKET_READ_TIMEOUT))?;
    Ok(socket)
}

fn send_v4_message(
    fd: RawFd,
    message: &[u8],
    response_addr: Option<&MdnsSource>,
    ifindex: u32,
) -> io::Result<()> {
    let addr = match response_addr {
        Some(MdnsSource::V4(src)) => *src,
        _ => SockaddrIn::from(SocketAddrV4::new(MDNS_V4_GROUP, MDNS_PORT)),
    };
    let iov = [IoSlice::new(message)];
    let packet_info = libc::in_pktinfo {
        ipi_ifindex: ifindex as libc::c_int,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    let cmsgs = [ControlMessage::Ipv4PacketInfo(&packet_info)];
    sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr)).map_err(nix_to_io)?;
    Ok(())
}

fn send_v6_message(
    fd: RawFd,
    message: &[u8],
    response_addr: Option<&MdnsSource>,
    ifindex: u32,
) -> io::Result<()> {
    let addr = match response_addr {
        Some(MdnsSource::V6(src)) => *src,
        _ => SockaddrIn6::from(SocketAddrV6::new(MDNS_V6_GROUP, MDNS_PORT, 0, ifindex)),
    };
    let iov = [IoSlice::new(message)];
    let packet_info = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
        ipi6_ifindex: ifindex,
    };
    let cmsgs = [ControlMessage::Ipv6PacketInfo(&packet_info)];
    sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr)).map_err(nix_to_io)?;
    Ok(())
}

fn recv_v4_packet(fd: RawFd) -> io::Result<MdnsPacket> {
    let mut buf = vec![0_u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = cmsg_space!(libc::in_pktinfo, libc::c_int);
    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(nix_to_io)?;
    let bytes = msg.bytes;
    let src = msg.address.ok_or_else(|| io::Error::other("missing source address"))?;
    let mut ifindex = 0;
    let mut hop_limit = None;
    let mut destination_is_multicast = false;
    for cmsg in msg.cmsgs().map_err(nix_to_io)? {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                ifindex = info.ipi_ifindex as u32;
                destination_is_multicast =
                    Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()) == MDNS_V4_GROUP;
            }
            ControlMessageOwned::Ipv4Ttl(ttl) => {
                hop_limit = Some(ttl as u32);
            }
            _ => {}
        }
    }

    buf.truncate(bytes);
    let query_unicast_response = parse_query_unicast_response(&buf[..bytes]);

    Ok(MdnsPacket {
        bytes: buf,
        ifindex,
        hop_limit,
        destination_is_multicast,
        family: MdnsFamily::V4,
        src: MdnsSource::V4(src),
        query_unicast_response,
    })
}

fn recv_v6_packet(fd: RawFd) -> io::Result<MdnsPacket> {
    let mut buf = vec![0_u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = cmsg_space!(libc::in6_pktinfo, libc::c_int);
    let msg = recvmsg::<SockaddrIn6>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(nix_to_io)?;
    let bytes = msg.bytes;
    let src = msg.address.ok_or_else(|| io::Error::other("missing source address"))?;
    let mut ifindex = 0;
    let mut hop_limit = None;
    let mut destination_is_multicast = false;
    for cmsg in msg.cmsgs().map_err(nix_to_io)? {
        match cmsg {
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                ifindex = info.ipi6_ifindex;
                destination_is_multicast = Ipv6Addr::from(info.ipi6_addr.s6_addr) == MDNS_V6_GROUP;
            }
            ControlMessageOwned::Ipv6HopLimit(limit) => {
                hop_limit = Some(limit as u32);
            }
            _ => {}
        }
    }

    buf.truncate(bytes);
    let query_unicast_response = parse_query_unicast_response(&buf[..bytes]);

    Ok(MdnsPacket {
        bytes: buf,
        ifindex,
        hop_limit,
        destination_is_multicast,
        family: MdnsFamily::V6,
        src: MdnsSource::V6(src),
        query_unicast_response,
    })
}

fn parse_query_unicast_response(packet: &[u8]) -> bool {
    let Ok(message) = Message::from_vec(packet) else {
        return false;
    };

    message.queries().iter().any(|query| query.mdns_unicast_response())
}

fn has_valid_mdns_hop_limit(family: MdnsFamily, hop_limit: Option<u32>) -> bool {
    match family {
        MdnsFamily::V4 => matches!(hop_limit, Some(MDNS_LINK_HOP_LIMIT) | Some(1)),
        MdnsFamily::V6 => hop_limit == Some(MDNS_LINK_HOP_LIMIT),
    }
}

fn normalize_name(name: &str) -> String {
    let mut name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    name.push('.');
    name
}

fn nix_to_io(err: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockLocalAnswerProvider {
        addrs: Vec<IpAddr>,
        ifindexed: HashMap<u32, Vec<IpAddr>>,
    }

    impl LocalDnsAnswerProvider for MockLocalAnswerProvider {
        fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
            Arc::new(
                self.addrs
                    .iter()
                    .copied()
                    .filter(|ip| {
                        matches!(
                            (query_type, ip),
                            (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
                        )
                    })
                    .collect(),
            )
        }

        fn load_local_answer_addrs_for_ifindex(
            &self,
            query_type: RecordType,
            ifindex: u32,
        ) -> Arc<Vec<IpAddr>> {
            Arc::new(
                self.ifindexed
                    .iter()
                    .filter(|(route_ifindex, _)| **route_ifindex == ifindex)
                    .flat_map(|(_, addrs)| addrs.iter())
                    .copied()
                    .filter(|ip| {
                        matches!(
                            (query_type, ip),
                            (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
                        )
                    })
                    .collect(),
            )
        }
    }

    fn query_packet(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(0);
        message.set_op_code(OpCode::Query);
        message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    fn query_packet_with_id(name: &str, record_type: RecordType, id: u16) -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(id);
        message.set_op_code(OpCode::Query);
        message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    fn query_packet_with_class(name: &str, record_type: RecordType, class: DNSClass) -> Vec<u8> {
        let mut query = Query::query(Name::from_str(name).unwrap(), record_type);
        query.set_query_class(class);

        let mut message = Message::new();
        message.set_id(0);
        message.set_op_code(OpCode::Query);
        message.add_query(query);
        message.to_vec().unwrap()
    }

    fn query_packet_with_types(name: &str, record_types: &[RecordType]) -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(0);
        message.set_op_code(OpCode::Query);
        for record_type in record_types {
            message.add_query(Query::query(Name::from_str(name).unwrap(), *record_type));
        }
        message.to_vec().unwrap()
    }

    fn query_packet_with_known_answer(name: &str, known_answer_ttl: u32) -> Vec<u8> {
        let name = Name::from_str(name).unwrap();
        let mut message = Message::new();
        message.set_id(0);
        message.set_op_code(OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            known_answer_ttl,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 1))),
        ));
        message.to_vec().unwrap()
    }

    fn query_packet_with_unicast_response(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut query = Query::query(Name::from_str(name).unwrap(), record_type);
        query.set_mdns_unicast_response(true);

        let mut message = Message::new();
        message.set_id(0);
        message.set_op_code(OpCode::Query);
        message.add_query(query);
        message.to_vec().unwrap()
    }

    #[test]
    fn normalize_name_adds_trailing_dot_and_lowercases() {
        assert_eq!(normalize_name("Landscape.LOCAL"), "landscape.local.");
        assert_eq!(normalize_name("landscape.local."), "landscape.local.");
    }

    #[test]
    fn response_answers_landscape_local_a() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };
        let response = build_response(
            &query_packet("landscape.local.", RecordType::A),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .expect("landscape.local A query must be answered");
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].name().to_string(), MDNS_HOSTNAME);
        assert_eq!(response.answers()[0].record_type(), RecordType::A);
        assert_eq!(response.answers()[0].ttl(), MDNS_HOST_TTL_SECS);
        assert!(response.answers()[0].mdns_cache_flush());
    }

    #[test]
    fn response_ignores_other_local_names() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };

        assert!(build_response(
            &query_packet("printer.local.", RecordType::A),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none());
    }

    #[test]
    fn response_requires_available_address_family() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };

        assert!(build_response(
            &query_packet("landscape.local.", RecordType::AAAA),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none());
    }

    #[test]
    fn response_ignores_unsupported_query_class() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };

        assert!(build_response(
            &query_packet_with_class("landscape.local.", RecordType::A, DNSClass::CH),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none());
    }

    #[test]
    fn response_deduplicates_answers_across_queries() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };

        let response = build_response(
            &query_packet_with_types("landscape.local.", &[RecordType::A, RecordType::ANY]),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .expect("landscape.local A/ANY query must be answered");
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].record_type(), RecordType::A);
    }

    #[test]
    fn response_suppresses_known_answers_with_sufficient_ttl() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };

        assert!(build_response(
            &query_packet_with_known_answer("landscape.local.", MDNS_HOST_TTL_SECS / 2),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .is_none());
    }

    #[test]
    fn response_does_not_suppress_known_answers_with_low_ttl() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };

        let response = build_response(
            &query_packet_with_known_answer("landscape.local.", MDNS_HOST_TTL_SECS / 2 - 1),
            0,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .expect("low-TTL known answer should not suppress response");
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.answers().len(), 1);
    }

    #[test]
    fn query_with_unicast_response_is_detected() {
        assert!(parse_query_unicast_response(&query_packet_with_unicast_response(
            "landscape.local.",
            RecordType::A,
        )));
    }

    #[test]
    fn ipv4_mdns_packets_accept_legacy_link_ttl() {
        assert!(has_valid_mdns_hop_limit(MdnsFamily::V4, Some(255)));
        assert!(has_valid_mdns_hop_limit(MdnsFamily::V4, Some(1)));
        assert!(!has_valid_mdns_hop_limit(MdnsFamily::V4, Some(254)));
        assert!(!has_valid_mdns_hop_limit(MdnsFamily::V4, None));
    }

    #[test]
    fn ipv6_mdns_packets_require_link_local_hop_limit() {
        assert!(has_valid_mdns_hop_limit(MdnsFamily::V6, Some(255)));
        assert!(!has_valid_mdns_hop_limit(MdnsFamily::V6, Some(1)));
        assert!(!has_valid_mdns_hop_limit(MdnsFamily::V6, Some(254)));
        assert!(!has_valid_mdns_hop_limit(MdnsFamily::V6, None));
    }

    #[test]
    fn response_interfaces_use_all_for_missing_packet_ifindex() {
        let interfaces = vec![
            MdnsInterface {
                ifindex: 3,
                name: "lan0".to_string(),
                has_ipv4: true,
                has_ipv6: false,
            },
            MdnsInterface {
                ifindex: 7,
                name: "lan1".to_string(),
                has_ipv4: false,
                has_ipv6: true,
            },
        ];

        assert_eq!(select_response_interfaces(&interfaces, 0), interfaces);
    }

    #[test]
    fn response_interfaces_match_packet_ifindex() {
        let interfaces = vec![
            MdnsInterface {
                ifindex: 3,
                name: "lan0".to_string(),
                has_ipv4: true,
                has_ipv6: false,
            },
            MdnsInterface {
                ifindex: 7,
                name: "lan1".to_string(),
                has_ipv4: false,
                has_ipv6: true,
            },
        ];

        assert_eq!(
            select_response_interfaces(&interfaces, 7),
            vec![MdnsInterface {
                ifindex: 7,
                name: "lan1".to_string(),
                has_ipv4: false,
                has_ipv6: true,
            }]
        );
    }

    #[test]
    fn response_interfaces_fallback_to_packet_ifindex_when_cache_misses() {
        let interfaces = vec![MdnsInterface {
            ifindex: 3,
            name: "lan0".to_string(),
            has_ipv4: true,
            has_ipv6: true,
        }];

        assert_eq!(
            select_response_interfaces(&interfaces, 9),
            vec![MdnsInterface {
                ifindex: 9,
                name: "ifindex 9".to_string(),
                has_ipv4: true,
                has_ipv6: true,
            }]
        );
    }

    #[test]
    fn response_mode_uses_legacy_unicast_for_non_mdns_source_port() {
        let src = MdnsSource::V4(SockaddrIn::from(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 2),
            49_152,
        )));

        assert_eq!(select_response_mode(&src, false, true), MdnsResponseMode::LegacyUnicast);
    }

    #[test]
    fn response_mode_uses_unicast_for_qu_or_direct_unicast_queries() {
        let src = MdnsSource::V4(SockaddrIn::from(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 2),
            MDNS_PORT,
        )));

        assert_eq!(select_response_mode(&src, true, true), MdnsResponseMode::UnicastMdns);
        assert_eq!(select_response_mode(&src, false, false), MdnsResponseMode::UnicastMdns);
        assert_eq!(select_response_mode(&src, false, true), MdnsResponseMode::MulticastMdns);
    }

    #[test]
    fn legacy_response_keeps_id_query_and_omits_cache_flush() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ifindexed: HashMap::new(),
        };
        let response = build_response(
            &query_packet_with_id("landscape.local.", RecordType::A, 0x1234),
            0,
            Some(&provider),
            MdnsResponseMode::LegacyUnicast,
        )
        .expect("legacy landscape.local A query must be answered");
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.queries().len(), 1);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].ttl(), LEGACY_UNICAST_TTL_SECS);
        assert!(!response.answers()[0].mdns_cache_flush());
    }
    #[test]
    fn response_uses_ifindex_specific_addresses_when_available() {
        let provider = MockLocalAnswerProvider {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
            ifindexed: HashMap::from([
                (3, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]),
                (7, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10))]),
            ]),
        };

        let response = build_response(
            &query_packet("landscape.local.", RecordType::A),
            7,
            Some(&provider),
            MdnsResponseMode::MulticastMdns,
        )
        .expect("landscape.local A query must be answered");
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].data(), &RData::A(A(Ipv4Addr::new(192, 168, 2, 10))));
    }
}
