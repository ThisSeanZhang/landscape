use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use crate::dump::udp_packet::dhcp::options::DhcpOptions;
use crate::dump::udp_packet::dhcp::{
    options::DhcpOptionMessageType, DhcpEthFrame, DhcpOptionFrame,
};

use arc_swap::ArcSwap;
use cidr::Ipv4Inet;
use landscape_common::dhcp::v4_server::config::{
    CustomDhcpOption, DHCPv4ServerConfig, DhcpV4DnrOptionConfig,
};
use landscape_common::dhcp::v4_server::status::DHCPv4OfferInfo;
use landscape_common::dns::dnr::{
    encode_dhcpv4_dnr_payload_truncated, is_valid_dnr_ipv4_addr, normalize_advertise_domains,
    DHCPV4_DNR_OPTION_CODE,
};
#[cfg(test)]
use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::net::MacAddr;

use crate::dhcp_server::dhcp_v4_status::DhcpV4AssignStatus;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT, LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME,
};
use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;
use tracing::instrument;

const IP_EXPIRE_INTERVAL: u64 = 60 * 10;

#[instrument(skip(server_ip, dhcp_server, service_status))]
pub async fn dhcp_v4_server(
    iface_name: String,
    iface_ifindex: u32,
    iface_mac: Option<MacAddr>,
    server_ip: Ipv4Addr,
    prefix_length: u8,
    dhcp_server: DHCPv4Server,
    service_status: WatchService,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let ip = server_ip;
    let link_name = iface_name.clone();
    tokio::spawn(async move {
        let handle = match crate::netlink::handle::create_handle() {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("failed to create netlink handle: {e:?}");
                return;
            }
        };
        crate::netlink::address::add_address_with_handle(
            &link_name,
            IpAddr::V4(ip),
            prefix_length,
            handle,
        )
        .await
    });

    let socket_addr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT);

    let socket2 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    // TODO: Error handle
    socket2.set_reuse_address(true).unwrap();
    socket2.set_reuse_port(true).unwrap();
    socket2.bind(&socket_addr.into()).unwrap();
    socket2.set_nonblocking(true).unwrap();
    socket2.bind_device(Some(iface_name.as_bytes())).unwrap();
    socket2.set_broadcast(true).unwrap();

    let socket = UdpSocket::from_std(socket2.into()).unwrap();

    let send_socket = Arc::new(socket);
    let recive_socket_raw = send_socket.clone();

    let (message_tx, mut message_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                result = recive_socket_raw.recv_from(&mut buf) => {
                    // 接收数据包
                    match result {
                        Ok((len, addr)) => {
                            // tracing::debug!("Received {} bytes from {}", len, addr);
                            let message = buf[..len].to_vec();
                            if let Err(e) = message_tx.try_send((message, addr)) {
                                tracing::error!("Error sending message to channel: {:?}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error receiving data: {:?}", e);
                        }
                    }
                },
                _ = message_tx.closed() => {
                    break;
                }
            }
        }
    });

    service_status.just_change_status(ServiceStatus::Running);

    let mut dhcp_server_service_status = service_status.subscribe();
    let timeout_timer = tokio::time::sleep(tokio::time::Duration::from_secs(IP_EXPIRE_INTERVAL));
    tokio::pin!(timeout_timer);
    let mut dhcp_server = dhcp_server;

    loop {
        tokio::select! {
            // 处理消息分支
            message = message_rx.recv() => {
                match message {
                    Some(message) => {
                    let _need_update_data = handle_dhcp_message(
                        &mut dhcp_server,
                        &send_socket,
                        iface_ifindex,
                        iface_mac,
                        message,
                    ).await;
                    },
                    None => {
                        tracing::error!("dhcp server handle server fail, exit loop");
                        break;
                    }
                }
            }
            // 租期超时分支
            _ = &mut timeout_timer => {
                timeout_timer.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(IP_EXPIRE_INTERVAL));
            }
            // 处理外部关闭服务通知
            change_result = dhcp_server_service_status.changed() => {
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }

                if service_status.is_exit() {
                    break;
                }
            }
        }
    }

    tracing::info!("DHCPv4 Server Stop: {:#?}", service_status);

    if !service_status.is_stop() {
        service_status.just_change_status(if service_status.is_exit() {
            ServiceStatus::Stop
        } else {
            ServiceStatus::Failed
        });
    }
}

async fn handle_dhcp_message(
    dhcp_server: &mut DHCPv4Server,
    send_socket: &Arc<UdpSocket>,
    iface_ifindex: u32,
    iface_mac: Option<MacAddr>,
    (message, msg_addr): (Vec<u8>, SocketAddr),
) -> bool {
    let dhcp = DhcpEthFrame::new(&message);
    // tracing::info!("dhcp: {dhcp:?}");

    if let Some(dhcp) = dhcp {
        // tracing::info!("dhcp xid: {:04x}", dhcp.xid);
        match dhcp.op {
            1 => match dhcp.options.message_type {
                DhcpOptionMessageType::Discover => {
                    let Some(payload) = gen_offer(dhcp_server, dhcp) else { return false };
                    let payload = crate::dump::udp_packet::EthUdpType::Dhcp(Box::new(payload));

                    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 68);

                    // tracing::debug!("payload: {payload:?}");
                    match send_socket.send_to(&payload.convert_to_payload(), &addr).await {
                        Ok(_len) => {
                            // tracing::debug!("send len: {:?}", len);
                        }
                        Err(e) => {
                            tracing::error!("error: {:?}", e);
                        }
                    }
                    return true;
                }
                DhcpOptionMessageType::Request => {
                    let Some(payload) = gen_ack(dhcp_server, dhcp, iface_ifindex, iface_mac) else {
                        return false;
                    };

                    let addr = if payload.is_broaddcast() {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 68)
                    } else {
                        let ip = if payload.ciaddr.is_unspecified() {
                            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))
                        } else {
                            IpAddr::V4(payload.ciaddr.clone())
                        };
                        SocketAddr::new(ip, msg_addr.port())
                    };

                    let payload = crate::dump::udp_packet::EthUdpType::Dhcp(Box::new(payload));

                    // tracing::debug!("payload ack: {:?}", payload.convert_to_payload());
                    match send_socket.send_to(&payload.convert_to_payload(), &addr).await {
                        Ok(_len) => {
                            // tracing::debug!("send len: {:?}", len);
                        }
                        Err(e) => {
                            tracing::error!("error: {:?}", e);
                        }
                    }
                    return true;
                }
                DhcpOptionMessageType::Decline => {
                    let options = dhcp.options;
                    if let Some(DhcpOptions::RequestedIpAddress(ip)) = options.has_option(50) {
                        dhcp_server.add_decline_ip(ip);
                    }
                }
                // DhcpOptionMessageType::Ack => todo!(),
                // DhcpOptionMessageType::Nak => todo!(),
                DhcpOptionMessageType::Release => {
                    tracing::info!("req: Release, {dhcp:?}");
                }
                DhcpOptionMessageType::Inform => {
                    tracing::info!("req: Inform, {dhcp:?}");
                }
                // DhcpOptionMessageType::ForceRenew => todo!(),
                // DhcpOptionMessageType::LeaseQuery => todo!(),
                // DhcpOptionMessageType::LeaseUnassigned => todo!(),
                // DhcpOptionMessageType::LeaseUnknown => todo!(),
                // DhcpOptionMessageType::LeaseActive => todo!(),
                // DhcpOptionMessageType::BulkLeaseQuery => todo!(),
                // DhcpOptionMessageType::LeaseQueryDone => todo!(),
                // DhcpOptionMessageType::ActiveLeaseQuery => todo!(),
                // DhcpOptionMessageType::LeaseQueryStatus => todo!(),
                // DhcpOptionMessageType::Tls => todo!(),
                _ => {}
            },
            2 => {}
            3 => {}
            _ => {}
        }
    }
    false
}

#[derive(Debug, Clone, Default)]
pub struct DhcpV4DnrRuntimeContext {
    /// Certificate/SNI domains are shared with the TLS resolver and hot-reload
    /// into DHCP DNR responses without restarting the DHCP service.
    pub local_domains: Arc<ArcSwap<Vec<String>>>,
    /// DoH endpoint is a startup snapshot; changing port/path requires a
    /// process restart so DHCP advertisements match the active DoH listener.
    pub doh_port: u16,
    pub doh_path: String,
}

pub struct DHCPv4Server {
    pub server_ip: Ipv4Addr,
    pub options_map: HashMap<u8, DhcpOptions>,
    pub global_custom_options: Vec<(u8, Vec<u8>)>,
    pub global_dynamic_options: Vec<CustomDhcpOption>,
    pub dnr_context: Option<DhcpV4DnrRuntimeContext>,
    pub address_lease_time: u32,
    status: Arc<Mutex<DhcpV4AssignStatus>>,
}

impl DHCPv4Server {
    pub fn new(
        config: DHCPv4ServerConfig,
        dnr_context: Option<DhcpV4DnrRuntimeContext>,
        status: Arc<Mutex<DhcpV4AssignStatus>>,
    ) -> Self {
        let ipv4 = Ipv4Inet::new(config.server_ip_addr, config.network_mask).unwrap();
        let cidr = ipv4.network();
        let broadcast_u32 = u32::from(config.server_ip_addr) | !u32::from(cidr.mask());

        let options = vec![
            DhcpOptions::SubnetMask(cidr.mask()),
            DhcpOptions::Router(config.server_ip_addr),
            DhcpOptions::ServerIdentifier(config.server_ip_addr),
            DhcpOptions::DomainNameServer(vec![config.server_ip_addr]),
            DhcpOptions::BroadcastAddr(Ipv4Addr::from(broadcast_u32)),
        ];

        let mut options_map = HashMap::new();
        for each in options.iter() {
            options_map.insert(each.get_index(), each.clone());
        }

        let mut global_dynamic_options = Vec::new();
        let global_custom_options: Vec<(u8, Vec<u8>)> = config
            .custom_options
            .iter()
            .filter_map(|opt| {
                if matches!(opt, CustomDhcpOption::Dnr(_)) {
                    global_dynamic_options.push(opt.clone());
                    return None;
                }
                match encode_custom_option(opt, &config, dnr_context.as_ref()) {
                    Ok(Some(raw)) => Some(raw),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::error!(
                            "global custom option code {}: {} — option skipped",
                            opt.code(),
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        let address_lease_time =
            config.address_lease_time.unwrap_or(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME);

        DHCPv4Server {
            server_ip: config.server_ip_addr,
            options_map,
            global_custom_options,
            global_dynamic_options,
            dnr_context,
            address_lease_time,
            status,
        }
    }

    #[cfg(test)]
    fn init(config: DHCPv4ServerConfig) -> Self {
        let status = Arc::new(Mutex::new(DhcpV4AssignStatus::init_for_test(config.clone())));
        Self::new(config, None, status)
    }

    #[cfg(test)]
    fn init_with_enrolled(
        config: DHCPv4ServerConfig,
        dnr_context: Option<DhcpV4DnrRuntimeContext>,
        enrolled_devices: Vec<EnrolledDevice>,
    ) -> Self {
        let status = Arc::new(Mutex::new(DhcpV4AssignStatus::from_config_and_devices(
            &config,
            enrolled_devices,
        )));
        Self::new(config, dnr_context, status)
    }

    pub fn add_decline_ip(&self, ip: Ipv4Addr) {
        self.status.lock().unwrap().add_decline_ip(ip);
    }

    pub fn resolve_options_for_mac(&self, mac: &MacAddr) -> (Vec<(u8, Vec<u8>)>, HashSet<u8>) {
        let per_mac = { self.status.lock().unwrap().per_mac_options.get(mac).cloned() };

        let mut merged: HashMap<u8, Vec<u8>> =
            self.global_custom_options.iter().map(|(code, data)| (*code, data.clone())).collect();
        let mut filter_set = HashSet::new();

        Self::merge_custom_options(
            mac,
            "dhcp_config",
            &self.global_dynamic_options,
            self.server_ip,
            self.dnr_context.as_ref(),
            &mut merged,
        );

        if let Some(ref pm) = per_mac {
            Self::merge_custom_options(
                mac,
                "enrolled_device",
                &pm.custom_options,
                self.server_ip,
                self.dnr_context.as_ref(),
                &mut merged,
            );
            filter_set.extend(pm.filter_options.iter().copied());
        }

        let custom_options: Vec<(u8, Vec<u8>)> = merged.into_iter().collect();
        (custom_options, filter_set)
    }

    fn merge_custom_options(
        mac: &MacAddr,
        source: &str,
        custom_options: &[CustomDhcpOption],
        server_ip: Ipv4Addr,
        dnr_context: Option<&DhcpV4DnrRuntimeContext>,
        merged: &mut HashMap<u8, Vec<u8>>,
    ) {
        for opt in custom_options {
            match encode_custom_option_with_defaults(opt, server_ip, dnr_context) {
                Ok(Some((code, data))) => {
                    merged.insert(code, data);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(
                        "{source}[{:?}]: skipping custom option code {}: {}",
                        mac,
                        opt.code(),
                        e
                    );
                }
            }
        }
    }

    pub fn offer_ip(&self, mac_addr: &MacAddr, hostname: Option<String>) -> Option<Ipv4Addr> {
        self.status.lock().unwrap().offer_ip(mac_addr, hostname)
    }

    pub fn clean_expire_ip(&self) -> bool {
        self.status.lock().unwrap().clean_expire_ip()
    }

    pub fn ack_request(
        &self,
        mac_addr: &MacAddr,
        ip_addr: Ipv4Addr,
        hostname: Option<String>,
    ) -> bool {
        self.status.lock().unwrap().ack_request(
            mac_addr,
            ip_addr,
            hostname,
            self.address_lease_time,
        )
    }

    pub fn get_offered_info(&self) -> DHCPv4OfferInfo {
        self.status.lock().unwrap().get_offered_info()
    }
}

fn encode_custom_option(
    opt: &CustomDhcpOption,
    config: &DHCPv4ServerConfig,
    dnr_context: Option<&DhcpV4DnrRuntimeContext>,
) -> Result<Option<(u8, Vec<u8>)>, String> {
    encode_custom_option_with_defaults(opt, config.server_ip_addr, dnr_context)
}

fn encode_custom_option_with_defaults(
    opt: &CustomDhcpOption,
    server_ip: Ipv4Addr,
    dnr_context: Option<&DhcpV4DnrRuntimeContext>,
) -> Result<Option<(u8, Vec<u8>)>, String> {
    let CustomDhcpOption::Dnr(config) = opt else {
        return opt.to_raw().map(Some);
    };

    let Some(context) = dnr_context else {
        return Ok(None);
    };

    let (domains, ips, port, doh_path) = match config {
        DhcpV4DnrOptionConfig::Local => (
            context.local_domains.load().as_ref().clone(),
            vec![server_ip],
            context.doh_port,
            context.doh_path.clone(),
        ),
        DhcpV4DnrOptionConfig::Custom { domains, ips, port, doh_path } => {
            let domains = if domains.is_empty() {
                context.local_domains.load().as_ref().clone()
            } else {
                domains.clone()
            };
            let ips = if ips.is_empty() { vec![server_ip] } else { ips.clone() };
            let port = port.unwrap_or(context.doh_port);
            let doh_path = doh_path.clone().unwrap_or_else(|| context.doh_path.clone());
            (domains, ips, port, doh_path)
        }
    };

    let domains = normalize_advertise_domains(domains);
    if domains.is_empty() {
        return Ok(None);
    }
    let ips = ips.into_iter().filter(|ip| is_valid_dnr_ipv4_addr(*ip)).collect::<Vec<_>>();
    if ips.is_empty() {
        return Ok(None);
    }
    let payload =
        encode_dhcpv4_dnr_payload_truncated(&domains, &ips, port, &doh_path, u8::MAX as usize);
    if payload.is_empty() {
        return Ok(None);
    }
    Ok(Some((DHCPV4_DNR_OPTION_CODE, payload)))
}

/// get offer
pub fn gen_offer(server: &mut DHCPv4Server, frame: DhcpEthFrame) -> Option<DhcpEthFrame> {
    let mut options = vec![];
    let request_params = if let Some(request_params) = frame.options.has_option(55) {
        request_params
    } else {
        crate::dump::udp_packet::dhcp::get_default_request_list()
    };

    // Resolve custom options and filter set for this client
    let (custom_opts, filter_set) = server.resolve_options_for_mac(&frame.chaddr);

    if let DhcpOptions::ParameterRequestList(info_list) = request_params {
        for each_index in info_list {
            // Skip if this option code is filtered out for this client
            if filter_set.contains(&each_index) {
                continue;
            }
            if let Some(opt) = server.options_map.get(&each_index) {
                options.push(opt.clone());
            } else {
                tracing::warn!(
                    "Note: Ignoring unsupported option request {each_index:?} from DHCP client"
                );
            }
        }
    }

    let mut options = DhcpOptionFrame {
        message_type: DhcpOptionMessageType::Offer,
        options,
        custom_raw_options: vec![],
        end: vec![255],
    };

    options.update_or_create_option(DhcpOptions::AddressLeaseTime(server.address_lease_time));
    options.update_or_create_option(DhcpOptions::ServerIdentifier(server.server_ip));

    options.apply_custom_and_filter(custom_opts, &filter_set);

    let hostname = frame.options.get_hostname();
    if let Some(client_addr) = server.offer_ip(&frame.chaddr, hostname) {
        Some(DhcpEthFrame {
            op: 2,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: frame.xid,
            secs: frame.secs,
            flags: frame.flags,
            ciaddr: Ipv4Addr::new(0, 0, 0, 0),
            yiaddr: client_addr,
            siaddr: server.server_ip,
            giaddr: Ipv4Addr::new(0, 0, 0, 0),
            chaddr: frame.chaddr,
            sname: [0; 64].to_vec(),
            file: [0; 128].to_vec(),
            magic_cookie: frame.magic_cookie,
            options,
        })
    } else {
        tracing::error!("dhcp v4 server is full");
        None
    }
}

fn gen_ack(
    server: &mut DHCPv4Server,
    frame: DhcpEthFrame,
    iface_ifindex: u32,
    iface_mac: Option<MacAddr>,
) -> Option<DhcpEthFrame> {
    let mut options = vec![];
    let request_params = if let Some(request_params) = frame.options.has_option(55) {
        request_params
    } else {
        crate::dump::udp_packet::dhcp::get_default_request_list()
    };

    // Resolve custom options and filter set for this client
    let (custom_opts, filter_set) = server.resolve_options_for_mac(&frame.chaddr);

    if let DhcpOptions::ParameterRequestList(info_list) = request_params {
        for each_index in info_list {
            // Skip if this option code is filtered out for this client
            if filter_set.contains(&each_index) {
                continue;
            }
            if let Some(opt) = server.options_map.get(&each_index) {
                options.push(opt.clone());
            }
        }
    }

    let mut client_ip = None;
    if frame.ciaddr != Ipv4Addr::UNSPECIFIED {
        tracing::debug!("client ip in ciaddr");
        client_ip = Some(frame.ciaddr);
    }

    if let Some(DhcpOptions::RequestedIpAddress(ciaddr)) = frame.options.has_option(50) {
        tracing::debug!("client ip in option");
        client_ip = Some(ciaddr);
    }

    let Some(client_ip) = client_ip else {
        tracing::warn!("can not find client request ip");
        return None;
    };

    let (message_type, client_addr, ciaddr) =
        if server.ack_request(&frame.chaddr, client_ip, frame.options.get_hostname()) {
            (DhcpOptionMessageType::Ack, client_ip, frame.ciaddr)
        } else {
            (DhcpOptionMessageType::Nak, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        };

    let is_nak = matches!(message_type, DhcpOptionMessageType::Nak);

    let mut options = DhcpOptionFrame {
        message_type,
        options,
        custom_raw_options: vec![],
        end: vec![255],
    };

    options.update_or_create_option(DhcpOptions::AddressLeaseTime(server.address_lease_time));
    options.update_or_create_option(DhcpOptions::ServerIdentifier(server.server_ip));

    if !is_nak {
        options.apply_custom_and_filter(custom_opts, &filter_set);
    }

    let offer = DhcpEthFrame {
        op: 2,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: frame.xid,
        secs: frame.secs,
        flags: frame.flags,
        ciaddr,
        yiaddr: client_addr,
        siaddr: server.server_ip,
        giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: frame.chaddr,
        sname: [0; 64].to_vec(),
        file: [0; 128].to_vec(),
        magic_cookie: frame.magic_cookie,
        options,
    };

    if !is_nak {
        if let Some(dev_mac) = iface_mac {
            if let Err(e) = landscape_ebpf::base::ip_mac::upsert_ipv4_ip_mac(
                iface_ifindex,
                client_addr,
                frame.chaddr,
                dev_mac,
            ) {
                tracing::warn!(
                    "failed to prewarm ip_mac_v4 for DHCP lease {client_addr} -> {}: {e}",
                    frame.chaddr
                );
            }
        }
    }

    Some(offer)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use arc_swap::ArcSwap;
    use landscape_common::{
        dhcp::v4_server::config::{CustomDhcpOption, DHCPv4ServerConfig, DhcpV4DnrOptionConfig},
        dns::dnr::{encode_dns_name, DHCPV4_DNR_OPTION_CODE},
        enrolled_device::EnrolledDevice,
        net::MacAddr,
    };

    use crate::dhcp_server::dhcp_server_new::{DHCPv4Server, DhcpV4DnrRuntimeContext};

    fn option_payload(server: &DHCPv4Server, mac: &MacAddr, code: u8) -> Vec<u8> {
        server
            .resolve_options_for_mac(mac)
            .0
            .into_iter()
            .find_map(|(option_code, payload)| (option_code == code).then_some(payload))
            .unwrap()
    }

    fn contains_bytes(payload: &[u8], needle: &[u8]) -> bool {
        payload.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn resolve_options_returns_global_when_no_per_mac() {
        let mut config = DHCPv4ServerConfig::default();
        config.custom_options = vec![
            CustomDhcpOption::TFTPServerName("192.168.1.1".to_string()),
            CustomDhcpOption::BootfileName("ipxe.kpxe".to_string()),
        ];
        let server = DHCPv4Server::init(config);
        let mac = MacAddr::from_str("00:00:00:00:00:01").unwrap();

        let (opts, filter) = server.resolve_options_for_mac(&mac);
        assert_eq!(opts.len(), 2);
        assert!(filter.is_empty());

        let opts_map: std::collections::HashMap<u8, Vec<u8>> = opts.into_iter().collect();
        assert_eq!(opts_map.get(&66).unwrap(), b"192.168.1.1");
        assert_eq!(opts_map.get(&67).unwrap(), b"ipxe.kpxe");
    }

    #[test]
    fn resolve_options_hot_encodes_global_dnr_domains() {
        let mut config = DHCPv4ServerConfig::default();
        config.custom_options = vec![CustomDhcpOption::Dnr(DhcpV4DnrOptionConfig::Local)];
        let local_domains = Arc::new(ArcSwap::from_pointee(vec!["old.example.com".to_string()]));
        let dnr_context = DhcpV4DnrRuntimeContext {
            local_domains: local_domains.clone(),
            doh_port: 443,
            doh_path: "/dns-query".to_string(),
        };
        let server = DHCPv4Server::init_with_enrolled(config, Some(dnr_context), vec![]);
        let mac = MacAddr::from_str("00:00:00:00:00:01").unwrap();

        let old_payload = option_payload(&server, &mac, DHCPV4_DNR_OPTION_CODE);
        local_domains.store(Arc::new(vec!["new.example.com".to_string()]));
        let new_payload = option_payload(&server, &mac, DHCPV4_DNR_OPTION_CODE);

        let old_name = encode_dns_name("old.example.com").unwrap();
        let new_name = encode_dns_name("new.example.com").unwrap();
        assert!(contains_bytes(&old_payload, &old_name));
        assert!(!contains_bytes(&old_payload, &new_name));
        assert!(contains_bytes(&new_payload, &new_name));
        assert!(!contains_bytes(&new_payload, &old_name));
    }

    #[test]
    fn resolve_options_enrolled_overrides_global_by_code() {
        let mut config = DHCPv4ServerConfig::default();
        config.custom_options = vec![
            CustomDhcpOption::TFTPServerName("192.168.1.1".to_string()),
            CustomDhcpOption::BootfileName("ipxe.kpxe".to_string()),
        ];
        let mac = MacAddr::from_str("AA:BB:CC:DD:EE:FF").unwrap();
        let enrolled = EnrolledDevice {
            mac,
            name: "device".to_string(),
            ipv4: Some(Ipv4Addr::new(192, 168, 5, 50)),
            dhcp_custom_options: vec![CustomDhcpOption::BootfileName("undionly.kpxe".to_string())],
            ..serde_json::from_value(serde_json::json!({
                "mac": "AA:BB:CC:DD:EE:FF",
                "name": "device"
            }))
            .unwrap()
        };

        let server = DHCPv4Server::init_with_enrolled(config, None, vec![enrolled]);

        let (opts, _) = server.resolve_options_for_mac(&mac);
        let opts_map: std::collections::HashMap<u8, Vec<u8>> = opts.into_iter().collect();
        // 66 from global
        assert_eq!(opts_map.get(&66).unwrap(), b"192.168.1.1");
        // 67 overridden by enrolled device
        assert_eq!(opts_map.get(&67).unwrap(), b"undionly.kpxe");
    }

    #[test]
    fn resolve_options_filter_set_applied() {
        let mac = MacAddr::from_str("AA:BB:CC:DD:EE:FF").unwrap();
        let enrolled = EnrolledDevice {
            mac,
            name: "device".to_string(),
            ipv4: Some(Ipv4Addr::new(192, 168, 5, 50)),
            dhcp_filter_options: vec![15, 28],
            ..serde_json::from_value(serde_json::json!({
                "mac": "AA:BB:CC:DD:EE:FF",
                "name": "device"
            }))
            .unwrap()
        };

        let server =
            DHCPv4Server::init_with_enrolled(DHCPv4ServerConfig::default(), None, vec![enrolled]);

        let (_, filter) = server.resolve_options_for_mac(&mac);
        assert!(filter.contains(&15));
        assert!(filter.contains(&28));
        assert!(!filter.contains(&1)); // SubnetMask not filtered
    }

    #[test]
    fn resolve_options_enrolled_overrides_dhcp_config_common_options() {
        let mut config = DHCPv4ServerConfig::default();
        config.custom_options = vec![
            CustomDhcpOption::TFTPServerName("global-tftp".to_string()),
            CustomDhcpOption::BootfileName("config.kpxe".to_string()),
        ];
        let mac = MacAddr::from_str("AA:BB:CC:DD:EE:FF").unwrap();
        let enrolled = EnrolledDevice {
            mac,
            name: "device".to_string(),
            ipv4: Some(Ipv4Addr::new(192, 168, 5, 51)),
            dhcp_custom_options: vec![CustomDhcpOption::BootfileName("enrolled.kpxe".to_string())],
            dhcp_filter_options: vec![28],
            ..serde_json::from_value(serde_json::json!({
                "mac": "AA:BB:CC:DD:EE:FF",
                "name": "device"
            }))
            .unwrap()
        };

        let server = DHCPv4Server::init_with_enrolled(config, None, vec![enrolled]);

        let (opts, filter) = server.resolve_options_for_mac(&mac);
        let opts_map: std::collections::HashMap<u8, Vec<u8>> = opts.into_iter().collect();
        assert_eq!(opts_map.get(&66).unwrap(), b"global-tftp");
        assert_eq!(opts_map.get(&67).unwrap(), b"enrolled.kpxe");
        assert!(filter.contains(&28));
    }
}
