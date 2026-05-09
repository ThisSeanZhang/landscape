use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
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
use landscape_common::dhcp::v4_server::status::{DHCPv4OfferInfo, DHCPv4OfferInfoItem};
use landscape_common::dns::dnr::{
    encode_dhcpv4_dnr_payload_truncated, is_valid_dnr_ipv4_addr, normalize_advertise_domains,
    DHCPV4_DNR_OPTION_CODE,
};
use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::net::MacAddr;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT, LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME,
};
use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::instrument;

const OFFER_VALID_TIME: u32 = 20;
const IP_EXPIRE_INTERVAL: u64 = 60 * 10;

#[instrument(skip(config, service_status, assigned_ips))]
pub async fn dhcp_v4_server(
    iface_name: String,
    iface_ifindex: u32,
    iface_mac: Option<MacAddr>,
    config: DHCPv4ServerConfig,
    dnr_context: Option<DhcpV4DnrRuntimeContext>,
    enrolled_devices: Vec<EnrolledDevice>,
    service_status: WatchService,
    assigned_ips: Arc<RwLock<DHCPv4OfferInfo>>,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let ip = config.server_ip_addr;

    let prefix_length = config.network_mask;
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
    let mut dhcp_server = DHCPv4Server::init_with_enrolled(config, dnr_context, enrolled_devices);

    // Publish the freshly initialized lease/static-binding view immediately so
    // UI state reflects the new DHCP instance instead of any stale pre-restart cache.
    update_assign_info(assigned_ips.clone(), dhcp_server.get_offered_info()).await;

    loop {
        tokio::select! {
            // 处理消息分支
            message = message_rx.recv() => {
                match message {
                    Some(message) => {
                        let need_update_data = handle_dhcp_message(
                            &mut dhcp_server,
                            &send_socket,
                            iface_ifindex,
                            iface_mac,
                            message,
                        ).await;
                        if need_update_data {
                            update_assign_info(assigned_ips.clone(), dhcp_server.get_offered_info()).await;
                        }
                    },
                    None => {
                        tracing::error!("dhcp server handle server fail, exit loop");
                        break;
                    }
                }
            }
            // 租期超时分支
            _ = &mut timeout_timer => {
                // dhcp_status.expire_check();
                timeout_timer.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_secs(IP_EXPIRE_INTERVAL));
                update_assign_info(assigned_ips.clone(), dhcp_server.get_offered_info()).await;
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

#[derive(Debug)]
struct DHCPv4ServerOfferedCache {
    hostname: Option<String>,
    ip: Ipv4Addr,
    relative_offer_time: u64,
    valid_time: u32,
    is_static: bool,
}

#[derive(Debug, Clone, Default)]
struct PerMacDhcpOptions {
    custom_options: Vec<CustomDhcpOption>,
    filter_options: Vec<u8>,
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

impl DHCPv4ServerOfferedCache {
    fn get_expire_time(&self) -> u64 {
        self.relative_offer_time + self.valid_time as u64
    }
}

#[derive(Debug)]
pub struct DHCPv4Server {
    /// DHCP 服务启动时间
    boot_time: f64,
    /// DHCP 服务启动 相对时间
    relative_boot_time: Instant,
    /// 服务器 IP
    server_ip: Ipv4Addr,
    /// 分配 IP 开始地址
    ip_range_start: Ipv4Inet,
    /// 总容量
    range_capacity: u32,
    /// 已分配的 IP 列表, True 表示是本次分配的
    allocated_host: HashMap<Ipv4Addr, bool>,
    /// 已分配的 IP
    offered_ip: HashMap<MacAddr, DHCPv4ServerOfferedCache>,
    /// Configured static binding IP for each MAC.
    static_binding_ip_by_mac: HashMap<MacAddr, Ipv4Addr>,
    /// Configured static binding owner for each IP.
    static_binding_mac_by_ip: HashMap<Ipv4Addr, MacAddr>,

    /// 持有的 OPTIONS
    options_map: HashMap<u8, DhcpOptions>,

    /// 全局自定义 DHCP option
    global_custom_options: Vec<(u8, Vec<u8>)>,
    /// 依赖运行时上下文的全局 option，需要在每次发包前重新编码。
    global_dynamic_options: Vec<CustomDhcpOption>,
    /// Enrolled device 中的 per-MAC option 设置，优先级高于公共 DHCP config
    enrolled_per_mac_options: HashMap<MacAddr, PerMacDhcpOptions>,
    dnr_context: Option<DhcpV4DnrRuntimeContext>,

    pub address_lease_time: u32,
}

impl DHCPv4Server {
    ///
    #[cfg(test)]
    fn init(config: DHCPv4ServerConfig) -> Self {
        Self::init_with_enrolled(config, None, vec![])
    }

    fn init_with_enrolled(
        config: DHCPv4ServerConfig,
        dnr_context: Option<DhcpV4DnrRuntimeContext>,
        enrolled_devices: Vec<EnrolledDevice>,
    ) -> Self {
        if config.ip_range_end == Some(Ipv4Addr::UNSPECIFIED) {
            tracing::warn!("ip_range_end is 0.0.0.0, treated as unset (using subnet last_address)");
        }

        let ip_range_start = Ipv4Inet::new(config.ip_range_start, config.network_mask).unwrap();
        let ip_addr_end = match config.ip_range_end {
            Some(addr) if addr != Ipv4Addr::UNSPECIFIED => addr,
            _ => ip_range_start.last_address(),
        };

        tracing::debug!("using {:?} -> {:?} to init range", config.ip_range_start, ip_addr_end);

        let range_capacity = u32::from(ip_addr_end) - u32::from(config.ip_range_start);

        let ipv4 = Ipv4Inet::new(config.server_ip_addr.clone(), config.network_mask).unwrap();

        let cidr = ipv4.network();
        // tracing::debug!("{:?}", ipv4.network());
        // tracing::debug!("{:?}", ipv4.first());
        // tracing::debug!("{:?}", ipv4.last());
        // tracing::debug!("{:?}", ipv4.is_host_address());
        // tracing::debug!("first: {:?}", ipv4.first().overflowing_add_u32(3).0.address());
        // tracing::debug!("size: {:?}", 1 << (32 - ipv4.network_length()));
        // tracing::debug!("mask: {:?}", ipv4.mask());
        // tracing::debug!("{:?}", cidr.network_length());
        // tracing::debug!("{:?}", cidr.first_address());
        // tracing::debug!("{:?}", cidr.is_host_address());
        // tracing::debug!("{:?}", cidr.last_address());

        let broadcast_u32 = u32::from(config.server_ip_addr) | !u32::from(cidr.mask());

        let mut options = vec![];
        options.push(DhcpOptions::SubnetMask(cidr.mask()));
        options.push(DhcpOptions::Router(config.server_ip_addr));
        options.push(DhcpOptions::ServerIdentifier(config.server_ip_addr));
        options.push(DhcpOptions::DomainNameServer(vec![config.server_ip_addr]));
        options.push(DhcpOptions::BroadcastAddr(Ipv4Addr::from(broadcast_u32)));
        // options_map.push(DhcpOptions::AddressLeaseTime(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME));

        tracing::debug!("dhcp v4 server options: {:#?}", options);
        // TODO
        let mut options_map = HashMap::new();
        for each in options.iter() {
            options_map.insert(each.get_index(), each.clone());
        }

        let mut allocated_host = HashMap::new();
        let mut offered_ip = HashMap::new();
        let mut static_binding_ip_by_mac = HashMap::new();
        let mut static_binding_mac_by_ip = HashMap::new();

        let mut enrolled_per_mac_options = HashMap::new();
        for device in enrolled_devices {
            if let Some(ipv4) = device.ipv4 {
                if let Some(old_ip) = static_binding_ip_by_mac.insert(device.mac, ipv4) {
                    allocated_host.remove(&old_ip);
                    static_binding_mac_by_ip.remove(&old_ip);
                }
                if let Some(old_mac) = static_binding_mac_by_ip.insert(ipv4, device.mac) {
                    if old_mac != device.mac {
                        static_binding_ip_by_mac.remove(&old_mac);
                        offered_ip.remove(&old_mac);
                    }
                }

                allocated_host.insert(ipv4, true);
                offered_ip.insert(
                    device.mac,
                    DHCPv4ServerOfferedCache {
                        hostname: None,
                        ip: ipv4,
                        relative_offer_time: 0,
                        valid_time: 86400,
                        is_static: true,
                    },
                );
            }

            if !device.dhcp_custom_options.is_empty() || !device.dhcp_filter_options.is_empty() {
                enrolled_per_mac_options.insert(
                    device.mac,
                    PerMacDhcpOptions {
                        custom_options: device.dhcp_custom_options,
                        filter_options: device.dhcp_filter_options,
                    },
                );
            }
        }

        // Parse global custom options. DNR depends on live certificate domains,
        // so keep it as config and encode it when building each response.
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
            boot_time: get_f64_timestamp(),
            relative_boot_time: Instant::now(),
            server_ip: config.server_ip_addr,
            ip_range_start,
            range_capacity,
            allocated_host,
            offered_ip,
            static_binding_ip_by_mac,
            static_binding_mac_by_ip,
            options_map,
            global_custom_options,
            global_dynamic_options,
            enrolled_per_mac_options,
            dnr_context,
            address_lease_time,
        }
    }

    fn add_decline_ip(&mut self, ip: Ipv4Addr) {
        if !self.allocated_host.contains_key(&ip) {
            self.allocated_host.insert(ip, false);
        }
    }

    /// Resolve the final set of custom options for a specific MAC address.
    /// Returns (custom_options, filter_set).
    ///
    /// - Starts with global_custom_options as baseline
    /// - Dynamically encodes global options that depend on runtime context (DNR)
    /// - Enrolled device per-MAC custom_options override global by code
    /// - Filter options are applied after all custom option sources are merged
    pub fn resolve_options_for_mac(&self, mac: &MacAddr) -> (Vec<(u8, Vec<u8>)>, HashSet<u8>) {
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

        if let Some(per_mac) = self.enrolled_per_mac_options.get(mac) {
            Self::merge_custom_options(
                mac,
                "enrolled_device",
                &per_mac.custom_options,
                self.server_ip,
                self.dnr_context.as_ref(),
                &mut merged,
            );
            filter_set.extend(per_mac.filter_options.iter().copied());
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

    #[cfg(test)]
    fn offer_ip_without_hostname(&mut self, mac_addr: &MacAddr) -> Option<Ipv4Addr> {
        self.offer_ip(mac_addr, None)
    }

    ///
    fn offer_ip(&mut self, mac_addr: &MacAddr, hostname: Option<String>) -> Option<Ipv4Addr> {
        if let Some(DHCPv4ServerOfferedCache { ip, .. }) = self.offered_ip.get(mac_addr) {
            tracing::info!(
                "allocated exist ip: {:?} for mac: {:?}, hostname: {hostname:?}",
                ip,
                mac_addr
            );
            return Some(ip.clone());
        }

        let mut seed = mac_addr.u32_ckecksum();
        // tracing::debug!("using seed: {seed:?}");
        loop {
            if self.allocated_host.len() as u32 == self.range_capacity {
                if !self.clean_expire_ip() {
                    tracing::error!("DHCP Server is full");
                    break;
                }
            }
            let index = seed % self.range_capacity;
            let (client_addr, _overflow) = self.ip_range_start.overflowing_add_u32(index);
            let address = client_addr.address();
            if self.allocated_host.contains_key(&address) {
                seed += 1;
            } else {
                tracing::info!(
                    "allocated new ip: {:?} for mac: {:?}, hostname: {hostname:?}",
                    address,
                    mac_addr
                );

                self.offered_ip.insert(
                    mac_addr.clone(),
                    DHCPv4ServerOfferedCache {
                        hostname,
                        ip: address,
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: OFFER_VALID_TIME,
                        is_static: false,
                    },
                );
                self.allocated_host.insert(address, true);
                return Some(address);
            }
        }
        None
    }

    /// 清理过期的 IP
    /// true 表示有清理
    /// false 表示无法清理
    pub fn clean_expire_ip(&mut self) -> bool {
        let current_time = self.relative_boot_time.elapsed().as_secs();

        let mut remove_keys = vec![];
        self.offered_ip.retain(|_key, value| {
            // 静态设置的不清理
            if value.is_static {
                true
            } else {
                if current_time > value.get_expire_time() {
                    remove_keys.push(value.ip.clone());
                    false
                } else {
                    true
                }
            }
        });

        self.allocated_host.retain(|_key, is_allocated_this_round| *is_allocated_this_round);

        for key in remove_keys.iter() {
            self.allocated_host.remove(key);
        }

        tracing::info!("DHCPv4 server cleans up these IPs: {remove_keys:?}");
        !remove_keys.is_empty()
    }

    fn is_ip_in_range(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let start = u32::from(self.ip_range_start.address());
        let end = start + self.range_capacity;
        ip_u32 >= start && ip_u32 < end
    }

    fn conflicts_with_static_binding(&self, mac_addr: &MacAddr, ip_addr: Ipv4Addr) -> bool {
        if let Some(static_ip) = self.static_binding_ip_by_mac.get(mac_addr) {
            if *static_ip != ip_addr {
                tracing::warn!(
                    "client {:?} requested {:?}, but static binding requires {:?}",
                    mac_addr,
                    ip_addr,
                    static_ip
                );
                return true;
            }
        }

        if let Some(static_mac) = self.static_binding_mac_by_ip.get(&ip_addr) {
            if static_mac != mac_addr {
                tracing::warn!(
                    "client {:?} requested static IP {:?} owned by {:?}",
                    mac_addr,
                    ip_addr,
                    static_mac
                );
                return true;
            }
        }

        false
    }

    #[cfg(test)]
    fn ack_request_without_hostname(&mut self, mac_addr: &MacAddr, ip_addr: Ipv4Addr) -> bool {
        self.ack_request(mac_addr, ip_addr, None)
    }

    /// 检查是否存在过, 存在过直接刷新时间
    pub fn ack_request(
        &mut self,
        mac_addr: &MacAddr,
        ip_addr: Ipv4Addr,
        hostname: Option<String>,
    ) -> bool {
        if self.conflicts_with_static_binding(mac_addr, ip_addr) {
            return false;
        }

        if let Some(offered_cache) = self.offered_ip.get_mut(mac_addr) {
            if offered_cache.ip == ip_addr {
                offered_cache.hostname = hostname;
                if !offered_cache.is_static {
                    // 非静态刷新掉 offer 时间
                    offered_cache.valid_time = self.address_lease_time;
                }
                // 静态和非静态都刷新相对分配时间
                offered_cache.relative_offer_time = self.relative_boot_time.elapsed().as_secs();
                return true;
            } else {
                tracing::error!(
                    "client: {mac_addr:?} request ip: {ip_addr:?}, not same as offer: {:?}",
                    offered_cache.ip
                )
            }
        } else {
            if self.allocated_host.contains_key(&ip_addr) {
                tracing::error!(
                    "Requested IP {ip_addr:?} is already allocated to another client, request by {mac_addr:?}"
                );
                return false;
            }

            if !self.is_ip_in_range(ip_addr) {
                tracing::warn!("Requested IP out of range");
                return false;
            }

            let lease_cache = DHCPv4ServerOfferedCache {
                hostname,
                ip: ip_addr,
                is_static: false,
                valid_time: self.address_lease_time,
                relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
            };

            self.offered_ip.insert(*mac_addr, lease_cache);
            self.allocated_host.insert(ip_addr, true);

            tracing::info!("Assigned unoffered IP {ip_addr:?} to client {mac_addr:?}");

            return true;
        }
        false
    }

    pub fn get_offered_info(&self) -> DHCPv4OfferInfo {
        let mut offered_ips = Vec::with_capacity(self.offered_ip.len());
        let relative_boot_time = self.relative_boot_time.elapsed().as_secs();
        for (
            mac,
            DHCPv4ServerOfferedCache {
                ip,
                relative_offer_time,
                valid_time,
                is_static,
                hostname,
            },
        ) in self.offered_ip.iter()
        {
            offered_ips.push(DHCPv4OfferInfoItem {
                hostname: hostname.clone(),
                mac: mac.clone(),
                ip: ip.clone(),
                relative_active_time: *relative_offer_time,
                expire_time: *valid_time,
                is_static: *is_static,
            });
        }
        DHCPv4OfferInfo {
            boot_time: self.boot_time,
            relative_boot_time,
            offered_ips,
        }
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

async fn update_assign_info(assigned_ips: Arc<RwLock<DHCPv4OfferInfo>>, info: DHCPv4OfferInfo) {
    match tokio::time::timeout(tokio::time::Duration::from_secs(5), assigned_ips.write()).await {
        Ok(mut write_lock) => {
            *write_lock = info;
        }
        Err(_) => {
            eprintln!("Failed to acquire write lock within timeout");
        }
    }
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
    use std::{net::Ipv4Addr, sync::Arc, thread::sleep, time::Duration};

    use arc_swap::ArcSwap;
    use cidr::Ipv4Inet;
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

    #[tokio::test]
    pub async fn test_ip_alloc() {
        landscape_common::init_tracing!();

        let config = DHCPv4ServerConfig::default();
        let mut dhcp_server = DHCPv4Server::init(config);
        tracing::debug!("dhcp_server: {:#?}", dhcp_server);
        let ip = Ipv4Addr::new(192, 168, 5, 226);
        let mac1 = MacAddr::from_str("00:00:00:00:00:01").unwrap();

        let result = dhcp_server.ack_request_without_hostname(&mac1, ip);
        tracing::debug!("result: {:?}", result);

        let result = dhcp_server.offer_ip_without_hostname(&mac1);
        tracing::debug!("result: {:?}", result);

        let result = dhcp_server.ack_request_without_hostname(&mac1, ip);
        tracing::debug!("result: {:?}", result);
    }

    #[test]
    pub fn test_ip_alloc_same_seed_large_then_2_lap() {
        landscape_common::init_tracing!();

        let ipv4 = Ipv4Inet::new(Ipv4Addr::new(192, 168, 1, 1), 30).unwrap();

        let mut config = DHCPv4ServerConfig::default();
        config.ip_range_start = ipv4.overflowing_add(1).0.address();
        config.network_mask = 30;
        let mut dhcp_server = DHCPv4Server::init(config);
        tracing::debug!("dhcp_server: {:#?}", dhcp_server);
        let mac1 = MacAddr::from_str("00:00:00:00:00:01").unwrap();
        let result = dhcp_server.offer_ip_without_hostname(&mac1);
        tracing::debug!("result: {:?}", result);

        let mac1 = MacAddr::from_str("00:00:00:00:00:02").unwrap();
        let result = dhcp_server.offer_ip_without_hostname(&mac1);
        tracing::debug!("result: {:?}", result);

        sleep(Duration::from_secs(25));
        let mac1 = MacAddr::from_str("00:00:00:00:00:03").unwrap();
        let result = dhcp_server.offer_ip_without_hostname(&mac1);
        tracing::debug!("result: {:?}", result);

        let mac1 = MacAddr::from_str("00:00:00:00:00:04").unwrap();
        let result = dhcp_server.offer_ip_without_hostname(&mac1);
        tracing::debug!("result: {:?}", result);
    }

    #[test]
    fn static_binding_rejects_old_ip_for_same_mac() {
        let config = DHCPv4ServerConfig::default();
        let mac = MacAddr::from_str("00:00:00:00:00:01").unwrap();
        let static_ip = Ipv4Addr::new(192, 168, 5, 10);
        let old_ip = Ipv4Addr::new(192, 168, 5, 20);

        let enrolled = EnrolledDevice {
            mac,
            name: "test".to_string(),
            ipv4: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({
                "mac": "00:00:00:00:00:01",
                "name": "test"
            }))
            .unwrap()
        };

        let mut dhcp_server = DHCPv4Server::init_with_enrolled(config, None, vec![enrolled]);

        assert!(!dhcp_server.ack_request_without_hostname(&mac, old_ip));
        assert!(dhcp_server.ack_request_without_hostname(&mac, static_ip));
    }

    #[test]
    fn static_binding_rejects_other_mac_requesting_reserved_ip() {
        let config = DHCPv4ServerConfig::default();
        let owner = MacAddr::from_str("00:00:00:00:00:01").unwrap();
        let other = MacAddr::from_str("00:00:00:00:00:02").unwrap();
        let static_ip = Ipv4Addr::new(192, 168, 5, 10);

        let enrolled = EnrolledDevice {
            mac: owner,
            name: "owner".to_string(),
            ipv4: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({
                "mac": "00:00:00:00:00:01",
                "name": "owner"
            }))
            .unwrap()
        };

        let mut dhcp_server = DHCPv4Server::init_with_enrolled(config, None, vec![enrolled]);

        assert!(!dhcp_server.ack_request_without_hostname(&other, static_ip));
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
        assert_eq!(
            server.static_binding_ip_by_mac.get(&mac).copied(),
            Some(Ipv4Addr::new(192, 168, 5, 51))
        );
    }
}
