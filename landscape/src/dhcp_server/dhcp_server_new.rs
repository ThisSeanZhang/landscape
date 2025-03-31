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

use cidr::Ipv4Inet;
use futures::TryStreamExt;
use landscape_common::dhcp::{DHCPv4OfferInfo, DHCPv4OfferInfoItem, DHCPv4ServerConfig};
use landscape_common::net::MacAddr;
use landscape_common::service::dhcp::DHCPv4ServiceWatchStatus;
use landscape_common::service::ServiceStatus;
use landscape_common::LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME;
use netlink_packet_route::address::AddressAttribute;
use rtnetlink::{new_connection, Handle};
use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;
use tracing::instrument;

const OFFER_VALID_TIME: u32 = 20;
const IP_EXPIRE_INTERVAL: u64 = 60 * 10;

async fn add_address(link_name: &str, ip: IpAddr, prefix_length: u8, handle: Handle) {
    let mut links = handle.link().get().match_name(link_name.to_string()).execute();
    if let Some(link) = links.try_next().await.unwrap() {
        let mut addr_iter = handle.address().get().execute();
        // 与要添加的 ip 是否相同
        let mut need_create_ip = true;
        while let Some(addr) = addr_iter.try_next().await.unwrap() {
            let perfix_len_equal = addr.header.prefix_len == prefix_length;
            let mut link_name_equal = false;
            let mut ip_equal = false;

            for attr in addr.attributes.iter() {
                match attr {
                    AddressAttribute::Address(addr) => {
                        if *addr == ip {
                            ip_equal = true;
                        }
                    }
                    AddressAttribute::Label(label) => {
                        if *label == link_name.to_string() {
                            link_name_equal = true;
                        }
                    }
                    _ => {}
                }
            }

            if link_name_equal {
                if ip_equal && perfix_len_equal {
                    need_create_ip = false;
                } else {
                    tracing::info!("del: {addr:?}");
                    handle.address().del(addr).execute().await.unwrap();
                    need_create_ip = true;
                }
            }
        }

        if need_create_ip {
            // tracing::info!("need create ip: {need_create_ip:?}");
            handle.address().add(link.header.index, ip, prefix_length).execute().await.unwrap()
        }
    }
}

#[instrument(skip(config, service_status))]
pub async fn dhcp_v4_server(
    iface_name: String,
    config: DHCPv4ServerConfig,
    service_status: DHCPv4ServiceWatchStatus,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let ip = config.server_ip_addr;

    let prefix_length = config.network_mask;
    let link_name = iface_name.clone();
    tokio::spawn(async move {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        add_address(&link_name, IpAddr::V4(ip), prefix_length, handle).await
    });

    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 67);

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
    let mut dhcp_server = DHCPv4Server::init(config);

    loop {
        tokio::select! {
            // 处理消息分支
            message = message_rx.recv() => {
                match message {
                    Some(message) => {
                        let need_update_data = handle_dhcp_message(&mut dhcp_server, &send_socket, message).await;
                        if need_update_data {
                            service_status.just_change_data(dhcp_server.get_offered_info());
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
                service_status.just_change_data(dhcp_server.get_offered_info());
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
        service_status.just_change_status(ServiceStatus::Stop);
    }
}

async fn handle_dhcp_message(
    dhcp_server: &mut DHCPv4Server,
    send_socket: &Arc<UdpSocket>,
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
                    let Some(payload) = gen_ack(dhcp_server, dhcp) else {
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
                DhcpOptionMessageType::Decline => todo!(),
                DhcpOptionMessageType::Ack => todo!(),
                DhcpOptionMessageType::Nak => todo!(),
                DhcpOptionMessageType::Release => {
                    tracing::info!("{dhcp:?}");
                }
                DhcpOptionMessageType::Inform => todo!(),
                DhcpOptionMessageType::ForceRenew => todo!(),
                DhcpOptionMessageType::LeaseQuery => todo!(),
                DhcpOptionMessageType::LeaseUnassigned => todo!(),
                DhcpOptionMessageType::LeaseUnknown => todo!(),
                DhcpOptionMessageType::LeaseActive => todo!(),
                DhcpOptionMessageType::BulkLeaseQuery => todo!(),
                DhcpOptionMessageType::LeaseQueryDone => todo!(),
                DhcpOptionMessageType::ActiveLeaseQuery => todo!(),
                DhcpOptionMessageType::LeaseQueryStatus => todo!(),
                DhcpOptionMessageType::Tls => todo!(),
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
    ip: Ipv4Addr,
    relative_offer_time: u64,
    valid_time: u32,
    is_static: bool,
}

impl DHCPv4ServerOfferedCache {
    fn get_expire_time(&self) -> u64 {
        self.relative_offer_time + self.valid_time as u64
    }
}

#[derive(Debug)]
pub struct DHCPv4Server {
    /// DHCP 服务启动时间
    relative_boot_time: Instant,
    /// 服务器 IP
    server_ip: Ipv4Addr,
    /// 分配 IP 开始地址
    ip_range_start: Ipv4Inet,
    /// 总容量
    range_capacity: u32,
    /// 已分配的 IP 列表
    allocated_host: HashSet<Ipv4Addr>,
    /// 已分配的 IP
    offered_ip: HashMap<MacAddr, DHCPv4ServerOfferedCache>,

    /// 持有的 OPTIONS
    options_map: HashMap<u8, DhcpOptions>,

    pub address_lease_time: u32,
}

impl DHCPv4Server {
    ///
    fn init(config: DHCPv4ServerConfig) -> Self {
        let ip_range_start = Ipv4Inet::new(config.ip_range_start, config.network_mask).unwrap();
        let ip_addr_end = config.ip_range_end.unwrap_or_else(|| ip_range_start.last_address());

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

        let mut options = vec![];
        options.push(DhcpOptions::SubnetMask(cidr.mask()));
        options.push(DhcpOptions::Router(config.server_ip_addr));
        options.push(DhcpOptions::ServerIdentifier(config.server_ip_addr));
        options.push(DhcpOptions::DomainNameServer(vec![config.server_ip_addr]));
        // options_map.push(DhcpOptions::AddressLeaseTime(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME));

        // TODO
        let mut options_map = HashMap::new();
        for each in options.iter() {
            options_map.insert(each.get_index(), each.clone());
        }

        let mut allocated_host = HashSet::new();
        let mut offered_ip = HashMap::new();
        for each in config.mac_binding_records {
            allocated_host.insert(each.ip);
            offered_ip.insert(
                each.mac,
                DHCPv4ServerOfferedCache {
                    ip: each.ip,
                    relative_offer_time: 0,
                    valid_time: each.expire_time,
                    is_static: true,
                },
            );
        }

        let address_lease_time =
            config.address_lease_time.unwrap_or(LANDSCAPE_DHCP_DEFAULT_ADDRESS_LEASE_TIME);

        DHCPv4Server {
            relative_boot_time: Instant::now(),
            server_ip: config.server_ip_addr,
            ip_range_start,
            range_capacity,
            allocated_host,
            offered_ip,
            options_map,
            address_lease_time,
        }
    }

    ///
    fn offer_ip(&mut self, mac_addr: &MacAddr) -> Option<Ipv4Addr> {
        if let Some(DHCPv4ServerOfferedCache { ip, .. }) = self.offered_ip.get(mac_addr) {
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
            if self.allocated_host.contains(&address) {
                seed += 1;
            } else {
                self.offered_ip.insert(
                    mac_addr.clone(),
                    DHCPv4ServerOfferedCache {
                        ip: address,
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: OFFER_VALID_TIME,
                        is_static: false,
                    },
                );
                self.allocated_host.insert(address);
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

        for key in remove_keys.iter() {
            self.allocated_host.remove(&key);
        }
        tracing::info!("DHCPv4 server cleans up these IPs: {remove_keys:?}");
        !remove_keys.is_empty()
    }

    /// 检查是否存在过, 存在过直接刷新时间
    pub fn ack_request(&mut self, mac_addr: &MacAddr, ip_addr: Ipv4Addr) -> bool {
        if let Some(offered_cache) = self.offered_ip.get_mut(mac_addr) {
            if offered_cache.ip == ip_addr {
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
            tracing::error!("can not find this request offer record client: {mac_addr:?} request ip: {ip_addr:?}")
        }

        // TODO: 检查此 IP 是否未被 offered, 没有被 offered 那就可以被分配
        false
    }

    pub fn get_offered_info(&self) -> DHCPv4OfferInfo {
        let mut offered_ips = Vec::with_capacity(self.offered_ip.len());
        let relative_boot_time = self.relative_boot_time.elapsed().as_secs();
        for (mac, DHCPv4ServerOfferedCache { ip, relative_offer_time, valid_time, .. }) in
            self.offered_ip.iter()
        {
            offered_ips.push(DHCPv4OfferInfoItem {
                mac: mac.clone(),
                ip: ip.clone(),
                relative_active_time: *relative_offer_time,
                expire_time: *valid_time,
            });
        }
        DHCPv4OfferInfo { relative_boot_time, offered_ips }
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

    if let DhcpOptions::ParameterRequestList(info_list) = request_params {
        for each_index in info_list {
            if let Some(opt) = server.options_map.get(&each_index) {
                options.push(opt.clone());
            } else {
                tracing::warn!("在配置中找不到这个 option 配置, index: {each_index:?}");
            }
        }
    }

    let mut options = DhcpOptionFrame {
        message_type: DhcpOptionMessageType::Offer,
        options,
        end: vec![255],
    };

    options.update_or_create_option(DhcpOptions::ServerIdentifier(server.server_ip));

    if let Some(client_addr) = server.offer_ip(&frame.chaddr) {
        tracing::info!("allocated ip: {:?} for mac: {:?}", client_addr, frame.chaddr);
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
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
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

fn gen_ack(server: &mut DHCPv4Server, frame: DhcpEthFrame) -> Option<DhcpEthFrame> {
    let mut options = vec![];
    let request_params = if let Some(request_params) = frame.options.has_option(55) {
        request_params
    } else {
        crate::dump::udp_packet::dhcp::get_default_request_list()
    };
    if let DhcpOptions::ParameterRequestList(info_list) = request_params {
        for each_index in info_list {
            if let Some(opt) = server.options_map.get(&each_index) {
                options.push(opt.clone());
            }
        }
    }

    let Some(DhcpOptions::RequestedIpAddress(client_ip)) = frame.options.has_option(50) else {
        tracing::warn!("can not find client request ip");
        return None;
    };

    let (message_type, client_addr) = if server.ack_request(&frame.chaddr, client_ip) {
        (DhcpOptionMessageType::Ack, client_ip)
    } else {
        (DhcpOptionMessageType::Nak, Ipv4Addr::UNSPECIFIED)
    };

    let mut options = DhcpOptionFrame { message_type, options, end: vec![255] };

    options.update_or_create_option(DhcpOptions::AddressLeaseTime(server.address_lease_time));
    options.update_or_create_option(DhcpOptions::ServerIdentifier(server.server_ip));

    let offer = DhcpEthFrame {
        op: 2,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: frame.xid,
        secs: frame.secs,
        flags: frame.flags,
        ciaddr: Ipv4Addr::new(0, 0, 0, 0),
        yiaddr: client_addr,
        siaddr: Ipv4Addr::new(0, 0, 0, 0),
        giaddr: Ipv4Addr::new(0, 0, 0, 0),
        chaddr: frame.chaddr,
        sname: [0; 64].to_vec(),
        file: [0; 128].to_vec(),
        magic_cookie: frame.magic_cookie,
        options,
    };
    Some(offer)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, thread::sleep, time::Duration};

    use cidr::Ipv4Inet;
    use landscape_common::{dhcp::DHCPv4ServerConfig, net::MacAddr};

    use crate::dhcp_server::dhcp_server_new::DHCPv4Server;

    #[tokio::test]
    pub async fn test_ip_alloc() {
        crate::init_tracing!();
        let config = DHCPv4ServerConfig::default();
        let mut dhcp_server = DHCPv4Server::init(config);
        tracing::debug!("dhcp_server: {:#?}", dhcp_server);
        let ip = Ipv4Addr::new(192, 168, 5, 226);
        let mac1 = MacAddr::from_str("00:00:00:00:00:01").unwrap();

        let result = dhcp_server.ack_request(&mac1, ip);
        tracing::debug!("result: {:?}", result);

        let result = dhcp_server.offer_ip(&mac1);
        tracing::debug!("result: {:?}", result);

        let result = dhcp_server.ack_request(&mac1, ip);
        tracing::debug!("result: {:?}", result);
    }

    #[test]
    pub fn test_ip_alloc_same_seed_large_then_2_lap() {
        crate::init_tracing!();

        let ipv4 = Ipv4Inet::new(Ipv4Addr::new(192, 168, 1, 1), 30).unwrap();

        let mut config = DHCPv4ServerConfig::default();
        config.ip_range_start = ipv4.overflowing_add(1).0.address();
        config.network_mask = 30;
        let mut dhcp_server = DHCPv4Server::init(config);
        tracing::debug!("dhcp_server: {:#?}", dhcp_server);
        let mac1 = MacAddr::from_str("00:00:00:00:00:01").unwrap();
        let result = dhcp_server.offer_ip(&mac1);
        tracing::debug!("result: {:?}", result);

        let mac1 = MacAddr::from_str("00:00:00:00:00:02").unwrap();
        let result = dhcp_server.offer_ip(&mac1);
        tracing::debug!("result: {:?}", result);

        sleep(Duration::from_secs(25));
        let mac1 = MacAddr::from_str("00:00:00:00:00:03").unwrap();
        let result = dhcp_server.offer_ip(&mac1);
        tracing::debug!("result: {:?}", result);

        let mac1 = MacAddr::from_str("00:00:00:00:00:04").unwrap();
        let result = dhcp_server.offer_ip(&mac1);
        tracing::debug!("result: {:?}", result);
    }
}
