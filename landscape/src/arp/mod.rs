use std::{mem, net::Ipv4Addr};

use landscape_common::net::MacAddr;
use libc::{sockaddr_ll, ETH_P_ARP};
use socket2::{Domain, Protocol, Type};
use std::os::fd::AsRawFd;
use tokio::{io::unix::AsyncFd, sync::mpsc};

pub mod scan;

pub async fn create_arp_listen(
    ifindex: u32,
) -> std::io::Result<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)> {
    // 创建 AF_PACKET 原始 socket
    let socket =
        socket2::Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(ETH_P_ARP.to_be())))?;
    socket.set_nonblocking(true)?; // 必须设置为非阻塞

    // 填写 sockaddr_ll
    let saddr = sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (ETH_P_ARP as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 1,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00], // 广播 MAC
    };

    let saddr_ptr = &saddr as *const sockaddr_ll as *const libc::sockaddr;
    let bind_result =
        unsafe { libc::bind(socket.as_raw_fd(), saddr_ptr, mem::size_of::<sockaddr_ll>() as u32) };

    if bind_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let async_fd = AsyncFd::new(socket)?;

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];

        loop {
            tokio::select! {
                // 处理发送消息
                send_msg = out_rx.recv() => {
                    match send_msg {
                        Some(packet) => {
                            let send_result = unsafe {
                                libc::send(
                                    async_fd.as_raw_fd(),
                                    packet.as_ptr() as *const libc::c_void,
                                    packet.len(),
                                    0,
                                )
                            };

                            if send_result < 0 {
                                eprintln!("Failed to send ARP packet: {}", std::io::Error::last_os_error());
                            }
                        }
                        None => {
                            // 发送通道关闭，退出任务
                            break;
                        }
                    }
                }

                // 处理接收消息
                recv_ready = async_fd.readable() => {
                    match recv_ready {
                        Ok(mut guard) => {
                            let recv_result = unsafe {
                                libc::recv(
                                    async_fd.as_raw_fd(),
                                    buf.as_mut_ptr() as *mut libc::c_void,
                                    buf.len(),
                                    0,
                                )
                            };

                            match recv_result {
                                n if n > 0 => {
                                    let data = buf[..n as usize].to_vec();

                                    // 验证是否为有效的ARP包
                                    if is_valid_arp_packet(&data) && in_tx.send(data).await.is_err() {
                                        // 接收通道关闭，退出任务
                                        break;
                                    }
                                }
                                -1 => {
                                    let errno = unsafe { *libc::__errno_location() };
                                    if errno == libc::EAGAIN {
                                        guard.clear_ready();
                                        continue;
                                    } else {
                                        eprintln!("Failed to receive ARP packet: {}", std::io::Error::last_os_error());
                                        break;
                                    }
                                }
                                _ => {
                                    eprintln!("Unexpected recv result: {}", recv_result);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error waiting for readable: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok((out_tx, in_rx))
}

/// 验证是否为有效的ARP包
pub fn is_valid_arp_packet(data: &[u8]) -> bool {
    // 检查最小长度 (Ethernet头14字节 + ARP头28字节 = 42字节)
    if data.len() < 42 {
        return false;
    }

    // 检查以太网类型是否为ARP (0x0806)
    if data[12] != 0x08 || data[13] != 0x06 {
        return false;
    }

    // 检查ARP硬件类型是否为以太网 (0x0001)
    if data[14] != 0x00 || data[15] != 0x01 {
        return false;
    }

    // 检查ARP协议类型是否为IPv4 (0x0800)
    if data[16] != 0x08 || data[17] != 0x00 {
        return false;
    }

    // 检查硬件地址长度 (6) 和协议地址长度 (4)
    if data[18] != 6 || data[19] != 4 {
        return false;
    }

    // 检查操作码 (1=请求, 2=响应)
    let opcode = (data[20] as u16) << 8 | (data[21] as u16);
    if opcode != 1 && opcode != 2 {
        return false;
    }

    true
}

/// Constructs an ARP request ("Who has") packet asking for the MAC address of `target_ip`.
///
/// # Arguments
///
/// * `target_ip` - The IPv4 address we want to resolve.
/// * `sender_mac` - Our MAC address (source MAC).
/// * `sender_ip` - Our IPv4 address (source IP).
///
/// # Returns
///
/// A byte vector representing the ARP request Ethernet frame (42 bytes).
pub fn build_arp_request_packet(
    target_ip: Ipv4Addr,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);

    // Ethernet Header (14 bytes)
    packet.extend_from_slice(&[0xff; 6]); // Destination MAC: Broadcast
    packet.extend_from_slice(&sender_mac.octets()); // Source MAC
    packet.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP (0x0806)

    // ARP Header (28 bytes)
    packet.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    packet.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    packet.push(6); // Hardware address length
    packet.push(4); // Protocol address length
    packet.extend_from_slice(&[0x00, 0x01]); // Opcode: request (1)
    packet.extend_from_slice(&sender_mac.octets()); // Sender MAC address
    packet.extend_from_slice(&sender_ip.octets()); // Sender IP address
    packet.extend_from_slice(&[0x00; 6]); // Target MAC address: unknown
    packet.extend_from_slice(&target_ip.octets()); // Target IP address

    packet
}

/// Parses an ARP reply packet to extract the sender's MAC and IP address.
///
/// # Arguments
///
/// * `frame` - A raw Ethernet frame containing the ARP reply (expected to be at least 42 bytes).
///
/// # Returns
///
/// `Some((MacAddr, Ipv4Addr))` if the frame is a valid ARP reply, otherwise `None`.
pub fn parse_arp_reply(frame: &[u8]) -> Option<(MacAddr, Ipv4Addr)> {
    if frame.len() < 42 {
        return None;
    }

    // EtherType should be ARP (0x0806)
    if frame[12] != 0x08 || frame[13] != 0x06 {
        return None;
    }

    // Opcode should be reply (0x0002)
    if frame[20] != 0x00 || frame[21] != 0x02 {
        return None;
    }

    // Extract sender MAC (offset 22–27)
    let mac = MacAddr::new(frame[22], frame[23], frame[24], frame[25], frame[26], frame[27]);

    // Extract sender IP (offset 28–31)
    let ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);

    Some((mac, ip))
}

/// Builds a Gratuitous ARP (GARP) packet where sender and target IP are the same.
///
/// # Arguments
///
/// * `claimed_ip` - The IP address being claimed (same as both sender and target).
/// * `sender_mac` - The MAC address claiming ownership of the IP.
///
/// # Returns
///
/// A byte vector representing the GARP packet.
pub fn build_gratuitous_arp_packet(claimed_ip: Ipv4Addr, sender_mac: MacAddr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);

    // Ethernet Header
    packet.extend_from_slice(&[0xff; 6]); // Destination MAC: Broadcast
    packet.extend_from_slice(&sender_mac.octets()); // Source MAC
    packet.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP (0x0806)

    // ARP Header
    packet.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    packet.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    packet.push(6); // Hardware address length
    packet.push(4); // Protocol address length
    packet.extend_from_slice(&[0x00, 0x01]); // Opcode: request (1)

    packet.extend_from_slice(&sender_mac.octets()); // Sender MAC
    packet.extend_from_slice(&claimed_ip.octets()); // Sender IP
    packet.extend_from_slice(&[0x00; 6]); // Target MAC: unspecified (00:00:00:00:00:00)
    packet.extend_from_slice(&claimed_ip.octets()); // Target IP: same as sender

    packet
}

pub fn send_garp_response_try_to_make_client_release_ip(
    ipv4: Ipv4Addr,
    mac_addr: MacAddr,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);

    // Ethernet Header (14 bytes)
    packet.extend_from_slice(&[0xff; 6]); // 目标MAC: 广播地址
    packet.extend_from_slice(&mac_addr.octets()); // 源MAC
    packet.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP (0x0806)

    // ARP Header (28 bytes)
    packet.extend_from_slice(&[0x00, 0x01]); // 硬件类型: 以太网
    packet.extend_from_slice(&[0x08, 0x00]); // 协议类型: IPv4
    packet.push(6); // 硬件地址长度
    packet.push(4); // 协议地址长度
    packet.extend_from_slice(&[0x00, 0x02]); // 操作码: 响应 (GARP响应)
    packet.extend_from_slice(&mac_addr.octets()); // 发送者MAC地址
    packet.extend_from_slice(&ipv4.octets()); // 发送者IP地址
    packet.extend_from_slice(&mac_addr.octets()); // 目标MAC地址: 自己的MAC
    packet.extend_from_slice(&ipv4.octets()); // 目标IP地址: 与源IP相同

    packet
}
