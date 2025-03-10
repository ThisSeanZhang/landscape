use landscape_common::error::LdResult;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use tokio::net::UdpSocket;

use crate::iface::ip::addresses_by_iface_name;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;

static ICMPV6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2);

pub async fn icmp_ra_server(
    iface_name: String,
    service_status: DefaultWatchServiceStatus,
) -> LdResult<()> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    socket.bind_device(Some(iface_name.as_bytes()))?;

    let address = addresses_by_iface_name(iface_name.to_string()).await;
    let mut link_ipv6_addr = None;
    let mut link_ifindex = 0;
    for addr in address.iter() {
        match addr.address {
            std::net::IpAddr::V4(_) => continue,
            std::net::IpAddr::V6(ipv6_addr) => {
                if ipv6_addr.is_unicast_link_local() {
                    link_ipv6_addr = Some(ipv6_addr);
                    link_ifindex = addr.ifindex;
                }
            }
        }
    }

    let Some(ipaddr) = link_ipv6_addr else {
        println!("can not find unicast_link_local");
        return Ok(());
    };
    println!("address {:?}", ipaddr);
    println!("link_ifindex {:?}", link_ifindex);

    socket.join_multicast_v6(&ICMPV6_MULTICAST, link_ifindex).unwrap();

    // let async_socket = AsyncFd::new(socket)?;
    // tokio::spawn(async move {
    //     loop {
    //         // 等待套接字可读
    //         let mut read_guard = async_socket.readable().await?;
    //         let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
    //         // 尝试进行非阻塞读取
    //         match read_guard.try_io(|inner| {
    //             // 这里调用的是 socket2::Socket 的 recv 方法
    //             inner.get_ref().recv_from(&mut buf)
    //         }) {
    //             Ok(Ok((n, addr))) => {
    //                 println!("接收到 {:?} 字节", n);
    //                 let sock = addr.as_socket();
    //                 if let Some(sock) = sock {
    //                     match sock {
    //                         SocketAddr::V4(socket_addr_v4) => {}
    //                         SocketAddr::V6(socket_addr_v6) => {
    //                             println!("地址 {:?}", socket_addr_v6.ip());
    //                             println!("地址 {:?}", socket_addr_v6.scope_id());
    //                         }
    //                     }
    //                 }
    //                 // 此处可以对接收到的数据进行解析处理
    //                 let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
    //                 println!("接收到 {:?}", data);
    //             }
    //             Ok(Err(e)) => {
    //                 eprintln!("I/O 错误: {}", e);
    //             }
    //             Err(_would_block) => {
    //                 // 如果操作仍然会阻塞，继续等待
    //                 continue;
    //             }
    //         }
    //     }
    // });

    let udp_socket = UdpSocket::from_std(socket.into()).unwrap();
    // let send_socket = Arc::new(udp_socket);

    // let data = [133, 0, 199, 38, 0, 0, 0, 1];
    // let addr = SocketAddrV6::new(ICMPV6_MULTICAST, 0, 0, 0);
    // udp_socket.send_to(&data, addr).await.unwrap();
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = udp_socket.recv_from(&mut buf) => {
                // 接收数据包
                match result {
                    Ok((len, addr)) => {

                        // if let Err(e) = message_tx.try_send((message, addr)) {
                        //     tracing::error!("Error sending message to channel: {:?}", e);
                        // }
                            //             println!("接收到 {:?} 字节", n);
                        match addr {
                            SocketAddr::V4(socket_addr_v4) => {}
                            SocketAddr::V6(socket_addr_v6) => {
                                println!("地址 {:?}", socket_addr_v6.ip());
                                println!("地址 {:?}", socket_addr_v6.scope_id());
                            }
                        }
                        // 此处可以对接收到的数据进行解析处理
                        let message = buf[..len].to_vec();
                        println!("接收到 {:?}", message);
                    }
                    Err(e) => {
                        tracing::error!("Error receiving data: {:?}", e);
                    }
                }
            },
            // _ = message_tx.closed() => {
            //     tracing::error!("message_tx closed");
            //     break;
            // }
        }
    }

    Ok(())
}
