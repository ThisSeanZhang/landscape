use landscape::iface::ip::addresses_by_iface_name;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;

// ping6 -I ens5 ff02::1
// cargo run --package landscape --bin icmp_sock_test
// rdisc6 ens6
#[tokio::main]
async fn main() -> io::Result<()> {
    let iface_name = "ens5";
    let multicast_addr = "ff02::2".parse::<Ipv6Addr>().unwrap();
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_loop_v6(false)?;
    socket.bind_device(Some(iface_name.as_bytes()))?;

    // 绑定到ICMPv6多播地址
    // let addr = SocketAddrV6::new(
    //     multicast_addr, // 链路本地路由器多播地址
    //     0,
    //     0,
    //     0,
    // );
    // socket.bind(&socket2::SockAddr::from(addr))?;

    // 绑定到未指定地址 - 接收该接口上的所有 ICMPv6 流量
    // let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    // socket.bind(&socket2::SockAddr::from(addr))?;
    // println!("绑定到地址: {:?}", addr);

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

    socket.join_multicast_v6(&multicast_addr, link_ifindex).unwrap();

    let udp_socket = UdpSocket::from_std(socket.into()).unwrap();
    // let send_socket = Arc::new(udp_socket);

    let data = [133, 0, 199, 38, 0, 0, 0, 1];
    let addr = SocketAddrV6::new(multicast_addr, 0, 0, 0);
    udp_socket.send_to(&data, addr).await.unwrap();
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
}
