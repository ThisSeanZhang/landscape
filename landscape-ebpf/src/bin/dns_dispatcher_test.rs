use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

// cargo run --package landscape-ebpf --bin dns_dispatcher_test
#[tokio::main]
pub async fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let is_test_udp = true;

    if is_test_udp {
        test_udp().await;
    } else {
        test_tcp().await;
    }
}
pub async fn test_tcp() {
    let (listener1, sock_fd1) = create_tcp_listener("0.0.0.0:55").await.unwrap();
    let (listener2, sock_fd2) = create_tcp_listener("0.0.0.0:55").await.unwrap();

    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd1, 0);
    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd2, 10);

    // attach eBPF
    landscape_ebpf::dns_dispatcher::attach_reuseport_ebpf(sock_fd1).unwrap();

    println!("Listening on TCP port 55 with sk_reuseport eBPF");

    let (listener3, sock_fd3) = create_tcp_listener("0.0.0.0:55").await.unwrap();
    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd3, 20);

    tokio::select! {
        _ = tokio::signal::ctrl_c()=> {},
        _ = tcp_listener(listener1, sock_fd1) => {},
        _ = tcp_listener(listener2, sock_fd2) => {},
        _ = tcp_listener(listener3, sock_fd3) => {},
    }
}

pub async fn test_udp() {
    let (udp_socket1, sock_fd1) = create_udp_socket("0.0.0.0:55").await.unwrap();
    let (udp_socket2, sock_fd2) = create_udp_socket("0.0.0.0:55").await.unwrap();

    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd1, 0);
    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd2, 10);

    // attach eBPF
    landscape_ebpf::dns_dispatcher::attach_reuseport_ebpf(sock_fd1).unwrap();

    println!("Listening on UDP port 55 with sk_reuseport eBPF");

    let (udp_socket3, sock_fd3) = create_udp_socket("0.0.0.0:55").await.unwrap();

    landscape_ebpf::map_setting::dns::setting_dns_sock_map(sock_fd3, 20);

    tokio::select! {
        _ = tokio::signal::ctrl_c()=> {},
        _ = udp_listener(udp_socket1, sock_fd1) => {}
        _ = udp_listener(udp_socket2, sock_fd2) => {}
        _ = udp_listener(udp_socket3, sock_fd3) => {}
    }
}

pub async fn create_udp_socket(addr: &str) -> std::io::Result<(UdpSocket, i32)> {
    let address: SocketAddr = addr.parse().unwrap();

    // 1. 创建 socket2 Socket
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;

    let fd = socket.as_raw_fd();

    // 2. 转成 Tokio UdpSocket
    let udp_socket = UdpSocket::from_std(socket.into())?;
    Ok((udp_socket, fd))
}

pub async fn create_tcp_listener(addr: &str) -> std::io::Result<(tokio::net::TcpListener, i32)> {
    let address: SocketAddr = addr.parse().unwrap();

    // 1. 创建 socket2 Socket
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;

    let fd = socket.as_raw_fd();

    // 2. 转成 Tokio TcpListener
    let tcp_listener = tokio::net::TcpListener::from_std(socket.into())?;
    Ok((tcp_listener, fd))
}

async fn tcp_listener(listener: tokio::net::TcpListener, id: i32) -> std::io::Result<()> {
    loop {
        let (mut stream, addr) = listener.accept().await?;
        println!("[{id}] New TCP connection from {:?}", addr);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => {
                        println!("[{id}] Connection closed by {:?}", addr);
                        return;
                    }
                    Ok(len) => {
                        println!("[{id}] Received {} bytes from {:?}", len, addr);
                        if let Err(e) = stream.write_all(&buf[..len]).await {
                            eprintln!("[{id}] Write error: {:?}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        eprintln!("[{id}] Read error: {:?}", e);
                        return;
                    }
                }
            }
        });
    }
}

async fn udp_listener(udp_socket: UdpSocket, id: i32) -> std::io::Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let (len, addr) = udp_socket.recv_from(&mut buf).await?;
        println!("[{id}] Received {} bytes from {:?}", len, addr);

        let _ = udp_socket.send_to(&buf[..len], &addr).await?;
    }
}
