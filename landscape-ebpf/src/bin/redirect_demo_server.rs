use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd as _;

use nix::sys::socket::AddressFamily;
use nix::sys::socket::Backlog;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::SockaddrLike;
use nix::sys::socket::bind;
use nix::sys::socket::listen;
use nix::sys::socket::setsockopt;
use nix::sys::socket::socket;
use nix::sys::socket::sockopt::IpTransparent;
use nix::sys::socket::sockopt::ReuseAddr;

fn handle_client(client: TcpStream) {
    let local_addr = client.local_addr().unwrap();
    let peer_addr = client.peer_addr().unwrap();

    println!("New connection:");
    println!("\tlocal: {local_addr}");
    println!("\tpeer: {peer_addr}");
    println!();
}

fn main() {
    // Create listener socket
    let fd = socket(AddressFamily::Inet6, SockType::Stream, SockFlag::empty(), None).unwrap();

    // Set some sockopts
    setsockopt(&fd, ReuseAddr, &true).unwrap();
    // unmark this the service will not work in linux 6.1.y
    // look at https://elixir.bootlin.com/linux/v6.1.121/source/net/core/filter.c#L73782
    // setsockopt(&fd, ReusePort, &true).unwrap();
    // 6.6.y or higher is ok
    setsockopt(&fd, IpTransparent, &true).unwrap();

    // Bind to SocketAddr
    let addr: Box<dyn SockaddrLike> = Box::new(nix::sys::socket::SockaddrIn6::from(
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 12345, 0, 0),
    ));
    bind(fd.as_raw_fd(), addr.as_ref()).unwrap();

    // Start listening
    listen(&fd, Backlog::new(128).unwrap()).unwrap();
    println!("start fd: {:?}", fd);
    let listener = TcpListener::from(fd);

    for client in listener.incoming() {
        let client = client.unwrap();
        handle_client(client);
    }
}
