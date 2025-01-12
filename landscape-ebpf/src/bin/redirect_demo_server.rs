use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd as _;
use std::str::FromStr;

use nix::sys::socket::bind;
use nix::sys::socket::listen;
use nix::sys::socket::setsockopt;
use nix::sys::socket::socket;
use nix::sys::socket::sockopt::IpTransparent;
use nix::sys::socket::sockopt::ReuseAddr;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::Backlog;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::SockaddrIn;

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
    let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None).unwrap();

    // Set some sockopts
    setsockopt(&fd, ReuseAddr, &true).unwrap();
    // unmark this the service will not work in linux 6.1.y
    // look at https://elixir.bootlin.com/linux/v6.1.121/source/net/core/filter.c#L73782
    // setsockopt(&fd, ReusePort, &true).unwrap();
    // 6.6.y or higher is ok
    setsockopt(&fd, IpTransparent, &true).unwrap();

    // Bind to addr
    let addr = format!("{}:{}", "0.0.0.0", 12345);
    let addr = SockaddrIn::from_str(&addr).unwrap();
    bind(fd.as_raw_fd(), &addr).unwrap();

    // Start listening
    listen(&fd, Backlog::new(128).unwrap()).unwrap();
    let listener = TcpListener::from(fd);

    println!("start");
    for client in listener.incoming() {
        let client = client.unwrap();
        handle_client(client);
    }
}
