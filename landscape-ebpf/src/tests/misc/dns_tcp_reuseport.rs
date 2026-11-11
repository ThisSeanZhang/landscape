//! Root-only check that the plain DNS/TCP listener is picked by the reuseport
//! dispatcher from the shared sockmap (role `DnsListenerRole::Tcp`).
//!
//! Run (needs root + the `test-misc` feature):
//!   cargo test -p landscape-ebpf --features test-misc --lib dns_tcp_reuseport -- --ignored --nocapture

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use landscape_common::flow::{DnsListenerRole, MAX_FLOW_ID};

use crate::dns_dispatcher::attach_reuseport_ebpf;
use crate::maps::{self, LandscapeMapPath};
use crate::tests::isolated_pin_root;

/// Bind one TCP socket with SO_REUSEPORT enabled.
fn reuseport_tcp_socket(addr: &str) -> Socket {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("socket");
    socket.set_reuse_port(true).expect("set SO_REUSEPORT");
    socket.set_reuse_address(true).expect("set SO_REUSEADDR");
    socket.bind(&addr.parse::<SocketAddr>().unwrap().into()).expect("bind");
    socket.listen(128).expect("listen");
    socket
}

/// Bind two TCP listeners on the same port, register both under the TCP role
/// for different flows, attach the dispatcher, and verify a client connection
/// is accepted by one of them (i.e. the reuseport program selected a socket
/// from the sockmap instead of dropping the SYN).
#[test]
#[ignore = "needs root + BPF and the test-misc feature"]
fn dns_tcp_listener_is_dispatched_through_shared_sockmap() {
    let root = isolated_pin_root("dns-tcp-reuseport");
    let paths: LandscapeMapPath = LandscapeMapPath::from_root(&root);
    maps::init_path(&paths);

    // Both listeners must carry SO_REUSEPORT so they can share one port and
    // form one reuseport group, exactly like the per-flow production sockets.
    let sock_a = reuseport_tcp_socket("127.0.0.1:0");
    let addr: SocketAddr = sock_a.local_addr().expect("listener A addr").as_socket().unwrap();
    let sock_b = reuseport_tcp_socket(&addr.to_string());
    let listener_a: TcpListener = sock_a.into();
    let listener_b: TcpListener = sock_b.into();

    let fd_a = listener_a.as_raw_fd();
    let fd_b = listener_b.as_raw_fd();

    let flow_a = 1u32;
    let flow_b = MAX_FLOW_ID;
    assert!(flow_b <= MAX_FLOW_ID);

    // Role-packed keys keep DNS/TCP separate from UDP/DoH in one sockmap.
    maps::dns::setting_dns_sock_map(&paths, fd_a, flow_a, DnsListenerRole::Tcp)
        .expect("register listener A in dns_flow_socks");
    maps::dns::setting_dns_sock_map(&paths, fd_b, flow_b, DnsListenerRole::Tcp)
        .expect("register listener B in dns_flow_socks");

    attach_reuseport_ebpf(&paths, fd_a, DnsListenerRole::Tcp).expect("attach DNS/TCP dispatcher");

    // The dispatcher resolves flow ids from flow_match_map; with no entry the
    // default flow (0) is used, so register that mapping as well.
    maps::dns::setting_dns_sock_map(&paths, fd_a, 0, DnsListenerRole::Tcp)
        .expect("register default-flow listener");

    listener_a.set_nonblocking(true).expect("nonblocking A");
    listener_b.set_nonblocking(true).expect("nonblocking B");

    let client = TcpStream::connect(addr).expect("TCP connect to reuseport group");
    client.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut accepted = false;
    while std::time::Instant::now() < deadline {
        if listener_a.accept().is_ok() || listener_b.accept().is_ok() {
            accepted = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(accepted, "dispatcher must deliver the SYN to a registered DNS/TCP listener");
}
