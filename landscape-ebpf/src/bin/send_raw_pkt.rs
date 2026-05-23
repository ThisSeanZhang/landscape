use std::os::fd::AsRawFd;
use std::process;

use nix::net::if_::if_nametoindex;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: send_raw_pkt <iface> <hex_pkt> [count]");
        process::exit(1);
    }

    let iface = &args[1];
    let pkt = match hex_decode(&args[2]) {
        Some(p) => p,
        None => {
            eprintln!("bad hex");
            process::exit(1);
        }
    };

    let count: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);

    let idx = if_nametoindex(iface.as_str()).expect("if_nametoindex");
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(0x0300)),
    )
    .expect("create raw socket");

    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: 0x0300u16.to_be(),
        sll_ifindex: idx as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };

    for _ in 0..count {
        unsafe {
            libc::sendto(
                sock.as_raw_fd(),
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
