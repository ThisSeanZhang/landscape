use std::os::fd::AsRawFd;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use libbpf_rs::{MapCore, MapFlags};
use nix::net::if_::if_nametoindex;

use crate::tests::test_id;

/// Poll `check` every 10ms until it returns `true` or `deadline` elapses.
///
/// Replaces fixed `thread::sleep` waits in tests that must wait for
/// kernel-side packet processing (BPF map updates happen asynchronously).
pub(crate) fn wait_for<F: FnMut() -> bool>(what: &str, deadline: Duration, mut check: F) {
    let start = Instant::now();
    loop {
        if check() {
            return;
        }
        if start.elapsed() >= deadline {
            panic!("timed out after {deadline:?} waiting for {what}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Allow in-flight packets to drain before asserting a negative outcome
/// (e.g. "no packet reached the dummy program").
pub(crate) fn settle(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

/// Send a raw ethernet frame on `iface` via an AF_PACKET socket.
pub(crate) fn send_raw_packet(iface: &str, pkt: &[u8]) {
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(0x0300)),
    )
    .expect("create raw socket");
    let idx = if_nametoindex(iface).expect("if_nametoindex");
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: 0x0300u16.to_be(),
        sll_ifindex: idx as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
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
}

/// A uniquely named veth pair (`{prefix}h{pid}` / `{prefix}p{pid}`) that is
/// removed on drop, so tests neither collide nor leak interfaces on panic.
pub(crate) struct VethPair {
    host: String,
    peer: String,
}

impl VethPair {
    pub(crate) fn create(prefix: &str) -> Self {
        let pid = test_id();
        let host = format!("{prefix}h{pid}");
        let peer = format!("{prefix}p{pid}");

        let _ = Command::new("ip").args(["link", "del", &host]).output();
        let out = Command::new("ip")
            .args(["link", "add", &host, "type", "veth", "peer", "name", &peer])
            .output()
            .expect("create veth");
        assert!(out.status.success(), "create veth failed");
        Command::new("ip").args(["link", "set", &host, "up"]).output().expect("up host");
        Command::new("ip").args(["link", "set", &peer, "up"]).output().expect("up peer");

        Self { host, peer }
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn peer(&self) -> &str {
        &self.peer
    }

    pub(crate) fn host_ifindex(&self) -> u32 {
        if_nametoindex(self.host.as_str()).expect("host ifindex") as u32
    }

    pub(crate) fn peer_ifindex(&self) -> u32 {
        if_nametoindex(self.peer.as_str()).expect("peer ifindex") as u32
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", &self.host]).output();
    }
}

/// Number of packets the dummy XDP program recorded (`0` = v4, `1` = v6).
pub(crate) fn dummy_recv_count(map: &libbpf_rs::MapMut, is_v6: bool) -> u64 {
    let k = if is_v6 { 1u32 } else { 0u32 }.to_ne_bytes();
    map.lookup(&k, MapFlags::ANY)
        .unwrap()
        .map_or(0, |v| u64::from_ne_bytes(v[0..8].try_into().unwrap()))
}

/// Zero the dummy receive counters for v4 and v6.
pub(crate) fn dummy_reset(map: &libbpf_rs::MapMut) {
    let v = [0u8; 8];
    map.update(&0u32.to_ne_bytes(), &v, MapFlags::ANY).unwrap();
    map.update(&1u32.to_ne_bytes(), &v, MapFlags::ANY).unwrap();
}
