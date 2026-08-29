use std::os::fd::AsRawFd;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use libbpf_rs::{MapCore, MapFlags};
use nix::net::if_::if_nametoindex;
use nix::sched::{setns, CloneFlags};

use crate::tests::test_id;

/// Ensure the BPF filesystem is mounted at `/sys/fs/bpf`.
///
/// BPF pinning (LIBBPF_PIN_BY_NAME) requires it; mount it once if missing.
pub(crate) fn ensure_bpffs() {
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mounted = mounts.lines().any(|l| l.split_whitespace().nth(1) == Some("/sys/fs/bpf"));
    if mounted {
        return;
    }
    let _ = std::fs::create_dir_all("/sys/fs/bpf");
    let out = Command::new("mount")
        .args(["-t", "bpf", "bpf", "/sys/fs/bpf"])
        .output()
        .expect("mount bpf fs");
    assert!(
        out.status.success(),
        "mount bpf fs on /sys/fs/bpf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A uniquely named network namespace (`lt{prefix}{pid}{n}`), removed on drop.
///
/// A fresh netns restarts the ifindex counter at 1, so veth interfaces get
/// small ifindexes (< PIPELINE_COUNT) and the test never pollutes the host
/// route table. `setns(2)` is per-thread: tests must stay single-threaded
/// while holding a namespace (no tokio task migration).
pub(crate) struct NetNsGuard {
    name: String,
}

/// Restores the caller's previous network namespace on drop.
pub(crate) struct NetNsEnter<'a> {
    _guard: &'a NetNsGuard,
    saved: std::fs::File,
}

impl<'a> Drop for NetNsEnter<'a> {
    fn drop(&mut self) {
        let _ = setns(&self.saved, CloneFlags::CLONE_NEWNET);
    }
}

impl NetNsGuard {
    pub(crate) fn create(prefix: &str) -> Self {
        let name = format!("lt{prefix}{}{}", std::process::id(), test_id());
        let _ = Command::new("ip").args(["netns", "del", &name]).output();
        let out = Command::new("ip").args(["netns", "add", &name]).output().expect("create netns");
        assert!(
            out.status.success(),
            "ip netns add {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self { name }
    }

    /// Enter this netns; the caller is restored to its previous netns on drop.
    ///
    /// NOTE: `/proc/thread-self/ns/net` is required — `/proc/self` refers to the
    /// main thread's namespace, and tests run on spawned threads.
    pub(crate) fn enter(&self) -> NetNsEnter<'_> {
        let saved = std::fs::File::open("/proc/thread-self/ns/net").expect("open current netns");
        let ns = std::fs::File::open(format!("/var/run/netns/{}", self.name)).expect("open netns");
        setns(&ns, CloneFlags::CLONE_NEWNET).expect("setns into netns");
        NetNsEnter { _guard: self, saved }
    }
}

impl Drop for NetNsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.name]).output();
    }
}

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
    /// Network namespace the host end was created in; used to delete the pair
    /// from the right place on drop.
    host_ns_fd: Option<std::fs::File>,
}

impl VethPair {
    /// Create a veth pair with both ends in the current namespace.
    pub(crate) fn create(prefix: &str) -> Self {
        Self::create_in_ns(prefix, None)
    }

    /// Create a veth pair whose peer end lives in `peer_ns` while the host end
    /// stays in the current namespace.
    pub(crate) fn create_with_netns(prefix: &str, peer_ns: &NetNsGuard) -> Self {
        Self::create_in_ns(prefix, Some(peer_ns))
    }

    fn create_in_ns(prefix: &str, peer_ns: Option<&NetNsGuard>) -> Self {
        let pid = test_id();
        let host = format!("{prefix}h{pid}");
        let peer = format!("{prefix}p{pid}");

        let _ = Command::new("ip").args(["link", "del", &host]).output();
        let mut args: Vec<&str> = vec!["link", "add", &host, "type", "veth", "peer", "name", &peer];
        if let Some(ns) = peer_ns {
            args.push("netns");
            args.push(&ns.name);
        }
        let out = Command::new("ip").args(&args).output().expect("create veth");
        assert!(out.status.success(), "create veth failed");
        Command::new("ip").args(["link", "set", &host, "up"]).output().expect("up host");
        if let Some(ns) = peer_ns {
            let _e = ns.enter();
            Command::new("ip").args(["link", "set", &peer, "up"]).output().expect("up peer");
        } else {
            Command::new("ip").args(["link", "set", &peer, "up"]).output().expect("up peer");
        }

        let host_ns_fd = std::fs::File::open("/proc/thread-self/ns/net").ok();
        Self { host, peer, host_ns_fd }
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
        if let Some(host_ns_fd) = &self.host_ns_fd {
            if let Ok(cur) = std::fs::File::open("/proc/thread-self/ns/net") {
                let _ = setns(host_ns_fd, CloneFlags::CLONE_NEWNET);
                let _ = Command::new("ip").args(["link", "del", &self.host]).output();
                let _ = setns(&cur, CloneFlags::CLONE_NEWNET);
                return;
            }
        }
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
