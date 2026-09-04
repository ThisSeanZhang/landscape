use std::fmt::Debug;
use std::net::Ipv6Addr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use etherparse::PacketBuilder;

use zerocopy::FromBytes;
use zerocopy::IntoBytes;

static TEST_ID: AtomicU32 = AtomicU32::new(0);

pub(crate) fn test_id() -> u32 {
    TEST_ID.fetch_add(1, Ordering::Relaxed)
}

static TEST_PIN_ROOT_COUNTER: AtomicU32 = AtomicU32::new(0);

/// An isolated BPF pin root under `/sys/fs/bpf/landscape-test/`.
///
/// Maps declared with `LIBBPF_PIN_BY_NAME` are auto-pinned by libbpf on load,
/// so tests redirect them into a unique per-test directory. The directory is
/// removed on drop (after all skels referencing it have been dropped), so
/// pinned maps never outlive the test that created them.
pub(crate) struct PinRootGuard(PathBuf);

impl PinRootGuard {
    pub(crate) fn new(prefix: &str) -> Self {
        crate::tests::net_utils::ensure_bpffs();
        let unique = TEST_PIN_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/sys/fs/bpf/landscape-test/{prefix}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create isolated bpf pin root");
        Self(path)
    }
}

impl Deref for PinRootGuard {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for PinRootGuard {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for PinRootGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn isolated_pin_root(prefix: &str) -> PinRootGuard {
    PinRootGuard::new(prefix)
}

pub(crate) fn check_ifindex(name: &str, ifindex: u32) {
    const PIPELINE_COUNT: u32 = 1024;
    if ifindex >= PIPELINE_COUNT {
        eprintln!(
            "WARNING: {} ifindex {} >= PIPELINE_COUNT ({}) — pipe_root_progs or dispatching map lookups may fail",
            name, ifindex, PIPELINE_COUNT
        );
    }
}

#[allow(dead_code)]
pub(crate) fn checked_if_nametoindex(name: &str) -> u32 {
    let ifindex =
        nix::net::if_::if_nametoindex(name).unwrap_or_else(|_| panic!("if_nametoindex({name})"));
    check_ifindex(name, ifindex as u32);
    ifindex as u32
}

mod chain;
mod check;
mod metric;
mod mss;
mod nat;
mod net_utils;
mod route;
mod scanner;
mod tc_chain;
mod time;
mod tproxy;
mod wire;
mod xdp_csum_verify;

pub(crate) mod test_route_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route_packet.skel.rs"));
}

pub(crate) mod test_tproxy_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_tproxy_packet.skel.rs"));
}

pub(crate) mod test_xdp_root {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_root.skel.rs"));
}

pub(crate) mod test_xdp_chain_stage {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_chain_stage.skel.rs"));
}

pub(crate) mod test_xdp_dummy {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_dummy.skel.rs"));
}

pub(crate) mod xdp_mss_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_mss.skel.rs"));
}

pub(crate) mod xdp_wan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_route.skel.rs"));
}

pub(crate) mod xdp_lan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_intro.skel.rs"));
}

pub(crate) mod xdp_lan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_chain.skel.rs"));
}

pub(crate) mod xdp_wan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_chain.skel.rs"));
}

pub(crate) mod wan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_intro.skel.rs"));
}

pub(crate) mod test_xdp_scanner_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_scanner.skel.rs"));
}

pub(crate) mod test_skb_scanner_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_skb_scanner.skel.rs"));
}

pub(crate) mod test_skb_read_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_skb_read.skel.rs"));
}

pub(crate) mod xdp_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_firewall.skel.rs"));
}

pub(crate) mod xdp_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat.skel.rs"));
}

pub(crate) mod test_xdp_nat4_modify_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_nat4_modify.skel.rs"));
}

pub(crate) mod test_csum_verify_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_csum_verify.skel.rs"));
}

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, Debug, Clone, Copy, Default)]
pub struct TestSkb {
    pub len: u32,
    pub pkt_type: u32,
    pub mark: u32,
    pub queue_mapping: u32,
    pub protocol: u32,
    pub vlan_present: u32,
    pub vlan_tci: u32,
    pub vlan_proto: u32,
    pub priority: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub tc_index: u32,
    pub cb: [u32; 5],
    pub hash: u32,
    pub tc_classid: u32,
    pub data: u32,
    pub data_end: u32,
    pub napi_id: u32,
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub data_meta: u32,
    pub flow_keys: u64,
    pub tstamp: u64,
    pub wire_len: u32,
    pub gso_segs: u32,
    pub sk: u64,
    pub gso_size: u32,
    pub tstamp_type: u8,
    pub _padding: [u8; 3],
    pub hwtstamp: u64,
}

#[allow(dead_code)]
fn dummpy_ipv6_tcp_pkg() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], //source mac
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    ) //destination mac
    .ipv6(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).octets(), //source ip
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).octets(), //destination ip
        64,                                                           //time to life
    )
    .tcp(
        21, //source port
        1234, 12345, // sequence number
        4000,
    );

    let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

    let mut payload = Vec::<u8>::with_capacity(builder.size(tcp_payload.len()));
    builder.write(&mut payload, &tcp_payload).unwrap();

    payload
}
