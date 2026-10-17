//! `struct __sk_buff` mirror used to drive `BPF_PROG_TEST_RUN` inputs and
//! to decode scanner outputs that report skb metadata (ex `tests/mod.rs`).

use zerocopy::{FromBytes, IntoBytes};

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
