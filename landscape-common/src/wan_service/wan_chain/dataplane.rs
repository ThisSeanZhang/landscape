//! PPPoE egress template shared between the wan-link service and the
//! eBPF PPPoE encap stage.
//!
//! (The former `WanChainDataplane` trait is gone: the per-link
//! `landscape_ebpf::chain::wan_link::WanLinkDataplane` is the dataplane
//! contract now, embedded in the per-link service.)

/// PPPoE egress header template handed to the dataplane for the
/// TC-encap program.  Wire layout mirrors `struct pppoe_egress_tmpl` in
/// the eBPF skeleton (all multi-byte fields in network byte order).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PppoeEgressTmpl {
    pub dmac: [u8; 6],
    pub smac: [u8; 6],
    pub eth_proto: u16,
    pub ver_type: u8,
    pub code: u8,
    pub session_id: u16,
    pub length: u16,
    pub protocol: u16,
}
