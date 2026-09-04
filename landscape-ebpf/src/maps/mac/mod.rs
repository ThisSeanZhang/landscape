//! IP-MAC maps (`ip_mac_v4` / `ip_mac_v6`): mirror types + ARP/neigh sync
//! service (`neigh_update` kprobe + periodic netlink reconcile).

pub(crate) mod neigh_update {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/neigh_update.skel.rs"));
}

mod init;
mod setting;
pub(crate) mod types;

pub use init::*;
pub use setting::*;
