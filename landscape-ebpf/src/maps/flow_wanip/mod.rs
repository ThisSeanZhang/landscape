//! Per-flow WAN-IP trie rules (`flow4_ip_map` / `flow6_ip_map` inner maps).

mod init;
mod setting;
pub(crate) mod types;

pub use init::*;
pub use setting::*;
