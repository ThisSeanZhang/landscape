//! Firewall blacklist maps (`firewall_block_ip4_map` / `firewall_block_ip6_map`).

mod init;
mod setting;
pub(crate) mod types;

pub use init::*;
pub use setting::*;
