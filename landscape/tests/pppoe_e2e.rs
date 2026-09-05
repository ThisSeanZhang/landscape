//! End-to-end smoke tests for the native PPPoE client
//! (`landscape::wan_service::pppoe_client::run`).
//!
//! Each test builds a real two-namespace topology (client/server veth pair),
//! runs a scripted PPPoE server in the server namespace, and drives the real
//! client (eBPF raw socket, TC attach, netlink/system state) inside the client
//! namespace.
//!
//! Run as root with:
//!
//! ```text
//! cargo test -p landscape --test pppoe_e2e -- --include-ignored --nocapture
//! ```

#[path = "pppoe_e2e/mod.rs"]
mod pppoe_e2e;
