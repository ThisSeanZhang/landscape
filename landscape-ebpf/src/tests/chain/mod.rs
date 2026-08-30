//! XDP pipeline / chain integration tests.
//!
//! These tests attach the full chain (intro → root → mss → firewall → exit)
//! to veth pairs and verify end-to-end packet flow. They require root and
//! run inside freshly created network namespaces (see `net_utils`), so each
//! test gets small ifindexes and a clean route table.
mod chain_levels;
mod lan_intro;
mod mss;
mod pipeline;
mod wan_route;
