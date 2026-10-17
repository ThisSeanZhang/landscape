//! Small standalone eBPF behaviour checks (`test-misc`): time, mark layout,
//! tproxy packet parsing, WAN trie probing and checksum verification.
mod mark_layout;
mod time;
mod tproxy;
mod wan_trie_probe;
mod xdp_csum_verify;
