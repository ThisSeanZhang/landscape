//! Small standalone eBPF behaviour checks (`test-misc`): time, mark layout,
//! tproxy packet parsing, WAN trie probing, checksum verification and the
//! DNS/TCP reuseport dispatch.
mod dns_tcp_reuseport;
mod mark_layout;
mod time;
mod tproxy;
mod wan_trie_probe;
mod xdp_csum_verify;
