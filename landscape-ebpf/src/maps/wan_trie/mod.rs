//! WAN ingress IPv6 prefix-dispatch trie (`wan_trie`): a stride-8
//! (256-way) multibit trie over the first 64 bits of the destination
//! address, carried by an arena. Mirror of `src/bpf/map/wan_trie.h`.

pub(crate) mod builder;
pub(crate) mod dispatcher;
pub(crate) mod types;
