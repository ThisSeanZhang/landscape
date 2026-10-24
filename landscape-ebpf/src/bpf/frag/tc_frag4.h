// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_TC_FRAG4_H
#define LAND_NAT_TC_FRAG4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "frag/frag.h"

/*
 * First-fragment translation cache (ADR 0016). A non-initial IPv4 fragment has
 * no transport header, so it cannot perform the port lookup itself. The first
 * fragment records the pre-translation transport ports (or ICMP Query
 * identifier) selected by the normal NAT path; later fragments use the IPv4
 * source, destination, identification, protocol, and direction to recover that
 * metadata, replay the shared NAT mapping/CT lookup, and derive the
 * translated addresses.
 *
 * This is deliberately not a reassembly table: it holds no fragment payload,
 * offset map, or reassembly timer. It supports in-order fragments only. The
 * per-direction LRU maps are bounded; a cache miss is dropped.
 */
struct napt_frag_key {
    __be32 src_addr;
    __be32 dst_addr;
    __be16 ip_id;
    __u8 proto;
    __u8 pad[1];
};

/*
 * The ports are the pre-translation ports from the first fragment. For ICMP
 * Query, src_port holds the identifier and dst_port is zero. A later fragment
 * calls the shared NAT mapping/CT lookup with these ports and derives the
 * translated IP addresses; the cache therefore does not duplicate the
 * translation result.
 */
struct napt_frag_value {
    __be16 src_port;
    __be16 dst_port;
};

_Static_assert(sizeof(struct napt_frag_key) == 12, "napt_frag_key must be 12 bytes");
_Static_assert(sizeof(struct napt_frag_value) == 4, "napt_frag_value must be 4 bytes");

/*
 * One bounded cache per direction. The key contains RFC 791 identification,
 * addresses, and protocol; the value contains only the port metadata. The LRU
 * type bounds memory and keeps one direction's burst from evicting the other.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct napt_frag_key);
    __type(value, struct napt_frag_value);
} napt_frag_cache_lan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct napt_frag_key);
    __type(value, struct napt_frag_value);
} napt_frag_cache_wan SEC(".maps");

/* RFC 791 §3.1 identification, addresses, and protocol identify a datagram's
 * fragments without relying on the absent transport header. */
static __always_inline void napt_frag_key_init(struct napt_frag_key *key, __be32 src_addr,
                                               __be32 dst_addr, __be16 ip_id, __u8 proto) {
    key->src_addr = src_addr;
    key->dst_addr = dst_addr;
    key->ip_id = ip_id;
    key->proto = proto;
}

/*
 * Record the port metadata for a first fragment when MF is set. The caller has
 * parsed the L4 header and has not yet run the normal state stage or written
 * translated fields into the packet. The ports are the original
 * (pre-translation) values; later fragments use them to replay the same
 * NAT mapping/CT lookup.
 */
static __always_inline void napt_frag_cache_store(__be32 src_addr, __be32 dst_addr, __be16 ip_id,
                                                  __u8 proto, __be16 src_port, __be16 dst_port,
                                                  __u8 direction) {
    struct napt_frag_key key = {};
    napt_frag_key_init(&key, src_addr, dst_addr, ip_id, proto);

    struct napt_frag_value value = {};
    value.src_port = src_port;
    value.dst_port = dst_port;
    if (direction == LAND_NAT_FRAG_FROM_LAN)
        bpf_map_update_elem(&napt_frag_cache_lan, &key, &value, BPF_ANY);
    else
        bpf_map_update_elem(&napt_frag_cache_wan, &key, &value, BPF_ANY);
}

/* ADR 0016: a non-initial fragment takes its ports from its direction's cache. */
static __always_inline int napt_frag_cache_lookup(__be32 src_addr, __be32 dst_addr, __be16 ip_id,
                                                  __u8 proto, __u8 direction, __be16 *src_port,
                                                  __be16 *dst_port) {
    struct napt_frag_key key = {};
    napt_frag_key_init(&key, src_addr, dst_addr, ip_id, proto);

    struct napt_frag_value *value = 0;
    if (direction == LAND_NAT_FRAG_FROM_LAN)
        value = bpf_map_lookup_elem(&napt_frag_cache_lan, &key);
    else
        value = bpf_map_lookup_elem(&napt_frag_cache_wan, &key);
    if (!value) return 0;

    *src_port = value->src_port;
    *dst_port = value->dst_port;
    return 1;
}

#endif /* LAND_NAT_TC_FRAG4_H */
