// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_TC_FRAG6_H
#define LAND_NAT_TC_FRAG6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "frag/frag.h"
#include "base/ipv6.h"

/*
 * First-fragment metadata cache (ADR 0022, amended by ADR 0025).
 *
 * A non-initial IPv6 fragment has no transport header, so it cannot read the
 * destination port used by the binding key. The first fragment records the final
 * protocol and ports; a later fragment uses the addresses and Fragment
 * identification to recover them. The cache is not reassembly state and holds
 * no payload, offsets, or translated addresses.
 */

#define NPTV6_FRAG_FLAG_HAS_PORTS 0x01U
#define NPTV6_FRAG_FLAG_ICMP 0x02U

struct nptv6_frag_key {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __be32 frag_id;
};

_Static_assert(sizeof(struct nptv6_frag_key) == 36, "nptv6_frag_key must be 36 bytes");

struct nptv6_frag_value {
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 frag_next_header;
    __u8 flags;
    __u8 pad[1];
};

_Static_assert(sizeof(struct nptv6_frag_value) == 8, "nptv6_frag_value must be 8 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nptv6_frag_key);
    __type(value, struct nptv6_frag_value);
} nptv6_frag_lan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nptv6_frag_key);
    __type(value, struct nptv6_frag_value);
} nptv6_frag_wan SEC(".maps");

static __always_inline void nptv6_frag_key_init(struct nptv6_frag_key *key,
                                                const struct in6_addr *src_addr,
                                                const struct in6_addr *dst_addr, __be32 frag_id) {
    key->src_addr = *src_addr;
    key->dst_addr = *dst_addr;
    key->frag_id = frag_id;
}

/* Store after the first fragment has created or found its binding. */
static __always_inline void nptv6_frag_cache_store(const struct in6_addr *src_addr,
                                                   const struct in6_addr *dst_addr, __be32 frag_id,
                                                   __u8 proto, __u8 frag_next_header,
                                                   __be16 src_port, __be16 dst_port, __u8 has_ports,
                                                   __u8 direction) {
    struct nptv6_frag_key key = {};
    nptv6_frag_key_init(&key, src_addr, dst_addr, frag_id);

    struct nptv6_frag_value value = {};
    value.src_port = src_port;
    value.dst_port = dst_port;
    value.proto = proto;
    value.frag_next_header = frag_next_header;
    if (has_ports) value.flags |= NPTV6_FRAG_FLAG_HAS_PORTS;
    if (proto == IPV6_NH_ICMPV6) value.flags |= NPTV6_FRAG_FLAG_ICMP;

    if (direction == LAND_NAT_FRAG_FROM_LAN)
        bpf_map_update_elem(&nptv6_frag_lan, &key, &value, BPF_ANY);
    else
        bpf_map_update_elem(&nptv6_frag_wan, &key, &value, BPF_ANY);
}

/*
 * Restore the first fragment's metadata. A cache entry whose Fragment header
 * type does not match the current non-initial fragment is rejected; this
 * narrows identification collisions without putting the protocol in the key.
 * For ICMPv6, src_port carries the Echo identifier.
 */
static __always_inline int nptv6_frag_cache_lookup(const struct in6_addr *src_addr,
                                                   const struct in6_addr *dst_addr, __be32 frag_id,
                                                   __u8 frag_next_header, __u8 direction,
                                                   struct nptv6_frag_value *out) {
    struct nptv6_frag_key key = {};
    nptv6_frag_key_init(&key, src_addr, dst_addr, frag_id);

    struct nptv6_frag_value *value = 0;
    if (direction == LAND_NAT_FRAG_FROM_LAN)
        value = bpf_map_lookup_elem(&nptv6_frag_lan, &key);
    else
        value = bpf_map_lookup_elem(&nptv6_frag_wan, &key);
    if (!value) return 0;

    if (value->frag_next_header != frag_next_header) return 0;

    *out = *value;
    return 1;
}

#endif /* LAND_NAT_TC_FRAG6_H */
