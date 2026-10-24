/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TC_NAT4_MAP_H
#define LAND_NAT_TC_NAT4_MAP_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"

#ifndef ENOENT
#define ENOENT 2
#endif

#define NAPT_FROM_WAN_PORT_COUNT 65536U
#define NAPT_FROM_WAN_UDP_BASE 0U
#define NAPT_FROM_WAN_TCP_BASE NAPT_FROM_WAN_PORT_COUNT
#define NAPT_FROM_WAN_ICMP_BASE (2U * NAPT_FROM_WAN_PORT_COUNT)
#define NAPT_FROM_WAN_ENTRIES (3U * NAPT_FROM_WAN_PORT_COUNT)

enum napt_mapping_kind {
    NAPT_MAPPING_FREE = 0,
    NAPT_MAPPING_DYNAMIC = 1,
    NAPT_MAPPING_STATIC = 2,
};

enum napt_gress {
    NAPT_GRESS_WAN = 0,
    NAPT_GRESS_LAN = 1,
};

#define NAPT_WAN_STATE_SHIFT 56
#define NAPT_WAN_REF_MASK ((1ULL << NAPT_WAN_STATE_SHIFT) - 1)
#define NAPT_WAN_STATE_ACTIVE 1ULL
#define NAPT_WAN_STATE_CLOSED 2ULL

struct napt_port_slot {
    __be16 port;
    __u16 pad;
    __u32 generation;
};

struct napt_from_lan_key {
    __be32 internal_addr;
    __be16 internal_port;
    __u8 proto;
    __u8 pad;
};

struct napt_from_lan_value {
    __be16 external_port;
    __u8 kind;
    __u8 allow_reuse;
    __u32 generation;
    __be32 trigger_addr;
    __be16 trigger_port;
    __u16 pad;
};

struct napt_from_wan_value {
    __be32 internal_addr;
    __be16 internal_port;
    __u8 kind;
    __u8 allow_reuse;
    __be32 trigger_addr;
    __be16 trigger_port;
    __u16 pad0;
    __u32 generation;
    __u32 pad1;
    __u64 state_ref;
};

struct napt_ct_key {
    __be32 internal_addr;
    __be32 remote_addr;
    __be16 internal_port;
    __be16 remote_port;
    __u8 proto;
    __u8 pad[3];
};

struct napt_ct_value {
    __be16 external_port;
    __u8 is_static;
    __u8 pad0;
    __u32 from_wan_gen;
    __u64 status;
    __u64 client_status;
    __u64 server_status;
    struct bpf_timer timer;
    __u64 create_time;
    __u64 ingress_bytes;
    __u64 ingress_packets;
    __u64 egress_bytes;
    __u64 egress_packets;
    __u32 cpu_id;
    __u32 ifindex;
    __u8 gress;
    __u8 flow_id;
    __u16 pad1;
};

_Static_assert(sizeof(struct napt_port_slot) == 8, "napt_port_slot must be 8 bytes");
_Static_assert(sizeof(struct napt_from_lan_key) == 8, "napt_from_lan_key must be 8 bytes");
_Static_assert(sizeof(struct napt_from_lan_value) == 16, "napt_from_lan_value must be 16 bytes");
_Static_assert(sizeof(struct napt_from_wan_value) == 32, "napt_from_wan_value must be 32 bytes");
_Static_assert(sizeof(struct napt_ct_key) == 16, "napt_ct_key must be 16 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 65536);
    __type(value, struct napt_port_slot);
} napt_udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 65536);
    __type(value, struct napt_port_slot);
} napt_tcp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 65536);
    __type(value, struct napt_port_slot);
} napt_icmp_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 196608);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct napt_from_lan_key);
    __type(value, struct napt_from_lan_value);
} napt_from_lan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NAPT_FROM_WAN_ENTRIES);
    __type(key, __u32);
    __type(value, struct napt_from_wan_value);
} napt_from_wan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 196608);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct napt_ct_key);
    __type(value, struct napt_ct_value);
} napt_ct SEC(".maps");

static __always_inline __u64 napt_state_make(__u8 state, __u64 refs) {
    return ((__u64)state << NAPT_WAN_STATE_SHIFT) | (refs & NAPT_WAN_REF_MASK);
}

static __always_inline __u8 napt_state_get(__u64 state_ref) {
    return (__u8)(state_ref >> NAPT_WAN_STATE_SHIFT);
}

static __always_inline __u64 napt_state_refs(__u64 state_ref) {
    return state_ref & NAPT_WAN_REF_MASK;
}

static __always_inline int napt_wan_index(__u8 proto, __be16 external_port, __u32 *index) {
    __u32 base;

    if (!index) return 0;

    if (proto == IPV4_PROTO_UDP)
        base = NAPT_FROM_WAN_UDP_BASE;
    else if (proto == IPV4_PROTO_TCP)
        base = NAPT_FROM_WAN_TCP_BASE;
    else if (proto == IPV4_PROTO_ICMP)
        base = NAPT_FROM_WAN_ICMP_BASE;
    else
        return 0;

    *index = base + (__u32)bpf_ntohs(external_port);
    return 1;
}

static __always_inline struct napt_from_wan_value *napt_wan_lookup(__u8 proto,
                                                                   __be16 external_port) {
    __u32 index;

    if (!napt_wan_index(proto, external_port, &index)) return 0;
    return bpf_map_lookup_elem(&napt_from_wan, &index);
}

static __always_inline int napt_wan_publish(__u8 proto, __be16 external_port,
                                            const struct napt_from_wan_value *value) {
    __u32 index;

    if (!napt_wan_index(proto, external_port, &index)) return -1;
    return bpf_map_update_elem(&napt_from_wan, &index, value, BPF_ANY) == 0 ? 0 : -1;
}

/* Array slots cannot be deleted; FREE is a zeroed value. */
static __always_inline void napt_wan_clear(__u8 proto, __be16 external_port) {
    __u32 index;
    struct napt_from_wan_value free_value = {};

    if (!napt_wan_index(proto, external_port, &index)) return;
    bpf_map_update_elem(&napt_from_wan, &index, &free_value, BPF_ANY);
}

static __always_inline int napt_wan_can_create_ct(const struct napt_from_wan_value *value) {
    if (value->kind == NAPT_MAPPING_STATIC) return 1;
    if (value->kind != NAPT_MAPPING_DYNAMIC) return 0;
    return napt_state_get(value->state_ref) == NAPT_WAN_STATE_ACTIVE &&
           napt_state_refs(value->state_ref) > 0;
}

static __always_inline int napt_wan_ref_inc(struct napt_from_wan_value *value) {
    for (int i = 0; i < 8; i++) {
        __u64 old = value->state_ref;
        if (napt_state_get(old) != NAPT_WAN_STATE_ACTIVE) return -1;
        __u64 refs = napt_state_refs(old);
        if (refs == NAPT_WAN_REF_MASK) return -1;
        __u64 next = napt_state_make(NAPT_WAN_STATE_ACTIVE, refs + 1);
        __u64 prev = __sync_val_compare_and_swap(&value->state_ref, old, next);
        if (prev == old) return 0;
    }
    return -1;
}

static __always_inline int napt_wan_ref_dec(struct napt_from_wan_value *value) {
    for (int i = 0; i < 8; i++) {
        __u64 old = value->state_ref;
        if (napt_state_get(old) != NAPT_WAN_STATE_ACTIVE) return -1;
        __u64 refs = napt_state_refs(old);
        if (refs <= 1) return -1;
        __u64 next = napt_state_make(NAPT_WAN_STATE_ACTIVE, refs - 1);
        __u64 prev = __sync_val_compare_and_swap(&value->state_ref, old, next);
        if (prev == old) return 0;
    }
    return -1;
}

static __always_inline int napt_wan_close_last(struct napt_from_wan_value *value) {
    __u64 old = napt_state_make(NAPT_WAN_STATE_ACTIVE, 1);
    __u64 next = napt_state_make(NAPT_WAN_STATE_CLOSED, 1);
    return __sync_val_compare_and_swap(&value->state_ref, old, next) == old ? 0 : -1;
}

static __always_inline void napt_lan_key_init(struct napt_from_lan_key *key, __be32 internal_addr,
                                              __be16 internal_port, __u8 proto) {
    key->internal_addr = internal_addr;
    key->internal_port = internal_port;
    key->proto = proto;
    key->pad = 0;
}

static __always_inline struct napt_from_lan_value *
napt_lan_lookup(__be32 internal_addr, __be16 internal_port, __u8 proto) {
    struct napt_from_lan_key key = {};
    struct napt_from_lan_value *value;

    napt_lan_key_init(&key, internal_addr, internal_port, proto);
    value = bpf_map_lookup_elem(&napt_from_lan, &key);
    if (value || internal_addr == 0) return value;

    napt_lan_key_init(&key, 0, internal_port, proto);
    return bpf_map_lookup_elem(&napt_from_lan, &key);
}

static __always_inline int napt_lan_insert(__be32 internal_addr, __be16 internal_port, __u8 proto,
                                           const struct napt_from_lan_value *value) {
    struct napt_from_lan_key key = {};

    napt_lan_key_init(&key, internal_addr, internal_port, proto);
    return bpf_map_update_elem(&napt_from_lan, &key, value, BPF_NOEXIST) == 0 ? 0 : -1;
}

static __always_inline int napt_lan_delete_dynamic(__be32 internal_addr, __be16 internal_port,
                                                   __u8 proto, __be16 external_port, __u32 gen) {
    struct napt_from_lan_key key = {};
    struct napt_from_lan_value *value;
    int ret;

    napt_lan_key_init(&key, internal_addr, internal_port, proto);
    value = bpf_map_lookup_elem(&napt_from_lan, &key);
    if (!value || value->kind != NAPT_MAPPING_DYNAMIC || value->external_port != external_port ||
        value->generation != gen)
        return 0;

    ret = bpf_map_delete_elem(&napt_from_lan, &key);
    return ret == 0 || ret == -ENOENT ? 0 : ret;
}

static __always_inline int napt_queue_pop(__u8 proto, __be16 *port, __u32 *gen) {
    struct napt_port_slot slot = {};

    if (proto == IPV4_PROTO_UDP) {
        if (bpf_map_pop_elem(&napt_udp_ports, &slot) != 0) return -1;
    } else if (proto == IPV4_PROTO_TCP) {
        if (bpf_map_pop_elem(&napt_tcp_ports, &slot) != 0) return -1;
    } else if (proto == IPV4_PROTO_ICMP) {
        if (bpf_map_pop_elem(&napt_icmp_ids, &slot) != 0) return -1;
    } else {
        return -1;
    }

    *port = slot.port;
    *gen = slot.generation;
    return 0;
}

static __always_inline int napt_queue_push(__u8 proto, __be16 port, __u32 gen) {
    struct napt_port_slot slot = {};

    slot.port = port;
    slot.generation = gen;

    if (proto == IPV4_PROTO_UDP) return bpf_map_push_elem(&napt_udp_ports, &slot, BPF_ANY);
    if (proto == IPV4_PROTO_TCP) return bpf_map_push_elem(&napt_tcp_ports, &slot, BPF_ANY);
    if (proto == IPV4_PROTO_ICMP) return bpf_map_push_elem(&napt_icmp_ids, &slot, BPF_ANY);
    return -1;
}

static __always_inline void napt_ct_key_init(struct napt_ct_key *key, __be32 internal_addr,
                                             __be16 internal_port, __be32 remote_addr,
                                             __be16 remote_port, __u8 proto) {
    key->internal_addr = internal_addr;
    key->internal_port = internal_port;
    key->remote_addr = remote_addr;
    key->remote_port = remote_port;
    key->proto = proto;
    key->pad[0] = 0;
    key->pad[1] = 0;
    key->pad[2] = 0;
}

#endif /* LAND_NAT_TC_NAT4_MAP_H */
