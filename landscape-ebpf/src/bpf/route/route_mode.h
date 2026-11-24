#ifndef __LD_ROUTE_MODE_H__
#define __LD_ROUTE_MODE_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ROUTE_BALANCE_DST_IP 0
#define ROUTE_BALANCE_FIVE_TUPLE 1
#define ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY 256
#define ROUTE_FLOW_MODE_MAP_ENTRIES 257

#define CONN_PIN_CACHE 0
#define L4_VERDICT_CACHE 1

#define ROUTE_CONN_FLAG_DROP (1U << 0)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, ROUTE_FLOW_MODE_MAP_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_flow_mode_map SEC(".maps");

struct route_flow_target_key {
    __u32 flow_id;
    __u32 ifindex;
} _route_flow_target_key;

struct route_conn_value {
    __u32 mark_value;
    u8 has_mac;
    u8 is_docker;
    u8 xdp_redirect_able;
    u8 flags;
    __u32 ifindex;
    __u16 link_chain_id;
    __u16 _pad;
} _route_conn_value;

_Static_assert(sizeof(struct route_conn_value) == 16, "route_conn_value must be 16 bytes");
_Static_assert(__builtin_offsetof(struct route_conn_value, link_chain_id) == 12,
               "route_conn_value link_chain_id must be at offset 12");

static __always_inline bool route_flow_is_five_tuple(u32 flow_id) {
    if (flow_id >= ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY) return false;
    u8 *mode = bpf_map_lookup_elem(&rt_flow_mode_map, &flow_id);
    return mode != NULL && *mode == ROUTE_BALANCE_FIVE_TUPLE;
}

static __always_inline bool route_any_flow_is_five_tuple(void) {
    u32 any_key = ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY;
    u8 *active = bpf_map_lookup_elem(&rt_flow_mode_map, &any_key);
    return active != NULL && *active != 0;
}

static __always_inline u32 route_avalanche32(u32 h) {
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

#endif /* __LD_ROUTE_MODE_H__ */
