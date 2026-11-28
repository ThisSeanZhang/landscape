#ifndef __LD_ROUTE4_SLOT_H__
#define __LD_ROUTE4_SLOT_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "route/route_mode.h"

struct route4_slot_key {
    __u32 flow_id;
    __u32 slot;
};

struct route4_target_info {
    u32 ifindex;
    u8 has_mac;
    u8 is_docker;
    __u16 link_chain_id;
};

_Static_assert(sizeof(struct route4_target_info) == 8, "route4_target_info must be 8 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route4_slot_key);
    __type(value, struct route4_target_info);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt4_slot_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_flow_target_key);
    __type(value, struct route4_target_info);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt4_flow_targets SEC(".maps");

static __always_inline u32 route4_target_slot(__be32 daddr) {
    return route_avalanche32((u32)daddr) & 0xFF;
}

static __always_inline u32 route4_five_tuple_slot(__be32 saddr, __be32 daddr, __be16 sport,
                                                  __be16 dport, u8 proto) {
    u32 h = (u32)saddr * 0xcc9e2d51U;
    h = (h << 15) | (h >> 17);
    h = (h * 0x1b873593U) ^ (u32)daddr;
    h = ((h << 13) | (h >> 19)) * 5U + 0xe6546b64U;
    u32 ports = ((u32)(u16)sport << 16) | (u32)(u16)dport;
    h ^= ports * 0xcc9e2d51U;
    h ^= ((u32)proto) * 0x9e3779b9U;
    return route_avalanche32(h) & 0xFF;
}

#endif /* __LD_ROUTE4_SLOT_H__ */
