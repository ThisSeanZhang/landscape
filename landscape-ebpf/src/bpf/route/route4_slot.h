#ifndef __LD_ROUTE4_SLOT_H__
#define __LD_ROUTE4_SLOT_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct route4_slot_key {
    __u32 flow_id;
    __u32 slot;
};

struct route4_target_info {
    u32 ifindex;
    __be32 gate_addr;
    u8 has_mac;
    u8 is_docker;
    u8 mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route4_slot_key);
    __type(value, struct route4_target_info);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt4_slot_map SEC(".maps");

static __always_inline u32 route4_target_slot(__be32 daddr) {
    u32 hash = (u32)daddr;
    hash ^= hash >> 16;
    hash ^= hash >> 8;
    return hash & 0xF;
}

#endif /* __LD_ROUTE4_SLOT_H__ */
