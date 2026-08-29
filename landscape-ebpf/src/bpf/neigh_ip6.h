#ifndef __LD_IP_NEIGH6_H__
#define __LD_IP_NEIGH6_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"

struct mac_key_v6 {
    union u_inet6_addr addr;
};

// Source of a mac_value_v6 entry. Entries sourced from kernel neigh / traffic
// learning follow the kernel neigh lifecycle and may be removed by the
// periodic userspace reconcile; entries sourced from DAD NS learning are
// exempt from reconcile deletion (the kernel usually has no valid neigh entry
// for a DAD target, which would otherwise wipe them within seconds).
#define LD_MAC_SOURCE_NEIGH 0
#define LD_MAC_SOURCE_DAD 1

struct mac_value_v6 {
    u32 ifindex;
    u8 mac[6];
    u8 dev_mac[6];
    __be16 proto;
    u8 sourced;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct mac_key_v6);
    __type(value, struct mac_value_v6);
    __uint(max_entries, 4096);
} ip_mac_v6 SEC(".maps");

#endif /* __LD_IP_NEIGH6_H__ */
