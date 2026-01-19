#ifndef LD_TP_H
#define LD_TP_H
#include <bpf/bpf_helpers.h>
#include "vmlinux_wrapper.h"

#define ETH_P_8021Q 0x8100
#define LAND_REDIRECT_NETNS_VLAN_ID 0xc00
#define LAND_REDIRECT_NETNS_VLAN_ID_MASK 0xF00

static __always_inline u8 get_flow_id_in_vlan_id(u16 vlan_id) {
    return vlan_id & ~LAND_REDIRECT_NETNS_VLAN_ID_MASK;
}

static __always_inline u16 get_flow_vlan_id(u8 flow_id) {
    return ((u16)flow_id & ~LAND_REDIRECT_NETNS_VLAN_ID_MASK) | LAND_REDIRECT_NETNS_VLAN_ID;
}

static __always_inline bool is_landscape_tag(u16 vlan_id) {
    return (vlan_id & LAND_REDIRECT_NETNS_VLAN_ID_MASK) == LAND_REDIRECT_NETNS_VLAN_ID;
}

#endif /* LD_TP_H */
