#ifndef __LD_FROM_LAN_ROOT_H_
#define __LD_FROM_LAN_ROOT_H_

#include <vmlinux.h>

/* Per-WAN binding snapshot, installed before the root is published.
 * Address fields are wire-format bytes so the roots can compare packet
 * bytes without byte swaps. */
struct wan_egress_binding {
    __u32 ifindex;
    __be32 wan_ip4;
    __be32 wan_mask4;
    __be32 gateway_ip4;
    __u8 source_mac[6];
    __u8 has_ipv4;
    __u8 has_l2;
    __u8 is_pppoe;
    __u8 wan_ip6[16];
    __u8 wan_mask6[16];
    __u8 gateway_ip6[16];
    __u8 has_ipv6;
};

#endif
