// SPDX-License-Identifier: GPL-2.0-or-later
//
// TC IPv4 NAT datapath. The reader is shared with the chain stages; the NAT
// state machine uses the active/idle/release cleanup model on top of the
// new nat_v4 maps.

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/tc_act.h"
#include "base/ipv4.h"
#include "base/mark.h"
#include "chain/tc_wan_exit_maps.h"
#include "frag/frag.h"
#include "reader/skb_ferry.h"
#include "reader/tc_read_head4.h"
#include "nat_v4/tc_nat4_packet.h"
#include "nat_v4/tc_nat4_rodata.h"
#include "nat_v4/tc_modify_head.h"

char LICENSE[] SEC("license") = "GPL";

#define TC_SLOT_V4 0

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_ingress_next_stage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_next_stage SEC(".maps");

#define TC_FROM_WAN_CHAIN_NEXT(skb) bpf_tail_call_static((skb), &wan_ingress_next_stage, TC_SLOT_V4)
#define TC_FROM_LAN_CHAIN_NEXT(skb) bpf_tail_call_static((skb), &wan_egress_next_stage, TC_SLOT_V4)

static __always_inline int napt_broadcast_mac(struct __sk_buff *skb, __u32 l3_offset) {
    if (l3_offset == 0) return 0;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct ethhdr *eth = (void *)data;
    if ((char *)(eth + 1) > data_end) return 0;

    const __u8 *dst = eth->h_dest;
    int broadcast = dst[0] == 0xff && dst[1] == 0xff && dst[2] == 0xff && dst[3] == 0xff &&
                    dst[4] == 0xff && dst[5] == 0xff;
    int ipv6_mcast = dst[0] == 0x33 && dst[1] == 0x33;
    return broadcast || ipv6_mcast;
}

const volatile u32 current_l3_offset = 14;

SEC("tc/egress")
int tc_v4_from_lan(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;
    int rc = TC_ACT_OK;

    if (!not_host_direct(skb_mark(skb))) goto chain;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_LAN))
        goto chain;

    if (napt_broadcast_mac(skb, current_l3_offset)) goto chain;
    if (napt_is_broadcast_ip4(src_addr) || napt_is_broadcast_ip4(dst_addr)) goto chain;

    if (land_nat_external_addr == 0) goto chain;

    if (cb.l4_protocol != IPV4_PROTO_ICMP && cb.l4_protocol != IPV4_PROTO_TCP &&
        cb.l4_protocol != IPV4_PROTO_UDP)
        goto chain;

    if (!cb.ports_valid) return TC_ACT_SHOT;

    rc = napt_lan_state(skb, &cb, src_addr, dst_addr, &new_addr, &new_port);
    if (rc == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (rc != TC_ACT_OK) goto chain;

    if (napt_is_icmp_error(&cb)) {
        rc = napt_modify_icmp_error(skb, new_addr, new_port, 0, cb.l3_offset);
    } else if (napt_is_non_initial(&cb)) {
        rc = napt_modify_fragment(skb, new_addr, LAND_NAT_FRAG_FROM_LAN, cb.l3_offset);
    } else {
        rc = napt_modify(skb, new_addr, new_port, LAND_NAT_FRAG_FROM_LAN, cb.l3_offset);
    }
    if (rc == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (rc != TC_ACT_OK) goto chain;

chain:
    TC_FROM_LAN_CHAIN_NEXT(skb);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/ingress")
int tc_v4_from_wan(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;
    int rc = TC_ACT_OK;

    if (!not_host_direct(skb_mark(skb))) goto chain;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_WAN))
        goto chain;

    if (napt_broadcast_mac(skb, current_l3_offset)) goto chain;
    if (napt_is_broadcast_ip4(src_addr) || napt_is_broadcast_ip4(dst_addr)) goto chain;

    if (dst_addr != land_nat_external_addr) goto chain;

    if (cb.l4_protocol != IPV4_PROTO_ICMP && cb.l4_protocol != IPV4_PROTO_TCP &&
        cb.l4_protocol != IPV4_PROTO_UDP)
        goto chain;

    if (!cb.ports_valid) return TC_ACT_SHOT;

    rc = napt_wan_state(skb, &cb, src_addr, dst_addr, &new_addr, &new_port);
    if (rc == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (rc != TC_ACT_OK) goto chain;

    if (napt_is_icmp_error(&cb)) {
        rc = napt_modify_icmp_error(skb, new_addr, new_port, 1, cb.l3_offset);
    } else if (napt_is_non_initial(&cb)) {
        rc = napt_modify_fragment(skb, new_addr, LAND_NAT_FRAG_FROM_WAN, cb.l3_offset);
    } else {
        rc = napt_modify(skb, new_addr, new_port, LAND_NAT_FRAG_FROM_WAN, cb.l3_offset);
    }
    if (rc == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (rc != TC_ACT_OK) goto chain;

chain:
    TC_FROM_WAN_CHAIN_NEXT(skb);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}
