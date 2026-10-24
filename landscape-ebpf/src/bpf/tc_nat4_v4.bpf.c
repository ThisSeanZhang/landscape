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
#include "frag/frag.h"
#include "reader/skb_ferry.h"
#include "reader/tc_read_head4.h"
#include "nat_v4/tc_nat4_packet.h"
#include "nat_v4/tc_nat4_rodata.h"
#include "nat_v4/tc_modify_head.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

SEC("tc")
int tc_v4_from_lan(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;

    if (skb->protocol != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_LAN))
        return TC_ACT_SHOT;

    if (land_nat_external_addr == 0) return TC_ACT_OK;

    if (cb.l4_protocol != IPV4_PROTO_ICMP && cb.l4_protocol != IPV4_PROTO_TCP &&
        cb.l4_protocol != IPV4_PROTO_UDP)
        return TC_ACT_OK;

    if (!cb.ports_valid) return TC_ACT_SHOT;

    int rc = napt_lan_state(skb, &cb, src_addr, dst_addr, &new_addr, &new_port);
    if (rc != TC_ACT_OK) return rc;

    if (napt_is_icmp_error(&cb)) return napt_modify_icmp_error(skb, new_addr, new_port, 0);

    if (napt_is_non_initial(&cb))
        return napt_modify_fragment(skb, new_addr, LAND_NAT_FRAG_FROM_LAN);

    return napt_modify(skb, new_addr, new_port, LAND_NAT_FRAG_FROM_LAN);
}

SEC("tc")
int tc_v4_from_wan(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;

    if (skb->protocol != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_WAN))
        return TC_ACT_SHOT;

    if (dst_addr != land_nat_external_addr) return TC_ACT_OK;

    if (cb.l4_protocol != IPV4_PROTO_ICMP && cb.l4_protocol != IPV4_PROTO_TCP &&
        cb.l4_protocol != IPV4_PROTO_UDP)
        return TC_ACT_OK;

    if (!cb.ports_valid) return TC_ACT_SHOT;

    int rc = napt_wan_state(skb, &cb, src_addr, &new_addr, &new_port);
    if (rc != TC_ACT_OK) return rc;

    if (napt_is_icmp_error(&cb)) return napt_modify_icmp_error(skb, new_addr, new_port, 1);

    if (napt_is_non_initial(&cb))
        return napt_modify_fragment(skb, new_addr, LAND_NAT_FRAG_FROM_WAN);

    return napt_modify(skb, new_addr, new_port, LAND_NAT_FRAG_FROM_WAN);
}
