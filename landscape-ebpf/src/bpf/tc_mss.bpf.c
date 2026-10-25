#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/proto_def.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "frag/frag.h"
#include "reader/skb_ferry.h"
#include "reader/tc_read_head4.h"
#include "reader/tc_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 mtu_size = 1492;

const volatile u32 current_l3_offset = 14;

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_HDR_LEN 20

static __always_inline void do_mss_clamp(struct __sk_buff *skb, u32 offset, u16 mss_value) {
    struct tcphdr *tcph;
    if (VALIDATE_READ_DATA(skb, &tcph, offset, sizeof(*tcph))) {
        return;
    }
    if (!tcph->syn) {
        return;
    }
    u8 tcp_size = (tcph->doff * 4);
    if (tcp_size <= TCP_HDR_LEN) {
        return;
    }
    u8 options_len = tcp_size - TCP_HDR_LEN;
    u8 option_pos = 0;

    for (int i = 0; i < 40; i++) {
        if (option_pos >= options_len) {
            return;
        }

        u8 remaining = options_len - option_pos;
        u32 option_offset = offset + TCP_HDR_LEN + option_pos;
        u8 kind_val;
        if (bpf_skb_load_bytes(skb, option_offset, &kind_val, sizeof(kind_val))) return;

        if (kind_val == TCP_OPT_EOL) {
            return;
        }

        if (kind_val == TCP_OPT_NOP) {
            option_pos += 1;
            continue;
        }

        if (remaining < 2) {
            return;
        }
        u8 opt_len_val;
        if (bpf_skb_load_bytes(skb, option_offset + 1, &opt_len_val, sizeof(opt_len_val))) return;
        if (opt_len_val < 2 || opt_len_val > remaining) return;

        if (kind_val == TCP_OPT_MSS) {
            if (opt_len_val != 4) {
                return;
            }
            __be16 mss_val;
            if (bpf_skb_load_bytes(skb, option_offset + 2, &mss_val, sizeof(mss_val))) {
                return;
            }
            if (bpf_ntohs(mss_val) > mss_value) {
                __be16 target_mss = bpf_htons(mss_value);
                if (bpf_l4_csum_replace(skb, offset + offsetof(struct tcphdr, check), mss_val,
                                        target_mss, 2 | 0)) {
                    ld_from_wan_log("modify checksum error");
                    return;
                }
                if (bpf_skb_store_bytes(skb, option_offset + 2, &target_mss, sizeof(target_mss),
                                        0)) {
                    ld_from_wan_log("modify mss error");
                    return;
                }
            }
            return;
        }

        option_pos += opt_len_val;
    }
}

static __always_inline void clamp_tcp_v4(struct __sk_buff *skb, u32 current_l3_offset, u16 mtu,
                                         u8 direction) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, direction)) return;
    if (cb.icmp_inner_l4_offset) return;
    if (cb.frag_code > LAND_NAT_FRAG_FIRST) return;
    if (cb.l4_protocol != IPV4_PROTO_TCP) return;
    if (cb.tcp_phase != NAPT_TCP_PHASE_SYN) return;
    if (cb.l4_offset < current_l3_offset) return;

    u32 ip_hdr_len = cb.l4_offset - current_l3_offset;
    if (ip_hdr_len + TCP_HDR_LEN >= mtu) return;
    do_mss_clamp(skb, cb.l4_offset, mtu - ip_hdr_len - TCP_HDR_LEN);
}

static __always_inline void clamp_tcp_v6(struct __sk_buff *skb, u32 current_l3_offset, u16 mtu,
                                         u8 direction) {
    struct skb_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    if (!tc_read_ipv6(skb, &cb, &src_addr, &dst_addr, current_l3_offset, direction)) return;
    if (cb.icmp_inner_l4_offset) return;
    if (cb.frag_code != LAND_NAT_FRAG_NONE) return;
    if (cb.l4_protocol != IPV6_NH_TCP) return;
    if (cb.tcp_phase != NAPT_TCP_PHASE_SYN) return;
    if (cb.l4_offset < current_l3_offset) return;

    u32 ip_hdr_len = cb.l4_offset - current_l3_offset;
    if (ip_hdr_len + TCP_HDR_LEN >= mtu) return;
    do_mss_clamp(skb, cb.l4_offset, mtu - ip_hdr_len - TCP_HDR_LEN);
}

SEC("tc/ingress")
int tc_mss_wan_ingress_v4(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v4(skb, current_l3_offset, mtu_size, LAND_NAT_FRAG_FROM_WAN);
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_mss_wan_ingress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v6(skb, current_l3_offset, mtu_size, LAND_NAT_FRAG_FROM_WAN);
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_mss_wan_egress_v4(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v4(skb, current_l3_offset, mtu_size, LAND_NAT_FRAG_FROM_LAN);
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int tc_mss_wan_egress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v6(skb, current_l3_offset, mtu_size, LAND_NAT_FRAG_FROM_LAN);
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
