#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/proto_def.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "reader/tc_mss4.h"
#include "reader/tc_mss6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 mtu_size = 1492;

const volatile u32 current_l3_offset = 14;

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_HDR_LEN 20

static __always_inline void do_mss_clamp(struct __sk_buff *skb, u32 offset, u8 tcp_doff,
                                         u16 mss_value) {
    u8 tcp_size = tcp_doff * 4;
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

static __always_inline void clamp_tcp_v4(struct __sk_buff *skb, u32 current_l3_offset, u16 mtu) {
    struct tc_mss4_view view;

    if (!tc_mss4_read(skb, current_l3_offset, &view)) return;

    u32 ip_hdr_len = view.l4_off - current_l3_offset;
    if (ip_hdr_len + TCP_HDR_LEN >= mtu) return;
    do_mss_clamp(skb, view.l4_off, view.doff, mtu - ip_hdr_len - TCP_HDR_LEN);
}

static __always_inline void clamp_tcp_v6(struct __sk_buff *skb, u32 current_l3_offset, u16 mtu) {
    struct tc_mss6_view view;

    if (!tc_mss6_read(skb, current_l3_offset, &view)) return;

    u32 ip_hdr_len = view.l4_off - current_l3_offset;
    if (ip_hdr_len + TCP_HDR_LEN >= mtu) return;
    do_mss_clamp(skb, view.l4_off, view.doff, mtu - ip_hdr_len - TCP_HDR_LEN);
}

SEC("tc/ingress")
int tc_mss_wan_ingress_v4(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v4(skb, current_l3_offset, mtu_size);
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_mss_wan_ingress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v6(skb, current_l3_offset, mtu_size);
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_mss_wan_egress_v4(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v4(skb, current_l3_offset, mtu_size);
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int tc_mss_wan_egress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        clamp_tcp_v6(skb, current_l3_offset, mtu_size);
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
