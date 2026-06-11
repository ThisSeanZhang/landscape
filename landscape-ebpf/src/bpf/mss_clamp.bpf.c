#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "pkg_def.h"
#include "wan_tc_pipeline.h"

char LICENSE[] SEC("license") = "GPL";

#undef BPF_LOG_TOPIC

const volatile u16 mtu_size = 1492;

const volatile u32 current_l3_offset = 14;

#define MAX_SEGMENT_SIZE 2
#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_HDR_LEN 20

static __always_inline int extract_ipv6_tcp_offset(struct __sk_buff *skb, u32 l3_offset,
                                                   u32 *ip_hdr_len) {
    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) return TC_ACT_SHOT;

    if (ip6h->version != 6) return TC_ACT_SHOT;

    u32 offset = l3_offset;
    u32 len = sizeof(struct ipv6hdr);
    u8 nexthdr = ip6h->nexthdr;
    struct ipv6_opt_hdr *opthdr;

#pragma unroll
    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM; i++) {
        switch (nexthdr) {
        case NEXTHDR_FRAGMENT:
        case NEXTHDR_AUTH:
            return TC_ACT_UNSPEC;
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST: {
            if (VALIDATE_READ_DATA(skb, &opthdr, offset + len, sizeof(*opthdr))) return TC_ACT_SHOT;

            nexthdr = opthdr->nexthdr;
            len += (opthdr->hdrlen + 1) * 8;
            break;
        }
        default:
            goto found_tcp;
        }
    }

found_tcp:
    if (nexthdr != NEXTHDR_TCP) return TC_ACT_UNSPEC;

    *ip_hdr_len = len;
    return TC_ACT_OK;
}

static __always_inline void do_mss_clamp(struct __sk_buff *skb, u32 offset, u16 mss_value) {
#define BPF_LOG_TOPIC "mss_clamp"
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

    // tcp hdr max is 60; options max is 40 bytes.
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

        if (kind_val == MAX_SEGMENT_SIZE) {
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
                    ld_bpf_log("modify checksum error");
                    return;
                }
                if (bpf_skb_store_bytes(skb, option_offset + 2, &target_mss, sizeof(target_mss),
                                        0)) {
                    ld_bpf_log("modify mss error");
                    return;
                }
            }
            return;
        }

        option_pos += opt_len_val;
    }

#undef BPF_LOG_TOPIC
}

static __always_inline int find_and_clamp_tcp(struct __sk_buff *skb, u32 current_l3_offset,
                                              __u32 *ip_hdr_len) {
    int ret = 0;
    u8 l3_protocol = 0;
    ret = current_l3_protocol(skb, current_l3_offset, &l3_protocol);
    if (ret != TC_ACT_OK) return TC_ACT_UNSPEC;

    bool is_ipv4 = l3_protocol == LANDSCAPE_IPV4_TYPE;
    __u32 l3_offset = current_l3_offset;

    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, l3_offset, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        if (iph->protocol != IPPROTO_TCP) {
            return TC_ACT_UNSPEC;
        }
        *ip_hdr_len = iph->ihl * 4;
    } else {
        ret = extract_ipv6_tcp_offset(skb, l3_offset, ip_hdr_len);
        if (ret != TC_ACT_OK) {
            return ret;
        }
    }
    return TC_ACT_OK;
}

SEC("tc/ingress")
int clamp_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "clamp_ingress"

    volatile __u32 ip_hdr_len = 0;
    if (!find_and_clamp_tcp(skb, current_l3_offset, &ip_hdr_len)) {
        do_mss_clamp(skb, ip_hdr_len + current_l3_offset, mtu_size - ip_hdr_len - TCP_HDR_LEN);
    }

    return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_MSS, TC_ACT_UNSPEC);
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int clamp_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "clamp_egress"

    volatile __u32 ip_hdr_len = 0;
    if (!find_and_clamp_tcp(skb, current_l3_offset, &ip_hdr_len)) {
        do_mss_clamp(skb, ip_hdr_len + current_l3_offset, mtu_size - ip_hdr_len - TCP_HDR_LEN);
    }

    return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_MSS, TC_ACT_UNSPEC);

#undef BPF_LOG_TOPIC
}
