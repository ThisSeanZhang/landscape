#include "vmlinux_wrapper.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "pkg_def.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

const volatile u16 mtu_size = 1492;

const volatile u32 current_l3_offset = 14;

#define MAX_SEGMENT_SIZE 2

struct tcp_option_hdr {
    u8 kind;
    u8 len;
};

static __always_inline int extract_ipv6_tcp_offset(struct __sk_buff *skb, u32 l3_offset,
                                                   u32 *ip_hdr_len) {
    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) return TC_ACT_SHOT;

    if (ip6h->version != 6) return TC_ACT_SHOT;

    u32 offset = l3_offset;
    u32 len = sizeof(struct ipv6hdr);
    u8 nexthdr = ip6h->nexthdr;
    struct ipv6_opt_hdr *opthdr;
    bool seen_fragment = false;

#pragma unroll
    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM; i++) {
        switch (nexthdr) {
        case NEXTHDR_FRAGMENT:
            seen_fragment = true;
            // fallthrough
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST:
        case NEXTHDR_AUTH: {
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
    if (seen_fragment) return TC_ACT_UNSPEC;

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
    if (tcp_size <= 20) {
        return;
    }
    // tcp option start offset
    u32 option_offset = offset + 20;
    u32 option_offset_end = offset + tcp_size;
    u16 *mss;
    // tcp hdr max is 60 - 20 = 40; 40 / 2 = 20;
    int times = (tcp_size - 20) / 2;
    times = times > 20 ? 20 : times;
    struct tcp_option_hdr *top_hdr;
    for (int i = 0; i < times; i++) {
        if (VALIDATE_READ_DATA(skb, &top_hdr, option_offset, sizeof(*top_hdr))) {
            return;
        }

        if (top_hdr->kind == MAX_SEGMENT_SIZE) {
            if (VALIDATE_READ_DATA(skb, &mss, option_offset + 2, sizeof(*mss))) {
                return;
            }
            // bpf_log_info("fond mss: %u", *mss);
            // bpf_log_info("fond mss: %u", bpf_ntohs(*mss));
            if (bpf_ntohs(*mss) > mss_value) {
                __be16 target_mss = bpf_ntohs(mss_value);
                if (bpf_l4_csum_replace(skb, offset + offsetof(struct tcphdr, check), *mss,
                                        target_mss, 2 | 0)) {
                    bpf_log_error("modify checksum error");
                    return;
                }
                if (bpf_skb_store_bytes(skb, option_offset + 2, &target_mss, sizeof(target_mss),
                                        0)) {
                    bpf_log_error("modify mss error");
                    return;
                }
            }

            return;
        }
        option_offset = option_offset + top_hdr->len;
        if (option_offset >= option_offset_end) {
            return;
        }
    }

#undef BPF_LOG_TOPIC
}

static __always_inline int find_and_clamp_tcp(struct __sk_buff *skb, u32 current_l3_offset,
                                              __u32 *ip_hdr_len) {
    int ret = 0;
    bool is_ipv4;
    if (current_l3_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
            return TC_ACT_UNSPEC;
        }

        if (eth->h_proto == ETH_IPV4) {
            is_ipv4 = true;
        } else if (eth->h_proto == ETH_IPV6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_UNSPEC;
        }
        u8 ip_version = (*p_version) >> 4;
        if (ip_version == 4) {
            is_ipv4 = true;
        } else if (ip_version == 6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    }
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

#define TCP_HDR_LEN 20

SEC("tc/ingress")
int clamp_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "clamp_ingress"

    volatile __u32 ip_hdr_len = 0;
    if (!find_and_clamp_tcp(skb, current_l3_offset, &ip_hdr_len)) {
        do_mss_clamp(skb, ip_hdr_len + current_l3_offset, mtu_size - ip_hdr_len - TCP_HDR_LEN);
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int clamp_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "clamp_egress"

    volatile __u32 ip_hdr_len = 0;
    if (!find_and_clamp_tcp(skb, current_l3_offset, &ip_hdr_len)) {
        do_mss_clamp(skb, ip_hdr_len + current_l3_offset, mtu_size - ip_hdr_len - TCP_HDR_LEN);
    }

    return TC_ACT_UNSPEC;

#undef BPF_LOG_TOPIC
}