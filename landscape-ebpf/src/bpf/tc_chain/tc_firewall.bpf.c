#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "pipeline/tc_stage.h"
#include "pipeline/tc_wan_exit_maps.h"
#include "firewall/firewall_packet.h"
#include "firewall/firewall_share.h"
#include "pkg_fragment.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_TOPIC

static __always_inline int fw_do_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< fw_do_egress <<<"

    bool is_v4;
    if (current_pkg_type(skb, current_l3_offset, &is_v4) != TC_ACT_OK) return TC_ACT_OK;

    struct packet_offset_info offset_info = {0};
    struct inet_pair ip_pair = {0};

    if (is_v4) {
        int ret = extract_firewall_v4_packet_info(skb, &offset_info, &ip_pair, current_l3_offset);
        if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;

        bool is_icmpx_error = is_icmp_error_pkt(&offset_info);
        if (likely(!is_icmpx_error)) {
            ret = frag_info_track(&offset_info, &ip_pair);
            if (ret != TC_ACT_OK) return TC_ACT_SHOT;
        }

        struct ipv4_lpm_key block_search_key = {
            .prefixlen = 32,
            .addr = ip_pair.dst_addr.ip,
        };
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
            return TC_ACT_SHOT;
    } else {
        int ret = extract_firewall_v6_packet_info(skb, &offset_info, &ip_pair, current_l3_offset);
        if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;

        bool is_icmpx_error = is_icmp_error_pkt(&offset_info);
        if (likely(!is_icmpx_error)) {
            ret = frag_info_track(&offset_info, &ip_pair);
            if (unlikely(ret != TC_ACT_OK)) return TC_ACT_SHOT;
        }

        struct ipv6_lpm_key block_search_key = {
            .prefixlen = 128,
        };
        __builtin_memcpy(&block_search_key.addr, &ip_pair.dst_addr, sizeof(block_search_key.addr));
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
            return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int fw_do_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< fw_do_ingress <<<"

    bool is_v4;
    if (current_pkg_type(skb, current_l3_offset, &is_v4) != TC_ACT_OK) return TC_ACT_OK;

    struct packet_offset_info offset_info = {0};
    struct inet_pair ip_pair = {0};

    if (is_v4) {
        int ret = extract_firewall_v4_packet_info(skb, &offset_info, &ip_pair, current_l3_offset);
        if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;

        bool is_icmpx_error = is_icmp_error_pkt(&offset_info);
        if (likely(!is_icmpx_error)) {
            ret = frag_info_track(&offset_info, &ip_pair);
            if (ret != TC_ACT_OK) return TC_ACT_SHOT;
        }

        struct ipv4_lpm_key block_search_key = {
            .prefixlen = 32,
            .addr = ip_pair.src_addr.ip,
        };
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
            return TC_ACT_SHOT;
    } else {
        int ret = extract_firewall_v6_packet_info(skb, &offset_info, &ip_pair, current_l3_offset);
        if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;

        bool is_icmpx_error = is_icmp_error_pkt(&offset_info);
        if (likely(!is_icmpx_error)) {
            ret = frag_info_track(&offset_info, &ip_pair);
            if (unlikely(ret != TC_ACT_OK)) return TC_ACT_SHOT;
        }

        struct ipv6_lpm_key block_search_key = {
            .prefixlen = 128,
        };
        __builtin_memcpy(&block_search_key.addr, &ip_pair.src_addr, sizeof(block_search_key.addr));
        if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
            return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int tc_firewall_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_firewall_wan_egress <<<"

    if (unlikely(fw_do_egress(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_EGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_firewall_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_firewall_wan_ingress <<<"

    if (unlikely(fw_do_ingress(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_INGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
