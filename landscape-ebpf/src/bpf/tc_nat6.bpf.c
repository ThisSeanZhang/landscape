#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "chain/tc_stage.h"
#include "chain/tc_cb.h"
#include "chain/tc_wan_exit_maps.h"
#include "nat/tc_nat6.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"
#include "fragment/frag6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_TOPIC

static __always_inline int tc_nat_v6_egress_do(struct __sk_buff *skb, u32 ifindex) {
#define BPF_LOG_TOPIC "tc_nat_v6_egress <<<"
    struct scan_ipv6_idx idx = {};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    if (scan_ipv6_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return TC_ACT_OK;
    }
    ret = skb_read_ipv6_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;
    if (unlikely(is_broadcast_ip6_pair(&ip_pair))) return TC_ACT_OK;
    ret = frag6_track(&idx, (const struct in6_addr *)&ip_pair.src_addr,
                      (const struct in6_addr *)&ip_pair.dst_addr, &ip_pair.src_port,
                      &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    ret = ipv6_egress_prefix_check_and_replace(skb, &idx, &ip_pair, current_l3_offset, ifindex);
    return ret == TC_ACT_SHOT ? TC_ACT_SHOT : TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_nat_v6_ingress_do(struct __sk_buff *skb, u32 ifindex) {
#define BPF_LOG_TOPIC "tc_nat_v6_ingress >>>"
    struct scan_ipv6_idx idx = {};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    if (scan_ipv6_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return TC_ACT_OK;
    }
    ret = skb_read_ipv6_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;
    if (unlikely(is_broadcast_ip6_pair(&ip_pair))) return TC_ACT_OK;
    ret = frag6_track(&idx, (const struct in6_addr *)&ip_pair.src_addr,
                      (const struct in6_addr *)&ip_pair.dst_addr, &ip_pair.src_port,
                      &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    ret = ipv6_ingress_prefix_check_and_replace(skb, &idx, &ip_pair, current_l3_offset, ifindex);
    return ret == TC_ACT_SHOT ? TC_ACT_SHOT : TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_nat_egress_v6_entry(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_nat_egress_v6 <<<"
    if (likely(current_l3_offset > 0)) {
        if (unlikely(is_broadcast_mac(skb) != TC_ACT_OK)) return TC_ACT_OK;
    }
    return tc_nat_v6_egress_do(skb, skb->ifindex);
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_nat_ingress_v6_entry(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">>> tc_nat_ingress_v6 >>>"
    if (likely(current_l3_offset > 0)) {
        if (unlikely(is_broadcast_mac(skb) != TC_ACT_OK)) return TC_ACT_OK;
    }
    return tc_nat_v6_ingress_do(skb, skb->ifindex);
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int tc_nat_wan_egress_v6(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_nat_wan_egress_v6 <<<"

    if (unlikely(tc_nat_egress_v6_entry(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_nat_wan_ingress_v6(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">>> tc_nat_wan_ingress_v6 >>>"

    if (unlikely(tc_nat_ingress_v6_entry(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
