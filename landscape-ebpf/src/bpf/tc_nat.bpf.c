#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "chain/tc_stage.h"
#include "chain/tc_cb.h"
#include "chain/tc_wan_exit_maps.h"
#include "nat/tc_nat4.h"
#include "nat/tc_nat6.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"
#include "fragment/frag4.h"
#include "fragment/frag6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_TOPIC

static __always_inline int tc_nat_v4_egress_do(struct __sk_buff *skb, u32 ifindex) {
#define BPF_LOG_TOPIC "tc_nat_v4_egress <<<"

    struct scan_ipv4_idx idx = {};
    struct inet4_pair ip_pair = {0};
    struct nat4_egress_result result = {};
    struct nat4_mapping_value_v3 *dyn_ingress = NULL;
    struct nat4_port_queue_value_v3 alloc_item = {0};
    int ret = 0;

    if (scan_ipv4_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return TC_ACT_OK;
    }
    ret = skb_read_ipv4_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;
    if (unlikely(is_broadcast_ip4_pair(&ip_pair))) {
        return TC_ACT_OK;
    }
    ret = frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port,
                      &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;

    bool is_icmpx_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    u8 nat_l4_protocol = is_icmpx_error ? idx.icmp_error_l4_protocol : idx.l4_protocol;
    bool allow_create_mapping = !is_icmpx_error && pkt_can_begin_ct(idx.pkt_type);

    ret = nat4_st_egress_lookup(ifindex, nat_l4_protocol, &ip_pair, &result);
    if (ret != TC_ACT_OK) {
        ret = nat4_dyn_egress_lookup_and_check(skb, ifindex, nat_l4_protocol, allow_create_mapping,
                                               &ip_pair, &result, &dyn_ingress, &alloc_item);
        if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    }

    struct nat4_timer_key ct_key = {0};
    ct_key.l4proto = nat_l4_protocol;
    ct_key.pair_ip.src_addr = ip_pair.dst_addr;
    ct_key.pair_ip.src_port = ip_pair.dst_port;
    ct_key.pair_ip.dst_addr.addr = result.nat_addr;
    ct_key.pair_ip.dst_port = result.nat_port;
    if (nat_l4_protocol == IPPROTO_ICMP) {
        ct_key.pair_ip.src_port = result.nat_port;
    }

    struct nat4_timer_value_v3 *ct_value = NULL;
    ret = nat4_ct_resolve(&ct_key, dyn_ingress, &ct_value);
    if (ret && allow_create_mapping) {
        ret = nat4_ct_create(skb, ifindex, &ct_key, &ip_pair.src_addr, ip_pair.src_port,
                             NAT_MAPPING_EGRESS, dyn_ingress, &ct_value);
        if (ret) {
            if (result.is_created && dyn_ingress &&
                dyn_ingress->state_ref == nat4_state_make(NAT4_STATE_ACTIVE, 0)) {
                nat4_delete_mapping_pair(nat_l4_protocol, result.nat_addr, result.nat_port,
                                         ip_pair.src_addr.addr, ip_pair.src_port);
                (void)nat4_queue_push(nat_l4_protocol, &alloc_item);
            }
            return TC_ACT_SHOT;
        }
    } else if (ret) {
        return TC_ACT_SHOT;
    }

    if (!is_icmpx_error) {
        nat4_ct_advance(idx.pkt_type, NAT_MAPPING_EGRESS, ct_value);
        nat_metric_accumulate(skb, false, ct_value);
    }

    struct nat4_action action = {
        .from_addr = ip_pair.src_addr,
        .from_port = ip_pair.src_port,
        .to_addr.addr = result.nat_addr,
        .to_port = result.nat_port,
    };

    ret = modify_headers_v4(skb, is_icmpx_error, nat_l4_protocol, current_l3_offset, idx.l4_offset,
                            idx.icmp_error_inner_l4_offset, true, &action);

    return ret ? TC_ACT_SHOT : TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_nat_v4_ingress_do(struct __sk_buff *skb, u32 ifindex) {
#define BPF_LOG_TOPIC "tc_nat_v4_ingress >>>"
    struct scan_ipv4_idx idx = {};
    struct inet4_pair ip_pair = {0};
    struct nat4_lan_result result = {};
    struct nat4_mapping_value_v3 *dyn_ingress = NULL;
    struct nat4_action action = {0};
    int ret = 0;

    if (scan_ipv4_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) return TC_ACT_OK;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return TC_ACT_OK;
    }
    ret = skb_read_ipv4_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    if (ret) return TC_ACT_OK;
    if ((is_broadcast_ip4_pair(&ip_pair))) {
        return TC_ACT_OK;
    }
    ret = frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port,
                      &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;

    bool is_icmpx_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    u8 nat_l4_protocol = is_icmpx_error ? idx.icmp_error_l4_protocol : idx.l4_protocol;

    struct nat4_timer_key ct_key = {0};
    ct_key.l4proto = nat_l4_protocol;
    ct_key.pair_ip.src_addr = ip_pair.src_addr;
    ct_key.pair_ip.src_port = ip_pair.src_port;
    ct_key.pair_ip.dst_addr = ip_pair.dst_addr;
    ct_key.pair_ip.dst_port = ip_pair.dst_port;

    struct nat4_timer_value_v3 *ct_value = NULL;

    enum ct_ingress_resolve cr = nat4_ct_ingress_resolve(&ct_key, &ct_value);
    if (cr == CT_RESOLVE_UNUSABLE) {
        return TC_ACT_SHOT;
    }
    if (cr == CT_RESOLVE_OK) {
        if (ct_value->is_static) {
            u32 mark = skb->mark;
            barrier_var(mark);
            skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
        }
        action.to_addr.addr = ct_value->client_addr.addr;
        action.to_port = ct_value->client_port;
        goto translate;
    }

    bool allow_create_ct = !is_icmpx_error && pkt_can_begin_ct(idx.pkt_type);
    if (!allow_create_ct) return TC_ACT_SHOT;

    ret = nat4_st_ingress_lookup(nat_l4_protocol, &ip_pair, &result);
    if (ret == TC_ACT_OK) {
        u32 mark = skb->mark;
        barrier_var(mark);
        skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
    } else {
        ret = nat4_dyn_ingress_lookup_and_check(nat_l4_protocol, &ip_pair, &result, &dyn_ingress);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
        if (!nat4_can_create_ct(dyn_ingress)) {
            return TC_ACT_SHOT;
        }
    }

    if (dyn_ingress == NULL && result.lan_addr == 0) {
        action.to_addr.addr = ip_pair.dst_addr.addr;
    } else {
        action.to_addr.addr = result.lan_addr;
    }
    action.to_port = result.lan_port;
    ret = nat4_ct_create(skb, ifindex, &ct_key, &action.to_addr, result.lan_port,
                         NAT_MAPPING_INGRESS, dyn_ingress, &ct_value);
    if (ret) return TC_ACT_SHOT;

translate:
    action.from_addr = ip_pair.dst_addr;
    action.from_port = ip_pair.dst_port;

    if (!is_icmpx_error) {
        nat4_ct_advance(idx.pkt_type, NAT_MAPPING_INGRESS, ct_value);
        nat_metric_accumulate(skb, true, ct_value);
    }

    ret = modify_headers_v4(skb, is_icmpx_error, nat_l4_protocol, current_l3_offset, idx.l4_offset,
                            idx.icmp_error_inner_l4_offset, false, &action);
    return ret ? TC_ACT_SHOT : TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

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
    ret = is_broadcast_ip_pair(LANDSCAPE_IPV6_TYPE, &ip_pair);
    if (ret != TC_ACT_OK) return TC_ACT_OK;
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
    ret = is_broadcast_ip_pair(LANDSCAPE_IPV6_TYPE, &ip_pair);
    if (ret != TC_ACT_OK) return TC_ACT_OK;
    ret = frag6_track(&idx, (const struct in6_addr *)&ip_pair.src_addr,
                      (const struct in6_addr *)&ip_pair.dst_addr, &ip_pair.src_port,
                      &ip_pair.dst_port);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    ret = ipv6_ingress_prefix_check_and_replace(skb, &idx, &ip_pair, current_l3_offset, ifindex);
    return ret == TC_ACT_SHOT ? TC_ACT_SHOT : TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_nat_egress_dispatch(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_nat_egress_dispatch <<<"
    bool is_ipv4;
    int ret;

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;

    u32 ifindex = skb->ifindex;

    if (is_ipv4) {
        return tc_nat_v4_egress_do(skb, ifindex);
    } else {
        return tc_nat_v6_egress_do(skb, ifindex);
    }
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_nat_ingress_dispatch(struct __sk_buff *skb) {
    bool is_ipv4;
    int ret;

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK)) return TC_ACT_OK;

    u32 ifindex = skb->ifindex;

    if (is_ipv4) {
        return tc_nat_v4_ingress_do(skb, ifindex);
    } else {
        return tc_nat_v6_ingress_do(skb, ifindex);
    }
}

SEC("tc/egress")
int tc_nat_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_nat_wan_egress <<<"

    if (unlikely(tc_nat_egress_dispatch(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_EGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_nat_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_nat_wan_ingress <<<"

    if (unlikely(tc_nat_ingress_dispatch(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;

    TC_CHAIN_WAN_INGRESS(skb);
    bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
