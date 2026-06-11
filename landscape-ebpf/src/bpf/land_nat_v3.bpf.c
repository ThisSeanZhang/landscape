#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "land_nat4_v3.h"
#include "land_nat6_v3.h"
#include "landscape.h"
#include "nat/nat_packet.h"
#include "wan_tc_pipeline.h"

char LICENSE[] SEC("license") = "GPL";

#undef BPF_LOG_TOPIC

#define IPV4_NAT_EGRESS_PROG_INDEX 0
#define IPV4_NAT_INGRESS_PROG_INDEX 0
#define IPV6_NAT_EGRESS_PROG_INDEX 1
#define IPV6_NAT_INGRESS_PROG_INDEX 1

const volatile u32 current_l3_offset = 14;

SEC("tc/egress") int nat_v4_egress(struct __sk_buff *skb);
SEC("tc/ingress") int nat_v4_ingress(struct __sk_buff *skb);
SEC("tc/egress") int nat_v6_egress(struct __sk_buff *skb);
SEC("tc/ingress") int nat_v6_ingress(struct __sk_buff *skb);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __array(values, int());
} ingress_prog_array SEC(".maps") = {
    .values =
        {
            [IPV4_NAT_INGRESS_PROG_INDEX] = (void *)&nat_v4_ingress,
            [IPV6_NAT_INGRESS_PROG_INDEX] = (void *)&nat_v6_ingress,
        },
};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __array(values, int());
} egress_prog_array SEC(".maps") = {
    .values =
        {
            [IPV4_NAT_EGRESS_PROG_INDEX] = (void *)&nat_v4_egress,
            [IPV6_NAT_EGRESS_PROG_INDEX] = (void *)&nat_v6_egress,
        },
};

SEC("tc/egress")
int nat_v4_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v4_egress_v3 <<<"
    struct packet_offset_info pkg_offset = {0};
    struct inet4_pair ip_pair = {0};
    struct nat4_mapping_value_v3 *nat_egress_value = NULL;
    struct nat4_mapping_value_v3 *nat_ingress_value = NULL;
    struct nat4_port_queue_value_v3 alloc_item = {0};
    bool created = false;
    int ret = 0;

    ret = scan_nat_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = read_nat_packet_info4(skb, &pkg_offset, &ip_pair);
    if (ret) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = is_broadcast_ip4_pair(&ip_pair);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = frag_info_track_v4(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;

    bool is_icmpx_error = is_icmp_error_pkt(&pkg_offset);
    u8 nat_l4_protocol =
        is_icmpx_error ? pkg_offset.icmp_error_l4_protocol : pkg_offset.l4_protocol;
    bool allow_create_mapping = !is_icmpx_error && pkt_allow_initiating_ct(pkg_offset.pkt_type);

    ret = nat4_v3_egress_lookup_or_new_mapping_v4(skb, skb->ifindex, nat_l4_protocol,
                                                  allow_create_mapping, &ip_pair, &nat_egress_value,
                                                  &nat_ingress_value, &alloc_item, &created);
    if (ret != TC_ACT_OK || !nat_egress_value || !nat_ingress_value) {
        return TC_ACT_SHOT;
    }

    bool is_dynamic = nat_egress_value->is_static == 0;
    bool is_ancestor = ip_pair.dst_addr.addr == nat_egress_value->trigger_addr &&
                       ip_pair.dst_port == nat_egress_value->trigger_port;

    if (is_dynamic && nat_egress_value->is_allow_reuse == 0 && nat_l4_protocol != IPPROTO_ICMP) {
        if (!is_ancestor) {
            return TC_ACT_SHOT;
        }
    }

    if (is_dynamic && is_ancestor) {
        u8 allow = get_flow_allow_reuse_port(skb->mark) ? 1 : 0;
        nat_egress_value->is_allow_reuse = allow;
        nat_ingress_value->is_allow_reuse = allow;
    }

    struct inet4_addr nat_addr = {
        .addr = nat_egress_value->addr,
    };
    __be16 nat_port = nat_egress_value->port;
    if (!is_dynamic) {
        struct wan_ip_info_key wan_search_key = {
            .ifindex = skb->ifindex,
            .l3_protocol = LANDSCAPE_IPV4_TYPE,
        };
        struct wan_ip_info_value *wan_ip_info =
            bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
        if (!wan_ip_info) return TC_ACT_SHOT;
        nat_addr.addr = wan_ip_info->addr.ip;
    }

    struct inet4_pair server_nat_pair = {
        .src_addr = ip_pair.dst_addr,
        .src_port = ip_pair.dst_port,
        .dst_addr = nat_addr,
        .dst_port = nat_port,
    };
    if (nat_l4_protocol == IPPROTO_ICMP) {
        server_nat_pair.src_port = nat_port;
    }

    struct nat4_timer_value_v3 *ct_value = NULL;
    ret = nat4_v3_lookup_or_new_ct(skb, skb->ifindex, nat_l4_protocol, allow_create_mapping,
                                   &server_nat_pair, &ip_pair.src_addr, ip_pair.src_port,
                                   NAT_MAPPING_EGRESS, nat_ingress_value, &ct_value);
    if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
        if (created && is_dynamic &&
            nat_ingress_value->state_ref == nat4_v3_state_make(NAT4_V3_STATE_ACTIVE, 0)) {
            nat4_v3_delete_mapping_pair(nat_l4_protocol, nat_addr.addr, nat_port,
                                        ip_pair.src_addr.addr, ip_pair.src_port);
            (void)nat4_v3_queue_push(nat_l4_protocol, &alloc_item);
        }
        return TC_ACT_SHOT;
    }

    if (!is_icmpx_error) {
        ct_state_transition(pkg_offset.pkt_type, NAT_MAPPING_EGRESS, nat4_v3_timer_base(ct_value));
        nat_metric_accumulate(skb, false, nat4_v3_timer_base(ct_value));
    }

    struct nat_action_v4 action = {
        .from_addr = ip_pair.src_addr,
        .from_port = ip_pair.src_port,
        .to_addr = nat_addr,
        .to_port = nat_port,
    };

    ret = modify_headers_v4(skb, is_icmpx_error, nat_l4_protocol, current_l3_offset,
                            pkg_offset.l4_offset, pkg_offset.icmp_error_inner_l4_offset, true,
                            &action);
    return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT,
                                           ret ? TC_ACT_SHOT : TC_ACT_UNSPEC);
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int nat_v4_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v4_ingress_v3 >>>"
    struct packet_offset_info pkg_offset = {0};
    struct inet4_pair ip_pair = {0};
    struct nat4_mapping_value_v3 *nat_ingress_value = NULL;
    int ret = 0;

    ret = scan_nat_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = read_nat_packet_info4(skb, &pkg_offset, &ip_pair);
    if (ret) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = is_broadcast_ip4_pair(&ip_pair);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = frag_info_track_v4(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;

    bool is_icmpx_error = is_icmp_error_pkt(&pkg_offset);
    u8 nat_l4_protocol =
        is_icmpx_error ? pkg_offset.icmp_error_l4_protocol : pkg_offset.l4_protocol;

    ret = nat4_v3_ingress_lookup_or_new_mapping4(nat_l4_protocol, &ip_pair, &nat_ingress_value);
    if (ret != TC_ACT_OK || !nat_ingress_value) {
        return TC_ACT_SHOT;
    }

    bool is_static = nat_ingress_value->is_static != 0;

    if (!is_static && nat_ingress_value->is_allow_reuse == 0 && nat_l4_protocol != IPPROTO_ICMP) {
        if (ip_pair.src_addr.addr != nat_ingress_value->trigger_addr ||
            ip_pair.src_port != nat_ingress_value->trigger_port) {
            return TC_ACT_SHOT;
        }
    }

    if (is_static) {
        u32 mark = skb->mark;
        barrier_var(mark);
        skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
    }

    struct inet4_addr lan_ip = {0};
    __be16 lan_port = 0;
    if (is_static && nat_ingress_value->addr == 0) {
        lan_ip.addr = ip_pair.dst_addr.addr;
    } else {
        lan_ip.addr = nat_ingress_value->addr;
    }
    lan_port = nat_ingress_value->port;

    struct inet4_pair server_nat_pair = {
        .src_addr = ip_pair.src_addr,
        .src_port = ip_pair.src_port,
        .dst_addr = ip_pair.dst_addr,
        .dst_port = ip_pair.dst_port,
    };

    u64 ingress_state_ref = nat_ingress_value->state_ref;
    bool do_new_ct = is_static ? (!is_icmpx_error && pkt_allow_initiating_ct(pkg_offset.pkt_type))
                               : (nat_ingress_value->is_allow_reuse &&
                                  nat4_v3_state_get(ingress_state_ref) == NAT4_V3_STATE_ACTIVE &&
                                  nat4_v3_ref_get(ingress_state_ref) > 0 && !is_icmpx_error &&
                                  pkt_allow_initiating_ct(pkg_offset.pkt_type));

    struct nat4_timer_value_v3 *ct_value = NULL;
    ret = nat4_v3_lookup_or_new_ct(skb, skb->ifindex, nat_l4_protocol, do_new_ct, &server_nat_pair,
                                   &lan_ip, lan_port, NAT_MAPPING_INGRESS, nat_ingress_value,
                                   &ct_value);
    if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
        return TC_ACT_SHOT;
    }

    if (!is_icmpx_error) {
        ct_state_transition(pkg_offset.pkt_type, NAT_MAPPING_INGRESS, nat4_v3_timer_base(ct_value));
        nat_metric_accumulate(skb, true, nat4_v3_timer_base(ct_value));
    }

    struct nat_action_v4 action = {
        .from_addr = ip_pair.dst_addr,
        .from_port = ip_pair.dst_port,
        .to_addr = lan_ip,
        .to_port = lan_port,
    };

    ret = modify_headers_v4(skb, is_icmpx_error, nat_l4_protocol, current_l3_offset,
                            pkg_offset.l4_offset, pkg_offset.icmp_error_inner_l4_offset, false,
                            &action);
    return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT,
                                            ret ? TC_ACT_SHOT : TC_ACT_UNSPEC);
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int nat_v6_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v6_egress_v3 <<<"
    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    ret = scan_nat_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = read_nat_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = is_broadcast_ip_pair(pkg_offset.l3_protocol, &ip_pair);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, ret);
    ret = frag_info_track(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    return wan_tc_pipeline_continue_egress(
        skb, EGRESS_STAGE_NAT,
        ipv6_egress_prefix_check_and_replace(skb, &pkg_offset, &ip_pair, skb->ifindex));
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int nat_v6_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v6_ingress_v3 >>>"
    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    ret = scan_nat_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = read_nat_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = is_broadcast_ip_pair(pkg_offset.l3_protocol, &ip_pair);
    if (ret != TC_ACT_OK) return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, ret);
    ret = frag_info_track(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) return TC_ACT_SHOT;
    return wan_tc_pipeline_continue_ingress(
        skb, INGRESS_STAGE_NAT,
        ipv6_ingress_prefix_check_and_replace(skb, &pkg_offset, &ip_pair, skb->ifindex));
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int ingress_nat(struct __sk_buff *skb) {
    bool is_ipv4;
    int ret;

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) return ret;
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK))
        return wan_tc_pipeline_continue_ingress(skb, INGRESS_STAGE_NAT, TC_ACT_UNSPEC);

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ingress_prog_array, IPV4_NAT_INGRESS_PROG_INDEX);
    } else {
        bpf_tail_call_static(skb, &ingress_prog_array, IPV6_NAT_INGRESS_PROG_INDEX);
    }

    return TC_ACT_SHOT;
}

SEC("tc/egress")
int egress_nat(struct __sk_buff *skb) {
    bool is_ipv4;
    int ret;

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) return ret;
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK))
        return wan_tc_pipeline_continue_egress(skb, EGRESS_STAGE_NAT, TC_ACT_UNSPEC);

    if (is_ipv4) {
        bpf_tail_call_static(skb, &egress_prog_array, IPV4_NAT_EGRESS_PROG_INDEX);
    } else {
        bpf_tail_call_static(skb, &egress_prog_array, IPV6_NAT_EGRESS_PROG_INDEX);
    }

    return TC_ACT_SHOT;
}
