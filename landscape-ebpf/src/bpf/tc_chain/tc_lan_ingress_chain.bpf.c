#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "route_v4.h"
#include "route_v6.h"
#include "route/route_packet.h"

#include "pipeline/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_TOPIC

#define TC_LAN_INGRESS_V4_SLOT 0
#define TC_LAN_INGRESS_V6_SLOT 1

static __always_inline int tc_lan_redirect_v4(struct __sk_buff *skb, u32 current_l3_offset,
                                              struct route_context_v4 *context) {
#define BPF_LOG_TOPIC "tc_lan_redirect_v4"
    int ret;
    struct lan_route_key_v4 lan_search_key = {0};
    struct mac_key_v4 mac_key_search = {0};
    struct mac_value_v4 *mac_value = NULL;

    lan_search_key.prefixlen = 32;
    lan_search_key.addr = context->daddr;

    struct lan_route_info_v4 *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &lan_search_key);

    if (lan_info == NULL) {
        return TC_ACT_OK;
    }

    if (lan_info->route_type == ROUTE_TYPE_WAN) return TC_ACT_UNSPEC;

    if (unlikely(lan_info->ifindex == skb->ingress_ifindex)) {
        return TC_ACT_UNSPEC;
    }

    if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr) {
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0 && lan_info->has_mac) {
        unsigned char ethhdr[14];
        ethhdr[12] = 0x08;
        ethhdr[13] = 0x00;

        if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;
        if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
    }

    bool target_has_mac = lan_info->has_mac;
    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        mac_key_search.addr = lan_info->addr;
    } else {
        mac_key_search.addr = context->daddr;
    }

    if (target_has_mac) {
        mac_value = bpf_map_lookup_elem(&ip_mac_v4, &mac_key_search);
        if (mac_value) {
            ret = store_mac_v4(skb, mac_value->mac, lan_info->mac_addr);
            if (!ret) return bpf_redirect(lan_info->ifindex, 0);
            ld_bpf_log("store_mac_v4 err: %d", ret);
        } else {
            ld_bpf_log("can't find mac, IP: %pI4", &mac_key_search.addr);
        }
    } else {
        return bpf_redirect(lan_info->ifindex, 0);
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET;

    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        param.ipv6_nh[0] = lan_info->addr;
    } else {
        param.ipv6_nh[0] = lan_search_key.addr;
    }

    ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
    if (unlikely(ret != 7)) {
        ld_bpf_log("bpf_redirect_neigh error: %d", ret);
    }

    return ret;
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_lan_redirect_v6(struct __sk_buff *skb, u32 current_l3_offset,
                                              struct route_context_v6 *context) {
#define BPF_LOG_TOPIC "tc_lan_redirect_v6"
    int ret;
    struct lan_route_key_v6 lan_search_key = {0};
    struct mac_key_v6 mac_key_search = {0};
    struct mac_value_v6 *mac_value = NULL;

    lan_search_key.prefixlen = 128;
    COPY_ADDR_FROM(lan_search_key.addr.bytes, context->daddr.bytes);

    struct lan_route_info_v6 *lan_info = bpf_map_lookup_elem(&rt6_lan_map, &lan_search_key);

    if (lan_info == NULL) return TC_ACT_OK;

    if (lan_info->route_type == ROUTE_TYPE_WAN) return TC_ACT_UNSPEC;

    if (unlikely(lan_info->ifindex == skb->ingress_ifindex)) return TC_ACT_UNSPEC;

    if (lan_info->route_type == ROUTE_TYPE_LAN &&
        ip_addr_equal_in6(&lan_info->addr, &context->daddr))
        return TC_ACT_UNSPEC;

    if (current_l3_offset == 0 && lan_info->has_mac) {
        unsigned char ethhdr[14];
        ethhdr[12] = 0x86;
        ethhdr[13] = 0xdd;

        if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;
        if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
    }

    bool target_has_mac = lan_info->has_mac;
    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        COPY_ADDR_FROM(mac_key_search.addr.all, lan_info->addr.all);
    } else {
        COPY_ADDR_FROM(mac_key_search.addr.all, context->daddr.all);
    }

    if (target_has_mac) {
        mac_value = bpf_map_lookup_elem(&ip_mac_v6, &mac_key_search);
        if (mac_value) {
            ret = store_mac_v6(skb, mac_value->mac, lan_info->mac_addr);
            if (!ret) return bpf_redirect(lan_info->ifindex, 0);
            ld_bpf_log("store_mac_v6 err: %d", ret);
        } else {
            ld_bpf_log("can't find mac, IP: %pI6", &mac_key_search.addr);
        }
    } else {
        return bpf_redirect(lan_info->ifindex, 0);
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET6;

    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        COPY_ADDR_FROM(param.ipv6_nh, lan_info->addr.all);
    } else {
        COPY_ADDR_FROM(param.ipv6_nh, lan_search_key.addr.all);
    }

    ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
    if (unlikely(ret != 7)) {
        ld_bpf_log("bpf_redirect_neigh error: %d", ret);
    }

    return ret;
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_pick_wan_v4(struct __sk_buff *skb, u32 current_l3_offset,
                                          const struct route_context_v4 *context,
                                          const u32 flow_id) {
#define BPF_LOG_TOPIC "tc_pick_wan_v4"
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route_target_slot_key_v4 slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route_target_slot_v4(context->daddr),
    };
    struct route_target_info_v4 *target_info = bpf_map_lookup_elem(&rt4_target_slot_map, &slot_key);

    if (target_info == NULL) {
        if (resolved_flow_id == 0) return TC_ACT_OK;
        ld_bpf_log("DROP flow_id v4: %d, ip: %pI4", resolved_flow_id, &context->saddr);
        return TC_ACT_SHOT;
    }

    if (target_info->ifindex != skb->ingress_ifindex) {
        if (current_l3_offset == 0 && target_info->has_mac) {
            if (prepend_dummy_mac(skb) != 0) {
                ld_bpf_log("add dummy_mac fail");
                return TC_ACT_SHOT;
            }
        }

        if (target_info->is_docker) {
            int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
            if (ret) ld_bpf_log("bpf_skb_vlan_push error");
            return bpf_redirect(target_info->ifindex, 0);
        }

        if (target_info->has_mac) {
            struct mac_value_v4 *mac_value =
                bpf_map_lookup_elem(&ip_mac_v4, &target_info->gate_addr);
            if (mac_value) {
                int ret = store_mac_v4(skb, mac_value->mac, target_info->mac);
                if (ret) ld_bpf_log("store_mac_v4 err: %d", ret);
            } else {
                ld_bpf_log("can't find mac by: %pI4", &target_info->gate_addr);
            }
        }
    }

    skb->cb[TC_CHAIN_CB_FORWARDED_OFFSET] = 1;
    return bpf_redirect(target_info->ifindex, 0);
#undef BPF_LOG_TOPIC
}

static __always_inline int tc_pick_wan_v6(struct __sk_buff *skb, u32 current_l3_offset,
                                          const struct route_context_v6 *context,
                                          const u32 flow_id) {
#define BPF_LOG_TOPIC "tc_pick_wan_v6"
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route_target_slot_key_v6 slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route_target_slot_v6(&context->daddr),
    };
    struct route_target_info_v6 *target_info = bpf_map_lookup_elem(&rt6_target_slot_map, &slot_key);

    if (target_info == NULL) {
        if (resolved_flow_id == 0) return TC_ACT_OK;
        ld_bpf_log("DROP flow_id v6: %d", resolved_flow_id);
        return TC_ACT_SHOT;
    }

    if (target_info->ifindex != skb->ingress_ifindex) {
        if (current_l3_offset == 0 && target_info->has_mac) {
            if (prepend_dummy_mac_v6(skb) != 0) {
                ld_bpf_log("add dummy_mac fail");
                return TC_ACT_SHOT;
            }
        }

        if (target_info->is_docker) {
            int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
            if (ret) ld_bpf_log("bpf_skb_vlan_push error");
            return bpf_redirect(target_info->ifindex, 0);
        }

        if (target_info->has_mac) {
            struct mac_value_v6 *mac_value =
                bpf_map_lookup_elem(&ip_mac_v6, &target_info->gate_addr);
            if (mac_value) {
                int ret = store_mac_v6(skb, mac_value->mac, target_info->mac);
                if (ret) ld_bpf_log("store_mac_v6 err: %d", ret);
            } else {
                ld_bpf_log("can't find mac by: %pI6", &target_info->gate_addr);
            }
        }
    }

    skb->cb[TC_CHAIN_CB_FORWARDED_OFFSET] = 1;
    return bpf_redirect(target_info->ifindex, 0);
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_lan_ingress_route_v4(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_lan_ingress_route_v4"
    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v4 context = {0};
    struct packet_offset_info offset_info = {0};

    ret = scan_route_packet(skb, current_l3_offset, &offset_info);
    if (ret == LD_SCAN_ERR) {
        return TC_ACT_SHOT;
    }
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = read_route_context_v4_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route_should_forward_v4(&context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = tc_lan_redirect_v4(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = flow_verdict_v4(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_WAN);

    ret = tc_pick_wan_v4(skb, current_l3_offset, &context, flow_mark);

    return ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_lan_ingress_route_v6(struct __sk_buff *skb) {
    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v6 context = {0};
    struct packet_offset_info offset_info = {0};

    ret = scan_route_packet(skb, current_l3_offset, &offset_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = read_route_context_v6_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route_should_forward_v6(&context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = tc_lan_redirect_v6(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = flow_verdict_v6(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_WAN);

    ret = tc_pick_wan_v6(skb, current_l3_offset, &context, flow_mark);

    return ret;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(__u32));
    __array(values, int());
} ls_lan_ingress_tails SEC(".maps") = {
    .values =
        {
            [TC_LAN_INGRESS_V4_SLOT] = (void *)&tc_lan_ingress_route_v4,
            [TC_LAN_INGRESS_V6_SLOT] = (void *)&tc_lan_ingress_route_v6,
        },
};

SEC("tc/ingress")
int tc_lan_ingress_intro(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_lan_ingress_intro"
    bool is_ipv4;
    int ret;

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) {
            return ret;
        }
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK)) {
        return TC_ACT_OK;
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ls_lan_ingress_tails, TC_LAN_INGRESS_V4_SLOT);
        ld_bpf_log("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ls_lan_ingress_tails, TC_LAN_INGRESS_V6_SLOT);
        ld_bpf_log("bpf_tail_call_static error");
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
