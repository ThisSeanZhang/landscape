#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "base/landscape.h"
#include "route/route4_path.h"
#include "route/route6_path.h"
#include "route/route4_context.h"
#include "route/route6_context.h"

#include "chain/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

// ── WAN egress route ──
//
// Attached to TC egress.  `tc_wan_egress_route` decides the destination
// (local outbound routing / forwarded handoff) and tail-calls the v4/v6 route
// worker (tc_route4/6_wan_egress) through the static `ls_wan_e_tails` prog
// array; the workers tail-call into the per-link egress chain roots
// (tc_wan_egress_roots, keyed by the WAN link's chain id).  This is the
// "route" role for egress: routing happens before the chain.

const volatile u32 current_l3_offset = 14;

#define TC_EGRESS_V4_SLOT 0
#define TC_EGRESS_V6_SLOT 1
#define TC_EGRESS_DIRECT_V4_SLOT 2
#define TC_EGRESS_DIRECT_V6_SLOT 3

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_wan_egress_roots SEC(".maps");

// ── tc_pick_wan: adapted from pick_wan_and_send_by_flow_id, always tailcalls to target root ──

static __always_inline int tc_route4_pick_wan_in_wan_egress(struct __sk_buff *skb,
                                                            u32 current_l3_offset,
                                                            const struct route4_context *context,
                                                            const u32 flow_id) {
    int ret;
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route4_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route4_target_slot(context->daddr),
    };
    struct route4_target_info *target_info = bpf_map_lookup_elem(&rt4_slot_map, &slot_key);

    if (target_info == NULL) {
        if (resolved_flow_id == 0) {
            ld_from_wan_log("DROP default flow v4, no target for: %pI4 -> %pI4", &context->saddr,
                            &context->daddr);
            return TC_ACT_SHOT;
        }
        ld_from_wan_log("DROP flow_id v4: %d, ip: %pI4 -> %pI4", resolved_flow_id, &context->saddr,
                        &context->daddr);
        return TC_ACT_SHOT;
    }

    if (target_info->ifindex != skb->ifindex) {
        if (current_l3_offset == 0 && target_info->has_mac) {
            if (prepend_dummy_mac(skb) != 0) {
                ld_from_wan_log("add dummy_mac fail");
                return TC_ACT_SHOT;
            }
        }

        if (target_info->is_docker) {
            ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
            if (ret) ld_from_wan_log("bpf_skb_vlan_push error");
            return bpf_redirect(target_info->ifindex, 0);
        }

        bool mac_stored = !target_info->has_mac;
        if (target_info->has_mac) {
            struct mac_value_v4 *mac_value =
                bpf_map_lookup_elem(&ip_mac_v4, &target_info->gate_addr);
            if (mac_value) {
                ret = store_mac_v4(skb, mac_value->mac, target_info->mac);
                if (!ret) {
                    mac_stored = true;
                } else {
                    ld_from_wan_log("store_mac_v4 err: %d", ret);
                }
            } else {
                ld_from_wan_log("can't find mac by: %pI4", &target_info->gate_addr);
            }
        }

        tc_cb_mark_forwarded(skb, target_info->link_chain_id);

        if (mac_stored) {
            return bpf_redirect(target_info->ifindex, 0);
        }

        struct bpf_redir_neigh param;
        param.nh_family = AF_INET;
        param.ipv4_nh = target_info->gate_addr;
        ret = bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
        if (unlikely(ret != TC_ACT_REDIRECT)) {
            ld_from_wan_log("bpf_redirect_neigh error: %d", ret);
        }
        return ret;
    }

    bpf_tail_call(skb, &tc_wan_egress_roots, target_info->link_chain_id);
    return TC_ACT_SHOT;
}

static __always_inline int tc_route6_pick_wan_in_wan_egress(struct __sk_buff *skb,
                                                            u32 current_l3_offset,
                                                            const struct route6_context *context,
                                                            const u32 flow_id) {
    int ret;
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route6_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route6_target_slot(&context->daddr),
    };
    struct route6_target_info *target_info = bpf_map_lookup_elem(&rt6_slot_map, &slot_key);

    if (target_info == NULL) {
        if (resolved_flow_id == 0) {
            ld_from_wan_log("DROP default flow v6, no target");
            return TC_ACT_SHOT;
        }
        ld_from_wan_log("DROP flow_id v6: %d", resolved_flow_id);
        return TC_ACT_SHOT;
    }

    if (target_info->ifindex != skb->ifindex) {
        if (current_l3_offset == 0 && target_info->has_mac) {
            if (prepend_dummy_mac_v6(skb) != 0) {
                ld_from_wan_log("add dummy_mac fail");
                return TC_ACT_SHOT;
            }
        }

        if (target_info->is_docker) {
            ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
            if (ret) ld_from_wan_log("bpf_skb_vlan_push error");
            return bpf_redirect(target_info->ifindex, 0);
        }

        bool mac_stored = !target_info->has_mac;
        if (target_info->has_mac) {
            struct mac_value_v6 *mac_value =
                bpf_map_lookup_elem(&ip_mac_v6, &target_info->gate_addr);
            if (mac_value) {
                ret = store_mac_v6(skb, mac_value->mac, target_info->mac);
                if (!ret) {
                    mac_stored = true;
                } else {
                    ld_from_wan_log("store_mac_v6 err: %d", ret);
                }
            } else {
                ld_from_wan_log("can't find mac by: %pI6", &target_info->gate_addr);
            }
        }

        tc_cb_mark_forwarded(skb, target_info->link_chain_id);

        if (mac_stored) return bpf_redirect(target_info->ifindex, 0);

        struct bpf_redir_neigh param;
        param.nh_family = AF_INET6;
        COPY_ADDR_FROM(param.ipv6_nh, target_info->gate_addr.in6_u.u6_addr32);
        ret = bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
        if (unlikely(ret != TC_ACT_REDIRECT)) ld_from_wan_log("bpf_redirect_neigh error: %d", ret);
        return ret;
    }

    bpf_tail_call(skb, &tc_wan_egress_roots, target_info->link_chain_id);
    return TC_ACT_SHOT;
}

// ── route workers ──

SEC("tc/egress")
int tc_route4_wan_egress(struct __sk_buff *skb) {
    int ret = 0;
    u32 flow_mark = skb_mark(skb);
    struct route4_context context = {0};
    struct route_view view = {0};

    ret = scan_route_packet(skb, current_l3_offset, &view);
    if (ret == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route4_read_context_from_scan(skb, &view, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (unlikely(is_broadcast_ip4(context.daddr))) {
        return TC_ACT_UNSPEC;
    }

    ret = tc_route4_lan_redirect_check_in_wan_egress(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }
    skb_set_mark(skb, flow_mark);

    ret = tc_route4_pick_wan_in_wan_egress(skb, current_l3_offset, &context, flow_mark);

    return ret;
}

SEC("tc/egress")
int tc_route4_wan_direct_egress(struct __sk_buff *skb) {
    int ret = 0;
    u32 flow_mark = skb_mark(skb);
    struct route4_context context = {0};
    struct route_view view = {0};

    ret = scan_route_packet(skb, current_l3_offset, &view);
    if (ret == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route4_read_context_from_scan(skb, &view, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (unlikely(is_broadcast_ip4(context.daddr))) {
        return TC_ACT_UNSPEC;
    }

    ret = tc_route4_lan_redirect_check_in_wan_egress(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = tc_route4_pick_wan_in_wan_egress(skb, current_l3_offset, &context, flow_mark);

    return ret;
}

SEC("tc/egress")
int tc_route6_wan_egress(struct __sk_buff *skb) {
    int ret = 0;
    u32 flow_mark = skb_mark(skb);
    struct route6_context context = {0};
    struct route_view view = {0};

    ret = scan_route_packet(skb, current_l3_offset, &view);
    if (ret == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route6_read_context_from_scan(skb, &view, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (unlikely(is_broadcast_ip6(context.daddr.in6_u.u6_addr8))) {
        return TC_ACT_UNSPEC;
    }

    ret = tc_route6_lan_redirect_check_in_wan_egress(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }
    skb_set_mark(skb, flow_mark);

    ret = tc_route6_pick_wan_in_wan_egress(skb, current_l3_offset, &context, flow_mark);

    return ret;
}

SEC("tc/egress")
int tc_route6_wan_direct_egress(struct __sk_buff *skb) {
    int ret = 0;
    u32 flow_mark = skb_mark(skb);
    struct route6_context context = {0};
    struct route_view view = {0};

    ret = scan_route_packet(skb, current_l3_offset, &view);
    if (ret == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route6_read_context_from_scan(skb, &view, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (unlikely(is_broadcast_ip6(context.daddr.in6_u.u6_addr8))) {
        return TC_ACT_UNSPEC;
    }

    ret = tc_route6_lan_redirect_check_in_wan_egress(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = tc_route6_pick_wan_in_wan_egress(skb, current_l3_offset, &context, flow_mark);

    return ret;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(__u32));
    __array(values, int());
} ls_wan_e_tails SEC(".maps") = {
    .values =
        {
            [TC_EGRESS_V4_SLOT] = (void *)&tc_route4_wan_egress,
            [TC_EGRESS_V6_SLOT] = (void *)&tc_route6_wan_egress,
            [TC_EGRESS_DIRECT_V4_SLOT] = (void *)&tc_route4_wan_direct_egress,
            [TC_EGRESS_DIRECT_V6_SLOT] = (void *)&tc_route6_wan_direct_egress,
        },
};

SEC("tc/egress")
int tc_wan_egress_route(struct __sk_buff *skb) {
    // Already routed by a landscape pick_wan: enter the target link's
    // chain directly, the decision (and its chain id) travels in cb.
    if (tc_cb_forwarded(skb)) {
        u32 chain = tc_cb_chain(skb);
        bpf_tail_call(skb, &tc_wan_egress_roots, chain);
        ld_from_wan_log("WAN-E ROOT-TAIL-FAILED chain %u", chain);
        return TC_ACT_SHOT;
    }

    bool is_ipv4;
    int ret;

    // Host-originated control plane with a direct chain assignment:
    // SO_MARK in the HostDirect layout (bits 0-15 = chain id), e.g. the
    // DHCPv6-PD socket of a native PPPoE link.  The policy stages
    // self-skip on this mark (base/mark.h), so the packet rides the
    // chain's terminal (PPP encapsulation) and exits untouched.
    u32 mark = skb_mark(skb);
    if (unlikely(is_host_direct(mark))) {
        u32 chain = get_host_direct_chain_id(mark);
        bpf_tail_call(skb, &tc_wan_egress_roots, chain);
        ld_from_wan_log("host-direct root tail failed chain %u; passing", chain);
        return TC_ACT_UNSPEC;
    }

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) {
            return TC_ACT_UNSPEC;
        }
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK)) {
        return TC_ACT_OK;
    }

    // LAN-originated forwarded handoff: traffic from LAN ifaces without
    // an XDP fast path arrives here through the TC redirect.  The LAN
    // side already ran its flow verdict and stamped the mark, so the
    // direct workers skip the verdict and hand the preserved flow id to
    // pick_wan (flow-0 default slots when the mark carries none).
    if (likely(skb->ingress_ifindex != 0)) {
        if (is_ipv4) {
            bpf_tail_call_static(skb, &ls_wan_e_tails, TC_EGRESS_DIRECT_V4_SLOT);
            bpf_printk("bpf_tail_call_static error");
        } else {
            bpf_tail_call_static(skb, &ls_wan_e_tails, TC_EGRESS_DIRECT_V6_SLOT);
            bpf_printk("bpf_tail_call_static error");
        }
    }

    // Locally originated: resolve the flow target (or the default one)
    // and either redirect cross-WAN or enter this link's chain from the
    // slot target.
    if (is_ipv4) {
        bpf_tail_call_static(skb, &ls_wan_e_tails, TC_EGRESS_V4_SLOT);
        bpf_printk("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ls_wan_e_tails, TC_EGRESS_V6_SLOT);
        bpf_printk("bpf_tail_call_static error");
    }

    return TC_ACT_SHOT;
}
