#include "vmlinux_wrapper.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "land_nat_common.h"
#include "nat/nat_maps.h"
#include "land_nat_v6.h"
#include "land_nat_v4.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

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

#define NAT_MAPPING_CACHE_SIZE 1024 * 64 * 2
#define NAT_MAPPING_TIMER_SIZE 1024 * 64 * 2

SEC("tc/egress")
int nat_v4_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v4_egress <<<"
    struct packet_offset_info pkg_offset = {0};
    struct inet4_pair ip_pair = {0};
    int ret = 0;

    ret = scan_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = read_packet_info4(skb, &pkg_offset, &ip_pair);
    if (ret) {
        return ret;
    }

    ret = is_broadcast_ip4_pair(&ip_pair);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = frag_info_track_v4(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }

    // bpf_log_info("packet :%pI4 : %u -> %pI4 : %u", ip_pair.src_addr.all,
    //              bpf_ntohs(ip_pair.src_port), ip_pair.dst_addr.all, bpf_ntohs(ip_pair.dst_port));

    // bpf_log_info("packet pkt_type: %d", packet_info.pkt_type);
    // bpf_log_info("icmp_error_payload_offset: %d", packet_info.icmp_error_payload_offset);

    bool is_icmpx_error = is_icmp_error_pkt(&pkg_offset);
    bool allow_create_mapping = !is_icmpx_error && pkt_allow_initiating_ct(pkg_offset.pkt_type);

    // egress  : Ac:Pc -> An:Pn
    // ingress : An:Pn -> Ac:Pc
    struct nat_mapping_value_v4 *nat_egress_value, *nat_ingress_value;

    ret = lookup_static_mapping_v4(skb, pkg_offset.l4_protocol, NAT_MAPPING_EGRESS, &ip_pair,
                                   &nat_ingress_value, &nat_egress_value);

    if (ret != TC_ACT_OK) {
        ret = egress_lookup_or_new_mapping_v4(skb, pkg_offset.l4_protocol, allow_create_mapping,
                                              &ip_pair, &nat_egress_value, &nat_ingress_value);

        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }

        // bool allow_reuse_port = get_flow_allow_reuse_port(skb->mark);
        // if (allow_reuse_port) {
        //     bpf_log_info("allow_reuse_port: %u, skb->mark: %u", allow_reuse_port, skb->mark);
        // }
        if (nat_egress_value->is_allow_reuse == 0 && pkg_offset.l4_protocol != IPPROTO_ICMP) {
            // PORT REUSE check
            if (!inet4_addr_equal(&ip_pair.dst_addr, &nat_egress_value->trigger_addr) ||
                ip_pair.dst_port != nat_egress_value->trigger_port) {
                bpf_log_info("FLOW_ALLOW_REUSE MARK not set, DROP PACKET");
                bpf_log_info("dst IP: %pI4,", &ip_pair.dst_addr);
                bpf_log_info("trg IP: %pI4,", &nat_egress_value->trigger_addr);
                bpf_log_info("trg port: %u,", bpf_ntohs(nat_egress_value->trigger_port));
                bpf_log_info("dst port: %u,", bpf_ntohs(ip_pair.dst_port));
                return TC_ACT_SHOT;
            }
        }

        // bpf_log_info("ingress value, %pI4 : %u", &nat_ingress_value->addr,
        //              bpf_ntohs(nat_ingress_value->port));
        // bpf_log_info("egress  value, %pI4 : %u", &nat_egress_value->addr.ip,
        //              bpf_ntohs(nat_egress_value->port));

        if (!nat_egress_value->is_static) {
            struct nat4_ct_value *ct_value;
            ret = lookup_or_new_ct4(pkg_offset.l4_protocol, allow_create_mapping, &ip_pair,
            //                         nat_egress_value, nat_ingress_value, &ct_value);

            // ret = lookup_or_new_ct(skb, pkg_offset.l4_protocol, allow_create_mapping, &ip_pair,
                                   nat_egress_value, nat_ingress_value, &ct_value);
            if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
                return TC_ACT_SHOT;
            }
            if (!is_icmpx_error || ct_value != NULL) {
                // ct_state_transition_v4(pkg_offset.l4_protocol, pkg_offset.pkt_type,
                //                        NAT_MAPPING_INGRESS, ct_value);
                ct_state_transition(pkg_offset.l4_protocol, pkg_offset.pkt_type, NAT_MAPPING_EGRESS,
                                    ct_value);
                nat_metric_accumulate(skb, false, ct_value);
            }
        }
    }

    // bpf_log_info("packet src port: %u -> %u", bpf_ntohs(ip_pair.src_port),
    //              bpf_ntohs(ip_pair.dst_port));
    // bpf_log_info("modify src port:  %u -> %u", bpf_ntohs(nat_egress_value->port),
    //              bpf_ntohs(ip_pair.dst_port));

    // bpf_log_info("src IP: %pI4,", &ip_pair.src_addr);
    // bpf_log_info("dst IP: %pI4,", &ip_pair.dst_addr);
    // bpf_log_info("mapping IP: %pI4,", &nat_egress_value->addr);

    if (nat_egress_value == NULL) {
        bpf_log_info("nat_egress_value is null");
        return TC_ACT_SHOT;
    }

    struct inet4_addr nat_addr;
    if (nat_egress_value->is_static) {
        struct wan_ip_info_key wan_search_key = {0};
        wan_search_key.ifindex = skb->ifindex;
        wan_search_key.l3_protocol = LANDSCAPE_IPV4_TYPE;

        struct wan_ip_info_value *wan_ip_info =
            bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
        if (!wan_ip_info) {
            bpf_log_info("can't find the wan ip, using ifindex: %d", skb->ifindex);
            return TC_ACT_SHOT;
        }
        nat_addr.addr = wan_ip_info->addr.ip;
    } else {
        nat_addr.addr = nat_egress_value->addr;
    }

    // bpf_log_info("nat_ip IP: %pI4:%u", &nat_addr.all, bpf_ntohs(nat_egress_value->port));

    // modify source
    ret = modify_headers_v4(skb, is_icmpx_error, pkg_offset.l4_protocol, current_l3_offset,
                            pkg_offset.l4_offset, pkg_offset.icmp_error_inner_l4_offset, true,
                            &ip_pair.src_addr, ip_pair.src_port, &nat_addr, nat_egress_value->port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int nat_v4_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v4_ingress >>>"

    struct packet_offset_info pkg_offset = {0};
    struct inet4_pair ip_pair = {0};
    int ret = 0;

    ret = scan_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = read_packet_info4(skb, &pkg_offset, &ip_pair);
    if (ret) {
        return ret;
    }

    ret = is_broadcast_ip4_pair(&ip_pair);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = frag_info_track_v4(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }

    bool is_icmpx_error = is_icmp_error_pkt(&pkg_offset);
    bool allow_create_mapping = !is_icmpx_error && pkg_offset.l4_protocol == IPPROTO_ICMP;

    // egress  : Ac:Pc -> An:Pn
    // ingress : An:Pn -> Ac:Pc
    struct nat_mapping_value_v4 *nat_egress_value, *nat_ingress_value;

    // 先检查是否有静态映射
    ret = lookup_static_mapping_v4(skb, pkg_offset.l4_protocol, NAT_MAPPING_INGRESS, &ip_pair,
                                   &nat_ingress_value, &nat_egress_value);
    if (ret != TC_ACT_OK) {
        ret = ingress_lookup_or_new_mapping4(skb, pkg_offset.l4_protocol, allow_create_mapping,
                                             &ip_pair, &nat_egress_value, &nat_ingress_value);

        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }

        // bpf_log_info("ingress value, %pI4 : %u", &nat_ingress_value->addr,
        //              bpf_ntohs(nat_ingress_value->port));
        // bpf_log_info("egress  value, %pI4 : %u", &nat_egress_value->addr.ip,
        //              bpf_ntohs(nat_egress_value->port));

        if (!nat_egress_value->is_static) {
            struct nat_timer_value *ct_timer_value;
            ret = lookup_or_new_ct4(pkg_offset.l4_protocol, allow_create_mapping, &ip_pair,
            //                        nat_egress_value, nat_ingress_value, &ct_timer_value);
            // ret = lookup_or_new_ct(skb, pkg_offset.l4_protocol, allow_create_mapping, &ip_pair,
                                   nat_egress_value, nat_ingress_value, &ct_timer_value);
            if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
                bpf_log_info("connect ret :%u", ret);
                return TC_ACT_SHOT;
            }
            if (!is_icmpx_error || ct_timer_value != NULL) {
                // ct_state_transition_v4(pkg_offset.l4_protocol, pkg_offset.pkt_type,
                // NAT_MAPPING_EGRESS,
                //                     ct_timer_value);

                ct_state_transition(pkg_offset.l4_protocol, pkg_offset.pkt_type,
                                    NAT_MAPPING_INGRESS, ct_timer_value);
                nat_metric_accumulate(skb, true, ct_timer_value);
            }
        }
        // } else {
        //     bpf_log_info("packet dst port: %u -> %u", bpf_ntohs(ip_pair.src_port),
        //                  bpf_ntohs(ip_pair.dst_port));
        //     bpf_log_info("modify dst port:  %u -> %u", bpf_ntohs(ip_pair.src_port),
        //                  bpf_ntohs(nat_ingress_value->port));

        //     bpf_log_info("src IP: %pI4,", &ip_pair.src_addr);
        //     bpf_log_info("dst IP: %pI4,", &ip_pair.dst_addr);
        //     bpf_log_info("real IP: %pI4,", &nat_ingress_value->addr);
    }

    if (nat_ingress_value == NULL) {
        bpf_log_info("nat_ingress_value is null");
        return TC_ACT_SHOT;
    }

    struct inet4_addr lan_ip;
    if (nat_ingress_value->is_static && nat_ingress_value->addr == 0) {
        lan_ip.addr = ip_pair.dst_addr.addr;
    } else {
        lan_ip.addr = nat_ingress_value->addr;
    }

    // if (nat_ingress_value->is_static && nat_ingress_value->addr.ip != 0) {
    //     bpf_log_info("lan_ip IP: %pI4:%u", &lan_ip.all, bpf_ntohs(nat_ingress_value->port));
    // }

    // bpf_log_info("nat_ip IP: %pI4:%u", &lan_ip.all, bpf_ntohs(nat_ingress_value->port));

    // modify source
    ret = modify_headers_v4(skb, is_icmpx_error, pkg_offset.l4_protocol, current_l3_offset,
                            pkg_offset.l4_offset, pkg_offset.icmp_error_inner_l4_offset, false,
                            &ip_pair.dst_addr, ip_pair.dst_port, &lan_ip, nat_ingress_value->port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int nat_v6_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v6_egress <<<"

    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    ret = scan_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = read_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) {
        return ret;
    }

    ret = is_broadcast_ip_pair(pkg_offset.l3_protocol, &ip_pair);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = frag_info_track(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }

    return ipv6_egress_prefix_check_and_replace(skb, &pkg_offset, &ip_pair);
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int nat_v6_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "nat_v6_ingress >>>"

    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    ret = scan_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = read_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) {
        return ret;
    }

    ret = is_broadcast_ip_pair(pkg_offset.l3_protocol, &ip_pair);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = frag_info_track(&pkg_offset, &ip_pair);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }

    return ipv6_ingress_prefix_check_and_replace(skb, &pkg_offset, &ip_pair);
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int ingress_nat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">>> ingress_nat >>>"

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
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ingress_prog_array, IPV4_NAT_INGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ingress_prog_array, IPV6_NAT_INGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int egress_nat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< egress_nat <<<"

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
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &egress_prog_array, IPV4_NAT_EGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &egress_prog_array, IPV6_NAT_EGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
