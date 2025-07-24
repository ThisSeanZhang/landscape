#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "flow_verdict_share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int current_eth_net_offset = 14;

static __always_inline int current_pkg_type(struct __sk_buff *skb, int current_eth_net_offset,
                                            bool *is_ipv4_) {
    bool is_ipv4;
    if (current_eth_net_offset != 0) {
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
    *is_ipv4_ = is_ipv4;
    return TC_ACT_OK;
}

SEC("tc/ingress")
int flow_verdict_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">> flow_verdict_ingress >>"
    struct ethhdr *eth;
    if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
        return TC_ACT_UNSPEC;
    }

    skb->mark = 100;

    bpf_log_info("mark: %d", skb->mark);

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int flow_verdict_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<< flow_verdict_egress <<"

    // if (skb->ingress_ifindex == 0) {
    //     return TC_ACT_UNSPEC;
    // }

    bool is_ipv4;

    int ret;
    if (current_pkg_type(skb, current_eth_net_offset, &is_ipv4) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    struct flow_ip_cache_key cache_key = {0};

    if (is_ipv4) {
        struct iphdr iph;

        // 读取 IPv4 头部
        ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &iph, sizeof(iph));
        if (ret) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        // 填充协议与地址
        // cache_key.match_key.l4_protocol = iph.protocol;  // 暂时不区分协议
        cache_key.match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        cache_key.match_key.src_addr.ip = iph.saddr;
        cache_key.dst_addr.ip = iph.daddr;
    } else {
        struct ipv6hdr ip6h;

        // 读取 IPv6 头部
        ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &ip6h, sizeof(ip6h));
        if (ret) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        // 填充协议与地址
        // cache_key.match_key.l4_protocol = ip6h.nexthdr; // 暂时不区分协议
        cache_key.match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
        COPY_ADDR_FROM(cache_key.match_key.src_addr.all, ip6h.saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(cache_key.dst_addr.all, ip6h.daddr.in6_u.u6_addr32);
    }

    // 获得 flow_id
    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &cache_key.match_key);

    volatile u32 flow_id;
    if (flow_id_ptr == NULL) {
        // 查不到 flow 配置, 如果按照原逻辑直接放行 会导致默认流中, 设置了转发 DNS 查询生效
        // 但是 访问时 IP 在进行到此处时 被直接发送 就导致行为不一致
        // if (skb->ingress_ifindex != 0) {
        //     // 因为不是本机流量, 放行数据包
        //     return TC_ACT_UNSPEC;
        // }
        // 是本机路由流量 ( DNS 中的 MARK 需要按照对应的 流去处理)
        flow_id = skb->mark;
    } else {
        flow_id = *flow_id_ptr;
    }

    u8 flow_id_u8 = flow_id & 0xff;

    // bpf_log_info("find flow_id: %d", *flow_id_ptr);

    volatile u32 flow_mark_action = 0;

    struct flow_ip_trie_key ip_trie_key = {0};
    ip_trie_key.prefixlen = is_ipv4 ? 64 : 160;
    ip_trie_key.l3_protocol = is_ipv4 ? LANDSCAPE_IPV4_TYPE : LANDSCAPE_IPV6_TYPE;
    COPY_ADDR_FROM(ip_trie_key.addr, cache_key.dst_addr.all);
    // struct flow_ip_trie_value *ip_flow_mark;
    u32 *ip_flow_mark;
    void *ip_rules_map = bpf_map_lookup_elem(&flow_v_ip_map, &flow_id);
    if (ip_rules_map != NULL) {
        ip_flow_mark = bpf_map_lookup_elem(ip_rules_map, &ip_trie_key);
        // if (ip_flow_mark != NULL) {
        //     flow_mark_action = ip_flow_mark->mark;
        //     // bpf_log_info("find ip map mark: %d", flow_mark_action);
        //     if (ip_flow_mark->override_dns == 1) {
        //         goto apply_action;
        //     }
        // }
    } else {
        // bpf_log_info("flow_id: %d, ip map is empty", *flow_id_ptr);
    }

    struct flow_dns_match_key key = {0};
    // struct flow_dns_match_value *dns_rule_value;
    u32 *dns_rule_value;
    key.l3_protocol = is_ipv4 ? LANDSCAPE_IPV4_TYPE : LANDSCAPE_IPV6_TYPE;
    COPY_ADDR_FROM(key.addr.all, cache_key.dst_addr.all);

    // 查询 DNS 配置信息，查看是否有转发流的配置
    void *dns_rules_map = bpf_map_lookup_elem(&flow_v_dns_map, &flow_id);
    if (dns_rules_map != NULL) {
        dns_rule_value = bpf_map_lookup_elem(dns_rules_map, &key);
        // if (dns_flow_mark != NULL) {
        //     flow_mark_action = *dns_flow_mark;
        //     // bpf_log_info("dns_flow_mark is:%d for: %pI4", flow_mark_action,
        //     &cache_key.dst_addr.ip);
        // } else {
        //     // bpf_log_info("dns_flow_mark is none for: %pI4", &cache_key.dst_addr.ip);
        // }
    } else {
        // bpf_log_info("flow_id: %d, dns map is empty", *flow_id_ptr);
    }

    // bpf_log_info("flow_id %d, flow_mark_action: %u", flow_id, flow_mark_action);
    u8 flow_action, dns_flow_id;
    struct flow_target_info *target_info;
apply_action:

    skb->mark = replace_flow_id(flow_mark_action, flow_id_u8);

    flow_action = get_flow_action(flow_mark_action);
    dns_flow_id = get_flow_id(flow_mark_action);
    // bpf_log_info("dns_flow_id %d, flow_action: %d ", dns_flow_id, flow_action);
    if (flow_action == FLOW_KEEP_GOING) {
        // 无动作
        // bpf_log_info("FLOW_KEEP_GOING ip: %pI4", cache_key.dst_addr.all);
    } else if (flow_action == FLOW_DIRECT) {
        // bpf_log_info("FLOW_DIRECT ip: %pI4", cache_key.dst_addr.all);
        return TC_ACT_UNSPEC;
    } else if (flow_action == FLOW_DROP) {
        // bpf_log_info("FLOW_DROP ip: %pI4", cache_key.dst_addr.all);
        return TC_ACT_SHOT;
    } else if (flow_action == FLOW_REDIRECT) {
        // bpf_log_info("FLOW_REDIRECT ip: %pI4, flow_id: %d", cache_key.dst_addr.all,
        //              dns_flow_id);
        flow_id = dns_flow_id;
    } else if (flow_action == FLOW_ALLOW_REUSE) {
        // 无动作
    }

keep_going:

    // 如果是本机的流量, 并且没有改变 flow_id 或者丢弃
    // 还是继续发送, 其余情况就必须发往 flow target
    if (flow_id == 0) {
        // if (skb->ingress_ifindex == 0 && flow_id == 0) {
        return TC_ACT_UNSPEC;
    }

    // 找到转发的目标
    target_info = bpf_map_lookup_elem(&flow_target_map, &flow_id);

    if (target_info == NULL) {
        // TODO: 这边执行 flow 因为获取不到 target 信息, 而进行的动作
        bpf_log_info("can not find target info, %d", flow_id);
        return TC_ACT_SHOT;
    }

    // 依据配置发往具体的端口， 检查 MAC 地址
    if (current_eth_net_offset == 0 && target_info->has_mac) {
        // 当前数据包没有 mac 对方有 mac
        if (prepend_dummy_mac(skb) != 0) {
            bpf_log_error("add dummy_mac fail");
            return TC_ACT_SHOT;
        }

    } else if (current_eth_net_offset != 0 && !target_info->has_mac) {
        // 当前有, 对方没有
        // 需要 6.6 以上支持 目前暂不实现
        bpf_log_info("drop");
        return TC_ACT_SHOT;
    }

    if (target_info->is_docker) {
        ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, LAND_REDIRECT_NETNS_VLAN_ID);
        if (ret) {
            bpf_log_info("bpf_skb_vlan_push error");
        }
        ret = bpf_redirect(target_info->ifindex, 0);
        if (ret != 7) {
            bpf_log_info("bpf_redirect error: %d", ret);
        }
        return ret;
    }

    bpf_log_info("drop");
    // 当前只支持转发到 docekr 中
    return TC_ACT_SHOT;

    // bpf_log_info("target_info->ifindex is: %d", target_info->ifindex);

    // if (current_eth_net_offset != 0 && target_info->has_mac) {
    //     struct bpf_fib_lookup fib_egress_param = {0};
    //     fib_egress_param.ifindex = target_info->ifindex;
    //     // fib_egress_param.ifindex = skb->ifindex;
    //     fib_egress_param.family = is_ipv4 ? AF_INET : AF_INET6;
    //     fib_egress_param.sport = 0;
    //     fib_egress_param.dport = 0;

    //     COPY_ADDR_FROM(fib_egress_param.ipv6_src, cache_key.match_key.src_addr.all);
    //     COPY_ADDR_FROM(fib_egress_param.ipv6_dst, cache_key.dst_addr.all);

    //     u32 flag = BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_DIRECT;

    //     print_bpf_fib_lookup(&fib_egress_param);
    //     int rcc = bpf_fib_lookup(skb, &fib_egress_param, sizeof(fib_egress_param), 0);

    //     bpf_log_info("fib_egress_param result is: %d", rcc);
    //     print_bpf_fib_lookup(&fib_egress_param);
    //     if (rcc == 0) {
    //         ret = bpf_skb_store_bytes(skb, 6, fib_egress_param.smac,
    //         sizeof(fib_egress_param.smac),
    //                                   0);
    //         if (ret) {
    //             bpf_log_info("ret is: %d", ret);
    //         }
    //         ret = bpf_skb_store_bytes(skb, 0, fib_egress_param.dmac,
    //         sizeof(fib_egress_param.dmac),
    //                                   0);
    //         if (ret) {
    //             bpf_log_info("ret2 is: %d", ret);
    //         }
    //     } else if (rcc == BPF_FIB_LKUP_RET_NO_NEIGH) {
    //         // 发送给邻居 需要使用 bpf_redirect_neigh, 但是默认路由不属于邻居
    //         struct bpf_redir_neigh param;
    //         if (is_ipv4) {
    //             param.nh_family = AF_INET;
    //             param.ipv4_nh = cache_key.dst_addr.ip;
    //         } else {
    //             param.nh_family = AF_INET6;
    //             COPY_ADDR_FROM(param.ipv6_nh, cache_key.dst_addr.all);
    //         }
    //         return bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
    //     } else {
    //         return TC_ACT_SHOT;
    //     }
    // }

    // // bpf_log_info("bpf_redirect to: %d", target_info->ifindex);
    // ret = bpf_redirect(target_info->ifindex, 0);
    // // bpf_log_info("bpf_redirect ret: %d", ret);
    // return ret;

#undef BPF_LOG_TOPIC
}