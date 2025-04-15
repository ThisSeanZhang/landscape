#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "flow_mark_share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int current_eth_net_offset = 14;

// todo: 将 flow_target_info 独立出来维护
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
    __type(key, struct flow_cache_key);
    __type(value, struct flow_target_info);
    __uint(max_entries, 4096);
} flow_cache_map SEC(".maps");

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
int flow_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">> flow_ingress"
    bool is_ipv4;

    skb->cb[4] = 111;
    struct flow_cache_key cache_key = {0};
    int ret;
    if (current_pkg_type(skb, current_eth_net_offset, &is_ipv4) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    if (current_eth_net_offset > 0) {
        ret = bpf_skb_load_bytes(skb, 6, &cache_key.match_key.h_source,
                                 sizeof(cache_key.match_key.h_source));
        if (ret) {
            bpf_log_info("mac bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
    }

    if (is_ipv4) {
        ret = bpf_skb_load_bytes(skb, current_eth_net_offset + 1, &cache_key.match_key.tos,
                                 sizeof(cache_key.match_key.tos));
        if (ret) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
    } else {
        __u16 first_2_bytes;
        ret =
            bpf_skb_load_bytes(skb, current_eth_net_offset, &first_2_bytes, sizeof(first_2_bytes));
        if (ret) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        first_2_bytes = bpf_ntohs(first_2_bytes);
        cache_key.match_key.tos = (first_2_bytes >> 4) & 0xFF;
    }

    // cache_key.match_key.vlan_tci = skb->vlan_present;
    PRINT_MAC_ADDR(cache_key.match_key.h_source);
    bpf_log_info("tos: %d", cache_key.match_key.tos);
    bpf_log_info("vlan_tci: %d", cache_key.match_key.vlan_tci);
    // bpf_log_info("vlan_tci: %d", skb.);
    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &cache_key.match_key);

    if (flow_id_ptr == NULL || *flow_id_ptr == 0) {
        // 查不到 flow 配置，通过使用默认路由进行处理
        return TC_ACT_UNSPEC;
    }

    u32 flow_id = *flow_id_ptr;
    skb->mark = flow_id;
    bpf_log_info("flow_id: %d", flow_id);

    struct bpf_fib_lookup fib_params = {0};
    fib_params.ifindex = skb->ifindex;
    fib_params.family = is_ipv4 ? AF_INET : AF_INET6;
    fib_params.sport = 0;
    fib_params.dport = 0;

    if (is_ipv4) {
        struct iphdr iph;

        // 读取 IPv4 头部
        ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &iph, sizeof(iph));
        if (ret) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        // 填充协议与地址
        fib_params.l4_protocol = iph.protocol;
        fib_params.ipv4_src = iph.saddr;
        fib_params.ipv4_dst = iph.daddr;
    } else {
        struct ipv6hdr ip6h;

        // 读取 IPv6 头部
        ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &ip6h, sizeof(ip6h));
        if (ret) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }

        // 填充协议与地址
        fib_params.l4_protocol = ip6h.nexthdr;
        COPY_ADDR_FROM(fib_params.ipv6_src, ip6h.saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(fib_params.ipv6_dst, ip6h.daddr.in6_u.u6_addr32);
    }

    // print_bpf_fib_lookup(&fib_params);
    // TODO：检查下目标 IP 是不是在黑名单中

    // 检查缓存, 直接发往选定的网卡
    COPY_ADDR_FROM(cache_key.src_addr.all, fib_params.ipv6_src);
    COPY_ADDR_FROM(cache_key.dst_addr.all, fib_params.ipv6_dst);

    struct flow_target_info *target_info;
    target_info = bpf_map_lookup_elem(&flow_cache_map, &cache_key);
    if (target_info == NULL) {
        int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);

        bpf_log_info("bpf_fib_lookup result is: %d", rc);
        if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
            // 缓存查询结果
            struct flow_target_info lo_cache = {0};
            bpf_map_update_elem(&flow_cache_map, &cache_key, &lo_cache, BPF_ANY);
            // 发往本机的直接放行
            return TC_ACT_UNSPEC;
        }

        print_bpf_fib_lookup(&fib_params);
        // 不是发往本机的
        // 1. 先检查有没有额外的 DNS Mark 配置

        // 2. 根据 flow_id 检索 flow 的配置, 目前只有一个目标网卡
        bpf_log_info("going to find target_info using flow_id: %d", flow_id);
        target_info = bpf_map_lookup_elem(&flow_target_map, &flow_id);
        if (target_info == NULL) {
            bpf_log_info("can not find target_info using flow_id: %d", flow_id);
            return TC_ACT_SHOT;
        }
    }

    // 为 0 表示是本机的
    if (target_info->ifindex == 0) {
        return TC_ACT_UNSPEC;
    }

    // 缓存当前的转发结果
    if (bpf_map_update_elem(&flow_cache_map, &cache_key, target_info, BPF_ANY)) {
        bpf_log_info("cache fail");
        return TC_ACT_SHOT;
    }

    // 依据配置发往具体的端口
    if (current_eth_net_offset == 0 && target_info->has_mac) {
        bpf_log_info("add dummy_mac");
        // 当前数据包没有 mac 对方有 mac
        if (prepend_dummy_mac(skb) != 0) {
            return TC_ACT_SHOT;
        }

    } else if (current_eth_net_offset != 0 && !target_info->has_mac) {
        // 当前有, 对方没有
        // 需要 6.6 以上支持 目前暂不实现
        return TC_ACT_SHOT;
    }

    if (target_info->is_docker) {
        bpf_skb_vlan_push(skb, ETH_P_8021Q, LAND_REDIRECT_NETNS_VLAN_ID);
        return bpf_redirect(target_info->ifindex, 0);
    }

    if (current_eth_net_offset != 0 && target_info->has_mac) {
        struct bpf_fib_lookup fib_egress_param = {0};
        fib_egress_param.ifindex = target_info->ifindex;
        // fib_egress_param.ifindex = skb->ifindex;
        fib_egress_param.family = is_ipv4 ? AF_INET : AF_INET6;
        fib_egress_param.sport = 0;
        fib_egress_param.dport = 0;

        COPY_ADDR_FROM(fib_egress_param.ipv6_src, cache_key.src_addr.all);
        COPY_ADDR_FROM(fib_egress_param.ipv6_dst, cache_key.dst_addr.all);

        u32 flag = BPF_FIB_LOOKUP_OUTPUT;

        int rcc = bpf_fib_lookup(skb, &fib_egress_param, sizeof(fib_egress_param), 0);

        bpf_log_info("fib_egress_param result is: %d", rcc);
        print_bpf_fib_lookup(&fib_egress_param);
        if (rcc == 0) {
            ret = bpf_skb_store_bytes(skb, 6, fib_egress_param.smac, sizeof(fib_egress_param.smac),
                                      0);
            if (ret) {
                bpf_log_info("ret is: %d", ret);
            }
            ret = bpf_skb_store_bytes(skb, 0, fib_egress_param.dmac, sizeof(fib_egress_param.dmac),
                                      0);
            if (ret) {
                bpf_log_info("ret2 is: %d", ret);
            }
        } else if (rcc == BPF_FIB_LKUP_RET_NO_NEIGH) {
            // 发送给邻居 需要使用 bpf_redirect_neigh, 但是默认路由不属于邻居
            struct bpf_redir_neigh param;
            if (is_ipv4) {
                param.nh_family = AF_INET;
                param.ipv4_nh = fib_params.ipv4_dst;
            } else {
                param.nh_family = AF_INET6;
                COPY_ADDR_FROM(param.ipv6_nh, fib_params.ipv6_dst);
            }
            return bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
        } else {
            return TC_ACT_SHOT;
        }
    }

    // bpf_log_info("bpf_redirect to: %d", target_info->ifindex);
    ret = bpf_redirect(target_info->ifindex, 0);
    // bpf_log_info("bpf_redirect ret: %d", ret);
    return ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int flow_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">> flow_egress"
    // TODO: 需要记录的是 通过 NAT 而来的 静态映射流量, 避免分流到其他端口

    // bpf_log_info("mark: %d", skb->mark);
    // bpf_log_info("ifindex: %d", skb->ifindex);
    // bpf_log_info("ingress_ifindex: %d", skb->ingress_ifindex);

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}