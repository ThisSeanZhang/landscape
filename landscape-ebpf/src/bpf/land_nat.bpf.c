#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "share_ifindex_ip.h"
#include "nat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

// #define ETH_IPV4 bpf_htons(0x0800) /* ETH IPV4 packet */
// #define ETH_IPV6 bpf_htons(0x86DD) /* ETH IPv6 packet */

const volatile int current_eth_net_offset = 14;

const volatile u64 TCP_SYN_TIMEOUT = 1E9 * 6;
const volatile u64 TCP_TCP_TRANS = 1E9 * 60 * 4;
const volatile u64 TCP_TIMEOUT = 1E9 * 60 * 10;

const volatile u64 UDP_TIMEOUT = 1E9 * 60 * 5;

static __always_inline int icmp_msg_type(struct icmphdr *icmph);
static __always_inline bool is_icmp_error_pkt(const struct ip_packet_info *pkt) {
    return pkt->l4_payload_offset >= 0 && pkt->icmp_error_payload_offset >= 0;
}

static __always_inline bool pkt_allow_initiating_ct(u8 pkt_type) {
    return pkt_type == PKT_CONNLESS || pkt_type == PKT_TCP_SYN;
}

#define NAT_MAPPING_CACHE_SIZE 1024 * 64 * 2
#define NAT_MAPPING_TIMER_SIZE 1024 * 64 * 2
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_mapping_key);
    __type(value, struct nat_mapping_value);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
} nat_mappings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_timer_key);
    __type(value, struct nat_timer_value);
    __uint(max_entries, NAT_MAPPING_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_mapping_timer SEC(".maps");

#define FRAG_CACHE_SIZE 1024 * 32
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct fragment_cache_key);
    __type(value, struct fragment_cache_value);
    __uint(max_entries, FRAG_CACHE_SIZE);
} fragment_cache SEC(".maps");

volatile const u16 tcp_range_start = 32768;
// volatile const u16 tcp_range_end = 32770;
volatile const u16 tcp_range_end = 65535;

volatile const u16 udp_range_start = 32768;
volatile const u16 udp_range_end = 65535;

volatile const u16 icmp_range_start = 32768;
volatile const u16 icmp_range_end = 65535;

static __always_inline int icmpx_err_l3_offset(int l4_off) {
    return l4_off + sizeof(struct icmphdr);
}

static __always_inline void ipv4_update_csum(struct __sk_buff *skb, u32 l4_csum_off,
                                             __be32 from_addr, __be16 from_port, __be32 to_addr,
                                             __be16 to_port, bool l4_pseudo, bool l4_mangled_0) {
    bpf_l4_csum_replace(skb, l4_csum_off, from_port, to_port,
                        2 | (l4_mangled_0 ? BPF_F_MARK_MANGLED_0 : 0));
    if (l4_pseudo) {
        bpf_l4_csum_replace(skb, l4_csum_off, from_addr, to_addr,
                            4 | BPF_F_PSEUDO_HDR | (l4_mangled_0 ? BPF_F_MARK_MANGLED_0 : 0));
    }
}

static __always_inline void ipv4_update_csum_inner(struct __sk_buff *skb, u32 l4_csum_off,
                                                   __be32 from_addr, __be16 from_port,
                                                   __be32 to_addr, __be16 to_port, bool l4_pseudo,
                                                   bool l4_mangled_0) {
    u16 csum;
    if (l4_mangled_0) {
        bpf_skb_load_bytes(skb, l4_csum_off, &csum, sizeof(csum));
    }
    if (!l4_mangled_0 || csum != 0) {
        // use bpf_l3_csum_replace to avoid updating skb csum
        bpf_l3_csum_replace(skb, l4_csum_off, from_port, to_port, 2);

        if (l4_pseudo) {
            bpf_l3_csum_replace(skb, l4_csum_off, from_addr, to_addr, 4);
        }
    }
}

static __always_inline void ipv4_update_csum_icmp_err(struct __sk_buff *skb, u32 icmp_csum_off,
                                                      u32 err_ip_check_off, u32 err_l4_csum_off,
                                                      __be32 from_addr, __be16 from_port,
                                                      __be32 to_addr, __be16 to_port,
                                                      bool err_l4_pseudo, bool l4_mangled_0) {
    u16 prev_csum;
    u16 curr_csum;
    bpf_skb_load_bytes(skb, err_ip_check_off, &prev_csum, sizeof(prev_csum));

    bpf_l3_csum_replace(skb, err_ip_check_off, from_addr, to_addr, 4);

    bpf_skb_load_bytes(skb, err_ip_check_off, &curr_csum, sizeof(curr_csum));
    bpf_l4_csum_replace(skb, icmp_csum_off, prev_csum, curr_csum, 2);

    // update of inner message
#if 1
    // the update of embedded layer 4 checksum is not required but may helpful
    // for packet tracking the TCP checksum might not be included in IPv4
    // packet, check if it exists first
    if (bpf_skb_load_bytes(skb, err_l4_csum_off, &prev_csum, sizeof(prev_csum))) {
        ipv4_update_csum_inner(skb, err_l4_csum_off, from_addr, from_port, to_addr, to_port,
                               err_l4_pseudo, l4_mangled_0);

        bpf_skb_load_bytes(skb, err_l4_csum_off, &curr_csum, sizeof(curr_csum));
        bpf_l4_csum_replace(skb, icmp_csum_off, prev_csum, curr_csum, 2);
    }
#endif
    bpf_l4_csum_replace(skb, icmp_csum_off, from_addr, to_addr, 4);
    bpf_l4_csum_replace(skb, icmp_csum_off, from_port, to_port, 2);
}

static __always_inline int modify_headers(struct __sk_buff *skb, bool is_ipv4, bool is_icmpx_error,
                                          u8 nexthdr, int l3_off, int l4_off, int err_l4_off,
                                          bool is_modify_source, union u_inet_addr *from_addr,
                                          __be16 from_port, union u_inet_addr *to_addr,
                                          __be16 to_port) {
#define BPF_LOG_TOPIC "modify_headers"

    int ret;
    int ip_offset =
        is_modify_source ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr);
    ret = bpf_skb_store_bytes(skb, l3_off + ip_offset, &to_addr->ip, sizeof(to_addr->ip), 0);

    if (ret) {
        return ret;
    }
    ret = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), from_addr->ip,
                              to_addr->ip, 4);
    if (ret) {
        return ret;
    }
    if (l4_off < 0) {
        return 0;
    }

    int l4_to_port_off;
    int l4_to_check_off;
    bool l4_check_pseudo;
    bool l4_check_mangle_0;
    switch (nexthdr) {
    case IPPROTO_TCP:
        l4_to_port_off = is_modify_source ^ is_icmpx_error ? offsetof(struct tcphdr, source)
                                                           : offsetof(struct tcphdr, dest);
        l4_to_check_off = offsetof(struct tcphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = false;
        break;
    case IPPROTO_UDP:
        l4_to_port_off = is_modify_source ^ is_icmpx_error ? offsetof(struct udphdr, source)
                                                           : offsetof(struct udphdr, dest);
        l4_to_check_off = offsetof(struct udphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = is_ipv4;
        break;
    case IPPROTO_ICMP:
        l4_to_port_off = offsetof(struct icmphdr, un.echo.id);
        l4_to_check_off = offsetof(struct icmphdr, checksum);
        l4_check_pseudo = !is_ipv4;
        l4_check_mangle_0 = false;
        break;
    default:
        return 1;
    }

    if (is_icmpx_error) {
        int icmpx_error_offset =
            is_modify_source ? offsetof(struct iphdr, daddr) : offsetof(struct iphdr, saddr);
        ret = bpf_write_inet_addr(skb, is_ipv4, icmpx_err_l3_offset(l4_off) + icmpx_error_offset,
                                  to_addr);
        if (ret) {
            return ret;
        }
    }

    ret = bpf_write_port(skb, (is_icmpx_error ? err_l4_off : l4_off) + l4_to_port_off, to_port);
    if (ret) {
        return ret;
    }

    if (is_icmpx_error) {
        if (is_ipv4) {
            ipv4_update_csum_icmp_err(skb, l4_off + offsetof(struct icmphdr, checksum),
                                      icmpx_err_l3_offset(l4_off) + offsetof(struct iphdr, check),
                                      err_l4_off + l4_to_check_off, from_addr->ip, from_port,
                                      to_addr->ip, to_port, l4_check_pseudo, l4_check_mangle_0);
        }
    } else {
        if (is_ipv4) {
            // __be16 check_sum;
            // bpf_skb_load_bytes(skb, l4_off + l4_to_check_off, &check_sum, sizeof(u16));
            // bpf_log_info("tcphdr before update checksum is: %u", bpf_ntohs(check_sum));

            ipv4_update_csum(skb, l4_off + l4_to_check_off, from_addr->ip, from_port, to_addr->ip,
                             to_port, l4_check_pseudo, l4_check_mangle_0);

            // bpf_skb_load_bytes(skb, l4_off + l4_to_check_off, &check_sum, sizeof(u16));
            // bpf_log_info("tcphdr before update checksum is: %u", bpf_ntohs(check_sum));
        }
    }

    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline bool ct_change_state(struct nat_timer_value *timer_track_value,
                                            u64 curr_state, u64 next_state) {
    return __sync_bool_compare_and_swap(&timer_track_value->status, curr_state, next_state);
}

static __always_inline int ct_reset_timer(struct nat_timer_value *timer_track_value, u64 timeout) {
#define BPF_LOG_TOPIC "ct_reset_timer"
    // bpf_log_info("ct_reset_timer : %llu", timeout);
    return bpf_timer_start(&timer_track_value->timer, timeout, 0);
#undef BPF_LOG_TOPIC
}

static __always_inline int ct_state_transition(u8 l4proto, u8 pkt_type, u8 gress,
                                               struct nat_timer_value *ct_timer_value) {
#define BPF_LOG_TOPIC "ct_state_transition"
    u64 curr_state = ct_timer_value->status;

#define NEW_STATE(__state)                                                                         \
    if (!ct_change_state(ct_timer_value, curr_state, (__state))) {                                 \
        return TC_ACT_SHOT;                                                                        \
    }
#define RESET_TIMER(__timeout) ct_reset_timer(ct_timer_value, (__timeout))

    if (pkt_type == PKT_CONNLESS) {
        NEW_STATE(OTHER_EST);
        RESET_TIMER(UDP_TIMEOUT);
        return TC_ACT_OK;
    }

    if (pkt_type == PKT_TCP_RST) {
        NEW_STATE(TIMER_INIT);
        RESET_TIMER(TCP_SYN_TIMEOUT);
        return TC_ACT_OK;
    }

    if (pkt_type == PKT_TCP_SYN) {
        NEW_STATE(TIMER_INIT);
        if (gress == ct_timer_value->gress) {
            RESET_TIMER(TCP_SYN_TIMEOUT);
        } else {
            RESET_TIMER(TCP_TCP_TRANS);
        }
        return TC_ACT_OK;
    }

    RESET_TIMER(TCP_TIMEOUT);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static int timer_clean_callback(void *map_mapping_timer_, struct nat_timer_key *key,
                                struct nat_timer_value *value) {
#define BPF_LOG_TOPIC "timer_clean_callback"

    // bpf_log_info("timer_clean_callback: %d", bpf_ntohs(value->trigger_port));
    struct nat_mapping_key egress_mapping_key = {
        .l4proto = key->l4proto,
        .gress = NAT_MAPPING_EGRESS,
        .from_addr = key->pair_ip.src_addr,
        .from_port = key->pair_ip.src_port,
    };

    struct nat_mapping_key ingress_mapping_key = {
        .l4proto = key->l4proto,
        .gress = NAT_MAPPING_INGRESS,
        .from_addr = key->pair_ip.dst_addr,
        .from_port = key->pair_ip.dst_port,
    };

    bpf_map_delete_elem(&nat_mappings, &egress_mapping_key);
    bpf_map_delete_elem(&nat_mappings, &ingress_mapping_key);

    bpf_map_delete_elem(&map_mapping_timer, key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat_timer_value *
insert_new_nat_timer(u8 l4proto, const struct nat_timer_key *key,
                     const struct nat_timer_value *val) {
#define BPF_LOG_TOPIC "insert_new_nat_timer"
    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    // bpf_ntohs(key->pair_ip.src_port), bpf_ntohs(key->pair_ip.dst_port)); bpf_log_info("src_ip:
    // %lu -> dst_ip: %lu", bpf_ntohl(key->pair_ip.src_addr.ip),
    // bpf_ntohl(key->pair_ip.dst_addr.ip));

    int ret = bpf_map_update_elem(&map_mapping_timer, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct nat_timer_value *value = bpf_map_lookup_elem(&map_mapping_timer, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &map_mapping_timer, CLOCK_MONOTONIC);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_set_callback(&value->timer, timer_clean_callback);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_start(&value->timer, l4proto == IPPROTO_TCP ? TCP_TIMEOUT : UDP_TIMEOUT, 0);
    if (ret) {
        goto delete_timer;
    }

    return value;
delete_timer:
    bpf_log_error("setup timer err:%d", ret);
    bpf_map_delete_elem(&map_mapping_timer, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline int lookup_or_new_ct(u8 l4proto, bool do_new,
                                            const struct inet_pair *pkt_ip_pair,
                                            struct nat_mapping_value *nat_egress_value,
                                            struct nat_mapping_value *nat_ingress_value,
                                            struct nat_timer_value **timer_value_) {
#define BPF_LOG_TOPIC "lookup_or_new_ct"

    struct nat_timer_key timer_key = {
        .l4proto = l4proto,
        ._pad = {0, 0, 0},
        .pair_ip =
            {
                .src_port = nat_ingress_value->port,
                .dst_port = nat_egress_value->port,
            },
    };
    COPY_ADDR_FROM(timer_key.pair_ip.src_addr.all, nat_ingress_value->addr.all);
    COPY_ADDR_FROM(timer_key.pair_ip.dst_addr.all, nat_egress_value->addr.all);

    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    //              bpf_ntohs(timer_key.pair_ip.src_port), bpf_ntohs(timer_key.pair_ip.dst_port));
    // bpf_log_info("src_ip: %lu -> dst_ip: %lu", bpf_ntohl(timer_key.pair_ip.src_addr.ip),
    //              bpf_ntohl(timer_key.pair_ip.dst_addr.ip));

    struct nat_timer_value *timer_value = bpf_map_lookup_elem(&map_mapping_timer, &timer_key);
    // bpf_log_info("timer_value: %u", timer_value);
    if (timer_value) {
        *timer_value_ = timer_value;
        return TIMER_EXIST;
    }
    if (!timer_value && !do_new) {
        return TIMER_NOT_FOUND;
    }

    struct nat_timer_value timer_value_new = {
        .trigger_saddr = nat_ingress_value->trigger_addr,
        .trigger_port = nat_ingress_value->trigger_port,
        .status = TIMER_INIT,
        ._pad = 0,
        .gress = NAT_MAPPING_EGRESS,
    };
    timer_value = insert_new_nat_timer(l4proto, &timer_key, &timer_value_new);
    if (timer_value == NULL) {
        return TIMER_ERROR;
    }

    // bpf_log_debug("insert new CT");

    *timer_value_ = timer_value;
    return TIMER_CREATED;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat_mapping_value *
insert_mappings(const struct nat_mapping_key *key, const struct nat_mapping_value *val,
                struct nat_mapping_value **lk_val_rev) {
#define BPF_LOG_TOPIC "insert_mappings"
    int ret;
    struct nat_mapping_key key_rev = {
        .gress = key->gress ^ GRESS_MASK,
        .l4proto = key->l4proto,
        .from_addr = val->addr,
        .from_port = val->port,
    };

    struct nat_mapping_value val_rev = {
        .port = key->from_port,
        .addr = key->from_addr,
        .trigger_addr = val->trigger_addr,
        .trigger_port = val->trigger_port,
        .active_time = val->active_time,
        ._pad = {0, 0, 0},
    };

    ret = bpf_map_update_elem(&nat_mappings, key, val, BPF_ANY);
    if (ret) {
        bpf_log_error("failed to insert binding entry, err:%d", ret);
        goto error_update;
    }
    ret = bpf_map_update_elem(&nat_mappings, &key_rev, &val_rev, BPF_ANY);
    if (ret) {
        bpf_log_error("failed to insert reverse binding entry, err:%d", ret);
        goto error_update;
    }

    if (lk_val_rev) {
        *lk_val_rev = bpf_map_lookup_elem(&nat_mappings, &key_rev);
        if (!*lk_val_rev) {
            return NULL;
        }
    }

    return bpf_map_lookup_elem(&nat_mappings, key);
error_update:
    bpf_map_delete_elem(&nat_mappings, key);
    bpf_map_delete_elem(&nat_mappings, &key_rev);
    return NULL;
#undef BPF_LOG_TOPIC
}

static int search_port_callback(u32 index, struct search_port_ctx *ctx) {
#define BPF_LOG_TOPIC "search_port_callback"
    ctx->ingress_key.from_port = bpf_htons(ctx->curr_port);
    struct nat_mapping_value *value = bpf_map_lookup_elem(&nat_mappings, &ctx->ingress_key);
    u64 current_time = bpf_ktime_get_ns();
    // 大于协议的超时时间
    if (!value || (current_time - value->active_time) > ctx->timeout_interval) {
        ctx->found = true;
        return BPF_LOOP_RET_BREAK;
    }

    if (ctx->curr_port != ctx->range.end) {
        ctx->curr_port++;
    } else {
        ctx->curr_port = ctx->range.start;
    }
    if (--ctx->remaining_size == 0) {
        return BPF_LOOP_RET_BREAK;
    }

    return BPF_LOOP_RET_CONTINUE;
#undef BPF_LOG_TOPIC
}

static __always_inline int
ingress_lookup_or_new_mapping(struct __sk_buff *skb, u8 ip_protocol, bool allow_create_mapping,
                              const struct inet_pair *pkt_ip_pair,
                              struct nat_mapping_value **nat_egress_value_,
                              struct nat_mapping_value **nat_ingress_value_) {
#define BPF_LOG_TOPIC "ingress_lookup_or_new_mapping"
    if (pkt_ip_pair == NULL) {
        return TC_ACT_SHOT;
    }
    //
    struct nat_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = ip_protocol,              // 原有的 l4 层协议值
        .from_port = pkt_ip_pair->dst_port,  // 数据包中的 内网端口
        .from_addr = pkt_ip_pair->dst_addr,
    };

    // 倒置的值
    struct nat_mapping_value *nat_ingress_value = bpf_map_lookup_elem(&nat_mappings, &ingress_key);
    struct nat_mapping_value *nat_egress_value = NULL;
    if (!nat_ingress_value) {
        if (!allow_create_mapping) {
            return TC_ACT_SHOT;
        }
        return TC_ACT_SHOT;
    } else {
        // 已经存在就查询另外一个值 并进行刷新时间
        struct nat_mapping_key egress_key = {
            .gress = NAT_MAPPING_EGRESS,
            .l4proto = ip_protocol,                // 原有的 l4 层协议值
            .from_port = nat_ingress_value->port,  // 数据包中的 内网端口
            .from_addr = nat_ingress_value->addr,  // 内网原始地址
        };
        nat_egress_value = bpf_map_lookup_elem(&nat_mappings, &egress_key);

        if (!nat_egress_value) {
            return TC_ACT_SHOT;
        }
        nat_ingress_value->active_time = bpf_ktime_get_ns();
        nat_egress_value->active_time = bpf_ktime_get_ns();
    }

    *nat_egress_value_ = nat_egress_value;
    *nat_ingress_value_ = nat_ingress_value;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
egress_lookup_or_new_mapping(struct __sk_buff *skb, u8 ip_protocol, bool allow_create_mapping,
                             const struct inet_pair *pkt_ip_pair,
                             struct nat_mapping_value **nat_egress_value_,
                             struct nat_mapping_value **nat_ingress_value_) {
#define BPF_LOG_TOPIC "egress_lookup_or_new_mapping"
    //
    struct nat_mapping_key egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = ip_protocol,              // 原有的 l4 层协议值
        .from_port = pkt_ip_pair->src_port,  // 数据包中的 内网端口
        .from_addr = pkt_ip_pair->src_addr,  // 内网原始地址
    };

    // 倒置的值
    struct nat_mapping_value *nat_ingress_value = NULL;
    struct nat_mapping_value *nat_egress_value = bpf_map_lookup_elem(&nat_mappings, &egress_key);
    if (!nat_egress_value) {
        if (!allow_create_mapping) {
            return TC_ACT_SHOT;
        }
        u32 wan_ip_key = skb->ifindex;
        __be32 *wan_ip = bpf_map_lookup_elem(&wan_ipv4_binding, &wan_ip_key);
        if (!wan_ip) {
            bpf_log_error("can't find the wan ip, using ifindex: %d", skb->ifindex);
            return TC_ACT_SHOT;
        }
        struct nat_mapping_value new_nat_egress_value = {0};

        new_nat_egress_value.addr.ip = *wan_ip;
        new_nat_egress_value.port = egress_key.from_port;  // 尽量先试试使用客户端发起时候的端口
        new_nat_egress_value.trigger_addr = pkt_ip_pair->dst_addr;
        new_nat_egress_value.trigger_port = pkt_ip_pair->dst_port;
        new_nat_egress_value.is_static = 0;
        new_nat_egress_value.active_time = bpf_ktime_get_ns();

        int ret;
        struct search_port_ctx ctx = {
            .ingress_key =
                {
                    .gress = NAT_MAPPING_INGRESS,
                    .l4proto = ip_protocol,
                    .from_addr = new_nat_egress_value.addr,
                    .from_port = new_nat_egress_value.port,
                },
            .curr_port = bpf_ntohs(new_nat_egress_value.port),
            .found = false,
        };

        if (ip_protocol == IPPROTO_TCP) {
            ctx.range.start = tcp_range_start;
            ctx.range.end = tcp_range_end;
            ctx.remaining_size = tcp_range_end - tcp_range_start;
            ctx.timeout_interval = TCP_TCP_TRANS;
        } else if (ip_protocol == IPPROTO_UDP) {
            ctx.range.start = udp_range_start;
            ctx.range.end = udp_range_end;
            ctx.remaining_size = udp_range_end - udp_range_start;
            ctx.timeout_interval = UDP_TIMEOUT;
        } else if (ip_protocol == IPPROTO_ICMP) {
            ctx.range.start = icmp_range_start;
            ctx.range.end = icmp_range_end;
            ctx.remaining_size = icmp_range_end - icmp_range_start;
            ctx.timeout_interval = UDP_TIMEOUT;
        }

        if (ctx.remaining_size == 0) {
            bpf_log_error("not free port range start: %d end: %d", ctx.range.start, ctx.range.end);
            return TC_ACT_SHOT;
        }

        if (ctx.curr_port < ctx.range.start || ctx.curr_port > ctx.range.end) {
            u16 index = ctx.curr_port % ctx.remaining_size;
            ctx.curr_port = ctx.range.start + index;
        }

        ret = bpf_loop(65536, search_port_callback, &ctx, 0);
        if (ret < 0) {
            return TC_ACT_SHOT;
        }

        if (ctx.found) {
            new_nat_egress_value.port = ctx.ingress_key.from_port;
            // bpf_log_debug("found free binding %d -> %d", bpf_ntohs(egress_key.from_port),
            //               bpf_ntohs(new_nat_egress_value.port));
        } else {
            // bpf_log_debug("mapping is full");
            return TC_ACT_SHOT;
        }
        nat_egress_value = insert_mappings(&egress_key, &new_nat_egress_value, &nat_ingress_value);
        if (!nat_egress_value) {
            return TC_ACT_SHOT;
        }
    } else {
        // 已经存在就查询另外一个值 并进行刷新时间
        struct nat_mapping_key ingress_key = {
            .gress = NAT_MAPPING_INGRESS,
            .l4proto = ip_protocol,               // 原有的 l4 层协议值
            .from_port = nat_egress_value->port,  // 数据包中的 内网端口
            .from_addr = nat_egress_value->addr,  // 内网原始地址
        };
        nat_ingress_value = bpf_map_lookup_elem(&nat_mappings, &ingress_key);

        if (!nat_ingress_value) {
            return TC_ACT_SHOT;
        }
        nat_ingress_value->active_time = bpf_ktime_get_ns();
        nat_egress_value->active_time = bpf_ktime_get_ns();
    }

    *nat_egress_value_ = nat_egress_value;
    *nat_ingress_value_ = nat_ingress_value;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int lookup_static_mapping(struct __sk_buff *skb, u8 ip_protocol, u8 gress,
                                                 const struct inet_pair *pkt_ip_pair,
                                                 struct nat_mapping_value **nat_gress_value_,
                                                 struct nat_mapping_value **nat_gress_value_rev_) {
#define BPF_LOG_TOPIC "lookup_static_mapping"
    struct nat_mapping_key gress_key = {
        .gress = gress,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->src_port,
        .from_addr = pkt_ip_pair->src_addr,
    };

    struct nat_mapping_value *nat_gress_value = NULL;
    struct nat_mapping_value *nat_gress_value_rev = NULL;
    u8 gress_rev = gress;
    if (gress == NAT_MAPPING_INGRESS) {
        gress_rev = NAT_MAPPING_EGRESS;
        gress_key.from_port = pkt_ip_pair->dst_port;
        gress_key.from_addr = pkt_ip_pair->dst_addr;
    } else {
        gress_rev = NAT_MAPPING_INGRESS;
    }

    // 倒置的值
    nat_gress_value = bpf_map_lookup_elem(&static_nat_mappings, &gress_key);
    if (nat_gress_value) {
        // 已经存在就查询另外一个值 并进行刷新时间
        struct nat_mapping_key ingress_key = {
            .gress = gress_rev,
            .l4proto = ip_protocol,              // 原有的 l4 层协议值
            .from_port = nat_gress_value->port,  // 数据包中的 内网端口
            .from_addr = nat_gress_value->addr,  // 内网原始地址
        };
        nat_gress_value_rev = bpf_map_lookup_elem(&static_nat_mappings, &ingress_key);

        if (!nat_gress_value_rev) {
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_SHOT;
    }

    *nat_gress_value_ = nat_gress_value;
    *nat_gress_value_rev_ = nat_gress_value_rev;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

/// IP Fragment Related Start
static __always_inline int fragment_track(struct __sk_buff *skb, struct ip_packet_info *pkt) {
#define BPF_LOG_TOPIC "fragment_track"

    // 没有被分片的数据包, 无需进行记录
    if (pkt->fragment_type == NOT_F || (pkt->fragment_type == END_F && pkt->fragment_off == 0)) {
        return TC_ACT_OK;
    }
    if (is_icmp_error_pkt(pkt)) {
        return TC_ACT_SHOT;
    }

    int ret;
    struct fragment_cache_key key = {
        ._pad = {0, 0, 0},
        .l4proto = pkt->ip_protocol,
        .id = pkt->fragment_id,
        .saddr = pkt->pair_ip.src_addr,
        .daddr = pkt->pair_ip.dst_addr,
    };

    struct fragment_cache_value *value;
    if (pkt->fragment_type == MORE_F && pkt->fragment_off == 0) {
        struct fragment_cache_value value_new;
        value_new.dport = pkt->pair_ip.dst_port;
        value_new.sport = pkt->pair_ip.src_port;

        ret = bpf_map_update_elem(&fragment_cache, &key, &value_new, BPF_ANY);
        if (ret) {
            return TC_ACT_SHOT;
        }
        value = bpf_map_lookup_elem(&fragment_cache, &key);
        if (!value) {
            return TC_ACT_SHOT;
        }
    } else {
        value = bpf_map_lookup_elem(&fragment_cache, &key);
        if (!value) {
            bpf_log_warn("fragmentation session of this packet was not tracked");
            return TC_ACT_SHOT;
        }
        pkt->pair_ip.src_port = value->sport;
        pkt->pair_ip.dst_port = value->dport;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
/// IP Fragment Related End

/// ICMP Related Start
static __always_inline int icmp_err_l3_offset(int l4_off) { return l4_off + ICMP_HDR_LEN; }

static __always_inline __be16 get_icmpx_query_id(struct icmphdr *icmph) {
    return icmph->un.echo.id;
}

static __always_inline int only_extract_ip_info(const struct iphdr *iph, struct inet_pair *ip_pair,
                                                u8 *pkt_ip_protocol, u32 *len_) {
#define BPF_LOG_TOPIC "only_extract_ip_info"
    inet_addr_set_ip(&ip_pair->src_addr, iph->saddr);
    inet_addr_set_ip(&ip_pair->dst_addr, iph->daddr);
    *pkt_ip_protocol = iph->protocol;
    if (iph->frag_off & IP_OFFSET) {
        // 分片数据包不可能产生错误消息
        return TC_ACT_SHOT;
    }
    *len_ = iph->ihl * 4;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#define ICMP_ERR_PACKET_L4_LEN 8
static __always_inline int extract_imcp_err_info(struct __sk_buff *skb, u32 l3_off,
                                                 struct inet_pair *err_ip_pair, u8 *pkt_ip_protocol,
                                                 u32 *l3_hdr_len) {
#define BPF_LOG_TOPIC "extract_imcp_err_info"
    int ret;

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, l3_off, sizeof(*iph))) {
        return TC_ACT_SHOT;
    }
    ret = only_extract_ip_info(iph, err_ip_pair, pkt_ip_protocol, l3_hdr_len);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    int l4_off = l3_off + *l3_hdr_len;
    if (*pkt_ip_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, l4_off, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        err_ip_pair->src_port = tcph->source;
        err_ip_pair->dst_port = tcph->dest;
    } else if (*pkt_ip_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, l4_off, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        err_ip_pair->src_port = udph->source;
        err_ip_pair->dst_port = udph->dest;
    } else if (*pkt_ip_protocol == IPPROTO_ICMP) {
        void *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, l4_off, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        switch (icmp_msg_type(icmph)) {
        case ICMP_QUERY_MSG: {
            err_ip_pair->src_port = err_ip_pair->dst_port = get_icmpx_query_id(icmph);
            break;
        }
        case ICMP_ERROR_MSG:
            // not parsing nested ICMP error
        case ICMP_ACT_UNSPEC:
            // ICMP message not parsed
            return TC_ACT_UNSPEC;
        default:
            bpf_log_error("drop icmp packet");
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int icmp_msg_type(struct icmphdr *icmph) {
    switch (icmph->type) {
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETERPROB:
        return ICMP_ERROR_MSG;
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}
/// ICMP Related End

static __always_inline int extract_iphdr_info(struct ip_packet_info *pkt, const struct iphdr *iph) {
#define BPF_LOG_TOPIC "extract_iphdr_info"

    if (iph->version != 4) {
        return TC_ACT_SHOT;
    }
    inet_addr_set_ip(&pkt->pair_ip.src_addr, iph->saddr);
    inet_addr_set_ip(&pkt->pair_ip.dst_addr, iph->daddr);

    pkt->fragment_off = (bpf_ntohs(iph->frag_off) & IP_OFFSET) << 3;
    if (iph->frag_off & IP_MF) {
        pkt->fragment_type = MORE_F;
    } else if (pkt->fragment_off) {
        pkt->fragment_type = END_F;
    } else {
        pkt->fragment_type = NOT_F;
    }
    pkt->fragment_id = bpf_ntohs(iph->id);
    pkt->ip_protocol = iph->protocol;
    pkt->l4_payload_offset += (iph->ihl * 4);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
/// @brief 提取数据包中的主要内容
/// @param skb
/// @param pkt
/// @return
static __always_inline int extract_packet_info(struct __sk_buff *skb, struct ip_packet_info *pkt) {
#define BPF_LOG_TOPIC "extract_packet_info"
    pkt->_pad = 0;
    if (pkt == NULL) {
        return TC_ACT_SHOT;
    }
    int eth_offset = current_eth_net_offset;
    pkt->l4_payload_offset = eth_offset;
    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, eth_offset, sizeof(struct iphdr))) {
        return TC_ACT_SHOT;
    }

    if (extract_iphdr_info(pkt, iph)) {
        return TC_ACT_SHOT;
    }

    // bpf_log_info("packet l4_payload offset: %d", pkt->l4_payload_offset);
    pkt->pkt_type = PKT_CONNLESS;
    pkt->icmp_error_payload_offset = -1;

    if (pkt->fragment_type != NOT_F && pkt->fragment_off != 0) {
        // 不是第一个数据包， 整个都是 payload
        // 因为没有头部信息, 所以 需要进行查询已有的 track 记录
        pkt->l4_payload_offset = -1;
        pkt->pair_ip.src_port = 0;
        pkt->pair_ip.dst_port = 0;
        return TC_ACT_OK;
    }

    if (pkt->ip_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, pkt->l4_payload_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pkt->pair_ip.src_port = tcph->source;
        pkt->pair_ip.dst_port = tcph->dest;
        // bpf_log_info("packet dst_port: %d", bpf_ntohs(tcph->dest));
        if (tcph->fin) {
            pkt->pkt_type = PKT_TCP_FIN;
        } else if (tcph->rst) {
            pkt->pkt_type = PKT_TCP_RST;
        } else if (tcph->syn) {
            pkt->pkt_type = PKT_TCP_SYN;
        } else {
            pkt->pkt_type = PKT_TCP_DATA;
        }
    } else if (pkt->ip_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, pkt->l4_payload_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pkt->pair_ip.src_port = udph->source;
        pkt->pair_ip.dst_port = udph->dest;
    } else if (pkt->ip_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, pkt->l4_payload_offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }
        //
        int ret;
        switch (icmp_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            struct inet_pair err_ip_pair = {};
            u32 err_l3_hdr_len;
            ret = extract_imcp_err_info(skb, icmp_err_l3_offset(pkt->l4_payload_offset),
                                        &err_ip_pair, &pkt->ip_protocol, &err_l3_hdr_len);
            if (ret != TC_ACT_OK) {
                return ret;
            }
            pkt->icmp_error_payload_offset =
                icmp_err_l3_offset(pkt->l4_payload_offset) + err_l3_hdr_len;
            bpf_log_trace("ICMP error protocol:%d, %pI4->%pI4, %pI4->%pI4, %d->%d",
                          pkt->ip_protocol, &pkt->pair_ip.src_addr, &pkt->pair_ip.dst_addr,
                          &err_ip_pair.src_addr.ip, &err_ip_pair.dst_addr.ip,
                          bpf_ntohs(err_ip_pair.src_port), bpf_ntohs(err_ip_pair.dst_port));

            if (!inet_addr_equal(&pkt->pair_ip.dst_addr, &err_ip_pair.src_addr)) {
                bpf_log_error("IP destination address does not match source "
                              "address inside ICMP error message");
                return TC_ACT_SHOT;
            }

            COPY_ADDR_FROM(pkt->pair_ip.src_addr.all, err_ip_pair.dst_addr.all);
            pkt->pair_ip.src_port = err_ip_pair.dst_port;
            pkt->pair_ip.dst_port = err_ip_pair.src_port;
            break;
        }
        case ICMP_QUERY_MSG: {
            pkt->pair_ip.src_port = pkt->pair_ip.dst_port = get_icmpx_query_id(icmph);
            bpf_log_trace("ICMP query, id:%d", bpf_ntohs(pkt->pair_ip.src_port));
            break;
        }
        case ICMP_ACT_UNSPEC:
            return TC_ACT_UNSPEC;
        default:
            bpf_log_error("icmp shot");
            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int current_pkg_type(struct __sk_buff *skb) {
    if (current_eth_net_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
            return TC_ACT_UNSPEC;
        }

        if (eth->h_proto != ETH_IPV4) {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_UNSPEC;
        }
        u8 ip_version = (*p_version) >> 4;
        if (ip_version != 4) {
            return TC_ACT_UNSPEC;
        }
    }
    return TC_ACT_OK;
}
SEC("tc")
int ingress_nat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">>> ingress_nat >>>"

    if (current_pkg_type(skb) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    // bpf_log_info("active");
    struct ip_packet_info packet_info;
    __builtin_memset(&packet_info, 0, sizeof(packet_info));
    // 接续数据包填充 eth_fram_info 的信息
    int ret = extract_packet_info(skb, &packet_info);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    // 检查是否有分片 并设置实际的 IP 端口
    ret = fragment_track(skb, &packet_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }
    u16 dst_port = bpf_ntohs(packet_info.pair_ip.dst_port);
    u8 *expose_port = NULL;
    if (packet_info.ip_protocol == IPPROTO_TCP) {
        if (dst_port < tcp_range_start || dst_port > tcp_range_end) {
            // bpf_log_info("find expose_port: %u", dst_port);
            expose_port = bpf_map_lookup_elem(&nat_expose_ports, &packet_info.pair_ip.dst_port);
        }
    } else if (packet_info.ip_protocol == IPPROTO_UDP) {
        if (dst_port < udp_range_start || dst_port > udp_range_end) {
            // bpf_log_info("find expose_port: %u", dst_port);
            expose_port = bpf_map_lookup_elem(&nat_expose_ports, &packet_info.pair_ip.dst_port);
        }
    }
    if (expose_port != NULL) {
        // bpf_log_info("find expose_port");
        return TC_ACT_OK;
    }

    bool is_icmpx_error = is_icmp_error_pkt(&packet_info);
    bool allow_create_mapping = packet_info.ip_protocol == IPPROTO_ICMP;

    // egress  存储的是 Ac:Pc -> An:Pn 的值
    // ingress 存储的是 An:Pn -> Ac:Pc 的值
    struct nat_mapping_value *nat_egress_value, *nat_ingress_value;

    // bpf_log_info("allow_create_mapping : %d", allow_create_mapping);

    ret = lookup_static_mapping(skb, packet_info.ip_protocol, NAT_MAPPING_INGRESS,
                                &packet_info.pair_ip, &nat_ingress_value, &nat_egress_value);
    if (ret != TC_ACT_OK) {
        ret = ingress_lookup_or_new_mapping(skb, packet_info.ip_protocol, allow_create_mapping,
                                            &packet_info.pair_ip, &nat_egress_value,
                                            &nat_ingress_value);

        // bpf_log_info("packet src port: %u ", bpf_ntohs(packet_info.pair_ip.src_port));
        // bpf_log_info("modify port: %u -> %u", bpf_ntohs(packet_info.pair_ip.dst_port),
        // bpf_ntohs(nat_egress_value->port));

        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }

        // bpf_log_info("ingress value, %pI4 : %u", &nat_ingress_value->addr,
        //              bpf_ntohs(nat_ingress_value->port));
        // bpf_log_info("egress  value, %pI4 : %u", &nat_egress_value->addr.ip,
        //              bpf_ntohs(nat_egress_value->port));

        if (!nat_egress_value->is_static) {
            struct nat_timer_value *ct_timer_value;
            ret = lookup_or_new_ct(packet_info.ip_protocol, allow_create_mapping,
                                   &packet_info.pair_ip, nat_egress_value, nat_ingress_value,
                                   &ct_timer_value);
            if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
                return TC_ACT_SHOT;
            }
            if (!is_icmpx_error || ct_timer_value != NULL) {
                ct_state_transition(packet_info.ip_protocol, packet_info.pkt_type,
                                    NAT_MAPPING_EGRESS, ct_timer_value);
            }
        }
        // } else {
        //     bpf_log_info("packet dst port: %u -> %u", bpf_ntohs(packet_info.pair_ip.src_port),
        //                  bpf_ntohs(packet_info.pair_ip.dst_port));
        //     bpf_log_info("modify dst port:  %u -> %u", bpf_ntohs(packet_info.pair_ip.src_port),
        //                  bpf_ntohs(nat_ingress_value->port));

        //     bpf_log_info("src IP: %pI4,", &packet_info.pair_ip.src_addr);
        //     bpf_log_info("dst IP: %pI4,", &packet_info.pair_ip.dst_addr);
        //     bpf_log_info("real IP: %pI4,", &nat_ingress_value->addr);
    }

    // modify source
    ret = modify_headers(skb, true, is_icmpx_error, packet_info.ip_protocol, current_eth_net_offset,
                         packet_info.l4_payload_offset, packet_info.icmp_error_payload_offset,
                         false, &packet_info.pair_ip.dst_addr, packet_info.pair_ip.dst_port,
                         &nat_ingress_value->addr, nat_ingress_value->port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

static __always_inline int self_packet(struct __sk_buff *skb, struct ip_packet_info *pkt) {
#define BPF_LOG_TOPIC "self_packet"
    if (pkt->ip_protocol == IPPROTO_ICMP) {
        return TC_ACT_UNSPEC;
    }
    struct bpf_sock_tuple server = {0};
    struct bpf_sock *sk = NULL;

    server.ipv4.saddr = pkt->pair_ip.dst_addr.ip;
    server.ipv4.sport = pkt->pair_ip.dst_port;
    server.ipv4.dport = pkt->pair_ip.src_port;
    server.ipv4.daddr = pkt->pair_ip.src_addr.ip;
    if (pkt->ip_protocol == IPPROTO_TCP) {
        sk = bpf_sk_lookup_tcp(skb, &server, sizeof(server.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else if (pkt->ip_protocol == IPPROTO_UDP) {
        sk = bpf_sk_lookup_udp(skb, &server, sizeof(server.ipv4), BPF_F_CURRENT_NETNS, 0);
    }

    // 找到了 SK
    if (sk != NULL) {
        bpf_sk_release(sk);
        // bpf_log_info("find sk");
        return TC_ACT_OK;
    }
    // 找不到
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int egress_nat(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< egress_nat <<<"

    if (current_pkg_type(skb) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    // bpf_log_info("active");
    struct ip_packet_info packet_info;
    __builtin_memset(&packet_info, 0, sizeof(packet_info));
    // 接续数据包填充 eth_fram_info 的信息
    int ret = extract_packet_info(skb, &packet_info);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }
    // bpf_log_info("packet pkt_type: %d", packet_info.pkt_type);

    // 检查是否有分片 并设置实际的 IP 端口
    ret = fragment_track(skb, &packet_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }
    // bpf_log_info("packet pkt_type: %d", packet_info.pkt_type);
    // bpf_log_info("icmp_error_payload_offset: %d", packet_info.icmp_error_payload_offset);

    if (bpf_map_lookup_elem(&nat_expose_ports, &packet_info.pair_ip.src_port) != NULL) {
        if (self_packet(skb, &packet_info) == TC_ACT_OK) {
            return TC_ACT_OK;
        }
    }

    bool is_icmpx_error = is_icmp_error_pkt(&packet_info);
    bool allow_create_mapping = !is_icmpx_error && pkt_allow_initiating_ct(packet_info.pkt_type);

    // egress  存储的是 Ac:Pc -> An:Pn 的值
    // ingress 存储的是 An:Pn -> Ac:Pc 的值
    struct nat_mapping_value *nat_egress_value, *nat_ingress_value;

    // bpf_log_info("allow_create_mapping : %d", allow_create_mapping);

    ret = lookup_static_mapping(skb, packet_info.ip_protocol, NAT_MAPPING_EGRESS,
                                &packet_info.pair_ip, &nat_egress_value, &nat_ingress_value);

    if (ret != TC_ACT_OK) {
        ret = egress_lookup_or_new_mapping(skb, packet_info.ip_protocol, allow_create_mapping,
                                           &packet_info.pair_ip, &nat_egress_value,
                                           &nat_ingress_value);

        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }

        u8 action = skb->mark & ACTION_MASK;
        if (action == SYMMETRIC_NAT) {
            // SYMMETRIC_NAT check
            if (!ip_addr_equal(&packet_info.pair_ip.dst_addr, &nat_egress_value->trigger_addr) ||
                packet_info.pair_ip.dst_port != nat_egress_value->trigger_port) {
                bpf_log_info("SYMMETRIC_NAT MARK DROP PACKET");
                bpf_log_info("dst IP: %pI4,", &packet_info.pair_ip.dst_addr);
                bpf_log_info("trigger_addr IP: %pI4,", &nat_egress_value->trigger_addr);
                bpf_log_info(
                    "compare ip result: %d",
                    ip_addr_equal(&packet_info.pair_ip.dst_addr, &nat_egress_value->trigger_addr));
                bpf_log_info("trigger_port: %u,", bpf_ntohs(nat_egress_value->trigger_port));
                bpf_log_info("dst_port: %u,", bpf_ntohs(packet_info.pair_ip.dst_port));
                bpf_log_info("compare port result: %d",
                             packet_info.pair_ip.dst_port == nat_egress_value->trigger_port);
                return TC_ACT_SHOT;
            }
        }

        // bpf_log_info("ingress value, %pI4 : %u", &nat_ingress_value->addr,
        //              bpf_ntohs(nat_ingress_value->port));
        // bpf_log_info("egress  value, %pI4 : %u", &nat_egress_value->addr.ip,
        //              bpf_ntohs(nat_egress_value->port));

        if (!nat_egress_value->is_static) {
            struct nat_timer_value *ct_timer_value;
            ret = lookup_or_new_ct(packet_info.ip_protocol, allow_create_mapping,
                                   &packet_info.pair_ip, nat_egress_value, nat_ingress_value,
                                   &ct_timer_value);
            if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
                return TC_ACT_SHOT;
            }
            if (!is_icmpx_error || ct_timer_value != NULL) {
                ct_state_transition(packet_info.ip_protocol, packet_info.pkt_type,
                                    NAT_MAPPING_EGRESS, ct_timer_value);
            }
        }
    }

    // bpf_log_info("packet src port: %u -> %u", bpf_ntohs(packet_info.pair_ip.src_port),
    //              bpf_ntohs(packet_info.pair_ip.dst_port));
    // bpf_log_info("modify src port:  %u -> %u", bpf_ntohs(nat_egress_value->port),
    //              bpf_ntohs(packet_info.pair_ip.dst_port));

    // bpf_log_info("src IP: %pI4,", &packet_info.pair_ip.src_addr);
    // bpf_log_info("dst IP: %pI4,", &packet_info.pair_ip.dst_addr);
    // bpf_log_info("mapping IP: %pI4,", &nat_egress_value->addr);

    // modify source
    ret = modify_headers(skb, true, is_icmpx_error, packet_info.ip_protocol, current_eth_net_offset,
                         packet_info.l4_payload_offset, packet_info.icmp_error_payload_offset, true,
                         &packet_info.pair_ip.src_addr, packet_info.pair_ip.src_port,
                         &nat_egress_value->addr, nat_egress_value->port);
    if (ret) {
        bpf_log_error("failed to update csum, err:%d", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}