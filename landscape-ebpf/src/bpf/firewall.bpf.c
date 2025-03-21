#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "firewall.h"
#include "firewall_share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;
const volatile int current_eth_net_offset = 14;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

SEC("tc") int ipv4_egress_firewall(struct __sk_buff *skb);
SEC("tc") int ipv4_ingress_firewall(struct __sk_buff *skb);
SEC("tc") int ipv6_egress_firewall(struct __sk_buff *skb);
SEC("tc") int ipv6_ingress_firewall(struct __sk_buff *skb);
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __array(values, int());
} prog_array SEC(".maps") = {
    .values =
        {
            [IPV4_EGRESS_PROG_INDEX] = (void *)&ipv4_egress_firewall,
            [IPV4_INGRESS_PROG_INDEX] = (void *)&ipv4_ingress_firewall,
            [IPV6_EGRESS_PROG_INDEX] = (void *)&ipv6_egress_firewall,
            [IPV6_INGRESS_PROG_INDEX] = (void *)&ipv6_ingress_firewall,
        },
};

#define FRAG_CACHE_SIZE 1024 * 32
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct fragment_cache_key);
    __type(value, struct fragment_cache_value);
    __uint(max_entries, FRAG_CACHE_SIZE);
} fragment_cache SEC(".maps");

static __always_inline int icmp_msg_type(struct icmphdr *icmph);
static __always_inline bool is_icmp_error_pkt(const struct packet_context *pkt) {
    return pkt->l4_payload_offset >= 0 && pkt->icmp_error_payload_offset >= 0;
}

static __always_inline bool pkt_allow_initiating_ct(u8 pkt_type) {
    return pkt_type == PKT_CONNLESS || pkt_type == PKT_TCP_SYN;
}

/// IP Fragment Related Start
static __always_inline int fragment_track(struct __sk_buff *skb, struct ip_context *pkt) {
#define BPF_LOG_TOPIC "fragment_track"

    // 没有被分片的数据包, 无需进行记录
    if (pkt->fragment_type == NOT_F || (pkt->fragment_type == END_F && pkt->fragment_off == 0)) {
        return TC_ACT_OK;
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

/// ICMP Related Start
static __always_inline int icmp_err_l3_offset(int l4_off) { return l4_off + ICMP_HDR_LEN; }

static __always_inline __be16 get_icmpx_query_id(struct icmphdr *icmph) {
    return icmph->un.echo.id;
}

static __always_inline int extract_iphdr_info(struct __sk_buff *skb, u32 *l3_offset,
                                              struct ip_context *ip_cxt) {
#define BPF_LOG_TOPIC "extract_iphdr_info"

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, *l3_offset, sizeof(*iph))) {
        return TC_ACT_SHOT;
    }

    if (iph->version != 4) {
        return TC_ACT_SHOT;
    }

    ip_cxt->pair_ip.src_addr.ip = iph->saddr;
    ip_cxt->pair_ip.dst_addr.ip = iph->daddr;

    ip_cxt->fragment_off = (bpf_ntohs(iph->frag_off) & IP_OFFSET) << 3;
    if (iph->frag_off & IP_MF) {
        ip_cxt->fragment_type = MORE_F;
    } else if (ip_cxt->fragment_off) {
        ip_cxt->fragment_type = END_F;
    } else {
        ip_cxt->fragment_type = NOT_F;
    }
    ip_cxt->fragment_id = bpf_ntohs(iph->id);

    ip_cxt->ip_protocol = iph->protocol;
    *l3_offset += (iph->ihl * 4);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int extract_ipv6hdr_info(struct __sk_buff *skb, u32 *l3_offset,
                                                struct ip_context *ip_cxt) {
#define BPF_LOG_TOPIC "extract_ipv6hdr_info"

    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, *l3_offset, sizeof(*ip6h))) {
        return TC_ACT_SHOT;
    }

    if (ip6h->version != 6) {
        return TC_ACT_SHOT;
    }

    int offset = *l3_offset;

    COPY_ADDR_FROM(ip_cxt->pair_ip.src_addr.ip6, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(ip_cxt->pair_ip.dst_addr.ip6, ip6h->daddr.in6_u.u6_addr32);

    int len = sizeof(struct ipv6hdr);
    u32 frag_hdr_off = 0;
    u8 nexthdr = ip6h->nexthdr;

    struct ipv6_opt_hdr *opthdr;
    struct frag_hdr *frag_hdr;

    for (int i = 0; i < MAX_IPV6_EXT_NUM; i++) {
        switch (nexthdr) {
        case NEXTHDR_AUTH:
            // Just passthrough IPSec packet
            return TC_ACT_UNSPEC;
        case NEXTHDR_FRAGMENT:
            frag_hdr_off = len;
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST: {
            // if (bpf_skb_load_bytes(skb, offset + len, &opthdr, sizeof(opthdr))) {
            //     return TC_ACT_SHOT;
            // }
            if (VALIDATE_READ_DATA(skb, &opthdr, offset + len, sizeof(*opthdr))) {
                return TC_ACT_SHOT;
            }
            len += (opthdr->hdrlen + 1) * 8;
            nexthdr = opthdr->nexthdr;
            break;
        }
        default:
            goto found_upper_layer;
        }
    }

    switch (nexthdr) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
    case NEXTHDR_ICMP:
        goto found_upper_layer;
    default:
        return TC_ACT_UNSPEC;
    }

found_upper_layer:
    if (frag_hdr_off) {
        // if (bpf_skb_load_bytes(skb, offset + frag_hdr_off, &frag_hdr, sizeof(frag_hdr))) {
        //     return TC_ACT_SHOT;
        // }

        if (VALIDATE_READ_DATA(skb, &frag_hdr, offset + frag_hdr_off, sizeof(*frag_hdr))) {
            return TC_ACT_SHOT;
        }
        ip_cxt->fragment_id = bpf_ntohl(frag_hdr->identification);
        ip_cxt->fragment_off = bpf_ntohs(frag_hdr->frag_off & bpf_htons(IPV6_FRAG_OFFSET));

        if (frag_hdr->frag_off & bpf_htons(IPV6_FRAG_MF)) {
            ip_cxt->fragment_type = MORE_F;
        } else if (ip_cxt->fragment_off) {
            ip_cxt->fragment_type = END_F;
        } else {
            ip_cxt->fragment_type = NOT_F;
        }
    }

    ip_cxt->ip_protocol = nexthdr;
    *l3_offset += len;

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#define ICMP_ERR_PACKET_L4_LEN 8
static __always_inline int extract_imcp_err_info(struct __sk_buff *skb, u32 *l3_offset,
                                                 struct ip_context *ip_ctx) {
#define BPF_LOG_TOPIC "extract_imcp_err_info"

    if (ip_ctx->ip_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, *l3_offset, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        ip_ctx->pair_ip.src_port = tcph->source;
        ip_ctx->pair_ip.dst_port = tcph->dest;
    } else if (ip_ctx->ip_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, *l3_offset, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        ip_ctx->pair_ip.src_port = udph->source;
        ip_ctx->pair_ip.dst_port = udph->dest;
    } else if (ip_ctx->ip_protocol == IPPROTO_ICMP) {
        void *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, *l3_offset, ICMP_ERR_PACKET_L4_LEN)) {
            return TC_ACT_SHOT;
        }
        switch (icmp_msg_type(icmph)) {
        case ICMP_QUERY_MSG: {
            ip_ctx->pair_ip.src_port = ip_ctx->pair_ip.dst_port = get_icmpx_query_id(icmph);
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

static __always_inline int icmp6_msg_type(struct icmp6hdr *icmp6h) {
    switch (icmp6h->icmp6_type) {
    case ICMPV6_DEST_UNREACH:
    case ICMPV6_PKT_TOOBIG:
    case ICMPV6_TIME_EXCEED:
    case ICMPV6_PARAMPROB:
        return ICMP_ERROR_MSG;
    case ICMPV6_ECHO_REQUEST:
    case ICMPV6_ECHO_REPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

/// ICMP Related End

static __always_inline bool ct_change_state(struct firewall_conntrack_action *timer_track_value,
                                            u64 curr_state, u64 next_state) {
    return __sync_bool_compare_and_swap(&timer_track_value->status, curr_state, next_state);
}

static __always_inline int ct_reset_timer(struct firewall_conntrack_action *timer_track_value,
                                          u64 timeout) {
#define BPF_LOG_TOPIC "ct_reset_timer"
    // bpf_log_info("ct_reset_timer : %llu", timeout);
    return bpf_timer_start(&timer_track_value->timer, timeout, 0);
#undef BPF_LOG_TOPIC
}

static __always_inline int ct_state_transition(u8 l4proto, u8 pkt_type,
                                               struct firewall_conntrack_action *ct_timer_value) {
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
        RESET_TIMER(TCP_SYN_TIMEOUT);
        return TC_ACT_OK;
    }

    RESET_TIMER(TCP_TIMEOUT);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static int timer_clean_callback(void *map_mapping_timer_, struct firewall_conntrack_key *key,
                                struct firewall_conntrack_action *value) {
#define BPF_LOG_TOPIC "timer_clean_callback"

    bpf_log_info("timer_clean_callback: %d", bpf_ntohs(value->trigger_port));

    bpf_map_delete_elem(&firewall_conntrack_map, key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat_timer_value *
insert_new_nat_timer(const struct firewall_conntrack_key *key,
                     const struct firewall_conntrack_action *val) {
#define BPF_LOG_TOPIC "insert_new_nat_timer"
    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    // bpf_ntohs(key->pair_ip.src_port), bpf_ntohs(key->pair_ip.dst_port)); bpf_log_info("src_ip:
    // %lu -> dst_ip: %lu", bpf_ntohl(key->pair_ip.src_addr.ip),
    // bpf_ntohl(key->pair_ip.dst_addr.ip));

    int ret = bpf_map_update_elem(&firewall_conntrack_map, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct firewall_conntrack_action *value = bpf_map_lookup_elem(&firewall_conntrack_map, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &firewall_conntrack_map, CLOCK_MONOTONIC);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_set_callback(&value->timer, timer_clean_callback);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_start(&value->timer,
                          key->ip_protocol == IPPROTO_TCP ? TCP_TIMEOUT : UDP_TIMEOUT, 0);
    if (ret) {
        goto delete_timer;
    }

    return value;
delete_timer:
    bpf_log_error("setup timer err:%d", ret);
    bpf_map_delete_elem(&firewall_conntrack_map, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline int lookup_static_rules(struct firewall_static_rule_key *timer_key,
                                               struct firewall_conntrack_action **timer_value_) {
#define BPF_LOG_TOPIC "lookup_static_rules"
    struct firewall_conntrack_action *action;
    action = bpf_map_lookup_elem(&firewall_allow_rules_map, timer_key);
    if (action) {
        *timer_value_ = action;
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
static __always_inline int lookup_or_create_ct(bool do_new,
                                               struct firewall_conntrack_key *timer_key,
                                               union u_inet_addr *remote_addr, __be16 *remote_port,
                                               struct firewall_conntrack_action **timer_value_) {
#define BPF_LOG_TOPIC "lookup_or_create_ct"

    struct firewall_conntrack_action *timer_value =
        bpf_map_lookup_elem(&firewall_conntrack_map, timer_key);
    if (timer_value) {
        *timer_value_ = timer_value;
        return TIMER_EXIST;
    }
    if (!timer_value && !do_new) {
        return TIMER_NOT_FOUND;
    }

    struct firewall_conntrack_action action = {
        .status = TIMER_INIT,
        .mark = 0,
        ._pad = 0,
        .trigger_port = *remote_port,
    };
    COPY_ADDR_FROM(action.trigger_addr.all, remote_addr->all);
    timer_value = insert_new_nat_timer(timer_key, &action);
    if (timer_value == NULL) {
        return TIMER_ERROR;
    }

    // bpf_log_debug("insert new CT, type: %d, ip_protocol: %d, port: %d", timer_key->ip_type,
    //               timer_key->ip_protocol, bpf_ntohs(timer_key->local_port));

    *timer_value_ = timer_value;
    return TIMER_CREATED;
#undef BPF_LOG_TOPIC
}

/// @brief 提取 IPv4 数据包中的主要内容
/// @return
static __always_inline int extract_v4_packet_info(struct __sk_buff *skb,
                                                  struct packet_context *pcxt,
                                                  int current_eth_net_offset) {
#define BPF_LOG_TOPIC "extract_v4_packet_info"
    // pcxt->_pad = 0;
    int ret;
    if (pcxt == NULL) {
        return TC_ACT_SHOT;
    }
    pcxt->l4_payload_offset = current_eth_net_offset;

    ret = extract_iphdr_info(skb, &pcxt->l4_payload_offset, &pcxt->ip_hdr);
    if (ret != TC_ACT_OK) {
        return TC_ACT_SHOT;
    }

    pcxt->ip_hdr.pkt_type = PKT_CONNLESS;
    pcxt->icmp_error_payload_offset = -1;

    if (pcxt->ip_hdr.fragment_type != NOT_F && pcxt->ip_hdr.fragment_off != 0) {
        // 不是第一个数据包， 整个都是 payload
        // 因为没有头部信息, 所以 需要进行查询已有的 track 记录
        pcxt->l4_payload_offset = -1;
        pcxt->ip_hdr.pair_ip.src_port = 0;
        pcxt->ip_hdr.pair_ip.dst_port = 0;
        return TC_ACT_OK;
    }

    if (pcxt->ip_hdr.ip_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, pcxt->l4_payload_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pcxt->ip_hdr.pair_ip.src_port = tcph->source;
        pcxt->ip_hdr.pair_ip.dst_port = tcph->dest;
        // bpf_log_info("packet dst_port: %d", bpf_ntohs(tcph->dest));
        if (tcph->fin) {
            pcxt->ip_hdr.pkt_type = PKT_TCP_FIN;
        } else if (tcph->rst) {
            pcxt->ip_hdr.pkt_type = PKT_TCP_RST;
        } else if (tcph->syn) {
            pcxt->ip_hdr.pkt_type = PKT_TCP_SYN;
        } else {
            pcxt->ip_hdr.pkt_type = PKT_TCP_DATA;
        }
    } else if (pcxt->ip_hdr.ip_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, pcxt->l4_payload_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pcxt->ip_hdr.pair_ip.src_port = udph->source;
        pcxt->ip_hdr.pair_ip.dst_port = udph->dest;
    } else if (pcxt->ip_hdr.ip_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, pcxt->l4_payload_offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }
        pcxt->ip_hdr.icmp_type = icmph->type;
        switch (icmp_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            struct ip_context icmp_error_ip_ctx = {0};
            pcxt->icmp_error_payload_offset = icmp_err_l3_offset(pcxt->l4_payload_offset);
            if (extract_iphdr_info(skb, &pcxt->icmp_error_payload_offset, &icmp_error_ip_ctx)) {
                return TC_ACT_SHOT;
            }
            if (icmp_error_ip_ctx.fragment_off) {
                // icmp 不处理分片导致的 icmp 错误
                return TC_ACT_SHOT;
            }
            ret = extract_imcp_err_info(skb, &pcxt->icmp_error_payload_offset, &icmp_error_ip_ctx);
            if (ret != TC_ACT_OK) {
                return ret;
            }

            bpf_log_trace("ICMP error protocol:%d, %pI4->%pI4, %pI4->%pI4, %d->%d",
                          pcxt->ip_hdr.ip_protocol, &pcxt->ip_hdr.pair_ip.src_addr,
                          &pcxt->ip_hdr.pair_ip.dst_addr, &icmp_error_ip_ctx.pair_ip.src_addr.ip,
                          &icmp_error_ip_ctx.pair_ip.dst_addr.ip,
                          bpf_ntohs(icmp_error_ip_ctx.pair_ip.src_port),
                          bpf_ntohs(icmp_error_ip_ctx.pair_ip.dst_port));

            if (!ip_addr_equal(&pcxt->ip_hdr.pair_ip.dst_addr,
                               &icmp_error_ip_ctx.pair_ip.src_addr)) {
                bpf_log_error("IP destination address does not match source "
                              "address inside ICMP error message");
                return TC_ACT_SHOT;
            }

            COPY_ADDR_FROM(pcxt->ip_hdr.pair_ip.src_addr.all,
                           icmp_error_ip_ctx.pair_ip.dst_addr.all);
            pcxt->ip_hdr.pair_ip.src_port = icmp_error_ip_ctx.pair_ip.dst_port;
            pcxt->ip_hdr.pair_ip.dst_port = icmp_error_ip_ctx.pair_ip.src_port;
            break;
        }
        case ICMP_QUERY_MSG: {
            pcxt->ip_hdr.pair_ip.src_port = pcxt->ip_hdr.pair_ip.dst_port =
                get_icmpx_query_id(icmph);
            // bpf_log_info("ICMP query, id:%d", bpf_ntohs(pcxt->ip_hdr.pair_ip.src_port));
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

/// @brief 提取 IPv4 数据包中的主要内容
/// @return
static __always_inline int extract_v6_packet_info(struct __sk_buff *skb,
                                                  struct packet_context *pcxt,
                                                  int current_eth_net_offset) {
#define BPF_LOG_TOPIC "extract_v6_packet_info"
    int ret;
    if (pcxt == NULL) {
        return TC_ACT_SHOT;
    }
    pcxt->l4_payload_offset = current_eth_net_offset;

    ret = extract_ipv6hdr_info(skb, &pcxt->l4_payload_offset, &pcxt->ip_hdr);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    pcxt->ip_hdr.pkt_type = PKT_CONNLESS;
    pcxt->icmp_error_payload_offset = -1;

    if (pcxt->ip_hdr.fragment_type != NOT_F && pcxt->ip_hdr.fragment_off != 0) {
        // 不是第一个数据包， 整个都是 payload
        // 因为没有头部信息, 所以 需要进行查询已有的 track 记录
        pcxt->l4_payload_offset = -1;
        pcxt->ip_hdr.pair_ip.src_port = 0;
        pcxt->ip_hdr.pair_ip.dst_port = 0;
        return TC_ACT_OK;
    }

    // bpf_log_info("pcxt->l4_payload_offset %d", pcxt->l4_payload_offset);
    // bpf_log_info("pcxt->ip_protocol %d", pcxt->ip_hdr.ip_protocol);
    if (pcxt->ip_hdr.ip_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, pcxt->l4_payload_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pcxt->ip_hdr.pair_ip.src_port = tcph->source;
        pcxt->ip_hdr.pair_ip.dst_port = tcph->dest;
        // bpf_log_info("packet dst_port: %d", bpf_ntohs(tcph->dest));
        if (tcph->fin) {
            pcxt->ip_hdr.pkt_type = PKT_TCP_FIN;
        } else if (tcph->rst) {
            pcxt->ip_hdr.pkt_type = PKT_TCP_RST;
        } else if (tcph->syn) {
            pcxt->ip_hdr.pkt_type = PKT_TCP_SYN;
        } else {
            pcxt->ip_hdr.pkt_type = PKT_TCP_DATA;
        }
    } else if (pcxt->ip_hdr.ip_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, pcxt->l4_payload_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pcxt->ip_hdr.pair_ip.src_port = udph->source;
        pcxt->ip_hdr.pair_ip.dst_port = udph->dest;
    } else if (pcxt->ip_hdr.ip_protocol == IPPROTO_ICMPV6) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, pcxt->l4_payload_offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }
        pcxt->ip_hdr.icmp_type = icmph->type;
        switch (icmp6_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            struct ip_context icmp_error_ip_ctx = {0};
            pcxt->icmp_error_payload_offset = icmp_err_l3_offset(pcxt->l4_payload_offset);
            if (extract_ipv6hdr_info(skb, &pcxt->icmp_error_payload_offset, &icmp_error_ip_ctx)) {
                return TC_ACT_SHOT;
            }
            if (icmp_error_ip_ctx.fragment_off) {
                // icmp 不处理分片导致的 icmp 错误
                return TC_ACT_SHOT;
            }
            ret = extract_imcp_err_info(skb, &pcxt->icmp_error_payload_offset, &icmp_error_ip_ctx);
            if (ret != TC_ACT_OK) {
                return ret;
            }

            bpf_log_trace("ICMP error protocol:%d, %pI4->%pI4, %pI4->%pI4, %d->%d",
                          pcxt->ip_hdr.ip_protocol, &pcxt->ip_hdr.pair_ip.src_addr,
                          &pcxt->ip_hdr.pair_ip.dst_addr, &icmp_error_ip_ctx.pair_ip.src_addr.ip,
                          &icmp_error_ip_ctx.pair_ip.dst_addr.ip,
                          bpf_ntohs(icmp_error_ip_ctx.pair_ip.src_port),
                          bpf_ntohs(icmp_error_ip_ctx.pair_ip.dst_port));

            if (!ip_addr_equal(&pcxt->ip_hdr.pair_ip.dst_addr,
                               &icmp_error_ip_ctx.pair_ip.src_addr)) {
                bpf_log_error("IP destination address does not match source "
                              "address inside ICMP error message");
                return TC_ACT_SHOT;
            }

            COPY_ADDR_FROM(pcxt->ip_hdr.pair_ip.src_addr.all,
                           icmp_error_ip_ctx.pair_ip.dst_addr.all);
            pcxt->ip_hdr.pair_ip.src_port = icmp_error_ip_ctx.pair_ip.dst_port;
            pcxt->ip_hdr.pair_ip.dst_port = icmp_error_ip_ctx.pair_ip.src_port;
            break;
        }
        case ICMP_QUERY_MSG: {
            pcxt->ip_hdr.pair_ip.src_port = pcxt->ip_hdr.pair_ip.dst_port =
                get_icmpx_query_id(icmph);
            // bpf_log_info("ICMP query, id:%d", bpf_ntohs(pcxt->ip_hdr.pair_ip.src_port));
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

SEC("tc")
int ipv4_egress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< ipv4_egress_firewall <<<"

    // bpf_log_info("bpf_tail_call ipv4_egress_firewall");

    struct packet_context packet_info;
    __builtin_memset(&packet_info, 0, sizeof(packet_info));
    int ret = extract_v4_packet_info(skb, &packet_info, current_eth_net_offset);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    if (!is_icmp_error_pkt(&packet_info)) {
        ret = fragment_track(skb, &packet_info.ip_hdr);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
    }

    // bpf_log_trace("packet ip:%pI4->%pI4", &packet_info.ip_hdr.pair_ip.src_addr,
    //               &packet_info.ip_hdr.pair_ip.dst_addr);
    // bpf_log_info("packet ip_protocol: %u ", packet_info.ip_hdr.ip_protocol);
    // bpf_log_info("packet ICMP type: %u ", packet_info.ip_hdr.icmp_type);
    // bpf_log_info("packet src port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port));
    // bpf_log_info("packet dst port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port));

    struct ipv4_lpm_key block_search_key = {
        .prefixlen = 32,
        .addr = packet_info.ip_hdr.pair_ip.dst_addr.ip,
    };
    struct ipv4_mark_action *mark_value =
        bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key);

    if (mark_value) {
        return TC_ACT_SHOT;
    }

    // 先检查是否有规则已经放行
    struct firewall_static_rule_key rule_key = {
        .prefixlen = 64,
        .ip_type = LANDSCAPE_IPV4_TYPE,
        .ip_protocol = packet_info.ip_hdr.ip_protocol,
        .local_port = packet_info.ip_hdr.pair_ip.src_port,
    };
    COPY_ADDR_FROM(rule_key.remote_address.all, &packet_info.ip_hdr.pair_ip.src_addr.all);

    if (packet_info.ip_hdr.ip_protocol == IPPROTO_ICMP) {
        rule_key.local_port = ((u16)packet_info.ip_hdr.icmp_type << 8);
    }
    struct firewall_static_ct_action *static_ct_value = NULL;
    ret = lookup_static_rules(&rule_key, &static_ct_value);
    if (static_ct_value == NULL) {
        struct firewall_conntrack_key conntrack_key = {
            .ip_type = LANDSCAPE_IPV4_TYPE,
            .ip_protocol = packet_info.ip_hdr.ip_protocol,
            .local_port = packet_info.ip_hdr.pair_ip.src_port};
        COPY_ADDR_FROM(conntrack_key.local_addr.all, &packet_info.ip_hdr.pair_ip.src_addr.all);
        // 需要进行创建
        bool is_icmpx_error = is_icmp_error_pkt(&packet_info);
        bool allow_create_mapping =
            !is_icmpx_error && pkt_allow_initiating_ct(packet_info.ip_hdr.pkt_type);

        // 没有端口开放 那就进行检查是否已经动态添加过了
        struct firewall_conntrack_action *ct_timer_value;
        ret = lookup_or_create_ct(allow_create_mapping, &conntrack_key,
                                  &packet_info.ip_hdr.pair_ip.dst_addr,
                                  &packet_info.ip_hdr.pair_ip.dst_port, &ct_timer_value);

        if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error || ct_timer_value != NULL) {
            ct_state_transition(packet_info.ip_hdr.ip_protocol, packet_info.ip_hdr.pkt_type,
                                ct_timer_value);
        }
    } else {
        // bpf_log_info("has firewall rule");
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ipv4_ingress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< ipv4_ingress_firewall <<<"

    struct packet_context packet_info;
    __builtin_memset(&packet_info, 0, sizeof(packet_info));
    int ret = extract_v4_packet_info(skb, &packet_info, current_eth_net_offset);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    if (!is_icmp_error_pkt(&packet_info)) {
        ret = fragment_track(skb, &packet_info.ip_hdr);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
    }

    // bpf_log_info("packet ip:%pI4->%pI4", &packet_info.ip_hdr.pair_ip.src_addr,
    //     &packet_info.ip_hdr.pair_ip.dst_addr);

    // bpf_log_info("packet ip_protocol: %u ", packet_info.ip_hdr.ip_protocol);
    // bpf_log_info("packet src port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port));
    // bpf_log_info("packet dst port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port));

    struct ipv4_lpm_key block_search_key = {
        .prefixlen = 32,
        .addr = packet_info.ip_hdr.pair_ip.src_addr.ip,
    };
    struct ipv4_mark_action *mark_value =
        bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key);

    if (mark_value) {
        return TC_ACT_SHOT;
    }

    // 先检查是否已经有旧连接了
    struct firewall_conntrack_key conntrack_key = {.ip_type = LANDSCAPE_IPV4_TYPE,
                                                   .ip_protocol = packet_info.ip_hdr.ip_protocol,
                                                   .local_port =
                                                       packet_info.ip_hdr.pair_ip.dst_port};
    COPY_ADDR_FROM(conntrack_key.local_addr.all, &packet_info.ip_hdr.pair_ip.dst_addr.all);

    struct firewall_conntrack_action *ct_timer_value;
    ret = lookup_or_create_ct(false, &conntrack_key, &packet_info.ip_hdr.pair_ip.src_addr,
                              &packet_info.ip_hdr.pair_ip.src_port, &ct_timer_value);

    if (ret == TIMER_EXIST || ret == TIMER_CREATED) {
        if (ct_timer_value != NULL) {
            ct_state_transition(packet_info.ip_hdr.ip_protocol, packet_info.ip_hdr.pkt_type,
                                ct_timer_value);
            return TC_ACT_UNSPEC;
        }
        bpf_log_error("ct_timer_value is NULL");
        return TC_ACT_SHOT;
    }

    // 检查用户是否已配置端口开放了
    struct firewall_static_rule_key rule_key = {
        .prefixlen = 64,
        .ip_type = LANDSCAPE_IPV4_TYPE,
        .ip_protocol = packet_info.ip_hdr.ip_protocol,
        .local_port = packet_info.ip_hdr.pair_ip.dst_port,
    };
    COPY_ADDR_FROM(rule_key.remote_address.all, &packet_info.ip_hdr.pair_ip.dst_addr.all);

    if (packet_info.ip_hdr.ip_protocol == IPPROTO_ICMP) {
        rule_key.local_port = ((u16)packet_info.ip_hdr.icmp_type << 8);
    }
    struct firewall_static_ct_action *static_ct_value = NULL;
    ret = lookup_static_rules(&rule_key, &static_ct_value);
    if (static_ct_value != NULL) {
        // bpf_log_info("has firewall rule");
        // bpf_log_info(
        //     "packet ip:%pI4:%d->%pI4:%d, ip_protocol: %d", &packet_info.ip_hdr.pair_ip.src_addr,
        //     bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port), &packet_info.ip_hdr.pair_ip.dst_addr,
        //     bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port), packet_info.ip_hdr.ip_protocol);
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ipv6_egress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< ipv6_egress_firewall <<<"

    struct packet_context packet_info;
    __builtin_memset(&packet_info, 0, sizeof(packet_info));
    int ret = extract_v6_packet_info(skb, &packet_info, current_eth_net_offset);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    if (!is_icmp_error_pkt(&packet_info)) {
        ret = fragment_track(skb, &packet_info.ip_hdr);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
    }

    // bpf_log_info("packet ip: [%pI6c]->[%pI6c]", &packet_info.ip_hdr.pair_ip.src_addr,
    //              &packet_info.ip_hdr.pair_ip.dst_addr);
    // bpf_log_info("packet ip_protocol: %u ", packet_info.ip_hdr.ip_protocol);
    // bpf_log_info("packet src port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port));
    // bpf_log_info("packet dst port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port));

    struct ipv6_lpm_key block_search_key = {
        .prefixlen = 128,
        .addr = packet_info.ip_hdr.pair_ip.dst_addr.ip,
    };
    struct firewall_action *mark_value =
        bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key);

    if (mark_value) {
        return TC_ACT_SHOT;
    }

    // 先检查是否有规则已经放行
    struct firewall_static_rule_key rule_key = {
        .prefixlen = 160,
        .ip_type = LANDSCAPE_IPV6_TYPE,
        .ip_protocol = packet_info.ip_hdr.ip_protocol,
        .local_port = packet_info.ip_hdr.pair_ip.src_port,
    };
    if (packet_info.ip_hdr.ip_protocol == IPPROTO_ICMPV6) {
        rule_key.local_port = ((u16)packet_info.ip_hdr.icmp_type << 8);
    }
    COPY_ADDR_FROM(rule_key.remote_address.all, &packet_info.ip_hdr.pair_ip.src_addr.all);

    struct firewall_static_ct_action *static_ct_value = NULL;
    ret = lookup_static_rules(&rule_key, &static_ct_value);
    if (static_ct_value == NULL) {
        struct firewall_conntrack_key conntrack_key = {
            .ip_type = LANDSCAPE_IPV6_TYPE,
            .ip_protocol = packet_info.ip_hdr.ip_protocol,
            .local_port = packet_info.ip_hdr.pair_ip.src_port};
        COPY_ADDR_FROM(conntrack_key.local_addr.all, &packet_info.ip_hdr.pair_ip.src_addr.all);
        // 需要进行创建
        bool is_icmpx_error = is_icmp_error_pkt(&packet_info);
        bool allow_create_mapping =
            !is_icmpx_error && pkt_allow_initiating_ct(packet_info.ip_hdr.pkt_type);

        // 没有端口开放 那就进行检查是否已经动态添加过了
        struct firewall_conntrack_action *ct_timer_value;
        ret = lookup_or_create_ct(allow_create_mapping, &conntrack_key,
                                  &packet_info.ip_hdr.pair_ip.dst_addr,
                                  &packet_info.ip_hdr.pair_ip.dst_port, &ct_timer_value);

        if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error || ct_timer_value != NULL) {
            ct_state_transition(packet_info.ip_hdr.ip_protocol, packet_info.ip_hdr.pkt_type,
                                ct_timer_value);
        }
    } else {
        // bpf_log_info("has firewall rule");
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ipv6_ingress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< ipv6_ingress_firewall <<<"

    struct packet_context packet_info;
    __builtin_memset(&packet_info, 0, sizeof(packet_info));
    int ret = extract_v6_packet_info(skb, &packet_info, current_eth_net_offset);
    if (ret != TC_ACT_OK) {
        if (ret == TC_ACT_SHOT) {
            bpf_log_trace("invalid packet");
        }
        return TC_ACT_UNSPEC;
    }

    if (!is_icmp_error_pkt(&packet_info)) {
        ret = fragment_track(skb, &packet_info.ip_hdr);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
    }

    // bpf_log_info("packet ip: [%pI6c]->[%pI6c]", &packet_info.ip_hdr.pair_ip.src_addr,
    //              &packet_info.ip_hdr.pair_ip.dst_addr);
    // bpf_log_info("packet ip_protocol: %u ", packet_info.ip_hdr.ip_protocol);
    // bpf_log_info("packet src port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port));
    // bpf_log_info("packet dst port: %u ", bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port));

    struct ipv6_lpm_key block_search_key = {
        .prefixlen = 128,
        .addr = packet_info.ip_hdr.pair_ip.src_addr.ip,
    };
    struct firewall_action *mark_value =
        bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key);

    if (mark_value) {
        return TC_ACT_SHOT;
    }

    // 先检查是否已经有旧连接了
    struct firewall_conntrack_key conntrack_key = {.ip_type = LANDSCAPE_IPV6_TYPE,
                                                   .ip_protocol = packet_info.ip_hdr.ip_protocol,
                                                   .local_port =
                                                       packet_info.ip_hdr.pair_ip.dst_port};
    COPY_ADDR_FROM(conntrack_key.local_addr.all, &packet_info.ip_hdr.pair_ip.dst_addr.all);

    struct firewall_conntrack_action *ct_timer_value;
    ret = lookup_or_create_ct(false, &conntrack_key, &packet_info.ip_hdr.pair_ip.src_addr,
                              &packet_info.ip_hdr.pair_ip.src_port, &ct_timer_value);

    if (ret == TIMER_EXIST || ret == TIMER_CREATED) {
        if (ct_timer_value != NULL) {
            ct_state_transition(packet_info.ip_hdr.ip_protocol, packet_info.ip_hdr.pkt_type,
                                ct_timer_value);
            return TC_ACT_UNSPEC;
        }
        bpf_log_info("ct_timer_value is NULL");
        return TC_ACT_SHOT;
    }

    // bpf_log_info("can not find exist conntrack");

    // 检查用户是否已配置端口开放了
    struct firewall_static_rule_key rule_key = {
        .prefixlen = 160,
        .ip_type = LANDSCAPE_IPV6_TYPE,
        .ip_protocol = packet_info.ip_hdr.ip_protocol,
        .local_port = packet_info.ip_hdr.pair_ip.dst_port,
    };
    COPY_ADDR_FROM(rule_key.remote_address.all, &packet_info.ip_hdr.pair_ip.dst_addr.all);

    if (packet_info.ip_hdr.ip_protocol == IPPROTO_ICMPV6) {
        rule_key.local_port = ((u16)packet_info.ip_hdr.icmp_type << 8);
    }
    struct firewall_static_ct_action *static_ct_value = NULL;
    ret = lookup_static_rules(&rule_key, &static_ct_value);
    if (static_ct_value != NULL) {
        // bpf_log_info("has firewall rule");
        // bpf_log_info(
        //     "packet ip:%pI4:%d->%pI4:%d, ip_protocol: %d", &packet_info.ip_hdr.pair_ip.src_addr,
        //     bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port), &packet_info.ip_hdr.pair_ip.dst_addr,
        //     bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port), packet_info.ip_hdr.ip_protocol);
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

/// main function
SEC("tc")
int egress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< egress_firewall <<<"

    bool is_ipv4;
    int ret;
    if (current_pkg_type(skb, current_eth_net_offset, &is_ipv4) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        ret = bpf_tail_call(skb, &prog_array, IPV4_EGRESS_PROG_INDEX);
    } else {
        ret = bpf_tail_call(skb, &prog_array, IPV6_EGRESS_PROG_INDEX);
    }
    // if (ret) {
    //     bpf_log_info("bpf_tail_call error: %d", ret);
    // }
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int ingress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< ingress_firewall <<<"

    bool is_ipv4;
    int ret;
    if (current_pkg_type(skb, current_eth_net_offset, &is_ipv4) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        ret = bpf_tail_call(skb, &prog_array, IPV4_INGRESS_PROG_INDEX);
    } else {
        ret = bpf_tail_call(skb, &prog_array, IPV6_INGRESS_PROG_INDEX);
    }
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}