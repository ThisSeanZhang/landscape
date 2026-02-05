#ifndef LD_NAT_V6_H
#define LD_NAT_V6_H
#include <vmlinux.h>
#include "landscape_log.h"
#include "pkg_scanner.h"
#include "pkg_fragment.h"
#include "land_nat_common.h"
#include "nat/nat_maps.h"
#include "land_wan_ip.h"

#define LAND_IPV6_NET_PREFIX_TRANS_MASK (0x0FULL << 56)

// struct ipv6_prefix_mapping_key {
//     u8 client_suffix[8];
//     u16 client_port;
//     // client suffix is 8 byte + 4 bit
//     u8 id_byte;
//     // TCP / UDP / ICMP6
//     u8 l4_protocol;
// };

// struct ipv6_prefix_mapping_value {
//     // client prefix is 7 byte + 4 bit
//     u8 client_prefix[8];
//     union u_inet_addr trigger_addr;
//     u16 trigger_port;
//     u8 is_allow_reuse;
//     u8 _pad;
// };

// #define CLIENT_PREFIX_CACHE_SIZE 65536 * 3
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __type(key, struct ipv6_prefix_mapping_key);
//     __type(value, struct ipv6_prefix_mapping_value);
//     __uint(max_entries, CLIENT_PREFIX_CACHE_SIZE);
// } ip6_client_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_timer_key_v6);
    __type(value, struct nat_timer_value_v6);
    __uint(max_entries, NAT_MAPPING_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat6_conn_timer SEC(".maps");

static __always_inline int get_l4_checksum_offset(u32 l4_offset, u8 l4_protocol,
                                                  u32 *l4_checksum_offset) {
    if (l4_protocol == IPPROTO_TCP) {
        *l4_checksum_offset = l4_offset + offsetof(struct tcphdr, check);
    } else if (l4_protocol == IPPROTO_UDP) {
        *l4_checksum_offset = l4_offset + offsetof(struct udphdr, check);
    } else if (l4_protocol == IPPROTO_ICMPV6) {
        *l4_checksum_offset = l4_offset + offsetof(struct icmp6hdr, icmp6_cksum);
    } else {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

static __always_inline bool is_same_prefix(const u8 prefix[7], const union u_inet_addr *a) {
    const u8 *b = a->bits;
    return prefix[0] == b[0] && prefix[1] == b[1] && prefix[2] == b[2] && prefix[3] == b[3] &&
           prefix[4] == b[4] && prefix[5] == b[5] && ((prefix[6] & 0xF0) == (b[6] & 0xF0));
    ;
}

static __always_inline int update_ipv6_cache_value(struct __sk_buff *skb, struct inet_pair *ip_pair,
                                                   struct nat_timer_value_v6 *value) {
    COPY_ADDR_FROM(value->client_prefix, ip_pair->src_addr.bits);
    bool allow_reuse_port = get_flow_allow_reuse_port(skb->mark);
    value->is_allow_reuse = allow_reuse_port ? 1 : 0;
    COPY_ADDR_FROM(value->trigger_addr.all, ip_pair->dst_addr.all);
    value->trigger_port = ip_pair->dst_port;
    value->flow_id = get_flow_id(skb->mark);
}

static __always_inline void nat6_metric_accumulate(struct __sk_buff *skb, bool ingress,
                                                   struct nat_timer_value_v6 *value) {
    u64 bytes = skb->len;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline int nat_metric_try_report_v6(struct nat_timer_key_v6 *timer_key,
                                                    struct nat_timer_value_v6 *timer_value,
                                                    u8 status) {
#define BPF_LOG_TOPIC "nat_metric_try_report_v6"

    struct nat_conn_metric_event *event;
    event = bpf_ringbuf_reserve(&nat_conn_metric_events, sizeof(struct nat_conn_metric_event), 0);
    if (event == NULL) {
        return -1;
    }

    __builtin_memcpy(event->src_addr.bits, timer_value->client_prefix, 8);
    __builtin_memcpy(event->src_addr.bits + 8, timer_key->client_suffix, 8);
    COPY_ADDR_FROM(event->dst_addr.bits, timer_value->trigger_addr.bytes);

    event->src_port = timer_key->client_port;
    event->dst_port = timer_value->trigger_port;

    event->l4_proto = timer_key->l4_protocol;
    event->l3_proto = LANDSCAPE_IPV6_TYPE;
    event->flow_id = timer_value->flow_id;
    event->trace_id = 0;
    event->time = bpf_ktime_get_ns();
    event->create_time = timer_value->create_time;
    event->ingress_bytes = timer_value->ingress_bytes;
    event->ingress_packets = timer_value->ingress_packets;
    event->egress_bytes = timer_value->egress_bytes;
    event->egress_packets = timer_value->egress_packets;
    event->cpu_id = timer_value->cpu_id;
    event->status = status;
    bpf_ringbuf_submit(event, 0);

    return 0;
#undef BPF_LOG_TOPIC
}

static int v6_timer_clean_callback(void *map_mapping_timer_, struct nat_timer_key_v6 *key,
                                   struct nat_timer_value_v6 *value) {
#define BPF_LOG_TOPIC "v6_timer_clean_callback"

    // bpf_log_info("v6_timer_clean_callback: %d", bpf_ntohs(value->trigger_port));
    u64 client_status = value->client_status;
    u64 server_status = value->server_status;
    u64 current_status = value->status;
    u64 next_status = current_status;
    u64 next_timeout = REPORT_INTERVAL;
    int ret;

    if (value->trigger_port == TEST_PORT) {
        bpf_log_info("timer_clean_callback: %pI6, current_status: %llu", &value->trigger_addr.bytes,
                     current_status);
    }

    if (current_status == TIMER_RELEASE) {
        if (value->trigger_port == TEST_PORT) {
            bpf_log_info("release CONNECT");
        }

        // struct nat_conn_event *event;
        // event = bpf_ringbuf_reserve(&nat_conn_events, sizeof(struct nat_conn_event), 0);
        // if (event != NULL) {
        //     COPY_ADDR_FROM(event->dst_addr.all, value->trigger_addr.bytes);
        //     __builtin_memcpy(event->src_addr.bits, value->client_prefix, 8);
        //     __builtin_memcpy(event->src_addr.bits + 8, key->client_suffix, 8);
        //     event->src_port = key->client_port;
        //     event->dst_port = value->trigger_port;
        //     event->l4_proto = key->l4_protocol;
        //     event->l3_proto = LANDSCAPE_IPV6_TYPE;
        //     event->flow_id = value->flow_id;
        //     event->trace_id = 0;
        //     event->create_time = value->create_time;
        //     event->event_type = NAT_DELETE_CONN;
        //     bpf_ringbuf_submit(event, 0);
        // }

        ret = nat_metric_try_report_v6(key, value, NAT_CONN_DELETE);
        if (ret) {
            bpf_log_info("call back report fail");
            bpf_timer_start(&value->timer, next_timeout, 0);
            return 0;
        }
        goto release;
    }

    ret = nat_metric_try_report_v6(key, value, NAT_CONN_ACTIVE);
    if (ret) {
        bpf_log_info("call back report fail");
        bpf_timer_start(&value->timer, next_timeout, 0);
        return 0;
    }

    if (current_status == TIMER_ACTIVE) {
        next_status = TIMER_TIMEOUT_1;
        next_timeout = REPORT_INTERVAL;

        if (value->trigger_port == TEST_PORT) {
            bpf_log_info("change next status TIMER_TIMEOUT_1");
        }
    } else if (current_status == TIMER_TIMEOUT_1) {
        next_status = TIMER_TIMEOUT_2;
        next_timeout = REPORT_INTERVAL;

        if (value->trigger_port == TEST_PORT) {
            bpf_log_info("change next status TIMER_TIMEOUT_2");
        }
    } else if (current_status == TIMER_TIMEOUT_2) {
        next_status = TIMER_RELEASE;
        if (key->l4_protocol == IPPROTO_TCP) {
            if (client_status == CT_SYN && server_status == CT_SYN) {
                next_timeout = TCP_TIMEOUT;
            } else {
                next_timeout = TCP_SYN_TIMEOUT;
            }
        } else {
            next_timeout = UDP_TIMEOUT;
        }

        if (value->trigger_port == TEST_PORT) {
            u64 show = (next_timeout / 1000000000ULL);
            bpf_log_info("change next status TIMER_RELEASE, next_timeout: %d", show);
        }
    } else {
        next_status = TIMER_TIMEOUT_2;
        next_timeout = REPORT_INTERVAL;
    }

    if (__sync_val_compare_and_swap(&value->status, current_status, next_status) !=
        current_status) {
        bpf_log_info("call back modify status fail, current status: %d new status: %d",
                     current_status, next_status);
        bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
        return 0;
    }

    bpf_timer_start(&value->timer, next_timeout, 0);

    return 0;
release:;
    bpf_map_delete_elem(&nat6_conn_timer, key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat_timer_value_v6 *
insert_ct6_timer(const struct nat_timer_key_v6 *key, struct nat_timer_value_v6 *val) {
#define BPF_LOG_TOPIC "insert_ct6_timer"

    int ret = bpf_map_update_elem(&nat6_conn_timer, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct nat_timer_value_v6 *value = bpf_map_lookup_elem(&nat6_conn_timer, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &nat6_conn_timer, CLOCK_MONOTONIC);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_set_callback(&value->timer, v6_timer_clean_callback);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
    if (ret) {
        goto delete_timer;
    }

    return value;
delete_timer:
    bpf_log_error("setup timer err:%d", ret);
    bpf_map_delete_elem(&nat6_conn_timer, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

// static __always_inline int update_ipv6_hash_cache_value(struct __sk_buff *skb,
//                                                         struct inet_pair *ip_pair,
//                                                         struct nat_timer_value_v6 *value) {
//     COPY_ADDR_FROM(value->client_prefix, ip_pair->src_addr.bits);
//     bool allow_reuse_port = get_flow_allow_reuse_port(skb->mark);
//     value->is_allow_reuse = allow_reuse_port ? 1 : 0;
//     COPY_ADDR_FROM(value->trigger_addr.bytes, ip_pair->dst_addr.all);
//     value->trigger_port = ip_pair->dst_port;
// }

static __always_inline int ct6_state_transition(u8 pkt_type, u8 gress,
                                                struct nat_timer_value_v6 *ct_timer_value) {
#define BPF_LOG_TOPIC "ct6_state_transition"
    u64 curr_state, *modify_status = NULL;
    if (gress == NAT_MAPPING_INGRESS) {
        curr_state = ct_timer_value->server_status;
        modify_status = &ct_timer_value->server_status;
    } else {
        curr_state = ct_timer_value->client_status;
        modify_status = &ct_timer_value->client_status;
    }

#define NEW_STATE(__state)                                                                         \
    if (!__sync_bool_compare_and_swap(modify_status, curr_state, (__state))) {                     \
        return TC_ACT_SHOT;                                                                        \
    }

    if (pkt_type == PKT_CONNLESS_V2) {
        NEW_STATE(CT_LESS_EST);
    }

    if (pkt_type == PKT_TCP_RST_V2) {
        NEW_STATE(CT_INIT);
    }

    if (pkt_type == PKT_TCP_SYN_V2) {
        NEW_STATE(CT_SYN);
    }

    if (pkt_type == PKT_TCP_FIN_V2) {
        NEW_STATE(CT_FIN);
    }

    u64 prev_state = __sync_lock_test_and_set(&ct_timer_value->status, TIMER_ACTIVE);
    if (prev_state != TIMER_ACTIVE) {
        if (ct_timer_value->trigger_port == TEST_PORT) {
            bpf_log_info("flush status to TIMER_ACTIVE: 20");
        }
        bpf_timer_start(&ct_timer_value->timer, REPORT_INTERVAL, 0);
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int search_ipv6_hash_mapping_egress(struct __sk_buff *skb,
                                                           struct packet_offset_info *offset_info,
                                                           struct inet_pair *ip_pair) {
    bool is_icmpx_error = is_icmp_error_pkt(offset_info);
    bool allow_create_mapping = pkt_allow_initiating_ct(offset_info->pkt_type);

    struct nat_timer_key_v6 key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
    key.id_byte = ip_pair->src_addr.bits[7] & 0x0F;
    // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
    key.l4_protocol = offset_info->l4_protocol;

    struct nat_timer_value_v6 *value;
    value = bpf_map_lookup_elem(&nat6_conn_timer, &key);
    if (value) {
        if (!is_same_prefix(value->client_prefix, ip_pair->src_addr.bits)) {
            update_ipv6_cache_value(skb, ip_pair, value);
        }
    } else {
        if (!allow_create_mapping) {
            return TC_ACT_SHOT;
        }

        struct nat_timer_value_v6 new_value = {};
        __builtin_memset(&new_value, 0, sizeof(new_value));
        new_value.create_time = bpf_ktime_get_ns();
        new_value.flow_id = get_flow_id(skb->mark);
        new_value.cpu_id = bpf_get_smp_processor_id();
        update_ipv6_cache_value(skb, ip_pair, &new_value);
        value = insert_ct6_timer(&key, &new_value);

        // if (value) {
        //     struct nat_conn_event *event;
        //     event = bpf_ringbuf_reserve(&nat_conn_events, sizeof(struct nat_conn_event), 0);
        //     if (event != NULL) {
        //         COPY_ADDR_FROM(event->dst_addr.bits, value->trigger_addr.bytes);
        //         __builtin_memcpy(event->src_addr.bits, value->client_prefix, 8);
        //         __builtin_memcpy(event->src_addr.bits + 8, key.client_suffix, 8);
        //         event->src_port = key.client_port;
        //         event->dst_port = value->trigger_port;
        //         event->l4_proto = key.l4_protocol;
        //         event->l3_proto = LANDSCAPE_IPV6_TYPE;
        //         event->flow_id = value->flow_id;
        //         event->trace_id = 0;
        //         event->create_time = value->create_time;
        //         event->event_type = NAT_CREATE_CONN;
        //         bpf_ringbuf_submit(event, 0);
        //     }
        // }
    }

    if (value) {
        ct6_state_transition(offset_info->pkt_type, NAT_MAPPING_EGRESS, value);
        nat6_metric_accumulate(skb, false, value);
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

// static __always_inline int search_ipv6_mapping_egress(struct __sk_buff *skb,
//                                                       struct packet_offset_info *offset_info,
//                                                       struct inet_pair *ip_pair) {
//     struct ipv6_prefix_mapping_key key = {0};
//     key.client_port = ip_pair->src_port;
//     COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
//     // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
//     key.id_byte = ip_pair->src_addr.bits[7] & 0x0F;
//     // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
//     key.l4_protocol = offset_info->l4_protocol;

//     struct ipv6_prefix_mapping_value *value;
//     value = bpf_map_lookup_elem(&ip6_client_map, &key);
//     if (value) {
//         if (!is_same_prefix(value->client_prefix, ip_pair->src_addr.bits)) {
//             update_ipv6_cache_value(skb, ip_pair, value);
//         }
//     } else {
//         struct ipv6_prefix_mapping_value new_value = {0};
//         update_ipv6_cache_value(skb, ip_pair, &new_value);
//         bpf_map_update_elem(&ip6_client_map, &key, &new_value, BPF_ANY);
//     }

//     return TC_ACT_OK;
// }

#define L4_CSUM_REPLACE_U64_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, flags)                 \
    do {                                                                                           \
        int _ret;                                                                                  \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) >> 32, (new_val) >> 32,         \
                                   flags | 4);                                                     \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace high 32bit err: %d", _ret);                                \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) & 0xFFFFFFFF,                   \
                                   (new_val) & 0xFFFFFFFF, flags | 4);                             \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace low 32bit err: %d", _ret);                                 \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

static __always_inline int check_egress_static_mapping_exist(struct __sk_buff *skb, u8 ip_protocol,
                                                             const struct inet_pair *pkt_ip_pair) {
#define BPF_LOG_TOPIC "check_egress_static_mapping_exist"
    struct static_nat_mapping_key egress_key = {0};
    struct nat_mapping_value *nat_gress_value = NULL;

    egress_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    egress_key.l4_protocol = ip_protocol;
    egress_key.gress = NAT_MAPPING_EGRESS;
    egress_key.prefixlen = 192;
    egress_key.port = pkt_ip_pair->src_port;
    COPY_ADDR_FROM(egress_key.addr.all, pkt_ip_pair->src_addr.all);

    nat_gress_value = bpf_map_lookup_elem(&static_nat_mappings, &egress_key);
    if (nat_gress_value) {
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline int
ipv6_egress_prefix_check_and_replace(struct __sk_buff *skb, struct packet_offset_info *offset_info,
                                     struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "ipv6_egress_prefix_check_and_replace"
    int ret;
    ret = check_egress_static_mapping_exist(skb, offset_info->l4_protocol, ip_pair);
    if (ret != TC_ACT_OK) {
        // Static mapping does not exist
        ret = search_ipv6_hash_mapping_egress(skb, offset_info, ip_pair);
        if (ret != TC_ACT_OK) {
            return TC_ACT_SHOT;
        }
    }

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = skb->ifindex;
    wan_search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (wan_ip_info == NULL) {
        return TC_ACT_SHOT;
    }

    if (is_icmp_error_pkt(offset_info)) {
        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->src_addr.all);
        COPY_ADDR_FROM(&new_ip_prefix, wan_ip_info->addr.all);
        new_ip_prefix = (old_ip_prefix & LAND_IPV6_NET_PREFIX_TRANS_MASK) |
                        (new_ip_prefix & ~LAND_IPV6_NET_PREFIX_TRANS_MASK);

        u32 error_sender_offset =
            offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, saddr);
        u32 inner_l3_ip_dst_offset =
            offset_info->icmp_error_l3_offset + offsetof(struct ipv6hdr, daddr);

        __be64 old_sender_ip_prefix, new_sender_ip_prefix;
#if defined(__riscv) || defined(__riscv__)
        if (bpf_skb_load_bytes(skb, error_sender_offset, &old_sender_ip_prefix, 8)) {
            return TC_ACT_SHOT;
        }
#else
        __be64 *error_sender_point;
        if (VALIDATE_READ_DATA(skb, &error_sender_point, error_sender_offset,
                               sizeof(*error_sender_point))) {
            return TC_ACT_SHOT;
        }
        old_sender_ip_prefix = *error_sender_point;
#endif
        COPY_ADDR_FROM(&new_sender_ip_prefix, wan_ip_info->addr.all);

        new_sender_ip_prefix = (old_sender_ip_prefix & LAND_IPV6_NET_PREFIX_TRANS_MASK) |
                               (new_sender_ip_prefix & ~LAND_IPV6_NET_PREFIX_TRANS_MASK);

        u32 inner_l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->icmp_error_inner_l4_offset,
                                   offset_info->icmp_error_l4_protocol,
                                   &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_dst_offset, &new_ip_prefix, 8, 0);
        if (ret) {
            bpf_printk("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        // ret = bpf_l4_csum_replace(skb, inner_l4_checksum_offset, old_inner_ip_prefix >> 32,
        //                           new_inner_ip_prefix >> 32, 4);

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, inner_l4_checksum_offset, old_ip_prefix, new_ip_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, new_ip_prefix, 0);

        // 因为更新了内层 checksum  所以要先更新内部checksum 改变导致外部 icmp checksum 改变的代码
        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);

        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            bpf_printk("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        bpf_skb_store_bytes(skb, error_sender_offset, &new_sender_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_sender_ip_prefix,
                                    new_sender_ip_prefix, BPF_F_PSEUDO_HDR);

    } else {
        // ipv6 sceck sum
        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 ip_src_offset = offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, saddr);

        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->src_addr.all);
        COPY_ADDR_FROM(&new_ip_prefix, wan_ip_info->addr.all);
        new_ip_prefix = (old_ip_prefix & LAND_IPV6_NET_PREFIX_TRANS_MASK) |
                        (new_ip_prefix & ~LAND_IPV6_NET_PREFIX_TRANS_MASK);
        bpf_skb_store_bytes(skb, ip_src_offset, &new_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, new_ip_prefix,
                                    BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

static __always_inline int check_ingress_mapping_exist(struct __sk_buff *skb, u8 ip_protocol,
                                                       const struct inet_pair *pkt_ip_pair,
                                                       __be64 *local_client_prefix) {
#define BPF_LOG_TOPIC "check_ingress_mapping_exist"
    struct static_nat_mapping_key ingress_key = {0};
    struct nat_mapping_value *value = NULL;

    __be64 dst_suffix, mapping_suffix;

    ingress_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    ingress_key.l4_protocol = ip_protocol;
    ingress_key.gress = NAT_MAPPING_INGRESS;
    ingress_key.prefixlen = 96;
    ingress_key.port = pkt_ip_pair->dst_port;

    value = bpf_map_lookup_elem(&static_nat_mappings, &ingress_key);
    if (value) {
        // 映射到当前的主机, 相对于 suffix 是空的
        if (value->addr.all[3] == 0 && value->addr.all[2] == 0) {
            return TC_ACT_UNSPEC;
        }

        // 映射中设置了前缀, 那么要进行修改
        if (value->addr.ip != 0) {
            COPY_ADDR_FROM(local_client_prefix, value->addr.bits);
            return TC_ACT_OK;
        }

        // 映射中只设置了后缀, 所以就只校验, 不修改
        COPY_ADDR_FROM(&mapping_suffix, value->addr.bits + 8);
        COPY_ADDR_FROM(&dst_suffix, pkt_ip_pair->dst_addr.bits + 8);

        if (mapping_suffix == dst_suffix) {
            return TC_ACT_UNSPEC;
        }
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

static __always_inline int
ipv6_ingress_prefix_check_and_replace(struct __sk_buff *skb, struct packet_offset_info *offset_info,
                                      struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "ipv6_ingress_prefix_check_and_replace"
    int ret;
    __be64 local_client_prefix = {0};

    ret = check_ingress_mapping_exist(skb, offset_info->l4_protocol, ip_pair, &local_client_prefix);
    if (ret == TC_ACT_UNSPEC) {
        u32 mark = skb->mark;
        barrier_var(mark);
        skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
        return TC_ACT_UNSPEC;
    }

    if (ret == TC_ACT_SHOT) {
        struct nat_timer_key_v6 key = {0};
        key.client_port = ip_pair->dst_port;
        COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
        // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
        key.id_byte = ip_pair->dst_addr.bits[7] & 0x0F;
        // bpf_printk("client_suffix: %02x %02x", key.client_suffix[0], key.client_suffix[1]);
        key.l4_protocol = offset_info->l4_protocol;

        struct nat_timer_value_v6 *value = bpf_map_lookup_elem(&nat6_conn_timer, &key);
        if (value == NULL) {
            bpf_printk("lookup client prefix error, key.id_byte: %x", key.id_byte);
            // bpf_printk("lookup client prefix error, key.client_suffix: %02x %02x %02x %02x %02x
            // %02x %02x %02x %02x", key.client_suffix[0], key.client_suffix[1],
            // key.client_suffix[2], key.client_suffix[3], key.client_suffix[4],
            // key.client_suffix[5], key.client_suffix[6], key.client_suffix[7],
            // key.client_suffix[8]);
            bpf_printk("lookup client prefix error, key.l4_protocol: %u", key.l4_protocol);
            bpf_printk("lookup client prefix error, key.client_port: %04x", key.client_port);
            return TC_ACT_SHOT;
        }

        COPY_ADDR_FROM(&local_client_prefix, value->client_prefix);

        // bpf_printk("is_allow_reuse: %u", value->is_allow_reuse);

        if (value->is_allow_reuse == 0 && offset_info->l4_protocol != IPPROTO_ICMPV6) {
            if (!ip_addr_equal(&ip_pair->src_addr, &value->trigger_addr) ||
                ip_pair->src_port != value->trigger_port) {
                bpf_printk("FLOW_ALLOW_REUSE MARK not set, DROP PACKET");
                bpf_printk("src info: [%pI6]:%u", &ip_pair->src_addr, bpf_ntohs(ip_pair->src_port));
                bpf_printk("trigger ip: [%pI6]:%u,", &value->trigger_addr,
                           bpf_ntohs(value->trigger_port));
                return TC_ACT_SHOT;
            }
        }

        ct6_state_transition(offset_info->pkt_type, NAT_MAPPING_INGRESS, value);
        nat6_metric_accumulate(skb, true, value);
    }

    if (is_icmp_error_pkt(offset_info)) {
        // 修改原数据包的 dst ip， 内部数据包的 src ip
        u32 inner_l3_ip_src_offset =
            offset_info->icmp_error_l3_offset + offsetof(struct ipv6hdr, saddr);

        __be64 old_inner_ip_prefix;
#if defined(__riscv) || defined(__riscv__)
        if (bpf_skb_load_bytes(skb, inner_l3_ip_src_offset, &old_inner_ip_prefix, 8)) {
            return TC_ACT_SHOT;
        }
#else
        __be64 *old_inner_ip_point;
        if (VALIDATE_READ_DATA(skb, &old_inner_ip_point, inner_l3_ip_src_offset,
                               sizeof(*old_inner_ip_point))) {
            return TC_ACT_SHOT;
        }
        old_inner_ip_prefix = *old_inner_ip_point;
#endif

        u32 inner_l4_checksum_offset = 0;
        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->icmp_error_inner_l4_offset,
                                   offset_info->icmp_error_l4_protocol,
                                   &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_src_offset, &local_client_prefix, 8, 0);
        if (ret) {
            bpf_printk("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, inner_l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        // 因为更新了内层 checksum  所以要先更新内部checksum 改变导致外部 icmp checksum 改变的代码
        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);
        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            bpf_printk("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        u32 ipv6_dst_offset = offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, daddr);
        bpf_skb_store_bytes(skb, ipv6_dst_offset, &local_client_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, BPF_F_PSEUDO_HDR);
    } else {
        u32 l4_checksum_offset = 0;
        if (get_l4_checksum_offset(offset_info->l4_offset, offset_info->l4_protocol,
                                   &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 dst_ip_offset = offset_info->l3_offset_when_scan + offsetof(struct ipv6hdr, daddr);

        __be64 old_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->dst_addr.all);
        bpf_skb_store_bytes(skb, dst_ip_offset, &local_client_prefix, 8, 0);

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, local_client_prefix,
                                    BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

#endif /* LD_NAT_V6_H */
