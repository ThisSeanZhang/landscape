#ifndef LD_NAT_V4_H
#define LD_NAT_V4_H
#include "landscape_log.h"
#include "pkg_scanner.h"
#include "pkg_fragment.h"
#include "land_nat_common.h"
#include "nat/nat_maps.h"
#include "land_wan_ip.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_mapping_key_v4);
    __type(value, struct nat_mapping_value_v4);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
} nat4_mappings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_timer_key);
    __type(value, struct nat_timer_value);
    __uint(max_entries, NAT_MAPPING_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat_mapping_timer SEC(".maps");

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

#define L3_CSUM_REPLACE_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, size)                      \
    do {                                                                                           \
        int _ret = bpf_l3_csum_replace(skb_ptr, csum_offset, old_val, new_val, size);              \
        if (_ret) {                                                                                \
            bpf_printk("l3_csum_replace err: %d", _ret);                                           \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

#define L4_CSUM_REPLACE_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, len_plus_flags)            \
    do {                                                                                           \
        int _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, old_val, new_val, len_plus_flags);    \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace err: %d", _ret);                                           \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

static __always_inline int ipv4_update_csum_inner_macro(struct __sk_buff *skb, u32 l4_csum_off,
                                                        __be32 from_addr, __be16 from_port,
                                                        __be32 to_addr, __be16 to_port,
                                                        bool l4_pseudo, bool l4_mangled_0) {
    u16 csum;
    if (l4_mangled_0) {
        READ_SKB_U16(skb, l4_csum_off, csum);
    }

    if (!l4_mangled_0 || csum != 0) {
        L3_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, from_port, to_port, 2);

        if (l4_pseudo) {
            L3_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, from_addr, to_addr, 4);
        }
    }
}

static __always_inline int ipv4_update_csum_icmp_err_macro(struct __sk_buff *skb, u32 icmp_csum_off,
                                                           u32 err_ip_check_off,
                                                           u32 err_l4_csum_off, __be32 from_addr,
                                                           __be16 from_port, __be32 to_addr,
                                                           __be16 to_port, bool err_l4_pseudo,
                                                           bool l4_mangled_0) {
    u16 prev_csum;
    u16 curr_csum;
    u16 *tmp_ptr;

    // bpf_skb_load_bytes(skb, err_ip_check_off, &prev_csum, sizeof(prev_csum));
    if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_ip_check_off, sizeof(*tmp_ptr))) {
        return 1;
    }
    prev_csum = *tmp_ptr;

    // 替换原始 L3 校验和 (4 bytes)
    L3_CSUM_REPLACE_OR_SHOT(skb, err_ip_check_off, from_addr, to_addr, 4);

    // bpf_skb_load_bytes(skb, err_ip_check_off, &curr_csum, sizeof(curr_csum));
    if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_ip_check_off, sizeof(*tmp_ptr))) {
        return 1;
    }
    curr_csum = *tmp_ptr;
    L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, prev_csum, curr_csum, 2);

    // if (bpf_skb_load_bytes(skb, err_l4_csum_off, &prev_csum, sizeof(prev_csum)) == 0) {
    if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_l4_csum_off, sizeof(*tmp_ptr)) == 0) {
        prev_csum = *tmp_ptr;
        ipv4_update_csum_inner_macro(skb, err_l4_csum_off, from_addr, from_port, to_addr, to_port,
                                     err_l4_pseudo, l4_mangled_0);

        // bpf_skb_load_bytes(skb, err_l4_csum_off, &curr_csum, sizeof(curr_csum));
        if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_l4_csum_off, sizeof(*tmp_ptr))) {
            return 1;
        }
        curr_csum = *tmp_ptr;
        L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, prev_csum, curr_csum, 2);
    }

    L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, from_addr, to_addr, 4);

    L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, from_port, to_port, 2);

    return 0;
}

static __always_inline int modify_headers_v4(struct __sk_buff *skb, bool is_icmpx_error, u8 nexthdr,
                                             u32 current_l3_offset, int l4_off, int err_l4_off,
                                             bool is_modify_source, struct inet4_addr *from_addr,
                                             __be16 from_port, struct inet4_addr *to_addr,
                                             __be16 to_port) {
#define BPF_LOG_TOPIC "modify_headers_v4"
    int ret;
    int l4_to_port_off;
    int l4_to_check_off;
    bool l4_check_pseudo;
    bool l4_check_mangle_0;

    int ip_offset =
        is_modify_source ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr);

    ret = bpf_skb_store_bytes(skb, current_l3_offset + ip_offset, &to_addr->addr,
                              sizeof(to_addr->addr), 0);
    if (ret) return ret;

    L3_CSUM_REPLACE_OR_SHOT(skb, current_l3_offset + offsetof(struct iphdr, check), from_addr->addr,
                            to_addr->addr, 4);

    if (l4_off == 0) return 0;

    switch (nexthdr) {
    case IPPROTO_TCP:
        l4_to_port_off =
            is_modify_source ? offsetof(struct tcphdr, source) : offsetof(struct tcphdr, dest);
        l4_to_check_off = offsetof(struct tcphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = false;
        break;
    case IPPROTO_UDP:
        l4_to_port_off =
            is_modify_source ? offsetof(struct udphdr, source) : offsetof(struct udphdr, dest);
        l4_to_check_off = offsetof(struct udphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = true;
        break;
    case IPPROTO_ICMP:
        l4_to_port_off = offsetof(struct icmphdr, un.echo.id);
        l4_to_check_off = offsetof(struct icmphdr, checksum);
        l4_check_pseudo = false;
        l4_check_mangle_0 = false;
        break;
    default:
        return 1;
    }

    if (is_icmpx_error) {
        if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) {
            l4_to_port_off =
                is_modify_source ? offsetof(struct tcphdr, dest) : offsetof(struct tcphdr, source);
        }

        int icmpx_error_offset =
            is_modify_source ? offsetof(struct iphdr, daddr) : offsetof(struct iphdr, saddr);

        ret = bpf_skb_store_bytes(skb, icmpx_err_l3_offset(l4_off) + icmpx_error_offset,
                                  &to_addr->addr, sizeof(to_addr->addr), 0);
        if (ret) return ret;

        ret = bpf_write_port(skb, err_l4_off + l4_to_port_off, to_port);
        if (ret) return ret;

        if (ipv4_update_csum_icmp_err_macro(
                skb, l4_off + offsetof(struct icmphdr, checksum),
                icmpx_err_l3_offset(l4_off) + offsetof(struct iphdr, check),
                err_l4_off + l4_to_check_off, from_addr->addr, from_port, to_addr->addr, to_port,
                l4_check_pseudo, l4_check_mangle_0))
            return TC_ACT_SHOT;

    } else {
        ret = bpf_write_port(skb, l4_off + l4_to_port_off, to_port);
        if (ret) return ret;

        u32 l4_csum_off = l4_off + l4_to_check_off;
        u32 flags_mangled = l4_check_mangle_0 ? BPF_F_MARK_MANGLED_0 : 0;

        L4_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, from_port, to_port, 2 | flags_mangled);

        if (l4_check_pseudo) {
            L4_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, from_addr->addr, to_addr->addr,
                                    4 | BPF_F_PSEUDO_HDR | flags_mangled);
        }
    }

    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline bool try_report() {}

static __always_inline void nat_metric_accumulate(struct __sk_buff *skb, bool ingress,
                                                  struct nat_timer_value *value) {
    u64 bytes = skb->len;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline int nat_metric_try_report_v4(struct nat_timer_key *timer_key,
                                                    struct nat_timer_value *timer_value) {
#define BPF_LOG_TOPIC "nat_metric_try_report_v4"

    struct nat_conn_metric_event *event;
    event = bpf_ringbuf_reserve(&nat_conn_metric_events, sizeof(struct nat_conn_metric_event), 0);
    if (event == NULL) {
        return -1;
    }

    event->src_addr.ip = timer_key->pair_ip.src_addr.addr;
    event->dst_addr.ip = timer_value->trigger_saddr.addr;

    event->src_port = timer_key->pair_ip.src_port;
    event->dst_port = timer_value->trigger_port;

    event->l4_proto = timer_key->l4proto;
    event->l3_proto = LANDSCAPE_IPV4_TYPE;
    event->flow_id = timer_value->flow_id;
    event->trace_id = 0;
    event->time = bpf_ktime_get_ns();
    event->create_time = timer_value->create_time;
    event->ingress_bytes = timer_value->ingress_bytes;
    event->ingress_packets = timer_value->ingress_packets;
    event->egress_bytes = timer_value->egress_bytes;
    event->egress_packets = timer_value->egress_packets;
    bpf_ringbuf_submit(event, 0);

    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline int ct_state_transition_v4(u8 l4proto, u8 pkt_type, u8 gress,
                                                  struct nat4_ct_value *ct_timer_value) {
#define BPF_LOG_TOPIC "ct_state_transition_v4"
    if (gress == NAT_MAPPING_INGRESS) {
        u64 curr_state = ct_timer_value->server_status;
        if (pkt_type == PKT_CONNLESS_V2) {
            return TC_ACT_OK;
        } else if (pkt_type == PKT_TCP_RST_V2) {
            if (!__sync_bool_compare_and_swap(&ct_timer_value->server_status, curr_state, CT_FIN)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        } else if (pkt_type == PKT_TCP_SYN_V2) {
            if (!__sync_bool_compare_and_swap(&ct_timer_value->server_status, curr_state, CT_SYN)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        } else if (pkt_type == PKT_TCP_FIN_V2) {
            if (!__sync_bool_compare_and_swap(&ct_timer_value->server_status, curr_state, CT_FIN)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }

    } else {
        u64 curr_state = ct_timer_value->client_status;
        if (pkt_type == PKT_CONNLESS_V2) {
            return TC_ACT_OK;
        } else if (pkt_type == PKT_TCP_RST_V2) {
            if (!__sync_bool_compare_and_swap(&ct_timer_value->client_status, curr_state, CT_FIN)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        } else if (pkt_type == PKT_TCP_SYN_V2) {
            if (!__sync_bool_compare_and_swap(&ct_timer_value->client_status, curr_state, CT_SYN)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        } else if (pkt_type == PKT_TCP_FIN_V2) {
            if (!__sync_bool_compare_and_swap(&ct_timer_value->client_status, curr_state, CT_FIN)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat4_ct_value *
insert_new_nat4_conn(u8 l4proto, const struct nat4_ct_key *key, const struct nat4_ct_value *val) {
#define BPF_LOG_TOPIC "insert_new_nat4_conn"
    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    // bpf_ntohs(key->pair_ip.src_port), bpf_ntohs(key->pair_ip.dst_port)); bpf_log_info("src_ip:
    // %lu -> dst_ip: %lu", bpf_ntohl(key->pair_ip.src_addr.ip),
    // bpf_ntohl(key->pair_ip.dst_addr.ip));

    int ret = bpf_map_update_elem(&nat4_conn_map, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct nat4_ct_value *value = bpf_map_lookup_elem(&nat4_conn_map, key);
    if (!value) return NULL;
    return value;
#undef BPF_LOG_TOPIC
}

static __always_inline int lookup_or_new_ct4(u8 l4proto, bool do_new,
                                             const struct inet4_pair *ip_pair,
                                             struct nat_mapping_value_v4 *nat_egress_value,
                                             struct nat_mapping_value_v4 *nat_ingress_value,
                                             struct nat4_ct_value **timer_value_) {
#define BPF_LOG_TOPIC "lookup_or_new_ct4"

    struct nat4_ct_key ct4_key = {
        .l4proto = l4proto,
        ._pad = {0, 0, 0},
        .pair_ip =
            {
                .src_addr = nat_ingress_value->addr,
                .dst_addr = nat_egress_value->addr,
                .src_port = nat_ingress_value->port,
                .dst_port = nat_egress_value->port,
            },
    };

    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    //              bpf_ntohs(ct4_key.pair_ip.src_port), bpf_ntohs(ct4_key.pair_ip.dst_port));
    // bpf_log_info("src_ip: %lu -> dst_ip: %lu", bpf_ntohl(ct4_key.pair_ip.src_addr.ip),
    //              bpf_ntohl(ct4_key.pair_ip.dst_addr.ip));

    struct nat4_ct_value *ct4_value = bpf_map_lookup_elem(&nat4_conn_map, &ct4_key);
    // bpf_log_info("ct4_value: %u", ct4_value);
    if (ct4_value) {
        *timer_value_ = ct4_value;
        return TIMER_EXIST;
    }

    if (!ct4_value && !do_new) {
        return TIMER_NOT_FOUND;
    }

    struct nat4_ct_value ct4_value_new = {0};
    ct4_value_new.trigger_port = nat_ingress_value->trigger_port;
    ct4_value_new.client_status = TIMER_INIT;
    ct4_value_new.server_status = TIMER_INIT;
    ct4_value_new.gress = NAT_MAPPING_EGRESS;
    ct4_value_new.trigger_saddr = nat_egress_value->trigger_addr;
    ct4_value_new.create_time = bpf_ktime_get_ns();

    ct4_value = insert_new_nat4_conn(l4proto, &ct4_key, &ct4_value_new);
    if (ct4_value == NULL) {
        return TIMER_ERROR;
    }
    // bpf_log_debug("insert new CT");

    // 发送 event
    struct nat_conn_event *event;
    event = bpf_ringbuf_reserve(&nat_conn_events, sizeof(struct nat_conn_event), 0);
    if (event != NULL) {
        event->dst_addr.ip = nat_egress_value->trigger_addr;
        event->src_addr.ip = nat_ingress_value->addr;
        event->src_port = nat_ingress_value->port;
        event->dst_port = nat_egress_value->trigger_port;
        event->l4_proto = l4proto;
        event->l3_proto = LANDSCAPE_IPV4_TYPE;
        event->flow_id = 0;
        event->trace_id = 0;
        event->create_time = ct4_value_new.create_time;
        event->event_type = NAT_CREATE_CONN;
        bpf_ringbuf_submit(event, 0);
    }

    *timer_value_ = ct4_value;
    return TIMER_CREATED;
#undef BPF_LOG_TOPIC
}

static __always_inline bool ct_change_state(u64 *status_in_value, u64 curr_state, u64 next_state) {
    return __sync_bool_compare_and_swap(status_in_value, curr_state, next_state);
}

static __always_inline int ct_state_transition(u8 l4proto, u8 pkt_type, u8 gress,
                                               struct nat_timer_value *ct_timer_value) {
#define BPF_LOG_TOPIC "ct_state_transition"
    u64 curr_state, *modify_status = NULL;
    if (gress == NAT_MAPPING_INGRESS) {
        curr_state = ct_timer_value->server_status;
        modify_status = &ct_timer_value->server_status;
    } else {
        curr_state = ct_timer_value->client_status;
        modify_status = &ct_timer_value->client_status;
    }

#define NEW_STATE(__state)                                                                         \
    if (!ct_change_state(modify_status, curr_state, (__state))) {                                  \
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

static int timer_clean_callback(void *map_mapping_timer_, struct nat_timer_key *key,
                                struct nat_timer_value *value) {
#define BPF_LOG_TOPIC "timer_clean_callback"

    // bpf_log_info("timer_clean_callback: %d", bpf_ntohs(value->trigger_port));
    u64 client_status = value->client_status;
    u64 server_status = value->server_status;
    u64 current_status = value->status;
    u64 next_status = current_status;
    u64 next_timeout = REPORT_INTERVAL;
    int ret;

    if (value->trigger_port == TEST_PORT) {
        bpf_log_info("timer_clean_callback: %pI4, current_status: %llu", &value->trigger_saddr.addr,
                     current_status);
    }

    if (current_status == TIMER_RELEASE) {
        if (value->trigger_port == TEST_PORT) {
            bpf_log_info("release CONNECT");
        }

        struct nat_conn_event *event;
        event = bpf_ringbuf_reserve(&nat_conn_events, sizeof(struct nat_conn_event), 0);
        if (event != NULL) {
            event->dst_addr.ip = value->trigger_saddr.addr;
            event->src_addr.ip = key->pair_ip.src_addr.addr;
            event->src_port = key->pair_ip.src_port;
            event->dst_port = value->trigger_port;
            event->l4_proto = key->l4proto;
            event->l3_proto = LANDSCAPE_IPV4_TYPE;
            event->flow_id = value->flow_id;
            event->trace_id = 0;
            event->create_time = value->create_time;
            event->event_type = NAT_DELETE_CONN;
            bpf_ringbuf_submit(event, 0);
        }
        goto release;
    }

    ret = nat_metric_try_report_v4(key, value);
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
        if (key->l4proto == IPPROTO_TCP) {
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
        // 更新状态失败, 说明有新的数据包到达
        bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
        return 0;
    }

    bpf_timer_start(&value->timer, next_timeout, 0);

    return 0;
release:;
    struct nat_mapping_key_v4 egress_mapping_key = {0};
    egress_mapping_key.l4proto = key->l4proto;
    egress_mapping_key.gress = NAT_MAPPING_EGRESS;
    egress_mapping_key.from_addr = key->pair_ip.src_addr.addr;
    egress_mapping_key.from_port = key->pair_ip.src_port;

    struct nat_mapping_key_v4 ingress_mapping_key = {0};
    ingress_mapping_key.l4proto = key->l4proto;
    ingress_mapping_key.gress = NAT_MAPPING_INGRESS;
    ingress_mapping_key.from_addr = key->pair_ip.dst_addr.addr;
    ingress_mapping_key.from_port = key->pair_ip.dst_port;

    bpf_map_delete_elem(&nat4_mappings, &egress_mapping_key);
    bpf_map_delete_elem(&nat4_mappings, &ingress_mapping_key);

    bpf_map_delete_elem(&nat_mapping_timer, key);
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

    int ret = bpf_map_update_elem(&nat_mapping_timer, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct nat_timer_value *value = bpf_map_lookup_elem(&nat_mapping_timer, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &nat_mapping_timer, CLOCK_MONOTONIC);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_set_callback(&value->timer, timer_clean_callback);
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
    bpf_map_delete_elem(&nat_mapping_timer, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline int lookup_or_new_ct(struct __sk_buff *skb, u8 l4proto, bool do_new,
                                            const struct inet4_pair *pkt_ip_pair,
                                            struct nat_mapping_value_v4 *nat_egress_value,
                                            struct nat_mapping_value_v4 *nat_ingress_value,
                                            struct nat_timer_value **timer_value_) {
#define BPF_LOG_TOPIC "lookup_or_new_ct"

    struct nat_timer_key timer_key = {0};
    u8 flow_id = get_flow_id(skb->mark);

    timer_key.l4proto = l4proto;
    timer_key.pair_ip.src_port = nat_ingress_value->port;
    timer_key.pair_ip.dst_port = nat_egress_value->port;
    timer_key.pair_ip.src_addr.addr = nat_ingress_value->addr;
    timer_key.pair_ip.dst_addr.addr = nat_egress_value->addr;

    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    //              bpf_ntohs(timer_key.pair_ip.src_port), bpf_ntohs(timer_key.pair_ip.dst_port));
    // bpf_log_info("src_ip: %lu -> dst_ip: %lu", bpf_ntohl(timer_key.pair_ip.src_addr.ip),
    //              bpf_ntohl(timer_key.pair_ip.dst_addr.ip));

    struct nat_timer_value *timer_value = bpf_map_lookup_elem(&nat_mapping_timer, &timer_key);
    // bpf_log_info("timer_value: %u", timer_value);
    if (timer_value) {
        *timer_value_ = timer_value;
        return TIMER_EXIST;
    }
    if (!timer_value && !do_new) {
        return TIMER_NOT_FOUND;
    }

    struct nat_timer_value timer_value_new = {0};
    timer_value_new.trigger_port = nat_ingress_value->trigger_port;
    timer_value_new.client_status = CT_INIT;
    timer_value_new.server_status = CT_INIT;
    timer_value_new.gress = NAT_MAPPING_EGRESS;
    timer_value_new.trigger_saddr.addr = nat_egress_value->trigger_addr;
    timer_value_new.create_time = nat_egress_value->active_time;
    timer_value_new.flow_id = flow_id;
    timer_value = insert_new_nat_timer(l4proto, &timer_key, &timer_value_new);
    if (timer_value == NULL) {
        return TIMER_ERROR;
    }
    // bpf_log_debug("insert new CT");

    // 发送 event
    struct nat_conn_event *event;
    event = bpf_ringbuf_reserve(&nat_conn_events, sizeof(struct nat_conn_event), 0);
    if (event != NULL) {
        event->dst_addr.ip = nat_egress_value->trigger_addr;
        event->src_addr.ip = nat_ingress_value->addr;
        event->src_port = nat_ingress_value->port;
        event->dst_port = nat_egress_value->trigger_port;
        event->l4_proto = l4proto;
        event->l3_proto = LANDSCAPE_IPV4_TYPE;
        event->flow_id = flow_id;
        event->trace_id = 0;
        event->create_time = timer_value_new.create_time;
        event->event_type = NAT_CREATE_CONN;
        bpf_ringbuf_submit(event, 0);
    }

    *timer_value_ = timer_value;
    return TIMER_CREATED;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat_mapping_value_v4 *
insert_mappings_v4(const struct nat_mapping_key_v4 *key, const struct nat_mapping_value_v4 *val,
                   struct nat_mapping_value_v4 **lk_val_rev) {
#define BPF_LOG_TOPIC "insert_mappings_v4"
    int ret;
    struct nat_mapping_key_v4 key_rev = {
        .gress = key->gress ^ GRESS_MASK,
        .l4proto = key->l4proto,
        .from_addr = val->addr,
        .from_port = val->port,
    };

    struct nat_mapping_value_v4 val_rev = {
        .port = key->from_port,
        .addr = key->from_addr,
        .trigger_addr = val->trigger_addr,
        .trigger_port = val->trigger_port,
        .active_time = val->active_time,
        ._pad = {0, 0, 0},
    };

    ret = bpf_map_update_elem(&nat4_mappings, key, val, BPF_ANY);
    if (ret) {
        bpf_log_error("failed to insert binding entry, err:%d", ret);
        goto error_update;
    }
    ret = bpf_map_update_elem(&nat4_mappings, &key_rev, &val_rev, BPF_ANY);
    if (ret) {
        bpf_log_error("failed to insert reverse binding entry, err:%d", ret);
        goto error_update;
    }

    if (lk_val_rev) {
        *lk_val_rev = bpf_map_lookup_elem(&nat4_mappings, &key_rev);
        if (!*lk_val_rev) {
            return NULL;
        }
    }

    return bpf_map_lookup_elem(&nat4_mappings, key);
error_update:
    bpf_map_delete_elem(&nat4_mappings, key);
    bpf_map_delete_elem(&nat4_mappings, &key_rev);
    return NULL;
#undef BPF_LOG_TOPIC
}

static int search_port_callback_v4(u32 index, struct search_port_ctx_v4 *ctx) {
#define BPF_LOG_TOPIC "search_port_callback_v4"
    ctx->ingress_key.from_port = bpf_htons(ctx->curr_port);
    struct nat_mapping_value_v4 *value = bpf_map_lookup_elem(&nat4_mappings, &ctx->ingress_key);
    // 大于协议的超时时间
    if (!value || ctx->timeout_interval > value->active_time) {
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
ingress_lookup_or_new_mapping4(struct __sk_buff *skb, u8 ip_protocol, bool allow_create_mapping,
                               const struct inet4_pair *pkt_ip_pair,
                               struct nat_mapping_value_v4 **nat_egress_value_,
                               struct nat_mapping_value_v4 **nat_ingress_value_) {
#define BPF_LOG_TOPIC "ingress_lookup_or_new_mapping"
    u64 current_time = bpf_ktime_get_ns();
    if (pkt_ip_pair == NULL) {
        return TC_ACT_SHOT;
    }
    //
    struct nat_mapping_key_v4 ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = ip_protocol,              // 原有的 l4 层协议值
        .from_port = pkt_ip_pair->dst_port,  // 数据包中的 内网端口
        .from_addr = pkt_ip_pair->dst_addr.addr,
    };

    // 倒置的值
    struct nat_mapping_value_v4 *nat_ingress_value =
        bpf_map_lookup_elem(&nat4_mappings, &ingress_key);
    struct nat_mapping_value_v4 *nat_egress_value = NULL;
    if (!nat_ingress_value) {
        if (!allow_create_mapping) {
            return TC_ACT_SHOT;
        }
        return TC_ACT_SHOT;
    } else {
        // 已经存在就查询另外一个值 并进行刷新时间
        struct nat_mapping_key_v4 egress_key = {
            .gress = NAT_MAPPING_EGRESS,
            .l4proto = ip_protocol,                // 原有的 l4 层协议值
            .from_port = nat_ingress_value->port,  // 数据包中的 内网端口
            .from_addr = nat_ingress_value->addr,  // 内网原始地址
        };
        nat_egress_value = bpf_map_lookup_elem(&nat4_mappings, &egress_key);

        if (!nat_egress_value) {
            return TC_ACT_SHOT;
        }
        nat_egress_value->active_time = nat_ingress_value->active_time = current_time;
    }

    *nat_egress_value_ = nat_egress_value;
    *nat_ingress_value_ = nat_ingress_value;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
egress_lookup_or_new_mapping_v4(struct __sk_buff *skb, u8 ip_protocol, bool allow_create_mapping,
                                const struct inet4_pair *pkt_ip_pair,
                                struct nat_mapping_value_v4 **nat_egress_value_,
                                struct nat_mapping_value_v4 **nat_ingress_value_) {
#define BPF_LOG_TOPIC "egress_lookup_or_new_mapping"
    //
    u64 curent_time = bpf_ktime_get_ns();
    struct nat_mapping_key_v4 egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = ip_protocol,                   // 原有的 l4 层协议值
        .from_port = pkt_ip_pair->src_port,       // 数据包中的 内网端口
        .from_addr = pkt_ip_pair->src_addr.addr,  // 内网原始地址
    };

    // 倒置的值
    struct nat_mapping_value_v4 *nat_ingress_value = NULL;
    struct nat_mapping_value_v4 *nat_egress_value =
        bpf_map_lookup_elem(&nat4_mappings, &egress_key);
    if (!nat_egress_value) {
        if (!allow_create_mapping) {
            return TC_ACT_SHOT;
        }
        struct wan_ip_info_key wan_search_key = {0};
        wan_search_key.ifindex = skb->ifindex;
        wan_search_key.l3_protocol = LANDSCAPE_IPV4_TYPE;

        struct wan_ip_info_value *wan_ip_info =
            bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);

        if (!wan_ip_info) {
            bpf_log_info("can't find the wan ip, using ifindex: %d", skb->ifindex);
            return TC_ACT_SHOT;
        }
        bool allow_reuse_port = get_flow_allow_reuse_port(skb->mark);
        struct nat_mapping_value_v4 new_nat_egress_value = {0};

        new_nat_egress_value.addr = wan_ip_info->addr.ip;
        new_nat_egress_value.port = egress_key.from_port;  // 尽量先试试使用客户端发起时候的端口
        new_nat_egress_value.trigger_addr = pkt_ip_pair->dst_addr.addr;
        new_nat_egress_value.trigger_port = pkt_ip_pair->dst_port;
        new_nat_egress_value.is_static = 0;
        new_nat_egress_value.active_time = curent_time;
        new_nat_egress_value.is_allow_reuse = allow_reuse_port ? 1 : 0;

        int ret;
        struct search_port_ctx_v4 ctx = {
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

        ctx.timeout_interval = new_nat_egress_value.active_time;
        if (ip_protocol == IPPROTO_TCP) {
            ctx.range.start = tcp_range_start;
            ctx.range.end = tcp_range_end;
            ctx.remaining_size = tcp_range_end - tcp_range_start;
            ctx.timeout_interval -= TCP_TIMEOUT;
        } else if (ip_protocol == IPPROTO_UDP) {
            ctx.range.start = udp_range_start;
            ctx.range.end = udp_range_end;
            ctx.remaining_size = udp_range_end - udp_range_start;
            ctx.timeout_interval -= UDP_TIMEOUT;
        } else if (ip_protocol == IPPROTO_ICMP) {
            ctx.range.start = icmp_range_start;
            ctx.range.end = icmp_range_end;
            ctx.remaining_size = icmp_range_end - icmp_range_start;
            ctx.timeout_interval -= UDP_TIMEOUT;
        }

        if (ctx.remaining_size == 0) {
            bpf_log_error("not free port range start: %d end: %d", ctx.range.start, ctx.range.end);
            return TC_ACT_SHOT;
        }

        if (ctx.curr_port < ctx.range.start || ctx.curr_port > ctx.range.end) {
            u16 index = ctx.curr_port % ctx.remaining_size;
            ctx.curr_port = ctx.range.start + index;
        }

        ret = bpf_loop(65536, search_port_callback_v4, &ctx, 0);
        if (ret < 0) {
            return TC_ACT_SHOT;
        }

        if (ctx.found) {
            new_nat_egress_value.port = ctx.ingress_key.from_port;
            // bpf_log_debug("found free binding %d -> %d", bpf_ntohs(egress_key.from_port),
            //               bpf_ntohs(new_nat_egress_value.port));
        } else {
            bpf_log_debug("mapping is full");
            return TC_ACT_SHOT;
        }
        nat_egress_value =
            insert_mappings_v4(&egress_key, &new_nat_egress_value, &nat_ingress_value);
        if (!nat_egress_value) {
            return TC_ACT_SHOT;
        }
    } else {
        // 已经存在就查询另外一个值 并进行刷新时间
        struct nat_mapping_key_v4 ingress_key = {
            .gress = NAT_MAPPING_INGRESS,
            .l4proto = ip_protocol,               // 原有的 l4 层协议值
            .from_port = nat_egress_value->port,  // 数据包中的 内网端口
            .from_addr = nat_egress_value->addr,  // 内网原始地址
        };
        nat_ingress_value = bpf_map_lookup_elem(&nat4_mappings, &ingress_key);

        if (!nat_ingress_value) {
            return TC_ACT_SHOT;
        }
        nat_egress_value->active_time = nat_ingress_value->active_time = curent_time;
    }

    *nat_egress_value_ = nat_egress_value;
    *nat_ingress_value_ = nat_ingress_value;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int
lookup_static_mapping_v4(struct __sk_buff *skb, u8 ip_protocol, u8 gress,
                         const struct inet4_pair *pkt_ip_pair,
                         struct nat_mapping_value_v4 **nat_ingress_value_,
                         struct nat_mapping_value_v4 **nat_egress_value_) {
#define BPF_LOG_TOPIC "lk_static_map_v4"
    struct static_nat_mapping_key egress_key = {0};
    struct static_nat_mapping_key ingress_key = {0};

    egress_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
    egress_key.l4_protocol = ip_protocol;
    ingress_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
    ingress_key.l4_protocol = ip_protocol;

    struct nat_mapping_value_v4 *nat_gress_value = NULL;
    struct nat_mapping_value_v4 *nat_gress_value_rev = NULL;
    if (gress == NAT_MAPPING_EGRESS) {
        egress_key.gress = NAT_MAPPING_EGRESS;
        egress_key.prefixlen = 192;
        egress_key.port = pkt_ip_pair->src_port;
        egress_key.addr.ip = pkt_ip_pair->src_addr.addr;

        // 倒置的值
        nat_gress_value = bpf_map_lookup_elem(&static_nat_mappings, &egress_key);
        if (nat_gress_value) {
            // bpf_log_info("find egress value: nat_port: %u", bpf_htons(nat_gress_value->port));
            *nat_egress_value_ = nat_gress_value;
        } else {
            // bpf_log_info("can't find egress value: %u", bpf_htons(egress_key.port));
            return TC_ACT_SHOT;
        }
    } else {
        ingress_key.prefixlen = 96;
        ingress_key.gress = NAT_MAPPING_INGRESS;
        ingress_key.port = pkt_ip_pair->dst_port;
        // using current ifindex to query
        // egress_key.addr.ip = skb->ifindex;
        nat_gress_value_rev = bpf_map_lookup_elem(&static_nat_mappings, &ingress_key);

        if (!nat_gress_value_rev) {
            // bpf_log_info("can't find ingress key: target port: %u, protocol: %u",
            // bpf_htons(ingress_key.port), ip_protocol);
            return TC_ACT_SHOT;
        }
        // bpf_log_info("find ingress value: target %pI4:%u", nat_gress_value_rev->addr.all,
        //              bpf_htons(nat_gress_value_rev->port));
        *nat_ingress_value_ = nat_gress_value_rev;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* LD_NAT_V4_H */
