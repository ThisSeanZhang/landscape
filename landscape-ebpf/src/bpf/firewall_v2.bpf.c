#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "firewall_v2.h"
#include "firewall_share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;
const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL

#define CLOCK_MONOTONIC 1

const volatile u64 REPORT_INTERVAL = 1E9 * 5;

static __always_inline bool pkt_allow_initiating_ct(u8 pkt_type) {
    return pkt_type == PKT_CONNLESS_V2 || pkt_type == PKT_TCP_SYN_V2;
}

static __always_inline void
firewall_metric_accumulate(struct __sk_buff *skb, bool ingress,
                           struct firewall_conntrack_action_v2 *timer_track_value) {
    u64 bytes = skb->len;
    if (ingress) {
        __sync_fetch_and_add(&timer_track_value->ingress_bytes, bytes);
        __sync_fetch_and_add(&timer_track_value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&timer_track_value->egress_bytes, bytes);
        __sync_fetch_and_add(&timer_track_value->egress_packets, 1);
    }
}

static __always_inline enum firewall_report_status
firewall_metric_try_report(struct firewall_conntrack_key *timer_key,
                           struct firewall_conntrack_action_v2 *timer_track_value) {
#define BPF_LOG_TOPIC "fm_try_report"
    __u64 now = bpf_ktime_get_ns();

    __u64 ingress_bytes_before = timer_track_value->ingress_bytes;
    __u64 ingress_packets_before = timer_track_value->ingress_packets;
    __u64 egress_bytes_before = timer_track_value->egress_bytes;
    __u64 egress_packets_before = timer_track_value->egress_packets;

    struct firewall_conn_metric_event *event;
    event = bpf_ringbuf_reserve(&firewall_conn_metric_events,
                                sizeof(struct firewall_conn_metric_event), 0);
    if (event != NULL) {
        COPY_ADDR_FROM(event->dst_addr.all, timer_track_value->trigger_addr.all);
        COPY_ADDR_FROM(event->src_addr.all, timer_key->local_addr.all);
        event->src_port = timer_key->local_port;
        event->dst_port = timer_track_value->trigger_port;
        event->l4_proto = timer_key->ip_protocol;
        event->l3_proto = timer_key->ip_type;
        event->flow_id = timer_track_value->flow_id;
        event->trace_id = 0;
        event->time = now;
        event->create_time = timer_track_value->create_time;
        event->ingress_bytes = ingress_bytes_before;
        event->ingress_packets = ingress_packets_before;
        event->egress_bytes = egress_bytes_before;
        event->egress_packets = egress_packets_before;
        bpf_ringbuf_submit(event, 0);

        timer_track_value->last_upload_ts = now;
        __sync_fetch_and_sub(&timer_track_value->ingress_bytes, ingress_bytes_before);
        __sync_fetch_and_sub(&timer_track_value->ingress_packets, ingress_packets_before);
        __sync_fetch_and_sub(&timer_track_value->egress_bytes, egress_bytes_before);
        __sync_fetch_and_sub(&timer_track_value->egress_packets, egress_packets_before);

        return FIREWALL_REPORT_NONE;
    }

    return FIREWALL_REPORT_CONFLICT;
#undef BPF_LOG_TOPIC
}

static __always_inline bool ct_change_state(struct firewall_conntrack_action_v2 *timer_track_value,
                                            u64 curr_state, u64 next_state) {
    return __sync_bool_compare_and_swap(&timer_track_value->conn_status, curr_state, next_state);
}

static __always_inline int
ct_state_transition(u8 l4proto, u8 pkt_type, struct firewall_conntrack_action_v2 *ct_timer_value) {
#define BPF_LOG_TOPIC "ct_state_transition"
    // bool ingress = false;
    u64 curr_state = ct_timer_value->conn_status;
    //     u64 connect_status = 0;
    //     if (ingress) {

    //         connect_status = ct_timer_value->local_status;
    //     } else {
    //         connect_status = ct_timer_value->remote_status;
    //     }

    // #define NEW_STATE(__state) \
    //     if (!ct_change_state(ct_timer_value, curr_state, (__state))) { \
    //         return TC_ACT_SHOT; \
    //     }

    //     if (pkt_type == PKT_CONNLESS) {
    //         NEW_STATE(OTHER_EST);
    //     }

    //     if (pkt_type == PKT_TCP_RST) {
    //         NEW_STATE(TIMER_INIT);
    //     }

    //     if (pkt_type == PKT_TCP_SYN) {
    //         NEW_STATE(TIMER_INIT);
    //     }
    u64 prev_state = __sync_lock_test_and_set(&ct_timer_value->conn_status, FIREWALL_ACTIVE);
    // bpf_log_info("flush status to FIREWALL_ACTIVE:20");

    if (prev_state == FIREWALL_TIMEOUT_2 || prev_state == FIREWALL_RELEASE ) {
        bpf_timer_start(&ct_timer_value->timer, CONN_EST_TIMEOUT, 0);
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static int timer_clean_callback(void *map_mapping_timer_, struct firewall_conntrack_key *key,
                                struct firewall_conntrack_action_v2 *value) {
#define BPF_LOG_TOPIC "timer_clean_callback"

    __u64 conn_status = value->conn_status;
    __u64 next_conn_status = conn_status;
    u64 next_timeout = CONN_EST_TIMEOUT;
    int ret;
    // bpf_log_info("timer_clean_callback: %d", bpf_ntohs(value->trigger_port));

    __u8 report_result;
    // 说明是 release 超时, 上报后释放 CONN
    if (conn_status == FIREWALL_RELEASE) {
        struct firewall_conn_event *event;
        event = bpf_ringbuf_reserve(&firewall_conn_events, sizeof(struct firewall_conn_event), 0);
        if (event != NULL) {
            COPY_ADDR_FROM(event->dst_addr.all, value->trigger_addr.all);
            COPY_ADDR_FROM(event->src_addr.all, key->local_addr.all);
            event->src_port = key->local_port;
            event->dst_port = value->trigger_port;
            event->l4_proto = key->ip_protocol;
            event->l3_proto = key->ip_type;
            event->flow_id = value->flow_id;
            event->trace_id = 0;
            event->create_time = value->create_time;
            event->report_time = bpf_ktime_get_ns();
            event->event_type = FIREWALL_DELETE_CONN;
            bpf_ringbuf_submit(event, 0);
        }

        // bpf_log_info("call back remove conn");
        ret = bpf_map_delete_elem(&fire2_conn_map, key);
        if (ret) {
            bpf_log_error("call back remove conn error: %pI4:%d->%pI4:%d", &key->local_addr,
                          bpf_ntohs(key->local_port), &value->trigger_addr,
                          bpf_ntohs(value->trigger_port));
        }
        return 0;
    }

    // 尝试进行上报
    report_result = firewall_metric_try_report(key, value);
    if (report_result != FIREWALL_REPORT_NONE) {
        bpf_log_info("call back report fail, try next");
        // 上报失败， 所以延期到下个周期
        bpf_timer_start(&value->timer, CONN_EST_TIMEOUT, 0);
        return 0;
    }

    if (conn_status == FIREWALL_ACTIVE) {
        // bpf_log_info("call back turn to timeout1");
        next_conn_status = FIREWALL_TIMEOUT_1;
        next_timeout = CONN_EST_TIMEOUT;
    } else if (conn_status == FIREWALL_TIMEOUT_1) {
        // bpf_log_info("call back turn to timeout2");
        next_conn_status = FIREWALL_TIMEOUT_2;
        next_timeout = CONN_EST_TIMEOUT;
    } else if (conn_status == FIREWALL_TIMEOUT_2) {
        // bpf_log_info("call back turn to release");
        next_conn_status = FIREWALL_RELEASE;
        next_timeout = key->ip_protocol == IPPROTO_TCP ? CONN_TCP_RELEASE : CONN_UDP_RELEASE;
    }

    if (__sync_val_compare_and_swap(&value->conn_status, conn_status, next_conn_status) !=
        conn_status) {
        bpf_log_info("call back modify status fail, current status: %d new status: %d", conn_status,
                     next_conn_status);
        // 更新状态失败, 说明有新的数据包到达
        bpf_timer_start(&value->timer, CONN_EST_TIMEOUT, 0);
        return 0;
    }

    bpf_timer_start(&value->timer, next_timeout, 0);

    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat_timer_value *
insert_new_nat_timer(const struct firewall_conntrack_key *key,
                     const struct firewall_conntrack_action_v2 *val) {
#define BPF_LOG_TOPIC "insert_new_nat_timer"
    // bpf_log_info("protocol: %u, src_port: %u -> dst_port: %u", l4proto,
    // bpf_ntohs(key->pair_ip.src_port), bpf_ntohs(key->pair_ip.dst_port)); bpf_log_info("src_ip:
    // %lu -> dst_ip: %lu", bpf_ntohl(key->pair_ip.src_addr.ip),
    // bpf_ntohl(key->pair_ip.dst_addr.ip));

    int ret = bpf_map_update_elem(&fire2_conn_map, key, val, BPF_NOEXIST);
    if (ret) {
        bpf_log_error("failed to insert conntrack entry, err:%d", ret);
        return NULL;
    }
    struct firewall_conntrack_action_v2 *value = bpf_map_lookup_elem(&fire2_conn_map, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &fire2_conn_map, CLOCK_MONOTONIC);
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
    bpf_map_delete_elem(&fire2_conn_map, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline int lookup_static_rules(struct firewall_static_rule_key *timer_key,
                                               struct firewall_conntrack_action_v2 **timer_value_) {
#define BPF_LOG_TOPIC "lookup_static_rules"
    struct firewall_conntrack_action_v2 *action;
    action = bpf_map_lookup_elem(&firewall_allow_rules_map, timer_key);
    if (action) {
        *timer_value_ = action;
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
static __always_inline int lookup_or_create_ct(struct __sk_buff *skb, bool do_new,
                                               struct firewall_conntrack_key *timer_key,
                                               union u_inet_addr *remote_addr, __be16 *remote_port,
                                               struct firewall_conntrack_action_v2 **timer_value_) {
#define BPF_LOG_TOPIC "lookup_or_create_ct"

    struct firewall_conntrack_action_v2 *timer_value =
        bpf_map_lookup_elem(&fire2_conn_map, timer_key);
    if (timer_value) {
        *timer_value_ = timer_value;
        return TIMER_EXIST;
    }
    if (!timer_value && !do_new) {
        return TIMER_NOT_FOUND;
    }

    struct firewall_conntrack_action_v2 action = {.conn_status = FIREWALL_INIT,
                                                  .local_status = CONN_CLOSED,
                                                  .remote_status = CONN_CLOSED,
                                                  .mark = 0,
                                                  ._pad = 0,
                                                  .trigger_port = *remote_port,
                                                  .create_time = bpf_ktime_get_ns(),
                                                  .last_upload_ts = 0,
                                                  .ingress_bytes = 0,
                                                  .ingress_packets = 0,
                                                  .egress_bytes = 0,
                                                  .egress_packets = 0};
    action.flow_id = get_flow_id(skb->mark);
    // if (skb->mark !=0) {
    //     bpf_log_info("skb->mark %d, action.flow_id: %d ", skb->mark, action.flow_id);
    // }
    COPY_ADDR_FROM(action.trigger_addr.all, remote_addr->all);
    timer_value = insert_new_nat_timer(timer_key, &action);
    if (timer_value == NULL) {
        return TIMER_ERROR;
    }

    // 发送 event
    struct firewall_conn_event *event;
    event = bpf_ringbuf_reserve(&firewall_conn_events, sizeof(struct firewall_conn_event), 0);
    if (event != NULL) {
        COPY_ADDR_FROM(event->dst_addr.all, action.trigger_addr.all);
        COPY_ADDR_FROM(event->src_addr.all, timer_key->local_addr.all);
        event->src_port = timer_key->local_port;
        event->dst_port = action.trigger_port;
        event->l4_proto = timer_key->ip_protocol;
        event->l3_proto = timer_key->ip_type;
        event->flow_id = action.flow_id;
        event->trace_id = 0;
        event->create_time = action.create_time;
        event->report_time = action.create_time;
        event->event_type = FIREWALL_CREATE_CONN;
        bpf_ringbuf_submit(event, 0);
    }

    // bpf_log_debug("insert new CT, type: %d, ip_protocol: %d, port: %d", timer_key->ip_type,
    //               timer_key->ip_protocol, bpf_ntohs(timer_key->local_port));

    *timer_value_ = timer_value;
    return TIMER_CREATED;
#undef BPF_LOG_TOPIC
}

/// main function
SEC("tc/egress")
int egress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< egress_firewall <<<"

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

    // 先检查是否有规则已经放行
    struct firewall_static_rule_key rule_key = {0};
    rule_key.prefixlen = pkg_offset.l3_protocol == LANDSCAPE_IPV6_TYPE ? 160 : 64;
    rule_key.ip_type = pkg_offset.l3_protocol;
    rule_key.ip_protocol = pkg_offset.l4_protocol;
    rule_key.local_port = ip_pair.src_port;

    // 限制的是可访问的 IP
    COPY_ADDR_FROM(rule_key.remote_address.bits, ip_pair.dst_addr.bits);

    bool is_icmpx_error = is_icmp_error_pkt(&pkg_offset);
    bool is_icmp = pkg_offset.l4_protocol == IPPROTO_ICMP || pkg_offset.l4_protocol == NEXTHDR_ICMP;
    u8 icmp_type = 255;  // unassigned icmp message

    if (!is_icmpx_error && is_icmp) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, pkg_offset.l4_offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }
        icmp_type = icmph->type;
        rule_key.local_port = ((u16)icmp_type << 8);
    }

    struct firewall_static_ct_action *static_ct_value = NULL;
    ret = lookup_static_rules(&rule_key, &static_ct_value);
    if (static_ct_value == NULL) {
        bool is_icmp_reply = is_icmp && (icmp_type == 0 || icmp_type == 129);
        if (is_icmp_reply) {
            return TC_ACT_UNSPEC;
        }

        // 没有端口开放 那就进行检查是否已经动态添加过了
        struct firewall_conntrack_key conntrack_key = {0};
        conntrack_key.ip_type = pkg_offset.l3_protocol;
        conntrack_key.ip_protocol = pkg_offset.l4_protocol;
        conntrack_key.local_port = ip_pair.src_port;
        COPY_ADDR_FROM(conntrack_key.local_addr.all, &ip_pair.src_addr.all);
        // 需要进行创建
        bool allow_create_mapping = !is_icmpx_error && pkt_allow_initiating_ct(pkg_offset.pkt_type);

        struct firewall_conntrack_action_v2 *ct_timer_value;
        ret = lookup_or_create_ct(skb, allow_create_mapping, &conntrack_key, &ip_pair.dst_addr,
                                  &ip_pair.dst_port, &ct_timer_value);

        if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
            return TC_ACT_SHOT;
        }
        if (!is_icmpx_error || ct_timer_value != NULL) {
            ct_state_transition(pkg_offset.l4_protocol, pkg_offset.pkt_type, ct_timer_value);
            firewall_metric_accumulate(skb, false, ct_timer_value);
        }
    } else {
        // bpf_log_info("has firewall rule");
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int ingress_firewall(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< ingress_firewall <<<"

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

    // 先检查是否已经有旧连接了
    struct firewall_conntrack_key conntrack_key = {0};
    conntrack_key.ip_type = pkg_offset.l3_protocol;
    conntrack_key.ip_protocol = pkg_offset.l4_protocol;
    conntrack_key.local_port = ip_pair.dst_port;
    COPY_ADDR_FROM(conntrack_key.local_addr.all, ip_pair.dst_addr.all);

    struct firewall_conntrack_action_v2 *ct_timer_value;
    ret = lookup_or_create_ct(skb, false, &conntrack_key, &ip_pair.src_addr, &ip_pair.src_port,
                              &ct_timer_value);

    if (ret == TIMER_EXIST || ret == TIMER_CREATED) {
        if (ct_timer_value != NULL) {
            ct_state_transition(pkg_offset.l4_protocol, pkg_offset.pkt_type, ct_timer_value);
            firewall_metric_accumulate(skb, true, ct_timer_value);
            return TC_ACT_UNSPEC;
        }
        bpf_log_error("ct_timer_value is NULL");
        return TC_ACT_SHOT;
    }

    // 检查用户是否已配置端口开放了
    struct firewall_static_rule_key rule_key = {0};
    rule_key.prefixlen = pkg_offset.l3_protocol == LANDSCAPE_IPV6_TYPE ? 160 : 64;
    rule_key.ip_type = pkg_offset.l3_protocol;
    rule_key.ip_protocol = pkg_offset.l4_protocol;
    rule_key.local_port = ip_pair.dst_port;
    // 限制的是可访问的 IP
    COPY_ADDR_FROM(rule_key.remote_address.all, ip_pair.src_addr.all);

    bool is_icmpx_error = is_icmp_error_pkt(&pkg_offset);
    bool is_icmp = pkg_offset.l4_protocol == IPPROTO_ICMP || pkg_offset.l4_protocol == NEXTHDR_ICMP;
    if (!is_icmpx_error && is_icmp) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, pkg_offset.l4_offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }
        rule_key.local_port = ((u16)icmph->type << 8);
    }

    struct firewall_static_ct_action *static_ct_value = NULL;
    ret = lookup_static_rules(&rule_key, &static_ct_value);
    if (static_ct_value != NULL) {
        // bpf_log_info("has firewall rule");
        // bpf_log_info(
        //     "packet ip:%pI4:%d->%pI4:%d, ip_protocol: %d", &packet_info.ip_hdr.pair_ip.src_addr,
        //     bpf_ntohs(packet_info.ip_hdr.pair_ip.src_port), &packet_info.ip_hdr.pair_ip.dst_addr,
        //     bpf_ntohs(packet_info.ip_hdr.pair_ip.dst_port), packet_info.ip_hdr.ip_protocol);
        u32 mark = skb->mark;
        barrier_var(mark);
        skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
        // bpf_log_info("set wan ingress mark: %u", skb->mark);
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
