#ifndef __LD_NAT6_CT_TIMER_H__
#define __LD_NAT6_CT_TIMER_H__

#include "nat_common.h"
#include "nat_metric.h"
#include "nat6_dyn_map.h"
#include "nat6_map_ops.h"

static __always_inline int nat6_metric_try_report(struct nat6_timer_key *timer_key,
                                                  struct nat6_timer_value *timer_value, u8 status) {
    struct nat_conn_metric_event *event;
    event = bpf_ringbuf_reserve(&nat_metric_events, sizeof(struct nat_conn_metric_event), 0);
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
    event->time = bpf_ktime_get_tai_ns();
    event->create_time = timer_value->create_time;
    event->ingress_bytes = timer_value->ingress_bytes;
    event->ingress_packets = timer_value->ingress_packets;
    event->egress_bytes = timer_value->egress_bytes;
    event->egress_packets = timer_value->egress_packets;
    event->cpu_id = timer_value->cpu_id;
    event->ifindex = timer_value->ifindex;
    event->status = status;
    event->gress = timer_value->gress;
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static int nat6_timer_clean_callback(void *map_mapping_timer_, struct nat6_timer_key *key,
                                     struct nat6_timer_value *value) {
#define BPF_LOG_TOPIC "nat6_timer_clean_callback"

    u64 client_status = value->client_status;
    u64 server_status = value->server_status;
    u64 current_status = value->status;
    u64 next_status = current_status;
    u64 next_timeout = REPORT_INTERVAL;
    int ret;

    if (value->trigger_port == TEST_PORT) {
        ld_bpf_log("timer_clean_callback: %pI6, current_status: %llu", &value->trigger_addr.bytes,
                   current_status);
    }

    if (current_status == TIMER_RELEASE) {
        if (!ct_try_set_status(&value->status, TIMER_RELEASE, TIMER_CLEAN_START)) {
            bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
            return 0;
        }
        current_status = TIMER_CLEAN_START;
    }

    if (current_status == TIMER_CLEAN_START) {
        if (value->trigger_port == TEST_PORT) {
            ld_bpf_log("release CONNECT");
        }

        ret = nat6_metric_try_report(key, value, NAT_CONN_DELETE);
        if (ret) {
            ld_bpf_log("call back report fail");
            bpf_timer_start(&value->timer, next_timeout, 0);
            return 0;
        }
        goto release;
    }

    ret = nat6_metric_try_report(key, value, NAT_CONN_ACTIVE);
    if (ret) {
        ld_bpf_log("call back report fail");
        bpf_timer_start(&value->timer, next_timeout, 0);
        return 0;
    }

    if (current_status == TIMER_ACTIVE) {
        next_status = TIMER_TIMEOUT_1;
        next_timeout = REPORT_INTERVAL;

        if (value->trigger_port == TEST_PORT) {
            ld_bpf_log("change next status TIMER_TIMEOUT_1");
        }
    } else if (current_status == TIMER_TIMEOUT_1) {
        next_status = TIMER_TIMEOUT_2;
        next_timeout = REPORT_INTERVAL;

        if (value->trigger_port == TEST_PORT) {
            ld_bpf_log("change next status TIMER_TIMEOUT_2");
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
            ld_bpf_log("change next status TIMER_RELEASE, next_timeout: %d", show);
        }
    } else {
        next_status = TIMER_TIMEOUT_2;
        next_timeout = REPORT_INTERVAL;
    }

    if (__sync_val_compare_and_swap(&value->status, current_status, next_status) !=
        current_status) {
        ld_bpf_log("call back modify status fail, current status: %d new status: %d",
                   current_status, next_status);
        bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
        return 0;
    }

    bpf_timer_start(&value->timer, next_timeout, 0);

    return 0;
release:;
    bpf_map_delete_elem(&nat6_timer_map, key);
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat6_timer_value *nat6_insert_timer(const struct nat6_timer_key *key,
                                                                  struct nat6_timer_value *val) {
#define BPF_LOG_TOPIC "nat6_insert_timer"

    int ret = bpf_map_update_elem(&nat6_timer_map, key, val, BPF_NOEXIST);
    if (ret) {
        ld_bpf_log("ct6 timer map insert failed: %d", ret);
        return NULL;
    }
    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &nat6_timer_map, CLOCK_MONOTONIC);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_set_callback(&value->timer, nat6_timer_clean_callback);
    if (ret) {
        goto delete_timer;
    }
    ret = bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
    if (ret) {
        goto delete_timer;
    }

    return value;
delete_timer:
    ld_bpf_log("ct6 timer setup failed: %d", ret);
    bpf_map_delete_elem(&nat6_timer_map, key);
    return NULL;
#undef BPF_LOG_TOPIC
}

static __always_inline int nat6_ct_advance(u8 pkt_type, u8 gress,
                                           struct nat6_timer_value *ct_timer_value) {
#define BPF_LOG_TOPIC "nat6_ct_advance"
    u64 curr_state, *modify_status = NULL;
    if (gress == NAT_MAPPING_INGRESS) {
        curr_state = ct_timer_value->server_status;
        modify_status = &ct_timer_value->server_status;
    } else {
        curr_state = ct_timer_value->client_status;
        modify_status = &ct_timer_value->client_status;
    }

    u64 next_status = curr_state;
    switch (pkt_type) {
    case PKT_CONNLESS_V2:
        next_status = CT_LESS_EST;
        break;
    case PKT_TCP_RST_V2:
        next_status = CT_INIT;
        break;
    case PKT_TCP_SYN_V2:
        next_status = CT_SYN;
        break;
    case PKT_TCP_FIN_V2:
        next_status = CT_FIN;
        break;
    }

    if (next_status != curr_state && !ct_try_set_status(modify_status, curr_state, next_status)) {
        return NAT_OP_ERR;
    }

    u64 current_status = ct_timer_value->status;
    if (ct_status_can_activate(current_status)) {
        u64 prev_status =
            __sync_val_compare_and_swap(&ct_timer_value->status, current_status, TIMER_ACTIVE);
        if (prev_status == current_status) {
            if (ct_timer_value->trigger_port == TEST_PORT) {
                ld_bpf_log("flush status to TIMER_ACTIVE: 20");
            }
            bpf_timer_start(&ct_timer_value->timer, REPORT_INTERVAL, 0);
        }
    }

    return NAT_OP_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_NAT6_CT_TIMER_H__ */
