#ifndef __LD_NAT4_CT_TIMER_H__
#define __LD_NAT4_CT_TIMER_H__

#include "nat_common.h"
#include "nat_metric.h"
#include "nat4_dyn_map.h"
#include "nat4_map_ops.h"

#ifndef ENOENT
#define ENOENT 2
#endif

#define NAT4_TIMER_STEP_DELETE_CT 1U
#define NAT4_TIMER_STEP_RESTART 2U

static __always_inline int nat4_metric_try_report(struct nat4_timer_key *timer_key,
                                                  struct nat4_timer_value_v3 *timer_value,
                                                  u8 status) {
#define BPF_LOG_TOPIC "nat4_metric_try_report"

    struct nat_conn_metric_event *event;
    event = bpf_ringbuf_reserve(&nat_metric_events, sizeof(struct nat_conn_metric_event), 0);
    if (event == NULL) {
        return -1;
    }

    event->src_addr.ip = timer_value->client_addr.addr;
    event->dst_addr.ip = timer_key->pair_ip.src_addr.addr;
    event->src_port = timer_value->client_port;
    event->dst_port = timer_key->pair_ip.src_port;
    event->l4_proto = timer_key->l4proto;
    event->l3_proto = LANDSCAPE_IPV4_TYPE;
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
#undef BPF_LOG_TOPIC
}

static __always_inline u32 nat4_timer_delete_ct(struct nat4_timer_key *key) {
    bpf_map_delete_elem(&nat4_timer_map, key);
    return NAT4_TIMER_STEP_DELETE_CT;
}

static __always_inline u32 nat4_timer_restart(struct nat4_timer_value_v3 *value, u64 current_status,
                                              u64 next_status, u64 timeout_ns, u64 *next_timeout) {
    if (current_status != next_status &&
        !ct_try_set_status(&value->status, current_status, next_status)) {
        *next_timeout = REPORT_INTERVAL;
        return NAT4_TIMER_STEP_RESTART;
    }

    *next_timeout = timeout_ns;
    return NAT4_TIMER_STEP_RESTART;
}

static __always_inline int nat4_ct_advance(u8 pkt_type, u8 gress,
                                           struct nat4_timer_value_v3 *ct_timer_value) {
#define BPF_LOG_TOPIC "nat4_ct_advance"
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
        return TC_ACT_SHOT;
    }

    u64 prev_state = __sync_lock_test_and_set(&ct_timer_value->status, TIMER_ACTIVE);
    if (prev_state != TIMER_ACTIVE) {
        if (ct_timer_value->client_port == TEST_PORT) {
            ld_bpf_log("flush status to TIMER_ACTIVE: 20");
        }
        bpf_timer_start(&ct_timer_value->timer, REPORT_INTERVAL, 0);
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline u32 nat4_handle_timer_step(struct nat4_timer_key *key,
                                                  struct nat4_timer_value_v3 *value,
                                                  bool force_queue_push_fail, int *queue_push_ret,
                                                  u64 *next_timeout) {
    u64 current_status = value->status;
    u64 next_status = current_status;
    int ret;

    *queue_push_ret = -2;
    *next_timeout = REPORT_INTERVAL;

    if (current_status == TIMER_PENDING_REF) {
        return nat4_timer_delete_ct(key);
    }

    if (current_status == TIMER_RELEASE) {
        ret = nat4_metric_try_report(key, value, NAT_CONN_DELETE);

        if (value->is_static) {
            return nat4_timer_delete_ct(key);
        }

        struct nat4_mapping_value_v3 *ingress_value = nat4_lookup_ingress_dynamic(
            key->l4proto, key->pair_ip.dst_addr.addr, key->pair_ip.dst_port);
        if (!ingress_value || ingress_value->generation != value->generation_snapshot) {
            return nat4_timer_delete_ct(key);
        }

        if (nat4_state_try_close_last(ingress_value) == 0) {
            return nat4_timer_restart(value, current_status, TIMER_DELETE_EGRESS,
                                      DELETE_RETRY_INTERVAL, next_timeout);
        }

        if (nat4_state_try_dec(ingress_value) == 0) {
            return nat4_timer_delete_ct(key);
        }

        return nat4_timer_delete_ct(key);
    }

    if (current_status == TIMER_DELETE_EGRESS) {
        struct nat4_mapping_key egress_key = {
            .gress = NAT_MAPPING_EGRESS,
            .l4proto = key->l4proto,
            .from_addr = value->client_addr.addr,
            .from_port = value->client_port,
        };
        struct nat4_egress_mapping_value_v3 *egress_value =
            nat4_lookup_egress_dynamic(key->l4proto, value->client_addr.addr, value->client_port);

        if (egress_value && egress_value->addr == key->pair_ip.dst_addr.addr &&
            egress_value->port == key->pair_ip.dst_port) {
            long del_ret = bpf_map_delete_elem(&nat4_egress_dyn_map, &egress_key);
            if (del_ret != 0 && del_ret != -ENOENT) {
                return nat4_timer_restart(value, current_status, current_status,
                                          DELETE_RETRY_INTERVAL, next_timeout);
            }
        }

        return nat4_timer_restart(value, current_status, TIMER_DELETE_INGRESS,
                                  DELETE_RETRY_INTERVAL, next_timeout);
    }

    if (current_status == TIMER_DELETE_INGRESS) {
        struct nat4_mapping_key ingress_key = {
            .gress = NAT_MAPPING_INGRESS,
            .l4proto = key->l4proto,
            .from_addr = key->pair_ip.dst_addr.addr,
            .from_port = key->pair_ip.dst_port,
        };
        struct nat4_mapping_value_v3 *ingress_value =
            bpf_map_lookup_elem(&nat4_ingress_dyn_map, &ingress_key);

        if (!ingress_value) {
            return nat4_timer_restart(value, current_status, TIMER_PUSH_QUEUE, QUEUE_RETRY_INTERVAL,
                                      next_timeout);
        }

        if (ingress_value->generation != value->generation_snapshot) {
            return nat4_timer_delete_ct(key);
        }

        long del_ret = bpf_map_delete_elem(&nat4_ingress_dyn_map, &ingress_key);
        if (del_ret != 0 && del_ret != -ENOENT) {
            return nat4_timer_restart(value, current_status, current_status, DELETE_RETRY_INTERVAL,
                                      next_timeout);
        }

        return nat4_timer_restart(value, current_status, TIMER_PUSH_QUEUE, QUEUE_RETRY_INTERVAL,
                                  next_timeout);
    }

    if (current_status == TIMER_PUSH_QUEUE) {
        if (value->is_static) {
            return nat4_timer_delete_ct(key);
        }

        struct nat4_port_queue_value_v3 free_item = {
            .port = key->pair_ip.dst_port,
            .last_generation = value->generation_snapshot,
        };
        *queue_push_ret = force_queue_push_fail ? -1 : nat4_queue_push(key->l4proto, &free_item);
        if (*queue_push_ret == 0) {
            return nat4_timer_delete_ct(key);
        }

        return nat4_timer_restart(value, current_status, current_status, QUEUE_RETRY_INTERVAL,
                                  next_timeout);
    }

    ret = nat4_metric_try_report(key, value, NAT_CONN_ACTIVE);
    if (ret) {
        *next_timeout = REPORT_INTERVAL;
        return NAT4_TIMER_STEP_RESTART;
    }

    if (current_status == TIMER_ACTIVE) {
        next_status = TIMER_TIMEOUT_1;
        *next_timeout = REPORT_INTERVAL;
    } else if (current_status == TIMER_TIMEOUT_1) {
        next_status = TIMER_TIMEOUT_2;
        *next_timeout = REPORT_INTERVAL;
    } else if (current_status == TIMER_TIMEOUT_2) {
        next_status = TIMER_RELEASE;
        if (key->l4proto == IPPROTO_TCP) {
            if (value->client_status == CT_SYN && value->server_status == CT_SYN) {
                *next_timeout = TCP_TIMEOUT;
            } else {
                *next_timeout = TCP_SYN_TIMEOUT;
            }
        } else {
            *next_timeout = UDP_TIMEOUT;
        }
    } else {
        next_status = TIMER_TIMEOUT_2;
        *next_timeout = REPORT_INTERVAL;
    }

    if (__sync_val_compare_and_swap(&value->status, current_status, next_status) !=
        current_status) {
        *next_timeout = REPORT_INTERVAL;
        return NAT4_TIMER_STEP_RESTART;
    }

    return NAT4_TIMER_STEP_RESTART;
}

static int nat4_timer_clean_callback(void *map_, struct nat4_timer_key *key,
                                     struct nat4_timer_value_v3 *value) {
#define BPF_LOG_TOPIC "nat4_timer_clean_callback"
    int queue_push_ret = -2;
    u64 next_timeout = REPORT_INTERVAL;
    u32 action = nat4_handle_timer_step(key, value, false, &queue_push_ret, &next_timeout);

    if (action == NAT4_TIMER_STEP_RESTART) {
        bpf_timer_start(&value->timer, next_timeout, 0);
    }
    return 0;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat4_timer_value_v3 *
nat4_insert_ct(const struct nat4_timer_key *key, const struct nat4_timer_value_v3 *val) {
    if (bpf_map_update_elem(&nat4_timer_map, key, val, BPF_NOEXIST) != 0) {
        return NULL;
    }
    struct nat4_timer_value_v3 *value = bpf_map_lookup_elem(&nat4_timer_map, key);
    if (!value) {
        return NULL;
    }
    if (bpf_timer_init(&value->timer, &nat4_timer_map, CLOCK_MONOTONIC) != 0) {
        goto err;
    }
    if (bpf_timer_set_callback(&value->timer, nat4_timer_clean_callback) != 0) {
        goto err;
    }
    if (bpf_timer_start(&value->timer, REPORT_INTERVAL, 0) != 0) {
        goto err;
    }
    return value;
err:
    bpf_map_delete_elem(&nat4_timer_map, key);
    return NULL;
}

enum ct_ingress_resolve {
    CT_RESOLVE_MISS = 0,
    CT_RESOLVE_OK = 1,
    CT_RESOLVE_UNUSABLE = 2,
};

static __always_inline enum ct_ingress_resolve
nat4_ct_ingress_resolve(const struct nat4_timer_key *ct_key,
                        struct nat4_timer_value_v3 **timer_value_) {
    struct nat4_timer_value_v3 *tv = bpf_map_lookup_elem(&nat4_timer_map, ct_key);
    if (!tv) {
        return CT_RESOLVE_MISS;
    }
    if (tv->status == TIMER_PENDING_REF || tv->status > TIMER_RELEASE) {
        return CT_RESOLVE_UNUSABLE;
    }
    *timer_value_ = tv;
    return CT_RESOLVE_OK;
}

static __always_inline int nat4_ct_resolve(const struct nat4_timer_key *ct_key,
                                           struct nat4_mapping_value_v3 *dyn_ingress,
                                           struct nat4_timer_value_v3 **timer_value_) {
    bool track_dynamic_ref = dyn_ingress != NULL;
    u16 generation_snapshot = track_dynamic_ref ? dyn_ingress->generation : 0;

    struct nat4_timer_value_v3 *timer_value = bpf_map_lookup_elem(&nat4_timer_map, ct_key);
    if (timer_value) {
        if (track_dynamic_ref && generation_snapshot != 0 &&
            timer_value->generation_snapshot != generation_snapshot) {
            bpf_map_delete_elem(&nat4_timer_map, ct_key);
        } else if (timer_value->status == TIMER_PENDING_REF) {
            return -1;
        } else {
            *timer_value_ = timer_value;
            return 0;
        }
    }
    return -1;
}

#endif /* __LD_NAT4_CT_TIMER_H__ */
