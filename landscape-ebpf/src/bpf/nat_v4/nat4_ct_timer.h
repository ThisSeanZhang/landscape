/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_NAT4_CT_TIMER_H
#define LAND_NAT_NAT4_CT_TIMER_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/mark.h"
#include "base/tc_act.h"
#include "reader/tc_nat_view.h"
#include "nat_v4/nat4_metric.h"
#include "nat_v4/tc_nat4_map.h"

#define NAPT_NSEC_PER_SEC 1000000000ULL
#define NAPT_CT_REPORT_INTERVAL_NS (5ULL * NAPT_NSEC_PER_SEC)
#define NAPT_TCP_SYN_TIMEOUT_NS (6ULL * NAPT_NSEC_PER_SEC)
#define NAPT_TCP_TIMEOUT_NS (10ULL * 60ULL * NAPT_NSEC_PER_SEC)
#define NAPT_UDP_TIMEOUT_NS (5ULL * 60ULL * NAPT_NSEC_PER_SEC)
#define NAPT_DELETE_RETRY_INTERVAL_NS (100ULL * 1000ULL * 1000ULL)
#define NAPT_QUEUE_RETRY_INTERVAL_NS (500ULL * 1000ULL * 1000ULL)

enum napt_ct_status {
    NAPT_CT_INIT = 0ULL,
    NAPT_CT_PENDING_REF = 10ULL,
    NAPT_CT_ACTIVE = 20ULL,
    NAPT_CT_IDLE_1 = 30ULL,
    NAPT_CT_IDLE_2 = 31ULL,
    NAPT_CT_RELEASE = 40ULL,
    NAPT_CT_CLEAN_START = 50ULL,
    NAPT_CT_DELETE_EGRESS = NAPT_CT_CLEAN_START,
    NAPT_CT_DELETE_INGRESS = 51ULL,
    NAPT_CT_PUSH_QUEUE = 52ULL,
};

enum napt_tcp_state {
    NAPT_TCP_STATE_INIT = 0ULL,
    NAPT_TCP_STATE_SYN = 1ULL,
    NAPT_TCP_STATE_FIN = 2ULL,
    NAPT_TCP_STATE_LESS_EST = 3ULL,
};

#define NAPT_TIMER_STEP_DELETE_CT 1U
#define NAPT_TIMER_STEP_RESTART 2U

static __always_inline int napt_ct_status_usable(__u64 status) {
    return status != NAPT_CT_PENDING_REF && status < NAPT_CT_CLEAN_START;
}

static __always_inline int napt_ct_status_can_activate(__u64 status) {
    return status != NAPT_CT_ACTIVE && status != NAPT_CT_PENDING_REF &&
           status < NAPT_CT_CLEAN_START;
}

static __always_inline int napt_ct_timer_start(struct napt_ct_value *value, __u64 ns) {
    return bpf_timer_start(&value->timer, ns, 0) == 0;
}

static __always_inline u32 napt_ct_delete(struct napt_ct_key *key) {
    bpf_map_delete_elem(&napt_ct, key);
    return NAPT_TIMER_STEP_DELETE_CT;
}

static __always_inline u32 napt_ct_restart(struct napt_ct_value *value, __u64 current, __u64 next,
                                           __u64 timeout, __u64 *next_timeout) {
    if (current != next && !__sync_bool_compare_and_swap(&value->status, current, next)) {
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
        return NAPT_TIMER_STEP_RESTART;
    }

    *next_timeout = timeout;
    return NAPT_TIMER_STEP_RESTART;
}

static __always_inline __u64 napt_ct_wait_ns(const struct napt_ct_key *key,
                                             const struct napt_ct_value *value) {
    if (key->proto == IPV4_PROTO_UDP) return NAPT_UDP_TIMEOUT_NS;

    if (key->proto == IPV4_PROTO_TCP) {
        if (value->client_status == NAPT_TCP_STATE_SYN &&
            value->server_status == NAPT_TCP_STATE_SYN)
            return NAPT_TCP_TIMEOUT_NS;
        return NAPT_TCP_SYN_TIMEOUT_NS;
    }

    return NAPT_UDP_TIMEOUT_NS;
}

/*
 * Advance one connection-tracking entry one step. The dynamic mapping is
 * cleaned in the same way as the production CT state machine: the last
 * reference closes the WAN array entry, then LAN and WAN entries are released
 * in separate retryable steps before the port returns to its queue.
 */
static __always_inline u32 napt_ct_timer_step(struct napt_ct_key *key, struct napt_ct_value *value,
                                              int force_queue_push_fail, int *queue_push_ret,
                                              __u64 *next_timeout) {
    __u64 current = value->status;
    __u64 next = current;
    int ret;

    *queue_push_ret = -2;
    *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;

    if (current == NAPT_CT_PENDING_REF) return napt_ct_delete(key);

    if (current == NAPT_CT_RELEASE) {
        if (!__sync_bool_compare_and_swap(&value->status, NAPT_CT_RELEASE, NAPT_CT_CLEAN_START))
            return NAPT_TIMER_STEP_RESTART;

        ret = napt_metric_try_report(key, value, NAPT_METRIC_DELETE);

        if (value->is_static) return napt_ct_delete(key);

        struct napt_from_wan_value *mapping = napt_wan_lookup(key->proto, value->external_port);
        if (!mapping || mapping->kind != NAPT_MAPPING_DYNAMIC ||
            mapping->generation != value->from_wan_gen)
            return napt_ct_delete(key);

        if (napt_wan_close_last(mapping) == 0) {
            *next_timeout = NAPT_DELETE_RETRY_INTERVAL_NS;
            return NAPT_TIMER_STEP_RESTART;
        }

        if (napt_wan_ref_dec(mapping) == 0) return napt_ct_delete(key);

        return napt_ct_delete(key);
    }

    if (current == NAPT_CT_DELETE_EGRESS) {
        if (napt_lan_delete_dynamic(key->internal_addr, key->internal_port, key->proto,
                                    value->external_port, value->from_wan_gen) != 0)
            return napt_ct_restart(value, current, current, NAPT_DELETE_RETRY_INTERVAL_NS,
                                   next_timeout);

        return napt_ct_restart(value, current, NAPT_CT_DELETE_INGRESS,
                               NAPT_DELETE_RETRY_INTERVAL_NS, next_timeout);
    }

    if (current == NAPT_CT_DELETE_INGRESS) {
        struct napt_from_wan_value *mapping = napt_wan_lookup(key->proto, value->external_port);

        if (!mapping)
            return napt_ct_restart(value, current, NAPT_CT_PUSH_QUEUE, NAPT_QUEUE_RETRY_INTERVAL_NS,
                                   next_timeout);
        if (mapping->kind != NAPT_MAPPING_DYNAMIC || mapping->generation != value->from_wan_gen)
            return napt_ct_delete(key);

        napt_wan_clear(key->proto, value->external_port);
        return napt_ct_restart(value, current, NAPT_CT_PUSH_QUEUE, NAPT_QUEUE_RETRY_INTERVAL_NS,
                               next_timeout);
    }

    if (current == NAPT_CT_PUSH_QUEUE) {
        if (value->is_static) return napt_ct_delete(key);

        *queue_push_ret = force_queue_push_fail ? -1
                                                : napt_queue_push(key->proto, value->external_port,
                                                                  value->from_wan_gen + 1);
        if (*queue_push_ret == 0) return napt_ct_delete(key);

        return napt_ct_restart(value, current, current, NAPT_QUEUE_RETRY_INTERVAL_NS, next_timeout);
    }

    ret = napt_metric_try_report(key, value, NAPT_METRIC_ACTIVE);
    if (ret) {
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
        return NAPT_TIMER_STEP_RESTART;
    }

    if (current == NAPT_CT_ACTIVE) {
        next = NAPT_CT_IDLE_1;
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
    } else if (current == NAPT_CT_IDLE_1) {
        next = NAPT_CT_IDLE_2;
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
    } else if (current == NAPT_CT_IDLE_2) {
        next = NAPT_CT_RELEASE;
        *next_timeout = napt_ct_wait_ns(key, value);
    } else {
        next = NAPT_CT_IDLE_2;
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
    }

    if (!__sync_bool_compare_and_swap(&value->status, current, next)) {
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
        return NAPT_TIMER_STEP_RESTART;
    }

    return NAPT_TIMER_STEP_RESTART;
}

static int napt_ct_timer_cb(void *map, struct napt_ct_key *key, struct napt_ct_value *value) {
    (void)map;
    int queue_push_ret = -2;
    __u64 next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
    u32 action = napt_ct_timer_step(key, value, 0, &queue_push_ret, &next_timeout);

    if (action == NAPT_TIMER_STEP_RESTART) bpf_timer_start(&value->timer, next_timeout, 0);
    return 0;
}

static __always_inline int napt_ct_timer_init(struct napt_ct_value *value) {
    if (bpf_timer_init(&value->timer, &napt_ct, 0) != 0) return -1;
    if (bpf_timer_set_callback(&value->timer, napt_ct_timer_cb) != 0) return -1;
    return 0;
}

static __always_inline struct napt_ct_value *napt_ct_insert(const struct napt_ct_key *key,
                                                            const struct napt_ct_value *initial) {
    struct napt_ct_value *value;

    if (bpf_map_update_elem(&napt_ct, key, initial, BPF_NOEXIST) != 0) return 0;

    value = bpf_map_lookup_elem(&napt_ct, key);
    if (!value) return 0;

    if (napt_ct_timer_init(value) != 0 || !napt_ct_timer_start(value, NAPT_CT_REPORT_INTERVAL_NS)) {
        bpf_map_delete_elem(&napt_ct, key);
        return 0;
    }

    return value;
}

static __always_inline struct napt_ct_value *
napt_ct_create(u32 ifindex, u32 mark, const struct napt_ct_key *key, __be16 external_port, u32 gen,
               int is_static, u8 gress, struct napt_from_wan_value *mapping) {
    struct napt_ct_value initial = {};
    struct napt_ct_value *value;

    initial.external_port = external_port;
    initial.from_wan_gen = gen;
    initial.is_static = is_static ? 1 : 0;
    initial.status = is_static ? NAPT_CT_INIT : NAPT_CT_PENDING_REF;
    initial.client_status = NAPT_TCP_STATE_INIT;
    initial.server_status = NAPT_TCP_STATE_INIT;
    initial.create_time = bpf_ktime_get_tai_ns();
    initial.cpu_id = bpf_get_smp_processor_id();
    initial.ifindex = ifindex;
    initial.gress = gress;
    initial.flow_id = get_flow_id(mark);

    value = napt_ct_insert(key, &initial);
    if (!value) return 0;

    if (!is_static) {
        if (!mapping || napt_wan_ref_inc(mapping) != 0) {
            bpf_map_delete_elem(&napt_ct, key);
            return 0;
        }
        value->status = NAPT_CT_INIT;
    }

    return value;
}

static __always_inline int napt_ct_advance_pkt(u8 l4_protocol, u8 tcp_phase, u8 gress,
                                               struct napt_ct_value *value) {
    __u64 current_state;
    __u64 *modify_state;
    __u64 next_state;

    if (gress == NAPT_GRESS_WAN) {
        current_state = value->server_status;
        modify_state = &value->server_status;
    } else {
        current_state = value->client_status;
        modify_state = &value->client_status;
    }

    next_state = current_state;
    if (l4_protocol == IPV4_PROTO_TCP) {
        if (tcp_phase == NAPT_TCP_PHASE_SYN)
            next_state = NAPT_TCP_STATE_SYN;
        else if (tcp_phase == NAPT_TCP_PHASE_RST)
            next_state = NAPT_TCP_STATE_INIT;
        else if (tcp_phase == NAPT_TCP_PHASE_FIN)
            next_state = NAPT_TCP_STATE_FIN;
    } else {
        next_state = NAPT_TCP_STATE_LESS_EST;
    }

    if (next_state != current_state &&
        !__sync_bool_compare_and_swap(modify_state, current_state, next_state))
        return TC_ACT_SHOT;

    __u64 status = value->status;
    if (napt_ct_status_can_activate(status)) {
        __u64 prev = __sync_val_compare_and_swap(&value->status, status, NAPT_CT_ACTIVE);
        if (prev == status) napt_ct_timer_start(value, NAPT_CT_REPORT_INTERVAL_NS);
    }

    return TC_ACT_OK;
}

static __always_inline int napt_ct_advance(const struct tc_nat_view *view, u8 gress,
                                           struct napt_ct_value *value) {
    return napt_ct_advance_pkt(view->l4_protocol, view->tcp_phase, gress, value);
}

enum napt_ct_resolve_result {
    NAPT_CT_RESOLVE_MISS = 0,
    NAPT_CT_RESOLVE_OK = 1,
    NAPT_CT_RESOLVE_UNUSABLE = 2,
};

static __always_inline enum napt_ct_resolve_result
napt_ct_resolve_ingress(const struct napt_ct_key *key, struct napt_ct_value **value_out) {
    struct napt_ct_value *value = bpf_map_lookup_elem(&napt_ct, key);

    if (!value) return NAPT_CT_RESOLVE_MISS;
    if (!napt_ct_status_usable(value->status)) return NAPT_CT_RESOLVE_UNUSABLE;

    *value_out = value;
    return NAPT_CT_RESOLVE_OK;
}

static __always_inline int napt_ct_resolve(const struct napt_ct_key *key,
                                           const struct napt_from_wan_value *mapping,
                                           struct napt_ct_value **value_out) {
    struct napt_ct_value *value = bpf_map_lookup_elem(&napt_ct, key);

    if (!value) return -1;

    if (mapping && mapping->kind == NAPT_MAPPING_DYNAMIC &&
        value->from_wan_gen != mapping->generation) {
        bpf_map_delete_elem(&napt_ct, key);
        return -1;
    }
    if (!napt_ct_status_usable(value->status)) return -1;

    *value_out = value;
    return 0;
}

#endif /* LAND_NAT_NAT4_CT_TIMER_H */
