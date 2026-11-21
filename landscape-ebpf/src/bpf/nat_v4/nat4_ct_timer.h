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
#define NAPT_CT_REPORT_INTERVAL_NS NAPT_NSEC_PER_SEC
#define NAPT_TCP_SYN_TIMEOUT_NS (6ULL * NAPT_NSEC_PER_SEC)
#define NAPT_TCP_CLOSE_TIMEOUT_NS (6ULL * NAPT_NSEC_PER_SEC)
#define NAPT_TCP_TIMEOUT_NS (10ULL * 60ULL * NAPT_NSEC_PER_SEC)
#define NAPT_UDP_TIMEOUT_NS (5ULL * 60ULL * NAPT_NSEC_PER_SEC)
#define NAPT_CLEAN_STEP_NS 1000U
#define NAPT_CLEAN_RETRY_MAX_NS (100U * 1000U * 1000U)
#define NAPT_DELETE_REPORT_MAX_ATTEMPTS 3U
#define NAPT_DELETE_REPORT_RETRY_NS (10ULL * 1000ULL * 1000ULL)

enum napt_ct_status {
    NAPT_CT_READY = 0ULL,
    NAPT_CT_ACQUIRE_REF = 10ULL,
    NAPT_CT_ACTIVE = 20ULL,
    NAPT_CT_IDLE_CHECK_1 = 30ULL,
    NAPT_CT_IDLE_CHECK_2 = 31ULL,
    /* A packet for this CT can reactivate it while the protocol timeout is running. */
    NAPT_CT_WAIT_TIMEOUT = 40ULL,
    NAPT_CT_WAIT_TCP_CLOSE = 41ULL,
    /* Cleanup owns the CT from this point on. */
    NAPT_CT_CLEAN_START = 49ULL,
    NAPT_CT_RELEASE_REF = NAPT_CT_CLEAN_START,
    NAPT_CT_DELETE_LAN_MAPPING = 50ULL,
    NAPT_CT_CLEAR_WAN_SLOT = 51ULL,
    NAPT_CT_RETURN_PORT = 52ULL,
    NAPT_CT_RETRY_DELETE_REPORT = 53ULL,
};

enum napt_tcp_flags {
    NAPT_TCP_LAN_SYN = 1U << 0,
    NAPT_TCP_WAN_SYN = 1U << 1,
    NAPT_TCP_LAN_FIN = 1U << 2,
    NAPT_TCP_WAN_FIN = 1U << 3,
    NAPT_TCP_RST_SEEN = 1U << 4,
    NAPT_TCP_BOTH_SYN = NAPT_TCP_LAN_SYN | NAPT_TCP_WAN_SYN,
    NAPT_TCP_BOTH_FIN = NAPT_TCP_LAN_FIN | NAPT_TCP_WAN_FIN,
};

#define NAPT_TIMER_STEP_DELETE_CT 1U
#define NAPT_TIMER_STEP_RESTART 2U

static __always_inline int napt_ct_status_usable(__u64 status) {
    return status != NAPT_CT_ACQUIRE_REF && status < NAPT_CT_CLEAN_START;
}

static __always_inline int napt_ct_status_can_activate(__u64 status) {
    return status < NAPT_CT_WAIT_TCP_CLOSE && status != NAPT_CT_ACQUIRE_REF &&
           status != NAPT_CT_ACTIVE;
}

static __always_inline int napt_ct_timer_start(struct napt_ct_value *value, __u64 ns) {
    long ret = bpf_timer_start(&value->timer, ns, 0);
    /* A packet may have woken a long idle wait between the timer's CAS and its rearm. */
    if (ns > NAPT_CT_REPORT_INTERVAL_NS && value->status == NAPT_CT_ACTIVE)
        ret = bpf_timer_start(&value->timer, NAPT_CT_REPORT_INTERVAL_NS, 0);
    return ret == 0;
}

static __always_inline u32 napt_ct_delete(struct napt_ct_key *key) {
    bpf_map_delete_elem(&napt_ct, key);
    return NAPT_TIMER_STEP_DELETE_CT;
}

/* All NAT resources owned by this CT have been released before report retries begin. */
static __always_inline u32 napt_ct_delete_or_retry_report(struct napt_ct_key *key,
                                                          struct napt_ct_value *value,
                                                          __u64 *next_timeout) {
    __u32 failures = value->delete_report_failures;
    if (failures == 0 || failures >= NAPT_DELETE_REPORT_MAX_ATTEMPTS) return napt_ct_delete(key);

    value->status = NAPT_CT_RETRY_DELETE_REPORT;
    *next_timeout = NAPT_DELETE_REPORT_RETRY_NS << (failures - 1);
    return NAPT_TIMER_STEP_RESTART;
}

static __always_inline u32 napt_cleanup_retry(struct napt_ct_value *value, __u64 *next_timeout) {
    __u32 delay = value->cleanup_retry_ns ? value->cleanup_retry_ns : NAPT_CLEAN_STEP_NS;
    *next_timeout = delay;
    value->cleanup_retry_ns =
        delay >= NAPT_CLEAN_RETRY_MAX_NS / 2 ? NAPT_CLEAN_RETRY_MAX_NS : delay * 2;
    return NAPT_TIMER_STEP_RESTART;
}

/* Only the timer advances a CT after it has claimed the last reference. */
static __always_inline u32 napt_cleanup_next(struct napt_ct_value *value, __u64 next,
                                             __u64 *next_timeout) {
    value->status = next;
    value->cleanup_retry_ns = 0;
    *next_timeout = NAPT_CLEAN_STEP_NS;
    return NAPT_TIMER_STEP_RESTART;
}

static __always_inline u32 napt_ct_release_ref(struct napt_ct_key *key, struct napt_ct_value *value,
                                               struct napt_from_wan_value *mapping, __u64 observed,
                                               __u64 *next_timeout) {
    __u64 refs = napt_state_refs(observed);
    if (napt_state_get(observed) != NAPT_WAN_STATE_ACTIVE || refs == 0)
        return napt_ct_delete_or_retry_report(key, value, next_timeout);

    /* Dropping the last reference also claims ownership of port cleanup. */
    __u64 next = refs == 1 ? napt_state_make(NAPT_WAN_STATE_CLOSED, 0) : observed - 1;
    if (!__sync_bool_compare_and_swap(&mapping->state_ref, observed, next))
        return napt_cleanup_retry(value, next_timeout);

    if (refs == 1) return napt_cleanup_next(value, NAPT_CT_DELETE_LAN_MAPPING, next_timeout);
    return napt_ct_delete_or_retry_report(key, value, next_timeout);
}

static __always_inline __u64 napt_ct_wait_ns(const struct napt_ct_key *key,
                                             const struct napt_ct_value *value) {
    if (key->proto != IPV4_PROTO_TCP) return NAPT_UDP_TIMEOUT_NS;

    if ((value->tcp_flags & NAPT_TCP_BOTH_SYN) == NAPT_TCP_BOTH_SYN) return NAPT_TCP_TIMEOUT_NS;
    return NAPT_TCP_SYN_TIMEOUT_NS;
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

    *queue_push_ret = -2;
    *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;

    if (current == NAPT_CT_ACQUIRE_REF) return napt_ct_delete(key);

    if (current == NAPT_CT_WAIT_TIMEOUT || current == NAPT_CT_WAIT_TCP_CLOSE) {
        /* A packet waking an earlier idle wait can leave a one-second timer pending. */
        __u64 now = bpf_ktime_get_ns();
        if (now < value->wait_deadline_ns) {
            *next_timeout = value->wait_deadline_ns - now;
            return NAPT_TIMER_STEP_RESTART;
        }
        if (!__sync_bool_compare_and_swap(&value->status, current, NAPT_CT_RELEASE_REF))
            return NAPT_TIMER_STEP_RESTART;

        value->delete_report_failures = napt_metric_try_report(key, value, NAPT_METRIC_DELETE) != 0;
        current = NAPT_CT_RELEASE_REF;
    }

    if (current == NAPT_CT_RELEASE_REF) {
        if (value->is_static) return napt_ct_delete_or_retry_report(key, value, next_timeout);

        struct napt_from_wan_value *mapping = napt_wan_lookup(key->proto, value->external_port);
        if (!mapping || mapping->kind != NAPT_MAPPING_DYNAMIC ||
            mapping->generation != value->from_wan_gen)
            return napt_ct_delete_or_retry_report(key, value, next_timeout);

        return napt_ct_release_ref(key, value, mapping, mapping->state_ref, next_timeout);
    }

    if (current == NAPT_CT_DELETE_LAN_MAPPING) {
        if (napt_lan_delete_dynamic(key->internal_addr, key->internal_port, key->proto,
                                    value->external_port, value->from_wan_gen) != 0)
            return napt_cleanup_retry(value, next_timeout);

        return napt_cleanup_next(value, NAPT_CT_CLEAR_WAN_SLOT, next_timeout);
    }

    if (current == NAPT_CT_CLEAR_WAN_SLOT) {
        struct napt_from_wan_value *mapping = napt_wan_lookup(key->proto, value->external_port);

        if (!mapping) return napt_cleanup_next(value, NAPT_CT_RETURN_PORT, next_timeout);
        if (mapping->kind != NAPT_MAPPING_DYNAMIC || mapping->generation != value->from_wan_gen)
            return napt_ct_delete_or_retry_report(key, value, next_timeout);

        if (napt_wan_clear(key->proto, value->external_port) != 0)
            return napt_cleanup_retry(value, next_timeout);
        return napt_cleanup_next(value, NAPT_CT_RETURN_PORT, next_timeout);
    }

    if (current == NAPT_CT_RETURN_PORT) {
        if (value->is_static) return napt_ct_delete_or_retry_report(key, value, next_timeout);

        *queue_push_ret = force_queue_push_fail ? -1
                                                : napt_queue_push(key->proto, value->external_port,
                                                                  value->from_wan_gen + 1);
        if (*queue_push_ret == 0) return napt_ct_delete_or_retry_report(key, value, next_timeout);

        return napt_cleanup_retry(value, next_timeout);
    }

    if (current == NAPT_CT_RETRY_DELETE_REPORT) {
        if (napt_metric_try_report(key, value, NAPT_METRIC_DELETE) == 0) return napt_ct_delete(key);
        value->delete_report_failures++;
        return napt_ct_delete_or_retry_report(key, value, next_timeout);
    }

    /* Reports carry cumulative counters, so a full metric ring can skip this sample. */
    napt_metric_try_report(key, value, NAPT_METRIC_ACTIVE);

    if (key->proto == IPV4_PROTO_TCP &&
        (value->tcp_flags & NAPT_TCP_BOTH_FIN) == NAPT_TCP_BOTH_FIN) {
        next = NAPT_CT_WAIT_TCP_CLOSE;
        *next_timeout = NAPT_TCP_CLOSE_TIMEOUT_NS;
    } else if (current == NAPT_CT_ACTIVE) {
        next = NAPT_CT_IDLE_CHECK_1;
    } else if (current == NAPT_CT_IDLE_CHECK_1) {
        next = NAPT_CT_IDLE_CHECK_2;
    } else if (current == NAPT_CT_IDLE_CHECK_2) {
        next = NAPT_CT_WAIT_TIMEOUT;
        *next_timeout = napt_ct_wait_ns(key, value);
    } else {
        next = NAPT_CT_IDLE_CHECK_2;
    }

    if (!__sync_bool_compare_and_swap(&value->status, current, next)) {
        *next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
    } else if (next == NAPT_CT_WAIT_TIMEOUT || next == NAPT_CT_WAIT_TCP_CLOSE) {
        value->wait_deadline_ns = bpf_ktime_get_ns() + *next_timeout;
    }

    return NAPT_TIMER_STEP_RESTART;
}

static int napt_ct_timer_cb(void *map, struct napt_ct_key *key, struct napt_ct_value *value) {
    (void)map;
    int queue_push_ret = -2;
    __u64 next_timeout = NAPT_CT_REPORT_INTERVAL_NS;
    u32 action = napt_ct_timer_step(key, value, 0, &queue_push_ret, &next_timeout);

    if (action == NAPT_TIMER_STEP_RESTART) napt_ct_timer_start(value, next_timeout);
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
    initial.status = is_static ? NAPT_CT_READY : NAPT_CT_ACQUIRE_REF;
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
        value->status = NAPT_CT_READY;
    }

    return value;
}

static __always_inline int napt_ct_advance_pkt(u8 l4_protocol, u8 tcp_phase, u8 gress,
                                               struct napt_ct_value *value) {
    if (l4_protocol == IPV4_PROTO_TCP) {
        __u64 status = value->status;
        if (status == NAPT_CT_ACTIVE && tcp_phase == NAPT_TCP_PHASE_ESTABLISHED) return TC_ACT_OK;
        if (!napt_ct_status_usable(status)) return TC_ACT_SHOT;
        if (status == NAPT_CT_WAIT_TCP_CLOSE)
            return napt_tcp_phase_is_syn(tcp_phase) ? TC_ACT_SHOT : TC_ACT_OK;

        __u64 seen = value->tcp_flags;
        __u64 flag = 0;
        if (napt_tcp_phase_is_syn(tcp_phase)) {
            if ((seen & NAPT_TCP_BOTH_FIN) == NAPT_TCP_BOTH_FIN) return TC_ACT_SHOT;
            flag = gress == NAPT_GRESS_WAN ? NAPT_TCP_WAN_SYN : NAPT_TCP_LAN_SYN;
        } else if (tcp_phase == NAPT_TCP_PHASE_FIN) {
            flag = gress == NAPT_GRESS_WAN ? NAPT_TCP_WAN_FIN : NAPT_TCP_LAN_FIN;
        } else if (tcp_phase == NAPT_TCP_PHASE_RST) {
            flag = NAPT_TCP_RST_SEEN;
        }
        if (tcp_phase == NAPT_TCP_PHASE_SYN && (seen & NAPT_TCP_RST_SEEN)) {
            /* A fresh SYN after RST reuses the mapping with a new handshake. */
            if (!__sync_bool_compare_and_swap(&value->tcp_flags, seen, flag)) return TC_ACT_SHOT;
        } else if (flag && !(seen & flag)) {
            __sync_fetch_and_or(&value->tcp_flags, flag);
        }
    }

    __u64 status = value->status;
    if (!napt_ct_status_can_activate(status)) return TC_ACT_OK;

    if (status != NAPT_CT_WAIT_TIMEOUT) {
        /* These states already have a one-second tick unless the timer just entered a long wait. */
        __u64 prev = __sync_val_compare_and_swap(&value->status, status, NAPT_CT_ACTIVE);
        if (prev != NAPT_CT_WAIT_TIMEOUT) return TC_ACT_OK;
    }
    if (__sync_bool_compare_and_swap(&value->status, NAPT_CT_WAIT_TIMEOUT, NAPT_CT_ACTIVE))
        napt_ct_timer_start(value, NAPT_CT_REPORT_INTERVAL_NS);
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

    /* The timer owns the CT through port cleanup and any pending DELETE report. */
    if (!value || !napt_ct_status_usable(value->status)) return -1;

    if (mapping && mapping->kind == NAPT_MAPPING_DYNAMIC &&
        value->from_wan_gen != mapping->generation) {
        bpf_map_delete_elem(&napt_ct, key);
        return -1;
    }

    *value_out = value;
    return 0;
}

#endif /* LAND_NAT_NAT4_CT_TIMER_H */
