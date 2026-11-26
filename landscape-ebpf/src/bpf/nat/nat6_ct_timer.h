#ifndef __LD_NAT6_CT_TIMER_H__
#define __LD_NAT6_CT_TIMER_H__

#include "base/printk.h"
#include "base/tcp_phase.h"
#include "nat/nat_common.h"
#include "nat/nat_metric.h"
#include "nat/nat6_dyn_map.h"
#include "nat/nat6_map_ops.h"

#define NAT6_TCP_CLOSE_TIMEOUT_NS (6ULL * 1000000000ULL)
#define NAT6_DELETE_REPORT_MAX_ATTEMPTS 3U
#define NAT6_DELETE_REPORT_RETRY_NS (10ULL * 1000 * 1000)

static __always_inline int nat6_metric_try_report(struct nat6_timer_key *timer_key,
                                                  struct nat6_timer_value *timer_value, u8 status) {
    struct nat_conn_metric_event *event;
    event = bpf_ringbuf_reserve(&nat_metric_events, sizeof(struct nat_conn_metric_event), 0);
    if (event == NULL) {
        return -1;
    }

    __builtin_memcpy(event->src_addr.in6_u.u6_addr8, &timer_value->client_prefix, 8);
    __builtin_memcpy(event->src_addr.in6_u.u6_addr8 + 8, timer_key->local.client_suffix, 8);
    COPY_ADDR_FROM(event->dst_addr.in6_u.u6_addr8, timer_key->remote_addr.in6_u.u6_addr8);

    event->src_port = timer_key->local.client_port;
    event->dst_port = timer_key->remote_port;

    event->l4_proto = timer_key->local.l4_protocol;
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

static __always_inline bool nat6_timer_step(struct nat6_timer_key *key,
                                            struct nat6_timer_value *value, u64 *next_timeout) {
    u64 current_status = value->status;
    u64 next_status = current_status;
    *next_timeout = REPORT_INTERVAL;

    if (key->remote_port == TEST_PORT) {
        ld_timer_log("timer_clean_callback: %pI6, current_status: %llu",
                     &key->remote_addr.in6_u.u6_addr8, current_status);
    }

    if (current_status == TIMER_WAIT_TIMEOUT || current_status == TIMER_WAIT_TCP_CLOSE) {
        /* A short wakeup from a previous wait can fire during this one. */
        u64 now = bpf_ktime_get_ns();
        if (now < value->wait_deadline_ns) {
            *next_timeout = value->wait_deadline_ns - now;
            return true;
        }
        if (!ct_try_set_status(&value->status, current_status, TIMER_CLEAN_START)) return true;
        /* Only the callback that claims cleanup owns the mapping reference. */
        if (!value->is_static) {
            struct nat6_mapping_value *mapping =
                bpf_map_lookup_elem(&nat6_mapping_map, &key->local);
            if (mapping) nat6_mapping_put(&key->local, mapping);
        }
        if (key->remote_port == TEST_PORT) {
            ld_timer_log("release CONNECT");
        }
        current_status = TIMER_CLEAN_START;
    }

    if (current_status == TIMER_CLEAN_START) {
        u8 failures = value->delete_report_failures;
        if (nat6_metric_try_report(key, value, NAT_CONN_DELETE) != 0 &&
            failures < NAT6_DELETE_REPORT_MAX_ATTEMPTS - 1) {
            value->delete_report_failures = failures + 1;
            *next_timeout = NAT6_DELETE_REPORT_RETRY_NS << failures;
            return true;
        }
        bpf_map_delete_elem(&nat6_timer_map, key);
        return false;
    }

    /* The next successful sample includes counters from skipped ACTIVE reports. */
    nat6_metric_try_report(key, value, NAT_CONN_ACTIVE);

    u64 flags = value->tcp_flags;
    if (key->local.l4_protocol == IPPROTO_TCP && (flags & NAPT_TCP_BOTH_FIN) == NAPT_TCP_BOTH_FIN) {
        next_status = TIMER_WAIT_TCP_CLOSE;
        *next_timeout = NAT6_TCP_CLOSE_TIMEOUT_NS;
    } else if (current_status == TIMER_ACTIVE) {
        next_status = TIMER_IDLE_CHECK_1;

        if (key->remote_port == TEST_PORT) {
            ld_timer_log("change next status TIMER_IDLE_CHECK_1");
        }
    } else if (current_status == TIMER_IDLE_CHECK_1) {
        next_status = TIMER_IDLE_CHECK_2;

        if (key->remote_port == TEST_PORT) {
            ld_timer_log("change next status TIMER_IDLE_CHECK_2");
        }
    } else if (current_status == TIMER_IDLE_CHECK_2) {
        next_status = TIMER_WAIT_TIMEOUT;
        if (key->local.l4_protocol == IPPROTO_TCP) {
            if ((flags & NAPT_TCP_BOTH_SYN) == NAPT_TCP_BOTH_SYN) {
                *next_timeout = TCP_TIMEOUT;
            } else {
                *next_timeout = TCP_SYN_TIMEOUT;
            }
        } else {
            *next_timeout = UDP_TIMEOUT;
        }

        if (key->remote_port == TEST_PORT) {
            u64 show = *next_timeout / 1000000000ULL;
            ld_timer_log("change next status TIMER_WAIT_TIMEOUT, next_timeout: %d", show);
        }
    } else {
        next_status = TIMER_IDLE_CHECK_2;
    }

    if (__sync_val_compare_and_swap(&value->status, current_status, next_status) !=
        current_status) {
        ld_timer_log("call back modify status fail, current status: %d new status: %d",
                     current_status, next_status);
        *next_timeout = REPORT_INTERVAL;
    } else if (next_status == TIMER_WAIT_TIMEOUT || next_status == TIMER_WAIT_TCP_CLOSE) {
        value->wait_deadline_ns = bpf_ktime_get_ns() + *next_timeout;
    }
    return true;
}

static __always_inline void nat6_timer_rearm(struct nat6_timer_value *value, u64 delay) {
    bpf_timer_start(&value->timer, delay, 0);
    /* A packet may have armed the short tick after the callback selected a long delay. */
    if (delay > REPORT_INTERVAL && value->status == TIMER_ACTIVE)
        bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
}

static int nat6_timer_clean_callback(void *map, struct nat6_timer_key *key,
                                     struct nat6_timer_value *value) {
    u64 next_timeout;
    if (nat6_timer_step(key, value, &next_timeout)) nat6_timer_rearm(value, next_timeout);
    return 0;
}

static __always_inline struct nat6_timer_value *nat6_insert_timer(const struct nat6_timer_key *key,
                                                                  struct nat6_timer_value *val) {
    int ret = bpf_map_update_elem(&nat6_timer_map, key, val, BPF_NOEXIST);
    if (ret) {
        ld_log("ct6 timer map insert failed: %d", ret);
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
    value->status = TIMER_CLEAN_START;
    ld_log("ct6 timer setup failed: %d", ret);
    bpf_map_delete_elem(&nat6_timer_map, key);
    return NULL;
}

static __always_inline bool nat6_allows_create_pkt(u8 l4_protocol, u8 tcp_phase, bool icmp_error) {
    if (icmp_error) return false;
    if (l4_protocol == NEXTHDR_TCP) return napt_tcp_phase_is_syn(tcp_phase);
    return l4_protocol == NEXTHDR_UDP || l4_protocol == NEXTHDR_ICMP;
}

static __always_inline int nat6_ct_advance_pkt(u8 l4_protocol, u8 tcp_phase, u8 gress,
                                               struct nat6_timer_value *ct_timer_value) {
    if (l4_protocol == NEXTHDR_TCP) {
        u64 status = ct_timer_value->status;
        if (status == TIMER_ACTIVE && tcp_phase == NAPT_TCP_PHASE_ESTABLISHED) return NAT_OP_OK;
        if (unlikely(status >= TIMER_WAIT_TCP_CLOSE)) {
            if (status == TIMER_WAIT_TCP_CLOSE && !napt_tcp_phase_is_syn(tcp_phase))
                return NAT_OP_OK;
            return NAT_OP_ERR;
        }
        if (!napt_tcp_track_flags(&ct_timer_value->tcp_flags, tcp_phase,
                                  gress == NAT_MAPPING_INGRESS))
            return NAT_OP_ERR;
    }

    u64 current_status = ct_timer_value->status;
    /* A competing tick can advance either short check, then enter WAIT_TIMEOUT. */
    for (int i = 0; i < 3 && ct_status_can_activate(current_status); i++) {
        u64 observed =
            __sync_val_compare_and_swap(&ct_timer_value->status, current_status, TIMER_ACTIVE);
        if (observed == current_status) {
            if (current_status == TIMER_WAIT_TIMEOUT)
                bpf_timer_start(&ct_timer_value->timer, REPORT_INTERVAL, 0);
            break;
        }
        current_status = observed;
    }

    /* A packet trying to wake a wait may have lost its CAS to cleanup. */
    return current_status >= TIMER_CLEAN_START ? NAT_OP_ERR : NAT_OP_OK;
}

#endif /* __LD_NAT6_CT_TIMER_H__ */
