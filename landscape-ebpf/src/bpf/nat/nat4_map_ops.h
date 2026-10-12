#ifndef __LD_NAT4_MAP_OPS_H__
#define __LD_NAT4_MAP_OPS_H__

#include "nat/nat_common.h"
#include "nat/nat4_static.h"
#include "nat/nat4_dyn_map.h"

#define NAT4_STATE_SHIFT 56
#define NAT4_REF_MASK ((1ULL << NAT4_STATE_SHIFT) - 1)
#define NAT4_STATE_ACTIVE 1
#define NAT4_STATE_CLOSED 2
#define DELETE_RETRY_INTERVAL 100000000ULL
#define QUEUE_RETRY_INTERVAL 500000000ULL

volatile const u16 tcp_range_start = 32768;
volatile const u16 tcp_range_end = 65535;

volatile const u16 udp_range_start = 32768;
volatile const u16 udp_range_end = 65535;

volatile const u16 icmp_range_start = 32768;
volatile const u16 icmp_range_end = 65535;

static __always_inline u64 nat4_state_make(u8 state, u64 refcnt) {
    return ((u64)state << NAT4_STATE_SHIFT) | (refcnt & NAT4_REF_MASK);
}

static __always_inline u8 nat4_state_get(u64 state_ref) {
    return (u8)(state_ref >> NAT4_STATE_SHIFT);
}

static __always_inline u64 nat4_ref_get(u64 state_ref) { return state_ref & NAT4_REF_MASK; }

static __always_inline bool nat4_can_create_ct(const struct nat4_mapping_value_v3 *ingress) {
    u64 sr = ingress->state_ref;
    return ingress->is_allow_reuse && nat4_state_get(sr) == NAT4_STATE_ACTIVE &&
           nat4_ref_get(sr) > 0;
}

static __always_inline int nat4_state_try_inc(struct nat4_mapping_value_v3 *value) {
    u64 old = value->state_ref;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (nat4_state_get(old) != NAT4_STATE_ACTIVE) {
            return -1;
        }
        u64 ref = nat4_ref_get(old);
        if (ref == NAT4_REF_MASK) {
            return -1;
        }
        u64 new_val = nat4_state_make(NAT4_STATE_ACTIVE, ref + 1);
        u64 prev = __sync_val_compare_and_swap(&value->state_ref, old, new_val);
        if (prev == old) {
            return 0;
        }
        old = prev;
    }

    return -1;
}

static __always_inline int nat4_state_try_dec(struct nat4_mapping_value_v3 *value) {
    u64 old = value->state_ref;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (nat4_state_get(old) != NAT4_STATE_ACTIVE) {
            return -1;
        }
        u64 ref = nat4_ref_get(old);
        if (ref <= 1) {
            return -1;
        }
        u64 new_val = nat4_state_make(NAT4_STATE_ACTIVE, ref - 1);
        u64 prev = __sync_val_compare_and_swap(&value->state_ref, old, new_val);
        if (prev == old) {
            return 0;
        }
        old = prev;
    }

    return -1;
}

static __always_inline int nat4_state_try_close_last(struct nat4_mapping_value_v3 *value) {
    u64 old = nat4_state_make(NAT4_STATE_ACTIVE, 1);
    u64 new_val = nat4_state_make(NAT4_STATE_CLOSED, 1);
    u64 prev = __sync_val_compare_and_swap(&value->state_ref, old, new_val);
    return prev == old ? 0 : -1;
}

static __always_inline void *nat4_free_port_queue(u8 l4proto) {
    if (l4proto == IPPROTO_TCP) {
        return &nat4_tcp_port_queue;
    }
    if (l4proto == IPPROTO_UDP) {
        return &nat4_udp_port_queue;
    }
    return &nat4_icmp_port_queue;
}

static __always_inline int nat4_queue_pop(u8 l4proto, struct nat4_port_queue_value_v3 *value) {
    void *queue = nat4_free_port_queue(l4proto);
    return bpf_map_pop_elem(queue, value);
}

static __always_inline int nat4_queue_push(u8 l4proto,
                                           const struct nat4_port_queue_value_v3 *value) {
    void *queue = nat4_free_port_queue(l4proto);
    return bpf_map_push_elem(queue, value, BPF_EXIST);
}

static __always_inline struct nat4_static_value *nat4_lookup_static_ingress(u8 l4proto,
                                                                            __be16 from_port) {
    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = l4proto,
        .from_addr = 0,
        .from_port = from_port,
    };
    return bpf_map_lookup_elem(&nat4_static_map, &ingress_key);
}

static __always_inline bool nat4_static_port_reserved(u8 l4proto, __be16 nat_port) {
    return nat4_lookup_static_ingress(l4proto, nat_port) != NULL;
}

struct nat4_alloc_ctx_v3 {
    u8 l4proto;
    struct nat4_port_queue_value_v3 value;
    bool found;
};

static int nat4_alloc_port_callback(u32 index, struct nat4_alloc_ctx_v3 *ctx) {
    if (nat4_queue_pop(ctx->l4proto, &ctx->value) != 0) {
        return BPF_LOOP_RET_BREAK;
    }
    if (!nat4_static_port_reserved(ctx->l4proto, ctx->value.port)) {
        ctx->found = true;
        return BPF_LOOP_RET_BREAK;
    }
    (void)nat4_queue_push(ctx->l4proto, &ctx->value);
    return BPF_LOOP_RET_CONTINUE;
}

static __always_inline int nat4_alloc_port(u8 l4proto, struct nat4_port_queue_value_v3 *out) {
    struct nat4_alloc_ctx_v3 ctx = {
        .l4proto = l4proto,
    };
    int ret = bpf_loop(NAT4_PORT_QUEUE_SIZE, nat4_alloc_port_callback, &ctx, 0);
    if (ret < 0 || !ctx.found) {
        return -1;
    }
    *out = ctx.value;
    return 0;
}

static __always_inline struct nat4_egress_mapping_value_v3 *
nat4_insert_mappings(const struct nat4_mapping_key *key,
                     const struct nat4_egress_mapping_value_v3 *val, u16 generation,
                     struct nat4_mapping_value_v3 **lk_val_rev) {
    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = key->l4proto,
        .from_addr = val->addr,
        .from_port = val->port,
    };

    struct nat4_mapping_value_v3 ingress_val = {
        .state_ref = nat4_state_make(NAT4_STATE_ACTIVE, 0),
        .addr = key->from_addr,
        .trigger_addr = val->trigger_addr,
        .port = key->from_port,
        .trigger_port = val->trigger_port,
        .generation = generation,
        ._pad = 0,
        .is_allow_reuse = val->is_allow_reuse,
    };

    if (bpf_map_update_elem(&nat4_egress_dyn_map, key, val, BPF_NOEXIST) != 0) {
        return NULL;
    }
    if (bpf_map_update_elem(&nat4_ingress_dyn_map, &ingress_key, &ingress_val, BPF_NOEXIST) != 0) {
        bpf_map_delete_elem(&nat4_egress_dyn_map, key);
        return NULL;
    }

    if (lk_val_rev) {
        *lk_val_rev = bpf_map_lookup_elem(&nat4_ingress_dyn_map, &ingress_key);
        if (!*lk_val_rev) {
            bpf_map_delete_elem(&nat4_egress_dyn_map, key);
            bpf_map_delete_elem(&nat4_ingress_dyn_map, &ingress_key);
            return NULL;
        }
    }

    struct nat4_egress_mapping_value_v3 *egress_out =
        bpf_map_lookup_elem(&nat4_egress_dyn_map, key);
    if (!egress_out) {
        bpf_map_delete_elem(&nat4_egress_dyn_map, key);
        bpf_map_delete_elem(&nat4_ingress_dyn_map, &ingress_key);
        return NULL;
    }

    return egress_out;
}

static __always_inline struct nat4_mapping_value_v3 *
nat4_lookup_ingress_dynamic(u8 l4proto, __be32 nat_addr, __be16 nat_port) {
    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = l4proto,
        .from_addr = nat_addr,
        .from_port = nat_port,
    };

    return bpf_map_lookup_elem(&nat4_ingress_dyn_map, &ingress_key);
}

static __always_inline struct nat4_egress_mapping_value_v3 *
nat4_lookup_egress_dynamic(u8 l4proto, __be32 client_addr, __be16 client_port) {
    struct nat4_mapping_key egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = l4proto,
        .from_addr = client_addr,
        .from_port = client_port,
    };

    return bpf_map_lookup_elem(&nat4_egress_dyn_map, &egress_key);
}

static __always_inline void nat4_delete_mapping_pair(u8 l4proto, __be32 nat_addr, __be16 nat_port,
                                                     __be32 client_addr, __be16 client_port) {
    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = l4proto,
        .from_addr = nat_addr,
        .from_port = nat_port,
    };
    struct nat4_mapping_key egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = l4proto,
        .from_addr = client_addr,
        .from_port = client_port,
    };

    bpf_map_delete_elem(&nat4_ingress_dyn_map, &ingress_key);
    bpf_map_delete_elem(&nat4_egress_dyn_map, &egress_key);
}

#endif /* __LD_NAT4_MAP_OPS_H__ */
