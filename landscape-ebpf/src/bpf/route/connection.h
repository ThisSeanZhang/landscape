#ifndef __LD_ROUTE_CONNECTION_H__
#define __LD_ROUTE_CONNECTION_H__
#include "route/route4_slot.h"
#include "route/route6_slot.h"
#include "route/route4_context.h"
#include "route/route6_context.h"
struct route_conn_key {
    struct in6_addr local_addr;
    struct in6_addr remote_addr;
    __be16 local_port;
    __be16 remote_port;
    u8 protocol;
    u8 ipv6;
    u8 pad[2];
};
struct route_policy_key {
    u32 flow_id;
    u32 ipv6;
};
struct route_conn_value {
    u64 generation;
    u64 seen_ns;
    u32 flow_id;
    __be32 tcp_syn_seq;
    union {
        struct route4_target_info v4;
        struct route6_target_info v6;
    } target;
};
_Static_assert(sizeof(struct route_conn_key) == 40, "route conn key ABI");
_Static_assert(sizeof(struct route_conn_value) == 56, "route conn value ABI");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_policy_key);
    __type(value, u64);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_conn_policy SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct route_conn_key);
    __type(value, struct route_conn_value);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_connections SEC(".maps");
static __always_inline u64 *route_policy(u32 flow_id, bool ipv6) {
    struct route_policy_key key = {.flow_id = flow_id, .ipv6 = ipv6};
    return bpf_map_lookup_elem(&rt_conn_policy, &key);
}
static __always_inline void route4_connection_key(const struct route4_context *c,
                                                  struct route_conn_key *k, bool reverse) {
    k->local_addr.in6_u.u6_addr32[0] = reverse ? c->daddr : c->saddr;
    k->remote_addr.in6_u.u6_addr32[0] = reverse ? c->saddr : c->daddr;
    k->local_port = reverse ? c->dst_port : c->src_port;
    k->remote_port = reverse ? c->src_port : c->dst_port;
    k->protocol = c->l4_protocol;
}
static __always_inline void route6_connection_key(const struct route6_context *c,
                                                  struct route_conn_key *k, bool reverse) {
    k->local_addr = reverse ? c->daddr : c->saddr;
    k->remote_addr = reverse ? c->saddr : c->daddr;
    k->local_port = reverse ? c->dst_port : c->src_port;
    k->remote_port = reverse ? c->src_port : c->dst_port;
    k->protocol = c->l4_protocol;
    k->ipv6 = 1;
}
// TCP/UDP are keyed by all five tuple members. Other protocols retain the
// ordinary slot path (including fragmented packets without transport ports).
static __always_inline bool route_conn_supported(u8 protocol) {
    return protocol == 6 || protocol == 17;
}
static __always_inline struct route_conn_value *route_connection(const struct route_conn_key *key,
                                                                 u32 flow_id, u64 generation) {
    struct route_conn_value *v = bpf_map_lookup_elem(&rt_connections, key);
    u64 now = bpf_ktime_get_ns();
    u64 idle = key->protocol == 6 ? 7200000000000ULL : 120000000000ULL;
    if (v && v->flow_id == flow_id && v->generation == generation && now - v->seen_ns < idle) {
        v->seen_ns = now;
        return v;
    }
    return NULL;
}
static __always_inline struct route4_target_info *
route4_select_connection(const struct route4_context *c, const struct route4_slot_key *slot) {
    u64 *generation = route_policy(slot->flow_id, false);
    if (!generation || !route_conn_supported(c->l4_protocol))
        return bpf_map_lookup_elem(&rt4_slot_map, slot);
    struct route_conn_key key = {};
    route4_connection_key(c, &key, false);
    struct route_conn_value *v = route_connection(&key, slot->flow_id, *generation);
    if (v && (!c->tcp_syn || c->tcp_syn_seq == v->tcp_syn_seq)) return &v->target.v4;
    struct route4_target_info *target = bpf_map_lookup_elem(&rt4_slot_map, slot);
    if (!target) return NULL;
    struct route_conn_value fresh = {.generation = *generation,
                                     .seen_ns = bpf_ktime_get_ns(),
                                     .flow_id = slot->flow_id,
                                     .tcp_syn_seq = c->tcp_syn_seq};
    fresh.target.v4 = *target;
    bpf_map_update_elem(&rt_connections, &key, &fresh, BPF_ANY);
    return target;
}
static __always_inline struct route6_target_info *
route6_select_connection(const struct route6_context *c, const struct route6_slot_key *slot) {
    u64 *generation = route_policy(slot->flow_id, true);
    if (!generation || !route_conn_supported(c->l4_protocol))
        return bpf_map_lookup_elem(&rt6_slot_map, slot);
    struct route_conn_key key = {};
    route6_connection_key(c, &key, false);
    struct route_conn_value *v = route_connection(&key, slot->flow_id, *generation);
    if (v && (!c->tcp_syn || c->tcp_syn_seq == v->tcp_syn_seq)) return &v->target.v6;
    struct route6_target_info *target = bpf_map_lookup_elem(&rt6_slot_map, slot);
    if (!target) return NULL;
    struct route_conn_value fresh = {.generation = *generation,
                                     .seen_ns = bpf_ktime_get_ns(),
                                     .flow_id = slot->flow_id,
                                     .tcp_syn_seq = c->tcp_syn_seq};
    fresh.target.v6 = *target;
    bpf_map_update_elem(&rt_connections, &key, &fresh, BPF_ANY);
    return target;
}
#endif
