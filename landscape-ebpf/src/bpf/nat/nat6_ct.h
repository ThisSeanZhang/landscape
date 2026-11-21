#ifndef __LD_NAT6_CT_H__
#define __LD_NAT6_CT_H__

#include "base/mark.h"
#include "nat/nat6_ct_timer.h"
#include "nat/nat_rodata6.h"

struct nat6_translation {
    __be64 client_prefix;
    bool replace;
    bool is_static;
};

/* Reserve a reference before publishing the CT. A new mapping already owns its first reference. */
static __always_inline struct nat6_mapping_value *
nat6_mapping_get(const struct nat6_timer_key *key, __be64 prefix, bool egress, bool allow_reuse) {
    struct nat6_mapping_value *mapping = bpf_map_lookup_elem(&nat6_mapping_map, &key->local);
    if (!mapping) {
        if (!egress) return NULL;
        struct nat6_mapping_value initial = {
            .refs = 1,
            .client_prefix = prefix,
            .trigger_addr = key->remote_addr,
            .trigger_port = key->remote_port,
            .allow_reuse = allow_reuse,
        };
        int ret = bpf_map_update_elem(&nat6_mapping_map, &key->local, &initial, BPF_NOEXIST);
        mapping = bpf_map_lookup_elem(&nat6_mapping_map, &key->local);
        if (!ret || !mapping) return mapping;
    }
    bool trigger = mapping->trigger_port == key->remote_port &&
                   ip_addr_equal_x(&mapping->trigger_addr, &key->remote_addr);
    bpf_spin_lock(&mapping->lock);
    bool admitted = mapping->refs &&
                    (trigger || mapping->allow_reuse || key->local.l4_protocol == NEXTHDR_ICMP);
    if (admitted) mapping->refs++;
    bpf_spin_unlock(&mapping->lock);
    return admitted ? mapping : NULL;
}

static __always_inline int nat6_resolve(const struct ip6_scan_offsets *off,
                                        const struct in6_addr *local, __be16 local_port,
                                        const struct in6_addr *remote, __be16 remote_port,
                                        bool egress, u32 mark, u32 ifindex, u64 bytes,
                                        struct nat6_translation *out) {
    __be64 prefix;
    __builtin_memcpy(&prefix, local, sizeof(prefix));
    u8 mask = (u8)(wan_ro_npt_mask >> 56);
    struct nat6_timer_key key = {
        .local =
            {
                .client_port = local_port,
                .id_byte = (u8)bpf_be64_to_cpu(prefix) & mask,
                .l4_protocol = off->l4_protocol,
            },
        .remote_addr = *remote,
        .remote_port = remote_port,
    };
    COPY_ADDR_FROM(key.local.client_suffix, (const u8 *)local + sizeof(prefix));
    bool icmp_error = off->icmp_inner_l4_offset != 0;
    bool allow_reuse = get_flow_allow_reuse_port(mark);
    struct nat6_timer_value *ct = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (unlikely(!ct)) {
        struct static_nat6_mapping_value *rule = nat6_lookup_static(&key.local);
        out->is_static = rule != NULL;
        out->replace = !rule || nat6_static_needs_prefix_replace(rule);
        out->client_prefix = prefix;
        if (!egress && rule && out->replace)
            __builtin_memcpy(&out->client_prefix, rule->lan_prefix, sizeof(prefix));

        if (!nat6_allows_create_pkt(off->l4_protocol, off->tcp_phase, icmp_error))
            return rule ? NAT_OP_OK : NAT_OP_ERR;

        struct nat6_mapping_value *mapping = NULL;
        struct nat6_timer_value initial = {};
        if (!rule) {
            mapping = nat6_mapping_get(&key, prefix, egress, allow_reuse);
            if (!mapping) return NAT_OP_ERR;
            if (!egress) out->client_prefix = mapping->client_prefix;
            initial.is_trigger = mapping->trigger_port == remote_port &&
                                 ip_addr_equal_x(&mapping->trigger_addr, remote);
            initial.allow_reuse = mapping->allow_reuse;
        }
        initial.gress = egress ? NAT_MAPPING_EGRESS : NAT_MAPPING_INGRESS;
        initial.is_static = out->is_static;
        initial.need_prefix_replace = out->replace;
        initial.create_time = bpf_ktime_get_tai_ns();
        initial.cpu_id = bpf_get_smp_processor_id();
        initial.flow_id = get_flow_id(mark);
        initial.ifindex = ifindex;
        initial.client_prefix = out->client_prefix;
        ct = nat6_insert_timer(&key, &initial);
        if (!ct) {
            if (mapping) nat6_mapping_put(&key.local, mapping);
            /* A simultaneous first packet may have published the same tuple. */
            ct = bpf_map_lookup_elem(&nat6_timer_map, &key);
            if (!ct) return !egress && rule ? NAT_OP_OK : NAT_OP_ERR;
        } else if (mapping && egress) {
            mapping->client_prefix = prefix;
        }
    }

    if (!icmp_error) {
        if (nat6_ct_advance_pkt(off->l4_protocol, off->tcp_phase,
                                egress ? NAT_MAPPING_EGRESS : NAT_MAPPING_INGRESS, ct))
            return NAT_OP_ERR;
        if (egress) {
            bool moved = ((ct->client_prefix ^ prefix) & ~((u64)mask << 56)) != 0;
            if (unlikely(moved || (ct->is_trigger && ct->allow_reuse != allow_reuse))) {
                if (!ct->is_static) {
                    struct nat6_mapping_value *mapping =
                        bpf_map_lookup_elem(&nat6_mapping_map, &key.local);
                    /* Recheck after lookup: a retiring CT must never update its successor's
                     * mapping. */
                    if (mapping && *(volatile u64 *)&ct->status < TIMER_CLEAN_START) {
                        bpf_spin_lock(&mapping->lock);
                        if (moved) mapping->client_prefix = prefix;
                        if (ct->is_trigger) {
                            mapping->allow_reuse = allow_reuse;
                            ct->allow_reuse = allow_reuse;
                        }
                        bpf_spin_unlock(&mapping->lock);
                    }
                }
                ct->client_prefix = prefix;
                ct->flow_id = get_flow_id(mark);
            }
        }
        if (egress) {
            __sync_fetch_and_add(&ct->egress_bytes, bytes);
            __sync_fetch_and_add(&ct->egress_packets, 1);
        } else {
            __sync_fetch_and_add(&ct->ingress_bytes, bytes);
            __sync_fetch_and_add(&ct->ingress_packets, 1);
        }
    }

    out->is_static = ct->is_static;
    out->replace = ct->need_prefix_replace;
    out->client_prefix = ct->client_prefix;
    return NAT_OP_OK;
}
#endif
