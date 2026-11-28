#ifndef __LD_FLOW_L4_MAPS_H__
#define __LD_FLOW_L4_MAPS_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define FLOW_L4_MAX_RULES_PER_FLOW 32

struct flow_l4_rule_entry {
    u32 mark;
    u16 start_port;
    u16 end_port;
    u16 priority;
    u8 l4_proto;
    u8 _pad[5];
} __flow_l4_rule_entry;

struct flow_l4_rule_set {
    u32 count;
    struct flow_l4_rule_entry entries[FLOW_L4_MAX_RULES_PER_FLOW];
} __flow_l4_rule_set;

struct flow_l4_meta {
    u32 active_mask_words[8];
} __flow_l4_meta;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct flow_l4_rule_set);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_l4_rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct flow_l4_meta);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_l4_meta_map SEC(".maps");

static __always_inline bool any_flow_has_l4_rules(void) {
    u32 zero = 0;
    const struct flow_l4_meta *meta = bpf_map_lookup_elem(&flow_l4_meta_map, &zero);
    if (meta == NULL) return false;
    return (meta->active_mask_words[0] | meta->active_mask_words[1] | meta->active_mask_words[2] |
            meta->active_mask_words[3] | meta->active_mask_words[4] | meta->active_mask_words[5] |
            meta->active_mask_words[6] | meta->active_mask_words[7]) != 0;
}

static __always_inline bool flow_has_l4_rules(u32 src_flow_id) {
    if (src_flow_id >= 256) return false;
    u32 zero = 0;
    const struct flow_l4_meta *meta = bpf_map_lookup_elem(&flow_l4_meta_map, &zero);
    if (meta == NULL) return false;
    u32 word_idx = (src_flow_id >> 5) & 7U;
    u32 bit = 1U << (src_flow_id & 31U);
    return (meta->active_mask_words[word_idx] & bit) != 0;
}

#endif /* __LD_FLOW_L4_MAPS_H__ */
