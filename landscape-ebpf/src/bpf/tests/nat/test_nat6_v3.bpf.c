#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "nat/tc_nat6.h"
#include "base/landscape.h"
#include "reader/tc_nat_read6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

/* Drive a disarmed CT through one production timer step. Return the delay in milliseconds. */
SEC("tc")
int nat6_report_tick(struct __sk_buff *skb) {
    struct nat6_timer_key key = {.l4_protocol = IPPROTO_UDP};
    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (!value) return -1;

    u64 next_timeout;
    if (!nat6_timer_step(&key, value, &next_timeout)) return 0;
    return next_timeout / 1000000ULL;
}

SEC("tc/egress")
int handle_ipv6_egress(struct __sk_buff *skb) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    int ret = 0;

    if (!tc_nat_read6(skb, current_l3_offset, LAND_FRAG_FROM_LAN, &off, &src_addr, &dst_addr,
                      &sport, &dport))
        return TC_ACT_SHOT;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&off)))) return TC_ACT_OK;
    if (unlikely(!off.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_egress_prefix_check_and_replace(skb, &off, &src_addr, &dst_addr, sport, dport,
                                               skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
}

static __always_inline int test_ipv6_ingress(struct __sk_buff *skb, u32 *head_before_rewrite) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    int ret = 0;

    if (!tc_nat_read6(skb, current_l3_offset, LAND_FRAG_FROM_WAN, &off, &src_addr, &dst_addr,
                      &sport, &dport))
        return TC_ACT_SHOT;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&off)))) return TC_ACT_OK;
    if (unlikely(!off.ports_valid)) return TC_ACT_SHOT;

    if (head_before_rewrite) *head_before_rewrite = skb->data_end - skb->data;
    ret = ipv6_ingress_prefix_check_and_replace(skb, &off, &src_addr, &dst_addr, sport, dport,
                                                skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
}

SEC("tc/ingress")
int handle_ipv6_ingress(struct __sk_buff *skb) { return test_ipv6_ingress(skb, NULL); }

struct ptb_sample {
    u32 head_before_rewrite;
    u32 head_after_rewrite;
    int verdict;
    /* Ethernet, outer IPv6, ICMPv6, quoted IPv6 and the quoted TCP header. */
    u8 frame[sizeof(struct ethhdr) + 2 * sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) +
             sizeof(struct tcphdr)];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ptb_sample);
} ptb_samples SEC(".maps");

SEC("tc/ingress")
int capture_ptb_ingress(struct __sk_buff *skb) {
    struct ptb_sample sample = {};
    sample.verdict = test_ipv6_ingress(skb, &sample.head_before_rewrite);
    sample.head_after_rewrite = skb->data_end - skb->data;
    u32 len = skb->len;
    /* Bounding the last byte gives the verifier a copy size in [1, sizeof(frame)]. */
    u64 last_byte = len - 1U;
    if (last_byte >= sizeof(sample.frame)) return TC_ACT_SHOT;
    barrier_var(last_byte);
    if (!bpf_skb_load_bytes(skb, 0, sample.frame, last_byte + 1))
        bpf_map_update_elem(&ptb_samples, &len, &sample, BPF_ANY);
    return TC_ACT_SHOT;
}
