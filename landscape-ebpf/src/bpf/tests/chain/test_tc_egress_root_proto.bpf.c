#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} target_root SEC(".maps");

// Overwrite wire eth->h_proto from skb->cb[0] (be16) without altering
// skb->protocol, then tail-call into tc_wan_egress_root.
SEC("tc/egress")
int tc_rewrite_eth_proto_and_call(struct __sk_buff *skb) {
    __be16 proto = (__be16)skb->cb[0];
    skb->cb[0] = 0;
    if (proto && bpf_skb_store_bytes(skb, 12, &proto, sizeof(proto), 0)) return 2;
    bpf_tail_call_static(skb, &target_root, 0);
    return -1;
}

SEC("tc/egress")
int tc_verdict_v4(struct __sk_buff *skb) { return 101; }

SEC("tc/egress")
int tc_verdict_v6(struct __sk_buff *skb) { return 102; }

SEC("tc/egress")
int tc_verdict_exit(struct __sk_buff *skb) { return 103; }
