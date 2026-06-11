#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "lan_tc_pipeline.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/ingress")
int lan_tc_pipeline_ingress_root(struct __sk_buff *skb) {
    return lan_tc_pipeline_tailcall_ingress_from(skb, (__u32)-1);
}

SEC("tc/egress")
int lan_tc_pipeline_egress_root(struct __sk_buff *skb) {
    return lan_tc_pipeline_tailcall_egress_from(skb, (__u32)-1);
}
