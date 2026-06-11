#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "wan_tc_pipeline.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/ingress")
int wan_tc_pipeline_ingress_root(struct __sk_buff *skb) {
    return wan_tc_pipeline_tailcall_ingress_from(skb, (__u32)-1);
}

SEC("tc/egress")
int wan_tc_pipeline_egress_root(struct __sk_buff *skb) {
    return wan_tc_pipeline_tailcall_egress_from(skb, (__u32)-1);
}
