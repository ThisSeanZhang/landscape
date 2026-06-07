#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 KEY = 0;

struct time_test_result {
    u64 tai_ns;
    u64 mono_ns;
    u64 boot_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct time_test_result);
} test_time_result_map SEC(".maps");

SEC("tc/ingress")
int test_time(struct __sk_buff *skb) {
    u32 key = KEY;
    struct time_test_result value = {
        .tai_ns = bpf_ktime_get_tai_ns(),
        .mono_ns = bpf_ktime_get_ns(),
        .boot_ns = bpf_ktime_get_boot_ns(),
    };

    bpf_map_update_elem(&test_time_result_map, &key, &value, BPF_ANY);
    return 0;
}
