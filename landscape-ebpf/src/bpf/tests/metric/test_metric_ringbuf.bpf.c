#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct test_metric_event {
    __u32 seq;
    __u64 ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} test_metric_events SEC(".maps");

// 仅用于把 test_metric_event 引入生成的 skeleton types 模块(ringbuf map
// 不声明 value 类型,BTF 无法导出载荷结构体)。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct test_metric_event);
} test_metric_event_sink SEC(".maps");

SEC("tc/ingress")
int test_emit_metric(struct __sk_buff *skb) {
    struct test_metric_event *event;

    event = bpf_ringbuf_reserve(&test_metric_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->seq = skb->mark;
    event->ts_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(event, 0);

    return 0;
}
