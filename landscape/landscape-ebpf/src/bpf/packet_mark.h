#include "vmlinux.h"
#include "landscape_log.h"

struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

//
struct ipv4_block_action {
    __u32 value;
};

struct ipv4_mark_action {
    __u32 mark;
};

#define OK_MARK 0
#define DIRECT_MARK 1
#define DROP_MARK 2
#define REDIRECT_MARK 3
#define SYMMETRIC_NAT 4

#define ACTION_MASK 0x00FF
#define INDEX_MASK 0xFF00

// DNS (目前) 或者 其他程序 可控制的 map,
// 其中的记录会变化
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ipv4_mark_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_mark_map SEC(".maps");

// 不会因为时间而过期的记录
// 且优先级低于其他 map
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ipv4_mark_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stable_mark_map SEC(".maps");

// 数据包过滤使用的 mark
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u8);
    __type(value, u32);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_index_map SEC(".maps");
