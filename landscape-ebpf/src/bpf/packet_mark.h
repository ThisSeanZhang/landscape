#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "landscape.h"

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

// 用于管理 Lan IP 功能控制的 IP
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ipv4_mark_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lanip_mark_map SEC(".maps");

// 用于管理 Wan IP 功能控制的 IP
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ipv4_mark_action);
    __uint(max_entries, 2048);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wanip_mark_map SEC(".maps");

// 数据包过滤使用的 mark
// 存储的数据是 redirect_id -> 具体网卡 index
// 网卡的 index 更新由 docker 的 event 进行触发
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u8);
    __type(value, u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_index_map SEC(".maps");
