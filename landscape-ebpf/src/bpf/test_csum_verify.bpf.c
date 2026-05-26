#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} csum_map SEC(".maps");

SEC("tc")
int test_csum_ip(struct __sk_buff *skb) {
    u32 key = 0;

    /* Approach A: using bpf_htonl — exactly how the XDP code gets values from packet */
    __be32 old_addr_a = bpf_htonl(0x0a0a0a70); /* 10.10.10.112 */
    __be32 new_addr_a = bpf_htonl(0x0a0101ec); /* 10.1.1.236 */
    __be16 old_csum_a = bpf_htons(0x882e);

    /* Approach B: hardcoded LE values (same bytes in memory as approach A on LE) */
    __be32 old_addr_b = 0x700a0a0a;
    __be32 new_addr_b = 0xec01010a; /* 10.1.1.236 in LE host order */
    __be16 old_csum_b = 0x2e88;

    /* === key 0: A: bpf_csum_diff direct (seed=csum) === */
    __u64 r0 = (__u64)(__u16)bpf_csum_diff(&old_addr_a, 4, &new_addr_a, 4, old_csum_a);
    bpf_map_update_elem(&csum_map, &key, &r0, BPF_ANY);

    /* === key 1: B: bpf_csum_diff direct (seed=csum) === */
    key = 1;
    __u64 r1 = (__u64)(__u16)bpf_csum_diff(&old_addr_b, 4, &new_addr_b, 4, old_csum_b);
    bpf_map_update_elem(&csum_map, &key, &r1, BPF_ANY);

    /* === key 2: A: raw delta (seed=0) === */
    key = 2;
    __u64 r2 = (__u64)bpf_csum_diff(&old_addr_a, 4, &new_addr_a, 4, 0);
    bpf_map_update_elem(&csum_map, &key, &r2, BPF_ANY);

    /* === key 3: B: raw delta (seed=0) === */
    key = 3;
    __u64 r3 = (__u64)bpf_csum_diff(&old_addr_b, 4, &new_addr_b, 4, 0);
    bpf_map_update_elem(&csum_map, &key, &r3, BPF_ANY);

    /* === key 4: verify memory bytes: read old_addr_a via *(u32*) === */
    key = 4;
    __u64 r4 = (__u64)(*(__u32 *)&old_addr_a);
    bpf_map_update_elem(&csum_map, &key, &r4, BPF_ANY);

    /* === key 5: verify memory bytes: read old_addr_b via *(u32*) === */
    key = 5;
    __u64 r5 = (__u64)(*(__u32 *)&old_addr_b);
    bpf_map_update_elem(&csum_map, &key, &r5, BPF_ANY);

    /* key 8: read new_addr_a memory */
    key = 8;
    __u64 r8 = (__u64)(*(__u32 *)&new_addr_a);
    bpf_map_update_elem(&csum_map, &key, &r8, BPF_ANY);

    /* key 9: read new_addr_b memory */
    key = 9;
    __u64 r9 = (__u64)(*(__u32 *)&new_addr_b);
    bpf_map_update_elem(&csum_map, &key, &r9, BPF_ANY);

    /* key 10: read old_csum_a via *(u16*) */
    key = 10;
    __u64 r10 = (__u64)(*(__u16 *)&old_csum_a);
    bpf_map_update_elem(&csum_map, &key, &r10, BPF_ANY);

    /* key 11: read old_csum_b via *(u16*) */
    key = 11;
    __u64 r11 = (__u64)(*(__u16 *)&old_csum_b);
    bpf_map_update_elem(&csum_map, &key, &r11, BPF_ANY);

    /* === key 6: csum_unfold + csum_fold chain on approach A === */
    key = 6;
    __wsum d6 = (__wsum)bpf_csum_diff(&old_addr_a, 4, &new_addr_a, 4, 0);

    __u32 x6 = (__u32)d6;
    x6 = x6 + ~(__u32)old_csum_a;
    if (x6 < ~(__u32)old_csum_a) x6 += 1;
    x6 = (x6 & 0xffff) + (x6 >> 16);
    x6 = (x6 & 0xffff) + (x6 >> 16);
    __u64 r6 = (__u64)(__u16)~x6;
    bpf_map_update_elem(&csum_map, &key, &r6, BPF_ANY);

    /* === key 7: csum_unfold + csum_fold chain on approach B === */
    key = 7;
    __wsum d7 = (__wsum)bpf_csum_diff(&old_addr_b, 4, &new_addr_b, 4, 0);

    __u32 x7 = (__u32)d7;
    x7 = x7 + ~(__u32)old_csum_b;
    if (x7 < ~(__u32)old_csum_b) x7 += 1;
    x7 = (x7 & 0xffff) + (x7 >> 16);
    x7 = (x7 & 0xffff) + (x7 >> 16);
    __u64 r7 = (__u64)(__u16)~x7;
    bpf_map_update_elem(&csum_map, &key, &r7, BPF_ANY);

    return 0;
}
