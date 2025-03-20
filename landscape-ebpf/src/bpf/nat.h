#ifndef LD_NAT_H
#define LD_NAT_H
#include "vmlinux.h"
#include "landscape_log.h"
#include "packet_def.h"

#define GRESS_MASK (1 << 0)

#define COPY_ADDR_FROM(t, s) (__builtin_memcpy((t), (s), sizeof(t)))
static __always_inline void inet_addr_set_ip(union u_inet_addr *addr, __be32 ip) { addr->ip = ip; }
static __always_inline bool inet_addr_equal(const union u_inet_addr *a,
                                            const union u_inet_addr *b) {
    return a->ip == b->ip;
}

static __always_inline int bpf_write_port(struct __sk_buff *skb, int port_off, __be16 to_port) {
    return bpf_skb_store_bytes(skb, port_off, &to_port, sizeof(to_port), 0);
}

static __always_inline int bpf_write_inet_addr(struct __sk_buff *skb, bool is_ipv4, int addr_off,
                                               union u_inet_addr *to_addr) {
    return bpf_skb_store_bytes(skb, addr_off, is_ipv4 ? &to_addr->ip : to_addr->all,
                               is_ipv4 ? sizeof(to_addr->ip) : sizeof(to_addr->all), 0);
}

/// @brief  解析的 ip 数据包载体
struct ip_packet_info {
    u8 _pad;
    // ip 报文承载的协议类型: TCP / UDP / ICMP
    u8 ip_protocol;
    // 数据包的处理类型 (例如, 非链接, SYN FIN)
    u8 pkt_type;
    // 是否还有分片
    u8 fragment_type;
    // 分片偏移量
    u16 fragment_off;
    // 当前分片 id
    u16 fragment_id;
    // l3 的负载偏移位置 当为 0 时表示没有 ip 的负载 也就是没有 TCP ICMP UDP 头部信息
    // 为 0 表示为 IP 的分片
    int l4_payload_offset;
    // icmp 错误时 icmp payload 的负载位置
    // 不为 0 表示 这个是 icmp 错误 包
    int icmp_error_payload_offset;

    struct inet_pair pair_ip;
};

// 所能映射的范围
struct mapping_range {
    u16 start;
    u16 end;
};

enum {
    NAT_MAPPING_INGRESS = 0,
    NAT_MAPPING_EGRESS = 1,
};
/// 作为 发出 和 接收 数据包时查询的 key
struct nat_mapping_key {
    u8 gress;
    u8 l4proto;
    __be16 from_port;
    union u_inet_addr from_addr;
};

struct nat_mapping_value {
    union u_inet_addr addr;
    // TODO： 触发这个关系的 ip 或者端口
    // 单独一张检查表， 使用这个 ip 获取是否需要检查
    union u_inet_addr trigger_addr;
    __be16 port;
    __be16 trigger_port;
    u8 is_static;
    u8 _pad[3];
    // 增加一个最后活跃时间
    u64 active_time;
    //
};

/// 作为静态映射 map
/// TODO: 支持多 Nat 网卡进行映射
struct nat_static_mapping_key {
    // 匹配数据长度
    __u32 prefixlen;
    u8 gress;
    u8 l4proto;
    __be16 from_port;
    union u_inet_addr from_addr;
};

//
struct nat_timer_key {
    u8 l4proto;
    u8 _pad[3];
    // Ac:Pc_An:Pn
    struct inet_pair pair_ip;
};

//
struct nat_timer_value {
    // 只关注 Timer 的状态
    u64 status;
    // As
    union u_inet_addr trigger_saddr;
    // Ps
    u16 trigger_port;
    u8 gress;
    u8 _pad;
    struct bpf_timer timer;
};

// 用于搜寻可用的端口
struct search_port_ctx {
    struct nat_mapping_key ingress_key;
    struct mapping_range range;
    u16 remaining_size;
    // 小端序的端口
    u16 curr_port;
    bool found;
    u64 timeout_interval;
};
#endif /* LD_NAT_H */
