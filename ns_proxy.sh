#!/bin/bash

# 设置网络命名空间和 veth 设备名称
NAMESPACE="tpns"
VETH_HOST="veth0"
VETH_NS="veth1"

# IPv4 配置
SUBNET="10.200.1.0/30"
HOST_IP="10.200.1.1"
NS_IP="10.200.1.2"

# IPv6 配置（示例使用 ULA 地址）
SUBNET6="fd00:200:1::/64"
HOST_IPV6="fd00:200:1::1"
NS_IPV6="fd00:200:1::2"

INTERFACE_OUT="ens3"  # 主机的外部接口名称

# 捕获退出信号以进行清理
trap cleanup INT

# 保存原始 sysctl 配置
ORIGINAL_IPV4_FORWARD=$(sysctl -n net.ipv4.ip_forward)
# ORIGINAL_IPV6_FORWARD=$(sysctl -n net.ipv6.conf.all.forwarding)

cleanup() {
    echo "清理配置..."

    # 还原 sysctl 配置
    sysctl -w net.ipv4.ip_forward=$ORIGINAL_IPV4_FORWARD
    # sysctl -w net.ipv6.conf.all.forwarding=$ORIGINAL_IPV6_FORWARD

    # 删除 iptables NAT 规则
    iptables -t nat -D POSTROUTING -s $SUBNET -o $INTERFACE_OUT -j MASQUERADE
    # ip6tables -t nat -D POSTROUTING -s $SUBNET6 -o $INTERFACE_OUT -j MASQUERADE

    # 删除 veth 设备和命名空间
    ip link del $VETH_HOST
    ip netns del $NAMESPACE

    echo "配置已清理。"
    exit 0
}

# 创建网络命名空间
ip netns add $NAMESPACE

# 创建 veth 对
ip link add $VETH_HOST type veth peer name $VETH_NS

# 将 veth 的一端移入命名空间
ip link set $VETH_NS netns $NAMESPACE

# 配置主机的 veth 接口（IPv4 和 IPv6）
ip addr add $HOST_IP/30 dev $VETH_HOST
ip -6 addr add $HOST_IPV6/64 dev $VETH_HOST
ip link set dev $VETH_HOST up

# 配置命名空间内的 veth 接口及路由（IPv4 和 IPv6）
ip netns exec $NAMESPACE ip addr add $NS_IP/30 dev $VETH_NS
ip netns exec $NAMESPACE ip -6 addr add $NS_IPV6/64 dev $VETH_NS
ip netns exec $NAMESPACE ip link set dev $VETH_NS up

# 添加默认路由（IPv4 和 IPv6）
ip netns exec $NAMESPACE ip route add default via $HOST_IP
# ip netns exec $NAMESPACE ip -6 route add default via $HOST_IPV6

# 配置命名空间内的自定义路由和规则（IPv4 部分示例）
ip netns exec $NAMESPACE ip rule add fwmark 0x1/0x1 lookup 100
ip netns exec $NAMESPACE ip route add local default dev lo table 100
ip netns exec $NAMESPACE sysctl -w net.ipv4.conf.lo.accept_local=1

# 启用 IP 转发（IPv4 和 IPv6）
sysctl -w net.ipv4.ip_forward=1
# sysctl -w net.ipv6.conf.all.forwarding=1

# 配置 NAT，使得命名空间内流量可以通过主机接口访问外部（IPv4 和 IPv6）
iptables -t nat -A POSTROUTING -s $SUBNET -o $INTERFACE_OUT -j MASQUERADE
# ip6tables -t nat -A POSTROUTING -s $SUBNET6 -o $INTERFACE_OUT -j MASQUERADE

echo "配置完成。按 Ctrl+C 以清理配置并退出。"

# 等待 Ctrl+C
while true; do
    sleep 1
done
