#!/bin/bash

# 添加路由规则
ip rule add fwmark 0x1/0x1 lookup 100
ip route add local default dev lo table 100

ip -6 rule add fwmark 0x1 lookup 106
ip -6 route add local ::/0 dev lo table 106

# ICMP passthrough (issue #206): only configure forwarding and NAT when required.
# Enable it with LAND_PROXY_ENABLE_ICMP_PASSTHROUGH=true. The mark below must match
# LAND_PROXY_ICMP_MARK_VALUE (default: 2). These commands may also be placed in
# /app/server/run.sh instead.
# echo 1 > /proc/sys/net/ipv4/ip_forward
# echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
# iptables -t nat -A POSTROUTING -m mark --mark 0x2/0x2 -j MASQUERADE
# ip6tables -t nat -A POSTROUTING -m mark --mark 0x2/0x2 -j MASQUERADE

/app/server/run.sh /app/server &
/app/redirect_pkg_handler &

# 等待子进程结束
wait
