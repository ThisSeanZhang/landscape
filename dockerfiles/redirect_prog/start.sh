#!/bin/bash

# 添加路由规则
ip rule add fwmark 0x1/0x1 lookup 100
ip route add local default dev lo table 100

ip -6 rule add fwmark 0x1 lookup 106
ip -6 route add local ::/0 dev lo table 106

# ICMP passthrough (issue #206): the tproxy eBPF marks ICMP/ICMPv6 with 0x2 and
# releases it to the routing stack instead of dropping it. Forward it out the
# default route (WAN) and SNAT so replies come back symmetrically. TCP/UDP still
# go through the TProxy listener untouched.
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
iptables -t nat -A POSTROUTING -m mark --mark 0x2/0x2 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -m mark --mark 0x2/0x2 -j MASQUERADE

/app/server/run.sh /app/server &
/app/redirect_pkg_handler &

# 等待子进程结束
wait
