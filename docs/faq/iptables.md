# 与 iptables 的关系
没有关系

所有的 DNS 标记, 还有转发均不会改变 iptables 规则,
当前 DNS / IP 标记服务生效的位置是在 **WAN 网卡**.  

也就是当 **数据包** 进入了 **开启了标记服务 WAN 网卡** 的 `EGRESS` 时, 才会进行匹配规则处理数据包.

具体可以看 [特性/eBPF 路由](../feature/route.md#加速原理) 中的介绍.
