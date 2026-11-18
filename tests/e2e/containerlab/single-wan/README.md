# 单 WAN 的 LAN 到 WAN 拓扑

本场景验证一个 LAN 客户端通过 Landscape 的 IPv4 路由和 NAT 访问 WAN。路由器使用默认 TC 模式。实验节点只有下列数据链路，脚本在路由器容器内经回环地址调用管理 API。

```text
client:eth1 ─── lan0 [ Landscape ] wan0 ─── eth1:wan
```

| 接口 | 地址或用途 |
| --- | --- |
| client 的 eth1 | 静态用例使用 192.0.2.10/24。DHCP 用例从无 IPv4 地址、无默认路由开始 |
| router 的 lan0 | 192.0.2.1/24，作为客户端的网关和 DHCP 下发的 DNS 服务器 |
| router 的 wan0 | 198.51.100.2/24，转发流量的 NAT 源地址 |
| wan 的 eth1 | 198.51.100.1/24，在 TCP 8080 提供 HTTP 服务并记录请求来源 |

节点和接线见[场景拓扑](single-wan.clab.yml)，路由、NAT、DHCP 地址池与租期见[初始化配置](landscape_init.toml)。

入口先通过管理 API 确认 lan0 和 wan0 存在，再检查两个接口上 Landscape 的 TC ingress 程序。使用此拓扑的可运行用例包括[静态 IPv4 转发](../cases/lan/static-forward/README.md)和[DHCPv4 首次获租](../cases/lan/dhcp-acquire/README.md)。

## 失败定位

拓扑部署开始后，失败的运行会在清理前向标准错误输出客户端地址、路由和 DNS，路由器地址、路由和 TC 过滤器，以及路由器、WAN 服务的日志。DHCP 用例还输出 LAN 设备和租约快照，可以用客户端 MAC 对照。若清理失败，脚本会打印保留的拓扑路径和重试命令。
