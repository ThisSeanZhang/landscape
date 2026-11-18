# Gateway 的 WAN 到 LAN 拓扑

```text
wan:eth1 ─── wan0 [ Landscape ] lan0 ─── eth1:backend
```

| 节点 | 接口与角色 |
| --- | --- |
| wan | eth1 使用 198.51.100.1/24，作为外部访问者和实验 WAN 下一跳 |
| router | Landscape 配置 wan0 为 198.51.100.2/24。lan0 使用 192.0.2.1/24 |
| backend | eth1 使用 192.0.2.10/24，运行用例指定的上游服务 |

两个网段各用一条点对点链路，管理 API 通过路由器容器的回环接口调用。共用的 Landscape 配置开启 Gateway，设置静态 WAN 地址和下一跳，并通过 LAN DHCP 服务登记直连网段。后端静态地址位于 DHCP 地址池之外。各用例自行配置代理规则、证书和后端进程。[拓扑定义](topology.clab.yml) · [Landscape 基础配置](landscape_init.toml)

使用此拓扑的用例包括 [HTTPS 路径改写](../../../cases/gateway/https-path-rewrite/README.md)、[SNI 透传](../../../cases/gateway/sni-passthrough/README.md)和[规则热更新](../../../cases/gateway/live-upstream-update/README.md)。
