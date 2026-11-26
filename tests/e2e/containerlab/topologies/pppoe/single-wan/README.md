# 单 WAN PPPoE 接入

`client:eth1 ── lan0 [Landscape] wan0 ── eth1:wan`

LAN 网关为 `192.0.2.1/24`。WAN 节点在独立网络中充当 PPPoE 接入端，宿主机需要支持 PPP 并提供 `/dev/ppp`。Landscape 使用内置 PPPoE 客户端，通过 PAP 和 IPCP 建立会话，使用 TC 处理 LAN 流量的 NAT。WAN 侧的 IPv4 地址通过 PPP 分配。[拓扑](topology.clab.yml) · [路由器配置](landscape_init.toml)

[重拨后 UDP 恢复用例](../../../cases/pppoe/redial-udp/README.md)负责启动接入服务、配置地址池并触发会话断开。
